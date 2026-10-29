//! Whole-module ahead-of-time block discovery.
//!
//! Before entry, Casa1 walks the reachable control-flow graph of the mapped
//! image starting at its entry point: each block is decoded instruction by
//! instruction, translated to IR, handed to the persistent AOT compiler, and
//! its direct successors are queued.  Only control-flow-reachable bytes are
//! translated, so data embedded in `.text` is never executed as code.
//!
//! The walk is deliberately conservative: indirect branches end a path
//! (their targets are unknown until runtime), undecodable bytes are skipped,
//! and a hard block/byte cap bounds startup work.  Translation failures are
//! counted, never fatal.

use std::collections::BTreeSet;

use crate::cpu::{
    CpuEngineConfig, CpuExecutionEngine, DecodedInstruction, DecodedOpcode, GuestArch,
    IrInstruction, MemoryImage,
};
use crate::error::AppResult;

/// A discovered basic block: its guest address and exact source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBlock {
    pub address: u64,
    pub bytes: Vec<u8>,
    /// Successor addresses (direct branches, calls and fallthroughs).
    pub successors: Vec<u64>,
}

/// Result of a whole-module walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrecompileReport {
    /// Blocks discovered and handed to the compiler.
    pub blocks: usize,
    /// Blocks the compiler accepted (persisted/loaded).
    pub compiled: usize,
    /// Paths skipped because bytes were unmapped, undecodable, too long, or
    /// the compiler rejected them.
    pub skipped: usize,
    /// Successors outside the module range that were not followed.
    pub out_of_range: usize,
    /// Profile/persisted seed addresses supplied for the union walk.
    pub seeded: usize,
    /// Seed addresses that were compiled (or loaded from the AOT cache).
    pub seeded_compiled: usize,
}

const MAX_BLOCK_BYTES: u64 = 4096;
const MAX_INSTRUCTION_BYTES: u64 = 15;

fn is_terminator(opcode: &DecodedOpcode) -> bool {
    matches!(
        opcode,
        DecodedOpcode::Ret
            | DecodedOpcode::JmpRel
            | DecodedOpcode::Jcc
            | DecodedOpcode::JmpRegister
            | DecodedOpcode::JmpMemory
            | DecodedOpcode::CallRel
            | DecodedOpcode::CallRegister
            | DecodedOpcode::CallMemory
            | DecodedOpcode::Loop
            | DecodedOpcode::Int { .. }
            | DecodedOpcode::Int3
            | DecodedOpcode::Hlt
            | DecodedOpcode::Ud2
    )
}

/// Decode the single instruction at `address` without consuming bytes past it.
///
/// `decode_block` decodes a whole byte slice, so the shortest slice that
/// yields an instruction is the instruction's own length; longer slices that
/// end mid-instruction are retried at shorter lengths.
fn decode_one(
    memory: &MemoryImage,
    engine: &CpuExecutionEngine,
    address: u64,
    end: u64,
) -> Option<DecodedInstruction> {
    let available = end.saturating_sub(address).min(MAX_INSTRUCTION_BYTES);
    (1..=available).find_map(|length| {
        let bytes = memory.read_bytes(address, length as usize).ok()?;
        let decoded = engine.decode_block(&bytes, address).ok()?;
        let first = decoded.first()?;
        (first.address == address && first.size as u64 <= length).then(|| first.clone())
    })
}

fn successors_from_ir(ir: &[IrInstruction]) -> Vec<u64> {
    let mut successors = Vec::new();
    for instruction in ir {
        match instruction {
            IrInstruction::Jump { target } => successors.push(*target),
            IrInstruction::JumpIf {
                target,
                fallthrough,
                ..
            } => {
                successors.push(*target);
                successors.push(*fallthrough);
            }
            IrInstruction::Call {
                target,
                return_address,
            } => {
                successors.push(*target);
                successors.push(*return_address);
            }
            IrInstruction::CallRegister { return_address, .. }
            | IrInstruction::CallMemory { return_address, .. } => {
                successors.push(*return_address);
            }
            _ => {}
        }
    }
    successors
}

fn discover_one(
    memory: &MemoryImage,
    engine: &mut CpuExecutionEngine,
    start: u64,
    end: u64,
) -> Option<DiscoveredBlock> {
    let mut cursor = start;
    loop {
        if cursor >= end || cursor - start > MAX_BLOCK_BYTES {
            return None;
        }
        let instruction = decode_one(memory, engine, cursor, end)?;
        cursor += instruction.size as u64;
        if is_terminator(&instruction.opcode) {
            break;
        }
    }
    if cursor == start {
        return None; // coverage: unreachable — every loop iteration advances cursor or returns earlier
    }
    let bytes = memory.read_bytes(start, (cursor - start) as usize).ok()?;
    let translated = engine.translate_block(&bytes, start).ok()?;
    let successors = successors_from_ir(&translated.ir);
    Some(DiscoveredBlock {
        address: start,
        bytes,
        successors,
    })
}

/// Discover every control-flow-reachable block in `[start, end)`, bounded by
/// `max_blocks`, and return them in discovery order.
#[cfg(test)]
pub fn discover_blocks(
    memory: &MemoryImage,
    arch: GuestArch,
    start: u64,
    end: u64,
    max_blocks: usize,
) -> AppResult<(Vec<DiscoveredBlock>, PrecompileReport)> {
    let config = CpuEngineConfig::from_profile(arch, "win11-23h2", "macOS", None)?;
    let mut engine = CpuExecutionEngine::new(config);
    let mut pending = vec![start];
    let mut visited = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut report = PrecompileReport::default();
    while let Some(address) = pending.pop() {
        if address < start || address >= end {
            report.out_of_range += 1;
            continue;
        }
        if !visited.insert(address) {
            continue;
        }
        if blocks.len() >= max_blocks {
            break;
        }
        let Some(block) = discover_one(memory, &mut engine, address, end) else {
            report.skipped += 1;
            continue;
        };
        for successor in &block.successors {
            if *successor < start || *successor >= end {
                report.out_of_range += 1;
            } else {
                pending.push(*successor);
            }
        }
        report.blocks += 1;
        blocks.push(block);
    }
    Ok((blocks, report))
}

/// Discover and compile the module's reachable blocks.  `compile` receives
/// each block's IR and must persist or cache it; a failure skips that block.
pub fn precompile_blocks<F>(
    memory: &MemoryImage,
    arch: GuestArch,
    start: u64,
    end: u64,
    max_blocks: usize,
    compile: F,
) -> AppResult<PrecompileReport>
where
    F: FnMut(&[IrInstruction], u64) -> AppResult<()>,
{
    precompile_blocks_with_seeds(memory, arch, start, end, max_blocks, &[], compile)
}

/// Discover the control-flow-reachable blocks starting at `start` **and** at
/// every address in `seeds` (persisted profile targets and known cache
/// misses), handing each distinct block to `compile`.
///
/// This is the union install/update pipeline: the static walk supplies
/// directly-reachable code, while profile seeds supply blocks reached only
/// through indirect calls or other runtime-only edges.  Addresses are visited
/// once regardless of how many sources discover them.
pub fn precompile_blocks_with_seeds<F>(
    memory: &MemoryImage,
    arch: GuestArch,
    start: u64,
    end: u64,
    max_blocks: usize,
    seeds: &[u64],
    mut compile: F,
) -> AppResult<PrecompileReport>
where
    F: FnMut(&[IrInstruction], u64) -> AppResult<()>,
{
    let config = CpuEngineConfig::from_profile(arch, "win11-23h2", "macOS", None)?;
    let mut engine = CpuExecutionEngine::new(config);
    let seed_set: BTreeSet<u64> = seeds.iter().copied().collect();
    let mut pending = vec![start];
    // LIFO: start is popped first, then profile seeds in ascending order.
    pending.extend(seed_set.iter().rev().copied());
    let mut visited = BTreeSet::new();
    let mut report = PrecompileReport {
        seeded: seed_set.len(),
        ..PrecompileReport::default()
    };
    while let Some(address) = pending.pop() {
        if address < start || address >= end {
            report.out_of_range += 1;
            continue;
        }
        if !visited.insert(address) {
            continue;
        }
        if report.blocks >= max_blocks {
            break;
        }
        let Some(block) = discover_one(memory, &mut engine, address, end) else {
            report.skipped += 1;
            continue;
        };
        report.blocks += 1;
        let translated = engine.translate_block(&block.bytes, address)?;
        for successor in &block.successors {
            if *successor < start || *successor >= end {
                report.out_of_range += 1;
            } else {
                pending.push(*successor);
            }
        }
        match compile(&translated.ir, address) {
            Ok(()) => {
                report.compiled += 1;
                if seed_set.contains(&address) {
                    report.seeded_compiled += 1;
                }
            }
            Err(_) => report.skipped += 1,
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_with(bytes: &[(u64, &[u8])]) -> MemoryImage {
        let mut memory = MemoryImage::default();
        for (address, data) in bytes {
            memory.map_bytes(*address, data);
        }
        memory
    }

    #[test]
    fn missing_and_undecodable_entries_are_skipped_not_fatal() {
        let memory = memory_with(&[(0x2000, &[0x0F, 0xFF])]);
        let (blocks, report) =
            discover_blocks(&memory, GuestArch::X86, 0x2000, 0x2004, 8).expect("discover");
        assert_eq!(blocks.len(), 0);
        assert_eq!(report.blocks, 0);
        assert_ne!(report.skipped, 0, "undecodable bytes are skipped");

        let (blocks, report) =
            discover_blocks(&memory, GuestArch::X86, 0x3000, 0x3010, 8).expect("discover");
        assert_eq!(blocks.len(), 0);
        assert_eq!(report.skipped, 1, "unmapped entry is one skipped path");
    }

    #[test]
    fn compiler_rejection_is_counted_and_walk_continues() {
        let memory = memory_with(&[(0x5000, &[0x90, 0x90, 0xC3])]);
        let report = precompile_blocks(&memory, GuestArch::X86, 0x5000, 0x5003, 4, |_, address| {
            if address == 0x5000 {
                Err(crate::error::AppError::new(
                    crate::reason::ReasonCode::RcUnimplInsn,
                    "synthetic compile refusal",
                ))
            } else {
                Ok(())
            }
        })
        .expect("precompile");
        assert_eq!(report.blocks, 1);
        assert_eq!(report.compiled, 0);
        assert_eq!(report.skipped, 1);

        // Conditional branch, fallthrough, call and indirect call all extend
        // the reachable set with their exact direct successors.
        // 0x1000: test eax,eax / jz 0x1006
        // 0x1004: call 0x1010 / ret
        // 0x1006: call eax / ret
        // 0x1008: call [eax] / ret
        // 0x1010: ret
        let mut code = vec![0x85, 0xC0, 0x74, 0x02];
        code.extend_from_slice(&[0xE8, 0x07, 0x00, 0x00, 0x00, 0xC3]);
        code.extend_from_slice(&[0xFF, 0xD0, 0xC3]);
        code.extend_from_slice(&[0xFF, 0x10, 0xC3]);
        code.push(0x90);
        code.push(0xC3);
        let memory = memory_with(&[(0x1000, &code)]);
        let mut discovered = Vec::new();
        let report = precompile_blocks(
            &memory,
            GuestArch::X86,
            0x1000,
            0x1011,
            16,
            |ir, address| {
                discovered.push((address, successors_from_ir(ir)));
                Ok(())
            },
        )
        .expect("precompile");
        assert_eq!(report.blocks, 5);
        assert_eq!(report.compiled, 5);
        assert!(discovered.iter().any(|(_, s)| s.contains(&0x1006)));
        assert!(discovered.iter().any(|(_, s)| s.contains(&0x1010)));
        assert!(
            discovered.iter().any(|(_, s)| s.len() == 1),
            "indirect call keeps only the return edge"
        );

        // A block without a terminator is capped, not walked forever.
        let long = vec![0x90_u8; 5000];
        let memory = memory_with(&[(0x3000, &long)]);
        let report =
            precompile_blocks(&memory, GuestArch::X86, 0x3000, 0x3000 + 5000, 4, |_, _| {
                Ok(())
            })
            .expect("precompile");
        assert_eq!(report.blocks, 0);
        assert_eq!(report.skipped, 1);

        // Out-of-range starts and successors are counted.
        let memory = memory_with(&[(0x4000, &[0xE9, 0xFB, 0x0F, 0x00, 0x00])]);
        let report = precompile_blocks(&memory, GuestArch::X86, 0x4000, 0x4005, 4, |_, _| Ok(()))
            .expect("precompile");
        assert_eq!(report.blocks, 1);
        assert_eq!(report.out_of_range, 1);

        // An empty module range makes the initial start itself out of range;
        // nothing is decoded or compiled.
        let mut compiles = 0_usize;
        let report = precompile_blocks(&memory, GuestArch::X86, 0x4000, 0x4000, 4, |_, _| {
            compiles += 1;
            Ok(())
        })
        .expect("precompile");
        assert_eq!(report.blocks, 0);
        assert_eq!(report.compiled, 0);
        assert_eq!(report.out_of_range, 1);
        assert_eq!(compiles, 0);

        // A self-loop successor revisits an already-visited block: the second
        // pop must be skipped, not compiled again.
        let mut compiles = 0_usize;
        let memory = memory_with(&[(0x6000, &[0xEB, 0xFE])]);
        let report = precompile_blocks(&memory, GuestArch::X86, 0x6000, 0x6002, 4, |_, address| {
            assert_eq!(address, 0x6000);
            compiles += 1;
            Ok(())
        })
        .expect("precompile");
        assert_eq!(report.blocks, 1);
        assert_eq!(report.compiled, 1);
        assert_eq!(compiles, 1);

        // A zero block budget stops the walk before any block is decoded.
        let memory = memory_with(&[(0x7000, &[0x90, 0xC3])]);
        let report = precompile_blocks(&memory, GuestArch::X86, 0x7000, 0x7002, 0, |_, _| {
            panic!("a zero block budget must not compile")
        })
        .expect("precompile");
        assert_eq!(report.blocks, 0);
        assert_eq!(report.compiled, 0);
        assert_eq!(report.skipped, 0);
    }
}
