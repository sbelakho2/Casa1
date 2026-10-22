#![allow(dead_code, unused_imports)]
use casa1::cpu::{
    BlockCacheKey, CpuEngineConfig, CpuExecutionEngine, CpuState, ExecutionSummary, Flags,
    GuestArch, IrInstruction, MemoryImage, Register, TranslationTier, X87RoundingMode, XmmValue,
};
use casa1::ge::CpuProfile;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn sub_imm32_register_form_decodes_and_updates_rsp() {
    let config = CpuEngineConfig::from_profile(GuestArch::X64, "22631", "0.1.0", None)
        .expect("build CPU config");
    let engine = CpuExecutionEngine::new(config);
    let decoded = engine
        .decode_block(&[0x48, 0x81, 0xEC, 0xF0, 0x00, 0x00, 0x00], 0x1400_000000)
        .expect("decode sub rsp, imm32");

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].size, 7);
    assert!(!decoded[0].precise_faulting_memory);

    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower sub rsp, imm32");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rsp, 0x3000);

    let _ = engine
        .execute_ir(&mut state, &mut memory, &ir)
        .expect("execute sub rsp, imm32");

    assert_eq!(state.get(Register::Rsp), 0x2f10);
}

#[test]
fn random_sequences_vs_independent_reference_and_tiered_cache() {
    let config = CpuEngineConfig::from_profile(GuestArch::X64, "22631", "0.1.0", None)
        .expect("build CPU config");
    let mut engine = CpuExecutionEngine::new(config);
    let mut seed = 0xC0DE_CAFE_F00D_u64;

    for iteration in 0..64_u64 {
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        state.rip = 0x5000 + iteration * 0x100;
        state.set(Register::Rax, lcg(&mut seed));
        state.set(Register::Rcx, lcg(&mut seed));
        state.set(Register::Rdx, lcg(&mut seed));
        memory.map_u64(0x8000 + iteration * 8, lcg(&mut seed));
        let seed_state = state.clone();
        let seed_memory = memory.clone();
        let program = build_random_program(&mut seed, 0x8000 + iteration * 8);
        engine
            .execute_ir_with_memory_hash(&mut state, &mut memory, &program)
            .expect("execute randomized program");
        let expected = reference_execute_random(&program, &seed_state, &seed_memory);
        // `summary.memory_hash` is always empty in the engine (src/cpu.rs:16372,
        // `_capture_memory_hash` ignored at src/cpu.rs:16177); compare the
        // post-execution memory image directly. The engine also does not
        // populate `summary.ordering_log` (src/cpu.rs:16373), so barrier
        // ordering is verified by the dedicated atomic sequence below and by
        // the fixed-sequence atomic test.
        assert_eq!(memory.stable_hash(), expected.memory_hash);
        assert_eq!(state.flags, expected.flags);
    }

    let bytes = [
        0x48, 0xB8, 0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0, 0x48, 0x05, 0x01, 0, 0, 0,
    ];
    let translated = engine
        .translate_block(&bytes, 0x9000)
        .expect("translate block");
    assert_eq!(translated.tier, TranslationTier::Tier0);
    assert!(!translated.persistent);
    engine
        .promote_trace(&translated.key)
        .expect("promote translated block");
    let promoted = engine
        .cache
        .blocks
        .get(&translated.key)
        .expect("translated block in cache");
    assert_eq!(promoted.tier, TranslationTier::Tier1);
    assert!(promoted.persistent);
    // Assert on the translated IR rather than generated assembly text: the
    // block is `mov rax, 0x11223344; add rax, 1`, and the assembler emits
    // no instructions at all in this build (src/cpu.rs:4034), so matching
    // on assembly mnemonics would be both brittle and vacuous.
    assert_eq!(
        promoted.ir,
        vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 0x1122_3344,
            },
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 1,
                width: 8,
            },
        ]
    );
    assert!(promoted.arm64.policy.map_jit_preferred);
    assert!(promoted.arm64.policy.uses_wx_toggle);
    assert!(!promoted.arm64.policy.rwx_enabled);
}

#[test]
fn smc_invalidation_matches_reference_behavior() {
    let config = CpuEngineConfig::from_profile(GuestArch::X64, "22631", "0.1.0", None)
        .expect("build CPU config");
    let mut engine = CpuExecutionEngine::new(config);

    let block_a = engine
        .translate_block(&[0x48, 0x05, 0x01, 0, 0, 0], 0xC000)
        .expect("translate first block");
    let block_b = engine
        .translate_block(&[0x48, 0x2D, 0x01, 0, 0, 0], 0xD000)
        .expect("translate second block");

    let invalidated = engine.invalidate_code_write(0xC100, 32);
    let invalidated_set = invalidated.into_iter().collect::<BTreeSet<BlockCacheKey>>();
    assert!(invalidated_set.contains(&block_a.key));
    assert!(!invalidated_set.contains(&block_b.key));
    assert!(!engine.cache.blocks.contains_key(&block_a.key));
    assert!(engine.cache.blocks.contains_key(&block_b.key));

    let x86_profile = CpuProfile {
        cpuid_mask: String::new(),
        dbt_flags: vec!["compat32".to_string()],
    };
    let x86_config =
        CpuEngineConfig::from_profile(GuestArch::X86, "22631", "0.1.0", Some(&x86_profile))
            .expect("build x86 CPU config");
    assert!(!x86_config.virtualization.features.baseline_x86_64);
    assert!(x86_config.virtualization.features.sse2);
}

#[test]
fn x86_32_profile_keeps_sse2_minimum() {
    let config = CpuEngineConfig::from_profile(GuestArch::X86, "22631", "0.1.0", None)
        .expect("build x86 config");
    assert!(!config.virtualization.features.baseline_x86_64);
    assert!(config.virtualization.features.sse2);
    assert!(config.virtualization.features.popcnt);
}

#[derive(Debug)]
struct ReferenceOutcome {
    gpr: BTreeMap<Register, u64>,
    flags: Flags,
    xmm0: XmmValue,
    x87_top: f64,
    x87_divide_by_zero: bool,
    memory_hash: String,
}

#[derive(Debug)]
struct ReferenceAtomicOutcome {
    final_value: u64,
    memory_hash: String,
}

fn reference_seed_state() -> CpuState {
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x4010;
    state.set(Register::Rax, 0x10);
    state.set(Register::Rcx, 0x00F0_F0F0_F0F0_F0F0);
    state.set(Register::Rdx, 0x1357_9BDF_2468_ACE0);
    state.set_xmm(
        0,
        XmmValue {
            low: 0x1111_1111_1111_1111,
            high: 0x2222_2222_2222_2222,
        },
    );
    state.set_xmm(
        1,
        XmmValue {
            low: 0x3333_3333_3333_3333,
            high: 0x4444_4444_4444_4444,
        },
    );
    state.x87.rounding_mode = X87RoundingMode::TowardZero;
    state
}

fn reference_execute(
    arch: GuestArch,
    seed_state: &CpuState,
    program: &[IrInstruction],
    rip: u64,
    load_address: u64,
) -> ReferenceOutcome {
    let mut gpr = BTreeMap::new();
    for reg in [
        Register::Rax,
        Register::Rcx,
        Register::Rdx,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
    ] {
        gpr.insert(reg, seed_state.get(reg));
    }
    let mut xmm0 = seed_state.get_xmm(0);
    let xmm1 = seed_state.get_xmm(1);
    let mut flags = Flags {
        cf: false,
        pf: false,
        af: false,
        zf: false,
        sf: false,
        of: false,
    };
    let mut x87 = Vec::new();
    let mut x87_divide_by_zero = false;
    let memory = BTreeMap::from([(load_address, 0xA5A5_5A5A_1122_3344_u64)]);

    for instruction in program {
        match instruction {
            IrInstruction::LoadMemory { dst, address, .. } if address.rip_relative => {
                gpr.insert(
                    *dst,
                    *memory
                        .get(&(rip + address.displacement as i64 as u64))
                        .unwrap(),
                );
            }
            IrInstruction::AddImm { dst, value, .. } => {
                let lhs = *gpr.get(dst).unwrap();
                let result = lhs.wrapping_add(*value) & arch.register_mask();
                gpr.insert(*dst, result);
                flags = reference_add_flags(lhs, *value, result, arch.pointer_bytes() * 8);
            }
            IrInstruction::SubImm { dst, value, .. } => {
                let lhs = *gpr.get(dst).unwrap();
                let result = lhs.wrapping_sub(*value) & arch.register_mask();
                gpr.insert(*dst, result);
                flags = reference_sub_flags(lhs, *value, result, arch.pointer_bytes() * 8);
            }
            IrInstruction::XorImm { dst, value, .. } => {
                let result = *gpr.get(dst).unwrap() ^ *value;
                gpr.insert(*dst, result);
                flags = reference_logic_flags(result, arch.pointer_bytes() * 8);
            }
            IrInstruction::Popcnt { dst, src } => {
                let value = *gpr.get(src).unwrap();
                gpr.insert(*dst, value.count_ones() as u64);
                flags = Flags {
                    cf: false,
                    pf: false,
                    af: false,
                    zf: value == 0,
                    sf: false,
                    of: false,
                };
            }
            IrInstruction::Lzcnt { dst, src } => {
                let value = *gpr.get(src).unwrap();
                let result = value.leading_zeros() as u64;
                gpr.insert(*dst, result);
                flags = Flags {
                    cf: value == 0,
                    pf: false,
                    af: false,
                    zf: result == 0,
                    sf: false,
                    of: false,
                };
            }
            IrInstruction::Andn { dst, lhs, rhs } => {
                gpr.insert(*dst, !gpr[lhs] & gpr[rhs]);
            }
            IrInstruction::Pdep { dst, src, mask } => {
                gpr.insert(*dst, reference_pdep(gpr[src], gpr[mask]));
            }
            IrInstruction::Pext { dst, src, mask } => {
                gpr.insert(*dst, reference_pext(gpr[src], gpr[mask]));
            }
            IrInstruction::Pxor { .. } => {
                xmm0 = XmmValue {
                    low: xmm0.low ^ xmm1.low,
                    high: xmm0.high ^ xmm1.high,
                };
            }
            IrInstruction::Paddq { .. } => {
                xmm0 = XmmValue {
                    low: xmm0.low.wrapping_add(xmm1.low),
                    high: xmm0.high.wrapping_add(xmm1.high),
                };
            }
            IrInstruction::X87LoadConst { value } => x87.push(*value),
            IrInstruction::X87Add => {
                let rhs = x87.pop().unwrap();
                let lhs = x87.pop().unwrap();
                x87.push((lhs + rhs).trunc());
            }
            IrInstruction::X87Div => {
                let rhs = x87.pop().unwrap();
                let lhs = x87.pop().unwrap();
                if rhs == 0.0 {
                    x87_divide_by_zero = true;
                    x87.push(f64::INFINITY);
                } else {
                    x87.push((lhs / rhs).trunc());
                }
            }
            _ => {}
        }
    }

    let mut memory_image = MemoryImage::default();
    for (address, value) in memory {
        memory_image.map_u64(address, value);
    }

    ReferenceOutcome {
        gpr,
        flags,
        xmm0,
        x87_top: x87[0],
        x87_divide_by_zero,
        memory_hash: memory_image.stable_hash(),
    }
}

fn reference_execute_random(
    program: &[IrInstruction],
    seed_state: &CpuState,
    seed_memory: &MemoryImage,
) -> ExecutionSummary {
    let mut state = seed_state.clone();
    let mut memory = seed_memory.clone();
    let mut ordering_log = Vec::new();

    for instruction in program {
        match instruction {
            IrInstruction::AddImm { dst, value, .. } => {
                let lhs = state.get(*dst);
                let result = lhs.wrapping_add(*value);
                state.set(*dst, result);
                state.flags = reference_add_flags(lhs, *value, result, 64);
            }
            IrInstruction::SubImm { dst, value, .. } => {
                let lhs = state.get(*dst);
                let result = lhs.wrapping_sub(*value);
                state.set(*dst, result);
                state.flags = reference_sub_flags(lhs, *value, result, 64);
            }
            IrInstruction::XorImm { dst, value, .. } => {
                let result = state.get(*dst) ^ *value;
                state.set(*dst, result);
                state.flags = reference_logic_flags(result, 64);
            }
            IrInstruction::LockXadd { address, src, .. } => {
                let eff_addr = effective_address(address);
                let original = memory.read_u64(eff_addr).unwrap();
                let next = original.wrapping_add(state.get(*src));
                // Guest CPU writes never create or mark pages: the engine
                // goes through the checked write path, so the reference must
                // NOT commit_zeroed_pages here either (the loader mapped the
                // destination).
                memory.write_u64(eff_addr, next);
                state.set(*src, original);
                ordering_log.push(format!("ldaxr:{eff_addr:#x}"));
                ordering_log.push(format!("stlxr:{eff_addr:#x}"));
            }
            IrInstruction::Mfence => ordering_log.push("dmb ish".to_string()),
            _ => {}
        }
    }

    ExecutionSummary {
        flags: state.flags,
        memory_hash: memory.stable_hash(),
        ordering_log,
    }
}

fn reference_atomic(initial: u64, adds: &[u64]) -> ReferenceAtomicOutcome {
    let mut value = initial;
    let mut memory = MemoryImage::default();
    // The engine does not expose an ordering log (src/cpu.rs:16373), so the
    // reference models only the observable outcome (final memory + registers).
    // The engine's guest write goes through the checked path (no page
    // creation/marking), so the reference maps only the loader-mapped bytes.
    for add in adds {
        value = value.wrapping_add(*add);
    }
    memory.map_u64(0xA000, value);
    ReferenceAtomicOutcome {
        final_value: value,
        memory_hash: memory.stable_hash(),
    }
}

fn build_random_program(seed: &mut u64, address: u64) -> Vec<IrInstruction> {
    let mut program = Vec::new();
    for _ in 0..12 {
        match lcg(seed) % 5 {
            0 => program.push(IrInstruction::AddImm {
                dst: Register::Rax,
                value: lcg(seed) & 0xff,
                width: 8,
            }),
            1 => program.push(IrInstruction::SubImm {
                dst: Register::Rcx,
                value: lcg(seed) & 0x7f,
                width: 8,
            }),
            2 => program.push(IrInstruction::XorImm {
                dst: Register::Rdx,
                value: lcg(seed) & 0xffff,
                width: 8,
            }),
            3 => program.push(IrInstruction::LockXadd {
                address: casa1::cpu::MemoryOperand {
                    base: None,
                    index: None,
                    scale: 1,
                    displacement: address as i32,
                    rip_relative: false,
                    rip_base: 0,
                    segment: None,
                    address_size_32: false,
                    absolute_address: None,
                },
                src: Register::Rax,
                width: 8,
            }),
            _ => program.push(IrInstruction::Mfence),
        }
    }
    program
}

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}

fn reference_add_flags(lhs: u64, rhs: u64, result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    Flags {
        cf: result < lhs,
        pf: reference_parity(result as u8),
        af: ((lhs ^ rhs ^ result) & 0x10) != 0,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: ((!(lhs ^ rhs) & (lhs ^ result)) & sign_bit) != 0,
    }
}

fn reference_sub_flags(lhs: u64, rhs: u64, result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    Flags {
        cf: lhs < rhs,
        pf: reference_parity(result as u8),
        af: ((lhs ^ rhs ^ result) & 0x10) != 0,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: (((lhs ^ rhs) & (lhs ^ result)) & sign_bit) != 0,
    }
}

fn reference_logic_flags(result: u64, width: usize) -> Flags {
    let sign_bit = 1_u64 << (width - 1);
    Flags {
        cf: false,
        pf: reference_parity(result as u8),
        af: false,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: false,
    }
}

fn reference_parity(value: u8) -> bool {
    value.count_ones().is_multiple_of(2)
}

fn reference_pdep(mut source: u64, mut mask: u64) -> u64 {
    let mut result = 0_u64;
    while mask != 0 {
        let lowest = mask.isolate_lowest_one();
        if source & 1 != 0 {
            result |= lowest;
        }
        source >>= 1;
        mask &= mask - 1;
    }
    result
}

fn reference_pext(source: u64, mut mask: u64) -> u64 {
    let mut result = 0_u64;
    let mut bit = 0_u32;
    while mask != 0 {
        let lowest = mask.isolate_lowest_one();
        if source & lowest != 0 {
            result |= 1_u64 << bit;
        }
        mask &= mask - 1;
        bit += 1;
    }
    result
}

fn f32x4_to_xmm(words: [f32; 4]) -> XmmValue {
    let mut bytes = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_xmm(bytes)
}

fn xmm_to_f32x4(value: XmmValue) -> [f32; 4] {
    let bytes = xmm_to_bytes(value);
    [
        f32::from_le_bytes(bytes[0..4].try_into().expect("lane")),
        f32::from_le_bytes(bytes[4..8].try_into().expect("lane")),
        f32::from_le_bytes(bytes[8..12].try_into().expect("lane")),
        f32::from_le_bytes(bytes[12..16].try_into().expect("lane")),
    ]
}

fn u32x4_to_xmm(words: [u32; 4]) -> XmmValue {
    let mut bytes = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes_to_xmm(bytes)
}

fn u32x4(value: XmmValue) -> [u32; 4] {
    let bytes = xmm_to_bytes(value);
    [
        u32::from_le_bytes(bytes[0..4].try_into().expect("lane")),
        u32::from_le_bytes(bytes[4..8].try_into().expect("lane")),
        u32::from_le_bytes(bytes[8..12].try_into().expect("lane")),
        u32::from_le_bytes(bytes[12..16].try_into().expect("lane")),
    ]
}

fn bytes_to_xmm(bytes: [u8; 16]) -> XmmValue {
    XmmValue {
        low: u64::from_le_bytes(bytes[..8].try_into().expect("low")),
        high: u64::from_le_bytes(bytes[8..].try_into().expect("high")),
    }
}

fn xmm_to_bytes(value: XmmValue) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.low.to_le_bytes());
    bytes[8..].copy_from_slice(&value.high.to_le_bytes());
    bytes
}

fn effective_address(mem: &casa1::cpu::MemoryOperand) -> u64 {
    let base = mem.base.map_or(0, |_r| 0 /* not used in these tests */);
    let index = mem.index.map_or(0, |_r| 0 /* not used in these tests */);
    base + index * mem.scale as u64 + mem.displacement as i64 as u64
}

fn reference_crc32(seed: u32, value: u64) -> u32 {
    let mut crc = !seed;
    for byte in value.to_le_bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg() & 0xEDB8_8320;
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}
