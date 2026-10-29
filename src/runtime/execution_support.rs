//! Instruction decoding caches, fault annotation, and execution budgets.

use super::*;

pub(crate) fn decode_current_instruction(
    engine: &CpuExecutionEngine,
    memory: &MemoryImage,
    rip: u64,
) -> AppResult<DecodedInstruction> {
    // Read up to 15 bytes (max x86 instruction length).  Unlike a blind
    // `read_into_slice` (which leaves the window zeroed when any trailing
    // byte is unmapped, causing misdecodes of garbage `add [eax], al`
    // sleds), the readable prefix is determined byte-by-byte so guest
    // callbacks sitting at the edge of a mapped region decode correctly.
    let mut bytes = [0_u8; 15];
    let mut readable = 0_usize;
    for (index, slot) in bytes.iter_mut().enumerate() {
        match memory.read_u8(rip + index as u64) {
            Ok(byte) => {
                *slot = byte;
                readable = index + 1;
            }
            Err(_) => break,
        }
    }
    // Try from LONGEST to SHORTEST.  Most x86 instructions are 2-6 bytes,
    // so trying the longest window first means we typically succeed on the
    // FIRST call to decode_block (1 call instead of 15).
    for len in (1..=readable.max(1)).rev() {
        if let Ok(decoded) = engine.decode_block(&bytes[..len], rip)
            && decoded.len() == 1
            && decoded[0].size == len
        {
            return Ok(decoded.into_iter().next().expect("decoded instruction"));
        }
    }
    let window = bytes[..readable]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    Err(AppError::new(
        ReasonCode::RcUnimplInsn,
        format!("failed to decode guest instruction at {rip:#x}: {window}"),
    ))
}

pub(crate) fn decode_current_instruction_cached(
    engine: &CpuExecutionEngine,
    memory: &MemoryImage,
    instruction_cache: &mut U64Map<CachedInstructionEntry>,
    instruction_cache_lru: &mut VecDeque<(u64, u64)>,
    instruction_cache_generation: &mut u64,
    instruction_cache_limit: usize,
    rip: u64,
) -> AppResult<Arc<CachedInstruction>> {
    if let Some(cached) = instruction_cache.get_mut(&rip) {
        // Verify the cached instruction still matches guest memory so
        // self-modifying code refreshes the cache. The check is a single
        // short read (≤15 bytes, the x86 max instruction length) on a stack
        // buffer — no heap allocation on the decode hot path.
        let size = cached.cached.decoded.size;
        let live_matches = if size <= 15 {
            let mut live = [0u8; 15];
            memory.read_into_slice(rip, &mut live[..size]).is_ok()
                && live[..size] == cached.cached.bytes[..]
        } else {
            false
        };
        if live_matches {
            *instruction_cache_generation = instruction_cache_generation.saturating_add(1);
            cached.generation = *instruction_cache_generation;
            instruction_cache_lru.push_back((rip, cached.generation));
            return Ok(Arc::clone(&cached.cached));
        }
        // Memory changed — fall through and re-decode below.
    }

    let decoded = decode_current_instruction(engine, memory, rip)?;
    let mut bytes = vec![0; decoded.size];
    memory.read_into_slice(rip, &mut bytes)?;
    *instruction_cache_generation = instruction_cache_generation.saturating_add(1);
    let cached = Arc::new(CachedInstruction { bytes, decoded });
    let generation = *instruction_cache_generation;

    instruction_cache.insert(
        rip,
        CachedInstructionEntry {
            cached: Arc::clone(&cached),
            generation,
        },
    );
    instruction_cache_lru.push_back((rip, generation));
    trim_instruction_cache(
        instruction_cache,
        instruction_cache_lru,
        instruction_cache_limit,
    );
    Ok(cached)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_basic_block_cached(
    engine: &mut CpuExecutionEngine,
    memory: &MemoryImage,
    instruction_cache: &mut U64Map<CachedInstructionEntry>,
    instruction_cache_lru: &mut VecDeque<(u64, u64)>,
    instruction_cache_generation: &mut u64,
    instruction_cache_limit: usize,
    basic_block_cache: &mut U64Map<CachedBlockEntry>,
    basic_block_cache_lru: &mut VecDeque<(u64, u64)>,
    basic_block_cache_generation: &mut u64,
    basic_block_cache_limit: usize,
    rip: u64,
) -> AppResult<Arc<CachedBlock>> {
    if let Some(cached) = basic_block_cache.get_mut(&rip) {
        // Verify the cached block still matches guest memory so
        // self-modifying code refreshes the cache. The check is a single
        // bounded read (≤ BASIC_BLOCK_MAX_BYTES = 512) into a stack
        // buffer — no heap allocation on the decode hot path.
        let len = cached.cached.bytes.len();
        let mut live = [0u8; BASIC_BLOCK_MAX_BYTES];
        let live_matches = len > 0
            && memory.read_into_slice(rip, &mut live[..len]).is_ok()
            && live[..len] == cached.cached.bytes[..];
        if live_matches {
            *basic_block_cache_generation = basic_block_cache_generation.saturating_add(1);
            cached.generation = *basic_block_cache_generation;
            basic_block_cache_lru.push_back((rip, cached.generation));
            return Ok(Arc::clone(&cached.cached));
        }
        // Memory changed — evict the stale entry (with its LRU records) and
        // fall through to re-decode below.
        let stale_generation = cached.generation;
        basic_block_cache_lru.retain(|(entry_rip, entry_generation)| {
            *entry_rip != rip || *entry_generation != stale_generation
        });
        basic_block_cache.remove(&rip);
    }

    let mut current_rip = rip;
    let mut bytes = Vec::new();
    let mut end_rip = rip;
    for _inst_idx in 0..BASIC_BLOCK_MAX_INSTRUCTIONS {
        let cached_instruction = decode_current_instruction_cached(
            engine,
            memory,
            instruction_cache,
            instruction_cache_lru,
            instruction_cache_generation,
            instruction_cache_limit,
            current_rip,
        )?;
        let decoded = &cached_instruction.decoded;
        let decoded_bytes = cached_instruction.bytes.as_slice();
        if !bytes.is_empty() && bytes.len() + decoded_bytes.len() > BASIC_BLOCK_MAX_BYTES {
            break;
        }
        end_rip = current_rip + decoded.size as u64;
        bytes.extend_from_slice(decoded_bytes);
        if instruction_controls_rip(decoded.opcode) || decoded.opcode == DecodedOpcode::Ret {
            break;
        }
        current_rip = end_rip;
    }

    if bytes.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("failed to build basic block at {rip:#x}"),
        ));
    }

    let translated = engine.translate_block(&bytes, rip)?;
    *basic_block_cache_generation = basic_block_cache_generation.saturating_add(1);
    let cached = Arc::new(CachedBlock {
        bytes,
        translated,
        start_rip: rip,
        end_rip,
    });
    let generation = *basic_block_cache_generation;
    basic_block_cache.insert(
        rip,
        CachedBlockEntry {
            cached: Arc::clone(&cached),
            generation,
        },
    );
    basic_block_cache_lru.push_back((rip, generation));
    trim_basic_block_cache(
        basic_block_cache,
        basic_block_cache_lru,
        basic_block_cache_limit,
    );
    Ok(cached)
}

pub(crate) fn trim_instruction_cache(
    instruction_cache: &mut U64Map<CachedInstructionEntry>,
    instruction_cache_lru: &mut VecDeque<(u64, u64)>,
    instruction_cache_limit: usize,
) {
    while instruction_cache.len() > instruction_cache_limit {
        let Some((rip, generation)) = instruction_cache_lru.pop_front() else {
            break;
        };
        let remove = instruction_cache
            .get(&rip)
            .map(|cached| cached.generation == generation)
            .unwrap_or(false);
        if remove {
            instruction_cache.remove(&rip);
        }
    }
}

pub(crate) fn trim_basic_block_cache(
    basic_block_cache: &mut U64Map<CachedBlockEntry>,
    basic_block_cache_lru: &mut VecDeque<(u64, u64)>,
    basic_block_cache_limit: usize,
) {
    while basic_block_cache.len() > basic_block_cache_limit {
        let Some((rip, generation)) = basic_block_cache_lru.pop_front() else {
            break;
        };
        let remove = basic_block_cache
            .get(&rip)
            .map(|cached| cached.generation == generation)
            .unwrap_or(false);
        if remove {
            basic_block_cache.remove(&rip);
        }
    }
}

pub(crate) fn annotate_guest_fault(
    error: AppError,
    memory: &MemoryImage,
    state: &CpuState,
) -> AppError {
    let rip = state.rip;
    let window = read_window(memory, rip, 15)
        .map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let registers = format!(
        "rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} rsp={:#x} rbp={:#x}",
        state.get(Register::Rax),
        state.get(Register::Rbx),
        state.get(Register::Rcx),
        state.get(Register::Rdx),
        state.get(Register::Rsi),
        state.get(Register::Rdi),
        state.get(Register::Rsp),
        state.get(Register::Rbp),
    );
    let mut wrapped = AppError::new(
        error.code,
        format!(
            "{} while executing guest instruction at {rip:#x}: {window} | {registers}",
            error.message
        ),
    );
    if let Ok(bytes) = read_window(memory, rip, 64) {
        let raw_block = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        match crate::cpu::decode_block(&bytes, rip, state.arch) {
            Ok(decoded) => {
                let summary = decoded
                    .iter()
                    .take(8)
                    .map(|instruction| {
                        format!(
                            "{:#x}:{:?} {:?}",
                            instruction.address, instruction.opcode, instruction.operands,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" || ");
                if !summary.is_empty() {
                    wrapped = wrapped.with_hint(format!("fault-block {summary}"));
                }
            }
            Err(decode_error) => {
                wrapped = wrapped.with_hint(format!(
                    "fault-block decode-failed={} bytes={raw_block}",
                    decode_error.message,
                ));
            }
        }
    }
    if let Ok(bytes) = read_window(memory, rip, 16)
        && bytes.starts_with(&[0xc5, 0xf5, 0x74, 0x01, 0xc5, 0xfd, 0xd7, 0xc0])
    {
        let caller = read_guest_u32(memory, state.get(Register::Rbp) + 4)
            .ok()
            .map(u64::from);
        let arg0 = read_guest_u32(memory, state.get(Register::Rbp) + 8)
            .ok()
            .map(u64::from)
            .unwrap_or(0);
        let arg1 = read_guest_u32(memory, state.get(Register::Rbp) + 12)
            .ok()
            .map(u64::from)
            .unwrap_or(0);
        let mut mapped = Vec::new();
        let mut first_unmapped = None;
        if arg0 != 0 {
            for offset in 0..64_u64 {
                match memory.read_u8(arg0 + offset) {
                    Ok(byte) => mapped.push(byte),
                    Err(_) => {
                        first_unmapped = Some(arg0 + offset);
                        break;
                    }
                }
            }
        }
        let hex = mapped
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii = mapped
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect::<String>();
        wrapped = wrapped.with_hint(format!(
                "steam-avx-strscan caller={} arg0={arg0:#x} arg1={arg1:#x} mapped_len={} first_unmapped={} hex=[{hex}] ascii={ascii}",
                caller
                    .map(|value| format!("{value:#x}"))
                    .unwrap_or_else(|| "<unavailable>".to_string()),
                mapped.len(),
                first_unmapped
                    .map(|value| format!("{value:#x}"))
                    .unwrap_or_else(|| "<none>".to_string()),
            ));
    }
    if rip == 0x401390 {
        let state_table = read_guest_u32(memory, 0x42a250).ok().map(u64::from);
        let record_base = read_guest_u32(memory, 0x42a270).ok().map(u64::from);
        let slot_values = state_table
            .map(|base| {
                (0..8)
                    .map(|index| {
                        let value = read_guest_u32(memory, base + 0x6c + index * 4)
                            .ok()
                            .map(u64::from)
                            .unwrap_or(0);
                        format!("{index}:{value:#x}")
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_else(|| "<unavailable>".to_string());
        let class_block = [0x4291e0_u64, 0x4291e4, 0x4291f0, 0x4291f4, 0x429204]
            .into_iter()
            .map(|address| {
                let value = read_guest_u32(memory, address)
                    .ok()
                    .map(u64::from)
                    .unwrap_or(0);
                format!("{address:#x}={value:#x}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let stack_probe = [
            state.get(Register::Rsp) + 4,
            state.get(Register::Rsp) + 8,
            state.get(Register::Rsp) + 12,
        ]
        .into_iter()
        .map(|address| {
            let value = read_guest_u32(memory, address)
                .ok()
                .map(u64::from)
                .unwrap_or(0);
            format!("{address:#x}={value:#x}")
        })
        .collect::<Vec<_>>()
        .join(",");
        let current_index = read_guest_u32(memory, state.get(Register::Rsp) + 8)
            .ok()
            .map(u64::from);
        let current_record = current_index
            .zip(record_base)
            .map(|(index, base)| {
                let record_address = base + index * 0x1c;
                let fields = (0..7)
                    .map(|slot| {
                        let value = read_guest_u32(memory, record_address + slot * 4)
                            .ok()
                            .map(u64::from)
                            .unwrap_or(0);
                        format!("{slot}:{value:#x}")
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("addr={record_address:#x} fields=[{fields}]")
            })
            .unwrap_or_else(|| "<unavailable>".to_string());
        wrapped = wrapped.with_hint(format!(
            "steam-401390 probe state_table={} record_base={} slot_6c=[{}] class_block=[{}] stack=[{}] current_record={}",
            state_table
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string()),
            record_base
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string()),
            slot_values,
            class_block,
            stack_probe,
            current_record,
        ));
    }
    if let Some(fault_address) = guest_access_violation_address(&error)
        && fault_address < 0x1000
    {
        let frame_probe = [
            state.get(Register::Rbp) + 4,
            state.get(Register::Rbp) + 8,
            state.get(Register::Rbp) + 12,
            state.get(Register::Rbp) + 16,
        ]
        .into_iter()
        .map(|address| {
            let value = read_guest_u32(memory, address)
                .ok()
                .map(u64::from)
                .unwrap_or(0);
            format!("{address:#x}={value:#x}")
        })
        .collect::<Vec<_>>()
        .join(",");
        let parent_ebp = read_guest_u32(memory, state.get(Register::Rbp))
            .ok()
            .map(u64::from)
            .unwrap_or(0);
        let parent_arg1 = if parent_ebp != 0 {
            read_guest_u32(memory, parent_ebp + 12).ok().map(u64::from)
        } else {
            None
        };
        let parent_arg2 = if parent_ebp != 0 {
            read_guest_u32(memory, parent_ebp + 16).ok().map(u64::from)
        } else {
            None
        };
        let parent_frame_probe = if parent_ebp != 0 {
            [
                parent_ebp + 4,
                parent_ebp + 8,
                parent_ebp + 12,
                parent_ebp + 16,
            ]
            .into_iter()
            .map(|address| {
                let value = read_guest_u32(memory, address)
                    .ok()
                    .map(u64::from)
                    .unwrap_or(0);
                format!("{address:#x}={value:#x}")
            })
            .collect::<Vec<_>>()
            .join(",")
        } else {
            "<unavailable>".to_string()
        };
        let parent_arg1_probe = match (parent_arg1, parent_arg2) {
            (Some(address), Some(length)) if address != 0 && length != 0 && length <= 64 => {
                match read_window(memory, address, length as usize) {
                    Ok(bytes) => {
                        let hex = bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let ascii = bytes
                            .iter()
                            .map(|byte| {
                                if byte.is_ascii_graphic() || *byte == b' ' {
                                    char::from(*byte)
                                } else {
                                    '.'
                                }
                            })
                            .collect::<String>();
                        let first_entry_probe = if bytes.len() >= 4 {
                            let first_entry =
                                u64::from(u32::from_le_bytes(bytes[0..4].try_into().unwrap()));
                            if first_entry != 0 {
                                match read_window(memory, first_entry, 64) {
                                    Ok(pointed_bytes) => {
                                        let end = pointed_bytes
                                            .iter()
                                            .position(|byte| *byte == 0)
                                            .unwrap_or(pointed_bytes.len());
                                        let pointed_ascii = pointed_bytes[..end]
                                            .iter()
                                            .map(|byte| {
                                                if byte.is_ascii_graphic() || *byte == b' ' {
                                                    char::from(*byte)
                                                } else {
                                                    '.'
                                                }
                                            })
                                            .collect::<String>();
                                        format!(
                                            " first_entry={first_entry:#x} first_ascii={pointed_ascii}"
                                        )
                                    }
                                    Err(_) => {
                                        format!(" first_entry={first_entry:#x} unreadable")
                                    }
                                }
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };
                        format!(
                            "addr={address:#x} len={length:#x} hex=[{hex}] ascii={ascii}{first_entry_probe}"
                        )
                    }
                    Err(_) => format!("addr={address:#x} len={length:#x} unreadable"),
                }
            }
            _ => "<unavailable>".to_string(),
        };
        wrapped = wrapped.with_hint(format!(
                "low-fault probe fault={fault_address:#x} rbx={:#x} frame=[{}] parent_ebp={parent_ebp:#x} parent_frame=[{}] parent_arg1={parent_arg1_probe}",
                state.get(Register::Rbx),
                frame_probe,
                parent_frame_probe,
            ));
    }
    for hint in error.reproduction_hints {
        wrapped = wrapped.with_hint(hint);
    }
    wrapped
}

pub(crate) fn guest_access_violation_address(error: &AppError) -> Option<u64> {
    if error.code != ReasonCode::RcUnimplInsn {
        return None;
    }
    let encoded = error.message.strip_prefix("unmapped guest memory at ")?;
    let hex = encoded.split_whitespace().next()?.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

/// Extracts the guest virtual address from a breakpoint fault error.
/// The error is produced by [`execute_ir_with_hashing`] when it encounters
/// [`IrInstruction::Breakpoint`] (raised by `int 0xCC`, `int 0x2d`, `int 0x03`).
pub(crate) fn guest_breakpoint_address(error: &AppError) -> Option<u64> {
    if error.code != ReasonCode::RcUnimplInsn {
        return None;
    }
    let encoded = error.message.strip_prefix("breakpoint at ")?;
    let hex = encoded.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

/// Maps a CPU-execution `AppError` to an NTSTATUS exception code and fault
/// address for SEH dispatch.  This is the catch-all fallback in
/// [`execute_ir_with_guest_exception_delivery`]: any `RcUnimplInsn` error
/// that is not an access-violation or breakpoint is routed through the
/// guest's SEH/VEH subsystem.
///
/// Returns `None` for access-violation and breakpoint errors (those are
/// handled by the dedicated helpers) and for non-`RcUnimplInsn` codes.
pub(crate) fn map_cpu_error_to_exception(error: &AppError) -> Option<(u32, u64)> {
    if error.code != ReasonCode::RcUnimplInsn {
        return None;
    }
    let msg = &error.message;
    // These are handled by the dedicated helpers above.
    if msg.starts_with("unmapped guest memory at ") {
        return None;
    }
    if msg.starts_with("breakpoint at ") {
        return None;
    }
    if msg == "integer divide by zero" {
        return Some((crate::seh::STATUS_INTEGER_DIVIDE_BY_ZERO, 0));
    }
    if msg == "integer divide overflow" {
        return Some((crate::seh::STATUS_INTEGER_OVERFLOW, 0));
    }
    // All other RcUnimplInsn errors represent instructions the CPU cannot
    // execute (unimplemented opcodes, unsupported operand forms, etc.).
    Some((crate::seh::STATUS_ILLEGAL_INSTRUCTION, 0))
}

pub(crate) fn pack_x86_eflags(state: &CpuState) -> u32 {
    let mut value = 0x2_u32 | ((state.eflags_extra & !0x8d7_u64) as u32);
    if state.flags.cf {
        value |= 1 << 0;
    }
    if state.flags.pf {
        value |= 1 << 2;
    }
    if state.flags.af {
        value |= 1 << 4;
    }
    if state.flags.zf {
        value |= 1 << 6;
    }
    if state.flags.sf {
        value |= 1 << 7;
    }
    if state.flags.of {
        value |= 1 << 11;
    }
    value
}

pub(crate) fn unpack_x86_eflags(state: &mut CpuState, value: u32) {
    state.flags.cf = value & (1 << 0) != 0;
    state.flags.pf = value & (1 << 2) != 0;
    state.flags.af = value & (1 << 4) != 0;
    state.flags.zf = value & (1 << 6) != 0;
    state.flags.sf = value & (1 << 7) != 0;
    state.flags.of = value & (1 << 11) != 0;
    state.eflags_extra = u64::from(value & !0x8d7_u32);
}

pub(crate) fn write_x86_exception_record(
    memory: &mut MemoryImage,
    base: u64,
    code: u32,
    fault_address: u64,
    exception_rip: u32,
    parameters: &[u32],
) {
    write_u32(memory, base, code);
    write_u32(memory, base + 4, 0);
    write_u32(memory, base + 8, 0);
    write_u32(memory, base + 12, exception_rip);
    let count = parameters.len().min(15);
    write_u32(memory, base + 16, count as u32);
    write_u32(memory, base + 20, 0);
    write_u32(memory, base + 24, fault_address as u32);
    for (index, parameter) in parameters.iter().take(count).enumerate() {
        write_u32(memory, base + 28 + (index as u64 * 4), *parameter);
    }
}

pub(crate) fn write_x86_context(memory: &mut MemoryImage, base: u64, state: &CpuState) {
    write_u32(memory, base, X86_CONTEXT_FLAGS_FULL);
    write_u32(memory, base + X86_CONTEXT_OFFSET_SEG_GS, 0);
    write_u32(memory, base + X86_CONTEXT_OFFSET_SEG_FS, 0);
    write_u32(memory, base + X86_CONTEXT_OFFSET_SEG_ES, 0x23);
    write_u32(memory, base + X86_CONTEXT_OFFSET_SEG_DS, 0x23);
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_EDI,
        state.get(Register::Rdi) as u32,
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_ESI,
        state.get(Register::Rsi) as u32,
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_EBX,
        state.get(Register::Rbx) as u32,
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_EDX,
        state.get(Register::Rdx) as u32,
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_ECX,
        state.get(Register::Rcx) as u32,
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_EAX,
        state.get(Register::Rax) as u32,
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_EBP,
        state.get(Register::Rbp) as u32,
    );
    write_u32(memory, base + X86_CONTEXT_OFFSET_EIP, state.rip as u32);
    write_u32(memory, base + X86_CONTEXT_OFFSET_SEG_CS, 0x1b);
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_EFLAGS,
        pack_x86_eflags(state),
    );
    write_u32(
        memory,
        base + X86_CONTEXT_OFFSET_ESP,
        state.get(Register::Rsp) as u32,
    );
    write_u32(memory, base + X86_CONTEXT_OFFSET_SEG_SS, 0x23);
}

pub(crate) fn read_x86_context(
    memory: &MemoryImage,
    base: u64,
    state: &mut CpuState,
) -> AppResult<()> {
    state.set(
        Register::Rdi,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EDI)?),
    );
    state.set(
        Register::Rsi,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_ESI)?),
    );
    state.set(
        Register::Rbx,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EBX)?),
    );
    state.set(
        Register::Rdx,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EDX)?),
    );
    state.set(
        Register::Rcx,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_ECX)?),
    );
    state.set(
        Register::Rax,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EAX)?),
    );
    state.set(
        Register::Rbp,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EBP)?),
    );
    state.rip = u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EIP)?);
    state.set(
        Register::Rsp,
        u64::from(read_guest_u32(memory, base + X86_CONTEXT_OFFSET_ESP)?),
    );
    unpack_x86_eflags(
        state,
        read_guest_u32(memory, base + X86_CONTEXT_OFFSET_EFLAGS)?,
    );
    Ok(())
}

pub(crate) fn instruction_controls_rip(opcode: DecodedOpcode) -> bool {
    matches!(
        opcode,
        DecodedOpcode::CallRel
            | DecodedOpcode::CallMemory
            | DecodedOpcode::CallRegister
            | DecodedOpcode::Jcc
            | DecodedOpcode::JmpRel
            | DecodedOpcode::JmpRegister
            | DecodedOpcode::JmpMemory
    )
}

pub(crate) fn advance_runtime_steps(
    runtime: &mut PeHostRuntime,
    steps: &mut u64,
    instruction_budget: u64,
    consumed_instructions: u64,
    memory: &MemoryImage,
    state: &CpuState,
    test_id: &str,
) -> AppResult<()> {
    let next_steps = steps.saturating_add(consumed_instructions);
    if RUN_DEADLINE_EXPIRED.load(std::sync::atomic::Ordering::Acquire) {
        // Mirrors the instruction-budget error so the runner's recovery
        // path produces diagnostic artifacts for deadline-capped runs.
        return Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!(
                "PE runtime exceeded the wall-clock deadline for {test_id} at {:#x}: steps={next_steps}",
                state.rip
            ),
        ));
    }
    if state.arch == GuestArch::X86 && runtime.enable_steam_tracing {
        let rip = state.rip;
        let rva = rip.saturating_sub(runtime.mapped_image_base);
        if runtime.steam_owner_allocator_probe_count < 16
            && (0x000a_bfd7..=0x000a_c04b).contains(&rva)
        {
            let counter_str = probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_873c)
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string());
            runtime.push_trace(
                "process",
                "SteamOwnerAllocatorStep",
                BTreeMap::from([
                    ("rip_rva".to_string(), json!(format!("{rva:#x}"))),
                    ("counter".to_string(), json!(counter_str)),
                    (
                        "eax".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rax))),
                    ),
                    (
                        "ecx".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rcx))),
                    ),
                    (
                        "esi".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rsi))),
                    ),
                    (
                        "ebp".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rbp))),
                    ),
                    (
                        "esp".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rsp))),
                    ),
                ]),
                json!(state.get(Register::Rax)),
            );
            runtime.steam_owner_allocator_probe_count += 1;
        }
        if runtime.steam_4ae970_probe_count < 16 && (0x000a_e970..=0x000a_ea10).contains(&rva) {
            let counter_str = probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_873c)
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string());
            runtime.push_trace(
                "process",
                "SteamHashStep",
                BTreeMap::from([
                    ("rip_rva".to_string(), json!(format!("{rva:#x}"))),
                    ("owner_counter".to_string(), json!(counter_str)),
                    (
                        "edi".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rdi))),
                    ),
                    (
                        "ebx".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rbx))),
                    ),
                    (
                        "ecx".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rcx))),
                    ),
                    (
                        "ebp".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rbp))),
                    ),
                    (
                        "esp".to_string(),
                        json!(format!("{:#x}", state.get(Register::Rsp))),
                    ),
                ]),
                json!(state.get(Register::Rax)),
            );
            runtime.steam_4ae970_probe_count += 1;
        }
    }
    if next_steps > instruction_budget {
        let rip = state.rip;
        let window = read_window(memory, rip, 15)
            .map(|bytes| {
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|_| "<unavailable>".to_string());
        let register_context = match state.arch {
            GuestArch::X64 => format!(
                " rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x}",
                state.get(Register::Rax),
                state.get(Register::Rbx),
                state.get(Register::Rcx),
                state.get(Register::Rdx),
                state.get(Register::Rsi),
                state.get(Register::Rdi),
            ),
            GuestArch::X86 => format!(
                " eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x} ebp={:#x} esp={:#x}",
                state.get(Register::Rax),
                state.get(Register::Rbx),
                state.get(Register::Rcx),
                state.get(Register::Rdx),
                state.get(Register::Rsi),
                state.get(Register::Rdi),
                state.get(Register::Rbp),
                state.get(Register::Rsp),
            ),
        };
        let steam_hot_rva = rip.saturating_sub(runtime.mapped_image_base);
        let steam_hot_context = if runtime.enable_steam_tracing
            && state.arch == GuestArch::X86
            && ((0x000a_e970..=0x000a_ea10).contains(&steam_hot_rva) || rip == 0x190a_e9dc)
        {
            format!(
                " steam_frame_key={} steam_owner_counter={} steam_stack_return={}",
                probe_read_guest_u32(memory, state.get(Register::Rbp) + 8)
                    .map(|value| format!("{value:#x}"))
                    .unwrap_or_else(|| "<unavailable>".to_string()),
                probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_873c)
                    .map(|value| format!("{value:#x}"))
                    .unwrap_or_else(|| "<unavailable>".to_string()),
                probe_read_guest_u32(memory, state.get(Register::Rsp))
                    .map(|value| format!(
                        "{:#x}",
                        u64::from(value).saturating_sub(runtime.mapped_image_base)
                    ))
                    .unwrap_or_else(|| "<unavailable>".to_string()),
            )
        } else {
            String::new()
        };
        return Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!(
                "PE runtime exceeded the instruction budget for {test_id} at {rip:#x}: {window} steps={next_steps} budget={instruction_budget}{register_context}{steam_hot_context}"
            ),
        ));
    }

    let previous_poll_bucket = *steps >> 8;
    let next_poll_bucket = next_steps >> 8;
    *steps = next_steps;
    for _ in previous_poll_bucket..next_poll_bucket {
        runtime.poll_live_input()?;
    }
    Ok(())
}

pub(crate) fn pe_runtime_instruction_budget(
    env: &BTreeMap<String, String>,
    live_mode: bool,
) -> AppResult<u64> {
    match env
        .get(PE_RUNTIME_BUDGET_ENV)
        .cloned()
        .or_else(|| std::env::var(PE_RUNTIME_BUDGET_ENV).ok())
    {
        None => Ok(if live_mode {
            u64::MAX
        } else {
            PE_RUNTIME_INSTRUCTION_BUDGET
        }),
        Some(raw) => raw.parse::<u64>().map_err(|error| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("invalid {PE_RUNTIME_BUDGET_ENV} value {raw:?}"),
            )
            .with_hint(error.to_string())
        }),
    }
}
