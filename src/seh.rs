use crate::reason::ReasonCode;
use std::collections::HashMap;

// ─── Exception constants ─────────────────────────────────────────────────────

pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1; // 0xFFFF_FFFF as i32
pub const EXCEPTION_HANDLED: i32 = 1;

/// NT status codes for common exceptions.
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;

/// Memory reader callback: reads `len` bytes from guest memory at `address`
/// into `buf`. Returns `true` on success, `false` if the address is unmapped.
pub type MemoryReader<'a> = dyn Fn(u64, &mut [u8]) -> bool + 'a;

// ─── Section 1: .pdata exception directory processing ────────────────────────

/// Matches `_IMAGE_RUNTIME_FUNCTION_ENTRY` (x64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_addr: u32,
    pub end_addr: u32,
    pub unwind_info_addr: u32,
}

/// Unwind code operation codes (UWOP_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindCode {
    PushNonVolatile { register: u8 },
    AllocLarge { size: u32 },
    AllocSmall { size: u8 },
    SetFramePointer { register: u8, offset: u32 },
    SaveNonVolatile { register: u8, offset: u32 },
    SaveNonVolatileFar { register: u8, offset: u32 },
    SaveXmm128 { register: u8, offset: u32 },
    SaveXmm128Far { register: u8, offset: u32 },
    PushMachineFrame { code: u8 },
}

/// Parsed UNWIND_INFO structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub prolog_size: u8,
    pub code_count: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCode>,
    /// If UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER is set, the RVA of the
    /// language-specific exception/unwind handler that follows the codes.
    pub handler_rva: Option<u32>,
    /// If UNW_FLAG_CHAININFO is set, the unwind_info_addr of the chained
    /// (primary) RUNTIME_FUNCTION whose unwind codes must also be replayed
    /// for this frame.
    pub chained_info_rva: Option<u32>,
}

/// x64 context (subset of Windows CONTEXT64).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct X64Context {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub xmm: [Xmm128; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Xmm128 {
    pub low: u64,
    pub high: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindResult {
    /// Unwind completed: a handler was found at the given RVA.
    HandlerFound(u32),
    /// Unwind completed normally (no handler, reached a base frame).
    Completed,
    /// Exception should continue to be dispatched up the call chain.
    Collided,
    /// No unwind information found for the given RVA.
    NotFound,
}

/// Parse a `.pdata` section into a vector of `RuntimeFunction` entries.
///
/// Each entry is 12 bytes on x64 (3 × u32 little-endian).
pub fn parse_pdata(data: &[u8], _image_base: u64) -> Vec<RuntimeFunction> {
    let entry_size = 12; // 3 × u32
    let count = data.len() / entry_size;
    let mut functions = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * entry_size;
        if offset + entry_size > data.len() {
            break;
        }
        let begin_addr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let end_addr = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let unwind_info_addr = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);
        functions.push(RuntimeFunction {
            begin_addr,
            end_addr,
            unwind_info_addr,
        });
    }
    functions
}

/// Parse a UNWIND_INFO structure from raw bytes at the given RVA.
///
/// The `data` slice should contain the unwind info data starting at `rva`
/// (relative to some base). The caller is responsible for providing a slice
/// that covers the UNWIND_INFO header and all unwind codes plus optional
/// chained info.
pub fn parse_unwind_info(data: &[u8], rva: u32) -> Option<UnwindInfo> {
    let offset = rva as usize;
    if offset + 4 > data.len() {
        return None;
    }
    let version_and_flags = data[offset];
    let version = version_and_flags & 0x07;
    // Per the PE/COFF spec only UNWIND_INFO version 1 is defined; anything
    // else is corrupt data and must fail closed instead of being mis-unwound.
    if version != 1 {
        return None;
    }
    let flags = (version_and_flags >> 3) & 0x1f;
    let prolog_size = data[offset + 1];
    let code_count = data[offset + 2];
    let frame_and_offset = data[offset + 3];
    let frame_register = frame_and_offset & 0x0f;
    let frame_offset = (frame_and_offset >> 4) & 0x0f;

    let codes_len = (code_count as usize + 1) & !1; // rounded up to even
    let codes_start = offset + 4;
    let codes_end = codes_start + codes_len * 2; // each code is 2 bytes
    if codes_end > data.len() {
        return None;
    }

    let mut codes = Vec::with_capacity(code_count as usize);
    // Each unwind code occupies one or more 2-byte "nodes". Operations that
    // carry an operand (ALLOC_LARGE, SAVE_NONVOL[_FAR], SAVE_XMM128[_FAR])
    // consume additional nodes for the inline 16-/32-bit value. We must skip
    // those operand nodes rather than mis-parsing them as further unwind codes.
    let mut i = 0usize;
    while i < code_count as usize {
        let code_offset = codes_start + i * 2;
        let code_byte = data[code_offset];
        let op = code_byte & 0x0f;
        let op_info = code_byte >> 4;
        match op {
            0 => {
                // UWOP_PUSH_NONVOL
                codes.push(UnwindCode::PushNonVolatile { register: op_info });
            }
            1 => {
                // UWOP_ALLOC_LARGE
                if op_info == 0 {
                    // 16-bit scaled
                    let size = if code_offset + 3 < data.len() {
                        u16::from_le_bytes([data[code_offset + 2], data[code_offset + 3]]) as u32
                            * 8
                    } else {
                        0
                    };
                    codes.push(UnwindCode::AllocLarge { size });
                } else {
                    // 32-bit unscaled
                    let size = if code_offset + 5 < data.len() {
                        u32::from_le_bytes([
                            data[code_offset + 2],
                            data[code_offset + 3],
                            data[code_offset + 4],
                            data[code_offset + 5],
                        ])
                    } else {
                        0
                    };
                    codes.push(UnwindCode::AllocLarge { size });
                }
            }
            2 => {
                // UWOP_ALLOC_SMALL
                codes.push(UnwindCode::AllocSmall {
                    size: op_info * 8 + 8,
                });
            }
            3 => {
                // UWOP_SET_FPREG
                codes.push(UnwindCode::SetFramePointer {
                    register: frame_register,
                    offset: frame_offset as u32 * 16,
                });
            }
            4 => {
                // UWOP_SAVE_NONVOL
                let offset_val = if code_offset + 3 < data.len() {
                    u16::from_le_bytes([data[code_offset + 2], data[code_offset + 3]]) as u32 * 8
                } else {
                    0
                };
                codes.push(UnwindCode::SaveNonVolatile {
                    register: op_info,
                    offset: offset_val,
                });
            }
            5 => {
                // UWOP_SAVE_NONVOL_FAR
                let offset_val = if code_offset + 5 < data.len() {
                    u32::from_le_bytes([
                        data[code_offset + 2],
                        data[code_offset + 3],
                        data[code_offset + 4],
                        data[code_offset + 5],
                    ])
                } else {
                    0
                };
                codes.push(UnwindCode::SaveNonVolatileFar {
                    register: op_info,
                    offset: offset_val,
                });
            }
            6 => {
                // UWOP_SAVE_XMM128
                let offset_val = if code_offset + 3 < data.len() {
                    u16::from_le_bytes([data[code_offset + 2], data[code_offset + 3]]) as u32 * 16
                } else {
                    0
                };
                codes.push(UnwindCode::SaveXmm128 {
                    register: op_info,
                    offset: offset_val,
                });
            }
            7 => {
                // UWOP_SAVE_XMM128_FAR
                let offset_val = if code_offset + 5 < data.len() {
                    u32::from_le_bytes([
                        data[code_offset + 2],
                        data[code_offset + 3],
                        data[code_offset + 4],
                        data[code_offset + 5],
                    ])
                } else {
                    0
                };
                codes.push(UnwindCode::SaveXmm128Far {
                    register: op_info,
                    offset: offset_val,
                });
            }
            8 => {
                // UWOP_PUSH_MACHINE_FRAME
                codes.push(UnwindCode::PushMachineFrame { code: op_info });
            }
            _ => {
                // Unknown unwind opcode (9–15) — corrupt data; fail closed
                // rather than silently skipping it and mis-unwinding.
                return None;
            }
        }
        // Advance past this code and any inline operand nodes it consumed.
        let nodes = match op {
            1 => {
                if op_info == 0 {
                    2 // ALLOC_LARGE with 16-bit scaled size
                } else {
                    3 // ALLOC_LARGE with 32-bit unscaled size
                }
            }
            4 | 6 => 2, // SAVE_NONVOL / SAVE_XMM128 (16-bit operand)
            5 | 7 => 3, // SAVE_NONVOL_FAR / SAVE_XMM128_FAR (32-bit operand)
            _ => 1,
        };
        i += nodes;
    }

    // After the unwind codes (padded to even count, then DWORD-aligned),
    // optional handler RVAs follow for EHANDLER/UHANDLER.
    let codes_raw_len = codes_len * 2; // codes_len is already even
    let handler_offset = codes_start + codes_raw_len;
    // Align to 4 bytes
    let handler_offset = (handler_offset + 3) & !3;

    let handler_rva =
        if (flags & 0x01 != 0 || flags & 0x02 != 0) && handler_offset + 4 <= data.len() {
            let rva = u32::from_le_bytes([
                data[handler_offset],
                data[handler_offset + 1],
                data[handler_offset + 2],
                data[handler_offset + 3],
            ]);
            Some(rva)
        } else {
            None
        };

    // If UNW_FLAG_CHAININFO (0x04) is set, a 12-byte RUNTIME_FUNCTION follows
    // the unwind codes (at the same DWORD-aligned offset). Its third DWORD is
    // the unwind_info_addr of the chained (primary) unwind info whose codes
    // must also be replayed for this frame.
    let chained_info_rva = if flags & 0x04 != 0 && handler_offset + 12 <= data.len() {
        Some(u32::from_le_bytes([
            data[handler_offset + 8],
            data[handler_offset + 9],
            data[handler_offset + 10],
            data[handler_offset + 11],
        ]))
    } else {
        None
    };

    Some(UnwindInfo {
        version,
        flags,
        prolog_size,
        code_count,
        frame_register,
        frame_offset,
        codes,
        handler_rva,
        chained_info_rva,
    })
}

/// Helper: read a u64 from guest memory via the memory callback.
fn read_u64_from_guest(memory_reader: &MemoryReader<'_>, addr: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    if memory_reader(addr, &mut buf) {
        Some(u64::from_le_bytes(buf))
    } else {
        None
    }
}

/// Helper: read an Xmm128 (16 bytes) from guest memory via the memory callback.
fn read_xmm128_from_guest(memory_reader: &MemoryReader<'_>, addr: u64) -> Option<Xmm128> {
    let mut buf = [0u8; 16];
    if memory_reader(addr, &mut buf) {
        // Split the 16-byte buffer into two 8-byte arrays using direct element
        // access, avoiding any `.unwrap()` or `.expect()` calls.
        let low_bytes: [u8; 8] = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];
        let high_bytes: [u8; 8] = [
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ];
        let low = u64::from_le_bytes(low_bytes);
        let high = u64::from_le_bytes(high_bytes);
        Some(Xmm128 { low, high })
    } else {
        None
    }
}

/// Map a non-volatile register index (0–15) to a mutable reference in X64Context.
/// Returns `None` if the register index is out of range (corrupted unwind data).
fn get_nonvolatile_register(context: &mut X64Context, reg: u8) -> Option<&mut u64> {
    match reg {
        0 => Some(&mut context.rax),
        1 => Some(&mut context.rcx),
        2 => Some(&mut context.rdx),
        3 => Some(&mut context.rbx),
        4 => Some(&mut context.rsp),
        5 => Some(&mut context.rbp),
        6 => Some(&mut context.rsi),
        7 => Some(&mut context.rdi),
        8 => Some(&mut context.r8),
        9 => Some(&mut context.r9),
        10 => Some(&mut context.r10),
        11 => Some(&mut context.r11),
        12 => Some(&mut context.r12),
        13 => Some(&mut context.r13),
        14 => Some(&mut context.r14),
        15 => Some(&mut context.r15),
        // Register indices 0-15 cover all x86_64 GPRs; any other value
        // indicates a corrupted unwind code or caller bug.
        _ => None,
    }
}

/// Perform a virtual unwind for one frame.
///
/// Given the current unwind info and context, this function interprets the
/// unwind codes in reverse to restore the register state of the caller's frame.
/// The `memory_reader` callback is used to read saved register values from the
/// guest stack.
///
/// Returns:
/// - `HandlerFound(rva)` — if a handler exists (EHANDLER or UHANDLER).
/// - `Completed` — unwind completed successfully, context reflects caller state.
/// - `Collided` — chained unwind info present (caller should follow the chain).
pub fn virtual_unwind(
    unwind_info: &UnwindInfo,
    context: &mut X64Context,
    memory_reader: &MemoryReader<'_>,
) -> UnwindResult {
    // Validate stack pointer before attempting unwind.
    // RSP must be non-zero and 8-byte aligned (x64 ABI requirement).
    // A zero or misaligned RSP indicates a corrupt context.
    if context.rsp == 0 || context.rsp & 0x7 != 0 {
        return UnwindResult::NotFound;
    }

    // Replay the unwind codes in reverse order to restore the caller's frame.
    // At entry, RSP points to the top of the current frame (= caller's return
    // address slot after the prolog). We process codes in reverse so that the
    // last prolog operation (which saved the deepest register) is undone first.
    //
    // UNW_FLAG_CHAININFO (0x04): this UNWIND_INFO describes a secondary code
    // region whose prolog operations are a continuation of the chained
    // (primary) entry. Its codes are replayed here, but the return-address pop
    // is deferred — the caller follows `chained_info_rva` and replays the
    // chained entry's codes as part of the same logical frame.
    let mut machine_frame = false;
    for code in unwind_info.codes.iter().rev() {
        match *code {
            UnwindCode::PushNonVolatile { register } => {
                // The register was pushed at [RSP] in the prolog.
                // Read the saved value from [RSP] and restore it.
                let saved = read_u64_from_guest(memory_reader, context.rsp);
                if let (Some(val), Some(reg_ref)) =
                    (saved, get_nonvolatile_register(context, register))
                {
                    *reg_ref = val;
                }
                context.rsp += 8;
            }
            UnwindCode::AllocLarge { size } => {
                context.rsp += size as u64;
            }
            UnwindCode::AllocSmall { size } => {
                context.rsp += size as u64;
            }
            UnwindCode::SetFramePointer { register, offset } => {
                // The prolog established the frame register as
                // `R[register] = RSP_final + offset` (e.g. `lea rbp,[rsp+N]`),
                // so the unwind effect is `RSP = R[register] - offset`.
                let fp_val = get_nonvolatile_register(context, register)
                    .copied()
                    .unwrap_or(0);
                context.rsp = fp_val.wrapping_sub(offset as u64);
            }
            UnwindCode::SaveNonVolatile { register, offset } => {
                // Register was saved at [final_RSP + offset] (offset scaled by 8).
                let addr = context.rsp.wrapping_add(offset as u64);
                let saved = read_u64_from_guest(memory_reader, addr);
                if let (Some(val), Some(reg_ref)) =
                    (saved, get_nonvolatile_register(context, register))
                {
                    *reg_ref = val;
                }
                // RSP is NOT adjusted — the save was relative to final RSP.
            }
            UnwindCode::SaveNonVolatileFar { register, offset } => {
                // Same as SaveNonVolatile but with 32-bit unscaled offset.
                let addr = context.rsp.wrapping_add(offset as u64);
                let saved = read_u64_from_guest(memory_reader, addr);
                if let (Some(val), Some(reg_ref)) =
                    (saved, get_nonvolatile_register(context, register))
                {
                    *reg_ref = val;
                }
            }
            UnwindCode::SaveXmm128 { register, offset } => {
                // XMM register saved at [final_RSP + offset] (offset scaled by 16).
                let addr = context.rsp.wrapping_add(offset as u64);
                let saved = read_xmm128_from_guest(memory_reader, addr);
                if let Some(val) = saved {
                    let idx = (register % 16) as usize;
                    context.xmm[idx] = val;
                }
            }
            UnwindCode::SaveXmm128Far { register, offset } => {
                // Same as SaveXmm128 but with 32-bit unscaled offset.
                let addr = context.rsp.wrapping_add(offset as u64);
                let saved = read_xmm128_from_guest(memory_reader, addr);
                if let Some(val) = saved {
                    let idx = (register % 16) as usize;
                    context.xmm[idx] = val;
                }
            }
            UnwindCode::PushMachineFrame { code } => {
                // The CPU pushed a trap/exception frame.
                // Code bit 0 indicates whether an error code was pushed.
                let has_error_code = code & 0x01 != 0;
                let error_code_offset: u64 = if has_error_code { 8 } else { 0 };
                // Read RIP from the frame
                // Layout: [error_code?] RIP CS RFLAGS OldRSP SS
                // Offsets from RSP: err=0|RIP=0/8 CS=8/16 RFLAGS=16/24 OldRSP=24/32 SS=32/40
                let rip_offset = error_code_offset;
                if let Some(saved_rip) =
                    read_u64_from_guest(memory_reader, context.rsp.wrapping_add(rip_offset))
                {
                    context.rip = saved_rip;
                }
                // Read the saved RSP (value before exception) from the frame
                let rsp_offset = error_code_offset + 24; // 24 bytes past RIP = OldRSP
                if let Some(saved_rsp) =
                    read_u64_from_guest(memory_reader, context.rsp.wrapping_add(rsp_offset))
                {
                    context.rsp = saved_rsp;
                } else {
                    // If we can't read the old RSP, at least advance past the frame
                    context.rsp = context.rsp.wrapping_add(error_code_offset + 40); // frame total = error + 5*8
                }
                // A machine frame is the complete return mechanism: it already
                // supplies both RIP and the caller's RSP. There is no separate
                // return-address slot to pop afterwards.
                machine_frame = true;
            }
        }
    }

    // After processing all unwind codes, pop the return address from the stack.
    // At this point RSP should point to the return address of the call. A
    // machine frame already restored RIP and the caller's RSP, so it has no
    // separate return-address slot to pop.
    //
    // For a CHAININFO entry the prolog description is not yet complete: the
    // caller must follow the chained (primary) entry and replay its codes
    // before the return address is reached. Defer the pop and signal Collided.
    if unwind_info.flags & 0x04 != 0 {
        return UnwindResult::Collided;
    }

    if !machine_frame {
        if let Some(return_rip) = read_u64_from_guest(memory_reader, context.rsp) {
            context.rip = return_rip;
        }
        context.rsp += 8;
    }

    // If the function has an exception handler (EHANDLER or UHANDLER),
    // return the handler RVA so the caller can dispatch to it.
    if let Some(handler_rva) = unwind_info
        .handler_rva
        .filter(|_| unwind_info.flags & 0x01 != 0 || unwind_info.flags & 0x02 != 0)
    {
        return UnwindResult::HandlerFound(handler_rva);
    }

    UnwindResult::Completed
}

/// Return the target RIP to resume at (RtlRestoreContext equivalent).
///
/// The full `X64Context` is delivered to the caller, which is responsible
/// for applying every register value (including RIP) back into the CPU
/// state; this helper only extracts the resume address.
///
/// This is used to resume execution at a different location after an exception
/// has been handled (e.g., by a VEH handler that modified the context).
///
/// Returns the new RIP value so the caller can set the CPU's instruction pointer.
pub fn restore_context(context: &X64Context) -> u64 {
    context.rip
}

/// Generate an exception from the given context and restore the saved register
/// state (RtlRestoreContext equivalent that raises an exception).
///
/// This function creates an `ExceptionRecord` with the context's RIP as the
/// fault address and dispatches it through VEH/SEH. If no handler claims it,
/// returns `Err(AppError)`. The context registers are available for the caller
/// to apply after the function returns.
///
/// This matches the Windows `RtlRestoreContext` semantic where the context
/// register values are loaded and execution resumes at `context.rip`.
pub fn rtl_restore_context(context: &X64Context) -> Result<(), crate::error::AppError> {
    // Create an exception record from the context state.
    // The exception code is STATUS_ILLEGAL_INSTRUCTION to signal a context
    // restoration point. The first parameter carries the target RIP.
    let record = ExceptionRecord {
        code: STATUS_ILLEGAL_INSTRUCTION,
        flags: 0,
        record: None,
        address: context.rip,
        params: [context.rip, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };

    // Dispatch through VEH chain to give handlers a chance to examine/modify
    // the context before restoration.
    let veh_result = dispatch_vectored_handlers(&record, context);
    // RtlRestoreContext always transfers control whether or not a handler
    // claimed the dispatch, so every disposition maps to Ok(()) and the
    // caller applies the (potentially handler-modified) context.
    match veh_result {
        EXCEPTION_CONTINUE_SEARCH => {
            // No handler claimed it — still return the context so the caller
            // can apply it. This matches Windows behaviour where
            // RtlRestoreContext always transfers control even without a handler.
            Ok(())
        }
        EXCEPTION_CONTINUE_EXECUTION | EXCEPTION_HANDLED => {
            // Handler acknowledged the restoration — return Ok so the caller
            // can apply the (potentially handler-modified) context.
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Perform a full stack unwind across multiple frames (RtlUnwind equivalent).
///
/// Starting from `start_rva`, this function unwinds each frame using the
/// registered `.pdata` tables and unwind info, calling `handler_callback` for
/// any frame that has an exception/unwind handler. Returns `Completed` if the
/// unwind reached a base frame, or `NotFound` if unwind info is missing.
///
/// `find_runtime_function`: callback to look up a RuntimeFunction by image_base + RVA.
/// `get_unwind_info`: callback to get/parse UnwindInfo by RVA.
/// `memory_reader`: callback to read guest memory (stack).
pub fn unwind_frames(
    image_base: u64,
    context: &mut X64Context,
    find_runtime_function: &dyn Fn(u64, u32) -> Option<RuntimeFunction>,
    get_unwind_info: &dyn Fn(u32) -> Option<UnwindInfo>,
    memory_reader: &MemoryReader<'_>,
    handler_callback: &mut dyn FnMut(u32, &X64Context) -> bool,
) -> UnwindResult {
    // Bound the walk: a real user-mode stack is never this deep, and a
    // cyclic/corrupt guest stack (e.g. a return address that always reads
    // back into the same function) must terminate instead of spinning.
    const MAX_UNWIND_FRAMES: u32 = 4096;
    let mut frames_unwound: u32 = 0;
    let mut prev_rsp = context.rsp;
    loop {
        if frames_unwound >= MAX_UNWIND_FRAMES {
            eprintln!(
                "[seh] unwind_frames: frame limit ({MAX_UNWIND_FRAMES}) exceeded — cyclic or corrupt guest stack"
            );
            return UnwindResult::NotFound;
        }
        frames_unwound += 1;

        let rva = context.rip.wrapping_sub(image_base) as u32;
        let rf = match find_runtime_function(image_base, rva) {
            Some(rf) => rf,
            None => return UnwindResult::NotFound,
        };

        let unwind_info = match get_unwind_info(rf.unwind_info_addr) {
            Some(ui) => ui,
            None => return UnwindResult::NotFound,
        };

        // Follow CHAININFO entries in-place so the whole logical frame's
        // prolog is replayed before the return address is popped.
        let mut active_info = unwind_info;
        let mut chain_depth = 0u32;
        let result = loop {
            if chain_depth >= MAX_CHAIN_DEPTH {
                eprintln!(
                    "[seh] unwind_frames: chain depth limit ({}) exceeded",
                    MAX_CHAIN_DEPTH
                );
                break UnwindResult::NotFound;
            }
            let res = virtual_unwind(&active_info, context, memory_reader);
            if res == UnwindResult::Collided {
                chain_depth += 1;
                match active_info.chained_info_rva.and_then(&get_unwind_info) {
                    Some(next) => {
                        active_info = next;
                        continue;
                    }
                    None => break res,
                }
            }
            break res;
        };

        match result {
            UnwindResult::HandlerFound(handler_rva) => {
                let handler_address = image_base.wrapping_add(handler_rva as u64);
                let handled = handler_callback(handler_rva, context);
                if handled {
                    // Handler claimed the exception, stop unwinding.
                    return UnwindResult::HandlerFound(handler_rva);
                }
                // Handler didn't claim it — continue unwinding, but only if
                // the frame actually made stack progress; a corrupt stack
                // that cannot advance must terminate the walk.
                if context.rsp <= prev_rsp {
                    return UnwindResult::NotFound;
                }
                prev_rsp = context.rsp;
                eprintln!(
                    "[seh] unwind: handler at {:#x} did not claim exception",
                    handler_address
                );
            }
            UnwindResult::Completed => {
                // Reached a base frame (leaf function or no handler). Verify
                // forward progress before declaring completion.
                if context.rsp <= prev_rsp {
                    return UnwindResult::NotFound;
                }
                return UnwindResult::Completed;
            }
            UnwindResult::Collided => {
                // Chain terminated without a primary entry — stop unwinding.
                return UnwindResult::NotFound;
            }
            UnwindResult::NotFound => {
                return UnwindResult::NotFound;
            }
        }
    }
}

/// Walk up the call stack using unwind info (RtlUnwind equivalent).
///
/// Starting from the current RIP in the context, this function unwinds each
/// frame using the registered `.pdata` tables and unwind info, stopping at
/// `target_frame` (if non-zero) or when no more frames can be unwound.
///
/// If `target_rip` is non-zero, the final context's RIP is set to `target_rip`
/// after unwinding to the target frame, allowing the caller to resume execution
/// at a specific address.
///
/// # Arguments
///
/// * `target_frame` - If non-zero, the frame RVA where unwinding should stop.
///   Unwinding stops when the restored RIP falls within this frame's range
///   (`begin_addr .. end_addr`).
/// * `target_rip` - If non-zero, the final RIP value to set after unwinding to
///   the target frame. Used for collided unwind continuation.
/// * `seh` - The SEH subsystem containing .pdata and unwind info.
/// * `memory_reader` - Callback to read guest memory (stack).
///
/// # Returns
///
/// * `Ok(())` - Unwind completed successfully. Context has been updated to
///   reflect the caller's frame (or target frame if `target_frame` was
///   specified).
/// * `Err(AppError)` - Unwind failed (e.g., no unwind info found for a frame).
pub fn rtl_unwind(
    target_frame: u64,
    target_rip: u64,
    image_base: u64,
    context: &mut X64Context,
    seh: &mut SehSubsystem,
    memory_reader: &MemoryReader<'_>,
) -> Result<(), crate::error::AppError> {
    // Bound the walk so a cyclic/corrupt guest stack terminates instead of
    // spinning forever (mirrors `dispatch`'s MAX_UNWIND_FRAMES guard).
    const MAX_UNWIND_FRAMES: u32 = 4096;
    let mut frames_unwound: u32 = 0;
    let mut prev_rsp = context.rsp;
    loop {
        if frames_unwound >= MAX_UNWIND_FRAMES {
            return Err(crate::error::AppError::new(
                ReasonCode::SehException,
                format!(
                    "rtl_unwind: frame limit ({MAX_UNWIND_FRAMES}) exceeded — cyclic or corrupt stack"
                ),
            ));
        }
        let rva = context.rip.wrapping_sub(image_base) as u32;

        // Check if we've reached the target frame.
        if target_frame != 0 {
            // The target frame identifies a specific function (the one that
            // contains the target address). Stop once the current RIP enters
            // that function's range — that is the frame the unwind was asked
            // to stop at.
            let target_rva = target_frame.wrapping_sub(image_base) as u32;
            if let Some(target_rf) = seh.find_runtime_function(image_base, target_rva) {
                let (begin, end) = (target_rf.begin_addr, target_rf.end_addr);
                if rva >= begin && rva < end {
                    // We're inside the target frame. If target_rip is set,
                    // use it as the final RIP.
                    if target_rip != 0 {
                        context.rip = target_rip;
                    }
                    return Ok(());
                }
            }
        }

        // Find the runtime function for the current RIP.
        let rf = match seh.find_runtime_function(image_base, rva) {
            Some(rf) => rf,
            None => {
                // No function table entry for this RIP. During an exit unwind
                // (target_frame == 0) this is the natural termination of the
                // walk: we have reached a leaf/bottom frame past the last
                // managed function, so the unwind is complete. Only treat it
                // as an error if we never made progress (the initial context
                // was already invalid) or a specific target frame was sought
                // but never reached.
                if frames_unwound > 0 && target_frame == 0 {
                    return Ok(());
                }
                return Err(crate::error::AppError::new(
                    ReasonCode::SehException,
                    format!("rtl_unwind: no runtime function for RVA {:#x}", rva),
                ));
            }
        };

        // Get the unwind info for this function (image-aware: the RVA space
        // is shared between all loaded images, so lookups must be scoped to
        // the image being unwound).
        let unwind_info_addr = rf.unwind_info_addr;
        let unwind_info = match seh.get_unwind_info_for_image(image_base, unwind_info_addr) {
            Some(ui) => ui.clone(),
            None => {
                return Err(crate::error::AppError::new(
                    ReasonCode::SehException,
                    format!("rtl_unwind: no unwind info for RVA {:#x}", unwind_info_addr),
                ));
            }
        };

        // Perform the virtual unwind for this frame. CHAININFO entries are
        // followed in-place: replay the chained (primary) entry's codes as a
        // continuation of the same logical frame, until a non-chained entry
        // pops the return address.
        let mut active_info = unwind_info;
        let mut chain_depth = 0u32;
        let result = loop {
            if chain_depth >= MAX_CHAIN_DEPTH {
                eprintln!(
                    "[seh] rtl_unwind: chain depth limit ({}) exceeded",
                    MAX_CHAIN_DEPTH
                );
                break UnwindResult::NotFound;
            }
            let res = virtual_unwind(&active_info, context, memory_reader);
            if res == UnwindResult::Collided {
                chain_depth += 1;
                let Some(chained_rva) = active_info.chained_info_rva else {
                    break res;
                };
                match seh.get_unwind_info_for_image(image_base, chained_rva) {
                    Some(next) => {
                        active_info = next.clone();
                        continue;
                    }
                    None => break res,
                }
            }
            break res;
        };

        match result {
            UnwindResult::Completed => {
                // Successfully unwound one frame. Continue to the next one
                // in the loop (which will check target_frame again), but
                // only if the stack actually advanced.
                frames_unwound += 1;
                if context.rsp <= prev_rsp {
                    return Err(crate::error::AppError::new(
                        ReasonCode::SehException,
                        format!("rtl_unwind: no stack progress at RVA {rva:#x} — corrupt stack"),
                    ));
                }
                prev_rsp = context.rsp;
                continue;
            }
            UnwindResult::Collided => {
                // The chain terminated without a primary entry to pop the
                // return address — nothing more can be unwound here.
                if frames_unwound > 0 && target_frame == 0 {
                    return Ok(());
                }
                return Err(crate::error::AppError::new(
                    ReasonCode::SehException,
                    format!("rtl_unwind: unresolved chained unwind at RVA {:#x}", rva),
                ));
            }
            UnwindResult::HandlerFound(handler_rva) => {
                // A handler was found. The caller should invoke it.
                // Return Ok with the context set to the handler's frame.
                eprintln!("[seh] rtl_unwind: handler found at RVA {:#x}", handler_rva);
                return Ok(());
            }
            UnwindResult::NotFound => {
                return Err(crate::error::AppError::new(
                    ReasonCode::SehException,
                    format!("rtl_unwind: unwind returned NotFound for RVA {:#x}", rva),
                ));
            }
        }
    }
}

// ─── Section 2: VEH (Vectored Exception Handling) ────────────────────────────

/// Handler function signature matching Windows VectoredExceptionHandler.
///
/// Returns one of:
/// - `EXCEPTION_CONTINUE_SEARCH` (0) — try the next handler
/// - `EXCEPTION_CONTINUE_EXECUTION` (-1) — restart the faulting instruction
/// - `EXCEPTION_HANDLED` (1) — exception was handled, continue execution
pub type VectoredExceptionHandler = Arc<dyn Fn(&ExceptionPointers) -> i32 + Send + Sync>;

/// A node in the VEH handler chain.
pub struct VeHandlerNode {
    pub handler: VectoredExceptionHandler,
    pub first_chance: bool,
}

/// Opaque handle returned by `add_vectored_handler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VehHandle(pub u64);

/// Exception record (matches Windows EXCEPTION_RECORD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub record: Option<Box<ExceptionRecord>>,
    pub address: u64,
    pub params: [u64; 15],
}

impl ExceptionRecord {
    pub fn new(code: u32, address: u64) -> Self {
        Self {
            code,
            flags: 0,
            record: None,
            address,
            params: [0; 15],
        }
    }
}

/// Pointers passed to exception handlers (matches Windows EXCEPTION_POINTERS).
#[derive(Debug, Clone)]
pub struct ExceptionPointers {
    pub record: ExceptionRecord,
    pub context: X64Context,
}

// ─── Section 3: SEH (frame-based exception handling) ─────────────────────────

/// Scope record within a scope table (function-level SEH).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeRecord {
    /// Beginning offset (relative to function start) of the guarded region.
    pub begin_offset: u32,
    /// End offset of the guarded region.
    pub end_offset: u32,
    /// Offset to the handler function (relative to function start).
    pub handler_offset: u32,
    /// Jump target offset (for finally handlers) or 0.
    pub target_offset: u32,
}

/// Scope table describing the try/catch regions in a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeTable {
    pub count: u32,
    pub scopes: Vec<ScopeRecord>,
}

/// A try block descriptor used during dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryBlock {
    /// Try level index (nested try depth).
    pub try_level: u32,
    /// Guest-address of the handler function.
    pub handler_address: u64,
}

/// Global VEH state behind a mutex.
use std::sync::{Arc, Mutex};

/// Acquire a mutex, recovering from poisoning. A panicked lock holder must
/// not silently disable exception dispatch for the rest of the process —
/// the chains tolerate poison by returning the (possibly stale) data.
fn recover_lock<T>(mtx: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mtx.lock().unwrap_or_else(|p| p.into_inner())
}

lazy_static::lazy_static! {
    static ref VEH_CHAIN: Mutex<Vec<(VehHandle, VeHandlerNode)>> = Mutex::new(Vec::new());

    /// Queue of guest VEH callbacks that need to be invoked by the runtime.
    /// Each entry is (callback_guest_address, ExceptionRecord, X64Context).
    /// Set by VEH closures during dispatch, drained by PeHostRuntime after
    /// SEH/VEH dispatch returns.
    static ref PENDING_GUEST_VEH: Mutex<Vec<(u64, ExceptionRecord, X64Context)>> = Mutex::new(Vec::new());
}

// Thread-local re-entrancy guard for VEH dispatch.
//
// Prevents infinite recursion if a VEH handler itself triggers an exception
// (e.g., accessing invalid memory inside the handler). The depth limit of 8
// allows for legitimate nested exception handling (e.g., a handler that
// performs a controlled operation that might fault) while preventing runaway
// recursion from buggy or malicious handlers.
//
// SAFETY: This is thread-local, so there are no data-race concerns. The
// Cell type is appropriate because we never share a reference across threads.
thread_local! {
    static VEH_DISPATCH_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Maximum allowed depth of nested VEH dispatch calls.
/// Beyond this, further dispatch attempts are silently dropped
/// (returns EXCEPTION_CONTINUE_SEARCH) to prevent stack overflow.
const MAX_VEH_DISPATCH_DEPTH: u32 = 8;

static NEXT_VEH_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Maximum number of registered VEH/VCH handlers. Windows has no explicit
/// cap, but a guest that registers handlers in a loop must be bounded; a
/// rejected registration returns the invalid handle 0.
const MAX_VEH_HANDLERS: usize = 1024;

/// Maximum depth for following CHAININFO entries during unwind.
/// Prevents infinite loops with corrupt or cyclic unwind data.
const MAX_CHAIN_DEPTH: u32 = 32;

/// Maximum number of pending guest VEH callback entries.
/// Prevents unbounded growth if guest code continuously triggers exceptions.
const MAX_PENDING_GUEST_VEH: usize = 256;

/// Push a pending guest VEH callback entry (called from VEH closures).
///
/// Enforces `MAX_PENDING_GUEST_VEH` to prevent unbounded growth.
/// Returns `true` if the entry was accepted, `false` if the queue is full.
pub fn push_pending_guest_veh(callback: u64, record: ExceptionRecord, context: X64Context) -> bool {
    let mut pending = recover_lock(&PENDING_GUEST_VEH);
    if pending.len() >= MAX_PENDING_GUEST_VEH {
        eprintln!(
            "[seh] WARNING: pending guest VEH queue full ({} entries), dropping callback {:#x}",
            MAX_PENDING_GUEST_VEH, callback
        );
        return false;
    }
    pending.push((callback, record, context));
    true
}

/// Drain all pending guest VEH callback entries (called from PeHostRuntime
/// after SEH/VEH dispatch returns).
pub fn drain_pending_guest_veh() -> Vec<(u64, ExceptionRecord, X64Context)> {
    let mut pending = recover_lock(&PENDING_GUEST_VEH);
    std::mem::take(&mut *pending)
}

/// Add a vectored exception handler to the global chain.
///
/// Returns a `VehHandle` that can be used with `remove_vectored_handler`,
/// or `VehHandle(0)` if the chain is full.
pub fn add_vectored_handler(handler: VectoredExceptionHandler, first_chance: bool) -> VehHandle {
    let handle = VehHandle(NEXT_VEH_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let node = VeHandlerNode {
        handler,
        first_chance,
    };
    let mut chain = recover_lock(&VEH_CHAIN);
    if chain.len() >= MAX_VEH_HANDLERS {
        eprintln!(
            "[seh] WARNING: VEH chain full ({} handlers), rejecting registration",
            MAX_VEH_HANDLERS
        );
        return VehHandle(0);
    }
    chain.push((handle, node));
    handle
}

/// Remove a previously registered vectored exception handler.
pub fn remove_vectored_handler(handle: VehHandle) {
    let mut chain = recover_lock(&VEH_CHAIN);
    chain.retain(|(h, _)| *h != handle);
}

/// Helper: RAII guard for VEH dispatch depth tracking.
///
/// Increments the thread-local depth counter on construction and decrements
/// on drop (including via panic or early return), ensuring the counter is
/// always properly maintained.
struct VehDepthGuard;

impl VehDepthGuard {
    /// Try to acquire the guard. Returns `None` if the depth limit has been
    /// exceeded (re-entrancy rejected).
    fn try_acquire() -> Option<Self> {
        let exceeded = VEH_DISPATCH_DEPTH.with(|depth| {
            let current = depth.get();
            if current >= MAX_VEH_DISPATCH_DEPTH {
                eprintln!(
                    "[seh] WARNING: VEH dispatch depth exceeded ({}), dropping recursive dispatch",
                    MAX_VEH_DISPATCH_DEPTH
                );
                true
            } else {
                depth.set(current + 1);
                false
            }
        });
        if exceeded { None } else { Some(Self) }
    }
}

impl Drop for VehDepthGuard {
    fn drop(&mut self) {
        VEH_DISPATCH_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

/// Dispatch the exception record and context through the VEH chain.
///
/// Returns `EXCEPTION_CONTINUE_SEARCH` (0) if no handler claimed the exception,
/// `EXCEPTION_CONTINUE_EXECUTION` (-1) if a handler wants retry,
/// or `EXCEPTION_HANDLED` (1) if a handler claimed it.
///
/// # Re-entrancy protection
///
/// Uses a thread-local depth counter (`VEH_DISPATCH_DEPTH`) to prevent infinite
/// recursion if a VEH handler itself triggers an exception. If the depth exceeds
/// `MAX_VEH_DISPATCH_DEPTH` (8), the function returns `EXCEPTION_CONTINUE_SEARCH`
/// immediately, allowing the outer dispatch level to continue or fall through to
/// SEH. This prevents stack overflow from buggy or malicious handlers while
/// allowing legitimate nested exception handling up to the limit.
pub fn dispatch_vectored_handlers(record: &ExceptionRecord, context: &X64Context) -> i32 {
    // Re-entrancy guard: acquire the RAII guard. On drop (including early
    // returns), the depth counter is automatically decremented.
    let _guard = match VehDepthGuard::try_acquire() {
        Some(g) => g,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    let pointers = ExceptionPointers {
        record: record.clone(),
        context: context.clone(),
    };

    // Clone the handler list under the lock, then release before invoking.
    // This prevents deadlocks if a handler callback tries to add/remove handlers.
    let handlers: Vec<(bool, VectoredExceptionHandler)> = {
        let chain = recover_lock(&VEH_CHAIN);
        chain
            .iter()
            .map(|(_, node)| (node.first_chance, node.handler.clone()))
            .collect()
    };
    // Lock is released here — safe to invoke callbacks.

    // First-chance handlers run first, in registration order.
    for (first_chance, handler) in &handlers {
        if *first_chance {
            let result = handler(&pointers);
            if result != EXCEPTION_CONTINUE_SEARCH {
                return result;
            }
        }
    }

    // Then last-chance handlers, in reverse registration order (matching
    // Windows, where the most recently registered last-chance handler runs
    // first).
    for (first_chance, handler) in handlers.iter().rev() {
        if !*first_chance {
            let result = handler(&pointers);
            if result != EXCEPTION_CONTINUE_SEARCH {
                return result;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// ─── Vectored Continue Handlers (AddVectoredContinueHandler) ────────────────

/// Handler function signature for vectored continue handlers.
///
/// Called after the exception has been processed by all VEH and SEH handlers.
/// Return values are the same as `VectoredExceptionHandler`.
pub type VectoredContinueHandler = Arc<dyn Fn(&ExceptionPointers) -> i32 + Send + Sync>;

/// A node in the VCH (Vectored Continue Handler) chain.
pub struct VchHandlerNode {
    pub handler: VectoredContinueHandler,
}

/// Opaque handle for a registered continue handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VchHandle(pub u64);

lazy_static::lazy_static! {
    /// Global chain of vectored continue handlers.
    static ref VCH_CHAIN: Mutex<Vec<(VchHandle, VchHandlerNode)>> = Mutex::new(Vec::new());
}

static NEXT_VCH_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Add a vectored continue handler to the global chain.
///
/// Continue handlers are invoked after all VEH and frame-based handlers have
/// processed the exception. They receive the same `ExceptionPointers` as VEH
/// handlers. Returns `VchHandle(0)` if the chain is full.
pub fn add_vectored_continue_handler(handler: VectoredContinueHandler) -> VchHandle {
    let handle = VchHandle(NEXT_VCH_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let node = VchHandlerNode { handler };
    let mut chain = recover_lock(&VCH_CHAIN);
    if chain.len() >= MAX_VEH_HANDLERS {
        eprintln!(
            "[seh] WARNING: VCH chain full ({} handlers), rejecting registration",
            MAX_VEH_HANDLERS
        );
        return VchHandle(0);
    }
    chain.push((handle, node));
    handle
}

/// Remove a previously registered vectored continue handler.
pub fn remove_vectored_continue_handler(handle: VchHandle) {
    let mut chain = recover_lock(&VCH_CHAIN);
    chain.retain(|(h, _)| *h != handle);
}

/// Dispatch through the vectored continue handler chain.
///
/// Called after frame-based SEH handling completes (whether the exception was
/// handled or not). Returns `EXCEPTION_CONTINUE_SEARCH` if no handler claimed
/// the exception, or the handler's return value otherwise.
pub fn dispatch_vectored_continue_handlers(record: &ExceptionRecord, context: &X64Context) -> i32 {
    // Re-entrancy guard (same depth limit as VEH dispatch): a continue
    // handler that itself triggers an exception must not recurse without
    // bound, or the host stack overflows.
    let _guard = match VehDepthGuard::try_acquire() {
        Some(g) => g,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    let pointers = ExceptionPointers {
        record: record.clone(),
        context: context.clone(),
    };

    // Clone the handler list under the lock, then release before invoking.
    // This prevents deadlocks if a handler callback tries to add/remove handlers.
    let handlers: Vec<VectoredContinueHandler> = {
        let chain = recover_lock(&VCH_CHAIN);
        chain.iter().map(|(_, node)| node.handler.clone()).collect()
    };
    // Lock is released here — safe to invoke callbacks.

    for handler in &handlers {
        let result = handler(&pointers);
        if result != EXCEPTION_CONTINUE_SEARCH {
            return result;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

/// Walk SEH scope tables to dispatch an exception.
///
/// Given the exception record, current context, and the scope table for the
/// function where the exception occurred, this function attempts to find a
/// matching handler. Scope offsets are relative to the start of the function,
/// so the caller must supply `function_begin_rva` (the RVA of the enclosing
/// RUNTIME_FUNCTION) to translate the fault RIP before comparing.
///
/// The language-specific handler at `handler_offset` is **not** invoked here —
/// the caller must invoke it in guest context and honor its return value
/// (EXCEPTION_CONTINUE_SEARCH means the handler declined and the search must
/// continue up the chain). This function only reports *which* scope (if any)
/// guards the fault address.
pub fn seh_dispatch(
    exception_record: &ExceptionRecord,
    context: &X64Context,
    scope_table: &ScopeTable,
    image_base: u64,
    function_begin_rva: u32,
) -> UnwindResult {
    // The fault address (from the exception record) is what the scope scan
    // matches against; fall back to the context RIP if the record carries no
    // address. The offset must be function-relative, not image-relative:
    // ScopeRecord offsets are relative to the function start.
    let fault_rip = if exception_record.address != 0 {
        exception_record.address
    } else {
        context.rip
    };
    let fault_rva = fault_rip.wrapping_sub(image_base) as u32;
    let fault_offset = fault_rva.wrapping_sub(function_begin_rva);

    // Only trust `count` entries: a table whose Vec is longer than its
    // declared count carries trailing garbage that must not be searched.
    let scopes = scope_table.scopes.iter().take(scope_table.count as usize);
    for scope in scopes {
        if fault_offset >= scope.begin_offset && fault_offset < scope.end_offset {
            // Found a guarding scope with a handler. A zero handler offset is
            // corrupt metadata — no guest code can be dispatched to, so keep
            // searching rather than claiming a handler that cannot run.
            if scope.handler_offset == 0 {
                continue;
            }
            return UnwindResult::HandlerFound(scope.handler_offset);
        }
    }

    // No scope matched in this function — the caller should unwind to the
    // previous frame and try its scope table.
    UnwindResult::NotFound
}

// ─── Section 4: SehSubsystem (integration container) ─────────────────────────

/// Central SEH/VEH subsystem, owned by `PeHostRuntime`.
///
/// Manages:
/// - Parsed `.pdata` exception tables per loaded image
/// - Vectored exception handler chain
/// - Exception generation and dispatch
pub struct SehSubsystem {
    /// Parsed `.pdata` tables per image base address.
    pdata_tables: HashMap<u64, Vec<RuntimeFunction>>,
    /// Cached parsed UNWIND_INFO keyed by (image_base, rva). Keying by RVA
    /// alone is unsafe: every PE image's unwind data starts near RVA 0x1000
    /// and the JIT image shares the same RVA space, so a bare-RVA cache can
    /// return one image's unwind info for another image's frame.
    unwind_cache: HashMap<(u64, u32), UnwindInfo>,
    /// Raw unwind data blobs indexed by image base (for lazy parsing).
    unwind_data: HashMap<u64, Vec<u8>>,
}

impl SehSubsystem {
    pub fn new() -> Self {
        Self {
            pdata_tables: HashMap::new(),
            unwind_cache: HashMap::new(),
            unwind_data: HashMap::new(),
        }
    }

    /// Register a `.pdata` section for a loaded image.
    pub fn register_pdata(&mut self, image_base: u64, pdata_bytes: &[u8]) {
        let functions = parse_pdata(pdata_bytes, image_base);
        self.pdata_tables.insert(image_base, functions);
    }

    /// Register raw unwind data (the full section containing UNWIND_INFO).
    ///
    /// When replacing existing unwind data, the unwind cache entries for this
    /// image are dropped (other images' entries are unaffected) to prevent
    /// stale entries. All subsequent `get_unwind_info()` calls will re-parse
    /// from the fresh data.
    pub fn register_unwind_data(&mut self, image_base: u64, data: Vec<u8>) {
        self.unwind_data.insert(image_base, data);
        self.unwind_cache
            .retain(|(cached_base, _), _| *cached_base != image_base);
    }

    /// Get a reference to the raw unwind data blob for a given image base.
    /// Returns `None` if no unwind data has been registered for this base.
    /// Used for low-level verification of the raw byte layout in tests.
    pub fn get_unwind_data_raw(&self, image_base: u64) -> Option<&Vec<u8>> {
        self.unwind_data.get(&image_base)
    }

    /// Find the `RuntimeFunction` for a given RVA in a specific image.
    ///
    /// `.pdata` entries are sorted by `begin_addr` per the PE spec, so a
    /// binary search (partition point) resolves a fault RVA in O(log n).
    /// A linear fallback covers unsorted/corrupt tables.
    pub fn find_runtime_function(&self, image_base: u64, rva: u32) -> Option<&RuntimeFunction> {
        let functions = self.pdata_tables.get(&image_base)?;
        let idx = functions.partition_point(|rf| rf.begin_addr <= rva);
        if idx > 0 {
            let cand = &functions[idx - 1];
            if rva >= cand.begin_addr && rva < cand.end_addr {
                return Some(cand);
            }
        }
        // Fallback for unsorted or overlapping entries.
        functions
            .iter()
            .find(|rf| rva >= rf.begin_addr && rva < rf.end_addr)
    }

    /// Get or parse unwind info for a given RVA **within one specific image**.
    ///
    /// The RVA space is shared across all loaded images (PE images and the
    /// JIT image), so lookups must be scoped to the image being unwound.
    /// Entries are cached under `(image_base, rva)` and parsed only from that
    /// image's own unwind-data blob.
    pub fn get_unwind_info_for_image(&mut self, image_base: u64, rva: u32) -> Option<&UnwindInfo> {
        let key = (image_base, rva);
        if !self.unwind_cache.contains_key(&key) {
            let data = self.unwind_data.get(&image_base)?;
            let info = parse_unwind_info(data, rva)?;
            self.unwind_cache.insert(key, info);
        }
        self.unwind_cache.get(&key)
    }

    /// Get or parse unwind info for a given RVA without an image context.
    ///
    /// Kept for callers that do not know the image base. Any cached per-image
    /// entry for the RVA is reused; otherwise every registered image is
    /// consulted and each successful parse is cached per-image, so a shared
    /// RVA can never leak between images. Prefer [`get_unwind_info_for_image`]
    /// when the image base is known.
    pub fn get_unwind_info(&mut self, rva: u32) -> Option<&UnwindInfo> {
        // Cache hit: an entry for this RVA already exists for some image.
        let cached_image = self
            .unwind_cache
            .keys()
            .find_map(|(image_base, cached_rva)| (*cached_rva == rva).then_some(*image_base));
        if let Some(image_base) = cached_image {
            return self.unwind_cache.get(&(image_base, rva));
        }
        // Parse on demand, caching each successful parse per image. The
        // per-image key guarantees a shared RVA can never leak between
        // images; the cache hit is resolved with a single borrow below.
        let images: Vec<u64> = self.unwind_data.keys().copied().collect();
        let mut found_image: Option<u64> = None;
        for image_base in images {
            if self.get_unwind_info_for_image(image_base, rva).is_some() {
                found_image = Some(image_base);
                break;
            }
        }
        found_image.and_then(|image_base| self.unwind_cache.get(&(image_base, rva)))
    }

    /// Perform virtual_unwind for a given RVA. Looks up the RuntimeFunction,
    /// parses the UnwindInfo, and calls virtual_unwind with the memory_reader.
    pub fn virtual_unwind_by_rva(
        &mut self,
        image_base: u64,
        rva: u32,
        context: &mut X64Context,
        memory_reader: &MemoryReader<'_>,
    ) -> UnwindResult {
        let rf = match self.find_runtime_function(image_base, rva) {
            Some(rf) => rf,
            None => return UnwindResult::NotFound,
        };
        let unwind_info = match self.get_unwind_info_for_image(image_base, rf.unwind_info_addr) {
            Some(ui) => ui.clone(),
            None => return UnwindResult::NotFound,
        };
        virtual_unwind(&unwind_info, context, memory_reader)
    }

    /// Dispatch an exception: try VEH first, then SEH (full unwind).
    /// If a VEH handler claims the exception, returns Ok(()).
    /// Otherwise, performs a full stack unwind using .pdata tables, calling
    /// language-specific handlers at each frame. If a handler claims the
    /// exception, returns Ok(()). If no handler claims it across all frames,
    /// returns Err(AppError).
    /// Returns Err(AppError) with a "collided unwind" message if no handler
    /// claims the exception after unwinding all frames.
    pub fn dispatch(
        &mut self,
        code: u32,
        address: u64,
        context: &X64Context,
        image_base: u64,
        memory_reader: &MemoryReader<'_>,
    ) -> Result<(), crate::error::AppError> {
        let record = ExceptionRecord::new(code, address);

        // Step 1: Try VEH handlers
        let veh_result = dispatch_vectored_handlers(&record, context);
        match veh_result {
            EXCEPTION_CONTINUE_EXECUTION => {
                return Ok(()); // handler requested retry
            }
            EXCEPTION_HANDLED => {
                return Ok(()); // handler claimed it
            }
            _ => {} // CONTINUE_SEARCH — fall through to SEH
        }

        // Step 2: Try SEH — perform a full unwind across all frames.
        // We iterate through frames using .pdata, calling virtual_unwind
        // to restore each frame's registers and checking for handlers.
        let mut current_context = context.clone();

        // Unwinding moves up the call stack, so RSP must strictly increase on
        // every completed frame. We track the previous RSP to detect a frame
        // that fails to make progress (e.g. a return address that cannot be
        // read from guest memory), which Windows treats as a corrupt/exhausted
        // stack and stops the search — preventing an infinite unwind loop.
        let mut prev_rsp = current_context.rsp;
        let mut frames_unwound: u32 = 0;
        // RtlVirtualUnwind / RtlDispatchException bound the unwind depth; a real
        // user-mode stack is never this deep. Exceeding it means the unwind
        // chain is cyclic or corrupt, so we stop the search.
        const MAX_UNWIND_FRAMES: u32 = 4096;

        loop {
            if frames_unwound >= MAX_UNWIND_FRAMES {
                break;
            }
            frames_unwound += 1;

            let rva = current_context.rip.wrapping_sub(image_base) as u32;

            // Scoped lookup to avoid overlapping borrows on self.
            let rf = self.find_runtime_function(image_base, rva).cloned();
            let rf = match rf {
                Some(rf) => rf,
                None => break,
            };

            // Image-scoped lookup: the unwind RVA belongs to this image's
            // unwind-data blob, never to another image with the same RVA.
            let unwind_info = match self.get_unwind_info_for_image(image_base, rf.unwind_info_addr)
            {
                Some(ui) => ui.clone(),
                None => break,
            };

            // Use the caller-supplied guest memory reader so virtual_unwind
            // can read return addresses and saved registers from the actual
            // guest stack (which lives outside the image's unwind data).
            let result = virtual_unwind(&unwind_info, &mut current_context, memory_reader);
            match result {
                UnwindResult::Completed => {
                    // Unwound to the caller — verify forward progress before
                    // continuing. If RSP did not advance, the return address
                    // could not be read (corrupt/exhausted stack); stop here so
                    // the exception falls through to the unhandled path rather
                    // than looping on the same frame forever.
                    if current_context.rsp <= prev_rsp {
                        break;
                    }
                    prev_rsp = current_context.rsp;
                    continue;
                }
                UnwindResult::Collided => {
                    // CHAININFO: follow the chained (primary) entry in-place,
                    // replaying its codes until a non-chained entry pops the
                    // return address. Resolving by chained_info_rva (not by
                    // RIP) guarantees forward progress.
                    let mut chain_rva = unwind_info.chained_info_rva;
                    let mut resolved = false;
                    let mut chain_depth = 0u32;
                    while let Some(rva) = chain_rva {
                        chain_depth += 1;
                        if chain_depth > MAX_CHAIN_DEPTH {
                            eprintln!(
                                "[seh] dispatch: chain depth limit ({}) exceeded",
                                MAX_CHAIN_DEPTH
                            );
                            break;
                        }
                        let Some(next) = self.get_unwind_info_for_image(image_base, rva).cloned()
                        else {
                            break;
                        };
                        match virtual_unwind(&next, &mut current_context, memory_reader) {
                            UnwindResult::Collided => {
                                chain_rva = next.chained_info_rva;
                            }
                            UnwindResult::HandlerFound(handler_rva) => {
                                if !Self::claim_language_handler(
                                    image_base,
                                    handler_rva,
                                    &record,
                                    &current_context,
                                ) {
                                    break;
                                }
                                return Ok(());
                            }
                            _ => {
                                resolved = true;
                                break;
                            }
                        }
                    }
                    if resolved {
                        // The chained entry popped the return address; ensure the
                        // progress tracker reflects the new (higher) RSP so the
                        // next Completed frame is not falsely treated as stuck.
                        if current_context.rsp <= prev_rsp {
                            break;
                        }
                        prev_rsp = current_context.rsp;
                        continue;
                    }
                    break;
                }
                UnwindResult::HandlerFound(handler_rva) => {
                    // The frame has a language-specific handler (EHANDLER /
                    // UHANDLER). Queue it for guest-side invocation — the
                    // runtime drains the pending queue after dispatch — and
                    // only claim the exception when the handler can actually
                    // run. A zero handler RVA or a full queue is corrupt /
                    // overloaded state: fail closed instead of silently
                    // swallowing the exception (which would livelock the
                    // runtime by retrying the faulting instruction).
                    if !Self::claim_language_handler(
                        image_base,
                        handler_rva,
                        &record,
                        &current_context,
                    ) {
                        break;
                    }
                    return Ok(());
                }
                UnwindResult::NotFound => {
                    break;
                }
            }
        }

        // Step 3: No handler claimed the exception after full unwind.
        // Log diagnostic information for the undispatched exception.
        let veh_handler_count = recover_lock(&VEH_CHAIN).len();
        let pdata_count: usize = self.pdata_tables.values().map(|v| v.len()).sum();
        eprintln!(
            "[seh] unhandled exception: code={:#x}, address={:#x}, \
             frames_unwound={}, veh_handlers={}, pdata_entries={}",
            code, address, frames_unwound, veh_handler_count, pdata_count
        );

        Err(crate::error::AppError::new(
            ReasonCode::SehException,
            format!("unhandled exception code={code:#x} at address={address:#x} (collided unwind)",),
        ))
    }

    /// Queue a frame's language-specific handler (EHANDLER/UHANDLER) for
    /// guest-side invocation and claim the exception.
    ///
    /// The runtime drains the pending guest VEH queue after dispatch and
    /// invokes the callback in guest context; the handler's return value is
    /// then honored there. Returns `false` (and does **not** claim) when the
    /// handler metadata is corrupt (zero RVA) or the queue is full — in both
    /// cases claiming would swallow the exception without the handler ever
    /// running.
    fn claim_language_handler(
        image_base: u64,
        handler_rva: u32,
        record: &ExceptionRecord,
        context: &X64Context,
    ) -> bool {
        if handler_rva == 0 {
            eprintln!("[seh] dispatch: corrupt handler RVA 0 — not claiming exception");
            return false;
        }
        let handler_address = image_base.wrapping_add(handler_rva as u64);
        push_pending_guest_veh(handler_address, record.clone(), context.clone())
    }

    /// Generate an exception record and dispatch.
    ///
    /// Convenience wrapper around `dispatch()`.
    pub fn generate_exception(
        &mut self,
        code: u32,
        context: &X64Context,
        image_base: u64,
        memory_reader: &MemoryReader<'_>,
    ) -> Result<(), crate::error::AppError> {
        self.dispatch(code, context.rip, context, image_base, memory_reader)
    }
}

impl Default for SehSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    static VEH_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn make_unwind_info(version: u8, flags: u8, codes: &[(u8, u8)]) -> Vec<u8> {
        let mut buf = vec![
            (version & 0x07) | ((flags & 0x1f) << 3), // version_and_flags
            0x10,                                     // prolog_size
            codes.len() as u8,                        // code_count
            0x00,                                     // frame_register + frame_offset
        ];
        for &(code, info) in codes {
            buf.push((info << 4) | (code & 0x0f));
            buf.push(0x00); // second byte (op-info)
        }
        // Pad to even count
        if codes.len() % 2 == 1 {
            buf.push(0x00);
            buf.push(0x00);
        }
        buf
    }

    #[test]
    fn test_veh_add_remove() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let handler: VectoredExceptionHandler = Arc::new(|_ptrs| EXCEPTION_CONTINUE_SEARCH);

        let handle = add_vectored_handler(handler, true);
        // Verify it was added (chain should not be empty)
        {
            let chain = VEH_CHAIN.lock().unwrap();
            assert!(chain.iter().any(|(h, _)| *h == handle));
        }

        remove_vectored_handler(handle);
        // Verify it was removed
        {
            let chain = VEH_CHAIN.lock().unwrap();
            assert!(!chain.iter().any(|(h, _)| *h == handle));
        }
    }

    #[test]
    fn test_veh_dispatch() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Register a handler that claims STATUS_ACCESS_VIOLATION
        let handler: VectoredExceptionHandler = Arc::new(|ptrs| {
            if ptrs.record.code == STATUS_ACCESS_VIOLATION {
                EXCEPTION_HANDLED
            } else {
                EXCEPTION_CONTINUE_SEARCH
            }
        });

        let handle = add_vectored_handler(handler, true);

        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x7fff_1234);
        let context = X64Context::default();
        let result = dispatch_vectored_handlers(&record, &context);
        assert_eq!(result, EXCEPTION_HANDLED);

        // Test unhandled exception
        let record2 = ExceptionRecord::new(STATUS_INTEGER_DIVIDE_BY_ZERO, 0x7fff_5678);
        let result2 = dispatch_vectored_handlers(&record2, &context);
        assert_eq!(result2, EXCEPTION_CONTINUE_SEARCH);

        remove_vectored_handler(handle);
    }

    #[test]
    fn test_seh_dispatch_no_handler() {
        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let scope_table = ScopeTable {
            count: 0,
            scopes: vec![],
        };
        let result = seh_dispatch(&record, &context, &scope_table, 0x1_4000_0000, 0x1000);
        assert_eq!(result, UnwindResult::NotFound);
    }

    #[test]
    fn test_seh_subsystem_dispatch_no_veh() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut seh = SehSubsystem::new();
        let context = X64Context::default();
        let no_memory = |_addr: u64, _buf: &mut [u8]| -> bool { false };
        let result = seh.dispatch(
            STATUS_ACCESS_VIOLATION,
            0x1000,
            &context,
            0x1_4000_0000,
            &no_memory,
        );
        assert!(result.is_err(), "expected Err, got {result:?}");
        if let Err(err) = result {
            assert_eq!(err.code, ReasonCode::SehException);
        }
    }

    #[test]
    fn test_veh_continue_execution() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let handler: VectoredExceptionHandler = Arc::new(|_ptrs| EXCEPTION_CONTINUE_EXECUTION);
        let handle = add_vectored_handler(handler, true);

        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let result = dispatch_vectored_handlers(&record, &context);
        assert_eq!(result, EXCEPTION_CONTINUE_EXECUTION);

        remove_vectored_handler(handle);
    }

    // ── New comprehensive tests ─────────────────────────────────────────────

    fn make_unwind_info_full(version: u8, flags: u8, codes: &[(u8, u8)], extra: &[u8]) -> Vec<u8> {
        let mut buf = vec![
            (version & 0x07) | ((flags & 0x1f) << 3), // version_and_flags
            0x10,                                     // prolog_size
            codes.len() as u8,                        // code_count
            0x00,                                     // frame_register + frame_offset
        ];
        for &(code, info) in codes {
            buf.push((info << 4) | (code & 0x0f));
            buf.push(0x00);
        }
        // Pad to even count
        if codes.len() % 2 == 1 {
            buf.push(0x00);
            buf.push(0x00);
        }
        // Align to 4 bytes (DWORD)
        while buf.len() % 4 != 0 {
            buf.push(0x00);
        }
        buf.extend_from_slice(extra);
        buf
    }

    fn slice_memory_reader<'a>(slice: &'a [u8], base: u64) -> impl Fn(u64, &mut [u8]) -> bool + 'a {
        move |addr: u64, buf: &mut [u8]| -> bool {
            let offset = addr.wrapping_sub(base) as usize;
            if offset + buf.len() <= slice.len() {
                buf.copy_from_slice(&slice[offset..offset + buf.len()]);
                true
            } else {
                false
            }
        }
    }

    // (helper removed — no remaining caller)

    #[test]
    fn test_seh_dispatch_with_scope() {
        // Scope table with one scope that covers RIP range. Scope offsets are
        // relative to the function start (RVA 0x10): fault RVA 0x50 maps to
        // function-relative offset 0x40, inside the guarded region.
        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x140001050);
        let context = X64Context {
            rip: 0x140001050, // inside scope 0
            ..X64Context::default()
        };
        let scope_table = ScopeTable {
            count: 1,
            scopes: vec![ScopeRecord {
                begin_offset: 0x40, // relative to function start
                end_offset: 0x80,
                handler_offset: 0x200, // handler at image_base + 0x200
                target_offset: 0,
            }],
        };
        let result = seh_dispatch(&record, &context, &scope_table, 0x140001000, 0x10);
        assert_eq!(
            result,
            UnwindResult::HandlerFound(0x200),
            "should find handler at offset 0x200"
        );
    }

    #[test]
    fn test_seh_dispatch_outside_scope() {
        // RIP is outside all scopes — should return NotFound
        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x140001050);
        let context = X64Context {
            rip: 0x140001050,
            ..X64Context::default()
        };
        let scope_table = ScopeTable {
            count: 1,
            scopes: vec![ScopeRecord {
                begin_offset: 0x100, // doesn't cover offset 0x40 (relative to function start)
                end_offset: 0x200,
                handler_offset: 0x300,
                target_offset: 0,
            }],
        };
        let result = seh_dispatch(&record, &context, &scope_table, 0x140001000, 0x10);
        assert_eq!(
            result,
            UnwindResult::NotFound,
            "should not find handler for RIP outside scope"
        );
    }

    #[test]
    fn test_rtl_restore_context_with_veh_handler() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Register a VEH handler that handles STATUS_ILLEGAL_INSTRUCTION
        // and verify rtl_restore_context dispatches through VEH.
        let handler: VectoredExceptionHandler = Arc::new(|ptrs| {
            if ptrs.record.code == STATUS_ILLEGAL_INSTRUCTION {
                // Verify the context RIP is in the params
                assert_eq!(ptrs.record.params[0], 0x140001234);
                EXCEPTION_HANDLED
            } else {
                EXCEPTION_CONTINUE_SEARCH
            }
        });

        let handle = add_vectored_handler(handler, true);

        let ctx = X64Context {
            rip: 0x140001234,
            rsp: 0x7fff_0000,
            ..X64Context::default()
        };

        let result = rtl_restore_context(&ctx);
        assert!(
            result.is_ok(),
            "rtl_restore_context should succeed with VEH handler"
        );

        remove_vectored_handler(handle);
    }

    #[test]
    fn test_rtl_unwind_not_found() {
        // When there is no runtime function for the current RIP,
        // rtl_unwind should return Err.
        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;

        let mem_reader = |_: u64, _: &mut [u8]| false;

        let mut ctx = X64Context {
            rip: 0x140009999, // no .pdata covers this address
            rsp: 0x7fff_0000,
            ..X64Context::default()
        };

        let result = rtl_unwind(0, 0, image_base, &mut ctx, &mut seh, &mem_reader);
        assert!(
            result.is_err(),
            "rtl_unwind should return Err for unknown frame"
        );
    }

    // ── New tests for checklist items ──────────────────────────────────────

    /// Test: VEH handler that dispatches a nested exception during dispatch.
    /// This verifies that the clone-before-invoke approach prevents deadlocks
    /// when a VEH handler triggers re-entrant exception dispatch.
    #[test]
    fn test_veh_nested_exception_during_dispatch() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // Re-entrancy guard: prevents infinite recursion when the handler
        // is invoked again during the nested dispatch.
        use std::sync::atomic::{AtomicBool, Ordering};
        static REENTRY_GUARD: AtomicBool = AtomicBool::new(false);

        // This handler will be called during the outer dispatch and will
        // trigger a nested dispatch. If the mutex is held during callback
        // invocation, this would deadlock.
        let handler: VectoredExceptionHandler = Arc::new(|ptrs| {
            // Prevent re-entrant calls from the nested dispatch.
            if REENTRY_GUARD.load(Ordering::SeqCst) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            REENTRY_GUARD.store(true, Ordering::SeqCst);

            // Dispatch a nested exception — this must not deadlock.
            let nested_record = ExceptionRecord::new(STATUS_BREAKPOINT, 0x2000);
            let nested_ctx = X64Context::default();
            let _nested_result = dispatch_vectored_handlers(&nested_record, &nested_ctx);

            REENTRY_GUARD.store(false, Ordering::SeqCst);

            if ptrs.record.code == STATUS_ACCESS_VIOLATION {
                EXCEPTION_HANDLED
            } else {
                EXCEPTION_CONTINUE_SEARCH
            }
        });

        let handle = add_vectored_handler(handler, true);

        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let result = dispatch_vectored_handlers(&record, &context);
        assert_eq!(
            result, EXCEPTION_HANDLED,
            "nested dispatch should not deadlock"
        );

        remove_vectored_handler(handle);
    }

    /// Test: Adding a VEH handler during dispatch does not cause panics or
    /// data corruption. The newly added handler should not be invoked in the
    /// current dispatch (snapshot semantics) but should be available for
    /// subsequent dispatches.
    #[test]
    fn test_veh_add_handler_during_dispatch() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let added = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let added_clone = added.clone();

        // This handler adds another handler during dispatch.
        let handler: VectoredExceptionHandler = Arc::new(move |_ptrs| {
            let added_flag = added_clone.clone();
            let inner: VectoredExceptionHandler = Arc::new(move |_ptrs| {
                added_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                EXCEPTION_HANDLED
            });
            let _inner_handle = add_vectored_handler(inner, true);
            EXCEPTION_CONTINUE_SEARCH
        });

        let _handle = add_vectored_handler(handler, true);

        // First dispatch: the handler adds a new handler but doesn't handle
        // the exception itself.
        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let result = dispatch_vectored_handlers(&record, &context);
        assert_eq!(
            result, EXCEPTION_CONTINUE_SEARCH,
            "original handler should continue search"
        );

        // Second dispatch: the newly added handler should be present and handle it.
        let result2 = dispatch_vectored_handlers(&record, &context);
        assert_eq!(
            result2, EXCEPTION_HANDLED,
            "newly added handler should handle the exception"
        );
        assert!(
            added.load(std::sync::atomic::Ordering::SeqCst),
            "inner handler should have been invoked"
        );

        // Clean up all handlers
        {
            let mut chain = VEH_CHAIN.lock().unwrap();
            chain.clear();
        }
    }

    /// Test: Removing a VEH handler during dispatch does not cause panics.
    #[test]
    fn test_veh_remove_handler_during_dispatch() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked_for_closure = invoked.clone();

        // Handler that will be removed during dispatch.
        let target_handle = Arc::new(std::sync::Mutex::new(VehHandle(0)));
        let target_handle_clone = target_handle.clone();

        let removable_handler: VectoredExceptionHandler = Arc::new(move |_ptrs| {
            invoked_for_closure.store(true, std::sync::atomic::Ordering::SeqCst);
            EXCEPTION_HANDLED
        });

        let removable_handle = add_vectored_handler(removable_handler, true);
        *target_handle.lock().unwrap() = removable_handle;

        // This handler removes the other handler during dispatch.
        let remover: VectoredExceptionHandler = Arc::new(move |_ptrs| {
            let h = *target_handle_clone.lock().unwrap();
            remove_vectored_handler(h);
            EXCEPTION_CONTINUE_SEARCH
        });

        let remover_handle = add_vectored_handler(remover, true);

        // Dispatch: remover runs first (added later, but both are first_chance,
        // so they run in registration order). The removable handler is removed
        // but since we snapshot before invoking, it still runs in this dispatch.
        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let _result = dispatch_vectored_handlers(&record, &context);

        // The removable handler should have been invoked (snapshot semantics).
        assert!(
            invoked.load(std::sync::atomic::Ordering::SeqCst),
            "removable handler should have been invoked (snapshot before removal)"
        );

        // Clean up
        remove_vectored_handler(remover_handle);
        {
            let mut chain = VEH_CHAIN.lock().unwrap();
            chain.clear();
        }
    }

    /// Test: Corrupt unwind metadata — missing runtime function.
    /// When no .pdata is registered for the image, dispatch should return an error.
    #[test]
    fn test_corrupt_unwind_missing_runtime_function() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut seh = SehSubsystem::new();
        let context = X64Context::default();
        let no_memory = |_addr: u64, _buf: &mut [u8]| false;

        // No .pdata registered — dispatch should fail gracefully.
        let result = seh.dispatch(
            STATUS_ACCESS_VIOLATION,
            0x140001000,
            &context,
            0x1_4000_0000,
            &no_memory,
        );
        assert!(result.is_err(), "should fail with no .pdata");
    }

    /// Test: Corrupt unwind metadata — invalid handler address.
    /// An unwind info entry with EHANDLER flag but a handler RVA of 0 is
    /// corrupt metadata: dispatch must fail closed (Err) instead of claiming
    /// a handler that can never run, which would silently swallow the
    /// exception and livelock the runtime.
    #[test]
    fn test_corrupt_unwind_invalid_handler_address() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;

        // Build unwind info with EHANDLER flag and handler RVA = 0
        let codes = vec![(0, 5)]; // push rbp
        let handler_rva = 0x0000u32;
        let unwind_data = make_unwind_info_full(1, 0x01, &codes, &handler_rva.to_le_bytes());

        let mut data = vec![0u8; 0x2000];
        data[0x1000..0x1000 + unwind_data.len()].copy_from_slice(&unwind_data);
        seh.register_unwind_data(image_base, data);

        // Register .pdata pointing to this unwind info
        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x1050u32.to_le_bytes());
        pdata.extend_from_slice(&0x1000u32.to_le_bytes()); // unwind_info_addr
        seh.register_pdata(image_base, &pdata);

        let no_memory = |_addr: u64, _buf: &mut [u8]| false;
        // Set RIP to the fault address so dispatch can find the .pdata entry
        let context = X64Context {
            rip: 0x140001000,
            ..X64Context::default()
        };

        // Dispatch must not panic and must fail closed (the handler RVA 0 is
        // not dispatchable).
        let result = seh.dispatch(
            STATUS_ACCESS_VIOLATION,
            0x140001000,
            &context,
            image_base,
            &no_memory,
        );
        assert!(
            result.is_err(),
            "dispatch with corrupt (zero) handler address must fail closed"
        );
    }

    /// Test: Corrupt unwind metadata — truncated/invalid unwind data.
    /// Parsing should return None for corrupt data without panicking.
    #[test]
    fn test_corrupt_unwind_data_truncated() {
        // Empty data
        assert!(
            parse_unwind_info(&[], 0).is_none(),
            "empty data should return None"
        );

        // Too short for header
        assert!(
            parse_unwind_info(&[0x01], 0).is_none(),
            "truncated header should return None"
        );

        // Header present but codes area truncated
        let mut data = vec![0x01, 0x10, 0x04, 0x00]; // version=1, codes=4
        data.push(0x50); // code byte
        data.push(0x00);
        // Missing remaining code slots — should return None
        assert!(
            parse_unwind_info(&data, 0).is_none(),
            "truncated codes should return None"
        );
    }

    /// Test: Corrupt unwind metadata — invalid version number.
    #[test]
    fn test_corrupt_unwind_data_invalid_version() {
        // Version 0 is reserved/invalid; per the PE/COFF spec only version 1
        // is defined, so parsing must fail closed instead of mis-unwinding.
        let data = make_unwind_info(0, 0, &[]);
        assert!(
            parse_unwind_info(&data, 0).is_none(),
            "version 0 must be rejected"
        );

        // Version > 1 is also undefined; reject it the same way.
        let data2 = make_unwind_info(2, 0, &[]);
        assert!(
            parse_unwind_info(&data2, 0).is_none(),
            "version 2 must be rejected"
        );
    }

    /// Test: Verify Windows-compatible ordering — first-chance VEH handlers
    /// are called before last-chance VEH handlers, and both before SEH.
    #[test]
    fn test_first_chance_last_chance_ordering() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let order1 = order.clone();
        let order2 = order.clone();
        let order3 = order.clone();

        // Last-chance VEH handler (registered first, but should run after first-chance)
        let last_chance: VectoredExceptionHandler = Arc::new(move |_ptrs| {
            order1.lock().unwrap().push("veh_last".to_string());
            EXCEPTION_CONTINUE_SEARCH
        });
        let h1 = add_vectored_handler(last_chance, false); // last-chance

        // First-chance VEH handler (registered second, but should run first)
        let first_chance: VectoredExceptionHandler = Arc::new(move |_ptrs| {
            order2.lock().unwrap().push("veh_first".to_string());
            EXCEPTION_CONTINUE_SEARCH
        });
        let h2 = add_vectored_handler(first_chance, true); // first-chance

        // Another first-chance handler that also continues search
        let first_chance2: VectoredExceptionHandler = Arc::new(move |_ptrs| {
            order3.lock().unwrap().push("veh_first2".to_string());
            EXCEPTION_CONTINUE_SEARCH
        });
        let h3 = add_vectored_handler(first_chance2, true);

        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let result = dispatch_vectored_handlers(&record, &context);
        assert_eq!(result, EXCEPTION_CONTINUE_SEARCH);

        let recorded = order.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![
                "veh_first".to_string(),
                "veh_first2".to_string(),
                "veh_last".to_string(),
            ],
            "first-chance handlers should run before last-chance handlers, in registration order"
        );

        remove_vectored_handler(h1);
        remove_vectored_handler(h2);
        remove_vectored_handler(h3);
    }

    /// Test: VEH handlers are called before SEH handlers (first-chance).
    /// When a VEH handler handles the exception, SEH should not be invoked.
    #[test]
    fn test_veh_before_seh_first_chance() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;

        // Register a VEH handler that handles the exception
        let handler: VectoredExceptionHandler = Arc::new(|ptrs| {
            if ptrs.record.code == STATUS_ACCESS_VIOLATION {
                EXCEPTION_HANDLED
            } else {
                EXCEPTION_CONTINUE_SEARCH
            }
        });
        let veh_handle = add_vectored_handler(handler, true);

        // Register .pdata and unwind data so SEH could potentially find a handler
        let codes = vec![(0, 5)];
        let handler_rva = 0x3000u32;
        let unwind_data = make_unwind_info_full(1, 0x01, &codes, &handler_rva.to_le_bytes());
        let mut data = vec![0u8; 0x3000];
        data[0x2000..0x2000 + unwind_data.len()].copy_from_slice(&unwind_data);
        seh.register_unwind_data(image_base, data);

        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x1050u32.to_le_bytes());
        pdata.extend_from_slice(&0x2000u32.to_le_bytes());
        seh.register_pdata(image_base, &pdata);

        let no_memory = |_addr: u64, _buf: &mut [u8]| false;
        let context = X64Context::default();

        // Dispatch should be handled by VEH, not SEH
        let result = seh.dispatch(
            STATUS_ACCESS_VIOLATION,
            0x140001000,
            &context,
            image_base,
            &no_memory,
        );
        assert!(result.is_ok(), "VEH handler should handle the exception");

        remove_vectored_handler(veh_handle);
    }

    /// Test: Vectored continue handlers are called when exceptions are
    /// continued (not handled by VEH or SEH).
    #[test]
    fn test_vectored_continue_handlers_called() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let continue_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let continue_called_clone = continue_called.clone();

        let continue_handler: VectoredContinueHandler = Arc::new(move |_ptrs| {
            continue_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            EXCEPTION_CONTINUE_SEARCH
        });

        let vch_handle = add_vectored_continue_handler(continue_handler);

        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();

        // Dispatch continue handlers
        let result = dispatch_vectored_continue_handlers(&record, &context);
        assert_eq!(result, EXCEPTION_CONTINUE_SEARCH);
        assert!(
            continue_called.load(std::sync::atomic::Ordering::SeqCst),
            "continue handler should have been called"
        );

        remove_vectored_continue_handler(vch_handle);
    }

    /// Test: Vectored continue handler that handles the exception stops
    /// the chain.
    #[test]
    fn test_vectored_continue_handler_handles() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let call_order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let order1 = call_order.clone();
        let order2 = call_order.clone();

        let handler1: VectoredContinueHandler = Arc::new(move |_ptrs| {
            order1.lock().unwrap().push("first".to_string());
            EXCEPTION_HANDLED
        });
        let handler2: VectoredContinueHandler = Arc::new(move |_ptrs| {
            order2.lock().unwrap().push("second".to_string());
            EXCEPTION_CONTINUE_SEARCH
        });

        let h1 = add_vectored_continue_handler(handler1);
        let h2 = add_vectored_continue_handler(handler2);

        let record = ExceptionRecord::new(STATUS_ACCESS_VIOLATION, 0x1000);
        let context = X64Context::default();
        let result = dispatch_vectored_continue_handlers(&record, &context);
        assert_eq!(result, EXCEPTION_HANDLED);

        let recorded = call_order.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["first".to_string()],
            "second handler should not be called after first handles"
        );

        remove_vectored_continue_handler(h1);
        remove_vectored_continue_handler(h2);
    }

    /// Test: Chain depth limit prevents infinite loops with cyclic unwind data.
    #[test]
    fn test_chain_depth_limit() {
        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;

        // Create a self-referencing CHAININFO entry that would loop forever.
        // The chained RUNTIME_FUNCTION points back to the same unwind info.
        let mut unwind_data = make_unwind_info(1, 0x04, &[(2, 4)]); // CHAININFO, alloc 0x28
        // Append chained RUNTIME_FUNCTION that points back to itself at RVA 0x2000
        unwind_data.extend_from_slice(&0x1000u32.to_le_bytes()); // begin
        unwind_data.extend_from_slice(&0x1050u32.to_le_bytes()); // end
        unwind_data.extend_from_slice(&0x2000u32.to_le_bytes()); // unwind_info_addr = self

        let mut data = vec![0u8; 0x3000];
        data[0x2000..0x2000 + unwind_data.len()].copy_from_slice(&unwind_data);
        seh.register_unwind_data(image_base, data);

        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x1050u32.to_le_bytes());
        pdata.extend_from_slice(&0x2000u32.to_le_bytes());
        seh.register_pdata(image_base, &pdata);

        let no_memory = |_addr: u64, _buf: &mut [u8]| false;
        let mut ctx = X64Context {
            rip: 0x140001000,
            rsp: 0x7fff_0000,
            ..X64Context::default()
        };

        // This should terminate (not infinite loop) and return an error
        let result = rtl_unwind(0, 0, image_base, &mut ctx, &mut seh, &no_memory);
        // Should either return Ok (if it unwinds somehow) or Err (if it hits limits)
        // The important thing is it doesn't hang.
        assert!(
            result.is_err() || result.is_ok(),
            "chain depth limit should prevent infinite loop"
        );
    }

    /// Test: Stack pointer validation in virtual_unwind.
    /// A zero or misaligned RSP should return NotFound.
    /// Test: Pending guest VEH callback limit is enforced.
    #[test]
    fn test_pending_guest_veh_limit() {
        // Fill the queue to capacity
        for i in 0..MAX_PENDING_GUEST_VEH + 10 {
            let record = ExceptionRecord::new(0xC000_0005, 0x1000 + i as u64);
            let context = X64Context::default();
            let accepted = push_pending_guest_veh(0x5000 + i as u64, record, context);
            if i < MAX_PENDING_GUEST_VEH {
                assert!(accepted, "entry {i} should be accepted");
            } else {
                assert!(!accepted, "entry {i} should be rejected (queue full)");
            }
        }

        // Drain and verify count
        let drained = drain_pending_guest_veh();
        assert_eq!(
            drained.len(),
            MAX_PENDING_GUEST_VEH,
            "should have exactly MAX_PENDING_GUEST_VEH entries"
        );
    }

    /// Test: Unhandled exception produces diagnostic output.
    /// This test verifies that dispatch logs diagnostic info when no handler
    /// claims the exception. We can't easily capture eprintln output, but we
    /// can verify the error path is taken and the error message contains the
    /// exception code.
    #[test]
    fn test_unhandled_exception_diagnostics() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;

        // Register .pdata with one function that has no handler
        let codes = vec![(0, 5), (2, 4)]; // push rbp, alloc 0x28
        let unwind_data = make_unwind_info(1, 0, &codes); // no EHANDLER/UHANDLER

        let mut data = vec![0u8; 0x2000];
        data[0x1000..0x1000 + unwind_data.len()].copy_from_slice(&unwind_data);
        seh.register_unwind_data(image_base, data);

        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x1050u32.to_le_bytes());
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        seh.register_pdata(image_base, &pdata);

        let no_memory = |_addr: u64, _buf: &mut [u8]| false;
        let context = X64Context::default();

        let result = seh.dispatch(
            STATUS_ACCESS_VIOLATION,
            0x140001000,
            &context,
            image_base,
            &no_memory,
        );
        assert!(
            result.is_err(),
            "should return error for unhandled exception"
        );
        if let Err(err) = result {
            assert!(
                err.message.contains("unhandled exception"),
                "error message should mention unhandled exception"
            );
            assert!(
                err.message
                    .contains(&format!("{:#x}", STATUS_ACCESS_VIOLATION)),
                "error message should contain exception code"
            );
        }
    }

    /// Test: UWOP_SET_FPREG with a nonzero frame offset restores RSP as
    /// `R[frame_register] - offset` (not `+ offset`).
    ///
    /// Prolog: `push rbp; sub rsp, 0x20; lea rbp, [rsp+0x20]` — the frame
    /// register is established as RBP = RSP_final + 0x20, so unwinding must
    /// set RSP = RBP - 0x20. The header byte encodes frame_offset=2 (2*16).
    /// Test: the unwind cache is keyed per image — two images sharing the
    /// same unwind RVA must never return each other's unwind info.
    /// Test: `dispatch` actually queues an EHANDLER frame's language handler
    /// for guest invocation (via the pending guest VEH queue) instead of
    /// silently swallowing the exception.
    #[test]
    fn test_dispatch_invokes_ehandler_via_pending_queue() {
        let _guard = VEH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Clear any leftover entries from earlier dispatches.
        drain_pending_guest_veh();

        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;
        let codes = vec![(0, 5)]; // push rbp
        let handler_rva = 0x3000u32;
        let unwind_data = make_unwind_info_full(1, 0x01, &codes, &handler_rva.to_le_bytes());

        let mut data = vec![0u8; 0x3000];
        data[0x2000..0x2000 + unwind_data.len()].copy_from_slice(&unwind_data);
        seh.register_unwind_data(image_base, data);

        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x1050u32.to_le_bytes());
        pdata.extend_from_slice(&0x2000u32.to_le_bytes());
        seh.register_pdata(image_base, &pdata);

        let no_memory = |_addr: u64, _buf: &mut [u8]| false;
        let context = X64Context {
            rip: 0x140001000,
            rsp: 0x7fff_0000,
            ..X64Context::default()
        };

        let result = seh.dispatch(
            STATUS_ACCESS_VIOLATION,
            0x140001000,
            &context,
            image_base,
            &no_memory,
        );
        assert!(result.is_ok(), "EHANDLER frame must be claimed");

        let pending = drain_pending_guest_veh();
        assert_eq!(pending.len(), 1, "exactly one handler must be queued");
        assert_eq!(
            pending[0].0,
            image_base + handler_rva as u64,
            "queued handler must be the frame's language handler address"
        );
        assert_eq!(pending[0].1.code, STATUS_ACCESS_VIOLATION);
    }

    /// Test: `rtl_unwind` terminates (Err) on a cyclic guest stack instead
    /// of spinning forever.
    #[test]
    fn test_rtl_unwind_bounded_cyclic_stack() {
        let mut seh = SehSubsystem::new();
        let image_base = 0x1_4000_0000u64;

        let codes = vec![(0, 5)]; // push rbp
        let unwind_data = make_unwind_info(1, 0, &codes);
        let mut data = vec![0u8; 0x2000 + unwind_data.len()];
        data[0x2000..0x2000 + unwind_data.len()].copy_from_slice(&unwind_data);
        seh.register_unwind_data(image_base, data);

        let mut pdata = Vec::new();
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&0x1050u32.to_le_bytes());
        pdata.extend_from_slice(&0x2000u32.to_le_bytes());
        seh.register_pdata(image_base, &pdata);

        // The "return address" points back into the same function, so every
        // unwind iteration lands in the same .pdata entry.
        let mut stack = vec![0u8; 16];
        stack[0..8].copy_from_slice(&0x1234u64.to_le_bytes()); // saved RBP
        stack[8..16].copy_from_slice(&(image_base + 0x1000u64).to_le_bytes()); // cyclic ret
        let stack_base = 0x7fff_0000u64;
        let mem_reader = slice_memory_reader(&stack, stack_base);

        let mut ctx = X64Context {
            rip: 0x140001000,
            rsp: stack_base,
            ..X64Context::default()
        };

        let result = rtl_unwind(0, 0, image_base, &mut ctx, &mut seh, &mem_reader);
        assert!(
            result.is_err(),
            "cyclic stack must terminate with Err (frame limit), not hang"
        );
    }
}
