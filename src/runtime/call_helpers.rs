//! Guest call argument/pointer helpers.

use super::*;

pub(crate) fn read_guest_pointer(
    memory: &MemoryImage,
    address: u64,
    arch: GuestArch,
) -> AppResult<u64> {
    match arch {
        GuestArch::X64 => memory.read_u64(address),
        GuestArch::X86 => Ok(read_u32(memory, address)? as u64),
    }
}

pub(crate) fn write_guest_pointer(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
    arch: GuestArch,
) -> AppResult<()> {
    match arch {
        GuestArch::X64 => {
            write_u64(memory, address, value);
            Ok(())
        }
        GuestArch::X86 => {
            let narrowed = match u32::try_from(value) {
                Ok(narrowed) => narrowed,
                Err(_) => {
                    let narrowed = value as u32;
                    let sign_extended = (narrowed as i32 as i64) as u64;
                    if sign_extended != value {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!("guest pointer {value:#x} does not fit in x86 address space"),
                        ));
                    }
                    narrowed
                }
            };
            write_u32(memory, address, narrowed);
            Ok(())
        }
    }
}

pub(crate) fn guest_call_arg(
    state: &CpuState,
    memory: &MemoryImage,
    index: usize,
) -> AppResult<u64> {
    match state.arch {
        GuestArch::X64 => match index {
            0 => Ok(state.get(Register::Rcx)),
            1 => Ok(state.get(Register::Rdx)),
            2 => Ok(state.get(Register::R8)),
            3 => Ok(state.get(Register::R9)),
            _ => read_guest_pointer(
                memory,
                state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8),
                GuestArch::X64,
            ),
        },
        GuestArch::X86 => read_guest_pointer(
            memory,
            state.get(Register::Rsp) + (index as u64 * 4),
            GuestArch::X86,
        ),
    }
}

/// Read a `double` thunk argument: Win64 passes floating-point arguments in
/// XMM0-XMM3; x86 cdecl passes them on the stack (8 bytes per double).
pub(crate) fn guest_call_arg_f64(
    state: &CpuState,
    memory: &MemoryImage,
    index: usize,
) -> AppResult<f64> {
    match state.arch {
        GuestArch::X64 => Ok(f64::from_bits(state.xmm[index].low)),
        GuestArch::X86 => {
            let bits = memory.read_u64(state.get(Register::Rsp) + (index as u64 * 8))?;
            Ok(f64::from_bits(bits))
        }
    }
}

/// Store a `double` return value following the guest ABI: XMM0 on x64 and
/// ST(0) (the emulated x87 stack) on x86, mirroring the `Atof` arm which
/// additionally leaves the bits in RAX for host-side inspection.
pub(crate) fn set_guest_f64_return(state: &mut CpuState, value: f64) {
    if state.arch == GuestArch::X64 {
        state.xmm[0].low = value.to_bits();
        state.xmm[0].high = 0;
    } else {
        state.x87.stack.push(value);
    }
    state.set(Register::Rax, value.to_bits());
}

pub(crate) fn guest_call_arg_u32(
    state: &CpuState,
    memory: &MemoryImage,
    index: usize,
) -> AppResult<u32> {
    Ok(guest_call_arg(state, memory, index)? as u32)
}
