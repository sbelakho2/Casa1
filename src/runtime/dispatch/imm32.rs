//! Input-method dispatch: the imm32.dll exports, in a dedicated module per
//! the audit's modularity requirement.  No IME is installed in the runtime,
//! so the surface answers the documented no-IME semantics: `ImmGetContext`
//! returns NULL (no input context), `ImmIsIME`/`ImmGetOpenStatus` report
//! FALSE, and the composition functions report the empty composition.
//!
//! Layer contract: the Imm* functions return BOOL/HDC-style values in EAX.

use super::super::*;

impl PeHostRuntime {
    /// Route every IMM thunk to its dispatch function.
    pub(crate) fn dispatch_imm(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::ImmGetContext
            | HostThunk::ImmGetDefaultIMEWnd
            | HostThunk::ImmGetVirtualKey => {
                // No IME: no input context, no default IME window, no
                // virtual key.
                let _hwnd = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::ImmIsIME | HostThunk::ImmGetOpenStatus => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::ImmReleaseContext => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let _imc = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::ImmGetCompositionStringW => {
                let _imc = guest_call_arg(state, memory, 0)?;
                let _index = guest_call_arg_u32(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let buffer_size = guest_call_arg_u32(state, memory, 3)?;
                if buffer != 0 && buffer_size >= 2 {
                    write_guest_u16(memory, buffer, 0).ok();
                }
                // No composition: the empty string (0 bytes written).
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::ImmSetCompositionStringW
            | HostThunk::ImmNotifyIME
            | HostThunk::ImmSimulateHotKey => {
                state.set(Register::Rax, 0);
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted IMM thunk {thunk:?}"),
            )),
        }
    }
}
