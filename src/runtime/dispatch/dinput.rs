//! DirectInput dispatch: the dinput.dll exports, in a dedicated module per
//! the audit's modularity requirement.  `DirectInputCreateW`/`DirectInputCreateEx`
//! hand out the DirectInput object (the classic IDirectInput7 surface);
//! no input devices exist in the runtime, so `CreateDevice` answers
//! DIERR_DEVICENOTREG — the honest no-device result.
//!
//! Layer contract: the create functions return the device object in EAX
//! (0 on failure); the method calls return HRESULTs.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// DIERR_DEVICENOTREG.
const DIERR_DEVICENOTREG: u32 = 0x8007_0012;
/// DI_OK.
const DI_OK: u32 = 0;

impl PeHostRuntime {
    /// Route every DirectInput thunk to its dispatch function.
    pub(crate) fn dispatch_dinput(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::DirectInputCreateW | HostThunk::DirectInputCreateEx => {
                let _instance = guest_call_arg(state, memory, 0)?;
                let _version = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                let mut arg = 3;
                if matches!(thunk, HostThunk::DirectInputCreateEx) {
                    let _iid = guest_call_arg(state, memory, 3)?;
                    arg = 4;
                }
                let _outer = guest_call_arg(state, memory, arg)?;
                if out == 0 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let object = self
                    .alloc_guest_object(memory, GuestObjectKind::DirectInput, vtable)
                    .unwrap_or(0);
                if object == 0 {
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
                self.dinput_objects.insert(object, 0_u32);
                if out != 0 {
                    write_guest_pointer(memory, out, object, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(DI_OK));
                Ok(())
            }
            HostThunk::DirectInputCreateDevice => {
                let _this = guest_call_arg(state, memory, 0)?;
                let _guid = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No input devices are registered.
                state.set(Register::Rax, u64::from(DIERR_DEVICENOTREG));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted DirectInput thunk {thunk:?}"),
            )),
        }
    }
}
