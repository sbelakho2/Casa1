//! VB6-runtime dispatch: the msvbvm60.dll exports, in a dedicated module
//! per the audit's modularity requirement.  The BASIC_CLASS_* exports are
//! the runtime's IUnknown/IDispatch entry points for its intrinsic objects:
//! the reference-counting pair routes through the shared guest-object
//! machinery and the dispatch pair answers the honest no-typeinfo results;
//! the native-call exports (`DllCall`/`DllFunc`/`DllProc`) report that the
//! VB6 native-call facility has no backend.
//!
//! Layer contract: the COM entry points return HRESULTs in EAX; the
//! native-call entry points return the documented failure.

use super::super::*;

/// S_OK.
const S_OK: u32 = 0;
/// E_NOTIMPL — the native-call facility has no backend.
const E_NOTIMPL: u32 = 0x8000_4001;
/// DISP_E_MEMBERNOTFOUND.
const DISP_E_MEMBERNOTFOUND: u32 = 0x8002_0003;

impl PeHostRuntime {
    /// Route every VB6-runtime thunk to its dispatch function.
    pub(crate) fn dispatch_msvbvm(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::BasicClassAddRef => {
                let this = guest_call_arg(state, memory, 0)?;
                self.add_ref_guest_object(this)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BasicClassRelease => {
                let this = guest_call_arg(state, memory, 0)?;
                self.release_guest_object(this)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BasicClassQueryInterface => {
                // The object's identity: S_OK with the same object.
                let this = guest_call_arg(state, memory, 0)?;
                let _riid = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, this, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BasicClassGetIDsOfNames
            | HostThunk::BasicDispatchInvoke
            | HostThunk::BasicClassInvoke => {
                // No typeinfo: the members are unknown.
                let _this = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(DISP_E_MEMBERNOTFOUND));
                Ok(())
            }
            HostThunk::DllCall | HostThunk::DllFunc | HostThunk::DllProc => {
                // The VB6 native-call facility has no backend.
                state.set(Register::Rax, u64::from(E_NOTIMPL));
                Ok(())
            }
            HostThunk::DllMain => {
                // The module entry: nothing to initialize.
                state.set(Register::Rax, 1);
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted VB6-runtime thunk {thunk:?}"),
            )),
        }
    }
}
