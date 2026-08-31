//! .NET activation dispatch: the mscoree.dll exports, in a dedicated module
//! per the audit's modularity requirement.  Casa1 does not host the
//! Microsoft CLR; these exports implement the honest semantics of a Windows
//! machine with no .NET runtime available: every activation entry point
//! fails with `COR_E_CLRNOTAVAILABLE` (0x80131013) and the directory
//! queries report failure, exactly as they do on a real Windows system
//! without .NET installed.
//!
//! Layer contract: every export returns its HRESULT in EAX.

use super::super::*;

/// COR_E_CLRNOTAVAILABLE — "the CLR is unavailable" (the error a Windows
/// machine without .NET returns from CLR activation).
const COR_E_CLRNOTAVAILABLE: u32 = 0x8013_1013;
/// E_FAIL.
const E_FAIL: u32 = 0x8000_4005;

impl PeHostRuntime {
    /// Route every mscoree thunk to its dispatch function.
    pub(crate) fn dispatch_mscoree(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::ClrCreateInstance => self.dispatch_clr_create_instance(state, memory),
            HostThunk::CorBindToRuntime | HostThunk::CorBindToRuntimeEx => {
                self.dispatch_cor_bind_to_runtime(state, memory)
            }
            HostThunk::GetCorSystemDirectory => {
                self.dispatch_get_cor_system_directory(state, memory)
            }
            HostThunk::GetRequestedRuntimeInfo => {
                self.dispatch_get_requested_runtime_info(state, memory)
            }
            HostThunk::LoadLibraryShim => self.dispatch_load_library_shim(state, memory),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted mscoree thunk {thunk:?}"),
            )),
        }
    }

    /// `CLRCreateInstance(rclsid, riid, ppv)` — no CLR meta host is
    /// installed.
    pub(crate) fn dispatch_clr_create_instance(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _rclsid = guest_call_arg(state, memory, 0)?;
        let _riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
        Ok(())
    }

    /// `CorBindToRuntimeEx(pwszVersion, pwszBuildFlavor, startupFlags,
    /// rclsid, riid, ppv)` (and the 4-argument CorBindToRuntime) — no CLR
    /// is available to bind.
    pub(crate) fn dispatch_cor_bind_to_runtime(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _version = guest_call_arg(state, memory, 0)?;
        let _flavor = guest_call_arg(state, memory, 1)?;
        let _startup_flags = guest_call_arg(state, memory, 2)?;
        let _rclsid = guest_call_arg(state, memory, 3)?;
        let _riid = guest_call_arg(state, memory, 4)?;
        let out = guest_call_arg(state, memory, 5)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
        Ok(())
    }

    /// `GetCORSystemDirectory(pbuffer, cchBuffer, pdwlength)` — no CLR
    /// directory exists.
    pub(crate) fn dispatch_get_cor_system_directory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let buffer = guest_call_arg(state, memory, 0)?;
        let _capacity = guest_call_arg_u32(state, memory, 1)?;
        let length_out = guest_call_arg(state, memory, 2)?;
        if buffer != 0 {
            write_guest_u16(memory, buffer, 0).ok();
        }
        if length_out != 0 {
            write_guest_u32(memory, length_out, 0).ok();
        }
        state.set(Register::Rax, u64::from(E_FAIL));
        Ok(())
    }

    /// `GetRequestedRuntimeInfo(...)` — no runtime is installed.
    pub(crate) fn dispatch_get_requested_runtime_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _pwsz = guest_call_arg(state, memory, 0)?;
        let _build = guest_call_arg(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        let _version = guest_call_arg_u32(state, memory, 3)?;
        let _dir = guest_call_arg(state, memory, 4)?;
        let _dir_size = guest_call_arg_u32(state, memory, 5)?;
        let _version_size = guest_call_arg(state, memory, 6)?;
        let _actual = guest_call_arg(state, memory, 7)?;
        let _actual_dir = guest_call_arg(state, memory, 8)?;
        state.set(Register::Rax, u64::from(E_FAIL));
        Ok(())
    }

    /// `LoadLibraryShim(...)` — no shim DLLs exist.
    pub(crate) fn dispatch_load_library_shim(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _name = guest_call_arg(state, memory, 0)?;
        let _version = guest_call_arg(state, memory, 1)?;
        let _namespace = guest_call_arg(state, memory, 2)?;
        let _handle = guest_call_arg(state, memory, 3)?;
        state.set(Register::Rax, u64::from(E_FAIL));
        Ok(())
    }
}
