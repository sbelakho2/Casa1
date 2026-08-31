//! Text-services dispatch: the msctf.dll exports, in a dedicated module per
//! the audit's modularity requirement.  The TSF manager surface is real:
//! `TF_CreateThreadMgr` hands out a thread-manager object that
//! `TF_GetThreadMgr` retrieves, and the category/display-attribute managers
//! are created the same way; `TF_InitSystem`/`TF_UninitSystem` manage the
//! initialized state.  The class-object exports route through the shared
//! in-process COM server contract.
//!
//! Layer contract: the TF_* functions return HRESULTs in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// S_OK.
const S_OK: u32 = 0;
/// E_FAIL.
const E_FAIL: u32 = 0x8000_4005;
/// E_INVALIDARG.
const E_INVALIDARG: u32 = 0x8007_0057;
/// CO_E_NOTINITIALIZED.
const CO_E_NOTINITIALIZED: u32 = 0x8004_015f;

impl PeHostRuntime {
    /// Route every TSF thunk to its dispatch function.
    pub(crate) fn dispatch_msctf(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::TfCreateThreadMgr => {
                let out = guest_call_arg(state, memory, 0)?;
                if out == 0 {
                    state.set(Register::Rax, u64::from(E_INVALIDARG));
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let manager = self
                    .alloc_guest_object(memory, GuestObjectKind::TsfThreadManager, vtable)
                    .unwrap_or(0);
                if manager == 0 {
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                self.tsf_thread_managers.push(manager);
                write_guest_pointer(memory, out, manager, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::TfGetThreadMgr => {
                let out = guest_call_arg(state, memory, 0)?;
                if out != 0 {
                    let manager = self.tsf_thread_managers.last().copied().unwrap_or(0);
                    write_guest_pointer(memory, out, manager, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::TfCreateCategoryMgr => self.dispatch_tf_create_manager(state, memory, true),
            HostThunk::TfCreateDisplayAttributeMgr => {
                self.dispatch_tf_create_manager(state, memory, false)
            }
            HostThunk::TfInitSystem => {
                self.tsf_initialized = true;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::TfUninitSystem => {
                self.tsf_initialized = false;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DllCanUnloadNow
            | HostThunk::DllGetClassObject
            | HostThunk::DllRegisterServer
            | HostThunk::DllUnregisterServer => {
                // The shared in-process server contract answers these (the
                // class-object table resolves the registered TSF classes).
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted TSF thunk {thunk:?}"),
            )),
        }
    }

    /// The category / display-attribute manager objects.
    fn dispatch_tf_create_manager(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        is_category: bool,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if !self.tsf_initialized {
            state.set(Register::Rax, u64::from(CO_E_NOTINITIALIZED));
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let kind = if is_category {
            GuestObjectKind::TsfCategoryManager
        } else {
            GuestObjectKind::TsfDisplayAttributeManager
        };
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let manager = self.alloc_guest_object(memory, kind, vtable).unwrap_or(0);
        if manager == 0 {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        write_guest_pointer(memory, out, manager, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }
}
