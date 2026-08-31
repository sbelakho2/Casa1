//! Common-dialog dispatch: the comdlg32.dll exports, in a dedicated module
//! per the audit's modularity requirement.  The runtime has no common-dialog
//! UI host, so the dialog entry points answer the documented failure: they
//! return FALSE and record the CDERR_DIALOGFAILURE error that
//! `CommDlgExtendedError` reports — exactly the behavior of a dialog that
//! fails to initialize.
//!
//! Layer contract: the dialog functions return BOOL in EAX;
//! `CommDlgExtendedError` returns the last dialog error code.

use super::super::*;

/// CDERR_INITIALIZATION.
const CDERR_INITIALIZATION: u32 = 0x0004;

impl PeHostRuntime {
    /// Route every common-dialog thunk to its dispatch function.
    pub(crate) fn dispatch_comdlg(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::GetOpenFileNameW
            | HostThunk::GetSaveFileNameW
            | HostThunk::ChooseColorW
            | HostThunk::ChooseFontW
            | HostThunk::FindTextW
            | HostThunk::ReplaceTextW
            | HostThunk::PageSetupDlgW
            | HostThunk::PrintDlgW
            | HostThunk::PrintDlgExW => {
                // No common-dialog host exists; the dialog fails to
                // initialize (the documented FALSE + CDERR_DIALOGFAILURE).
                let _struct = guest_call_arg(state, memory, 0)?;
                self.comdlg_last_error = CDERR_INITIALIZATION;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::CommDlgExtendedError => {
                let error = self.comdlg_last_error;
                state.set(Register::Rax, u64::from(error));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted common-dialog thunk {thunk:?}"),
            )),
        }
    }
}
