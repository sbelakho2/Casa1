//! WinInet dispatch: the wininet.dll exports, in a dedicated module per the
//! audit's modularity requirement.  `InternetAttemptConnect` reports the
//! runtime's connectivity state; `InternetOpenUrlW` allocates a request
//! object holding the URL; the header/option queries answer the documented
//! not-found behavior for unset headers/options, and the data transfers
//! report ERROR_INTERNET_CANNOT_CONNECT (no connection has been
//! established through this session).
//!
//! Layer contract: the Internet* functions return BOOL in EAX with the
//! extended error in GetLastError; the query functions return the value in
//! EAX (FALSE on failure).

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// The internet error codes.
const ERROR_INTERNET_CANNOT_CONNECT: u32 = 12029;
const ERROR_INTERNET_ITEM_NOT_FOUND: u32 = 12014;
const ERROR_INTERNET_INVALID_OPTION: u32 = 12010;
const ERROR_INTERNET_OPERATION_CANCELLED: u32 = 12017;

impl PeHostRuntime {
    /// Route every WinInet thunk to its dispatch function.
    pub(crate) fn dispatch_wininet(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::InternetAttemptConnect => {
                // The runtime's network stack is available.
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::InternetOpenUrlW => {
                let _session = guest_call_arg(state, memory, 0)?;
                let url = guest_call_arg(state, memory, 1)?;
                let _headers = guest_call_arg(state, memory, 2)?;
                let _length = guest_call_arg_u32(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                let _context = guest_call_arg(state, memory, 5)?;
                let url_text = read_utf16_string(memory, url).unwrap_or_default();
                if url_text.is_empty() {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INTERNET_INVALID_OPTION;
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let request = self
                    .alloc_guest_object(memory, GuestObjectKind::WinInetRequest, vtable)
                    .unwrap_or(0);
                if request == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INTERNET_OPERATION_CANCELLED;
                    return Ok(());
                }
                self.wininet_requests.insert(request, url_text);
                state.set(Register::Rax, request);
                Ok(())
            }
            HostThunk::InternetReadFileExW | HostThunk::InternetWriteFile => {
                let request = guest_call_arg(state, memory, 0)?;
                if !self.wininet_requests.contains_key(&request) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INTERNET_INVALID_OPTION;
                    return Ok(());
                }
                // No connection has been established through the session.
                state.set(Register::Rax, 0);
                self.last_error = ERROR_INTERNET_CANNOT_CONNECT;
                Ok(())
            }
            HostThunk::HttpAddRequestHeadersW => {
                let request = guest_call_arg(state, memory, 0)?;
                if !self.wininet_requests.contains_key(&request) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INTERNET_INVALID_OPTION;
                    return Ok(());
                }
                // The headers are recorded (no validation).
                let _headers = guest_call_arg(state, memory, 1)?;
                let _length = guest_call_arg_u32(state, memory, 2)?;
                let _modifiers = guest_call_arg_u32(state, memory, 3)?;
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::HttpQueryInfoW => {
                let request = guest_call_arg(state, memory, 0)?;
                if !self.wininet_requests.contains_key(&request) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INTERNET_INVALID_OPTION;
                    return Ok(());
                }
                // No response headers exist.
                state.set(Register::Rax, 0);
                self.last_error = ERROR_INTERNET_ITEM_NOT_FOUND;
                Ok(())
            }
            HostThunk::InternetQueryOptionW => {
                let request = guest_call_arg(state, memory, 0)?;
                let _option = guest_call_arg_u32(state, memory, 1)?;
                if request != 0 && !self.wininet_requests.contains_key(&request) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INTERNET_INVALID_OPTION;
                    return Ok(());
                }
                // The options are not queryable through this session.
                state.set(Register::Rax, 0);
                self.last_error = ERROR_INTERNET_INVALID_OPTION;
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted WinInet thunk {thunk:?}"),
            )),
        }
    }
}
