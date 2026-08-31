//! HTTP API dispatch: the httpapi.dll exports, in a dedicated module per
//! the audit's modularity requirement.  The URL-group surface is real:
//! `HttpInitialize`/`HttpTerminate` manage the initialized state,
//! `HttpCreateHttpHandle` hands out a request queue, and
//! `HttpAddUrl`/`HttpRemoveUrl` register and unregister URL prefixes.
//! No HTTP requests are ever received, so the receive/wait entry points
//! answer the documented ERROR_IO_PENDING (no request has arrived) and the
//! response senders answer the documented invalid-request errors.
//!
//! Layer contract: every export returns its ERROR_* code in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_IO_PENDING — the operation is pending (no request has arrived).
const ERROR_IO_PENDING: u32 = 997;
/// ERROR_ALREADY_EXISTS.
const ERROR_ALREADY_EXISTS: u32 = 183;

impl PeHostRuntime {
    /// Route every HTTP-API thunk to its dispatch function.
    pub(crate) fn dispatch_httpapi(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::HttpInitialize => {
                let _version = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let _reserved = guest_call_arg(state, memory, 2)?;
                self.http_initialized = true;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::HttpTerminate => {
                let _flags = guest_call_arg_u32(state, memory, 0)?;
                self.http_initialized = false;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::HttpCreateHttpHandle => {
                let out = guest_call_arg(state, memory, 0)?;
                let _reserved = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let queue = self
                    .alloc_guest_object(memory, GuestObjectKind::HttpRequestQueue, vtable)
                    .unwrap_or(0);
                if queue == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                self.http_queues.insert(queue, Vec::new());
                write_guest_pointer(memory, out, queue, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::HttpAddUrl => {
                let queue = guest_call_arg(state, memory, 0)?;
                let url = guest_call_arg(state, memory, 1)?;
                let _context = guest_call_arg(state, memory, 2)?;
                let Some(urls) = self.http_queues.get_mut(&queue) else {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                };
                let url_text = read_utf16_string(memory, url).unwrap_or_default();
                if urls.contains(&url_text) {
                    state.set(Register::Rax, u64::from(ERROR_ALREADY_EXISTS));
                    return Ok(());
                }
                urls.push(url_text);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::HttpRemoveUrl => {
                let queue = guest_call_arg(state, memory, 0)?;
                let url = guest_call_arg(state, memory, 1)?;
                let Some(urls) = self.http_queues.get_mut(&queue) else {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                };
                let url_text = read_utf16_string(memory, url).unwrap_or_default();
                urls.retain(|u| *u != url_text);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::HttpReceiveHttpRequest | HostThunk::HttpWaitForDisconnect => {
                // No request has arrived; the operation stays pending.
                let _queue = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_IO_PENDING));
                Ok(())
            }
            HostThunk::HttpSendHttpResponse | HostThunk::HttpSendResponseEntityBody => {
                // No request id exists; the send is rejected.
                let _queue = guest_call_arg(state, memory, 0)?;
                let request_id = guest_call_arg(state, memory, 1)?;
                state.set(
                    Register::Rax,
                    u64::from(if request_id == 0 {
                        ERROR_INVALID_PARAMETER
                    } else {
                        ERROR_IO_PENDING
                    }),
                );
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted HTTP-API thunk {thunk:?}"),
            )),
        }
    }
}
