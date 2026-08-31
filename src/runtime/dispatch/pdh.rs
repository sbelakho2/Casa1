//! Performance-database and event-log dispatch: the pdh.dll and wevtapi.dll
//! exports, in a dedicated module per the audit's modularity requirement.
//! The PDH surface is a real query/counter state: `PdhOpenQuery` hands out
//! a query, `PdhAddCounter` registers a counter (the counter path is
//! recorded), `PdhCollectQueryData` collects the (empty) data, and
//! `PdhGetFormattedCounterValue` reports the honest PDH_CSTATUS_NO_DATA.
//! The event-log surface opens sessions/logs/queries/subscriptions and
//! reports the honest zero-event results.
//!
//! Layer contract: every export returns its ERROR_*/PDH_*/ERROR_* code in
//! EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_NO_MORE_ITEMS.
const ERROR_NO_MORE_ITEMS: u32 = 259;
/// PDH_CSTATUS_NO_DATA — the counter has no data.
const PDH_CSTATUS_NO_DATA: u32 = 0x8000_07d5;
/// ERROR_INSUFFICIENT_BUFFER.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

impl PeHostRuntime {
    /// Route every PDH thunk to its dispatch function.
    pub(crate) fn dispatch_pdh(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::PdhOpenQuery => {
                let _data_source = guest_call_arg(state, memory, 0)?;
                let _user = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let query = self
                    .alloc_guest_object(memory, GuestObjectKind::PdhQuery, vtable)
                    .unwrap_or(0);
                if query == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                self.pdh_queries.insert(query, Vec::new());
                write_guest_pointer(memory, out, query, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PdhCloseQuery => {
                let query = guest_call_arg(state, memory, 0)?;
                self.pdh_queries.remove(&query);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PdhAddCounter => {
                let query = guest_call_arg(state, memory, 0)?;
                let path = guest_call_arg(state, memory, 1)?;
                let _user = guest_call_arg(state, memory, 2)?;
                let out = guest_call_arg(state, memory, 3)?;
                let Some(counters) = self.pdh_queries.get_mut(&query) else {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                };
                let path_text = read_utf16_string(memory, path).unwrap_or_default();
                let handle = 0x8000_0000 | (counters.len() as u64);
                counters.push(path_text);
                if out != 0 {
                    write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PdhRemoveCounter => {
                let _counter = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PdhCollectQueryData => {
                let _query = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PdhGetFormattedCounterValue => {
                let _counter = guest_call_arg(state, memory, 0)?;
                let _format = guest_call_arg_u32(state, memory, 1)?;
                let status_out = guest_call_arg(state, memory, 2)?;
                let _value = guest_call_arg(state, memory, 3)?;
                if status_out != 0 {
                    write_guest_u32(memory, status_out, PDH_CSTATUS_NO_DATA).ok();
                }
                // The counter has no collected data.
                state.set(Register::Rax, u64::from(PDH_CSTATUS_NO_DATA));
                Ok(())
            }
            HostThunk::PdhEnumObjects | HostThunk::PdhEnumCounters => {
                // No performance objects are registered.
                let _data_source = guest_call_arg(state, memory, 0)?;
                let _machine = guest_call_arg(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let size = guest_call_arg(state, memory, 3)?;
                let _detail = guest_call_arg_u32(state, memory, 4)?;
                let _refresh = guest_call_arg_u32(state, memory, 5)?;
                if buffer != 0 {
                    write_guest_u16(memory, buffer, 0).ok();
                }
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted PDH thunk {thunk:?}"),
            )),
        }
    }

    /// Route every event-log thunk to its dispatch function.
    pub(crate) fn dispatch_wevtapi(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::EvtOpenSession => {
                let _login = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let _server = guest_call_arg(state, memory, 2)?;
                let out = guest_call_arg(state, memory, 3)?;
                let handle = self.evt_alloc_handle(memory, GuestObjectKind::EvtSession)?;
                if handle == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::EvtOpenLog
            | HostThunk::EvtQuery
            | HostThunk::EvtSubscribe
            | HostThunk::EvtCreateBookmark => {
                let mut arg = 0;
                if matches!(thunk, HostThunk::EvtOpenLog) {
                    let _session = guest_call_arg(state, memory, 0)?;
                    let _path = guest_call_arg(state, memory, 1)?;
                    let _flags = guest_call_arg_u32(state, memory, 2)?;
                    arg = 3;
                } else if matches!(thunk, HostThunk::EvtQuery) {
                    let _session = guest_call_arg(state, memory, 0)?;
                    let _path = guest_call_arg(state, memory, 1)?;
                    let _query = guest_call_arg(state, memory, 2)?;
                    let _flags = guest_call_arg_u32(state, memory, 3)?;
                    arg = 4;
                } else if matches!(thunk, HostThunk::EvtSubscribe) {
                    let _session = guest_call_arg(state, memory, 0)?;
                    let _signal = guest_call_arg(state, memory, 1)?;
                    let _path = guest_call_arg(state, memory, 2)?;
                    let _query = guest_call_arg(state, memory, 3)?;
                    let _bookmark = guest_call_arg(state, memory, 4)?;
                    arg = 5;
                }
                let out = guest_call_arg(state, memory, arg)?;
                let kind = if matches!(thunk, HostThunk::EvtOpenLog) {
                    GuestObjectKind::EvtLog
                } else if matches!(thunk, HostThunk::EvtQuery) {
                    GuestObjectKind::EvtQuery
                } else if matches!(thunk, HostThunk::EvtSubscribe) {
                    GuestObjectKind::EvtSubscription
                } else {
                    GuestObjectKind::EvtBookmark
                };
                let handle = self.evt_alloc_handle(memory, kind)?;
                if handle == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::EvtNext => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _count = guest_call_arg_u32(state, memory, 1)?;
                let _events = guest_call_arg(state, memory, 2)?;
                let _timeout = guest_call_arg_u32(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                // No events exist in any log.
                state.set(Register::Rax, u64::from(ERROR_NO_MORE_ITEMS));
                Ok(())
            }
            HostThunk::EvtRender => {
                let _context = guest_call_arg(state, memory, 0)?;
                let event = guest_call_arg(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let buffer_size = guest_call_arg(state, memory, 3)?;
                let _buffer = guest_call_arg(state, memory, 4)?;
                let used = guest_call_arg(state, memory, 5)?;
                let _property = guest_call_arg(state, memory, 6)?;
                if event == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                if used != 0 {
                    write_guest_u32(memory, used, 0).ok();
                }
                let _ = buffer_size;
                state.set(Register::Rax, u64::from(ERROR_INSUFFICIENT_BUFFER));
                Ok(())
            }
            HostThunk::EvtClose => {
                let handle = guest_call_arg(state, memory, 0)?;
                self.evt_handles.remove(&handle);
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted event-log thunk {thunk:?}"),
            )),
        }
    }

    fn evt_alloc_handle(
        &mut self,
        memory: &mut MemoryImage,
        kind: GuestObjectKind,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let handle = self.alloc_guest_object(memory, kind, vtable).unwrap_or(0);
        if handle != 0 {
            self.evt_handles.insert(handle, 0_u32);
        }
        Ok(handle)
    }
}
