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
/// PDH_MORE_DATA — the enumeration buffer was too small.
const PDH_MORE_DATA: u32 = 0x8000_07d2;
/// PDH_CSTATUS_NO_DATA — the counter has no collected data.
const PDH_CSTATUS_NO_DATA: u32 = 0x8000_07d5;
/// PDH_CSTATUS_NO_OBJECT — the counter path names an unknown object.
const PDH_CSTATUS_NO_OBJECT: u32 = 0xc000_0bb8;
/// PDH_CSTATUS_NO_COUNTER — the object has no such counter.
const PDH_CSTATUS_NO_COUNTER: u32 = 0xc000_0bb9;
/// PDH_INVALID_HANDLE.
const PDH_INVALID_HANDLE: u32 = 0xc000_0bbc;
/// PDH_INVALID_ARGUMENT.
const PDH_INVALID_ARGUMENT: u32 = 0xc000_0bbd;
/// PDH_INVALID_DATA — a rate counter has only one sample so far.
const PDH_INVALID_DATA: u32 = 0xc000_0bd6;
/// ERROR_INSUFFICIENT_BUFFER.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// The PDH formatted-value types.
const PDH_FMT_LONG: u32 = 0x0000_0100;
const PDH_FMT_DOUBLE: u32 = 0x0000_0200;
const PDH_FMT_LARGE: u32 = 0x0000_0400;
const PDH_FMT_MASK: u32 = PDH_FMT_LONG | PDH_FMT_DOUBLE | PDH_FMT_LARGE;

/// The PERF_* counter types reported through lpdwType.
const PERF_COUNTER_RAWCOUNT: u32 = 0x0001_0000;
const PERF_RAW_FRACTION: u32 = 0x2002_0400;
const PERF_ELAPSED_TIME: u32 = 0x3024_0500;
const PERF_100NSEC_TIMER: u32 = 0x5420_7420;

/// The high bit every runtime PDH counter handle carries.
const PDH_COUNTER_HANDLE_BASE: u64 = 0x8000_0000;

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
            HostThunk::PdhCloseQuery => self.dispatch_pdh_close_query(state, memory),
            HostThunk::PdhAddCounter => self.dispatch_pdh_add_counter(state, memory),
            HostThunk::PdhRemoveCounter => self.dispatch_pdh_remove_counter(state, memory),
            HostThunk::PdhCollectQueryData => self.dispatch_pdh_collect_query_data(state, memory),
            HostThunk::PdhGetFormattedCounterValue => {
                self.dispatch_pdh_get_formatted_counter_value(state, memory)
            }
            HostThunk::PdhEnumObjects => self.dispatch_pdh_enum(state, memory, false),
            HostThunk::PdhEnumCounters => self.dispatch_pdh_enum(state, memory, true),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted PDH thunk {thunk:?}"),
            )),
        }
    }

    // ── PDH: the real counter model ────────────────────────────────────────

    /// `PdhCloseQuery(query)` — release the query and every counter that
    /// belongs to it.
    fn dispatch_pdh_close_query(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let query = guest_call_arg(state, memory, 0)?;
        self.pdh_queries.remove(&query);
        let owner = format!("q:{query:#x}");
        self.pdh_queries
            .retain(|_, entry| !is_pdh_counter_entry(entry) || entry[1] != owner);
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `PdhAddCounter(query, path, user, counterOut)` — register a counter
    /// over the real host performance data.  Unknown objects/counters are
    /// rejected with the documented PDH status codes.
    fn dispatch_pdh_add_counter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let query = guest_call_arg(state, memory, 0)?;
        let path = guest_call_arg(state, memory, 1)?;
        let _user = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if !self.pdh_queries.contains_key(&query) || is_pdh_counter_entry(&self.pdh_queries[&query])
        {
            state.set(Register::Rax, u64::from(PDH_INVALID_HANDLE));
            return Ok(());
        }
        let path_text = read_utf16_string(memory, path).unwrap_or_default();
        match parse_counter_path(&path_text) {
            Err(PdhPathError::NoObject) => {
                state.set(Register::Rax, u64::from(PDH_CSTATUS_NO_OBJECT));
                return Ok(());
            }
            Err(PdhPathError::NoCounter) => {
                state.set(Register::Rax, u64::from(PDH_CSTATUS_NO_COUNTER));
                return Ok(());
            }
            Ok(kind) => {
                let _ = kind;
                let index = self
                    .pdh_queries
                    .values()
                    .filter(|entry| is_pdh_counter_entry(entry))
                    .count() as u64;
                let handle = PDH_COUNTER_HANDLE_BASE | index;
                self.pdh_queries
                    .insert(handle, vec![path_text.clone(), format!("q:{query:#x}")]);
                if let Some(counters) = self.pdh_queries.get_mut(&query) {
                    counters.push(path_text);
                }
                if out != 0 {
                    write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
        }
    }

    /// `PdhRemoveCounter(counter)` — drop the counter registration.
    fn dispatch_pdh_remove_counter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let counter = guest_call_arg(state, memory, 0)?;
        let Some(entry) = self.pdh_queries.remove(&counter) else {
            state.set(Register::Rax, u64::from(PDH_INVALID_HANDLE));
            return Ok(());
        };
        if is_pdh_counter_entry(&entry)
            && let Some(query) = entry[1]
                .strip_prefix("q:")
                .and_then(|text| u64::from_str_radix(text, 16).ok())
            && let Some(counters) = self.pdh_queries.get_mut(&query)
            && let Some(position) = counters.iter().position(|path| path == &entry[0])
        {
            counters.remove(position);
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `PdhCollectQueryData(query)` — take a real host sample for every
    /// counter of the query (rate counters keep the previous sample for the
    /// delta computation).
    fn dispatch_pdh_collect_query_data(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let query = guest_call_arg(state, memory, 0)?;
        let Some(entry) = self.pdh_queries.get(&query) else {
            state.set(Register::Rax, u64::from(PDH_INVALID_HANDLE));
            return Ok(());
        };
        if is_pdh_counter_entry(entry) {
            state.set(Register::Rax, u64::from(PDH_INVALID_HANDLE));
            return Ok(());
        }
        let owner = format!("q:{query:#x}");
        let handles: Vec<u64> = self
            .pdh_queries
            .iter()
            .filter(|(_, entry)| is_pdh_counter_entry(entry) && entry[1] == owner)
            .map(|(handle, _)| *handle)
            .collect();
        for handle in handles {
            let Some(path) = self
                .pdh_queries
                .get(&handle)
                .and_then(|entry| entry.first().cloned())
            else {
                continue;
            };
            let Ok(kind) = parse_counter_path(&path) else {
                continue;
            };
            let Some((_instant, raw, aux)) = sample_counter(kind) else {
                continue;
            };
            if let Some(entry) = self.pdh_queries.get_mut(&handle) {
                if entry.len() >= 6 {
                    entry[4] = entry[2].clone();
                    entry[5] = entry[3].clone();
                    entry.truncate(6);
                } else {
                    entry.resize(6, String::new());
                }
                entry[2] = raw.to_string();
                entry[3] = aux.to_string();
            }
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `PdhGetFormattedCounterValue(counter, format, type, value)` — the
    /// formatted value from the collected samples.
    fn dispatch_pdh_get_formatted_counter_value(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let counter = guest_call_arg(state, memory, 0)?;
        let format = guest_call_arg_u32(state, memory, 1)?;
        let type_out = guest_call_arg(state, memory, 2)?;
        let value_out = guest_call_arg(state, memory, 3)?;
        let Some(entry) = self.pdh_queries.get(&counter) else {
            state.set(Register::Rax, u64::from(PDH_INVALID_HANDLE));
            return Ok(());
        };
        if !is_pdh_counter_entry(entry) {
            state.set(Register::Rax, u64::from(PDH_INVALID_HANDLE));
            return Ok(());
        }
        if entry.len() < 6 || entry[2].is_empty() {
            if value_out != 0 {
                write_guest_u32(memory, value_out, PDH_CSTATUS_NO_DATA).ok();
            }
            state.set(Register::Rax, u64::from(PDH_CSTATUS_NO_DATA));
            return Ok(());
        }
        let Ok(kind) = parse_counter_path(&entry[0]) else {
            state.set(Register::Rax, u64::from(PDH_CSTATUS_NO_DATA));
            return Ok(());
        };
        if type_out != 0 {
            write_guest_u32(memory, type_out, counter_perf_type(kind)).ok();
        }
        let formatted = format & PDH_FMT_MASK;
        if formatted == 0 {
            if value_out != 0 {
                write_guest_u32(memory, value_out, PDH_INVALID_ARGUMENT).ok();
            }
            state.set(Register::Rax, u64::from(PDH_INVALID_ARGUMENT));
            return Ok(());
        }
        let value = match kind {
            PdhCounterKind::ProcessorTime => {
                let (Ok(raw), Ok(aux)) = (entry[2].parse::<u64>(), entry[3].parse::<u64>()) else {
                    state.set(Register::Rax, u64::from(PDH_INVALID_DATA));
                    return Ok(());
                };
                let (Ok(prev_raw), Ok(prev_aux)) =
                    (entry[4].parse::<u64>(), entry[5].parse::<u64>())
                else {
                    // A rate counter needs two collects.
                    if value_out != 0 {
                        write_guest_u32(memory, value_out, PDH_INVALID_DATA).ok();
                    }
                    state.set(Register::Rax, u64::from(PDH_INVALID_DATA));
                    return Ok(());
                };
                let delta_raw = raw.saturating_sub(prev_raw);
                let delta_aux = aux.saturating_sub(prev_aux);
                if delta_aux == 0 {
                    0.0
                } else {
                    (delta_raw as f64 / delta_aux as f64 * 100.0).clamp(0.0, 100.0)
                }
            }
            _ => {
                let Ok(bits) = entry[2].parse::<u64>() else {
                    state.set(Register::Rax, u64::from(PDH_INVALID_DATA));
                    return Ok(());
                };
                f64::from_bits(bits)
            }
        };
        write_pdh_formatted_value(memory, value_out, formatted, value);
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `PdhEnumObjects` / `PdhEnumCounters` — the runtime's object/counter
    /// MULTI_SZ registry (PDH_MORE_DATA carries the required length).
    fn dispatch_pdh_enum(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        counters: bool,
    ) -> AppResult<()> {
        let _source = guest_call_arg(state, memory, 0)?;
        let _machine = guest_call_arg(state, memory, 1)?;
        let (object_name, buffer, size_out) = if counters {
            (
                guest_call_arg(state, memory, 2)?,
                guest_call_arg(state, memory, 3)?,
                guest_call_arg(state, memory, 4)?,
            )
        } else {
            (
                0,
                guest_call_arg(state, memory, 2)?,
                guest_call_arg(state, memory, 3)?,
            )
        };
        if size_out == 0 {
            state.set(Register::Rax, u64::from(PDH_INVALID_ARGUMENT));
            return Ok(());
        }
        let names: Vec<&'static str> = if counters {
            let object = read_utf16_string(memory, object_name).unwrap_or_default();
            match pdh_object_name(&object) {
                Some("Processor") => vec!["% Processor Time"],
                Some("System") => vec!["System Up Time"],
                Some("Memory") => vec![
                    "Available Bytes",
                    "Committed Bytes",
                    "% Committed Bytes In Use",
                ],
                Some(_) => Vec::new(),
                None => {
                    state.set(Register::Rax, u64::from(PDH_CSTATUS_NO_OBJECT));
                    return Ok(());
                }
            }
        } else {
            vec!["System", "Memory", "Processor"]
        };
        let required: usize = names
            .iter()
            .map(|name| name.encode_utf16().count() + 1)
            .sum::<usize>()
            + 1;
        let capacity = read_guest_u32(memory, size_out).unwrap_or(0) as usize;
        if buffer == 0 || capacity < required {
            write_guest_u32(memory, size_out, required as u32).ok();
            state.set(Register::Rax, u64::from(PDH_MORE_DATA));
            return Ok(());
        }
        let mut offset = buffer;
        for name in &names {
            for unit in name.encode_utf16().chain([0]) {
                write_guest_u16(memory, offset, unit).ok();
                offset += 2;
            }
        }
        write_guest_u16(memory, offset, 0).ok();
        write_guest_u32(memory, size_out, required as u32).ok();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
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

/// The counters the runtime models over the host's real performance data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PdhCounterKind {
    ProcessorTime,
    SystemUpTime,
    MemoryAvailable,
    MemoryCommitted,
    MemoryCommittedPercent,
}

/// Why a counter path was rejected (the two documented PDH status codes).
enum PdhPathError {
    NoObject,
    NoCounter,
}

/// A PDH counter entry is the two-element registration vector; a query
/// entry is the (possibly empty) list of paths.
fn is_pdh_counter_entry(entry: &[String]) -> bool {
    entry.len() >= 2 && entry[1].starts_with("q:")
}

/// The object component of a counter path (the component before the
/// optional instance and the counter name).
fn pdh_object_name(component: &str) -> Option<&'static str> {
    let name = component.split('(').next().unwrap_or(component).trim();
    if name.eq_ignore_ascii_case("Processor") {
        Some("Processor")
    } else if name.eq_ignore_ascii_case("System") {
        Some("System")
    } else if name.eq_ignore_ascii_case("Memory") {
        Some("Memory")
    } else {
        None
    }
}

/// Parse a counter path (`\Object(Instance)\Counter`, optionally prefixed
/// by a machine component) into the modeled counter.
fn parse_counter_path(path: &str) -> Result<PdhCounterKind, PdhPathError> {
    let components: Vec<&str> = path.split('\\').filter(|part| !part.is_empty()).collect();
    if components.is_empty() {
        return Err(PdhPathError::NoObject);
    }
    let Some(object_index) = components
        .iter()
        .position(|component| pdh_object_name(component).is_some())
    else {
        return Err(PdhPathError::NoObject);
    };
    if object_index + 1 >= components.len() {
        return Err(PdhPathError::NoCounter);
    }
    let object = pdh_object_name(components[object_index]).unwrap_or("");
    let counter = components[object_index + 1].trim().to_ascii_lowercase();
    let kind = match (object, counter.as_str()) {
        ("Processor", "% processor time") | ("Processor", "percent processor time") => {
            PdhCounterKind::ProcessorTime
        }
        ("System", "system up time") => PdhCounterKind::SystemUpTime,
        ("Memory", "available bytes") => PdhCounterKind::MemoryAvailable,
        ("Memory", "committed bytes") => PdhCounterKind::MemoryCommitted,
        ("Memory", "% committed bytes in use") => PdhCounterKind::MemoryCommittedPercent,
        _ => return Err(PdhPathError::NoCounter),
    };
    Ok(kind)
}

fn counter_perf_type(kind: PdhCounterKind) -> u32 {
    match kind {
        PdhCounterKind::ProcessorTime => PERF_100NSEC_TIMER,
        PdhCounterKind::SystemUpTime => PERF_ELAPSED_TIME,
        PdhCounterKind::MemoryCommittedPercent => PERF_RAW_FRACTION,
        PdhCounterKind::MemoryAvailable | PdhCounterKind::MemoryCommitted => PERF_COUNTER_RAWCOUNT,
    }
}

/// Write the PDH_FMT_COUNTERVALUE: the status at offset 0 and the value in
/// the union at offset 8 (the struct's natural double alignment).
fn write_pdh_formatted_value(memory: &mut MemoryImage, out: u64, format: u32, value: f64) {
    if out == 0 {
        return;
    }
    write_guest_u32(memory, out, 0).ok();
    match format {
        PDH_FMT_LARGE => write_guest_u64(memory, out + 8, value.max(0.0).trunc() as u64).ok(),
        PDH_FMT_LONG => write_guest_u32(memory, out + 8, value.max(0.0) as u32).ok(),
        _ => write_guest_f64(memory, out + 8, value).ok(),
    };
}

/// Take one host sample for the counter: `(instant, raw, aux)`, where the
/// rate counters store the busy ticks in `raw` and the total ticks in `aux`.
fn sample_counter(kind: PdhCounterKind) -> Option<(bool, u64, u64)> {
    match kind {
        PdhCounterKind::ProcessorTime => host_cpu_ticks().map(|(busy, total)| (false, busy, total)),
        PdhCounterKind::SystemUpTime => {
            host_uptime_seconds().map(|seconds| (true, seconds.to_bits(), 0))
        }
        PdhCounterKind::MemoryAvailable => {
            host_available_bytes().map(|bytes| (true, bytes.to_bits(), 0))
        }
        PdhCounterKind::MemoryCommitted => host_total_bytes().and_then(|total| {
            host_available_bytes()
                .map(|available| (true, (total - available).max(0.0).to_bits(), 0))
        }),
        PdhCounterKind::MemoryCommittedPercent => host_total_bytes().and_then(|total| {
            host_available_bytes().map(|available| {
                let used = (total - available).max(0.0);
                let percent = if total > 0.0 {
                    used / total * 100.0
                } else {
                    0.0
                };
                (true, percent.clamp(0.0, 100.0).to_bits(), 0)
            })
        }),
    }
}

/// One `sysctlbyname` read (the name must be null-terminated).
fn host_sysctl(name: &[u8], buffer: *mut libc::c_void, size: &mut usize) -> bool {
    // SAFETY: the name is a static, null-terminated byte string and the
    // buffer/size pair describes a live local value of matching size.
    unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            buffer,
            size,
            std::ptr::null_mut(),
            0,
        ) == 0
    }
}

fn host_sysctl_u64(name: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    let mut size = std::mem::size_of::<u64>();
    if host_sysctl(name, &mut value as *mut u64 as *mut libc::c_void, &mut size) {
        Some(value)
    } else {
        None
    }
}

fn host_sysctl_u32(name: &[u8]) -> Option<u32> {
    let mut value = 0_u32;
    let mut size = std::mem::size_of::<u32>();
    if host_sysctl(name, &mut value as *mut u32 as *mut libc::c_void, &mut size) {
        Some(value)
    } else {
        None
    }
}

/// The host's aggregate CPU ticks as `(busy, total)` from the mach host
/// CPU-load statistics (`HOST_CPU_LOAD_INFO`).
#[allow(deprecated)] // libc's mach_host_self; the mach2 crate is not a direct dependency
fn host_cpu_ticks() -> Option<(u64, u64)> {
    let mut info = libc::host_cpu_load_info {
        cpu_ticks: [0; libc::CPU_STATE_MAX as usize],
    };
    let mut count = libc::HOST_CPU_LOAD_INFO_COUNT;
    // SAFETY: `mach_host_self` returns the host port and `info` is the
    // matching `host_cpu_load_info` buffer for HOST_CPU_LOAD_INFO.
    let result = unsafe {
        libc::host_statistics(
            libc::mach_host_self(),
            libc::HOST_CPU_LOAD_INFO,
            &mut info as *mut libc::host_cpu_load_info as libc::host_info_t,
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS {
        return None;
    }
    let user = info.cpu_ticks[libc::CPU_STATE_USER as usize] as u64;
    let system = info.cpu_ticks[libc::CPU_STATE_SYSTEM as usize] as u64;
    let nice = info.cpu_ticks[libc::CPU_STATE_NICE as usize] as u64;
    let idle = info.cpu_ticks[libc::CPU_STATE_IDLE as usize] as u64;
    let total = user
        .saturating_add(system)
        .saturating_add(nice)
        .saturating_add(idle);
    let busy = user.saturating_add(system).saturating_add(nice);
    Some((busy, total))
}

/// Seconds since the host booted (`kern.boottime`).
fn host_uptime_seconds() -> Option<f64> {
    let mut boot = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = std::mem::size_of::<libc::timeval>();
    if !host_sysctl(
        b"kern.boottime\0",
        &mut boot as *mut libc::timeval as *mut libc::c_void,
        &mut size,
    ) {
        return None;
    }
    // SAFETY: `time` with a null pointer only reads the system clock.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    Some((now as f64 - boot.tv_sec as f64).max(0.0))
}

/// The host's free physical memory (free pages times the page size).
fn host_available_bytes() -> Option<f64> {
    let page_size = host_sysctl_u32(b"hw.pagesize\0")? as f64;
    let free_pages = host_sysctl_u32(b"vm.page_free_count\0")? as f64;
    Some(free_pages * page_size)
}

/// The host's total physical memory (`hw.memsize`).
fn host_total_bytes() -> Option<f64> {
    host_sysctl_u64(b"hw.memsize\0").map(|bytes| bytes as f64)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const QUERY_OUT: u64 = 0x41_000;
    const PATH: u64 = 0x41_100;
    const COUNTER_OUT: u64 = 0x41_200;
    const TYPE_OUT: u64 = 0x41_300;
    const VALUE_OUT: u64 = 0x41_400;
    const BUFFER: u64 = 0x41_500;
    const SIZE_OUT: u64 = 0x41_600;
    const OBJECT_NAME: u64 = 0x41_700;

    fn write_wide(fixture: &mut Fixture, address: u64, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fixture.memory.map_bytes(address, &bytes);
    }

    fn read_multi_sz(fixture: &Fixture, address: u64) -> Vec<String> {
        let mut names = Vec::new();
        let mut current = Vec::new();
        for index in 0..256_u64 {
            let unit = read_guest_u16(&fixture.memory, address + index * 2).unwrap_or(0);
            if unit == 0 {
                if current.is_empty() {
                    break;
                }
                names.push(String::from_utf16_lossy(&current));
                current.clear();
            } else {
                current.push(unit);
            }
        }
        names
    }

    fn open_query(fixture: &mut Fixture) -> u64 {
        fixture.memory.map_bytes(QUERY_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(fixture, HostThunk::PdhOpenQuery, &[0, 0, QUERY_OUT as u32]),
            0
        );
        read_guest_pointer(&fixture.memory, QUERY_OUT, GuestArch::X86).unwrap()
    }

    fn add_counter(fixture: &mut Fixture, query: u64, path: &str) -> u64 {
        write_wide(fixture, PATH, path);
        fixture.memory.map_bytes(COUNTER_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::PdhAddCounter,
                &[query as u32, PATH as u32, 0, COUNTER_OUT as u32]
            ),
            0,
            "add counter {path}"
        );
        read_guest_pointer(&fixture.memory, COUNTER_OUT, GuestArch::X86).unwrap()
    }

    fn formatted(fixture: &mut Fixture, counter: u64) -> (u64, f64, u32) {
        fixture.memory.map_bytes(TYPE_OUT, &[0_u8; 8]);
        fixture.memory.map_bytes(VALUE_OUT, &[0_u8; 16]);
        let status = dispatch_x86(
            fixture,
            HostThunk::PdhGetFormattedCounterValue,
            &[
                counter as u32,
                PDH_FMT_DOUBLE,
                TYPE_OUT as u32,
                VALUE_OUT as u32,
            ],
        );
        let value = read_guest_f64(&fixture.memory, VALUE_OUT + 8).unwrap_or(0.0);
        let counter_type = read_guest_u32(&fixture.memory, TYPE_OUT).unwrap_or(0);
        (status, value, counter_type)
    }

    #[test]
    fn counter_pipeline_reports_real_host_values() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("pdh-counters");
            let query = open_query(&mut fixture);
            assert_ne!(query, 0);
            let cpu = add_counter(&mut fixture, query, "\\Processor(_Total)\\% Processor Time");
            assert_eq!(cpu, PDH_COUNTER_HANDLE_BASE);
            let uptime = add_counter(&mut fixture, query, "\\System\\System Up Time");
            let available = add_counter(&mut fixture, query, "\\Memory\\Available Bytes");

            // Before any collect the counter has no data.
            let (status, _, _) = formatted(&mut fixture, cpu);
            assert_eq!(status, u64::from(PDH_CSTATUS_NO_DATA));

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhCollectQueryData,
                    &[query as u32]
                ),
                0
            );
            // A rate counter needs two samples.
            let (status, _, _) = formatted(&mut fixture, cpu);
            assert_eq!(status, u64::from(PDH_INVALID_DATA));
            std::thread::sleep(std::time::Duration::from_millis(30));
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhCollectQueryData,
                    &[query as u32]
                ),
                0
            );
            let (status, percent, counter_type) = formatted(&mut fixture, cpu);
            assert_eq!(status, 0, "PDH_CSTATUS_VALID_DATA");
            assert!((0.0..=100.0).contains(&percent), "cpu percent {percent}");
            assert_eq!(counter_type, PERF_100NSEC_TIMER);

            // The instantaneous counters report the real host values.
            let (status, seconds, counter_type) = formatted(&mut fixture, uptime);
            assert_eq!(status, 0);
            assert!(seconds > 0.0, "system up time {seconds}");
            assert_eq!(counter_type, PERF_ELAPSED_TIME);
            let (status, bytes, counter_type) = formatted(&mut fixture, available);
            assert_eq!(status, 0);
            assert!(bytes > 0.0, "available bytes {bytes}");
            assert_eq!(counter_type, PERF_COUNTER_RAWCOUNT);

            // Unknown paths answer the documented status codes.
            write_wide(&mut fixture, PATH, "\\NoSuchObject\\Counter");
            fixture.memory.map_bytes(COUNTER_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhAddCounter,
                    &[query as u32, PATH as u32, 0, COUNTER_OUT as u32]
                ),
                u64::from(PDH_CSTATUS_NO_OBJECT)
            );
            write_wide(&mut fixture, PATH, "\\Memory\\No Such Counter");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhAddCounter,
                    &[query as u32, PATH as u32, 0, COUNTER_OUT as u32]
                ),
                u64::from(PDH_CSTATUS_NO_COUNTER)
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::PdhCollectQueryData, &[0x1234]),
                u64::from(PDH_INVALID_HANDLE)
            );

            // Removal and close release the registrations.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhRemoveCounter,
                    &[available as u32]
                ),
                0
            );
            let (status, _, _) = formatted(&mut fixture, available);
            assert_eq!(status, u64::from(PDH_INVALID_HANDLE));
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::PdhCloseQuery, &[query as u32]),
                0
            );
            let (status, _, _) = formatted(&mut fixture, cpu);
            assert_eq!(status, u64::from(PDH_INVALID_HANDLE));
        })
    }

    #[test]
    fn enumeration_lists_the_real_object_and_counter_sets() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("pdh-enum");
            fixture.memory.map_bytes(SIZE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhEnumObjects,
                    &[0, 0, 0, SIZE_OUT as u32, 0, 0]
                ),
                u64::from(PDH_MORE_DATA)
            );
            let required = read_guest_u32(&fixture.memory, SIZE_OUT).unwrap();
            assert!(required > 0);
            fixture.memory.map_bytes(BUFFER, &vec![0_u8; 256]);
            write_guest_u32(&mut fixture.memory, SIZE_OUT, required).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhEnumObjects,
                    &[0, 0, BUFFER as u32, SIZE_OUT as u32, 0, 0]
                ),
                0
            );
            let objects = read_multi_sz(&fixture, BUFFER);
            assert!(objects.iter().any(|name| name == "Processor"));
            assert!(objects.iter().any(|name| name == "Memory"));
            assert!(objects.iter().any(|name| name == "System"));

            write_wide(&mut fixture, OBJECT_NAME, "Memory");
            write_guest_u32(&mut fixture.memory, SIZE_OUT, 0).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhEnumCounters,
                    &[0, 0, OBJECT_NAME as u32, 0, SIZE_OUT as u32, 0]
                ),
                u64::from(PDH_MORE_DATA)
            );
            fixture.memory.map_bytes(BUFFER, &vec![0_u8; 256]);
            write_guest_u32(&mut fixture.memory, SIZE_OUT, 256).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhEnumCounters,
                    &[0, 0, OBJECT_NAME as u32, BUFFER as u32, SIZE_OUT as u32, 0]
                ),
                0
            );
            let counters = read_multi_sz(&fixture, BUFFER);
            assert!(counters.iter().any(|name| name == "Available Bytes"));
            assert!(
                counters
                    .iter()
                    .any(|name| name == "% Committed Bytes In Use")
            );

            write_wide(&mut fixture, OBJECT_NAME, "NotAnObject");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::PdhEnumCounters,
                    &[0, 0, OBJECT_NAME as u32, BUFFER as u32, SIZE_OUT as u32, 0]
                ),
                u64::from(PDH_CSTATUS_NO_OBJECT)
            );
        })
    }
}
