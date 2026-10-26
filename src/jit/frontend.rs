#![allow(unused_imports)]

use super::*;
use crate::cpu::{
    ConditionCode, CpuState, GuestArch, GuestMemoryFault, GuestMemoryStore, IrInstruction,
    MemoryImage, Register,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

// ── Memory-access helpers called from JIT-compiled code ─────────────────────
//
// These `extern "C"` functions provide safe MemoryImage access to JIT-compiled
// blocks.  Instead of a fragile flat-memory mirror (which caused host-SP/state
// corruption), JIT code computes the effective guest address into a register
// and `BL`s one of these helpers, passing the CpuState pointer (x0 at block
// entry) and the address.
//
// Fault channel: a failed guest read must NEVER surface as a successful
// zero-valued read.  `jit_helper_load` records the faulting address in
// `CpuState::jit_pending_fault` and returns 0; the dispatcher
// (`CpuEngine::execute_with_jit` in cpu.rs) checks the marker after the
// compiled block returns and converts it into the same "unmapped guest
// memory" error the interpreter produces, which the caller then annotates
// via `annotate_guest_fault` exactly like an interpreter fault.
//
// ABI: helper(state: *mut CpuState, memory: *mut MemoryImage, address: u64,
// width: u64) -> u64
//
// Production worker slices execute the same compiled blocks but have no
// `MemoryImage` (the worker must not touch the runtime's page table).  They
// install a `GuestSliceMemory` view over the canonical store in a
// thread-local; when present, these helpers ignore the (null) `MemoryImage`
// pointer and access the shared canonical bytes through that view.  The
// view's aligned-word atomics provide cross-worker coherence, and unmapped
// accesses are reported through the normal `jit_pending_fault` channel.

thread_local! {
    pub(super) static WORKER_SLICE_MEMORY: std::cell::Cell<*const GuestSliceMemory> =
        const { std::cell::Cell::new(std::ptr::null()) };
    pub(super) static WORKER_SLICE_CODE_WRITTEN: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Install the worker-slice memory view for the duration of a slice.  The
/// guard clears the thread-local on drop so a stale pointer can never leak
/// into a later host-thread execution on the same native worker.
pub(crate) struct WorkerSliceGuard {
    pub(super) previous: *const GuestSliceMemory,
}

impl WorkerSliceGuard {
    pub(crate) fn install(memory: &GuestSliceMemory) -> Self {
        WORKER_SLICE_CODE_WRITTEN.with(|flag| flag.set(false));
        let previous = WORKER_SLICE_MEMORY.with(|slot| {
            let previous = slot.get();
            slot.set(memory as *const GuestSliceMemory);
            previous
        });
        Self { previous }
    }

    pub(crate) fn code_written(&self) -> bool {
        WORKER_SLICE_CODE_WRITTEN.with(|flag| flag.get())
    }
}

impl Drop for WorkerSliceGuard {
    fn drop(&mut self) {
        WORKER_SLICE_MEMORY.with(|slot| slot.set(self.previous));
    }
}

pub(super) fn worker_slice_memory() -> Option<&'static GuestSliceMemory> {
    WORKER_SLICE_MEMORY.with(|slot| {
        let pointer = slot.get();
        if pointer.is_null() {
            None
        } else {
            // SAFETY: `WorkerSliceGuard::install` publishes a valid view for
            // the whole duration of the worker's slice, and the guard clears
            // it before the view can be dropped (the job owns the Arc).
            Some(unsafe { &*pointer })
        }
    })
}

/// Read 1/2/4/8 bytes from guest memory.  Returns the zero-extended value.
/// On an unmapped address, records the fault in `state.jit_pending_fault` and
/// returns 0 — the dispatcher converts the marker into a guest access
/// violation error, so an unmapped read is never treated as a successful read
/// of zero.
///
/// # Safety
///
/// The raw pointers passed in must be valid for the duration of the call;
/// JIT-generated code guarantees this by only passing pointers to live
/// guest state, memory images, and IR owned by the executing block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn jit_helper_load(
    state: *mut CpuState,
    memory: *mut MemoryImage,
    address: u64,
    width: u64,
) -> u64 {
    if let Some(slice_memory) = worker_slice_memory() {
        return match slice_memory.load(address, width as usize) {
            Ok(value) => value,
            Err(fault) => {
                if !state.is_null() {
                    unsafe {
                        (*state).jit_pending_fault = Some(fault.address);
                        (*state).jit_pending_fault_write = false;
                    };
                }
                0
            }
        };
    }
    if memory.is_null() {
        return 0;
    }
    let mem = unsafe { &*memory };
    let result = match width {
        1 => mem.read_u8(address).map(u64::from),
        2 => mem.read_u16(address).map(u64::from),
        4 => mem.read_u32(address).map(u64::from),
        _ => mem.read_u64(address),
    };
    match result {
        Ok(value) => value,
        Err(_) => {
            // Guest access violation: remember the faulting address for the
            // dispatcher instead of silently fabricating a zero read.
            if !state.is_null() {
                unsafe {
                    (*state).jit_pending_fault = Some(address);
                    (*state).jit_pending_fault_write = false;
                };
            }
            0
        }
    }
}

/// Write 1/2/4/8 bytes to guest memory.
///
/// A failed guest write must NEVER surface as a successful write.  The write
/// goes through [`MemoryImage::guest_write_checked`], so unmapped memory is
/// never materialized: on fault the precise address is recorded in
/// `state.jit_pending_fault` (with `jit_pending_fault_write = true`) and the
/// JIT-compiled caller's immediate flag test exits the block via
/// `EXIT_GUEST_FAULT` before any later instruction executes.
///
/// # Safety
///
/// The raw pointers passed in must be valid for the duration of the call;
/// JIT-generated code guarantees this by only passing pointers to live
/// guest state, memory images, and IR owned by the executing block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn jit_helper_store(
    state: *mut CpuState,
    memory: *mut MemoryImage,
    address: u64,
    value: u64,
    width: u64,
) {
    let bytes: [u8; 8] = value.to_le_bytes();
    let write_len = match width {
        1 | 2 | 4 | 8 => width as usize,
        _ => 8,
    };
    if let Some(slice_memory) = worker_slice_memory() {
        match slice_memory.store(address, &bytes[..write_len]) {
            Ok(code_write) => {
                if code_write {
                    WORKER_SLICE_CODE_WRITTEN.with(|flag| flag.set(true));
                    JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
                }
            }
            Err(fault) => {
                if !state.is_null() {
                    unsafe {
                        (*state).jit_pending_fault = Some(fault.address);
                        (*state).jit_pending_fault_write = true;
                    };
                }
            }
        }
        return;
    }
    if memory.is_null() {
        return;
    }
    let mem = unsafe { &mut *memory };
    let result = mem.guest_write_checked(address, &bytes[..write_len]);
    match result {
        Ok(()) => {
            // Self-modifying code: a native store to a page that hosts a
            // compiled block must invalidate that block before it runs again.
            note_guest_code_write(address, write_len);
        }
        Err(fault) => {
            // Guest access violation: remember the faulting address (the
            // precise first-unmapped byte) and the access type for the
            // dispatcher.
            if !state.is_null() {
                unsafe {
                    (*state).jit_pending_fault = Some(fault.address);
                    (*state).jit_pending_fault_write = true;
                };
            }
        }
    }
}

/// Universal single-instruction executor: executes ONE IR instruction directly
/// on CpuState + MemoryImage.  Called from JIT-compiled code for instructions
/// that don't have dedicated native emission arms.  This is NOT an interpreter
/// — it executes exactly one instruction per call, invoked from JIT code.
#[unsafe(no_mangle)]
/// Execute a single IR instruction against guest state.
///
/// # Safety
///
/// `state`, `memory` and `insn_ptr` must be valid, non-null pointers to a
/// live `CpuState`, `MemoryImage`, and `IrInstruction` for the duration of
/// the call. JIT-generated code only passes pointers owned by the executing
/// block's runtime.
pub unsafe extern "C" fn jit_helper_execute_insn(
    state: *mut CpuState,
    memory: *mut MemoryImage,
    insn_ptr: *const IrInstruction,
) {
    if state.is_null() || memory.is_null() || insn_ptr.is_null() {
        return;
    }
    let s = unsafe { &mut *state };
    let m = unsafe { &mut *memory };
    let insn_slice = unsafe { std::slice::from_raw_parts(insn_ptr, 1) };
    let _ = crate::cpu::execute_ir_with_hashing(s, m, insn_slice, None, false, None);
}

/// seg: 0=FS, 1=GS.  Returns the segment base (e.g., TEB address for FS).
///
/// # Safety
///
/// The raw pointers passed in must be valid for the duration of the call;
/// JIT-generated code guarantees this by only passing pointers to live
/// guest state, memory images, and IR owned by the executing block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn jit_helper_segment_base(state: *mut CpuState, seg: u64) -> u64 {
    if state.is_null() {
        return 0;
    }
    let s = unsafe { &*state };
    match seg {
        0 => s.segment_bases.fs,
        1 => s.segment_bases.gs,
        _ => 0,
    }
}

pub(super) fn parity_byte(v: u8) -> bool {
    let count = (0..8).filter(|&i| v & (1 << i) != 0).count();
    count % 2 == 0
}

/// Compute x86 flags from an ALU result and store into CpuState.flags.
/// op: 0=add, 1=sub, 2=logic(and/or/xor/test), 3=cmp(=sub).
///
/// # Safety
///
/// The raw pointers passed in must be valid for the duration of the call;
/// JIT-generated code guarantees this by only passing pointers to live
/// guest state, memory images, and IR owned by the executing block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn jit_helper_set_flags(
    state: *mut CpuState,
    result: u64,
    lhs: u64,
    rhs: u64,
    op: u64,
    width: u64,
) {
    if state.is_null() {
        return;
    }
    let s = unsafe { &mut *state };
    // The helper writes `flags` directly; a parked lazy computation from a
    // prior interpreted instruction must not survive it.
    s.pending_flags = None;
    let bits = (width * 8) as u32;
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let r = result & mask;
    let a = lhs & mask;
    let b = rhs & mask;
    let msb = 1u64 << (bits - 1);
    s.flags.zf = r == 0;
    s.flags.sf = r & msb != 0;
    s.flags.pf = parity_byte(r as u8);
    match op {
        0 => {
            // add: CF = unsigned wrap of the width-masked sum.  The sum MUST
            // be truncated to the operation width BEFORE the comparison: for
            // an 8-bit add of 0xff+0x01 the unmasked sum is 0x100, and
            // 0x100 < 0xff is false — reporting CF=0 although the 8-bit
            // operation overflowed.  `sum & mask` makes CF exact at every
            // width; at 64 bits the mask is u64::MAX, so `& mask` is the
            // identity and `sum < a` is the true 64-bit carry.
            let sum = a.wrapping_add(b) & mask;
            s.flags.cf = sum < a;
            let (sa, sb, sr) = (a & msb != 0, b & msb != 0, r & msb != 0);
            s.flags.of = sa == sb && sr != sa;
            s.flags.af = (a ^ b ^ r) & 0x10 != 0;
        }
        // sub and cmp are the same ALU operation: CMP computes the flags of a
        // subtraction without storing the result.  On width-masked operands
        // `a < b` is the exact borrow at every width (no truncation needed).
        1 | 3 => {
            s.flags.cf = a < b;
            let (sa, sb, sr) = (a & msb != 0, b & msb != 0, r & msb != 0);
            s.flags.of = sa != sb && sr != sa;
            s.flags.af = (a ^ b ^ r) & 0x10 != 0;
        }
        _ => {
            s.flags.cf = false;
            s.flags.of = false;
            s.flags.af = false;
        }
    }
}

/// Materialise any parked lazy flags before compiled code reads flag bytes.
///
/// # Safety
/// `state` must be null or point at a live `CpuState` owned by the executing
/// block for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn jit_helper_materialize_flags(state: *mut CpuState) {
    if state.is_null() {
        return;
    }
    unsafe { (*state).materialize_pending_flags_for_jit() };
}

/// Trivial Win32 APIs that the JIT can service with a direct native helper
/// instead of the generic `dispatch_import` name lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum InlineApi {
    GetLastError = 0,
    SetLastError = 1,
    GetCurrentThreadId = 2,
    GetCurrentProcessId = 3,
    GetCurrentThread = 4,
    GetCurrentProcess = 5,
    QueryPerformanceCounter = 6,
    GetTickCount64 = 7,
    InterlockedIncrement = 8,
    InterlockedDecrement = 9,
    InterlockedExchange = 10,
    InterlockedExchangeAdd = 11,
    InterlockedCompareExchange = 12,
    InitializeSRWLock = 13,
    AcquireSRWLockExclusive = 14,
    ReleaseSRWLockExclusive = 15,
    AcquireSRWLockShared = 16,
    ReleaseSRWLockShared = 17,
    TryAcquireSRWLockExclusive = 18,
    TryAcquireSRWLockShared = 19,
    CurrentTeb = 20,
    CurrentPeb = 21,
}

impl InlineApi {
    pub const COUNT: usize = 22;

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::GetLastError => "GetLastError",
            Self::SetLastError => "SetLastError",
            Self::GetCurrentThreadId => "GetCurrentThreadId",
            Self::GetCurrentProcessId => "GetCurrentProcessId",
            Self::GetCurrentThread => "GetCurrentThread",
            Self::GetCurrentProcess => "GetCurrentProcess",
            Self::QueryPerformanceCounter => "QueryPerformanceCounter",
            Self::GetTickCount64 => "GetTickCount64",
            Self::InterlockedIncrement => "InterlockedIncrement",
            Self::InterlockedDecrement => "InterlockedDecrement",
            Self::InterlockedExchange => "InterlockedExchange",
            Self::InterlockedExchangeAdd => "InterlockedExchangeAdd",
            Self::InterlockedCompareExchange => "InterlockedCompareExchange",
            Self::InitializeSRWLock => "InitializeSRWLock",
            Self::AcquireSRWLockExclusive => "AcquireSRWLockExclusive",
            Self::ReleaseSRWLockExclusive => "ReleaseSRWLockExclusive",
            Self::AcquireSRWLockShared => "AcquireSRWLockShared",
            Self::ReleaseSRWLockShared => "ReleaseSRWLockShared",
            Self::TryAcquireSRWLockExclusive => "TryAcquireSRWLockExclusive",
            Self::TryAcquireSRWLockShared => "TryAcquireSRWLockShared",
            Self::CurrentTeb => "CurrentTeb",
            Self::CurrentPeb => "CurrentPeb",
        }
    }

    /// Return the inline identity of a canonical host thunk, if it is one of
    /// the trivial APIs.
    pub fn from_thunk(thunk: &crate::runtime::HostThunk) -> Option<Self> {
        use crate::runtime::HostThunk;
        Some(match thunk {
            HostThunk::GetLastError => Self::GetLastError,
            HostThunk::SetLastError => Self::SetLastError,
            HostThunk::GetCurrentThreadId => Self::GetCurrentThreadId,
            HostThunk::GetCurrentProcessId => Self::GetCurrentProcessId,
            HostThunk::GetCurrentThread => Self::GetCurrentThread,
            HostThunk::GetCurrentProcess => Self::GetCurrentProcess,
            HostThunk::QueryPerformanceCounter => Self::QueryPerformanceCounter,
            HostThunk::GetTickCount64 => Self::GetTickCount64,
            HostThunk::InterlockedIncrement => Self::InterlockedIncrement,
            HostThunk::InterlockedDecrement => Self::InterlockedDecrement,
            HostThunk::InterlockedExchange => Self::InterlockedExchange,
            HostThunk::InterlockedExchangeAdd => Self::InterlockedExchangeAdd,
            HostThunk::InterlockedCompareExchange => Self::InterlockedCompareExchange,
            HostThunk::InitializeSRWLock => Self::InitializeSRWLock,
            HostThunk::AcquireSRWLockExclusive => Self::AcquireSRWLockExclusive,
            HostThunk::ReleaseSRWLockExclusive => Self::ReleaseSRWLockExclusive,
            HostThunk::AcquireSRWLockShared => Self::AcquireSRWLockShared,
            HostThunk::ReleaseSRWLockShared => Self::ReleaseSRWLockShared,
            HostThunk::TryAcquireSRWLockExclusive => Self::TryAcquireSRWLockExclusive,
            HostThunk::TryAcquireSRWLockShared => Self::TryAcquireSRWLockShared,
            _ => return None,
        })
    }
}

pub(super) static INLINE_API_TARGETS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<u64, (InlineApi, u64)>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Register a resolved host-thunk address as an inline-able API target.
pub fn register_inline_api_target(address: u64, api: InlineApi) {
    register_inline_api_target_for(address, api, 0);
}

/// Register an inline-able target owned by a particular runtime.  The owner id
/// prevents a runtime teardown from unregistering a concurrently live
/// runtime's mapping at the same synthetic address.
pub fn register_inline_api_target_for(address: u64, api: InlineApi, owner: u64) {
    if let Ok(mut targets) = INLINE_API_TARGETS.write() {
        targets.insert(address, (api, owner));
    }
}

pub fn inline_api_for_target(address: u64) -> Option<InlineApi> {
    INLINE_API_TARGETS
        .read()
        .ok()
        .and_then(|targets| targets.get(&address).map(|(api, _)| *api))
}

/// Remove a stale inline-API target when a runtime is torn down.
pub fn unregister_inline_api_target(address: u64, owner: u64) {
    if let Ok(mut targets) = INLINE_API_TARGETS.write()
        && let Some((_, registered_owner)) = targets.get(&address)
        && *registered_owner == owner
    {
        targets.remove(&address);
    }
}

pub static INLINED_API_CALLS: [AtomicU64; InlineApi::COUNT] =
    [const { AtomicU64::new(0) }; InlineApi::COUNT];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineApiMetrics {
    pub total: u64,
    pub per_api: [u64; InlineApi::COUNT],
}

pub fn inline_api_metrics() -> InlineApiMetrics {
    let mut per_api = [0u64; InlineApi::COUNT];
    let mut total = 0;
    for (index, counter) in INLINED_API_CALLS.iter().enumerate() {
        per_api[index] = counter.load(Ordering::Relaxed);
        total += per_api[index];
    }
    InlineApiMetrics { total, per_api }
}

pub fn reset_inline_api_metrics() {
    for counter in &INLINED_API_CALLS {
        counter.store(0, Ordering::Relaxed);
    }
}

/// Native helper for the inlined trivial APIs.  Runs with the same
/// `(runtime, state, memory)` inputs as the fast-thunk bridge but performs the
/// whole API semantic inline (no `dispatch_import` match, no name lookup).
///
/// # Safety
/// `runtime`, `state` and `memory` must point at live objects owned by the
/// executing block for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn jit_helper_inline_api(
    runtime: *mut libc::c_void,
    state: *mut CpuState,
    memory: *mut MemoryImage,
    api: u64,
    return_address: u64,
) -> i64 {
    if runtime.is_null() || state.is_null() || memory.is_null() {
        return -1;
    }
    let runtime = unsafe { &mut *(runtime as *mut crate::runtime::PeHostRuntime) };
    let state = unsafe { &mut *state };
    let memory = unsafe { &mut *memory };
    let api = match api {
        0 => InlineApi::GetLastError,
        1 => InlineApi::SetLastError,
        2 => InlineApi::GetCurrentThreadId,
        3 => InlineApi::GetCurrentProcessId,
        4 => InlineApi::GetCurrentThread,
        5 => InlineApi::GetCurrentProcess,
        6 => InlineApi::QueryPerformanceCounter,
        7 => InlineApi::GetTickCount64,
        8 => InlineApi::InterlockedIncrement,
        9 => InlineApi::InterlockedDecrement,
        10 => InlineApi::InterlockedExchange,
        11 => InlineApi::InterlockedExchangeAdd,
        12 => InlineApi::InterlockedCompareExchange,
        13 => InlineApi::InitializeSRWLock,
        14 => InlineApi::AcquireSRWLockExclusive,
        15 => InlineApi::ReleaseSRWLockExclusive,
        16 => InlineApi::AcquireSRWLockShared,
        17 => InlineApi::ReleaseSRWLockShared,
        18 => InlineApi::TryAcquireSRWLockExclusive,
        19 => InlineApi::TryAcquireSRWLockShared,
        20 => InlineApi::CurrentTeb,
        21 => InlineApi::CurrentPeb,
        _ => return -1,
    };
    let _ = return_address;
    INLINED_API_CALLS[api.index()].fetch_add(1, Ordering::Relaxed);
    // `guest_call_arg` defines the emulator's call ABI (Win64 registers, x86
    // stack args at RSP).  The inline call therefore leaves RSP untouched,
    // exactly as a returned leaf call would.
    unsafe { inline_api_semantics(runtime, state, memory, api) }
}

pub(super) unsafe fn inline_api_semantics(
    runtime: &mut crate::runtime::PeHostRuntime,
    state: &mut CpuState,
    memory: &mut MemoryImage,
    api: InlineApi,
) -> i64 {
    let arg = |index: usize| crate::runtime::guest_call_arg(state, memory, index).unwrap_or(0);
    match api {
        InlineApi::GetLastError => {
            state.set(Register::Rax, u64::from(runtime.last_error));
        }
        InlineApi::SetLastError => {
            runtime.last_error = arg(0) as u32;
            state.set(Register::Rax, 0);
        }
        InlineApi::GetCurrentThreadId => {
            state.set(Register::Rax, u64::from(runtime.win32.current_thread_id()));
            runtime.last_error = 0;
        }
        InlineApi::GetCurrentProcessId => {
            state.set(Register::Rax, u64::from(runtime.win32.current_process_id()));
            runtime.last_error = 0;
        }
        InlineApi::GetCurrentThread => {
            let handle = runtime.win32.current_thread_handle();
            state.set(Register::Rax, u64::from(handle));
            runtime.last_error = 0;
        }
        InlineApi::GetCurrentProcess => {
            let handle = runtime.win32.current_process_handle();
            state.set(Register::Rax, u64::from(handle));
            runtime.last_error = 0;
        }
        InlineApi::QueryPerformanceCounter => {
            let counter_ptr = arg(0);
            if counter_ptr == 0 {
                state.set(Register::Rax, 0);
                runtime.last_error = 87; // ERROR_INVALID_PARAMETER
            } else {
                let counter = runtime.anticheat.clock.query_performance_counter() as u64;
                let _ = crate::runtime::write_u64(memory, counter_ptr, counter);
                state.set(Register::Rax, 1);
                runtime.last_error = 0;
            }
        }
        InlineApi::GetTickCount64 => {
            state.set(Register::Rax, runtime.anticheat.clock.tick_count64());
            runtime.last_error = 0;
        }
        InlineApi::InterlockedIncrement => {
            let destination = arg(0);
            match memory.interlocked_increment_u32(destination) {
                Ok(value) => {
                    state.set(Register::Rax, u64::from(value));
                    runtime.last_error = 0;
                }
                Err(_) => {
                    state.set(Register::Rax, 0);
                    runtime.last_error = 87;
                }
            }
        }
        InlineApi::InterlockedDecrement => {
            let destination = arg(0);
            match memory.interlocked_decrement_u32(destination) {
                Ok(value) => {
                    state.set(Register::Rax, u64::from(value));
                    runtime.last_error = 0;
                }
                Err(_) => {
                    state.set(Register::Rax, 0);
                    runtime.last_error = 87;
                }
            }
        }
        InlineApi::InterlockedExchange => {
            let destination = arg(0);
            let value = arg(1) as u32;
            match memory.interlocked_exchange_u32(destination, value) {
                Ok(previous) => {
                    state.set(Register::Rax, u64::from(previous));
                    runtime.last_error = 0;
                }
                Err(_) => {
                    state.set(Register::Rax, 0);
                    runtime.last_error = 87;
                }
            }
        }
        InlineApi::InterlockedExchangeAdd => {
            let destination = arg(0);
            let addend = arg(1) as u32;
            match memory.interlocked_exchange_add_u32(destination, addend) {
                Ok(previous) => {
                    state.set(Register::Rax, u64::from(previous));
                    runtime.last_error = 0;
                }
                Err(_) => {
                    state.set(Register::Rax, 0);
                    runtime.last_error = 87;
                }
            }
        }
        InlineApi::InterlockedCompareExchange => {
            let destination = arg(0);
            let exchange = arg(1) as u32;
            let comparand = arg(2) as u32;
            match memory.interlocked_compare_exchange_u32(destination, exchange, comparand) {
                Ok(previous) => {
                    state.set(Register::Rax, u64::from(previous));
                    runtime.last_error = 0;
                }
                Err(_) => {
                    state.set(Register::Rax, 0);
                    runtime.last_error = 87;
                }
            }
        }
        InlineApi::InitializeSRWLock => {
            let lock = arg(0);
            runtime.srw_locks.insert(
                lock,
                std::sync::Arc::new(crate::threads::GuestSRWLock::new()),
            );
            let _ = crate::runtime::write_guest_pointer(memory, lock, 0, state.arch);
            state.set(Register::Rax, 0);
            runtime.last_error = 0;
        }
        InlineApi::AcquireSRWLockExclusive => {
            let lock = arg(0);
            let srw = runtime
                .srw_locks
                .entry(lock)
                .or_insert_with(|| std::sync::Arc::new(crate::threads::GuestSRWLock::new()))
                .clone();
            srw.acquire_exclusive();
            state.set(Register::Rax, 0);
            runtime.last_error = 0;
        }
        InlineApi::ReleaseSRWLockExclusive => {
            let lock = arg(0);
            if let Some(srw) = runtime.srw_locks.get(&lock) {
                srw.release_exclusive();
            }
            state.set(Register::Rax, 0);
            runtime.last_error = 0;
        }
        InlineApi::AcquireSRWLockShared => {
            let lock = arg(0);
            let srw = runtime
                .srw_locks
                .entry(lock)
                .or_insert_with(|| std::sync::Arc::new(crate::threads::GuestSRWLock::new()))
                .clone();
            srw.acquire_shared();
            state.set(Register::Rax, 0);
            runtime.last_error = 0;
        }
        InlineApi::ReleaseSRWLockShared => {
            let lock = arg(0);
            if let Some(srw) = runtime.srw_locks.get(&lock) {
                srw.release_shared();
            }
            state.set(Register::Rax, 0);
            runtime.last_error = 0;
        }
        InlineApi::TryAcquireSRWLockExclusive => {
            let lock = arg(0);
            let acquired = if let Some(srw) = runtime.srw_locks.get(&lock) {
                srw.try_acquire_exclusive()
            } else {
                let srw = std::sync::Arc::new(crate::threads::GuestSRWLock::new());
                let acquired = srw.try_acquire_exclusive();
                runtime.srw_locks.insert(lock, srw);
                acquired
            };
            state.set(Register::Rax, u64::from(acquired));
            runtime.last_error = 0;
        }
        InlineApi::TryAcquireSRWLockShared => {
            let lock = arg(0);
            let acquired = if let Some(srw) = runtime.srw_locks.get(&lock) {
                srw.try_acquire_shared()
            } else {
                let srw = std::sync::Arc::new(crate::threads::GuestSRWLock::new());
                let acquired = srw.try_acquire_shared();
                runtime.srw_locks.insert(lock, srw);
                acquired
            };
            state.set(Register::Rax, u64::from(acquired));
            runtime.last_error = 0;
        }
        InlineApi::CurrentTeb => {
            state.set(Register::Rax, runtime.teb_base);
            runtime.last_error = 0;
        }
        InlineApi::CurrentPeb => {
            state.set(Register::Rax, runtime.peb_base);
            runtime.last_error = 0;
        }
    }
    0
}

/// Number of `IrInstruction` variants — the size of the per-opcode JIT
/// lowering telemetry arrays.
pub const IR_OPCODE_COUNT: usize = 364;

/// Per-opcode counters of IR instructions lowered to native ARM64 emission
/// by [`JitCompiler::compile_instruction`].  Indexed by
/// [`ir_opcode_index`]; incremented when a dedicated native emission arm
/// completes (EXIT_UNIMPL early-returns are counted as neither native nor
/// helper-fallback).
pub static JIT_NATIVE_LOWERED: [AtomicU64; IR_OPCODE_COUNT] =
    [const { AtomicU64::new(0) }; IR_OPCODE_COUNT];

/// Per-opcode counters of IR instructions that fell back to the universal
/// interpreter helper (`jit_helper_execute_insn`, which executes one
/// instruction via `execute_ir_with_hashing`).  Indexed by
/// [`ir_opcode_index`].
pub static JIT_HELPER_FALLBACK: [AtomicU64; IR_OPCODE_COUNT] =
    [const { AtomicU64::new(0) }; IR_OPCODE_COUNT];

/// Stable opcode index for an [`IrInstruction`], in declaration order.
/// The match is exhaustive over every variant so adding a variant without
/// updating this table is a compile error.
pub fn ir_opcode_index(insn: &IrInstruction) -> usize {
    match insn {
        IrInstruction::Cpuid => 0,
        IrInstruction::Xgetbv => 1,
        IrInstruction::MovImm { .. } => 2,
        IrInstruction::MovImm8 { .. } => 3,
        IrInstruction::MovReg { .. } => 4,
        IrInstruction::MovReg8 { .. } => 5,
        IrInstruction::MovdFromXmm { .. } => 6,
        IrInstruction::NotMemory { .. } => 7,
        IrInstruction::AddImm { .. } => 8,
        IrInstruction::AddReg8 { .. } => 9,
        IrInstruction::AddReg8Op { .. } => 10,
        IrInstruction::AddMemory8 { .. } => 11,
        IrInstruction::AddOperand { .. } => 12,
        IrInstruction::AddMemory { .. } => 13,
        IrInstruction::AddImmMemory { .. } => 14,
        IrInstruction::AdcOperand { .. } => 15,
        IrInstruction::AdcReg8Op { .. } => 16,
        IrInstruction::AdcMemory { .. } => 17,
        IrInstruction::AdcMemory8 { .. } => 18,
        IrInstruction::AdcImm { .. } => 19,
        IrInstruction::AdcImm8 { .. } => 20,
        IrInstruction::AddImm8 { .. } => 21,
        IrInstruction::AdcImmMemory { .. } => 22,
        IrInstruction::OrImm { .. } => 23,
        IrInstruction::OrImm8 { .. } => 24,
        IrInstruction::AndImm8 { .. } => 25,
        IrInstruction::OrImmMemory { .. } => 26,
        IrInstruction::SubImm { .. } => 27,
        IrInstruction::SubImm8 { .. } => 28,
        IrInstruction::SubImmMemory { .. } => 29,
        IrInstruction::AndImm { .. } => 30,
        IrInstruction::AndImmMemory { .. } => 31,
        IrInstruction::AndReg { .. } => 32,
        IrInstruction::AndMemory { .. } => 33,
        IrInstruction::RolImm { .. } => 34,
        IrInstruction::RorImm { .. } => 35,
        IrInstruction::RclImm { .. } => 36,
        IrInstruction::RcrImm { .. } => 37,
        IrInstruction::RolImmMemory { .. } => 38,
        IrInstruction::RorImmMemory { .. } => 39,
        IrInstruction::RclImmMemory { .. } => 40,
        IrInstruction::RcrImmMemory { .. } => 41,
        IrInstruction::ShlImm { .. } => 42,
        IrInstruction::ShrImm { .. } => 43,
        IrInstruction::SarImm { .. } => 44,
        IrInstruction::ShlImmMemory { .. } => 45,
        IrInstruction::ShrImmMemory { .. } => 46,
        IrInstruction::SarImmMemory { .. } => 47,
        IrInstruction::RolCl { .. } => 48,
        IrInstruction::RclCl { .. } => 49,
        IrInstruction::RcrCl { .. } => 50,
        IrInstruction::RolClMemory { .. } => 51,
        IrInstruction::RorClMemory { .. } => 52,
        IrInstruction::RclClMemory { .. } => 53,
        IrInstruction::RcrClMemory { .. } => 54,
        IrInstruction::ShlClMemory { .. } => 55,
        IrInstruction::ShrClMemory { .. } => 56,
        IrInstruction::SarClMemory { .. } => 57,
        IrInstruction::ShlCl { .. } => 58,
        IrInstruction::RorCl { .. } => 59,
        IrInstruction::ShrCl { .. } => 60,
        IrInstruction::SarCl { .. } => 61,
        IrInstruction::ShldImm { .. } => 62,
        IrInstruction::ShldCl { .. } => 63,
        IrInstruction::ShrdImm { .. } => 64,
        IrInstruction::ImulImm { .. } => 65,
        IrInstruction::ImulReg { .. } => 66,
        IrInstruction::MulAcc { .. } => 67,
        IrInstruction::ImulAcc { .. } => 68,
        IrInstruction::Div { .. } => 69,
        IrInstruction::Idiv { .. } => 70,
        IrInstruction::SubReg8 { .. } => 71,
        IrInstruction::SbbReg8 { .. } => 72,
        IrInstruction::NegReg { .. } => 73,
        IrInstruction::NegReg8 { .. } => 74,
        IrInstruction::NotReg { .. } => 75,
        IrInstruction::NotReg8 { .. } => 76,
        IrInstruction::Cdq { .. } => 77,
        IrInstruction::Movs { .. } => 78,
        IrInstruction::Stos { .. } => 79,
        IrInstruction::Lods { .. } => 80,
        IrInstruction::Cmps { .. } => 81,
        IrInstruction::Scas { .. } => 82,
        IrInstruction::Bound { .. } => 83,
        IrInstruction::Hlt => 84,
        IrInstruction::Cli => 85,
        IrInstruction::Sti => 86,
        IrInstruction::Std => 87,
        IrInstruction::Ud2 => 88,
        IrInstruction::Sahf => 89,
        IrInstruction::Lahf => 90,
        IrInstruction::SetCarryFlag { .. } => 91,
        IrInstruction::ComplementCarryFlag => 92,
        IrInstruction::PushAll => 93,
        IrInstruction::PopAll => 94,
        IrInstruction::LoadSegment { .. } => 95,
        IrInstruction::PortIn { .. } => 96,
        IrInstruction::PortOut { .. } => 97,
        IrInstruction::MovFromDr { .. } => 98,
        IrInstruction::MovToDr { .. } => 99,
        IrInstruction::Fxsave { .. } => 100,
        IrInstruction::Fxrstor { .. } => 101,
        IrInstruction::Xsave { .. } => 102,
        IrInstruction::Xsaveopt { .. } => 122,
        IrInstruction::Xrstor { .. } => 103,
        IrInstruction::SubOperand { .. } => 104,
        IrInstruction::SubMemory { .. } => 105,
        IrInstruction::SubMemory8 { .. } => 106,
        IrInstruction::SbbMemory { .. } => 107,
        IrInstruction::SbbMemory8 { .. } => 108,
        IrInstruction::SbbImm8 { .. } => 109,
        IrInstruction::SbbImm { .. } => 110,
        IrInstruction::SbbOperand { .. } => 111,
        IrInstruction::Compare { .. } => 112,
        IrInstruction::Test { .. } => 113,
        IrInstruction::ExchangeRegisters { .. } => 114,
        IrInstruction::ExchangeMemory { .. } => 115,
        IrInstruction::ExchangeRegisters8 { .. } => 116,
        IrInstruction::ExchangeMemory8 { .. } => 117,
        IrInstruction::SignExtendTo64 { .. } => 118,
        IrInstruction::SignExtend { .. } => 119,
        IrInstruction::ZeroExtendTo64 { .. } => 120,
        IrInstruction::XorImm { .. } => 121,
        IrInstruction::XorImm8 { .. } => 122,
        IrInstruction::XorImmMemory { .. } => 123,
        IrInstruction::XorReg { .. } => 124,
        IrInstruction::XorReg8 { .. } => 125,
        IrInstruction::XorReg8Op { .. } => 126,
        IrInstruction::XorMemory8 { .. } => 127,
        IrInstruction::XorMemory { .. } => 128,
        IrInstruction::OrReg { .. } => 129,
        IrInstruction::OrMemory { .. } => 130,
        IrInstruction::OrMemory8 { .. } => 131,
        IrInstruction::AndReg8 { .. } => 132,
        IrInstruction::AndReg8Op { .. } => 133,
        IrInstruction::AndMemory8 { .. } => 134,
        IrInstruction::BitTest { .. } => 135,
        IrInstruction::BitTestImm { .. } => 136,
        IrInstruction::OrReg8 { .. } => 137,
        IrInstruction::OrReg8Op { .. } => 138,
        IrInstruction::IncReg { .. } => 139,
        IrInstruction::DecReg { .. } => 140,
        IrInstruction::IncReg8 { .. } => 141,
        IrInstruction::DecReg8 { .. } => 142,
        IrInstruction::IncMemory { .. } => 143,
        IrInstruction::DecMemory { .. } => 144,
        IrInstruction::Cmov { .. } => 145,
        IrInstruction::LoadMemory8 { .. } => 146,
        IrInstruction::LoadMemory { .. } => 147,
        IrInstruction::StoreMemory8 { .. } => 148,
        IrInstruction::StoreMemory { .. } => 149,
        IrInstruction::StoreImmediate { .. } => 150,
        IrInstruction::Call { .. } => 151,
        IrInstruction::CallRegister { .. } => 152,
        IrInstruction::CallMemory { .. } => 153,
        IrInstruction::JumpRegister { .. } => 154,
        IrInstruction::JumpMemory { .. } => 155,
        IrInstruction::Setcc { .. } => 156,
        IrInstruction::SetccMemory { .. } => 157,
        IrInstruction::JumpIf { .. } => 158,
        IrInstruction::Jump { .. } => 159,
        IrInstruction::Nop => 160,
        IrInstruction::LoadEffectiveAddress { .. } => 161,
        IrInstruction::PushReg { .. } => 162,
        IrInstruction::PushMemory { .. } => 163,
        IrInstruction::PushImm { .. } => 164,
        IrInstruction::PushFlags { .. } => 165,
        IrInstruction::PopReg { .. } => 166,
        IrInstruction::PopMemory { .. } => 167,
        IrInstruction::PopFlags { .. } => 168,
        IrInstruction::Cld => 169,
        IrInstruction::Leave => 170,
        IrInstruction::Return { .. } => 171,
        IrInstruction::Popcnt { .. } => 172,
        IrInstruction::Lzcnt { .. } => 173,
        IrInstruction::Bsf { .. } => 174,
        IrInstruction::Bswap { .. } => 175,
        IrInstruction::Rdtsc => 176,
        IrInstruction::MovdToXmm { .. } => 177,
        IrInstruction::Pshufd { .. } => 178,
        IrInstruction::Pshuflw { .. } => 179,
        IrInstruction::Psrldq { .. } => 180,
        IrInstruction::Pslldq { .. } => 181,
        IrInstruction::Movlhps { .. } => 182,
        IrInstruction::StoreDwordFromXmm { .. } => 183,
        IrInstruction::MoveXmm { .. } => 184,
        IrInstruction::LoadXmm { .. } => 185,
        IrInstruction::StoreXmm { .. } => 186,
        IrInstruction::MoveVector { .. } => 187,
        IrInstruction::LoadVector { .. } => 188,
        IrInstruction::StoreVector { .. } => 189,
        IrInstruction::Pxor { .. } => 190,
        IrInstruction::VectorOr { .. } => 191,
        IrInstruction::VectorAnd { .. } => 192,
        IrInstruction::VectorAndNot { .. } => 193,
        IrInstruction::VectorXor { .. } => 194,
        IrInstruction::Paddd { .. } => 195,
        IrInstruction::Paddq { .. } => 196,
        IrInstruction::Psubd { .. } => 197,
        IrInstruction::Pmulld { .. } => 198,
        IrInstruction::VectorAddQ { .. } => 199,
        IrInstruction::VectorIntOp { .. } => 200,
        IrInstruction::VectorCompareEqBytes { .. } => 201,
        IrInstruction::VectorMoveMaskBytes { .. } => 202,
        IrInstruction::VzeroUpper => 203,
        IrInstruction::X87ClearExceptions => 204,
        IrInstruction::X87LoadInt32 { .. } => 205,
        IrInstruction::X87LoadInt64 { .. } => 206,
        IrInstruction::X87Load { .. } => 207,
        IrInstruction::X87LoadControlWord { .. } => 208,
        IrInstruction::X87NegateTop => 209,
        IrInstruction::X87AddMemory { .. } => 210,
        IrInstruction::X87MulMemory { .. } => 211,
        IrInstruction::X87DivMemory { .. } => 212,
        IrInstruction::X87Swap { .. } => 213,
        IrInstruction::X87StoreControlWord { .. } => 214,
        IrInstruction::X87Store { .. } => 215,
        IrInstruction::X87StorePopRegister { .. } => 216,
        IrInstruction::X87StorePop { .. } => 217,
        IrInstruction::X87Compare { .. } => 218,
        IrInstruction::X87Init => 219,
        IrInstruction::LoadMxcsr { .. } => 220,
        IrInstruction::StoreMxcsr { .. } => 221,
        IrInstruction::Cvtpd2ps { .. } => 222,
        IrInstruction::Cvtdq2pd { .. } => 223,
        IrInstruction::Addsd { .. } => 224,
        IrInstruction::Divss { .. } => 225,
        IrInstruction::SseArith { .. } => 226,
        IrInstruction::SseSqrt { .. } => 227,
        IrInstruction::SseRcp { .. } => 228,
        IrInstruction::SseRsqrt { .. } => 229,
        IrInstruction::CvtIntToFloat { .. } => 230,
        IrInstruction::CvtFloatToInt { .. } => 231,
        IrInstruction::Ucomi { .. } => 232,
        IrInstruction::Comiss { .. } => 233,
        IrInstruction::Pcmpistri { .. } => 234,
        IrInstruction::HaddPs { .. } => 235,
        IrInstruction::Pshufb { .. } => 236,
        IrInstruction::BlendD { .. } => 237,
        IrInstruction::Crc32 { .. } => 238,
        IrInstruction::Rdrand { .. } => 239,
        IrInstruction::Rdseed { .. } => 240,
        IrInstruction::Rdpmc { .. } => 241,
        IrInstruction::Clflush { .. } => 242,
        IrInstruction::Clflushopt { .. } => 243,
        IrInstruction::Clwb { .. } => 244,
        IrInstruction::Pcommit => 245,
        IrInstruction::Xbegin { .. } => 246,
        IrInstruction::Xend => 247,
        IrInstruction::Xabort { .. } => 248,
        IrInstruction::Xtest => 249,
        IrInstruction::Encls => 250,
        IrInstruction::Enclu => 251,
        IrInstruction::SaveSsP { .. } => 252,
        IrInstruction::Rstorssp { .. } => 253,
        IrInstruction::Incssp { .. } => 254,
        IrInstruction::Wrss { .. } => 255,
        IrInstruction::Wruss { .. } => 256,
        IrInstruction::BndmkReg { .. } => 257,
        IrInstruction::BndmkMem { .. } => 258,
        IrInstruction::BndclReg { .. } => 259,
        IrInstruction::BndclMem { .. } => 260,
        IrInstruction::BndcuReg { .. } => 261,
        IrInstruction::BndcuMem { .. } => 262,
        IrInstruction::BndcnReg { .. } => 263,
        IrInstruction::BndcnMem { .. } => 264,
        IrInstruction::BndmovReg { .. } => 265,
        IrInstruction::BndmovMemLoad { .. } => 266,
        IrInstruction::BndmovMemStore { .. } => 267,
        IrInstruction::Andn { .. } => 268,
        IrInstruction::Bextr { .. } => 269,
        IrInstruction::Blsi { .. } => 270,
        IrInstruction::Blsmsk { .. } => 271,
        IrInstruction::Blsr { .. } => 272,
        IrInstruction::Bzhi { .. } => 273,
        IrInstruction::Mulx { .. } => 274,
        IrInstruction::Pdep { .. } => 275,
        IrInstruction::Pext { .. } => 276,
        IrInstruction::Rorx { .. } => 277,
        IrInstruction::Sarx { .. } => 278,
        IrInstruction::Shrx { .. } => 279,
        IrInstruction::Shlx { .. } => 280,
        IrInstruction::LockCmpxchg { .. } => 281,
        IrInstruction::CmpxchgRegisters { .. } => 282,
        IrInstruction::LockCmpxchg8b { .. } => 283,
        IrInstruction::LockXadd { .. } => 284,
        IrInstruction::XaddRegisters { .. } => 285,
        IrInstruction::Mfence => 286,
        IrInstruction::X87LoadConst { .. } => 287,
        IrInstruction::X87AddPop { .. } => 288,
        IrInstruction::X87Mul { .. } => 289,
        IrInstruction::X87DivRegister { .. } => 290,
        IrInstruction::X87DivPop { .. } => 291,
        IrInstruction::X87Add => 292,
        IrInstruction::X87Div => 293,
        IrInstruction::AdcReg8 { .. } => 294,
        IrInstruction::Adcx { .. } => 295,
        IrInstruction::Adox { .. } => 296,
        IrInstruction::PopSeg { .. } => 297,
        IrInstruction::FmaVector { .. } => 298,
        IrInstruction::ShuffleF32 { .. } => 299,
        IrInstruction::ShuffleF64 { .. } => 300,
        IrInstruction::AlignD { .. } => 301,
        IrInstruction::AlignQ { .. } => 302,
        IrInstruction::InsertSubVector { .. } => 303,
        IrInstruction::ExtractSubVector { .. } => 304,
        IrInstruction::BroadcastSubVector { .. } => 305,
        IrInstruction::BroadcastMask { .. } => 306,
        IrInstruction::PermuteVarDq { .. } => 307,
        IrInstruction::PermuteVarPsPd { .. } => 308,
        IrInstruction::PermuteI2 { .. } => 309,
        IrInstruction::PermuteT2 { .. } => 310,
        IrInstruction::PermuteImm { .. } => 311,
        IrInstruction::PermuteImm2Src { .. } => 312,
        IrInstruction::AddPacked { .. } => 313,
        IrInstruction::SubPacked { .. } => 314,
        IrInstruction::MulPacked { .. } => 315,
        IrInstruction::DivPacked { .. } => 316,
        IrInstruction::MinPacked { .. } => 317,
        IrInstruction::MaxPacked { .. } => 318,
        IrInstruction::SqrtPacked { .. } => 319,
        IrInstruction::ConvertPacked { .. } => 320,
        IrInstruction::ConvertToInt { .. } => 321,
        IrInstruction::ConvertFromInt { .. } => 322,
        IrInstruction::ComparePacked { .. } => 323,
        IrInstruction::FixupSpecial { .. } => 324,
        IrInstruction::ExtractExponent { .. } => 325,
        IrInstruction::ExtractMantissa { .. } => 326,
        IrInstruction::ReducePrecision { .. } => 327,
        IrInstruction::RangePacked { .. } => 328,
        IrInstruction::ScaleByPower2 { .. } => 329,
        IrInstruction::FloatClass { .. } => 330,
        IrInstruction::Pternlog { .. } => 331,
        IrInstruction::ConflictDetect { .. } => 332,
        IrInstruction::CompressVector { .. } => 333,
        IrInstruction::ExpandVector { .. } => 334,
        IrInstruction::GatherVector { .. } => 335,
        IrInstruction::ScatterVector { .. } => 336,
        IrInstruction::Kand { .. } => 337,
        IrInstruction::Kor { .. } => 338,
        IrInstruction::Kxor { .. } => 339,
        IrInstruction::Knot { .. } => 340,
        IrInstruction::Kshiftl { .. } => 341,
        IrInstruction::Kshiftr { .. } => 342,
        IrInstruction::Kadd { .. } => 343,
        IrInstruction::Ktest { .. } => 344,
        IrInstruction::Kunpck { .. } => 345,
        IrInstruction::AesEnc { .. } => 346,
        IrInstruction::AesEncLast { .. } => 347,
        IrInstruction::AesDec { .. } => 348,
        IrInstruction::AesDecLast { .. } => 349,
        IrInstruction::AesImc { .. } => 350,
        IrInstruction::AesKeyGenAssist { .. } => 351,
        IrInstruction::Pclmulqdq { .. } => 352,
        IrInstruction::Sha1Rnds4 { .. } => 353,
        IrInstruction::Sha1NextE { .. } => 354,
        IrInstruction::Sha1Msg1 { .. } => 355,
        IrInstruction::Sha1Msg2 { .. } => 356,
        IrInstruction::Sha256Rnds2 { .. } => 357,
        IrInstruction::Sha256Msg1 { .. } => 358,
        IrInstruction::Sha256Msg2 { .. } => 359,
        IrInstruction::Breakpoint => 360,
        IrInstruction::SpillStore { .. } => 361,
        IrInstruction::SpillLoad { .. } => 362,
        IrInstruction::ExplicitFlags { .. } => 363,
    }
}

/// Snapshot the aggregate JIT lowering telemetry: `(native_lowered, helper_fallback)`.
pub fn jit_lowering_telemetry() -> (u64, u64) {
    let native = JIT_NATIVE_LOWERED
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum();
    let fallback = JIT_HELPER_FALLBACK
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum();
    (native, fallback)
}
pub(super) const JIT_PAGE_SIZE: usize = 64 * 1024;

// ── Executable-memory capability probe ──────────────────────────────────────
//
// Native execution is enabled only after this probe has actually EXECUTED an
// ARM64 stub (`movz w0, #42 ; ret`) through a candidate mechanism.  The probe
// runs in throw-away child processes so a blocked mechanism is observed as a
// SIGBUS/SIGSEGV exit status instead of killing the emulator.
//
// Empirically measured on macOS 26 / Apple Silicon (M5 Pro):
//
//   mechanism                                      result
//   ---------------------------------------------  --------------------------
//   mmap RW anon -> mprotect RX                    executes, returns 42
//   MAP_JIT RWX + pthread_jit_write_protect_np     executes, returns 42
//   MAP_JIT RW + pthread_jit_write_protect_np      SIGBUS (no PROT_EXEC)
//   MAP_JIT RWX, no write-protect toggles          SIGBUS (write-protect on)
//
// The SIGBUS on the RW-only MAP_JIT mapping was the long-standing blocker:
// PROT_EXEC is required in the mmap request — pthread_jit_write_protect_np
// only toggles write protection, it cannot add execute permission.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitExecMechanism {
    /// MAP_JIT with PROT_READ|PROT_WRITE|PROT_EXEC, toggled with
    /// `pthread_jit_write_protect_np(0/1)` around code writes.
    MapJitWx,
    /// Plain RW anonymous mapping flipped to RX with `mprotect`.
    MprotectRx,
    /// Direct RWX mapping (non-Apple-Silicon fallback).
    RwxMmap,
    /// No mechanism could execute the stub; compiled blocks stay disabled and
    /// the interpreter/AOT path handles every guest block.
    Unavailable,
}

impl std::fmt::Display for JitExecMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MapJitWx => write!(f, "MAP_JIT RWX + pthread_jit_write_protect_np"),
            Self::MprotectRx => write!(f, "mmap RW + mprotect RX"),
            Self::RwxMmap => write!(f, "mmap RWX"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Outcome of one executable-memory probe, including the exact OS refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitExecProbeOutcome {
    /// The ARM64 stub executed and returned this value (42 on success).
    Executed(u64),
    /// `mmap` failed with this errno.
    MmapFailed(i32),
    /// `mprotect(PROT_EXEC)` failed with this errno.
    MprotectFailed(i32),
    /// The process faulted while writing the stub (serialised with this signal).
    WriteFaulted(i32),
    /// The process faulted while executing the stub (serialised with this signal).
    ExecuteFaulted(i32),
    /// `fork` failed with this errno.
    ForkFailed(i32),
    /// The probe child exited without a result (exit status).
    ChildFailed(i32),
    /// The probe does not run on this build target.
    NotProbed,
}

impl std::fmt::Display for JitExecProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Executed(value) => write!(f, "executed, returned {value}"),
            Self::MmapFailed(errno) => write!(
                f,
                "mmap failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            ),
            Self::MprotectFailed(errno) => write!(
                f,
                "mprotect(PROT_EXEC) failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            ),
            Self::WriteFaulted(signal) => write!(f, "write faulted: signal {signal}"),
            Self::ExecuteFaulted(signal) => write!(f, "execution faulted: signal {signal}"),
            Self::ForkFailed(errno) => write!(
                f,
                "fork failed: errno {errno} ({})",
                std::io::Error::from_raw_os_error(errno)
            ),
            Self::ChildFailed(code) => write!(f, "probe child exited without a result: {code}"),
            Self::NotProbed => write!(f, "not probed on this target"),
        }
    }
}

/// Raw probe matrix for every mechanism the JIT knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitExecProbeMatrix {
    pub mprotect_rx: JitExecProbeOutcome,
    pub map_jit_wx_write_protect: JitExecProbeOutcome,
    /// The historical allocator mode (MAP_JIT without PROT_EXEC).  Kept as an
    /// explicit negative probe so the regression cannot return silently.
    pub map_jit_rw_write_protect: JitExecProbeOutcome,
    /// MAP_JIT RWX written without the write-protect toggle.
    pub map_jit_wx_no_write_protect: JitExecProbeOutcome,
    /// Mechanism the JIT actually uses (first successful probe).
    pub selected: JitExecMechanism,
}

impl JitExecProbeMatrix {
    // Used by the Apple Silicon probe module; on other targets the selected
    // mechanism is the conservative RwxMmap fallback.
    #[allow(dead_code)]
    pub(super) fn select(
        mprotect_rx: JitExecProbeOutcome,
        map_jit_wx_write_protect: JitExecProbeOutcome,
        map_jit_rw_write_protect: JitExecProbeOutcome,
        map_jit_wx_no_write_protect: JitExecProbeOutcome,
    ) -> Self {
        let selected = if matches!(map_jit_wx_write_protect, JitExecProbeOutcome::Executed(42)) {
            JitExecMechanism::MapJitWx
        } else if matches!(mprotect_rx, JitExecProbeOutcome::Executed(42)) {
            JitExecMechanism::MprotectRx
        } else {
            JitExecMechanism::Unavailable
        };
        Self {
            mprotect_rx,
            map_jit_wx_write_protect,
            map_jit_rw_write_protect,
            map_jit_wx_no_write_protect,
            selected,
        }
    }
}

/// Run the full probe once per process.  Cached because each probe forks four
/// short-lived children and the answer cannot change while the process lives.
pub(super) static JIT_EXECUTION_CAPABILITY: LazyLock<JitExecProbeMatrix> =
    LazyLock::new(probe_jit_execution);

/// Cached executable-memory capability of the current process.
pub fn jit_execution_capability() -> JitExecProbeMatrix {
    *JIT_EXECUTION_CAPABILITY
}

/// True when at least one mechanism executed the ARM64 probe stub.
pub fn jit_execution_available() -> bool {
    jit_execution_capability().selected != JitExecMechanism::Unavailable
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) mod exec_probe {
    use super::{JitExecProbeMatrix, JitExecProbeOutcome};
    use std::ffi::c_void;
    use std::ptr;

    const PROBE_PAGE_SIZE: usize = 4096;
    /// `movz w0, #42 ; ret`
    const PROBE_STUB: [u32; 2] = [0x5280_0540, 0xd65f_03c0];

    const STAGE_MMAP_FAILED: u32 = 1;
    const STAGE_MPROTECT_FAILED: u32 = 2;
    const STAGE_WRITING: u32 = 3;
    const STAGE_EXECUTING: u32 = 4;
    const STAGE_EXECUTED: u32 = 5;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProbeMessage {
        stage: u32,
        value: i32,
    }

    #[derive(Clone, Copy)]
    enum ProbeMode {
        MprotectRx,
        MapJitWxProtect,
        MapJitRwProtect,
        MapJitWxNoProtect,
        /// Fault injection: request an mmap the kernel must refuse.
        #[cfg(test)]
        InvalidMmap,
        /// Fault injection: mprotect an unaligned address so the kernel refuses.
        #[cfg(test)]
        InvalidMprotect,
        /// Fault injection: exit without reporting any probe stage.
        #[cfg_attr(not(test), allow(dead_code))]
        ExitWithoutResult,
    }

    /// Test-only seams used to drive the probe's OS-failure protocol without
    /// requiring a genuinely broken host.
    #[cfg(test)]
    static PROBE_FORCE_PIPE_FAIL: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    #[cfg(test)]
    static PROBE_FORCE_FORK_FAIL: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    #[cfg(test)]
    static PROBE_FORCE_MPROTECT_FAIL: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    // Replace the real waitpid status with a synthetic signaled status so the
    // parent-side signal mapping is deterministic.
    #[cfg(test)]
    thread_local! {
        static PROBE_FORCE_SIGNAL_STATUS: std::cell::Cell<Option<i32>> =
            const { std::cell::Cell::new(None) };
    }
    // Force the MAP_JIT RW mapping request to be refused so the child reaches
    // the normal exit path instead of dying on the SIGBUS it exists to prove.
    #[cfg(test)]
    thread_local! {
        static PROBE_FORCE_MAP_JIT_RW_MMAP_FAIL: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    /// Terminate the probe process.  Test builds use the normal `exit` path so
    /// LLVM's coverage counters recorded by the forked child are flushed;
    /// production keeps the async-signal-safe `_exit`.
    unsafe fn probe_exit(code: libc::c_int) -> ! {
        #[cfg(test)]
        {
            unsafe { libc::exit(code) }
        }
        #[cfg(not(test))]
        {
            unsafe { libc::_exit(code) }
        }
    }

    fn last_errno() -> i32 {
        // SAFETY: `__error()` returns the calling thread's errno slot on macOS.
        unsafe { *libc::__error() }
    }

    fn send(fd: libc::c_int, stage: u32, value: i32) {
        let message = ProbeMessage { stage, value };
        // SAFETY: `fd` is the probe pipe's write end; the message is 8 bytes
        // (well below PIPE_BUF), so the write is atomic.  Errors are ignored:
        // the parent detects a missing result as a child failure.
        unsafe {
            let _ = libc::write(
                fd,
                &message as *const ProbeMessage as *const c_void,
                std::mem::size_of::<ProbeMessage>(),
            );
        }
    }

    /// Child half: map, write, protect, EXECUTE the stub, then `_exit`.
    /// Deliberately allocation-free (only syscalls + a raw fn pointer).
    unsafe fn probe_child(mode: ProbeMode, fd: libc::c_int) -> ! {
        // A parent may have installed a SIGBUS page-sync handler; restore the
        // default so a blocked mechanism terminates instead of looping.
        unsafe {
            libc::signal(libc::SIGBUS, libc::SIG_DFL);
            libc::signal(libc::SIGSEGV, libc::SIG_DFL);
        }

        let (prot, flags) = match mode {
            ProbeMode::MprotectRx | ProbeMode::ExitWithoutResult => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            ),
            ProbeMode::MapJitWxProtect | ProbeMode::MapJitWxNoProtect => (
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
            ),
            ProbeMode::MapJitRwProtect => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
            ),
            #[cfg(test)]
            ProbeMode::InvalidMmap => (
                libc::PROT_READ | libc::PROT_WRITE,
                // Unknown flag bit: the kernel must reject the request.
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | 0x4000_0000,
            ),
            #[cfg(test)]
            ProbeMode::InvalidMprotect => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            ),
        };

        // Test-only seam: the real MAP_JIT RW child dies on SIGBUS before the
        // profile runtime can flush, so inject an invalid flag to exercise the
        // same arm through the mmap-failure report path instead.
        #[cfg(test)]
        let flags = if matches!(mode, ProbeMode::MapJitRwProtect)
            && PROBE_FORCE_MAP_JIT_RW_MMAP_FAIL.with(|flag| flag.take())
        {
            flags | 0x4000_0000
        } else {
            flags
        };

        match mode {
            // Exit non-zero without a result message: the parent must report
            // the child's exit status via the ChildFailed outcome.
            ProbeMode::ExitWithoutResult => unsafe { probe_exit(7) },
            _ => {}
        }

        // SAFETY: plain anonymous mmap; fd=-1 with MAP_ANONYMOUS is valid.
        let page = unsafe { libc::mmap(ptr::null_mut(), PROBE_PAGE_SIZE, prot, flags, -1, 0) };
        if page == libc::MAP_FAILED {
            send(fd, STAGE_MMAP_FAILED, last_errno());
            unsafe { probe_exit(0) };
        }

        if matches!(
            mode,
            ProbeMode::MapJitWxProtect | ProbeMode::MapJitRwProtect
        ) {
            unsafe { libc::pthread_jit_write_protect_np(0) };
        }

        send(fd, STAGE_WRITING, 0);
        // SAFETY: `page` is a live PROBE_PAGE_SIZE mapping and the stub fits.
        unsafe {
            ptr::copy_nonoverlapping(
                PROBE_STUB.as_ptr() as *const u8,
                page as *mut u8,
                std::mem::size_of_val(&PROBE_STUB),
            );
        }

        #[cfg(test)]
        if matches!(mode, ProbeMode::InvalidMprotect) {
            // Unaligned address: mprotect must fail with EINVAL, exercising the
            // same reporting arm as a genuine permission failure.
            let unaligned = (page as *mut u8).wrapping_add(1) as *mut c_void;
            let rc = unsafe {
                libc::mprotect(
                    unaligned,
                    PROBE_PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            };
            if rc != 0 {
                send(fd, STAGE_MPROTECT_FAILED, last_errno());
                unsafe { probe_exit(0) };
            }
        }

        if matches!(mode, ProbeMode::MprotectRx) {
            #[cfg(test)]
            let forced = PROBE_FORCE_MPROTECT_FAIL.swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let forced = false;
            let rc = if forced {
                unsafe { libc::open(c"/casa1/probe/mprotect-failure".as_ptr(), libc::O_RDONLY) };
                -1
            } else {
                unsafe { libc::mprotect(page, PROBE_PAGE_SIZE, libc::PROT_READ | libc::PROT_EXEC) }
            };
            if rc != 0 {
                send(fd, STAGE_MPROTECT_FAILED, last_errno());
                unsafe { probe_exit(0) };
            }
        } else if matches!(
            mode,
            ProbeMode::MapJitWxProtect | ProbeMode::MapJitRwProtect
        ) {
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }

        send(fd, STAGE_EXECUTING, 0);
        // SAFETY: the mapping contains the two-instruction ARM64 stub and (for
        // the successful modes) is executable.  A blocked mapping faults here;
        // the parent observes the signal on the child.
        let stub: unsafe extern "C" fn() -> u64 = unsafe { std::mem::transmute(page) };
        let value = unsafe { stub() };
        send(fd, STAGE_EXECUTED, value as i32);
        unsafe { probe_exit(0) }
    }

    fn run(mode: ProbeMode) -> JitExecProbeOutcome {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` points to two valid c_int slots.
        #[cfg(test)]
        let forced_pipe_failure =
            PROBE_FORCE_PIPE_FAIL.swap(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let forced_pipe_failure = false;
        let pipe_rc = if forced_pipe_failure {
            // Fault injection: a real failing syscall sets errno before the
            // same error-reporting path as a failed pipe(2).
            unsafe { libc::open(c"/casa1/probe/pipe-failure".as_ptr(), libc::O_RDONLY) };
            -1
        } else {
            unsafe { libc::pipe(fds.as_mut_ptr()) }
        };
        if pipe_rc != 0 {
            return JitExecProbeOutcome::ForkFailed(last_errno());
        }
        // SAFETY: fork has no Rust-level preconditions.  The child only uses
        // async-signal-safe syscalls and a raw code pointer, then `_exit`s.
        #[cfg(test)]
        let forced_fork_failure =
            PROBE_FORCE_FORK_FAIL.swap(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let forced_fork_failure = false;
        let pid = if forced_fork_failure {
            unsafe { libc::open(c"/casa1/probe/fork-failure".as_ptr(), libc::O_RDONLY) };
            -1
        } else {
            unsafe { libc::fork() }
        };
        if pid < 0 {
            let errno = last_errno();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return JitExecProbeOutcome::ForkFailed(errno);
        }
        if pid == 0 {
            unsafe {
                libc::close(fds[0]);
                probe_child(mode, fds[1]);
            }
        }

        unsafe { libc::close(fds[1]) };
        let mut last: Option<ProbeMessage> = None;
        loop {
            let mut message = ProbeMessage { stage: 0, value: 0 };
            // SAFETY: `message` is a valid 8-byte destination and `fds[0]` is
            // the open read end of the probe pipe.
            let read = unsafe {
                libc::read(
                    fds[0],
                    &mut message as *mut ProbeMessage as *mut c_void,
                    std::mem::size_of::<ProbeMessage>(),
                )
            };
            if read == std::mem::size_of::<ProbeMessage>() as isize {
                last = Some(message);
                continue;
            }
            break;
        }
        unsafe { libc::close(fds[0]) };

        let mut status: libc::c_int = 0;
        // SAFETY: `pid` is the child returned by fork above.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        #[cfg(test)]
        if let Some(forced) = PROBE_FORCE_SIGNAL_STATUS.with(|forced| forced.replace(None)) {
            status = forced;
        }
        let signal = if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        };

        match last {
            Some(message) if message.stage == STAGE_EXECUTED => {
                JitExecProbeOutcome::Executed(message.value as u64)
            }
            Some(message) if message.stage == STAGE_MMAP_FAILED => {
                JitExecProbeOutcome::MmapFailed(message.value)
            }
            Some(message) if message.stage == STAGE_MPROTECT_FAILED => {
                JitExecProbeOutcome::MprotectFailed(message.value)
            }
            Some(message) if message.stage == STAGE_WRITING => {
                JitExecProbeOutcome::WriteFaulted(signal)
            }
            Some(_) => JitExecProbeOutcome::ExecuteFaulted(signal),
            None => {
                if libc::WIFEXITED(status) {
                    JitExecProbeOutcome::ChildFailed(libc::WEXITSTATUS(status))
                } else {
                    JitExecProbeOutcome::ExecuteFaulted(signal)
                }
            }
        }
    }

    pub(super) fn matrix() -> JitExecProbeMatrix {
        let mprotect_rx = run(ProbeMode::MprotectRx);
        let map_jit_wx_write_protect = run(ProbeMode::MapJitWxProtect);
        let map_jit_rw_write_protect = run(ProbeMode::MapJitRwProtect);
        let map_jit_wx_no_write_protect = run(ProbeMode::MapJitWxNoProtect);
        JitExecProbeMatrix::select(
            mprotect_rx,
            map_jit_wx_write_protect,
            map_jit_rw_write_protect,
            map_jit_wx_no_write_protect,
        )
    }

    #[cfg(test)]
    mod probe_fault_tests {
        use super::*;

        #[test]
        fn jit_probe_invalid_mmap_reports_exact_errno() {
            assert_eq!(
                run(ProbeMode::InvalidMmap),
                JitExecProbeOutcome::MmapFailed(libc::EINVAL),
                "an invalid mmap request must serialise the kernel errno"
            );
        }

        #[test]
        fn jit_probe_invalid_mprotect_reports_exact_errno() {
            assert_eq!(
                run(ProbeMode::InvalidMprotect),
                JitExecProbeOutcome::MprotectFailed(libc::EINVAL),
                "an unaligned mprotect must serialise EINVAL"
            );
        }

        #[test]
        fn jit_probe_map_jit_rw_without_exec_rejects_execution() {
            assert_eq!(
                run(ProbeMode::MapJitRwProtect),
                JitExecProbeOutcome::ExecuteFaulted(libc::SIGBUS),
                "a MAP_JIT RW mapping without PROT_EXEC must fault when executed"
            );
        }

        #[test]
        fn jit_probe_map_jit_rw_mapping_rejection_reports_einval() {
            PROBE_FORCE_MAP_JIT_RW_MMAP_FAIL.with(|flag| flag.set(true));
            let outcome = run(ProbeMode::MapJitRwProtect);
            PROBE_FORCE_MAP_JIT_RW_MMAP_FAIL.with(|flag| flag.set(false));
            assert_eq!(
                outcome,
                JitExecProbeOutcome::MmapFailed(libc::EINVAL),
                "an invalid MAP_JIT RW mapping request must report EINVAL instead of executing the stub"
            );
        }

        #[test]
        fn jit_probe_forced_mprotect_failure_reports_real_errno() {
            PROBE_FORCE_MPROTECT_FAIL.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                run(ProbeMode::MprotectRx),
                JitExecProbeOutcome::MprotectFailed(libc::ENOENT),
                "a refused mprotect must keep the failing syscall's errno"
            );
        }

        #[test]
        fn jit_probe_silent_child_exit_rejects_success() {
            assert_eq!(
                run(ProbeMode::ExitWithoutResult),
                JitExecProbeOutcome::ChildFailed(7),
                "a silent probe child must surface its exit status"
            );
        }

        #[test]
        fn jit_probe_signal_death_rejects_execution_success() {
            PROBE_FORCE_SIGNAL_STATUS.with(|status| status.set(Some(libc::SIGSEGV)));
            assert_eq!(
                run(ProbeMode::ExitWithoutResult),
                JitExecProbeOutcome::ExecuteFaulted(libc::SIGSEGV),
                "a signal death must surface the signal, not a success"
            );
        }

        #[test]
        fn jit_probe_pipe_failure_reports_real_errno() {
            PROBE_FORCE_PIPE_FAIL.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                run(ProbeMode::MprotectRx),
                JitExecProbeOutcome::ForkFailed(libc::ENOENT),
                "pipe failure must keep the failing syscall's errno"
            );
        }

        #[test]
        fn jit_probe_fork_failure_reports_real_errno() {
            PROBE_FORCE_FORK_FAIL.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                run(ProbeMode::MprotectRx),
                JitExecProbeOutcome::ForkFailed(libc::ENOENT),
                "fork failure must keep the failing syscall's errno"
            );
        }

        #[test]
        fn jit_probe_send_pins_exact_message_and_rejects_truncation() {
            let mut fds = [0 as libc::c_int; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            send(fds[1], STAGE_MPROTECT_FAILED, libc::EINVAL);
            unsafe { libc::close(fds[1]) };

            let mut message = ProbeMessage { stage: 0, value: 0 };
            let read = unsafe {
                libc::read(
                    fds[0],
                    &mut message as *mut ProbeMessage as *mut c_void,
                    std::mem::size_of::<ProbeMessage>(),
                )
            };
            unsafe { libc::close(fds[0]) };
            assert_eq!(
                read,
                std::mem::size_of::<ProbeMessage>() as isize,
                "a stage message must be exactly 8 bytes"
            );
            assert_eq!(message.stage, STAGE_MPROTECT_FAILED);
            assert_eq!(message.value, libc::EINVAL);
        }

        #[test]
        fn jit_probe_last_errno_reports_failed_syscall() {
            let rc = unsafe { libc::open(c"/casa1/probe/missing".as_ptr(), libc::O_RDONLY) };
            assert_eq!(rc, -1, "the fixture path must not exist");
            assert_eq!(last_errno(), libc::ENOENT);
        }
    }
}

/// Probe every executable-memory mechanism in isolated child processes.
pub fn probe_jit_execution() -> JitExecProbeMatrix {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        exec_probe::matrix()
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        JitExecProbeMatrix {
            mprotect_rx: JitExecProbeOutcome::NotProbed,
            map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
            selected: JitExecMechanism::RwxMmap,
        }
    }
}

/// Compiles a sequence of IR instructions into ARM64 machine code.
pub struct JitCompiler {
    pub(super) emitter: Emitter,
    pub(super) memory_manager: JitMemoryManager,
    /// IR instructions that need the universal helper.  Each is boxed so its
    /// address is stable (Vec reallocation won't move it).
    #[allow(clippy::vec_box)]
    pub(super) helper_insns: Vec<Box<IrInstruction>>,
    /// Byte offset of the safepoint `cbnz` instruction emitted by
    /// `emit_safepoint_check`; patched with the stub offset when the block
    /// body and stub have been emitted.  `None` when the block has no
    /// safepoint check (or it has already been patched).
    pub(super) safepoint_cbnz_patch: Option<usize>,
    /// Byte offsets of the guest-fault `cbnz` instructions emitted after
    /// each load/store helper call; all patched to the single fault-exit
    /// stub by `finish_fault_stub` once the block body has been emitted.
    pub(super) fault_cbnz_patches: Vec<usize>,
    /// Link slots belonging to the block currently being compiled.
    pub(super) link_slots: Option<LinkSlots>,
    /// Relocations for every absolute address embedded in the emitted code.
    /// Used to serialize translated blocks into the persistent AOT cache and
    /// to re-bind them after loading into a new address space.
    pub(super) relocations: Vec<AotRelocation>,
    /// True when the block currently being compiled used the universal
    /// single-instruction interpreter helper, which needs a live
    /// `MemoryImage` pointer and therefore may not run on a production
    /// worker.
    pub(super) used_interpreter_helper: bool,
    /// True while compiling a production-worker (slice) block.  In this mode
    /// indirect `call`/`jmp` and `ret` lower to self-contained native exits
    /// that publish the resolved target in the per-thread cell instead of
    /// calling the `MemoryImage`-dependent interpreter helper, so the worker
    /// can keep them out of the owner's dispatch loop.  Cooperative
    /// (`block_cache`) compilation leaves this false and is byte-identical to
    /// before.
    pub(super) worker_program: bool,
}

impl Default for JitCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl JitCompiler {
    pub fn new() -> Self {
        Self {
            emitter: Emitter::new(),
            memory_manager: JitMemoryManager::new(),
            helper_insns: Vec::new(),
            safepoint_cbnz_patch: None,
            fault_cbnz_patches: Vec::new(),
            link_slots: None,
            relocations: Vec::new(),
            used_interpreter_helper: false,
            worker_program: false,
        }
    }

    /// Compile a block for a production worker slice.
    ///
    /// Identical to [`Self::compile_block`] except that indirect `call`/`jmp`
    /// lower to native exits that publish the resolved target into the
    /// per-thread exit cell (no `MemoryImage` helper), so the worker can
    /// resolve them with an inline cache and continue natively.  The flag is
    /// scoped to this call, so cooperative compilation is unaffected.
    pub(crate) fn compile_worker_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
    ) -> AppResult<JitCompiledBlock> {
        self.worker_program = true;
        let result = self.compile_block(ir, guest_address, arch, None);
        self.worker_program = false;
        result
    }

    /// Compile a block of IR instructions into executable ARM64 code.
    ///
    /// `fast_thunk_addrs` — an optional set of guest thunk addresses that have
    /// Returns true if every IR instruction in the block can be JIT-compiled.
    /// Used to reject blocks that would only partially compile (causing
    /// double-execution of side-effecting instructions).
    pub(super) fn can_compile_block(ir: &[IrInstruction]) -> bool {
        ir.iter().all(Self::can_compile_instruction)
    }

    /// Returns true if a single IR instruction has a JIT emission arm.
    ///
    /// This is the JIT-SAFE gate: instructions whose emission exits the block
    /// MID-WAY (before the block's remaining instructions have run) must NOT
    /// be compiled, because the dispatcher would have to re-run the rest of
    /// the block and double-execute the already-run prefix.  Excluded:
    /// virtualization-dependent instructions (Cpuid/Xgetbv), RIP-relative
    /// memory access (the effective address is unavailable at IR level), and
    /// FXSAVE/FXRSTOR (x87/SSE state serialization stays in the
    /// interpreter).  Everything else either has a dedicated native arm or
    /// runs through the universal single-instruction helper, which is safe.
    pub(super) fn can_compile_instruction(insn: &IrInstruction) -> bool {
        match insn {
            IrInstruction::Cpuid | IrInstruction::Xgetbv => false,
            IrInstruction::Fxsave { .. } | IrInstruction::Fxrstor { .. } => false,
            IrInstruction::LoadMemory { address, .. }
            | IrInstruction::LoadMemory8 { address, .. }
            | IrInstruction::StoreMemory { address, .. }
            | IrInstruction::StoreMemory8 { address, .. }
            | IrInstruction::StoreImmediate { address, .. } => !address.rip_relative,
            _ => true,
        }
    }

    /// Copy the emitted ARM64 bytes into a fresh code block, flush the
    /// instruction cache, and mark the block executable through the mechanism
    /// selected by the capability probe.
    pub(super) fn install_code(&self, code_ptr: *mut u8, code_size: usize) -> AppResult<()> {
        // W^X thread safety: serialize every writer of the executable code
        // zone.  `pthread_jit_write_protect_np` is per-thread, so the lock is
        // only needed to keep two installers from writing concurrently; an
        // executing thread keeps its execute view and never takes this lock.
        let _install = JIT_CODE_INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: code_ptr was allocated by the memory manager for at least
        // code_size bytes; emitter.code holds exactly code_size bytes.
        unsafe {
            if !self.memory_manager.make_writable(code_ptr, code_size) {
                return Err(AppError::new(
                    ReasonCode::RcJitCodeAllocFailed,
                    "JIT: executable code page is not writable",
                ));
            }
            ptr::copy_nonoverlapping(self.emitter.code.as_ptr(), code_ptr, code_size);
            if !self.memory_manager.finalize_code(code_ptr, code_size) {
                return Err(AppError::new(
                    ReasonCode::RcJitCodeAllocFailed,
                    "JIT: failed to make compiled block executable",
                ));
            }
        }
        Ok(())
    }

    /// Install a translated block deserialized from the persistent AOT cache.
    ///
    /// The loader validates the record's logical code hash (with relocation
    /// sites zeroed), re-binds every embedded absolute address to this
    /// process's helpers/link slots, then finalizes the page executable.  On
    /// any mismatch it fails before touching executable memory, so the caller
    /// falls back to compiling from IR.
    pub(super) fn install_aot_record(&mut self, record: &AotRecord) -> AppResult<JitCompiledBlock> {
        if record.format != AOT_FORMAT_VERSION
            || record.translator != AOT_TRANSLATOR_VERSION
            || record.machine != AotRecord::machine_tag()
            || record.cpu_profile != aot_target_cpu_profile()
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT record key mismatch",
            ));
        }
        if record.code_size as usize != record.code.len() || record.code.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT record code size mismatch",
            ));
        }
        let mut code = record.code.clone();
        for relocation in &record.relocations {
            let offset = relocation.offset as usize;
            if offset % 4 != 0 || offset.checked_add(16).is_none_or(|end| end > code.len()) {
                return Err(AppError::new(
                    ReasonCode::RcJitCompilationError,
                    "AOT relocation out of range",
                ));
            }
            code[offset..offset + 16].fill(0);
        }
        if fnv1a(&code) != record.logical_code_hash {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT logical code hash mismatch",
            ));
        }

        let link_slots = LinkSlots::new();
        for relocation in &record.relocations {
            let value = match relocation.kind {
                AotRelocKind::SafepointFlag => &JIT_SAFEPOINT_REQUESTED as *const AtomicBool as u64,
                AotRelocKind::CodeEpoch => &JIT_CODE_EPOCH as *const AtomicU64 as u64,
                AotRelocKind::JumpLink => Arc::as_ptr(&link_slots.jump) as u64,
                AotRelocKind::TakenLink => Arc::as_ptr(&link_slots.taken) as u64,
                AotRelocKind::FallthroughLink => Arc::as_ptr(&link_slots.fallthrough) as u64,
                AotRelocKind::CallLink => Arc::as_ptr(&link_slots.call) as u64,
                AotRelocKind::ReturnEntryLink => Arc::as_ptr(&link_slots.return_entry) as u64,
                AotRelocKind::Helper(helper) => helper.address(),
            };
            let offset = relocation.offset as usize;
            // Preserve the destination register chosen by the emitter: most
            // absolute loads target x26, but link exits load their slot into
            // x9 (a caller-saved scratch that survives frame restoration).
            let original = u32::from_le_bytes(
                record.code[offset..offset + 4]
                    .try_into()
                    .expect("validated relocation width"),
            );
            let destination = original & 0x1f;
            let mut emitter = Emitter::new();
            emitter.mov_imm64_fixed(destination, value);
            code[offset..offset + 16].copy_from_slice(&emitter.code);
        }

        let code_size = code.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "AOT: failed to allocate executable memory",
            ));
        }
        let _install = JIT_CODE_INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: code_ptr was allocated for at least code_size bytes and the
        // code vector has exactly code_size bytes.
        unsafe {
            if !self.memory_manager.make_writable(code_ptr, code_size) {
                return Err(AppError::new(
                    ReasonCode::RcJitCodeAllocFailed,
                    "AOT: executable code page is not writable",
                ));
            }
            ptr::copy_nonoverlapping(code.as_ptr(), code_ptr, code_size);
            if !self.memory_manager.finalize_code(code_ptr, code_size) {
                return Err(AppError::new(
                    ReasonCode::RcJitCodeAllocFailed,
                    "AOT: failed to make loaded block executable",
                ));
            }
        }

        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address: record.guest_address,
            instruction_count: record.instruction_count as usize,
            source_hash: record.code_hash,
            last_exit_info: record.exit_info,
            compile_tier: CompilationTier::Tier0,
            ends_in_control_flow: record.exit_info.is_some(),
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe: record.worker_safe,
        })
    }

    pub fn compile_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<JitCompiledBlock> {
        self.emitter = Emitter::new();
        self.used_interpreter_helper = false;
        self.relocations.clear();
        let link_slots = LinkSlots::new();
        self.link_slots = Some(link_slots.clone());

        // Prologue: save callee-saved registers and set up frame
        self.emit_prologue(arch);
        self.emit_current_block_tag(guest_address);

        // Load guest GPRs from CpuState into ARM64 registers
        // x0 = &CpuState, x1 = memory base, x2 = &MemoryImage, x3 = &ChainState
        self.emit_load_guest_registers(arch);

        // Per-block accounting, SMC epoch and link-budget checks.  These run
        // only when `x3` is a real `ChainState` (always true for the executor
        // in this module); the branch targets are emitted inline.
        self.emit_chain_guard(ir.len() as u64, arch);

        // Host safepoint check: every compiled block polls the safepoint
        // flag at entry, so a chained loop re-entering its first block is
        // still interruptible by the scheduler.  The stub is emitted and
        // the branch patched after the body below.
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(ir.len() as u64);

        // Compile each IR instruction, optionally using fast-thunk info
        // to emit direct calls for known host thunks.
        let last = ir.len().saturating_sub(1);
        for (index, insn) in ir.iter().enumerate() {
            self.compile_instruction(insn, arch, fast_thunk_addrs, index == last)?;
        }

        // Epilogue: store guest GPRs back to CpuState and return
        self.emit_store_guest_registers(arch);
        self.emit_epilogue();

        // Safepoint stub: the prologue cbnz branches here when the
        // safepoint flag is set; store guest state and return EXIT_SAFEPOINT.
        self.finish_safepoint_stub(arch);

        // Guest-fault stub: every load/store helper call in the body ends
        // with a cbnz that branches here when `jit_pending_fault` is set;
        // store guest state and return EXIT_GUEST_FAULT so the dispatcher
        // raises the access violation at the faulting instruction.
        self.finish_fault_stub(arch);

        // Allocate executable memory and copy the code
        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT: failed to allocate executable memory",
            ));
        }

        // SAFETY: code_ptr was allocated by memory_manager.allocate_code_space
        // and is valid for code_size bytes. emitter.code is a valid Vec.
        // The regions are non-overlapping. finalize_code flushes the
        // instruction cache and sets executable permissions.
        self.install_code(code_ptr, code_size)?;

        // Compute a simple hash of the source IR for integrity verification.
        // Uses FNV-1a style hashing of the instruction discriminants and guest_address.
        let source_hash = compute_ir_hash(ir, guest_address);
        let last_exit_info = block_exit_info(ir);
        let worker_safe = block_is_worker_safe(ir, self.used_interpreter_helper);
        self.link_slots = None;

        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address,
            instruction_count: ir.len(),
            source_hash,
            last_exit_info,
            compile_tier: CompilationTier::Tier0,
            ends_in_control_flow: block_ends_in_control_flow(ir),
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe,
        })
    }

    pub fn emit_safepoint_check(&mut self, _arch: GuestArch) {
        // The check is emitted into every compiled block so that translated
        // execution polls the host safepoint flag even when block chains
        // never return to the dispatcher.  The check is live in every block
        // whenever the capability probe selected an executable-memory
        // mechanism.
        //
        // Layout:
        //   mov_imm64 x26, &JIT_SAFEPOINT_REQUESTED   // flag address
        //   ldrb  w26, [x26]                          // 1-byte atomic load
        //   cbnz  w26, safepoint_stub                 // patched at block end
        //   <block body>
        //   <normal exit: store guest regs; movz x0, EXIT_NORMAL; epilogue>
        //   safepoint_stub:                           // (forward branch target)
        //     store guest regs
        //     movz x0, EXIT_SAFEPOINT
        //     epilogue
        //
        // x26 is a scratch temp (guest GPRs live in x4-x20) and is
        // initialized by the block body before any use, so the check
        // clobbering it at block entry is safe.
        let flag_addr = &JIT_SAFEPOINT_REQUESTED as *const AtomicBool as u64;
        self.emit_reloc_imm64(regmap::X26, flag_addr, AotRelocKind::SafepointFlag);
        self.emitter.ldr8(regmap::X26, regmap::X26, 0);
        self.safepoint_cbnz_patch = Some(self.emitter.len());
        self.emitter.cbnz(regmap::X26, 0);
    }

    /// Emit an absolute 64-bit immediate and record it for AOT relocation.
    pub(super) fn emit_reloc_imm64(&mut self, rd: u32, value: u64, kind: AotRelocKind) {
        let offset = self.emitter.len() as u32;
        self.emitter.mov_imm64_fixed(rd, value);
        self.relocations.push(AotRelocation { offset, kind });
    }

    /// Write a guest RIP value into `CpuState` so a whole-function exit is
    /// decoded with the correct target even though a function has multiple
    /// static exits (the single `last_exit_info` slot cannot represent them).
    pub(super) fn emit_set_state_rip(&mut self, target: u64) {
        self.emitter.mov_imm64(regmap::X26, target);
        self.emitter.str64(
            regmap::X26,
            regmap::X0,
            std::mem::offset_of!(CpuState, rip) as u32,
        );
    }

    /// Seed the Tier-2 spill slots that back guest R13/R14/R15 from the
    /// incoming register values.  Without this, a function that reads those
    /// registers would observe stale host scratch state.
    pub(super) fn emit_spill_slots_init(&mut self, _arch: GuestArch) {
        for (slot, guest) in [(0u32, 13usize), (1, 14), (2, 15)] {
            let arm = regmap::guest_to_arm(guest);
            self.emitter
                .str64(arm, regmap::X0, Self::SPILL_BASE + slot * 8);
        }
    }

    /// Emit the per-block guard: counters, SMC epoch comparison and the link
    /// budget.  All exits are taken BEFORE the block body runs, so a dispatch
    /// boundary never re-executes guest instructions.
    pub(super) fn emit_chain_guard(&mut self, _instruction_count: u64, arch: GuestArch) {
        // if code_epoch != chain.smc_epoch -> exit EXIT_CODE_EPOCH
        let epoch_addr = &JIT_CODE_EPOCH as *const AtomicU64 as u64;
        self.emit_reloc_imm64(regmap::X26, epoch_addr, AotRelocKind::CodeEpoch);
        self.emitter.ldr64(regmap::X21, regmap::X26, 0);
        self.emitter
            .ldr64(regmap::X22, regmap::X23, chain_offsets::SMC_EPOCH);
        self.emitter.subs_reg(31, regmap::X21, regmap::X22);
        let epoch_ok = self.emitter.len();
        self.emitter.bcond(0, 0); // EQ placeholder
        self.emit_guard_exit(EXIT_CODE_EPOCH, arch);
        self.patch_bcond(epoch_ok, self.emitter.len());

        // if link_budget == 0 -> exit EXIT_LINK_BUDGET, else decrement.
        self.emitter
            .ldr64(regmap::X21, regmap::X23, chain_offsets::LINK_BUDGET);
        let budget_pos = self.emitter.len();
        self.emitter.cbnz(regmap::X21, 0);
        self.emit_guard_exit(EXIT_LINK_BUDGET, arch);
        self.patch_cbnz(budget_pos, self.emitter.len());
        self.emitter.sub_imm(regmap::X21, regmap::X21, 1);
        self.emitter
            .str64(regmap::X21, regmap::X23, chain_offsets::LINK_BUDGET);
    }

    /// Account for a block that passed every entry guard and is about to run.
    pub(super) fn emit_block_accounting(&mut self, instruction_count: u64) {
        self.emitter
            .ldr64(regmap::X21, regmap::X23, chain_offsets::BLOCKS);
        self.emitter.add_imm(regmap::X21, regmap::X21, 1);
        self.emitter
            .str64(regmap::X21, regmap::X23, chain_offsets::BLOCKS);
        self.emitter
            .ldr64(regmap::X22, regmap::X23, chain_offsets::INSTRUCTIONS);
        self.emitter.mov_imm64(regmap::X21, instruction_count);
        self.emitter.add_reg(regmap::X22, regmap::X22, regmap::X21);
        self.emitter
            .str64(regmap::X22, regmap::X23, chain_offsets::INSTRUCTIONS);
    }

    /// Inline guard exit: store guest registers and return `exit_code`.
    pub(super) fn emit_guard_exit(&mut self, exit_code: u64, arch: GuestArch) {
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, exit_code as u16, 0);
        self.emit_epilogue();
    }

    pub(super) fn patch_bcond(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let condition = self.emitter.code[position] & 0x0f;
        let insn = 0x5400_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(condition);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    pub(super) fn patch_cbnz(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let register = self.emitter.code[position] & 0x1f;
        let insn = 0xb500_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(register);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    /// Materialise parked interpreter flags before a native flag read.
    pub(super) fn emit_materialize_flags(&mut self) {
        self.emitter.mov_reg(regmap::X24, regmap::X0);
        self.emitter.mov_reg(regmap::X28, regmap::X2);
        self.emit_bl_to(AotHelper::MaterializeFlags);
        self.emitter.mov_reg(regmap::X0, regmap::X24);
        self.emitter.mov_reg(regmap::X2, regmap::X28);
    }

    /// Load the six x86 flag bytes into scratch registers x10-x14.
    ///
    /// **Callers must have stored guest registers first**: x10-x15 hold guest
    /// RSI/RDI/R8-R11 and are clobbered here.  This is only emitted for a
    /// block-terminating `Jcc`, where either exit reloads the state or the
    /// linked target's prologue does.
    pub(super) fn emit_x86_flag_loads(&mut self) {
        let base = std::mem::offset_of!(CpuState, flags) as u32;
        let cf = base + std::mem::offset_of!(crate::cpu::Flags, cf) as u32;
        let pf = base + std::mem::offset_of!(crate::cpu::Flags, pf) as u32;
        let zf = base + std::mem::offset_of!(crate::cpu::Flags, zf) as u32;
        let sf = base + std::mem::offset_of!(crate::cpu::Flags, sf) as u32;
        let of = base + std::mem::offset_of!(crate::cpu::Flags, of) as u32;
        self.emitter.ldr8(10, regmap::X0, cf);
        self.emitter.ldr8(11, regmap::X0, pf);
        self.emitter.ldr8(12, regmap::X0, zf);
        self.emitter.ldr8(13, regmap::X0, sf);
        self.emitter.ldr8(14, regmap::X0, of);
    }

    /// Emit a real ARM64 conditional branch implementing an x86 `Jcc`
    /// condition.  Returns the byte position of the `b.cond` so the caller can
    /// patch it to the taken path once that path has been emitted.
    pub(super) fn emit_x86_condition_branch(&mut self, condition: ConditionCode) -> usize {
        const EQ: u32 = 0;
        const NE: u32 = 1;
        match condition {
            ConditionCode::Equal => {
                self.emitter.subs_imm(31, 12, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotEqual => {
                self.emitter.subs_imm(31, 12, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Overflow => {
                self.emitter.subs_imm(31, 14, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotOverflow => {
                self.emitter.subs_imm(31, 14, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Below => {
                self.emitter.subs_imm(31, 10, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotBelow => {
                self.emitter.subs_imm(31, 10, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Above => {
                self.emitter.movz(15, 1, 0);
                self.emitter.eor_reg(9, 10, 15);
                self.emitter.eor_reg(15, 12, 15);
                self.emitter.and_reg(9, 9, 15);
                self.emitter.subs_imm(31, 9, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotAbove => {
                self.emitter.orr_reg(9, 10, 12);
                self.emitter.subs_imm(31, 9, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Sign => {
                self.emitter.subs_imm(31, 13, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotSign => {
                self.emitter.subs_imm(31, 13, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Less => {
                self.emitter.subs_reg(31, 13, 14);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::GreaterEqual => {
                self.emitter.subs_reg(31, 13, 14);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::LessEqual => {
                self.emitter.eor_reg(9, 13, 14);
                self.emitter.orr_reg(9, 12, 9);
                self.emitter.subs_imm(31, 9, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Greater => {
                self.emitter.eor_reg(9, 13, 14);
                self.emitter.movz(15, 1, 0);
                self.emitter.eor_reg(9, 9, 15);
                self.emitter.eor_reg(15, 12, 15);
                self.emitter.and_reg(9, 9, 15);
                self.emitter.subs_imm(31, 9, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Parity => {
                self.emitter.subs_imm(31, 11, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotParity => {
                self.emitter.subs_imm(31, 11, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
        }
    }

    /// Emit a native link exit for a worker block: branch to the successor's
    /// entry when the slot is published, otherwise return `exit_code` with the
    /// already-stored guest state.
    pub(super) fn emit_link_exit(
        &mut self,
        slot: &Arc<AtomicU64>,
        kind: AotRelocKind,
        exit_code: u64,
    ) {
        // Restore the flat-mirror base and hand the chain pointer to the
        // target prologue.  x1/x3 are caller-saved and may have been clobbered
        // by helper calls earlier in the block.
        self.emitter
            .ldr64(regmap::X1, regmap::X23, chain_offsets::FLAT_BASE);
        self.emitter.mov_reg(regmap::X3, regmap::X23);
        self.emit_reloc_imm64(regmap::X9, Arc::as_ptr(slot) as u64, kind);
        self.emitter.ldar64(regmap::X9, regmap::X9);
        self.emit_frame_restore();
        self.emitter.cbz(regmap::X9, 8);
        self.emitter.br(regmap::X9);
        self.emitter.movz(regmap::X0, exit_code as u16, 0);
        self.emitter.ret();
    }

    /// Emit the safepoint stub (store guest registers, return EXIT_SAFEPOINT)
    /// at the end of the block and patch the prologue `cbnz` to branch to it.
    /// Must be called after the block body and its normal epilogue.
    pub(super) fn finish_safepoint_stub(&mut self, arch: GuestArch) {
        let Some(cbnz_pos) = self.safepoint_cbnz_patch.take() else {
            return;
        };
        let stub_pos = self.emitter.len();
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, EXIT_SAFEPOINT as u16, 0);
        self.emit_epilogue();
        let offset = (stub_pos as i32 - cbnz_pos as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let insn = 0xb5000000u32 | (((offset as u32) & 0x7ffff) << 5) | regmap::X26;
        let bytes = insn.to_le_bytes();
        self.emitter.code[cbnz_pos..cbnz_pos + 4].copy_from_slice(&bytes);
    }

    /// Publish `guest_address` as the block currently executing.  x3 (the
    /// legacy exit-reason slot) now carries a pointer to a per-thread
    /// `u64` owned by `execute_block`; x23 keeps that pointer across helper
    /// calls (callee-saved) and across chained jumps (`emit_frame_restore`
    /// restores it from the stack, and the jump exit re-copies it into x3).
    /// Emitted before guest registers are loaded, so x10 is still scratch.
    pub(super) fn emit_current_block_tag(&mut self, guest_address: u64) {
        self.emitter.mov_reg(regmap::X23, regmap::X3);
        self.emitter.mov_imm64(10, guest_address);
        self.emitter
            .str64(10, regmap::X23, chain_offsets::CURRENT_BLOCK);
    }

    pub(super) fn emit_prologue(&mut self, arch: GuestArch) {
        // ARM64 prologue is identical for x86 and x86_64 guest architectures;
        // arch parameter reserved for future divergence (e.g., different frame layouts)
        let _ = arch;
        // Save callee-saved registers: x19-x28, fp(x29), lr(x30)
        // We use x19-x20 for guest R14/R15, x21-x25 as temps, x26-x28 as base pointers
        self.emitter.stp64_pre(29, 30, 31, -64); // stp fp, lr, [sp, #-64]!
        self.emitter.mov_reg(29, 31); // mov fp, sp
        // Save x19-x28
        self.emitter.stp64_pre(19, 20, 31, -64); // stp x19, x20, [sp, #-64]!
        self.emitter.stp64_pre(21, 22, 31, -64);
        self.emitter.stp64_pre(23, 24, 31, -64);
        self.emitter.stp64_pre(25, 26, 31, -64);
        self.emitter.stp64_pre(27, 28, 31, -64);
    }

    /// Pop this block's prologue frame (x19-x28, fp, lr) WITHOUT returning.
    /// Used by the chained-jump exit: the source block must release its host
    /// frame before branching to the target's prologue, otherwise a chained
    /// loop leaks one 96-byte frame per hop (host-SP drift).
    pub(super) fn emit_frame_restore(&mut self) {
        // Restore x19-x28
        self.emitter.ldp64_post(27, 28, 31, 64);
        self.emitter.ldp64_post(25, 26, 31, 64);
        self.emitter.ldp64_post(23, 24, 31, 64);
        self.emitter.ldp64_post(21, 22, 31, 64);
        self.emitter.ldp64_post(19, 20, 31, 64);
        // Restore fp, lr
        self.emitter.ldp64_post(29, 30, 31, 64);
    }

    pub(super) fn emit_epilogue(&mut self) {
        self.emit_frame_restore();
        self.emitter.ret();
    }

    /// Emit a worker indirect control-transfer exit.
    ///
    /// Publishes `payload_reg` (the resolved target, or the guest address the
    /// target must be loaded from) into word 2 of the per-thread exit cell
    /// (`x23`, set by `emit_current_block_tag`), stores guest registers, and
    /// returns `exit_code` in `x0`.  `x23` is callee-saved and survives every
    /// helper call in the block, so it still points at the cell here.
    pub(super) fn emit_indirect_exit(&mut self, payload_reg: u32, exit_code: u64, arch: GuestArch) {
        self.emitter
            .str64(payload_reg, regmap::X23, EXIT_CELL_PAYLOAD_OFFSET as u32);
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, exit_code as u16, 0);
        self.emit_epilogue();
    }

    /// Emit a native worker direct call.
    ///
    /// The return address is pushed through the fault-checked store helper (so
    /// a guest-stack fault aborts before the callee runs), the statically known
    /// return successor is pushed onto the chain's return stack, and the call
    /// branches straight into the compiled callee when its link slot is
    /// published.  When the target is a host thunk or an uncompiled block the
    /// block exits with `EXIT_CALL_PUSHED`: the return address is already on
    /// the guest stack, so the worker must not push it again.
    pub(super) fn emit_worker_call(&mut self, target: u64, return_address: u64, arch: GuestArch) {
        let arm_sp = regmap::guest_to_arm(4);
        self.emitter.sub_imm(arm_sp, arm_sp, 8);
        self.emitter.mov_imm64(regmap::X25, return_address);
        self.emit_helper_store(arm_sp, regmap::X25, 8, arch);

        // Push (return_address, compiled return entry) onto the chain stack.
        // x9 is a scratch here (guest RBP was already spilled by the store
        // helper).
        self.emitter
            .ldr64(regmap::X21, regmap::X23, chain_offsets::RETURN_DEPTH);
        self.emitter
            .subs_imm(31, regmap::X21, CHAIN_RETURN_DEPTH as u32);
        let full = self.emitter.len();
        self.emitter.bcond(2, 0); // HS: depth >= capacity
        self.emitter
            .mov_imm64(regmap::X22, chain_offsets::RETURN_STACK as u64);
        self.emitter.add_reg(regmap::X22, regmap::X23, regmap::X22);
        self.emitter.lsl_imm(regmap::X9, regmap::X21, 4);
        self.emitter.add_reg(regmap::X22, regmap::X22, regmap::X9);
        self.emitter.mov_imm64(regmap::X25, return_address);
        self.emitter.str64(regmap::X25, regmap::X22, 0);
        if let Some(slots) = self.link_slots.as_ref() {
            let return_entry = Arc::clone(&slots.return_entry);
            self.emit_reloc_imm64(
                regmap::X26,
                Arc::as_ptr(&return_entry) as u64,
                AotRelocKind::ReturnEntryLink,
            );
            self.emitter.ldar64(regmap::X26, regmap::X26);
            self.emitter.str64(regmap::X26, regmap::X22, 8);
        } else {
            self.emitter.movz(regmap::X26, 0, 0);
            self.emitter.str64(regmap::X26, regmap::X22, 8);
        }
        self.emitter.add_imm(regmap::X21, regmap::X21, 1);
        self.emitter
            .str64(regmap::X21, regmap::X23, chain_offsets::RETURN_DEPTH);
        self.patch_bcond(full, self.emitter.len());
        self.emitter
            .ldr64(regmap::X21, regmap::X23, chain_offsets::NATIVE_CALLS);
        self.emitter.add_imm(regmap::X21, regmap::X21, 1);
        self.emitter
            .str64(regmap::X21, regmap::X23, chain_offsets::NATIVE_CALLS);

        if let Some(slots) = self.link_slots.as_ref() {
            let call = Arc::clone(&slots.call);
            self.emit_link_exit(&call, AotRelocKind::CallLink, EXIT_CALL_PUSHED);
        } else {
            self.emitter.movz(regmap::X0, EXIT_CALL_PUSHED as u16, 0);
            self.emit_epilogue();
        }
        let _ = target;
    }

    /// Emit a native worker `ret`: read guest `[rsp]`, advance `rsp`, then
    /// branch to the return-stack entry when the guest stack agrees with the
    /// statically pushed prediction.  A miss returns `EXIT_RET_RESOLVED` so
    /// the worker can resolve the dynamic target and continue.
    pub(super) fn emit_worker_return(&mut self, stack_adjust: u64, arch: GuestArch) {
        let arm_sp = regmap::guest_to_arm(4);
        self.emit_helper_load(regmap::X9, arm_sp, 8, arch);
        let slot = match arch {
            GuestArch::X86 => 4,
            GuestArch::X64 => 8,
        };
        self.emitter
            .add_imm(arm_sp, arm_sp, (slot + stack_adjust) as u32);

        self.emitter
            .ldr64(regmap::X21, regmap::X23, chain_offsets::RETURN_DEPTH);
        let depth_zero = self.emitter.len();
        self.emitter.cbz(regmap::X21, 0);
        self.emitter.sub_imm(regmap::X21, regmap::X21, 1);
        self.emitter
            .mov_imm64(regmap::X22, chain_offsets::RETURN_STACK as u64);
        self.emitter.add_reg(regmap::X22, regmap::X23, regmap::X22);
        self.emitter.lsl_imm(regmap::X25, regmap::X21, 4);
        self.emitter.add_reg(regmap::X22, regmap::X22, regmap::X25);
        self.emitter.ldr64(regmap::X25, regmap::X22, 0);
        self.emitter.ldr64(10, regmap::X22, 8);
        self.emitter.subs_reg(31, regmap::X25, regmap::X9);
        let mismatch = self.emitter.len();
        self.emitter.bcond(1, 0); // NE: guest stack disagrees

        // Matched prediction: count a hit, pop, and branch to the linked
        // successor when its entry is known.  x21 holds the popped depth;
        // use x22 for the counter so the depth is not clobbered.
        self.emitter
            .ldr64(regmap::X22, regmap::X23, chain_offsets::NATIVE_RETURN_HITS);
        self.emitter.add_imm(regmap::X22, regmap::X22, 1);
        self.emitter
            .str64(regmap::X22, regmap::X23, chain_offsets::NATIVE_RETURN_HITS);
        self.emitter
            .str64(regmap::X21, regmap::X23, chain_offsets::RETURN_DEPTH);
        let no_entry = self.emitter.len();
        self.emitter.cbz(10, 0);

        // Linked return.
        self.emit_store_guest_registers(arch);
        self.emitter
            .ldr64(regmap::X1, regmap::X23, chain_offsets::FLAT_BASE);
        self.emitter.mov_reg(regmap::X3, regmap::X23);
        self.emit_frame_restore();
        self.emitter.br(10);

        // Mismatched prediction: count a miss and mispredict, do not pop, and
        // fall through to the resolved-exit path (the real guest stack wins).
        let mismatch_label = self.emitter.len();
        self.patch_bcond(mismatch, mismatch_label);
        self.emitter.ldr64(
            regmap::X21,
            regmap::X23,
            chain_offsets::NATIVE_RETURN_MISSES,
        );
        self.emitter.add_imm(regmap::X21, regmap::X21, 1);
        self.emitter.str64(
            regmap::X21,
            regmap::X23,
            chain_offsets::NATIVE_RETURN_MISSES,
        );
        self.emitter.ldr64(
            regmap::X21,
            regmap::X23,
            chain_offsets::NATIVE_RETURN_MISPREDICTS,
        );
        self.emitter.add_imm(regmap::X21, regmap::X21, 1);
        self.emitter.str64(
            regmap::X21,
            regmap::X23,
            chain_offsets::NATIVE_RETURN_MISPREDICTS,
        );

        let exit_label = self.emitter.len();
        self.patch_cbz(no_entry, exit_label);
        self.emit_store_guest_registers(arch);
        self.emitter
            .str64(regmap::X9, regmap::X23, chain_offsets::PAYLOAD);
        self.emitter.movz(regmap::X0, EXIT_RET_RESOLVED as u16, 0);
        self.emit_epilogue();

        // Underflow: a return with no prediction is a miss, not a
        // misprediction, and still publishes the real target.
        let zero_stub = self.emitter.len();
        self.patch_cbz(depth_zero, zero_stub);
        self.emitter.ldr64(
            regmap::X21,
            regmap::X23,
            chain_offsets::NATIVE_RETURN_MISSES,
        );
        self.emitter.add_imm(regmap::X21, regmap::X21, 1);
        self.emitter.str64(
            regmap::X21,
            regmap::X23,
            chain_offsets::NATIVE_RETURN_MISSES,
        );
        self.emit_store_guest_registers(arch);
        self.emitter
            .str64(regmap::X9, regmap::X23, chain_offsets::PAYLOAD);
        self.emitter.movz(regmap::X0, EXIT_RET_RESOLVED as u16, 0);
        self.emit_epilogue();
    }

    pub(super) fn patch_cbz(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let register = self.emitter.code[position] & 0x1f;
        let insn = 0xb400_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(register);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    /// Emit a `BL` (branch-with-link) to a known helper.  The helper's
    /// address is embedded through the relocation table so an AOT-loaded
    /// block re-binds to the current process's helper.
    pub(super) fn emit_bl_to(&mut self, helper: AotHelper) {
        let offset = self.emitter.len() as u32;
        self.emitter.mov_imm64_fixed(regmap::X26, helper.address());
        self.relocations.push(AotRelocation {
            offset,
            kind: AotRelocKind::Helper(helper),
        });
        self.emitter.blr(regmap::X26);
    }

    /// Emit a call to `jit_helper_load(state, memory, address, width) -> u64`,
    /// placing the result in `dst`.  The helper is a normal `extern "C"`
    /// function that clobbers caller-saved registers (x0-x18), which hold our
    /// guest GPRs (x4-x17).  So we must save all guest GPRs to CpuState before
    /// the call and reload them after.  We also save the CpuState/MemoryImage
    /// pointers and the address (in callee-saved temps) across the call.
    ///
    /// Immediately after the call the emitted sequence tests the
    /// `jit_pending_fault` channel and branches to the fault-exit stub when a
    /// fault is pending, so a faulting guest load aborts the block AT the
    /// faulting instruction (never executing later instructions).
    pub(super) fn emit_helper_load(
        &mut self,
        dst: u32,
        addr_reg: u32,
        width: u64,
        arch: GuestArch,
    ) {
        // Save all guest GPRs to CpuState (x0), then save x0 (CpuState ptr) and
        // x2 (MemoryImage ptr) in callee-saved regs before the call.
        self.emit_store_guest_registers(arch);
        self.emitter.mov_reg(24, 0); // x24 = CpuState ptr (callee-saved)
        self.emitter.mov_reg(28, 2); // x28 = MemoryImage ptr (callee-saved)
        self.emitter.mov_reg(27, addr_reg); // x27 = address (callee-saved)
        // Set up helper args: (state, memory, address, width).
        self.emitter.mov_reg(0, 24); // x0 = CpuState ptr
        self.emitter.mov_reg(1, 28); // x1 = MemoryImage ptr
        self.emitter.mov_reg(2, 27); // x2 = address
        self.emitter.movz(3, width as u16, 0); // x3 = width
        self.emit_bl_to(AotHelper::Load);
        // Result in x0 → save to x27 (callee-saved).
        self.emitter.mov_reg(27, 0);
        // Restore x0 = CpuState, then reload guest GPRs.
        self.emitter.mov_reg(0, 24);
        self.emit_load_guest_registers(arch);
        // Restore x2 = MemoryImage ptr (load_guest_registers doesn't touch x2,
        // but the helper clobbered it; restore for subsequent memory ops).
        self.emitter.mov_reg(2, 28);
        // Move the result from x27 into the destination guest register.
        self.emitter.mov_reg(dst, 27);
        self.emit_fault_check();
    }

    /// Emit a call to `jit_helper_store(state, memory, address, value, width)`.
    /// Like the load helper call, the emitted sequence immediately tests the
    /// `jit_pending_fault` channel so a faulting guest store aborts the block
    /// at the faulting instruction.
    pub(super) fn emit_helper_store(
        &mut self,
        addr_reg: u32,
        val_reg: u32,
        width: u64,
        arch: GuestArch,
    ) {
        // Save all guest GPRs to CpuState first.
        self.emit_store_guest_registers(arch);
        self.emitter.mov_reg(24, 0); // x24 = CpuState ptr
        self.emitter.mov_reg(28, 2); // x28 = MemoryImage ptr
        self.emitter.mov_reg(27, addr_reg); // x27 = address
        self.emitter.mov_reg(25, val_reg); // x25 = value
        // Set up helper args: (state, memory, address, value, width).
        self.emitter.mov_reg(0, 24); // x0 = CpuState ptr
        self.emitter.mov_reg(1, 28); // x1 = MemoryImage ptr
        self.emitter.mov_reg(2, 27); // x2 = address
        self.emitter.mov_reg(3, 25); // x3 = value
        self.emitter.movz(4, width as u16, 0); // x4 = width
        self.emit_bl_to(AotHelper::Store);
        // Restore x0 = CpuState, then reload guest GPRs.
        self.emitter.mov_reg(0, 24);
        self.emit_load_guest_registers(arch);
        self.emitter.mov_reg(2, 28); // restore MemoryImage ptr
        self.emit_fault_check();
    }

    /// Emit the immediate post-helper fault test:
    ///
    /// ```text
    /// mov_imm64 x26, #jit_pending_fault_offset   // field offset in CpuState
    /// add       x26, x0, x26                     // x26 = &state.jit_pending_fault
    /// ldrb      w26, [x26]                       // tag byte: 0 = no fault
    /// cbnz      w26, <fault_stub>                // patched by finish_fault_stub
    /// ```
    ///
    /// x0 holds the CpuState pointer and x26 is a scratch temp at this point
    /// in both `emit_helper_load` and `emit_helper_store`.  The offset may
    /// exceed the 12-bit unsigned offset of a plain LDRB (the field sits at
    /// the end of CpuState), so the address is computed in x26 first.
    pub(super) fn emit_fault_check(&mut self) {
        self.emitter.mov_imm64(26, Self::JIT_FAULT_BASE as u64);
        self.emitter.add_reg(26, 0, 26);
        self.emitter.ldr8(26, 26, 0);
        let pos = self.emitter.len();
        self.emitter.cbnz(26, 0); // placeholder; patched to the fault stub
        self.fault_cbnz_patches.push(pos);
    }

    /// Emit the single guest-fault exit stub shared by every load/store
    /// fault check in the block, then patch every `cbnz` to branch to it:
    ///
    /// ```text
    /// fault_stub:
    ///   emit_store_guest_registers(arch)
    ///   movz x0, EXIT_GUEST_FAULT
    ///   emit_epilogue()                    // return EXIT_GUEST_FAULT
    /// ```
    ///
    /// The dispatcher maps `EXIT_GUEST_FAULT` to `JitExitReason::GuestFault`
    /// and converts `CpuState::jit_pending_fault` (+ `jit_pending_fault_write`)
    /// into the interpreter's access-violation error.
    pub(super) fn finish_fault_stub(&mut self, arch: GuestArch) {
        let patches = std::mem::take(&mut self.fault_cbnz_patches);
        if patches.is_empty() {
            return;
        }
        let stub_pos = self.emitter.len();
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, EXIT_GUEST_FAULT as u16, 0);
        self.emit_epilogue();
        for pos in patches {
            let offset = (stub_pos as i32 - pos as i32) / 4;
            debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
            let insn = 0xb5000000u32 | (((offset as u32) & 0x7ffff) << 5) | regmap::X26;
            let bytes = insn.to_le_bytes();
            self.emitter.code[pos..pos + 4].copy_from_slice(&bytes);
        }
    }

    /// Compute the effective guest address of a MemoryOperand into `dst_reg`.
    /// Handles base + index*scale + displacement, rip-relative, and absolute.
    pub(super) fn emit_effective_address(
        &mut self,
        operand: &crate::cpu::MemoryOperand,
        dst_reg: u32,
        _rip: u64,
        arch: GuestArch,
    ) {
        // Handle segment prefix: if the operand has a segment, call
        // jit_helper_segment_base to get the segment base (FS=TEB address)
        // and start the effective address from there.
        let seg_code = match operand.segment {
            Some(crate::cpu::SegmentRegister::Fs) => Some(0u64),
            Some(crate::cpu::SegmentRegister::Gs) => Some(1u64),
            _ => None,
        };
        if let Some(abs) = operand.absolute_address {
            // Absolute address (MOFFS): may still need segment base added.
            if let Some(sc) = seg_code {
                // segment_base + absolute_address
                self.emit_segment_base(dst_reg, sc, arch);
                self.emitter.mov_imm64(27, abs);
                self.emitter.add_reg(dst_reg, dst_reg, 27);
            } else {
                self.emitter.mov_imm64(dst_reg, abs);
            }
            return;
        }
        // If segmented, start from the segment base.
        if let Some(sc) = seg_code {
            self.emit_segment_base(dst_reg, sc, arch);
        } else {
            // Start with displacement.
            let disp = operand.displacement as i64;
            self.emitter.mov_imm64(dst_reg, disp as u64);
        }
        if let Some(base) = operand.base {
            let arm_base = regmap::guest_to_arm(base.index());
            self.emitter.add_reg(dst_reg, dst_reg, arm_base);
        }
        if let Some(index) = operand.index {
            let arm_index = regmap::guest_to_arm(index.index());
            match operand.scale {
                0 | 1 => {
                    self.emitter.add_reg(dst_reg, dst_reg, arm_index);
                }
                2 => {
                    self.emitter.lsl_imm(27, arm_index, 1);
                    self.emitter.add_reg(dst_reg, dst_reg, 27);
                }
                4 => {
                    self.emitter.lsl_imm(27, arm_index, 2);
                    self.emitter.add_reg(dst_reg, dst_reg, 27);
                }
                8 => {
                    self.emitter.lsl_imm(27, arm_index, 3);
                    self.emitter.add_reg(dst_reg, dst_reg, 27);
                }
                _ => {
                    self.emitter.mov_imm64(27, operand.scale as u64);
                    self.emitter.mul_reg(27, arm_index, 27);
                    self.emitter.add_reg(dst_reg, dst_reg, 27);
                }
            }
        }
        if operand.rip_relative {
            // Can't compute rip-relative at IR level; emit a placeholder.
            // (Blocks with rip_relative memory should have been rejected by
            // can_compile_instruction if they also have other issues.)
        }
    }

    /// Emit code to load the segment base into dst_reg via a helper call.
    pub(super) fn emit_segment_base(&mut self, dst_reg: u32, seg_code: u64, arch: GuestArch) {
        self.emit_store_guest_registers(arch);
        self.emitter.mov_reg(24, 0);
        self.emitter.mov_reg(0, 24);
        self.emitter.movz(1, seg_code as u16, 0);
        self.emit_bl_to(AotHelper::SegmentBase);
        self.emitter.mov_reg(27, 0);
        self.emitter.mov_reg(0, 24);
        self.emit_load_guest_registers(arch);
        self.emitter.mov_reg(dst_reg, 27);
    }

    /// Call jit_helper_set_flags(state, result, lhs, rhs, op, width).
    /// The operands are in ARM64 registers; we save guest state, set up
    /// args, call, and restore.
    pub(super) fn emit_set_flags(
        &mut self,
        result_reg: u32,
        lhs_reg: u32,
        rhs_reg: u32,
        op: u64,
        width: u64,
        arch: GuestArch,
    ) {
        self.emitter.mov_reg(28, 2); // save MemoryImage ptr
        self.emit_store_guest_registers(arch);
        self.emitter.mov_reg(24, 0); // save CpuState
        // Save the operand regs into callee-saved (they're guest regs that
        // emit_store_guest_registers just wrote to CpuState; but the ARM64
        // regs holding them are x4-x20 which the helper clobbers).
        // So we must capture them BEFORE the store. Actually store_guest_registers
        // already ran, so the guest regs in x4-x20 are stale. We need to
        // pass the values. Save them in x25-x27 BEFORE store.
        // Redo: save operands first, then store, then call.
        // (This is handled by the caller passing callee-saved regs.)
        // For simplicity, pass the values via x25/x26/x27 which are callee-saved
        // and survive the BL.
        // The caller already has result/lhs/rhs in regs — but those are guest
        // regs (x4-x20) that get clobbered. So the caller must use callee-saved
        // temps. We assume result_reg/lhs_reg/rhs_reg are already in
        // callee-saved regs (x23-x28).
        self.emitter.mov_reg(0, 24); // x0 = CpuState
        self.emitter.mov_reg(1, result_reg); // x1 = result
        self.emitter.mov_reg(2, lhs_reg); // x2 = lhs
        self.emitter.mov_reg(3, rhs_reg); // x3 = rhs
        // x4 = op, x5 = width — but x4 is a guest reg (RAX).  Use x21/x22
        // for op/width: they are scratch temps in this ABI and, crucially,
        // are NOT among result/lhs/rhs (x27/x25/x26 here, or the guest
        // destination in the logic arm).  Using x27/x28 would clobber the
        // result/lhs values before they are passed, which made every JIT
        // compare see stale flags (ZF := (op==0)).
        self.emitter.movz(21, op as u16, 0);
        self.emitter.movz(22, width as u16, 0);
        self.emitter.mov_reg(0, 24); // x0 = CpuState
        self.emitter.mov_reg(1, result_reg);
        self.emitter.mov_reg(2, lhs_reg);
        self.emitter.mov_reg(3, rhs_reg);
        self.emitter.mov_reg(4, 21); // x4 = op
        self.emitter.mov_reg(5, 22); // x5 = width
        self.emit_bl_to(AotHelper::SetFlags);
        self.emitter.mov_reg(0, 24); // restore CpuState
        self.emit_load_guest_registers(arch);
        self.emitter.mov_reg(2, 28); // restore MemoryImage ptr
    }

    /// Emit a native register/immediate-source ALU operation.
    /// op: 0=add, 1=sub, 2=and, 3=or, 4=xor.
    pub(super) fn emit_native_alu_reg(
        &mut self,
        insn: &IrInstruction,
        dst: Register,
        src: &crate::cpu::CompareOperand,
        width: usize,
        op: u8,
        arch: GuestArch,
    ) {
        use crate::cpu::CompareOperand;
        let dst_arm = regmap::guest_to_arm(dst.index());
        let src_arm = match src {
            CompareOperand::Register(reg) => regmap::guest_to_arm(reg.index()),
            CompareOperand::ImmediateU64(value) => {
                self.emitter.mov_imm64(regmap::X21, *value);
                regmap::X21
            }
            _ => {
                // Memory-source ALU forms keep the interpreter helper.
                let _ = self.emit_interpreter_fallback(insn, arch);
                return;
            }
        };
        if width == 4 {
            // 32-bit x86 ops ignore the upper halves and zero-extend.
            self.emitter.uxtw_reg(dst_arm, dst_arm);
            self.emitter.uxtw_reg(src_arm, src_arm);
        } else if width == 2 {
            self.emitter.mov_imm64(regmap::X22, 0xffff);
            self.emitter.and_reg(dst_arm, dst_arm, regmap::X22);
            self.emitter.and_reg(src_arm, src_arm, regmap::X22);
        } else if width == 1 {
            self.emitter.mov_imm64(regmap::X22, 0xff);
            self.emitter.and_reg(dst_arm, dst_arm, regmap::X22);
            self.emitter.and_reg(src_arm, src_arm, regmap::X22);
        }
        match op {
            0 => self.emitter.add_reg(dst_arm, dst_arm, src_arm),
            1 => self.emitter.sub_reg(dst_arm, dst_arm, src_arm),
            2 => self.emitter.and_reg(dst_arm, dst_arm, src_arm),
            3 => self.emitter.orr_reg(dst_arm, dst_arm, src_arm),
            4 => self.emitter.eor_reg(dst_arm, dst_arm, src_arm),
            _ => unreachable!("invalid ALU op"),
        }
        if width == 4 {
            self.emitter.uxtw_reg(dst_arm, dst_arm);
        } else if width == 2 {
            self.emitter.mov_imm64(regmap::X22, 0xffff);
            self.emitter.and_reg(dst_arm, dst_arm, regmap::X22);
        } else if width == 1 {
            self.emitter.mov_imm64(regmap::X22, 0xff);
            self.emitter.and_reg(dst_arm, dst_arm, regmap::X22);
        }
    }

    /// Emit a Compare or Test instruction: evaluate operands, call set_flags.
    pub(super) fn emit_compare_test(
        &mut self,
        lhs: &crate::cpu::CompareOperand,
        rhs: &crate::cpu::CompareOperand,
        width: u64,
        op: u64,
        arch: GuestArch,
    ) {
        // Resolve lhs into x25, rhs into x26 (callee-saved temps).
        match lhs {
            crate::cpu::CompareOperand::Register(r) => {
                self.emitter.mov_reg(25, regmap::guest_to_arm(r.index()));
            }
            crate::cpu::CompareOperand::ImmediateU64(v) => {
                self.emitter.mov_imm64(25, *v);
            }
            _ => {
                self.emitter.mov_imm64(25, 0);
            }
        }
        match rhs {
            crate::cpu::CompareOperand::Register(r) => {
                self.emitter.mov_reg(26, regmap::guest_to_arm(r.index()));
            }
            crate::cpu::CompareOperand::ImmediateU64(v) => {
                self.emitter.mov_imm64(26, *v);
            }
            _ => {
                self.emitter.mov_imm64(26, 0);
            }
        }
        // result = lhs - rhs (for cmp) or lhs & rhs (for test).
        if op == 3 {
            self.emitter.sub_reg(27, 25, 26);
        } else {
            self.emitter.and_reg(27, 25, 26);
        }
        self.emit_set_flags(27, 25, 26, op, width, arch);
    }

    /// Load guest GPRs from CpuState (pointed to by x0) into ARM64 working registers.
    pub(super) fn emit_load_guest_registers(&mut self, arch: GuestArch) {
        // CpuState layout for gpr[0..16] is identical for x86 and x86_64;
        // arch parameter reserved for future 32-vs-64-bit state differences
        let _ = arch;
        // CpuState layout (Rust repr(Rust) field reordering).  The gpr/xmm
        // offsets are derived from the real layout via offset_of! (GPR_BASE /
        // XMM_BASE), not hardcoded, so adding fields cannot drift them.
        //   offset 0x00: (beginning of struct, non-gpr fields with alignment >= 8)
        //   offset GPR_BASE: gpr[16] (16 x u64 = 128 bytes)
        //   offset XMM_BASE: xmm[16] (256 bytes)
        //   ...
        // We need to load gpr[0..16] from CpuState into x4-x15, x16, x17, x19, x20
        let gpr_base: u32 = Self::GPR_BASE; // derived offset of gpr[] in CpuState (offset_of!)

        // Load guest registers in pairs for efficiency.
        // Uses signed-offset (no writeback) LDP to avoid corrupting x0.
        for i in (0..16).step_by(2) {
            let arm_lo = regmap::guest_to_arm(i);
            let arm_hi = regmap::guest_to_arm(i + 1);
            let offset = gpr_base + (i as u32) * 8;
            self.emitter.ldp64(arm_lo, arm_hi, 0, offset as i32);
        }
    }

    /// Store guest GPRs from ARM64 working registers back to CpuState (x0).
    pub(super) fn emit_store_guest_registers(&mut self, arch: GuestArch) {
        // Same gpr layout for x86 and x86_64; arch reserved for future use
        // when 32-bit state may need partial register saving
        let _ = arch;
        let gpr_base: u32 = Self::GPR_BASE; // derived offset of gpr[] in CpuState (offset_of!)

        for i in (0..16).step_by(2) {
            let arm_lo = regmap::guest_to_arm(i);
            let arm_hi = regmap::guest_to_arm(i + 1);
            let offset = gpr_base + (i as u32) * 8;
            self.emitter
                .emit((0xa9000000 | ((offset >> 3) & 0x7f) << 15 | (arm_hi << 10)) | arm_lo);
        }
    }

    /// Compile a single IR instruction.
    pub(super) fn compile_instruction(
        &mut self,
        insn: &IrInstruction,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
        is_last: bool,
    ) -> AppResult<()> {
        match insn {
            IrInstruction::Nop => {
                self.emitter.nop();
            }

            IrInstruction::MovImm { dst, value } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.mov_imm64(arm_dst, *value);
                if arch == GuestArch::X86 {
                    // Zero-extend to 32 bits for x86: MOV Wd, Wd (ORR Wd, WZR, Wd)
                    // Writing Wd implicitly zeroes the upper 32 bits of Xd
                    self.emitter.emit(0x2a0003e0 | (arm_dst << 16) | arm_dst);
                }
            }

            IrInstruction::MovImm8 { dst, value } => {
                let arm_dst = regmap::guest_to_arm(dst.full_register().index());
                self.emitter.movz(arm_dst, *value as u16, 0);
            }

            IrInstruction::MovReg { dst, src, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                let arm_src = regmap::guest_to_arm(src.index());
                self.emitter.mov_reg(arm_dst, arm_src);
                if *width == 4 {
                    // 32-bit mov zero-extends: MOV Wd, Ws (ORR Wd, WZR, Ws)
                    // Writing Wd implicitly zeroes the upper 32 bits of Xd
                    self.emitter.emit(0x2a0003e0 | (arm_src << 16) | arm_dst);
                }
            }

            IrInstruction::MovReg8 { dst, src } => {
                let arm_dst = regmap::guest_to_arm(dst.full_register().index());
                let arm_src = regmap::guest_to_arm(src.full_register().index());
                // Extract byte and zero-extend
                self.emitter.uxtb(arm_dst, arm_src);
            }

            // ── Native register-source ALU forms ──────────────────────────
            // Without these, a loop like `add rax, rcx` fell back to the
            // interpreter helper on every iteration, making Tier-2 slower than
            // the dispatcher.  Flags are materialised separately when live.
            IrInstruction::AddOperand { dst, src, width } => {
                self.emit_native_alu_reg(insn, *dst, src, *width, 0, arch);
            }
            IrInstruction::SubOperand { dst, src, width } => {
                self.emit_native_alu_reg(insn, *dst, src, *width, 1, arch);
            }
            IrInstruction::AddImm { dst, value, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                if *value <= 0xfff {
                    self.emitter.add_imm(arm_dst, arm_dst, *value as u32);
                } else {
                    self.emitter.mov_imm64(regmap::X21, *value);
                    self.emitter.add_reg(arm_dst, arm_dst, regmap::X21);
                }
                if *width == 4 {
                    // 32-bit operation: mask the result to the low 32 bits
                    // (zero-extend).  Previously this called `uxtb`, which
                    // masks to a BYTE — a 32-bit `add`/`lea` would then keep
                    // only the low 8 bits, corrupting loop counters and
                    // pointers and hanging counted loops forever.
                    self.emitter.uxtw_reg(arm_dst, arm_dst);
                }
            }

            IrInstruction::SubImm { dst, value, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                if *value <= 0xfff {
                    self.emitter.sub_imm(arm_dst, arm_dst, *value as u32);
                } else {
                    self.emitter.mov_imm64(regmap::X21, *value);
                    self.emitter.sub_reg(arm_dst, arm_dst, regmap::X21);
                }
                if *width == 4 {
                    self.emitter.uxtw_reg(arm_dst, arm_dst);
                }
            }

            IrInstruction::AndImm { dst, value, width } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                let mask = if *width == 4 {
                    (*value as u32) as u64
                } else {
                    *value
                };
                self.emitter.mov_imm64(regmap::X21, mask);
                self.emitter.and_reg(arm_dst, arm_dst, regmap::X21);
            }

            IrInstruction::OrImm {
                dst,
                value,
                width: _,
            } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.mov_imm64(regmap::X21, *value);
                self.emitter.orr_reg(arm_dst, arm_dst, regmap::X21);
            }

            IrInstruction::XorImm {
                dst,
                value,
                width: _,
            } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.mov_imm64(regmap::X21, *value);
                self.emitter.eor_reg(arm_dst, arm_dst, regmap::X21);
            }

            IrInstruction::ShlImm {
                dst,
                count,
                width: _,
            } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.lsl_imm(arm_dst, arm_dst, *count as u32);
            }

            IrInstruction::ShrImm {
                dst,
                count,
                width: _,
            } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.lsr_imm(arm_dst, arm_dst, *count as u32);
            }

            IrInstruction::SarImm {
                dst,
                count,
                width: _,
            } => {
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emitter.asr_imm(arm_dst, arm_dst, *count as u32);
            }

            IrInstruction::PushReg { src } => {
                // Push via helper (safe MemoryImage access): store [rsp-8] = src, rsp -= 8.
                let arm_src = regmap::guest_to_arm(src.index());
                let arm_sp = regmap::guest_to_arm(4); // RSP is at index 4
                // Compute addr = rsp - 8 into X21, then rsp -= 8.
                self.emitter.sub_imm(regmap::X21, arm_sp, 8);
                self.emitter.sub_imm(arm_sp, arm_sp, 8);
                // jit_helper_store(state=x0, memory=x2, addr=X21, val=arm_src,
                // width=8); a fault exits the block via EXIT_GUEST_FAULT.
                self.emit_helper_store(regmap::X21, arm_src, 8, arch);
            }

            IrInstruction::PopReg { dst } => {
                // Pop via helper: dst = load(rsp), rsp += 8.
                let arm_dst = regmap::guest_to_arm(dst.index());
                let arm_sp = regmap::guest_to_arm(4);
                self.emit_helper_load(arm_dst, arm_sp, 8, arch);
                self.emitter.add_imm(arm_sp, arm_sp, 8);
            }

            IrInstruction::PushImm { value, width } => {
                // Push an immediate onto the guest stack: rsp -= width; store [rsp] = value.
                let arm_sp = regmap::guest_to_arm(4);
                let w = *width as u64;
                self.emitter.sub_imm(arm_sp, arm_sp, w as u32);
                // Load value into X22, store via helper.
                self.emitter.mov_imm64(22, *value);
                self.emit_helper_store(arm_sp, 22, w, arch);
            }

            // PushFlags / PopFlags are routed to the interpreter: the JIT
            // does not maintain an EFLAGS word, and pushing 0 / popping 8
            // would diverge from the interpreter's pack_eflags semantics.
            IrInstruction::PushFlags { .. } | IrInstruction::PopFlags { .. } => {
                self.emit_interpreter_fallback(insn, arch)?;
            }

            // ── Register-register ALU ops ──────────────────────────────
            // These use CompareOperand for the source.  We handle the
            // Register case natively (emit ARM64 op), and call
            // jit_helper_set_flags to update x86 flags for JumpIf.
            IrInstruction::XorReg { dst, src, width }
            | IrInstruction::OrReg { dst, src, width }
            | IrInstruction::AndReg { dst, src, width } => {
                if let crate::cpu::CompareOperand::Register(src_reg) = src {
                    let arm_dst = regmap::guest_to_arm(dst.index());
                    let arm_src = regmap::guest_to_arm(src_reg.index());
                    // Save lhs (dst) for flags, do the op, then set flags.
                    self.emitter.mov_reg(27, arm_dst); // lhs
                    match insn {
                        IrInstruction::XorReg { .. } => {
                            self.emitter.eor_reg(arm_dst, arm_dst, arm_src)
                        }
                        IrInstruction::OrReg { .. } => {
                            self.emitter.orr_reg(arm_dst, arm_dst, arm_src)
                        }
                        IrInstruction::AndReg { .. } => {
                            self.emitter.and_reg(arm_dst, arm_dst, arm_src)
                        }
                        _ => {}
                    }
                    if *width == 4 {
                        self.emitter.uxtw_reg(arm_dst, arm_dst);
                    }
                    // Set flags: op=2 (logic), result=dst, lhs=x27, rhs=arm_src
                    self.emit_set_flags(arm_dst, 27, arm_src, 2, *width as u64, arch);
                } else {
                    // Memory/immediate operands: route to the interpreter,
                    // which resolves them via read_compare_operand.
                    self.emit_interpreter_fallback(insn, arch)?;
                }
            }

            // ── Compare / Test (set flags without storing result) ──────
            IrInstruction::Compare { lhs, rhs, width } => {
                self.emit_compare_test(lhs, rhs, *width as u64, 3, arch); // op=3 (cmp)
            }
            IrInstruction::Test { lhs, rhs, width } => {
                self.emit_compare_test(lhs, rhs, *width as u64, 2, arch);
            }

            IrInstruction::LoadEffectiveAddress {
                dst,
                address,
                width,
            } => {
                // LEA: compute effective address into dst (no memory access).
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emit_effective_address(address, arm_dst, 0, arch);
                let _ = width;
            }

            IrInstruction::Leave => {
                // leave = mov rsp, rbp; pop rbp
                let arm_sp = regmap::guest_to_arm(4);
                let arm_bp = regmap::guest_to_arm(5);
                self.emitter.mov_reg(arm_sp, arm_bp);
                self.emit_helper_load(arm_bp, arm_sp, 8, arch);
                self.emitter.add_imm(arm_sp, arm_sp, 8);
            }

            IrInstruction::Return { stack_adjust } => {
                if self.worker_program {
                    self.emit_worker_return(*stack_adjust, arch);
                    return Ok(());
                }
                // Cooperative fallback: let the dispatcher execute the `ret`
                // through the IR interpreter (it reads [rsp], sets rip and
                // pops the stack).  The prefix before the ret already ran.
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_RET as u16, 0);
                self.emit_epilogue();
            }

            IrInstruction::Call {
                target,
                return_address,
            } => {
                // Trivial-API inlining: a call to one of the hot leaf APIs
                // goes straight to a native helper.  The helper performs the
                // exact Win32 semantic against the live runtime (last error,
                // thread/process identity, monotonic clock, interlocked and
                // SRW fast paths), so no generic name lookup or dispatch match
                // is executed.
                if let Some(api) = inline_api_for_target(*target) {
                    // x0..x3 hold the JIT ABI context.  The helper itself
                    // pushes/pops the x86 return address through MemoryImage,
                    // so this call site never depends on the flat-base
                    // register (which earlier helper calls may clobber).
                    self.emitter.mov_reg(regmap::X21, regmap::X0);
                    self.emitter.mov_reg(regmap::X22, regmap::X1);
                    self.emitter.mov_reg(regmap::X25, regmap::X2);
                    self.emitter.mov_reg(regmap::X24, regmap::X3);
                    let runtime_static = &SIGBUS_PE_RUNTIME as *const _ as u64;
                    self.emitter.mov_imm64(regmap::X26, runtime_static);
                    self.emitter.ldr64(regmap::X0, regmap::X26, 0);
                    self.emitter.mov_reg(regmap::X1, regmap::X21);
                    self.emitter.mov_reg(regmap::X2, regmap::X25);
                    self.emitter.mov_imm64(regmap::X3, api.index() as u64);
                    self.emitter.mov_imm64(4, *return_address);
                    self.emitter
                        .mov_imm64(regmap::X26, jit_helper_inline_api as *const () as u64);
                    self.emitter.blr(regmap::X26);
                    self.emitter.mov_reg(regmap::X0, regmap::X21);
                    self.emitter.mov_reg(regmap::X1, regmap::X22);
                    self.emitter.mov_reg(regmap::X2, regmap::X25);
                    self.emitter.mov_reg(regmap::X3, regmap::X24);
                    let gpr_base: u32 = Self::GPR_BASE;
                    for i in (0..16).step_by(2) {
                        let arm_lo = regmap::guest_to_arm(i);
                        let arm_hi = regmap::guest_to_arm(i + 1);
                        let offset = gpr_base + (i as u32) * 8;
                        self.emitter
                            .ldp64(arm_lo, arm_hi, regmap::X0, offset as i32);
                    }
                    return Ok(());
                }

                // Production workers resolve the call themselves: push the
                // static return address natively, push the return link onto
                // the chain stack, then branch directly into the compiled
                // callee when the call slot is published.  Only an unlinked
                // call (host thunk / cold callee) returns to the worker.
                if self.worker_program {
                    self.emit_worker_call(*target, *return_address, arch);
                    return Ok(());
                }

                // Fast-thunk path: if a host thunk with an ARM64 trampoline
                // is registered for this call target, emit a direct `blr` to
                // the trampoline instead of returning EXIT_THUNK. This
                // bypasses the full dispatch loop and is significantly faster.
                if let Some(addrs) = fast_thunk_addrs
                    && addrs.contains(target)
                {
                    // Look up the trampoline address from the global map.
                    // Propagate lock poisoning as an explicit error rather
                    // than silently recovering — the caller can decide how
                    // to handle a poisoned lock (e.g., retry or abort).
                    let map = FAST_THUNK_MAP.lock().map_err(|e| {
                        AppError::new(
                            ReasonCode::RcLockPoisoned,
                            format!("FAST_THUNK_MAP lock poisoned during compile: {e}"),
                        )
                    })?;
                    #[cfg(test)]
                    let forced_miss = JIT_TEST_THUNK_MAP_MISS.with(|miss| miss.replace(false));
                    #[cfg(not(test))]
                    let forced_miss = false;
                    let thunk_opt = if forced_miss {
                        None
                    } else {
                        map.get(target).copied()
                    };
                    if let Some(thunk_addr) = thunk_opt {
                        // Direct resolved-thunk call site: this Call no longer
                        // returns EXIT_THUNK to the dispatcher.
                        JIT_THUNK_DIRECT_CALLS.fetch_add(1, Ordering::Relaxed);
                        // ── Push return_address onto guest stack ──
                        let arm_sp = regmap::guest_to_arm(4);
                        self.emitter.sub_imm(arm_sp, arm_sp, 8);
                        self.emitter.mov_imm64(regmap::X21, *return_address);
                        self.emitter.str64_reg(regmap::X21, 1, arm_sp);

                        // ── Save JIT entry context in callee-saved regs ──
                        // x0 = CpuState ptr, x1 = mem_base, x2 = MemoryImage
                        // x3 = exit_reason ptr
                        self.emitter.mov_reg(regmap::X21, regmap::X0);
                        self.emitter.mov_reg(regmap::X22, regmap::X1);
                        // x23 is reserved for the current-block cell pointer
                        // and must survive every emitted call site.
                        self.emitter.mov_reg(regmap::X25, regmap::X2);
                        self.emitter.mov_reg(regmap::X24, regmap::X3);

                        // ── Load PeHostRuntime ptr from global static ──
                        let static_addr = &SIGBUS_PE_RUNTIME as *const _ as u64;
                        self.emitter.mov_imm64(regmap::X26, static_addr);
                        self.emitter.ldr64(regmap::X0, regmap::X26, 0);

                        // ── Set up bridge arguments ──
                        self.emitter.mov_reg(regmap::X1, regmap::X21); // CpuState
                        self.emitter.mov_reg(regmap::X2, regmap::X25); // MemoryImage
                        self.emitter.mov_imm64(regmap::X3, *target); // thunk_address

                        // ── Call the trampoline ──
                        self.emitter.mov_imm64(regmap::X26, thunk_addr as u64);
                        self.emitter.blr(regmap::X26);

                        // ── Restore JIT entry context ──
                        self.emitter.mov_reg(regmap::X0, regmap::X21);
                        self.emitter.mov_reg(regmap::X1, regmap::X22);
                        self.emitter.mov_reg(regmap::X2, regmap::X25);
                        self.emitter.mov_reg(regmap::X3, regmap::X24);

                        // Reload guest GPRs from CpuState (the bridge may
                        // have modified them via dispatch_import).
                        let gpr_base: u32 = Self::GPR_BASE;
                        for i in (0..16).step_by(2) {
                            let arm_lo = regmap::guest_to_arm(i);
                            let arm_hi = regmap::guest_to_arm(i + 1);
                            let offset = gpr_base + (i as u32) * 8;
                            self.emitter
                                .ldp64(arm_lo, arm_hi, regmap::X0, offset as i32);
                        }

                        return Ok(());
                    }
                }

                // Fallback: standard EXIT_THUNK path.
                //
                // Previously this pushed the return address onto the guest
                // stack here in native code via `str64_reg(X21, X1, sp)` — but
                // X1 holds the memory base, so that wrote to [mem_base + rsp]
                // (flat-memory absolute), NOT the guest [rsp], corrupting the
                // return address.  Instead we just signal EXIT_THUNK and let
                // the dispatcher perform the call setup correctly (it has safe
                // MemoryImage access).  The block's straight-line instructions
                // before the call already ran natively; the dispatcher must NOT
                // re-run them (handled in execute_with_jit's EXIT_THUNK arm).
                let _ = return_address;
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_THUNK as u16, 0);
                self.emit_epilogue();
            }

            IrInstruction::Jump { target } => {
                // Unconditional jump.  When a link has been published in this
                // block's atomic link slot, branch straight into the target
                // block's entry (no dispatcher round-trip).  The target's
                // prologue reloads guest registers, checks the SMC epoch /
                // link budget and polls the host safepoint flag, so chaining
                // preserves every dispatch invariant.
                let _ = target;
                self.emit_store_guest_registers(arch);
                if let Some(slots) = self.link_slots.as_ref() {
                    let jump = Arc::clone(&slots.jump);
                    self.emit_link_exit(&jump, AotRelocKind::JumpLink, EXIT_JUMP);
                } else {
                    self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                    self.emit_epilogue();
                }
            }
            IrInstruction::JumpIf {
                condition,
                target,
                fallthrough,
            } => {
                // Real ARM64 conditional branch.  Flags are materialised from
                // CpuState (including any parked lazy computation) and tested
                // natively; the host no longer evaluates the condition.  The
                // two successor edges have independent link slots so either
                // direction can chain without patching code.
                let _ = (target, fallthrough);
                if !is_last {
                    // A non-terminating conditional branch would need an
                    // in-block merge label; decoded basic blocks always put a
                    // Jcc last, so retain the host-evaluated fallback for this
                    // defensive case.
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_COND_BRANCH as u16, 0);
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_store_guest_registers(arch);
                self.emit_materialize_flags();
                self.emit_x86_flag_loads();
                let taken_branch = self.emit_x86_condition_branch(*condition);
                // Fallthrough path.
                if let Some(slots) = self.link_slots.as_ref() {
                    let fallthrough = Arc::clone(&slots.fallthrough);
                    self.emit_link_exit(
                        &fallthrough,
                        AotRelocKind::FallthroughLink,
                        EXIT_COND_NOT_TAKEN,
                    );
                } else {
                    self.emitter.movz(regmap::X0, EXIT_COND_NOT_TAKEN as u16, 0);
                    self.emit_epilogue();
                }
                // Taken path.
                self.patch_bcond(taken_branch, self.emitter.len());
                if let Some(slots) = self.link_slots.as_ref() {
                    let taken = Arc::clone(&slots.taken);
                    self.emit_link_exit(&taken, AotRelocKind::TakenLink, EXIT_COND_TAKEN);
                } else {
                    self.emitter.movz(regmap::X0, EXIT_COND_TAKEN as u16, 0);
                    self.emit_epilogue();
                }
            }

            IrInstruction::Cpuid => {
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_CPUID as u16, 0);
                self.emit_epilogue();
            }

            // ── Crypto: AES-NI lowering to ARM64 NEON AESE/AESD/AESIMC ──────────
            //
            // CpuState layout (offsets derived via offset_of!, see GPR_BASE /
            // XMM_BASE):
            //   offset GPR_BASE: gpr[16]  (16 × u64)
            //   offset XMM_BASE: xmm[16]  (16 × XmmValue = 16 × 16 bytes)
            // x0 holds the CpuState pointer throughout the compiled block.
            //
            // We use NEON registers V0 and V1 as temporaries.
            IrInstruction::AesEnc { dst, src } => {
                // x86 AESENC xmm1, xmm2 → ShiftRows, SubBytes, MixColumns, XOR(round_key)
                // ARM64  AESE Vd, Vn    → SubBytes, ShiftRows, MixColumns, XOR(Vn)
                // The two are equivalent because ShiftRows and SubBytes commute.
                let dst_off: u32 = (Self::XMM_BASE + (*dst as u32) * 16) >> 4;
                let src_off: u32 = (Self::XMM_BASE + (*src as u32) * 16) >> 4;
                // Load state (dst) into V0, round key (src) into V1
                self.emitter.ldr_q_imm(0, 0, dst_off as u16);
                self.emitter.ldr_q_imm(1, 0, src_off as u16);
                self.emitter.aese(0, 1);
                self.emitter.str_q_imm(0, 0, dst_off as u16);
            }

            IrInstruction::AesDec { dst, src } => {
                let dst_off: u32 = (Self::XMM_BASE + (*dst as u32) * 16) >> 4;
                let src_off: u32 = (Self::XMM_BASE + (*src as u32) * 16) >> 4;
                self.emitter.ldr_q_imm(0, 0, dst_off as u16);
                self.emitter.ldr_q_imm(1, 0, src_off as u16);
                self.emitter.aesd(0, 1);
                self.emitter.str_q_imm(0, 0, dst_off as u16);
            }

            IrInstruction::AesImc { dst, src } => {
                // AESIMC operates on a single XMM register (inverse mix columns).
                let dst_off: u32 = (Self::XMM_BASE + (*dst as u32) * 16) >> 4;
                let src_off: u32 = (Self::XMM_BASE + (*src as u32) * 16) >> 4;
                self.emitter.ldr_q_imm(0, 0, src_off as u16);
                self.emitter.aesimc(0, 0);
                self.emitter.str_q_imm(0, 0, dst_off as u16);
            }

            // ── Crypto: PCLMULQDQ lowering to ARM64 NEON PMULL/PMULL2 ──────────
            //
            // PCLMULQDQ imm controls which 64-bit halves to multiply:
            //   imm[0]  selects dst half (0=low, 1=high)
            //   imm[4]  selects src half (0=low, 1=high)
            //
            // ARM64 NEON:
            //   PMULL  Vd.1Q, Vn.1D, Vm.1D  → multiply lower halves
            //   PMULL2 Vd.1Q, Vn.2D, Vm.2D  → multiply upper halves
            //
            // For mixed cases (e.g. high × low), we use EXT #8 to swap the
            // 64-bit halves of the target operand before PMULL.
            IrInstruction::Pclmulqdq { dst, src, imm } => {
                let dst_off: u32 = (Self::XMM_BASE + (*dst as u32) * 16) >> 4;
                let src_off: u32 = (Self::XMM_BASE + (*src as u32) * 16) >> 4;
                let use_dst_hi = (*imm & 0x01) != 0;
                let use_src_hi = (*imm & 0x10) != 0;
                self.emitter.ldr_q_imm(0, 0, dst_off as u16);
                self.emitter.ldr_q_imm(1, 0, src_off as u16);
                match (use_dst_hi, use_src_hi) {
                    (false, false) => {
                        // low × low → PMULL (both operands already in low position)
                        self.emitter.pmull_1q(0, 0, 1);
                    }
                    (true, true) => {
                        // high × high → PMULL2
                        self.emitter.pmull2_1q(0, 0, 1);
                    }
                    (true, false) => {
                        // high(dst) × low(src) → swap dst halves, then PMULL
                        self.emitter.ext_16b(0, 0, 0, 8);
                        self.emitter.pmull_1q(0, 0, 1);
                    }
                    (false, true) => {
                        // low(dst) × high(src) → swap src halves, then PMULL
                        self.emitter.ext_16b(1, 1, 1, 8);
                        self.emitter.pmull_1q(0, 0, 1);
                    }
                }
                self.emitter.str_q_imm(0, 0, dst_off as u16);
            }
            IrInstruction::LoadMemory {
                dst,
                address,
                width,
            } => {
                if address.rip_relative {
                    // RIP-relative addressing needs the instruction's RIP,
                    // unavailable at IR level.  Fall back to interpreter.
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_effective_address(address, 21, 0, arch);
                let arm_dst = regmap::guest_to_arm(dst.index());
                self.emit_helper_load(arm_dst, 21, *width as u64, arch);
            }
            IrInstruction::LoadMemory8 { dst, address } => {
                if address.rip_relative {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_effective_address(address, 21, 0, arch);
                let arm_dst = regmap::guest_to_arm(dst.full_register().index());
                self.emit_helper_load(arm_dst, 21, 1, arch);
            }
            IrInstruction::StoreMemory {
                src,
                address,
                width,
            } => {
                if address.rip_relative {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_effective_address(address, 21, 0, arch);
                let arm_src = regmap::guest_to_arm(src.index());
                self.emit_helper_store(21, arm_src, *width as u64, arch);
            }
            IrInstruction::StoreMemory8 { src, address } => {
                if address.rip_relative {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_effective_address(address, 21, 0, arch);
                let arm_src = regmap::guest_to_arm(src.full_register().index());
                self.emit_helper_store(21, arm_src, 1, arch);
            }
            IrInstruction::StoreImmediate {
                address,
                value,
                width,
            } => {
                if address.rip_relative {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                    self.emit_epilogue();
                    return Ok(());
                }
                self.emit_effective_address(address, 21, 0, arch);
                self.emitter.mov_imm64(22, *value);
                self.emit_helper_store(21, 22, *width as u64, arch);
            }

            IrInstruction::Fxsave { .. } | IrInstruction::Fxrstor { .. } => {
                // These instructions operate on a 512-byte FXSAVE area in memory.
                // The interpreter handles the complex x87/SSE state serialization.
                // Exit JIT to interpreter to execute natively.
                self.emit_store_guest_registers(arch);
                self.emitter.movz(regmap::X0, EXIT_UNIMPL as u16, 0);
                self.emit_epilogue();
                // EXIT_UNIMPL exits the whole block to the AOT interpreter:
                // counted as neither native lowering nor helper fallback.
                return Ok(());
            }

            // ── Indirect control transfer (production-worker lowering) ────
            // Guest `jmp reg` / `call reg` / `jmp [mem]` / `call [mem]`.  On
            // the cooperative path these use the universal interpreter helper
            // (which needs a live `MemoryImage`).  On a production worker the
            // block is self-contained: it publishes the resolved target (for a
            // register operand) or the guest address the target must be loaded
            // from (memory operand) into the per-thread exit cell and exits,
            // letting the worker resolve it with an inline cache and continue
            // natively.  A rip-relative memory operand has no resolvable
            // effective address at IR level, so it stays a helper (and thus a
            // worker host barrier).
            IrInstruction::JumpRegister { src } if self.worker_program => {
                self.emit_indirect_exit(
                    regmap::guest_to_arm(src.index()),
                    EXIT_INDIRECT_JUMP_REG,
                    arch,
                );
            }
            IrInstruction::CallRegister { src, .. } if self.worker_program => {
                self.emit_indirect_exit(
                    regmap::guest_to_arm(src.index()),
                    EXIT_INDIRECT_CALL_REG,
                    arch,
                );
            }
            IrInstruction::JumpMemory { address }
                if self.worker_program && !address.rip_relative =>
            {
                self.emit_effective_address(address, 25, 0, arch);
                self.emit_indirect_exit(25, EXIT_INDIRECT_JUMP_MEM, arch);
            }
            IrInstruction::CallMemory { address, .. }
                if self.worker_program && !address.rip_relative =>
            {
                self.emit_effective_address(address, 25, 0, arch);
                self.emit_indirect_exit(25, EXIT_INDIRECT_CALL_MEM, arch);
            }

            // ── Tier-2 register-allocation spills ────────────────────────
            // These only touch the host-side spill area in CpuState; they are
            // never guest-visible memory and do not perturb guest registers
            // beyond the explicit src/dst.
            IrInstruction::SpillStore { slot, src } => {
                if (*slot as usize) >= crate::jit_ssa::SPILL_SLOTS {
                    self.emit_interpreter_fallback(insn, arch)?;
                } else {
                    let arm_src = regmap::guest_to_arm(src.index());
                    let offset = Self::SPILL_BASE + (*slot as u32) * 8;
                    self.emitter.str64(arm_src, regmap::X0, offset);
                }
            }
            IrInstruction::SpillLoad { slot, dst } => {
                if (*slot as usize) >= crate::jit_ssa::SPILL_SLOTS {
                    self.emit_interpreter_fallback(insn, arch)?;
                } else {
                    let arm_dst = regmap::guest_to_arm(dst.index());
                    let offset = Self::SPILL_BASE + (*slot as u32) * 8;
                    self.emitter.ldr64(arm_dst, regmap::X0, offset);
                    if arch == GuestArch::X86 {
                        self.emitter.uxtw_reg(arm_dst, arm_dst);
                    }
                }
            }
            IrInstruction::ExplicitFlags {
                op,
                lhs,
                rhs,
                result,
                width,
            } => {
                self.emit_set_flags(
                    regmap::guest_to_arm(result.index()),
                    regmap::guest_to_arm(lhs.index()),
                    regmap::guest_to_arm(rhs.index()),
                    *op as u64,
                    *width as u64,
                    arch,
                );
            }

            // Universal catch-all: for any instruction without a dedicated
            // JIT arm, emit a call to jit_helper_execute_insn(state, memory,
            // &insn) so the interpreter executes it with identical semantics.
            _ => {
                JIT_HELPER_FALLBACK[ir_opcode_index(insn)].fetch_add(1, Ordering::Relaxed);
                self.emit_interpreter_fallback(insn, arch)?;
            }
        }

        JIT_NATIVE_LOWERED[ir_opcode_index(insn)].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Emit a call to `jit_helper_execute_insn` for an IR instruction the JIT
    /// does not compile natively. The instruction is stored in
    /// `self.helper_insns` so its pointer remains valid for the lifetime of
    /// the JitCompiler; guest registers are saved/restored around the call.
    pub(super) fn emit_interpreter_fallback(
        &mut self,
        insn: &IrInstruction,
        arch: GuestArch,
    ) -> AppResult<()> {
        self.used_interpreter_helper = true;
        // Store a boxed copy so the address is stable across Vec growth.
        let boxed = Box::new(insn.clone());
        let insn_ptr = &*boxed as *const IrInstruction as u64;
        self.helper_insns.push(boxed);
        // Save guest GPRs to CpuState, call helper, reload.
        self.emit_store_guest_registers(arch);
        self.emitter.mov_reg(24, 0); // save CpuState
        self.emitter.mov_reg(28, 2); // save MemoryImage ptr
        self.emitter.mov_reg(0, 24); // x0 = CpuState
        self.emitter.mov_reg(1, 28); // x1 = MemoryImage
        self.emitter.mov_imm64(2, insn_ptr); // x2 = &insn
        self.emit_bl_to(AotHelper::ExecuteInsn);
        self.emitter.mov_reg(0, 24); // restore CpuState
        self.emit_load_guest_registers(arch);
        self.emitter.mov_reg(2, 28); // restore MemoryImage ptr
        Ok(())
    }

    /// Byte offset of the `gpr[]` array within CpuState.
    /// Derived from the real repr(Rust) layout with `offset_of!` so adding
    /// fields (e.g. `jit_pending_fault`) can never silently drift the
    /// offsets baked into emitted code.  Verified by
    /// `cpu_state_jit_field_offsets_are_verified`.
    /// Historical anchor (pre-fault-channel layout): gpr at +0x20 (32),
    /// xmm at +0xA0 (160).
    const GPR_BASE: u32 = std::mem::offset_of!(CpuState, gpr) as u32;
    /// Byte offset of the xmm[] array within CpuState.
    const XMM_BASE: u32 = std::mem::offset_of!(CpuState, xmm) as u32;
    /// Byte offset of the `jit_pending_fault` channel within CpuState.  The
    /// emitted fault check after each load/store helper call does an LDRB of
    /// this field (the `Option<u64>` tag byte: 0 when no fault is pending, 1
    /// when one is) and branches to the fault-exit stub when nonzero.
    const JIT_FAULT_BASE: u32 = std::mem::offset_of!(CpuState, jit_pending_fault) as u32;
    /// Byte offset of the host-only Tier-2 spill area within CpuState.
    const SPILL_BASE: u32 = std::mem::offset_of!(CpuState, jit_spill) as u32;

    /// Get reference to the memory manager.
    pub fn memory_manager(&self) -> &JitMemoryManager {
        &self.memory_manager
    }

    /// Get mutable reference to the memory manager.
    pub fn memory_manager_mut(&mut self) -> &mut JitMemoryManager {
        &mut self.memory_manager
    }
}
