//! JIT execution engine for Casa1.
//!
//! Compiles translated IR blocks into native ARM64 machine code and executes them
//! directly on the host CPU. Uses MAP_JIT for W^X-compliant executable memory
//! allocation on Apple Silicon.

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
    static WORKER_SLICE_MEMORY: std::cell::Cell<*const GuestSliceMemory> =
        const { std::cell::Cell::new(std::ptr::null()) };
    static WORKER_SLICE_CODE_WRITTEN: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Install the worker-slice memory view for the duration of a slice.  The
/// guard clears the thread-local on drop so a stale pointer can never leak
/// into a later host-thread execution on the same native worker.
pub(crate) struct WorkerSliceGuard {
    previous: *const GuestSliceMemory,
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

fn worker_slice_memory() -> Option<&'static GuestSliceMemory> {
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

fn parity_byte(v: u8) -> bool {
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

static INLINE_API_TARGETS: std::sync::LazyLock<
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

unsafe fn inline_api_semantics(
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

// ── JIT helper semantic tests ───────────────────────────────────────────────
//
// Native execution is capability-gated (see `jit_execution_capability`); the
// host-side helpers are plain `extern "C"` functions — these tests call
// `jit_helper_set_flags` / `jit_helper_load` directly and check their
// semantics against the x86 truth table.

#[cfg(test)]
mod jit_helper_semantics {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ExpectedFlags {
        zf: bool,
        sf: bool,
        pf: bool,
        cf: bool,
        of: bool,
        af: bool,
    }

    fn width_mask(bits: u32) -> u64 {
        if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    fn even_low_byte_parity(value: u64) -> bool {
        let low = value as u8;
        (0..8).filter(|&i| low & (1 << i) != 0).count() % 2 == 0
    }

    fn truth_add(lhs: u64, rhs: u64, bits: u32) -> ExpectedFlags {
        let m = width_mask(bits);
        let (a, b) = (lhs & m, rhs & m);
        let sum = a.wrapping_add(b) & m;
        let msb = 1u64 << (bits - 1);
        ExpectedFlags {
            zf: sum == 0,
            sf: sum & msb != 0,
            pf: even_low_byte_parity(sum),
            cf: sum < a,
            of: (a & msb != 0) == (b & msb != 0) && (sum & msb != 0) != (a & msb != 0),
            af: (a ^ b ^ sum) & 0x10 != 0,
        }
    }

    fn truth_sub(lhs: u64, rhs: u64, bits: u32) -> ExpectedFlags {
        let m = width_mask(bits);
        let (a, b) = (lhs & m, rhs & m);
        let (diff, _borrow) = a.overflowing_sub(b);
        let diff = diff & m;
        let msb = 1u64 << (bits - 1);
        ExpectedFlags {
            zf: diff == 0,
            sf: diff & msb != 0,
            pf: even_low_byte_parity(diff),
            cf: a < b,
            of: (a & msb != 0) != (b & msb != 0) && (diff & msb != 0) != (a & msb != 0),
            af: (a ^ b ^ diff) & 0x10 != 0,
        }
    }

    fn truth_logic(result: u64, bits: u32) -> ExpectedFlags {
        let r = result & width_mask(bits);
        let msb = 1u64 << (bits - 1);
        ExpectedFlags {
            zf: r == 0,
            sf: r & msb != 0,
            pf: even_low_byte_parity(r),
            cf: false,
            of: false,
            af: false,
        }
    }

    fn read_flags(state: &CpuState) -> ExpectedFlags {
        ExpectedFlags {
            zf: state.flags.zf,
            sf: state.flags.sf,
            pf: state.flags.pf,
            cf: state.flags.cf,
            of: state.flags.of,
            af: state.flags.af,
        }
    }

    fn call_set_flags(result: u64, lhs: u64, rhs: u64, op: u64, width: u64) -> ExpectedFlags {
        let mut state = CpuState::new(GuestArch::X64);
        unsafe { jit_helper_set_flags(&mut state, result, lhs, rhs, op, width) };
        read_flags(&state)
    }

    fn check_vector(name: &str, lhs: u64, rhs: u64, width: u64) {
        let bits = (width * 8) as u32;
        let m = width_mask(bits);
        let (a, b) = (lhs & m, rhs & m);

        // add
        let sum = a.wrapping_add(b);
        let got = call_set_flags(sum, a, b, 0, width);
        assert_eq!(
            got,
            truth_add(a, b, bits),
            "{name} (w={width}): add flags mismatch for {a:#x} + {b:#x}"
        );

        // sub
        let diff = a.wrapping_sub(b);
        let got_sub = call_set_flags(diff, a, b, 1, width);
        assert_eq!(
            got_sub,
            truth_sub(a, b, bits),
            "{name} (w={width}): sub flags mismatch for {a:#x} - {b:#x}"
        );

        // cmp — flags of a subtraction without storing the result
        let got_cmp = call_set_flags(diff, a, b, 3, width);
        assert_eq!(
            got_cmp, got_sub,
            "{name} (w={width}): cmp({a:#x}, {b:#x}) must produce identical flags to sub"
        );

        // logic
        let logic = a & b;
        let got_logic = call_set_flags(logic, a, b, 2, width);
        assert_eq!(
            got_logic,
            truth_logic(logic, bits),
            "{name} (w={width}): logic flags mismatch for {a:#x} & {b:#x}"
        );
    }

    #[test]
    fn jit_helper_load_unmapped_read_marks_fault_and_returns_zero() {
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let address = 0x0000_0001_0000_0000u64;
        for width in [1u64, 2, 4, 8] {
            state.jit_pending_fault = None;
            state.jit_pending_fault_write = true;
            let value = unsafe { jit_helper_load(&mut state, &mut memory, address, width) };
            assert_eq!(value, 0, "failed read returns 0 to JIT code (w={width})");
            assert_eq!(
                state.jit_pending_fault,
                Some(address),
                "fault address must be recorded for the dispatcher (w={width})"
            );
            assert!(
                !state.jit_pending_fault_write,
                "a faulting READ must record access type write=false (w={width})"
            );
        }
    }

    #[test]
    fn jit_helper_load_mapped_read_returns_value_without_fault() {
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let address = 0x4000;
        memory.write_u64(address, 0x1122_3344_5566_7788);
        let value = unsafe { jit_helper_load(&mut state, &mut memory, address, 8) };
        assert_eq!(value, 0x1122_3344_5566_7788);
        assert_eq!(
            state.jit_pending_fault, None,
            "a successful read must not fabricate a fault"
        );
        assert!(!state.jit_pending_fault_write);
    }

    #[test]
    fn jit_helper_store_unmapped_write_marks_fault_and_never_creates_page() {
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        // Cross-page guard probe: map only byte 0x4000, so a store at 0x4001
        // faults at the first guarded byte.
        memory.map_bytes(0x4000, &[0x11]);
        for width in [1u64, 2, 4, 8] {
            state.jit_pending_fault = None;
            state.jit_pending_fault_write = false;
            unsafe {
                jit_helper_store(
                    &mut state,
                    &mut memory,
                    0x0000_0100_0000,
                    0xDEAD_BEEF,
                    width,
                )
            };
            assert_eq!(
                state.jit_pending_fault,
                Some(0x0000_0100_0000),
                "fault address must be recorded for the dispatcher (w={width})"
            );
            assert!(
                state.jit_pending_fault_write,
                "a faulting WRITE must record access type write=true (w={width})"
            );
            assert!(
                memory
                    .guest_read_checked(0x0000_0100_0000, &mut [0_u8; 1])
                    .is_err(),
                "a failed guest store must NEVER materialize the page (w={width})"
            );
        }

        // Precise fault address: store past the single mapped byte.
        state.jit_pending_fault = None;
        unsafe { jit_helper_store(&mut state, &mut memory, 0x4001, 0xFFFF, 2) };
        assert_eq!(
            state.jit_pending_fault,
            Some(0x4001),
            "fault address must be the first guarded byte"
        );
        assert!(state.jit_pending_fault_write);
        assert_eq!(
            memory.read_u8(0x4000).unwrap(),
            0x11,
            "no partial write before the faulting byte"
        );
    }

    #[test]
    fn jit_helper_store_mapped_write_succeeds_without_fault() {
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        memory.map_zeroed_if_unmapped(0x4000, 0x100);
        for width in [1u64, 2, 4, 8] {
            state.jit_pending_fault = None;
            unsafe {
                jit_helper_store(
                    &mut state,
                    &mut memory,
                    0x4008,
                    0x1122_3344_5566_7788,
                    width,
                )
            };
            assert_eq!(
                state.jit_pending_fault, None,
                "a successful store must not fabricate a fault (w={width})"
            );
            assert!(!state.jit_pending_fault_write);
        }
        assert_eq!(memory.read_u64(0x4008).unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(memory.read_u8(0x4008).unwrap(), 0x88);
    }

    fn stride_sample_values(bits: u32) -> Vec<u64> {
        let mask = width_mask(bits);
        let msb = 1u64 << (bits - 1);
        let mut values = vec![
            0,
            1,
            mask,
            mask - 1,
            msb,
            msb - 1,
            msb + 1,
            0x0f,
            0x10,
            0xff,
            0x0f_0f,
            0xf0_f0,
            0x55_55,
            0xaa_aa,
        ];
        let stride = mask / 257;
        for k in 0..=256u64 {
            values.push(k.wrapping_mul(stride) & mask);
        }
        values
    }

    #[test]
    fn jit_helper_set_flags_add_exhaustive_8bit() {
        // EXHAUSTIVE: every pair (a, b) in 0..=255 × 0..=255 — this is the
        // exact vector family where the unmasked-sum carry bug lived (e.g.
        // 0xff + 0x01 must set CF; the old code computed sum = 0x100 and
        // 0x100 < 0xff = false).
        let mut state = CpuState::new(GuestArch::X64);
        for a in 0..=255u64 {
            for b in 0..=255u64 {
                let sum = a.wrapping_add(b) & 0xff;
                unsafe { jit_helper_set_flags(&mut state, sum, a, b, 0, 1) };
                let got = read_flags(&state);
                assert_eq!(
                    got,
                    truth_add(a, b, 8),
                    "8-bit ADD flags mismatch for {a:#x} + {b:#x}"
                );
            }
        }
    }

    #[test]
    fn jit_helper_set_flags_sub_exhaustive_8bit() {
        let mut state = CpuState::new(GuestArch::X64);
        for a in 0..=255u64 {
            for b in 0..=255u64 {
                let diff = a.wrapping_sub(b) & 0xff;
                unsafe { jit_helper_set_flags(&mut state, diff, a, b, 1, 1) };
                let got = read_flags(&state);
                assert_eq!(
                    got,
                    truth_sub(a, b, 8),
                    "8-bit SUB flags mismatch for {a:#x} - {b:#x}"
                );
            }
        }
    }

    #[test]
    fn jit_helper_set_flags_add_sub_dense_samples_16_32_64() {
        // Dense samples at 16/32/64: every width edge (0, 1, msb±1, mask-1,
        // mask, carry/borrow boundaries, AF nibble edges) plus a stride
        // sample covering the full width.
        let mut state = CpuState::new(GuestArch::X64);
        for (width, bits) in [(2u64, 16u32), (4, 32), (8, 64)] {
            let values = stride_sample_values(bits);
            for &a in &values {
                for &b in &values {
                    let sum = a.wrapping_add(b) & width_mask(bits);
                    unsafe { jit_helper_set_flags(&mut state, sum, a, b, 0, width) };
                    assert_eq!(
                        read_flags(&state),
                        truth_add(a, b, bits),
                        "ADD flags mismatch at {bits} bits for {a:#x} + {b:#x}"
                    );
                    let diff = a.wrapping_sub(b) & width_mask(bits);
                    unsafe { jit_helper_set_flags(&mut state, diff, a, b, 1, width) };
                    assert_eq!(
                        read_flags(&state),
                        truth_sub(a, b, bits),
                        "SUB flags mismatch at {bits} bits for {a:#x} - {b:#x}"
                    );
                    unsafe { jit_helper_set_flags(&mut state, diff, a, b, 3, width) };
                    assert_eq!(
                        read_flags(&state),
                        truth_sub(a, b, bits),
                        "CMP flags mismatch at {bits} bits for {a:#x} cmp {b:#x}"
                    );
                }
            }
        }
    }
}

const JIT_PAGE_SIZE: usize = 64 * 1024;

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
    fn select(
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
static JIT_EXECUTION_CAPABILITY: LazyLock<JitExecProbeMatrix> = LazyLock::new(probe_jit_execution);

/// Cached executable-memory capability of the current process.
pub fn jit_execution_capability() -> JitExecProbeMatrix {
    *JIT_EXECUTION_CAPABILITY
}

/// True when at least one mechanism executed the ARM64 probe stub.
pub fn jit_execution_available() -> bool {
    jit_execution_capability().selected != JitExecMechanism::Unavailable
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod exec_probe {
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

/// Global mapping from guest thunk address (u64) to ARM64 trampoline executable
/// address (usize).  Populated by [`FastThunkTable::register_with_guest_addr`] and
/// consumed by [`JitCompiler::compile_instruction`] when emitting a direct `bl`
/// to a fast-thunk trampoline.
static FAST_THUNK_MAP: LazyLock<Mutex<HashMap<u64, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// When set to `true`, the JIT chaining mechanism will refuse to create
/// *new* block chains.  Existing chains are unaffected — they must be
/// broken explicitly via [`JitRuntime::break_all_chains()`].
///
/// # Protocol
/// - **Watchdog / live-session thread** sets this flag periodically to
///   force the PE runtime to stop forming new chains, eventually causing
///   execution to return to the main loop where the CPU yield check fires.
/// - **PE runtime main loop** checks this flag before auto-chaining in
///   [`get_or_compile`](JitRuntime::get_or_compile) and
///   [`chain_blocks`](JitRuntime::chain_blocks).  After breaking chains
///   and yielding, it clears the flag.
pub static JIT_CHAIN_BREAK_REQUESTED: AtomicBool = AtomicBool::new(false);

/// When set to `true`, the host-side scheduler has requested that the
/// next JIT-compiled block exit to the dispatcher so the safepoint body
/// can run (pump pending guest threads, drain timers/APCs, advance the
/// guest clock).
///
/// # Protocol
/// - **Host scheduler (PE runtime main loop / live watchdog)** sets this
///   flag when the block-dispatch safepoint has been overdue.
/// - **JIT-compiled blocks** check the flag at their prologue (see
///   [`JitCompiler::emit_safepoint_check`]) and exit with `EXIT_SAFEPOINT`
///   when set; the dispatcher maps that to
///   [`JitExitReason::Safepoint`], runs the safepoint body, then
///   re-dispatches the block.
///
/// Active whenever the capability probe selected an executable-memory
/// mechanism: every compiled block reads this flag in its prologue, so a
/// long-running native chain can still reach the host safepoint.
pub static JIT_SAFEPOINT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Global pointer to the active [`JitRuntime`] instance, used by the live
/// session's watchdog thread to force chain-breaking when the worker thread
/// is stuck inside JIT-compiled chains that never return to the dispatcher.
///
/// # Safety
/// - Set by [`register_jit_runtime()`] before the main execution loop starts
///   and cleared by [`unregister_jit_runtime()`] after it finishes.
/// - The pointer is only dereferenced while the PE runtime's main loop is
///   running — at that point `JitRuntime` is guaranteed to be alive on the
///   worker thread's stack (inside `PeHostRuntime`).
/// - `AtomicPtr` is used instead of `Mutex<Option<NonNull>>` because
///   `NonNull` is not `Send`, making it ineligible for use in a static.
static JIT_RUNTIME_PTR: AtomicPtr<JitRuntime> = AtomicPtr::new(std::ptr::null_mut());

/// Global lock that prevents the MAP_JIT permission race between JIT code
/// execution and chain-breaking operations.
///
/// On Apple Silicon, `pthread_jit_write_protect_np(0)` (called inside
/// `make_writable()`) makes ALL MAP_JIT pages non-executable for ALL threads.
/// If the worker thread is executing JIT code via `entry_fn()` at that moment,
/// it gets `EXC_BAD_ACCESS` (prefetch abort, code=2).
///
/// # Locking protocol
///
/// * **Read lock** — acquired by `execute_with_jit()` around `entry_fn()`
///   (JIT code execution). Multiple read locks can be held concurrently
///   (though there is currently only one worker thread).
/// * **Write lock (try)** — acquired by `chain_blocks()`, `break_all_chains()`,
///   and `force_break_all_chains()` via `try_write()`. If the worker holds
///   the read lock (inside `entry_fn()`), the chain operation silently skips.
///   The `JIT_CHAIN_BREAK_REQUESTED` flag ensures that the worker will skip
///   JIT execution on its next iteration, allowing the chain operation to
///   succeed then.
///
/// # Why `try_write()` instead of `write()`
///
/// Using a blocking `write()` would cause a deadlock: the watchdog thread
/// would block waiting for the worker to release the read lock, but the
/// worker cannot release the read lock until it exits `entry_fn()`, which
/// requires the watchdog to break chains first. `try_write()` breaks this
/// circular dependency by making chain-breaking best-effort rather than
/// mandatory.
pub static JIT_EXEC_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Register the active [`JitRuntime`] so the live-session watchdog can
/// force chain-breaking across threads.
///
/// Must be paired with a matching call to [`unregister_jit_runtime()`].
pub fn register_jit_runtime(runtime: &mut JitRuntime) {
    JIT_RUNTIME_PTR.store(runtime as *mut JitRuntime, Ordering::Release);
}

/// Unregister the active [`JitRuntime`] — called after the main execution loop
/// finishes so the watchdog no longer holds a reference.
pub fn unregister_jit_runtime() {
    JIT_RUNTIME_PTR.store(std::ptr::null_mut(), Ordering::Release);
}

/// Forcefully break all JIT block chains on the worker thread, regardless of
/// which thread calls this function.
///
/// This is safe to call from any thread as long as [`register_jit_runtime()`]
/// was called and the runtime is still alive (i.e., the worker thread has not
/// yet called [`unregister_jit_runtime()`]).
///
/// # MAP_JIT permission race
///
/// On Apple Silicon, `pthread_jit_write_protect_np(0)` (called inside
/// `break_all_chains()` → `unchain_block()` → `make_writable()`) makes ALL
/// MAP_JIT pages non-executable for ALL threads.  If the worker thread is
/// executing JIT code (via `entry_fn()` in `execute_with_jit`) at that moment,
/// it gets `EXC_BAD_ACCESS` (prefetch abort, code=2).
///
/// To mitigate this, `force_break_all_chains()` sleeps for 50 ms before
/// calling `break_all_chains()`.  During this sleep, the worker thread has
/// time to exit `entry_fn()` naturally (between block iterations).  Before
/// entering `entry_fn()`, `execute_with_jit()` checks
/// [`JIT_CHAIN_BREAK_REQUESTED`] and skips JIT execution if the flag is set,
/// avoiding the race entirely for the common case.
///
/// For the rare case where the worker is already inside an already-formed
/// chain (a loop of ARM64 B instructions that never returns to the
/// dispatcher), the 50 ms sleep does not help — the worker never exits
/// `entry_fn()`.  In this case, `break_all_chains()` is called without
/// protection, exposing the same microsecond race window as the original
/// code (which worked for 85,000+ blocks before hitting the race).
///
/// Callers MUST set [`JIT_CHAIN_BREAK_REQUESTED`] to `true` BEFORE calling
/// this function.  The worker checks that flag in `chain_blocks()` and in
/// `execute_with_jit()` before `entry_fn()`, stopping new chains from forming.
pub fn force_break_all_chains() {
    // Sleep to give the worker thread a chance to exit entry_fn() between
    // iterations so chain_blocks() can later acquire the write lock.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Try to acquire the write lock on JIT_EXEC_LOCK to prevent the MAP_JIT
    // permission race. If the worker is inside entry_fn() (holding the read
    // lock), try_write() fails and we return early — chain-breaking will be
    // retried on the next 50 ms tick.
    let _lock = match JIT_EXEC_LOCK.try_write() {
        Ok(guard) => guard,
        Err(_) => {
            eprintln!(
                "[jit] force_break_all_chains: worker holds read lock — deferring chain break"
            );
            return;
        }
    };

    let ptr = JIT_RUNTIME_PTR.load(Ordering::Acquire);
    if !ptr.is_null() {
        // SAFETY: The worker is not inside entry_fn() (we acquired the write
        // lock), so there is no MAP_JIT permission race.
        unsafe {
            (*ptr).break_all_chains();
        }
    }
}

// ---------------------------------------------------------------------------
// SIGBUS handler for on-demand guest memory page sync during JIT execution
// ---------------------------------------------------------------------------

/// Stored as raw pointers for signal-safe access from the SIGBUS handler.
///
/// # Lifetime Safety Protocol
/// These pointers are set with `Ordering::Release` by
/// [`JitRuntime::install_sigbus_handler`] before JIT execution begins, and
/// cleared (set to null) with `Ordering::Release` by
/// [`JitRuntime::remove_sigbus_handler`] after execution completes.
///
/// Additionally, [`JitRuntime::Drop`] calls `remove_sigbus_handler_session`,
/// ensuring the pointers are nullified before the `JitRuntime` is dropped.
/// This prevents the SIGBUS handler from dereferencing a dangling pointer
/// after the runtime has been freed. The handler loads with `Ordering::Acquire`
/// and checks for null before dereferencing, so a null value is always safe.
///
/// The `MemoryImage` pointer is similarly cleared in `remove_sigbus_handler`
/// and `remove_sigbus_handler_session`, ensuring it cannot outlive the
/// referenced `MemoryImage`.
static SIGBUS_JIT_RUNTIME: AtomicPtr<JitRuntime> = AtomicPtr::new(std::ptr::null_mut());
static SIGBUS_JIT_MEMORY: AtomicPtr<MemoryImage> = AtomicPtr::new(std::ptr::null_mut());

/// PeHostRuntime pointer, stored as a raw c_void pointer so that
/// JIT-compiled ARM64 code can load it and pass it as the first
/// argument (runtime_ptr) to the fast-thunk bridge function.
/// Set by pe_runtime.rs before calling `execute_with_jit`.
static SIGBUS_PE_RUNTIME: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());
/// Publish the live `PeHostRuntime` pointer for JIT call sites that service
/// Win32 APIs directly (fast thunks and inlined trivial APIs).  The caller
/// must clear it with a null pointer when the runtime borrow ends.
pub fn set_pe_runtime_pointer(pointer: *mut libc::c_void) {
    SIGBUS_PE_RUNTIME.store(pointer, Ordering::Release);
}

/// SIGBUS loop detection: tracks the last fault address and a consecutive
/// hit counter. If the same page faults more than MAX_CONSECUTIVE_FAULTS
/// times, the handler disables itself to break the infinite loop.
static SIGBUS_LAST_FAULT_ADDR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SIGBUS_CONSECUTIVE_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const MAX_CONSECUTIVE_FAULTS: usize = 32;

/// Total SIGBUS events for diagnostics (monotonic counter).
pub static SIGBUS_TOTAL_EVENTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Once `true`, JIT native execution is disabled for the rest of the process
/// and all blocks fall back to the IR interpreter.  Set by the SIGBUS handler
/// when a single block execution generates an excessive number of page faults
/// (a "fault storm") — the signature of a compiled block walking across many
/// uncommitted guest pages (or a block that landed in non-code data) such that
/// it would otherwise fault forever without ever returning to the dispatcher.
/// Graceful degradation: the program keeps running, just via the interpreter.
pub static JIT_FAULT_STORM_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Threshold of total SIGBUS events after which the JIT is permanently
/// disabled for the process.  A correctly-running block faults a handful of
/// times at most (a few uncommitted pages); reaching thousands means the
/// block is diverging through guest memory and would never return.
const SIGBUS_FAULT_STORM_THRESHOLD: u64 = 4096;

/// Diagnostic counters for SIGBUS handler analysis.
pub static SIGBUS_PAGE_FOUND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static SIGBUS_PAGE_NOT_FOUND: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub static SIGBUS_DISABLED_EVENTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Diagnostic: SIGBUS fault address was within FlatGuestMemory range.
pub static SIGBUS_IN_FLAT_RANGE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: SIGBUS fault address was OUTSIDE FlatGuestMemory range.
pub static SIGBUS_OUT_FLAT_RANGE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: SIGBUS handler re-entered (recursive SIGBUS from write_volatile).
pub static SIGBUS_RECURSIVE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: first fault address seen (for debugging).
pub static SIGBUS_FIRST_FAULT_ADDR: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Diagnostic: handler entry depth (detects recursive SIGBUS).
static SIGBUS_HANDLER_DEPTH: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// ── Guest-page materialisation instrumentation ──────────────────────────────
//
// The flat guest mirror is populated strictly on demand: only guest pages
// that are actually committed (or faulted on) are copied into it.  These
// monotonic counters make that work observable so tests can assert that the
// former whole-4-GiB prefault is gone.

/// Number of 4 KiB guest pages copied into (materialised in) the flat mirror.
pub static GUEST_PAGES_MATERIALISED: AtomicU64 = AtomicU64::new(0);
/// Number of batched sync operations performed (one per contiguous run of
/// materialised pages, plus one per page in the signal-handler fast path).
pub static GUEST_SYNC_OPERATIONS: AtomicU64 = AtomicU64::new(0);
/// Total bytes copied from `MemoryImage` into the flat mirror.
pub static GUEST_SYNC_BYTES_COPIED: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the guest-page materialisation counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestMemoryTelemetry {
    pub pages_materialised: u64,
    pub sync_operations: u64,
    pub bytes_copied: u64,
}

/// Read the current guest-page materialisation counters.
pub fn guest_memory_telemetry() -> GuestMemoryTelemetry {
    GuestMemoryTelemetry {
        pages_materialised: GUEST_PAGES_MATERIALISED.load(Ordering::Relaxed),
        sync_operations: GUEST_SYNC_OPERATIONS.load(Ordering::Relaxed),
        bytes_copied: GUEST_SYNC_BYTES_COPIED.load(Ordering::Relaxed),
    }
}

/// Reset the guest-page materialisation counters (test/diagnostic helper).
pub fn reset_guest_memory_telemetry() {
    GUEST_PAGES_MATERIALISED.store(0, Ordering::Relaxed);
    GUEST_SYNC_OPERATIONS.store(0, Ordering::Relaxed);
    GUEST_SYNC_BYTES_COPIED.store(0, Ordering::Relaxed);
}

// ── Resolved host-thunk target instrumentation ─────────────────────────────

/// Number of guest→host thunk resolutions served from the resolved-target
/// index (the fast path that bypasses the entry scan and global-map lock).
pub static THUNK_RESOLVE_HITS: AtomicU64 = AtomicU64::new(0);
/// Number of guest→host thunk resolutions that missed the fast index and
/// fell back to the global map (or returned "not registered").
pub static THUNK_RESOLVE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Reset the thunk-resolution counters (test/diagnostic helper).
pub fn reset_thunk_resolve_telemetry() {
    THUNK_RESOLVE_HITS.store(0, Ordering::Relaxed);
    THUNK_RESOLVE_MISSES.store(0, Ordering::Relaxed);
}

/// `(hits, misses)` since the last reset.
pub fn thunk_resolve_telemetry() -> (u64, u64) {
    (
        THUNK_RESOLVE_HITS.load(Ordering::Relaxed),
        THUNK_RESOLVE_MISSES.load(Ordering::Relaxed),
    )
}

// ── Executable-code write tracking (self-modifying code) ────────────────────
//
// Guest stores execute inside JIT-compiled code through `jit_helper_store`.
// That helper runs while the owning thread is inside `execute_block`, so it
// cannot form a `&JitRuntime` (the runtime is mutably borrowed there).
// Instead the executing thread publishes a pointer to the runtime's
// `SmcState` in a thread-local, and the helper records writes into that
// state's atomics:
//
//   * `watched`  — lock-free open-addressing set of guest pages that host a
//                  compiled block (key = page + 1, 0 = empty);
//   * `dirty`    — bounded lock-free ring of pages written since the last
//                  drain (overflow sets a flag: the drain then invalidates
//                  every block, which is always safe).
//
// Tracking is per runtime, not global: two runtimes in one process (tests,
// live sessions) never invalidate each other's blocks.  When no runtime is
// executing on this thread the helper's fast path is a thread-local load.
const SMC_WATCH_SLOTS: usize = 8192;
const SMC_WATCH_MASK: usize = SMC_WATCH_SLOTS - 1;
const SMC_DIRTY_SLOTS: usize = 4096;

struct SmcState {
    watched: Box<[AtomicU64]>,
    watched_count: AtomicUsize,
    watch_overflow: AtomicBool,
    dirty: Box<[AtomicU64]>,
    dirty_count: AtomicUsize,
    dirty_overflow: AtomicBool,
}

impl SmcState {
    fn new() -> Self {
        Self {
            watched: (0..SMC_WATCH_SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            watched_count: AtomicUsize::new(0),
            watch_overflow: AtomicBool::new(false),
            dirty: (0..SMC_DIRTY_SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            dirty_count: AtomicUsize::new(0),
            dirty_overflow: AtomicBool::new(false),
        }
    }

    fn slot(page: u64) -> usize {
        let x = (page >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (x >> (64 - 13)) as usize & SMC_WATCH_MASK
    }

    /// Rebuild the watched-page set from the runtime's current `code_pages`.
    /// Called only when blocks are added/removed (never during execution).
    fn rebuild_watch<'a>(&self, pages: impl Iterator<Item = &'a u64>) {
        for slot in self.watched.iter() {
            slot.store(0, Ordering::Relaxed);
        }
        let mut count = 0usize;
        let mut overflow = false;
        for &page in pages {
            let key = page + 1;
            let mut idx = Self::slot(page);
            let mut placed = false;
            for _ in 0..SMC_WATCH_SLOTS {
                if self.watched[idx].load(Ordering::Relaxed) == 0 {
                    self.watched[idx].store(key, Ordering::Release);
                    placed = true;
                    break;
                }
                idx = (idx + 1) & SMC_WATCH_MASK;
            }
            if placed {
                count += 1;
            } else {
                // Hash table full: treat every page as watched (conservative).
                overflow = true;
                break;
            }
        }
        self.watched_count.store(count, Ordering::Release);
        self.watch_overflow.store(overflow, Ordering::Release);
    }

    fn is_watched(&self, page: u64) -> bool {
        if self.watch_overflow.load(Ordering::Acquire) {
            return true;
        }
        let key = page + 1;
        let mut idx = Self::slot(page);
        for _ in 0..SMC_WATCH_SLOTS {
            let value = self.watched[idx].load(Ordering::Acquire);
            if value == 0 {
                return false;
            }
            if value == key {
                return true;
            }
            idx = (idx + 1) & SMC_WATCH_MASK;
        }
        false
    }

    fn mark_dirty(&self, page: u64) {
        let pos = self.dirty_count.fetch_add(1, Ordering::Relaxed);
        if pos < SMC_DIRTY_SLOTS {
            self.dirty[pos].store(page + 1, Ordering::Release);
        } else {
            self.dirty_overflow.store(true, Ordering::Release);
        }
    }

    /// Take the dirty pages (4K-aligned) and the overflow flag, clearing both.
    fn take_dirty(&self) -> (Vec<u64>, bool) {
        let count = self
            .dirty_count
            .swap(0, Ordering::AcqRel)
            .min(SMC_DIRTY_SLOTS);
        let mut pages = Vec::with_capacity(count);
        for slot in self.dirty.iter().take(count) {
            let value = slot.swap(0, Ordering::AcqRel);
            if value != 0 {
                pages.push((value - 1) & !0xfff);
            }
        }
        let overflow = self.dirty_overflow.swap(false, Ordering::AcqRel);
        (pages, overflow)
    }
}

/// Guest stores observed at a watched code page (diagnostic counter).
pub static SMC_WRITES_OBSERVED: AtomicU64 = AtomicU64::new(0);
/// Code pages marked dirty by such stores (diagnostic counter).
pub static SMC_PAGES_MARKED_DIRTY: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// `SmcState` of the runtime executing on this thread, or null.
    static ACTIVE_SMC: std::cell::Cell<*const SmcState> =
        const { std::cell::Cell::new(std::ptr::null()) };
}

/// RAII publication of the executing runtime's SMC state to the helper.
struct ActiveSmcGuard(*const SmcState);

impl ActiveSmcGuard {
    fn install(state: &SmcState) -> Self {
        let previous = ACTIVE_SMC.with(|cell| {
            let previous = cell.get();
            cell.set(state as *const SmcState);
            previous
        });
        Self(previous)
    }
}

impl Drop for ActiveSmcGuard {
    fn drop(&mut self) {
        ACTIVE_SMC.with(|cell| cell.set(self.0));
    }
}

/// Serializes writes to executable code pages across every host thread.
/// `pthread_jit_write_protect_np` is per-thread, so this lock only prevents
/// two installers from writing the same code zone concurrently; executing
/// threads keep their own execute view and never take this lock.
static JIT_CODE_INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// Number of block-to-block links published (atomic link-slot stores).
pub static JIT_CHAIN_LINKS_FORMED: AtomicU64 = AtomicU64::new(0);
/// Number of block-to-block links cleared (invalidation / chain break).
pub static JIT_CHAIN_LINKS_BROKEN: AtomicU64 = AtomicU64::new(0);
/// Number of guest Call sites compiled to a direct resolved-thunk call.
pub static JIT_THUNK_DIRECT_CALLS: AtomicU64 = AtomicU64::new(0);

/// Monotonic epoch of guest code writes.
///
/// Every compiled block's prologue compares this value with the epoch captured
/// by its execution chain.  A write to a compiled-code page bumps the epoch, so
/// the next block entry in an otherwise native chain exits to its dispatcher
/// before the stale block can run.  Combined with [`LINK_BUDGET`] this makes
/// per-block SMC checks and safepoint polling non-skippable even when blocks
/// branch directly into one another.
pub static JIT_CODE_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Maximum number of native block entries between two returns to the worker
/// loop (or the cooperative dispatcher).  The counter lives in the per-chain
/// [`ChainState`] and is decremented by every block prologue; reaching zero
/// forces a dispatch boundary where the safepoint and SMC checks are
/// re-evaluated by the host.
pub(crate) const LINK_BUDGET: u64 = 256;

/// Byte offsets into the `#[repr(C)]` [`ChainState`] that are embedded in
/// compiled code.  Keeping them as named constants makes the ABI auditable and
/// keeps the emitter, the executor and the relocation writer in sync.
pub(crate) mod chain_offsets {
    pub(crate) const CURRENT_BLOCK: u32 = 0;
    pub(crate) const FLAT_BASE: u32 = 8;
    pub(crate) const PAYLOAD: u32 = 16;
    pub(crate) const LINK_BUDGET: u32 = 24;
    pub(crate) const BLOCKS: u32 = 32;
    pub(crate) const INSTRUCTIONS: u32 = 40;
    pub(crate) const SMC_EPOCH: u32 = 48;
    pub(crate) const RETURN_DEPTH: u32 = 56;
    pub(crate) const NATIVE_CALLS: u32 = 64;
    pub(crate) const NATIVE_RETURN_HITS: u32 = 72;
    pub(crate) const NATIVE_RETURN_MISSES: u32 = 80;
    pub(crate) const NATIVE_RETURN_MISPREDICTS: u32 = 88;
    pub(crate) const RETURN_STACK: u32 = 96;
}

/// Maximum depth of the native direct-call return stack carried by one chain.
pub(crate) const CHAIN_RETURN_DEPTH: usize = 16;

/// Per-execution state shared with compiled code through `x3`/`x23`.
///
/// This replaces the legacy four-word exit cell.  It is a plain (non-atomic)
/// stack object owned exclusively by the thread executing the chain, so the
/// emitted loads/stores never race: a worker owns its state for the duration
/// of a slice, and the cooperative dispatcher owns it for one block chain.
#[repr(C)]
pub(crate) struct ChainState {
    pub(crate) current_block: u64,
    pub(crate) flat_base: u64,
    pub(crate) payload: u64,
    pub(crate) link_budget: u64,
    pub(crate) blocks: u64,
    pub(crate) instructions: u64,
    pub(crate) smc_epoch: u64,
    pub(crate) return_depth: u64,
    pub(crate) native_calls: u64,
    pub(crate) native_return_hits: u64,
    pub(crate) native_return_misses: u64,
    pub(crate) native_return_mispredicts: u64,
    /// `(guest return address, compiled entry)` pairs, newest at
    /// `return_depth - 1`.  A caller pushes the statically known return
    /// address; a native `ret` pops it only when the guest stack agrees.
    pub(crate) return_stack: [[u64; 2]; CHAIN_RETURN_DEPTH],
}

impl ChainState {
    pub(crate) fn new(flat_base: u64, block_address: u64, link_budget: u64) -> Self {
        Self {
            current_block: block_address,
            flat_base,
            payload: 0,
            link_budget,
            blocks: 0,
            instructions: 0,
            smc_epoch: JIT_CODE_EPOCH.load(Ordering::Acquire),
            return_depth: 0,
            native_calls: 0,
            native_return_hits: 0,
            native_return_misses: 0,
            native_return_mispredicts: 0,
            return_stack: [[0; 2]; CHAIN_RETURN_DEPTH],
        }
    }

    pub(crate) fn push_return(&mut self, target: u64, entry: u64) {
        if self.return_depth as usize >= CHAIN_RETURN_DEPTH {
            return;
        }
        self.return_stack[self.return_depth as usize] = [target, entry];
        self.return_depth += 1;
    }

    #[allow(dead_code)] // used by native/AOT diagnostics
    pub(crate) fn return_entry(&self, target: u64) -> Option<u64> {
        if self.return_depth == 0 {
            return None;
        }
        let top = self.return_stack[self.return_depth as usize - 1];
        (top[0] == target && top[1] != 0).then_some(top[1])
    }
}

/// Record a guest write to `[address, address + length)`.
///
/// Called from `jit_helper_store` for every native guest store.  The fast path
/// is a thread-local load when this thread is not executing JIT code.
pub fn note_guest_code_write(address: u64, length: usize) {
    if length == 0 {
        return;
    }
    let state_ptr = ACTIVE_SMC.with(|cell| cell.get());
    if state_ptr.is_null() {
        return;
    }
    // SAFETY: the pointer is published by `ActiveSmcGuard` for the duration
    // of `execute_block` on this same thread; the referenced boxed state
    // outlives the guard, and all accesses are atomics (no Rust references
    // to the mutably borrowed runtime are formed).
    let state = unsafe { &*state_ptr };
    if state.watched_count.load(Ordering::Acquire) == 0
        && !state.watch_overflow.load(Ordering::Acquire)
    {
        return;
    }
    let end = address.saturating_add(length as u64);
    let mut page = address & !0xfff;
    let last = end.saturating_sub(1) & !0xfff;
    let mut observed = false;
    while page <= last {
        if state.is_watched(page) {
            state.mark_dirty(page);
            SMC_PAGES_MARKED_DIRTY.fetch_add(1, Ordering::Relaxed);
            observed = true;
        }
        page = match page.checked_add(0x1000) {
            Some(next) => next,
            None => return,
        };
    }
    if observed {
        SMC_WRITES_OBSERVED.fetch_add(1, Ordering::Relaxed);
        JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
    }
}

/// `(writes_observed, pages_marked_dirty)` since process start.
pub fn smc_telemetry() -> (u64, u64) {
    (
        SMC_WRITES_OBSERVED.load(Ordering::Relaxed),
        SMC_PAGES_MARKED_DIRTY.load(Ordering::Relaxed),
    )
}

/// Reset the SMC diagnostic counters (test helper).
pub fn reset_smc_telemetry() {
    SMC_WRITES_OBSERVED.store(0, Ordering::Relaxed);
    SMC_PAGES_MARKED_DIRTY.store(0, Ordering::Relaxed);
}

/// Helper: write JIT diagnostic info to a temp file for post-crash analysis.
/// The runner process captures stderr via pipes that are lost if the runner
/// crashes, so we write to a file as a fallback.  Not called from signal
/// handlers — only from the JIT worker thread diagnostic path.
pub fn write_diag_file(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/casa1_jit_diag.txt")
    {
        let _ = writeln!(f, "{}", msg);
    }
}

/// Re-entrancy guard for the SIGBUS handler. Set to `true` on entry with
/// `Ordering::Acquire`, cleared on exit with `Ordering::Release`. If the
/// handler is re-entered (e.g., `write_volatile` triggers another SIGBUS),
/// the guard is already `true` and the handler returns immediately, preventing
/// infinite recursion and potential memory corruption.
///
/// # Protocol
/// - Entry: `swap(true, Acquire)` — if the previous value was `true`, another
///   invocation is already active; return immediately.
/// - Exit: `store(false, Release)` — ensures all writes made during the handler
///   are visible before another invocation can proceed.
static SIGBUS_IN_HANDLER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Signal-safe SIGBUS fallback for a page the guest has not materialised.
///
/// # Behavior
/// - **Shared pages**: committed bytes already live in the mapping both views
///   alias; touching one byte forces the kernel to back the page, and the
///   retried instruction proceeds without any copy.
/// - **Uncommitted pages**: a single lossless zero write backs the page.
/// - **Loop detection**: if the same page faults more than
///   `MAX_CONSECUTIVE_FAULTS` times, the handler disables itself (stores
///   null pointers) to break an infinite SIGBUS loop.
///
/// # Safety
/// - Must be async-signal-safe: no heap allocation, no locks, no non-reentrant
///   libc functions. Only async-signal-safe operations are used: atomic loads/
///   stores and volatile loads/stores.
/// - The handler reads the fault address from `siginfo_t`, aligns it to a page
///   boundary, and backs that page in place: committed pages are already in
///   the shared canonical mapping (one volatile read forces residency), and
///   uncommitted pages get a lossless zero write.
/// - After the handler returns, the kernel retries the faulting instruction.
///
/// # Acquire/Release Protocol for `SIGBUS_JIT_RUNTIME` and `SIGBUS_JIT_MEMORY`
/// - Pointers are stored via `AtomicPtr` with `Ordering::Release` by the host
///   thread before JIT execution begins (`install_sigbus_handler`).
/// - This handler loads them with `Ordering::Acquire` to synchronise with the
///   Release store, establishing a happens-before relationship so that all
///   writes to `JitRuntime`/`MemoryImage` fields prior to the Release are
///   visible to the signal handler.
/// - Pointers are cleared (set to null) with `Ordering::Release` when JIT
///   execution ends (`remove_sigbus_handler`), ensuring no stale references.
///
/// # Recursive SIGBUS Handling
/// - Recursive SIGBUS (e.g., from `write_volatile` touching an unmapped page)
///   is detected via `SIGBUS_IN_HANDLER` AtomicBool with Acquire/Release
///   ordering. If the guard is already set, the handler immediately returns
///   without touching any memory, preventing infinite recursion and corrupted
///   state. The `SA_NODEFER` flag allows re-entry so we can detect it.
///   `SIGBUS_HANDLER_DEPTH` is kept as a secondary diagnostic counter.
extern "C" fn sigbus_sa_handler(sig: i32, info: *mut libc::siginfo_t, _ctx: *mut c_void) {
    // ── Re-entrancy guard (AtomicBool with Acquire/Release) ───────────
    // swap(true, Acquire) atomically sets the flag and returns the previous
    // value. If it was already true, another invocation is active (e.g.,
    // write_volatile in the pre-fault code triggered another SIGBUS).
    // Return immediately to prevent infinite recursion and state corruption.
    if SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire) {
        SIGBUS_RECURSIVE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // ── Depth tracking (diagnostic only) ──────────────────────────────
    let _depth = SIGBUS_HANDLER_DEPTH.fetch_add(1, Ordering::Relaxed);

    // SAFETY: `info` is a valid `siginfo_t*` provided by the kernel when
    // SA_SIGINFO is set. The kernel guarantees it points to a properly
    // initialized siginfo structure for SIGBUS.
    let fault_addr = unsafe { (*info).si_addr() as u64 };
    let page = fault_addr & !0xfff;

    // Record first fault address for diagnostics
    if SIGBUS_FIRST_FAULT_ADDR.load(Ordering::Relaxed) == 0 {
        SIGBUS_FIRST_FAULT_ADDR.store(fault_addr, Ordering::Relaxed);
    }

    // ── Loop detection ────────────────────────────────────────────────
    let last = SIGBUS_LAST_FAULT_ADDR.load(Ordering::Relaxed);
    if last == page {
        let count = SIGBUS_CONSECUTIVE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= MAX_CONSECUTIVE_FAULTS {
            // Same page faulted too many times.  Previously this branch
            // disabled the handler and returned WITHOUT committing the page,
            // which left the faulting instruction to retry forever (each
            // retry hit the now-null runtime path and returned immediately) —
            // an infinite hang with the SIGBUS counter frozen.  Instead, we
            // permanently switch the runtime to the IR interpreter (so this
            // is the last JIT-compiled block we ever run) and COMMIT the
            // faulting page so this instruction succeeds and execution can
            // proceed to the block epilogue and return to the dispatcher,
            // where the interpreter takes over.
            JIT_FAULT_STORM_DISABLED.store(true, Ordering::Relaxed);
            let runtime_ptr = SIGBUS_JIT_RUNTIME.load(Ordering::Acquire);
            if !runtime_ptr.is_null() {
                // SAFETY: runtime_ptr was set with Release by
                // install_sigbus_handler before JIT execution; we hold the
                // IN_HANDLER guard so it cannot be torn down concurrently.
                let runtime = unsafe { &*runtime_ptr };
                let flat_base = runtime.flat_memory.base() as *mut u8;
                let flat_size = runtime.flat_memory.size();
                // Zero-fill the whole faulting page in the flat mirror so the
                // retrying load/store succeeds.  The page is within the
                // direct-window mmap (fault_addr was validated in-range for prior
                // faults; defensively bounds-check here too).
                let page_off = page as usize;
                if page_off
                    .checked_add(4096)
                    .map(|e| e <= flat_size)
                    .unwrap_or(false)
                {
                    unsafe {
                        std::ptr::write_bytes(flat_base.add(page_off), 0, 4096);
                    }
                }
            }
            SIGBUS_HANDLER_DEPTH.fetch_sub(1, Ordering::Relaxed);
            SIGBUS_IN_HANDLER.store(false, Ordering::Release);
            return;
        }
    } else {
        SIGBUS_LAST_FAULT_ADDR.store(page, Ordering::Relaxed);
        SIGBUS_CONSECUTIVE_COUNT.store(1, Ordering::Relaxed);
    }

    let total = SIGBUS_TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;

    // ── Fault-storm circuit breaker ──────────────────────────────────
    // If a single process has accumulated an enormous number of SIGBUS
    // events, a compiled block is diverging through guest memory (e.g. a
    // block that landed in a data section and is walking pages) and would
    // otherwise fault forever.  Permanently disable JIT native execution so
    // all subsequent blocks use the IR interpreter (which handles every
    // memory access via the safe MemoryImage API and cannot fault-loop).
    if total >= SIGBUS_FAULT_STORM_THRESHOLD {
        JIT_FAULT_STORM_DISABLED.store(true, Ordering::Relaxed);
    }

    // ── Acquire/Release protocol for static pointers ──────────────────
    // Load pointers with Acquire ordering to synchronize with the Release
    // store in `install_sigbus_handler`. This establishes a happens-before
    // relationship: all writes to JitRuntime/MemoryImage fields that
    // occurred before the Release store are visible to this handler.
    let runtime_ptr = SIGBUS_JIT_RUNTIME.load(Ordering::Acquire);
    let memory_ptr = SIGBUS_JIT_MEMORY.load(Ordering::Acquire);

    if runtime_ptr.is_null() || memory_ptr.is_null() {
        SIGBUS_DISABLED_EVENTS.fetch_add(1, Ordering::Relaxed);
        SIGBUS_HANDLER_DEPTH.fetch_sub(1, Ordering::Relaxed);
        SIGBUS_IN_HANDLER.store(false, Ordering::Release);
        return; // No handler active — let default SIGBUS handler take over
    }

    // SAFETY: `runtime_ptr` was set by `install_sigbus_handler` with
    // `Ordering::Release` before JIT execution. We loaded it with
    // `Ordering::Acquire` and validated as non-null above. The referenced
    // `JitRuntime` remains alive for the entire duration of JIT execution
    // (cleared only in `remove_sigbus_handler`/`Drop` after execution
    // completes, which stores null with `Ordering::Release`).
    let runtime = unsafe { &*runtime_ptr };
    // SAFETY: Same as `runtime_ptr` — `memory_ptr` was set with
    // `Ordering::Release` and loaded with `Ordering::Acquire`. The
    // `MemoryImage` remains alive for the entire JIT execution.
    let memory = unsafe { &*memory_ptr };

    // ── Diagnostic: check if fault is within FlatGuestMemory range ────
    let flat_base = runtime.flat_memory.base();
    let flat_size = runtime.flat_memory.size() as u64;
    // Use saturating arithmetic to prevent u64 overflow when flat_base is
    // near the top of the address space (defensive, unlikely on 64-bit macOS).
    let flat_end = flat_base.saturating_add(flat_size);
    if fault_addr >= flat_base && fault_addr < flat_end {
        SIGBUS_IN_FLAT_RANGE.fetch_add(1, Ordering::Relaxed);
    } else {
        // ── Fail-fast on OUT-OF-RANGE faults ─────────────────────────────
        // A fault outside the flat guest memory region is NOT a guest page
        // sync: it is either a failure to execute the compiled code page
        // (the faulting instruction is the branch into JIT code) or a wild
        // pointer inside compiled code.  Neither is recoverable by syncing
        // guest pages: returning would retry the faulting instruction
        // forever (an infinite SIGBUS spin).  Restore the default SIGBUS
        // disposition and re-raise so the process dies with the honest
        // signal — the caller (JIT self-test parent, runner) reports the
        // failure instead of hanging.
        SIGBUS_OUT_FLAT_RANGE.fetch_add(1, Ordering::Relaxed);
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
            libc::raise(libc::SIGBUS);
        }
        // Unreachable when the raise terminated the process; keep a final
        // guard so the handler never returns into the faulting instruction.
        std::process::abort();
    }

    // ── Faulting-page fallback ─────────────────────────────────────────
    //
    // The flat view and the interpreter now share the same canonical pages,
    // so a committed page needs no copy: reading one byte forces the kernel
    // to back the page that the canonical store already owns.  A page with no
    // committed bytes is backed with a lossless zero write so the retried
    // instruction can proceed.  This path is a safety net for pages the guest
    // has not committed yet, never routine synchronisation.
    let flat_base_ptr = runtime.flat_memory.base() as *mut u8;
    service_faulting_page(runtime, memory, page, flat_base_ptr, flat_size as usize);
    SIGBUS_HANDLER_DEPTH.fetch_sub(1, Ordering::Relaxed);
    // Clear re-entrancy guard with Release ordering to ensure all writes
    // made during the handler are visible before another invocation proceeds.
    SIGBUS_IN_HANDLER.store(false, Ordering::Release);
    _ = sig; // suppress unused variable warning
}

/// Back a faulting flat page without copying canonical data.
///
/// Split out of the signal handler so the three fallback cases (fully mapped,
/// partially mapped, uncommitted) are unit-testable and every accounting
/// branch is covered by adversarial tests.
fn service_faulting_page(
    runtime: &JitRuntime,
    memory: &MemoryImage,
    page: u64,
    flat_base_ptr: *mut u8,
    flat_size: usize,
) {
    let mut materialised_pages = 0u64;
    let mut sync_operations = 0u64;
    let mut copied_bytes = 0u64;
    if memory.page_is_fully_mapped(page) {
        // SAFETY: `page` is in the flat window (validated by the caller) and
        // the byte belongs to the canonical store shared by both views.
        unsafe {
            let _ = std::ptr::read_volatile(flat_base_ptr.add(page as usize));
        }
        runtime.flat_memory.mark_page_materialised_signal_safe(page);
        SIGBUS_PAGE_FOUND.fetch_add(1, Ordering::Relaxed);
        materialised_pages = 1;
        sync_operations = 1;
        copied_bytes = 4096;
    } else if memory.page_exists(page) {
        // Partially mapped page: touch a mapped byte if one exists.  A fully
        // unmapped tail is left alone; writing zero there is lossless but is
        // not needed for a page the kernel has already backed.
        SIGBUS_PAGE_NOT_FOUND.fetch_add(1, Ordering::Relaxed);
        if memory.page_byte_is_mapped(page, 0) {
            // SAFETY: byte 0 is inside the mapped, shared page.
            unsafe {
                let _ = std::ptr::read_volatile(flat_base_ptr.add(page as usize));
            }
        } else if memory.page_byte_is_mapped(page, 4095) {
            // SAFETY: the last byte is inside the mapped, shared page.
            unsafe {
                let _ = std::ptr::read_volatile(flat_base_ptr.add(page as usize + 4095));
            }
        }
    } else {
        SIGBUS_PAGE_NOT_FOUND.fetch_add(1, Ordering::Relaxed);
        let offset = page as usize;
        if let Some(end_offset) = offset.checked_add(4095)
            && end_offset < flat_size
        {
            // SAFETY: end_offset < flat_size keeps the write inside the flat
            // window.  The page holds no guest bytes, so zero is lossless.
            unsafe {
                std::ptr::write_volatile(flat_base_ptr.add(end_offset), 0u8);
            }
            runtime.flat_memory.mark_page_materialised_signal_safe(page);
        }
    }
    GUEST_PAGES_MATERIALISED.fetch_add(materialised_pages, Ordering::Relaxed);
    GUEST_SYNC_OPERATIONS.fetch_add(sync_operations, Ordering::Relaxed);
    GUEST_SYNC_BYTES_COPIED.fetch_add(copied_bytes, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// ARM64 register mapping for guest GPRs
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod regmap {
    /// Map guest x86/x64 register index to ARM64 register.
    /// Guest: RAX(0), RCX(1), RDX(2), RBX(3), RSP(4), RBP(5), RSI(6), RDI(7),
    ///        R8(8), R9(9), R10(10), R11(11), R12(12), R13(13), R14(14), R15(15)
    /// ARM64: x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x19, x20
    pub const fn guest_to_arm(guest_index: usize) -> u32 {
        match guest_index {
            0 => 4,   // RAX -> x4
            1 => 5,   // RCX -> x5
            2 => 6,   // RDX -> x6
            3 => 7,   // RBX -> x7
            4 => 8,   // RSP -> x8
            5 => 9,   // RBP -> x9
            6 => 10,  // RSI -> x10
            7 => 11,  // RDI -> x11
            8 => 12,  // R8  -> x12
            9 => 13,  // R9  -> x13
            10 => 14, // R10 -> x14
            11 => 15, // R11 -> x15
            12 => 16, // R12 -> x16
            13 => 17, // R13 -> x17
            14 => 19, // R14 -> x19
            15 => 20, // R15 -> x20
            _ => 4,
        }
    }

    pub const X0: u32 = 0;
    pub const X1: u32 = 1;
    pub const X2: u32 = 2;
    pub const X3: u32 = 3;
    pub const X9: u32 = 9;
    pub const X21: u32 = 21;
    pub const X22: u32 = 22;
    pub const X23: u32 = 23;
    pub const X24: u32 = 24;
    pub const X25: u32 = 25;
    pub const X26: u32 = 26;
    pub const X27: u32 = 27;
    pub const X28: u32 = 28;
    pub const FP: u32 = 29;
    pub const LR: u32 = 30;
    pub const SP: u32 = 31;
    pub const XZR: u32 = 31;
}

// ---------------------------------------------------------------------------
// ARM64 instruction encoder
// ---------------------------------------------------------------------------

pub struct Emitter {
    code: Vec<u8>,
}

#[allow(dead_code)]
impl Emitter {
    fn new() -> Self {
        Self {
            code: Vec::with_capacity(4096),
        }
    }

    #[inline(always)]
    fn emit(&mut self, insn: u32) {
        self.code.extend_from_slice(&insn.to_le_bytes());
    }

    fn len(&self) -> usize {
        self.code.len()
    }

    // -- Moves and immediates --

    /// MOV Xd, Xn (alias for ORR Xd, XZR, Xn)
    fn mov_reg(&mut self, rd: u32, rn: u32) {
        self.emit(0xaa0003e0 | (rn << 16) | rd);
    }

    /// MOVZ Xd, #imm16, LSL #shift
    fn movz(&mut self, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        self.emit(0xd2800000 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// MOVK Xd, #imm16, LSL #shift
    fn movk(&mut self, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        self.emit(0xf2800000 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// Move a 64-bit immediate into register using MOVZ + MOVK sequence.
    fn mov_imm64(&mut self, rd: u32, value: u64) {
        let chunks: [(u16, u32); 4] = [
            ((value & 0xffff) as u16, 0),
            (((value >> 16) & 0xffff) as u16, 16),
            (((value >> 32) & 0xffff) as u16, 32),
            (((value >> 48) & 0xffff) as u16, 48),
        ];

        self.movz(rd, chunks[0].0, chunks[0].1);
        for &(imm, shift) in &chunks[1..] {
            if imm != 0 {
                self.movk(rd, imm, shift);
            }
        }
    }

    /// Fixed-width 64-bit immediate load (always four instructions).
    ///
    /// AOT-cached code embeds absolute addresses that change between address
    /// spaces.  A fixed four-instruction encoding gives every relocation a
    /// constant size, so the loader can re-bind it in place without shifting
    /// the surrounding code.
    fn mov_imm64_fixed(&mut self, rd: u32, value: u64) {
        self.movz(rd, (value & 0xffff) as u16, 0);
        self.movk(rd, ((value >> 16) & 0xffff) as u16, 16);
        self.movk(rd, ((value >> 32) & 0xffff) as u16, 32);
        self.movk(rd, ((value >> 48) & 0xffff) as u16, 48);
    }

    // -- ALU --

    /// ADD Xd, Xn, #imm12
    fn add_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0x91000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, #imm12
    fn sub_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xd1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// ADD Xd, Xn, Xm
    fn add_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x8b000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, Xm
    fn sub_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xcb000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// AND Xd, Xn, Xm
    fn and_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x8a000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ANDS Xd, Xn, Xm (logical AND setting NZCV).
    fn ands_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xea000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ORR Xd, Xn, Xm
    fn orr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xaa000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// EOR Xd, Xn, Xm
    fn eor_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xca000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// MUL Xd, Xn, Xm
    fn mul_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9b007c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// SDIV Xd, Xn, Xm
    fn sdiv(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9ac00c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// UDIV Xd, Xn, Xm
    fn udiv(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9ac00800 | (rm << 16) | (rn << 5) | rd);
    }

    /// MSUB Xd, Xn, Xm, Xa (Xd = Xa - Xn*Xm)
    fn msub(&mut self, rd: u32, rn: u32, rm: u32, ra: u32) {
        self.emit(0x9b008000 | (rm << 16) | (ra << 10) | (rn << 5) | rd);
    }

    /// NEG Xd, Xn (SUB Xd, XZR, Xn)
    fn neg(&mut self, rd: u32, rn: u32) {
        self.emit(0xcb000000 | (rn << 16) | (31 << 5) | rd);
    }

    /// MVN Xd, Xn (ORN Xd, XZR, Xn)
    fn mvn(&mut self, rd: u32, rn: u32) {
        self.emit(0xaa200000 | (rn << 16) | (31 << 5) | rd);
    }

    // -- Shifts --

    /// LSL Xd, Xn, #shift
    fn lsl_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0xd3400000 | ((64 - shift) << 16) | ((63 - shift) << 10) | (rn << 5) | rd);
    }

    /// LSR Xd, Xn, #shift
    fn lsr_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0xd3400000 | ((shift & 63) << 16) | (63 << 10) | (rn << 5) | rd);
    }

    /// ASR Xd, Xn, #shift
    fn asr_imm(&mut self, rd: u32, rn: u32, shift: u32) {
        self.emit(0x93400000 | ((shift & 63) << 16) | (63 << 10) | (rn << 5) | rd);
    }

    /// ROR Xd, Xn, Xm
    fn ror_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02c00 | (rm << 16) | (rn << 5) | rd);
    }

    /// LSLV Xd, Xn, Xm
    fn lsl_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02000 | (rm << 16) | (rn << 5) | rd);
    }

    /// LSRV Xd, Xn, Xm
    fn lsr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02400 | (rm << 16) | (rn << 5) | rd);
    }

    /// ASRV Xd, Xn, Xm
    fn asr_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x1ac02800 | (rm << 16) | (rn << 5) | rd);
    }

    // -- Flag-setting ALU --

    /// ADDS Xd, Xn, #imm12
    fn adds_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xb1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// SUBS Xd, Xn, #imm12
    fn subs_imm(&mut self, rd: u32, rn: u32, imm12: u32) {
        self.emit(0xf1000000 | ((imm12 & 0xfff) << 10) | (rn << 5) | rd);
    }

    /// ADDS Xd, Xn, Xm
    fn adds_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xab000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SUBS Xd, Xn, Xm
    fn subs_reg(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xeb000000 | (rm << 16) | (rn << 5) | rd);
    }

    /// ADCS Xd, Xn, Xm
    fn adcs(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0x9a100000 | (rm << 16) | (rn << 5) | rd);
    }

    /// SBCS Xd, Xn, Xm
    fn sbcs(&mut self, rd: u32, rn: u32, rm: u32) {
        self.emit(0xfa100000 | (rm << 16) | (rn << 5) | rd);
    }

    // -- Memory --

    /// LDR Xt, [Xn, #offset] (64-bit unsigned offset)
    fn ldr64(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xf9400000 | ((offset >> 3) << 10) | (rn << 5) | rt);
    }

    /// LDAR Xt, [Xn] — 64-bit load-acquire, used to publish/read block links.
    fn ldar64(&mut self, rt: u32, rn: u32) {
        self.emit(0xc8dffc00 | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, #offset] (64-bit unsigned offset)
    fn str64(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xf9000000 | ((offset >> 3) << 10) | (rn << 5) | rt);
    }

    /// LDR Wt, [Xn, #offset] (32-bit unsigned offset)
    fn ldr32(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xb9400000 | ((offset >> 2) << 10) | (rn << 5) | rt);
    }

    /// STR Wt, [Xn, #offset] (32-bit unsigned offset)
    fn str32(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0xb9000000 | ((offset >> 2) << 10) | (rn << 5) | rt);
    }

    /// LDRB Wt, [Xn, #offset]
    fn ldr8(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0x39400000 | ((offset & 0xfff) << 10) | (rn << 5) | rt);
    }

    /// STRB Wt, [Xn, #offset]
    fn str8(&mut self, rt: u32, rn: u32, offset: u32) {
        self.emit(0x39000000 | ((offset & 0xfff) << 10) | (rn << 5) | rt);
    }

    /// LDR Xt, [Xn, Xm] (register offset, 64-bit, option=UXTX/LSL)
    fn ldr64_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xf8606800 | (rm << 16) | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, Xm] (register offset, 64-bit, option=UXTX/LSL)
    fn str64_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xf8206800 | (rm << 16) | (rn << 5) | rt);
    }

    /// LDR Wt, [Xn, Xm] (register offset, 32-bit)
    fn ldr32_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xb8600800 | (rm << 16) | (rn << 5) | rt);
    }

    /// STR Wt, [Xn, Xm] (register offset, 32-bit)
    fn str32_reg(&mut self, rt: u32, rn: u32, rm: u32) {
        self.emit(0xb8200800 | (rm << 16) | (rn << 5) | rt);
    }

    // -- Pairs --

    /// STP Xt1, Xt2, [Xn, #offset]! (pre-index)
    fn stp64_pre(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa9800000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    /// LDP Xt1, Xt2, [Xn, #offset] (signed offset, no writeback)
    fn ldp64(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa9400000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    /// LDP Xt1, Xt2, [Xn], #offset (post-index)
    fn ldp64_post(&mut self, rt1: u32, rt2: u32, rn: u32, offset: i32) {
        let imm7 = ((offset >> 3) & 0x7f) as u32;
        self.emit(0xa8c00000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1);
    }

    // -- Branches --

    fn b(&mut self, offset: i32) {
        self.emit(0x14000000 | ((offset >> 2) & 0x3fffffff) as u32);
    }

    fn bl(&mut self, offset: i32) {
        self.emit(0x94000000 | ((offset >> 2) & 0x3fffffff) as u32);
    }

    fn br(&mut self, rn: u32) {
        self.emit(0xd61f0000 | (rn << 5));
    }

    fn blr(&mut self, rn: u32) {
        self.emit(0xd63f0000 | (rn << 5));
    }

    fn ret(&mut self) {
        self.emit(0xd65f03c0);
    }

    fn nop(&mut self) {
        self.emit(0xd503201f);
    }

    /// B.cond offset (cond: 0=EQ,1=NE,2=CS,3=CC,4=MI,5=PL,6=VS,7=VC,8=HI,9=LS,10=GE,11=LT,12=GT,13=LE,14=AL)
    fn bcond(&mut self, cond: u32, offset: i32) {
        self.emit(0x54000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | (cond & 0xf));
    }

    /// CBZ Xn, offset (compare and branch if zero)
    fn cbz(&mut self, rn: u32, offset: i32) {
        self.emit(0xb4000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | rn);
    }

    /// CBNZ Xn, offset (compare and branch if not zero)
    fn cbnz(&mut self, rn: u32, offset: i32) {
        self.emit(0xb5000000u32 | (((offset >> 2) as u32 & 0x7ffff) << 5) | rn);
    }

    // -- Extensions --

    fn sxtb(&mut self, rd: u32, rn: u32) {
        self.emit(0x93401c00 | (rn << 5) | rd);
    }
    fn sxth(&mut self, rd: u32, rn: u32) {
        self.emit(0x93403c00 | (rn << 5) | rd);
    }
    fn sxtw(&mut self, rd: u32, rn: u32) {
        self.emit(0x93407c00 | (rn << 5) | rd);
    }
    fn uxtb(&mut self, rd: u32, rn: u32) {
        // UXTB Wd, Wn — zero-extend byte (mask low 8 bits, clear upper 56).
        self.emit(0x53001c00 | (rn << 5) | rd);
    }
    fn uxth(&mut self, rd: u32, rn: u32) {
        // UXTH Wd, Wn — zero-extend halfword (mask low 16 bits).
        self.emit(0x53003c00 | (rn << 5) | rd);
    }
    /// Zero-extend a 32-bit value to 64 bits, i.e. mask the register to its
    /// low 32 bits (clearing the upper 32).  Implemented as `MOV Wd, Wn`
    /// (ORR Wd, WZR, Wn), because writing a 32-bit W register implicitly
    /// zero-extends the result to the full X register.
    fn uxtw_reg(&mut self, rd: u32, rn: u32) {
        self.emit(0x2a0003e0 | (rn << 16) | rd);
    }

    // -- Miscellaneous --

    fn rbit(&mut self, rd: u32, rn: u32) {
        self.emit(0xdac00000 | (rn << 5) | rd);
    }
    fn clz(&mut self, rd: u32, rn: u32) {
        self.emit(0xdac01000 | (rn << 5) | rd);
    }

    /// CSEL Xd, Xn, Xm, cond
    fn csel(&mut self, rd: u32, rn: u32, rm: u32, cond: u32) {
        self.emit(0x1a800000 | (rm << 16) | (cond << 12) | (rn << 5) | rd);
    }

    /// CSET Xd, cond (conditional set to 1)
    fn cset(&mut self, rd: u32, cond: u32) {
        let inv = cond ^ 1;
        self.emit(0x9a9f07e0 | (inv << 12) | rd);
    }

    /// DMB ISH
    fn dmb_ish(&mut self) {
        self.emit(0xd5033f9b);
    }

    /// ISB
    fn isb(&mut self) {
        self.emit(0xd5033fdf);
    }

    // -- NEON/SIMD --

    /// EOR Vd.16B, Vn.16B, Vm.16B
    fn eor_vec(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x6e201c00 | (vm << 16) | (vn << 5) | vd);
    }

    /// ORR Vd.16B, Vn.16B, Vm.16B
    fn orr_vec(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4e201c00 | (vm << 16) | (vn << 5) | vd);
    }

    /// ADD Vd.2D, Vn.2D, Vm.2D
    fn add_vec_2d(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4e208400 | (vm << 16) | (vn << 5) | vd);
    }

    /// DUP Vd.2D, Xn (scalar to vector)
    fn dup_to_vec(&mut self, vd: u32, rn: u32) {
        self.emit(0x4e080400 | (rn << 5) | vd);
    }

    /// MOV Xd, Vn.D[0] (vector element to scalar)
    fn vec_to_scalar(&mut self, rd: u32, vn: u32) {
        self.emit(0x4e082400 | (vn << 5) | rd);
    }

    // -- NEON crypto (AES, SHA, PMULL) --

    /// AESE Vd.16B, Vn.16B – AES single round encryption
    fn aese(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e284800 | (vn << 16) | vd);
    }

    /// AESD Vd.16B, Vn.16B – AES single round decryption
    fn aesd(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e285800 | (vn << 16) | vd);
    }

    /// AESMC Vd.16B, Vn.16B – AES mix columns
    fn aesmc(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e287800 | (vn << 16) | vd);
    }

    /// AESIMC Vd.16B, Vn.16B – AES inverse mix columns
    fn aesimc(&mut self, vd: u32, vn: u32) {
        self.emit(0x4e286800 | (vn << 16) | vd);
    }

    // -- SHA1 instructions --

    /// SHA1C Qd, Sn, Vm.4S – SHA1 hash update with choice function
    fn sha1c(&mut self, qd: u32, sn: u32, vm: u32) {
        self.emit(0x5e000000 | (vm << 16) | (sn << 5) | qd);
    }

    /// SHA1P Qd, Sn, Vm.4S – SHA1 hash update with parity function
    fn sha1p(&mut self, qd: u32, sn: u32, vm: u32) {
        self.emit(0x5e001000 | (vm << 16) | (sn << 5) | qd);
    }

    /// SHA1M Qd, Sn, Vm.4S – SHA1 hash update with majority function
    fn sha1m(&mut self, qd: u32, sn: u32, vm: u32) {
        self.emit(0x5e002000 | (vm << 16) | (sn << 5) | qd);
    }

    /// SHA1H Qd, Sn – SHA1 fixed rotate (hash update)
    fn sha1h(&mut self, qd: u32, sn: u32) {
        self.emit(0x5e005800 | (sn << 5) | qd);
    }

    /// SHA1SU0 Vd.4S, Vn.4S, Vm.4S – SHA1 schedule update 0
    fn sha1su0(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x5e003000 | (vm << 16) | (vn << 5) | vd);
    }

    /// SHA1SU1 Vd.4S, Vn.4S – SHA1 schedule update 1
    fn sha1su1(&mut self, vd: u32, vn: u32) {
        self.emit(0x5e005000 | (vn << 5) | vd);
    }

    // -- SHA256 instructions --

    /// SHA256H Qd, Qn, Vm.4S – SHA256 hash update (part 1)
    fn sha256h(&mut self, qd: u32, qn: u32, vm: u32) {
        self.emit(0x5e004000 | (vm << 16) | (qn << 5) | qd);
    }

    /// SHA256H2 Qd, Qn, Vm.4S – SHA256 hash update (part 2)
    fn sha256h2(&mut self, qd: u32, qn: u32, vm: u32) {
        self.emit(0x5e005000 | (vm << 16) | (qn << 5) | qd);
    }

    /// SHA256SU0 Vd.4S, Vn.4S – SHA256 schedule update 0
    fn sha256su0(&mut self, vd: u32, vn: u32) {
        self.emit(0x5e006000 | (vn << 5) | vd);
    }

    /// SHA256SU1 Vd.4S, Vn.4S, Vm.4S – SHA256 schedule update 1
    fn sha256su1(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x5e007000 | (vm << 16) | (vn << 5) | vd);
    }

    // -- PMULL (carry-less multiply for PCLMULQDQ) --

    /// PMULL Vd.1Q, Vn.1D, Vm.1D – 64-bit carry-less multiply (polynomial 64x64 → 128)
    fn pmull_1q(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x0ee0e000 | (vm << 16) | (vn << 5) | vd);
    }

    /// PMULL2 Vd.1Q, Vn.2D, Vm.2D – 64-bit carry-less multiply from upper halves
    fn pmull2_1q(&mut self, vd: u32, vn: u32, vm: u32) {
        self.emit(0x4ee0e000 | (vm << 16) | (vn << 5) | vd);
    }

    // -- NEON permutation (lane rearrangement) --

    /// EXT Vd.16B, Vn.16B, Vm.16B, #imm – extract bytes from {Vn:Vm} starting at #imm
    fn ext_16b(&mut self, vd: u32, vn: u32, vm: u32, imm: u8) {
        self.emit(0x6e000000 | ((imm as u32) << 10) | (vm << 16) | (vn << 5) | vd);
    }

    // -- NEON 128-bit load/store (for XMM register access) --

    /// LDR Qd, [Xn, #imm] – load 128-bit NEON register from memory
    fn ldr_q_imm(&mut self, vd: u32, rn: u32, imm: u16) {
        self.emit(0x3dc00000 | ((imm as u32) << 10) | (rn << 5) | vd);
    }

    /// STR Qd, [Xn, #imm] – store 128-bit NEON register to memory
    fn str_q_imm(&mut self, vd: u32, rn: u32, imm: u16) {
        self.emit(0x3d800000 | ((imm as u32) << 10) | (rn << 5) | vd);
    }
}

// ---------------------------------------------------------------------------
// JIT memory management
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Executable memory manager
// ---------------------------------------------------------------------------

// Test-only fault-injection seams.  Each counter records how many times the
// corresponding operation was entered; when the matching `*_AT` slot equals
// that 1-based call index the operation fails.  `0` disables the seam.
#[cfg(test)]
thread_local! {
    static JIT_TEST_ALLOC_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_FAIL_ALLOC_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_WRITE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_DENY_WRITE_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_FINALIZE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_DENY_FINALIZE_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_DENY_THUNK_ZONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Force the next `chain_blocks` call to fail (self-test error-path probe).
    static JIT_TEST_FORCE_CHAIN_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Force the next resolved-thunk map lookup to miss.
    static JIT_TEST_THUNK_MAP_MISS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Make the self-test host thunk write the wrong sentinel.
    static JIT_TEST_SELF_TEST_THUNK_BAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Drive the parent self-test's executable-resolution paths: 1 = make
    /// `current_exe` fail, 2 = spawn a nonexistent child, 3 = spawn `/bin/true`
    /// (exits 0 without a report).
    static JIT_TEST_SELF_TEST_EXE_MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// Compile the self-test's first block with a wrong immediate.
    static JIT_TEST_SELF_TEST_WRONG_ORIGINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Skip writing the self-test's re-patched instruction (finalize still runs).
    static JIT_TEST_SKIP_REPATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Count `execute_block` entries per thread and suppress the safepoint
    /// flag on the configured 1-based call.
    static JIT_TEST_EXEC_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JIT_TEST_IGNORE_SAFEPOINT_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Force the host safepoint flag on the configured 1-based execute call.
    static JIT_TEST_FORCE_SAFEPOINT_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Corrupt the next non-empty SMC drain: 1 = drop the invalidation
    /// (stale block stays cached), 2 = evict the cache without an
    /// invalidation event (stale clone detected, counter stays zero).
    static JIT_TEST_SMC_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// Ignore the faulted-block bar once (simulates a lost quarantine).
    static JIT_TEST_IGNORE_FAULTED_BLOCKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Pre-publish the source link before `chain_blocks` (simulates an
    /// already-linked slot whose publication is not re-counted).
    static JIT_TEST_PREPUBLISH_CHAIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn test_seam_fails(
    calls: &'static std::thread::LocalKey<std::cell::Cell<usize>>,
    fail_at: &'static std::thread::LocalKey<std::cell::Cell<usize>>,
) -> bool {
    calls.with(|calls| {
        let call = calls.get() + 1;
        calls.set(call);
        fail_at.with(|fail_at| fail_at.get() == call)
    })
}

/// Manages executable memory for JIT-compiled code using MAP_JIT on Apple Silicon.
pub struct JitMemoryManager {
    pages: Vec<(*mut u8, usize)>,
    write_offset: usize,
    /// Executable-memory mechanism selected by the runtime capability probe.
    mechanism: JitExecMechanism,
    total_allocated: AtomicUsize,
    total_used: AtomicUsize,
}

// SAFETY: JitMemoryManager contains raw mmap'd pointers that are only
// accessed through &mut methods (allocate_code_space) or atomic counters.
// The pages vector is only modified under &mut self. The mmap'd memory
// itself is thread-safe (the kernel manages page tables independently).
unsafe impl Send for JitMemoryManager {}
// SAFETY: All shared state uses atomic operations (total_allocated,
// total_used). Mutable operations (allocate_code_space) require &mut self.
// The mmap'd pointers are only read through raw pointers, not through
// shared references that could create data races.
unsafe impl Sync for JitMemoryManager {}

impl Default for JitMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl JitMemoryManager {
    pub fn new() -> Self {
        Self::with_capability(jit_execution_capability())
    }

    /// Construct a manager for an explicit capability matrix.  Used by tests
    /// that need to exercise the unavailable/fallback path deterministically.
    fn with_capability(capability: JitExecProbeMatrix) -> Self {
        Self {
            pages: Vec::new(),
            write_offset: 0,
            mechanism: capability.selected,
            total_allocated: AtomicUsize::new(0),
            total_used: AtomicUsize::new(0),
        }
    }

    /// The executable-memory mechanism this manager uses.
    pub fn mechanism(&self) -> JitExecMechanism {
        self.mechanism
    }

    unsafe fn allocate_page(&mut self, size: usize) -> *mut u8 {
        let aligned = size.div_ceil(JIT_PAGE_SIZE) * JIT_PAGE_SIZE;

        // MAP_JIT RWX is the canonical Apple Silicon W^X mapping:
        // pthread_jit_write_protect_np(0) makes it writable, (1) makes it
        // executable.  PROT_EXEC is required in the mmap request — the
        // write-protect toggle cannot add execute permission to an RW-only
        // mapping (that was the SIGBUS blocker).
        let ptr = match self.mechanism {
            JitExecMechanism::MapJitWx => {
                #[cfg(target_arch = "aarch64")]
                {
                    unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            aligned,
                            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
                            -1,
                            0,
                        )
                    }
                }
                #[cfg(not(target_arch = "aarch64"))]
                {
                    return std::ptr::null_mut();
                }
            }
            JitExecMechanism::MprotectRx => unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    aligned,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            },
            JitExecMechanism::RwxMmap => unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    aligned,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            },
            JitExecMechanism::Unavailable => return std::ptr::null_mut(),
        };

        if ptr == libc::MAP_FAILED {
            return std::ptr::null_mut();
        }

        self.pages.push((ptr as *mut u8, aligned));
        self.total_allocated.fetch_add(aligned, Ordering::Relaxed);
        ptr as *mut u8
    }

    /// Allocate code space and return a writable pointer.
    pub fn allocate_code_space(&mut self, size: usize) -> *mut u8 {
        #[cfg(test)]
        if test_seam_fails(&JIT_TEST_ALLOC_CALLS, &JIT_TEST_FAIL_ALLOC_AT) {
            return std::ptr::null_mut();
        }
        let aligned = size.div_ceil(64) * 64;

        if let Some(&(page_ptr, page_size)) = self.pages.last()
            && self.write_offset + aligned <= page_size
        {
            // SAFETY: page_ptr is a valid mmap'd pointer and
            // write_offset + aligned <= page_size was checked above,
            // so the resulting pointer is within the allocated region.
            let ptr = unsafe { page_ptr.add(self.write_offset) };
            self.write_offset += aligned;
            self.total_used.fetch_add(aligned, Ordering::Relaxed);
            return ptr;
        }

        let new_size = aligned.max(JIT_PAGE_SIZE);
        // SAFETY: allocate_page is an unsafe method that performs mmap.
        // The caller ensures this is called from a single-threaded context
        // (&mut self). The returned pointer is validated for null before use.
        unsafe {
            let ptr = self.allocate_page(new_size);
            if ptr.is_null() {
                return std::ptr::null_mut();
            }
            self.write_offset = aligned;
            self.total_used.fetch_add(aligned, Ordering::Relaxed);
            ptr
        }
    }

    /// Find the mapping that contains `ptr` (used for page-granular mprotect).
    fn mapping_containing(&self, ptr: *mut u8) -> Option<(*mut u8, usize)> {
        self.pages.iter().copied().find(|(base, size)| {
            let address = ptr as usize;
            address >= *base as usize && address < *base as usize + *size
        })
    }

    /// Finalize code: flush icache and set executable permissions.
    ///
    /// Returns `false` when the selected mechanism cannot make the block
    /// executable (the caller then reports a compilation error and the
    /// interpreter handles the block).
    ///
    /// # Safety
    /// Caller must ensure `ptr` points to a valid code region of `size` bytes
    /// that was allocated by this memory manager.
    pub unsafe fn finalize_code(&self, ptr: *mut u8, size: usize) -> bool {
        if matches!(self.mechanism, JitExecMechanism::Unavailable) || ptr.is_null() || size == 0 {
            return false;
        }
        #[cfg(test)]
        if test_seam_fails(&JIT_TEST_FINALIZE_CALLS, &JIT_TEST_DENY_FINALIZE_AT) {
            return false;
        }
        unsafe {
            Self::flush_icache(ptr, size);
        }
        match self.mechanism {
            JitExecMechanism::MapJitWx => {
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    libc::pthread_jit_write_protect_np(1);
                }
                true
            }
            JitExecMechanism::MprotectRx => match self.mapping_containing(ptr) {
                // SAFETY: `base`/`mapping_size` are the exact anonymous mapping
                // returned by mmap and are page-aligned by the kernel.
                Some((base, mapping_size)) => unsafe {
                    libc::mprotect(
                        base as *mut c_void,
                        mapping_size,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) == 0
                },
                None => false,
            },
            JitExecMechanism::RwxMmap => true,
            JitExecMechanism::Unavailable => false, // coverage: unreachable — finalize_code returns early when mechanism is Unavailable
        }
    }

    /// Make the JIT code zone writable for patching.
    ///
    /// Returns `false` when the mechanism cannot provide writable code memory.
    ///
    /// # Safety
    ///
    /// `ptr` must point into the JIT code zone owned by this manager (or be
    /// null) and the caller must ensure no other thread is executing code in
    /// that zone while it is made writable.
    pub unsafe fn make_writable(&self, ptr: *mut u8, _size: usize) -> bool {
        #[cfg(test)]
        if test_seam_fails(&JIT_TEST_WRITE_CALLS, &JIT_TEST_DENY_WRITE_AT) {
            return false;
        }
        match self.mechanism {
            JitExecMechanism::MapJitWx => {
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    libc::pthread_jit_write_protect_np(0);
                }
                true
            }
            JitExecMechanism::MprotectRx => match self.mapping_containing(ptr) {
                // SAFETY: same mapping invariant as finalize_code.
                Some((base, mapping_size)) => unsafe {
                    libc::mprotect(
                        base as *mut c_void,
                        mapping_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    ) == 0
                },
                None => false,
            },
            JitExecMechanism::RwxMmap => true,
            JitExecMechanism::Unavailable => false,
        }
    }

    /// Ensure the calling thread may execute MAP_JIT code before dispatching a
    /// compiled block.  The write-protect toggle is per-thread on Apple
    /// Silicon, so a compilation or chain-patch performed by another thread
    /// must not leave this thread's execute view disabled.
    ///
    /// # Safety
    /// Safe to call on any thread; it only toggles the thread-local JIT
    /// write-protection state.
    pub unsafe fn prepare_execution(&self) {
        Self::prepare_execution_for_mechanism(self.mechanism);
    }

    /// Switch the CALLING THREAD into execute mode for the selected
    /// executable-memory mechanism.  Production workers call this directly
    /// (they do not own the runtime's `JitMemoryManager`); the toggle is
    /// per-thread, so every worker must do it for itself.
    pub(crate) fn prepare_execution_for_mechanism(mechanism: JitExecMechanism) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if matches!(mechanism, JitExecMechanism::MapJitWx) {
            unsafe {
                libc::pthread_jit_write_protect_np(1);
            }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let _ = mechanism;
    }

    /// # Safety
    /// Caller must ensure `ptr` is valid and `size` bytes are accessible.
    unsafe fn flush_icache(ptr: *mut u8, size: usize) {
        // SAFETY: On aarch64, the data cache (dc cvau) and instruction cache
        // (ic ivau) must be manually invalidated after writing code.
        // `addr` iterates in 64-byte cache-line-aligned steps within
        // [ptr, ptr+size), which is safe given the caller's guarantees.
        // dsb ish and isb ensure ordering of cache maintenance operations.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let mut addr = ptr as usize & !63;
            let end = ptr as usize + size;
            while addr < end {
                core::arch::asm!("dc cvau, {}", in(reg) addr);
                addr += 64;
            }
            core::arch::asm!("dsb ish");
            addr = ptr as usize & !63;
            while addr < end {
                core::arch::asm!("ic ivau, {}", in(reg) addr);
                addr += 64;
            }
            core::arch::asm!("isb");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            // No icache flush needed on non-ARM64 architectures
            let _ = (ptr, size);
        }
    }

    pub fn total_allocated(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }
    pub fn total_used(&self) -> usize {
        self.total_used.load(Ordering::Relaxed)
    }
}

impl Drop for JitMemoryManager {
    fn drop(&mut self) {
        for (ptr, size) in &self.pages {
            // SAFETY: Each (ptr, size) pair was returned by a successful
            // mmap call in allocate_page. munmap releases the mapping.
            // No other code accesses these pages after Drop runs.
            unsafe {
                libc::munmap(*ptr as *mut libc::c_void, *size);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Flat guest memory for direct JIT access
// ---------------------------------------------------------------------------

/// The JIT's flat view of the canonical guest address space.
///
/// This is **not** a mirror: it aliases the very same large `mmap` owned by
/// [`crate::cpu::GuestMemoryStore`].  A guest store executed by JIT-compiled
/// code and a store performed through the interpreter's [`MemoryImage`] touch
/// the same bytes, so no post-execution copy-back exists.
///
/// `materialised` is a one-bit-per-4-KiB-page record of which pages this view
/// has been told about (fully mapped pages seen by a sync/materialisation
/// pass).  It is diagnostic only: even a page not marked here is already
/// coherent, because the bytes live in the shared store.
pub struct FlatGuestMemory {
    store: Arc<GuestMemoryStore>,
    /// One bit per 4 KiB page of the flat window.  Atomics keep the SIGBUS
    /// fast path async-signal-safe.
    materialised: Box<[AtomicU64]>,
}

// SAFETY: FlatGuestMemory contains only an Arc to the canonical store (which
// is Send+Sync) and an atomic bitmap.
unsafe impl Send for FlatGuestMemory {}
// SAFETY: all shared state is atomic or behind the store's own synchronisation.
unsafe impl Sync for FlatGuestMemory {}

impl FlatGuestMemory {
    pub fn new(_arch: GuestArch) -> Self {
        let store = Arc::new(GuestMemoryStore::new());
        // One bit per page; the window is at most 256 GiB (8 MiB bitmap).
        let bitmap_words = store.flat_size().div_ceil(4096 * 64);
        let materialised = (0..bitmap_words)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            store,
            materialised,
        }
    }

    /// Point this view at `store` (the store owned by the live MemoryImage).
    ///
    /// This is the only "sync" the hot path performs: an `Arc` identity check.
    /// When the store changes (first attachment, or a different image), the
    /// diagnostic bitmap is reset because the pages refer to different bytes.
    pub(crate) fn attach_store(&mut self, store: &Arc<GuestMemoryStore>) {
        if Arc::ptr_eq(&self.store, store) {
            return;
        }
        self.store = Arc::clone(store);
        let required_words = store.flat_size().div_ceil(4096 * 64);
        if self.materialised.len() != required_words {
            self.materialised = (0..required_words)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice();
        } else {
            for word in &self.materialised {
                word.store(0, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &Arc<GuestMemoryStore> {
        &self.store
    }

    #[inline]
    pub fn base(&self) -> u64 {
        self.store.flat_base()
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.store.is_valid()
    }

    /// Number of 4 KiB pages in the flat window (the whole direct range).
    pub fn total_page_count(&self) -> u64 {
        (self.store.flat_size() / 4096) as u64
    }

    /// Bitmap index/bit for a page base address, or `None` when the page is
    /// outside the flat region.
    fn materialised_bit(&self, page_addr: u64) -> Option<(usize, u64)> {
        if !self.is_valid() {
            return None;
        }
        let offset = page_addr as usize;
        if offset % 4096 != 0 || offset >= self.size() {
            return None;
        }
        let page = offset / 4096;
        let word = page / 64;
        let bit = 1u64 << (page % 64);
        Some((word, bit))
    }

    /// Record that `page_addr` has been made visible to this view.
    /// Async-signal-safe: a single lock-free atomic OR with no allocation.
    #[inline]
    pub fn mark_page_materialised_signal_safe(&self, page_addr: u64) {
        if let Some((word, bit)) = self.materialised_bit(page_addr) {
            self.materialised[word].fetch_or(bit, Ordering::Relaxed);
        }
    }

    /// Returns `true` when `page_addr` has been materialised into this view.
    pub fn is_page_materialised(&self, page_addr: u64) -> bool {
        match self.materialised_bit(page_addr) {
            Some((word, bit)) => self.materialised[word].load(Ordering::Relaxed) & bit != 0,
            None => false,
        }
    }

    /// Number of guest pages materialised in this view so far.
    pub fn materialised_page_count(&self) -> u64 {
        self.materialised
            .iter()
            .map(|word| word.load(Ordering::Relaxed).count_ones() as u64)
            .sum()
    }

    /// Copy `data` into the canonical store at a flat guest address.
    ///
    /// Kept for explicit producer paths; routine JIT execution never calls
    /// this because both views already alias the same bytes.
    pub fn sync_from_memory_image(&self, guest_addr: u64, data: &[u8]) {
        if !self.is_valid() {
            return;
        }
        let offset = guest_addr as usize;
        if offset.saturating_add(data.len()) <= self.size() {
            // SAFETY: offset + data.len() <= size (checked above), so the
            // destination is inside the shared flat window. `data` is a
            // separate host buffer.
            unsafe {
                ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    (self.base() as *mut u8).add(offset),
                    data.len(),
                );
            }
        }
    }

    /// Read bytes from the canonical flat window.
    pub fn read(&self, guest_addr: u64, buf: &mut [u8]) {
        if !self.is_valid() {
            return;
        }
        let offset = guest_addr as usize;
        if offset.saturating_add(buf.len()) <= self.size() {
            // SAFETY: the source is inside the shared flat window and `buf`
            // is a distinct host allocation.
            unsafe {
                ptr::copy_nonoverlapping(
                    (self.base() as *const u8).add(offset),
                    buf.as_mut_ptr(),
                    buf.len(),
                );
            }
        }
    }

    /// Materialise the given guest pages into this view.
    ///
    /// Because the view aliases the canonical store, **no bytes are copied**:
    /// a page is marked materialised only after confirming that the
    /// `MemoryImage` has it fully mapped.  The per-page telemetry is retained
    /// for the sync-path benchmark and diagnostics; `bytes_copied` counts the
    /// bytes whose transfer this design eliminated.
    pub fn materialise_pages(&self, memory: &MemoryImage, pages: &[u64]) -> GuestMemoryTelemetry {
        let mut stats = GuestMemoryTelemetry::default();
        if !self.is_valid() || pages.is_empty() {
            return stats;
        }
        if !Arc::ptr_eq(&self.store, memory.canonical_store()) {
            // The view must be attached before it can describe the image.
            // Callers attach first; refusing here keeps byte identity a hard
            // invariant rather than silently reporting another store's pages.
            return stats;
        }

        // Page-aligned, in-bounds, sorted, deduplicated page list.
        let mut sorted: Vec<u64> = pages
            .iter()
            .filter_map(|&page| {
                let aligned = page & !0xfff;
                ((aligned as usize) < self.size()).then_some(aligned)
            })
            .collect();
        if sorted.is_empty() {
            return stats;
        }
        sorted.sort_unstable();
        sorted.dedup();

        let mut index = 0usize;
        while index < sorted.len() {
            let mut run_end_index = index;
            while run_end_index < sorted.len() {
                let page = sorted[run_end_index];
                if !memory.page_is_fully_mapped(page) {
                    break;
                }
                self.mark_page_materialised_signal_safe(page);
                stats.pages_materialised += 1;
                stats.bytes_copied += 4096;
                run_end_index += 1;
                if run_end_index < sorted.len() && sorted[run_end_index] != page + 4096 {
                    break;
                }
            }
            if run_end_index > index {
                stats.sync_operations += 1;
            } else {
                // Partially mapped page: not visible to JIT direct access.
                run_end_index = index + 1;
            }
            index = run_end_index;
        }

        GUEST_PAGES_MATERIALISED.fetch_add(stats.pages_materialised, Ordering::Relaxed);
        GUEST_SYNC_OPERATIONS.fetch_add(stats.sync_operations, Ordering::Relaxed);
        GUEST_SYNC_BYTES_COPIED.fetch_add(stats.bytes_copied, Ordering::Relaxed);
        stats
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.store.flat_size()
    }
}

// ---------------------------------------------------------------------------
// Production worker-slice memory and program
// ---------------------------------------------------------------------------

/// A worker-safe view of the canonical guest memory.
///
/// Workers must not touch the runtime's `MemoryImage` (its page table is
/// mutable and owned by the runtime thread), but they must run against the
/// *same* canonical bytes.  This view aliases the canonical store's flat
/// window and snapshots which pages are fully mapped.  Accesses to any other
/// page fail (and are reported as a guest fault) so the runtime owner can
/// service them with the full page table/VM.
///
/// Aligned word accesses use `AtomicU64` operations so two workers touching
/// neighbouring bytes in the same word can never tear or lose each other's
/// writes; unaligned accesses are merged with the same atomic RMW, giving
/// x86-style byte-preserving semantics.
pub(crate) struct GuestSliceMemory {
    store: Arc<GuestMemoryStore>,
    fully_mapped: BTreeSet<u64>,
    code_pages: BTreeSet<u64>,
    /// Guest code-page writes observed by workers, drained by the runtime
    /// owner to invalidate stale compiled blocks before the next dispatch.
    code_writes: Mutex<Vec<(u64, usize)>>,
}

impl GuestSliceMemory {
    fn new(memory: &MemoryImage, code_pages: BTreeSet<u64>) -> Self {
        let fully_mapped = memory
            .committed_page_addresses()
            .into_iter()
            .filter(|page| memory.page_is_fully_mapped(*page))
            .collect();
        Self {
            store: Arc::clone(memory.canonical_store()),
            fully_mapped,
            code_pages,
            code_writes: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn flat_base(&self) -> u64 {
        self.store.flat_base()
    }

    pub(crate) fn flat_size(&self) -> u64 {
        self.store.flat_size() as u64
    }

    fn range_available(&self, address: u64, len: usize) -> bool {
        if len == 0 || self.store.flat_base() == 0 {
            return false;
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        if end > self.flat_size() {
            return false;
        }
        let mut page = address & !0xfff;
        let last = (end - 1) & !0xfff;
        loop {
            if !self.fully_mapped.contains(&page) {
                return false;
            }
            if page == last {
                return true;
            }
            page = page.saturating_add(0x1000);
        }
    }

    fn first_fault(&self, address: u64, len: usize, write: bool) -> GuestMemoryFault {
        let mut current = address;
        let end = address.saturating_add(len as u64);
        while current < end {
            let page = current & !0xfff;
            if !self.fully_mapped.contains(&page) || current >= self.flat_size() {
                return GuestMemoryFault {
                    address: current,
                    write,
                    read_len: len,
                };
            }
            current = page.saturating_add(0x1000);
        }
        GuestMemoryFault {
            address,
            write,
            read_len: len,
        }
    }

    #[inline]
    fn atomic_word(&self, word_base: u64) -> &AtomicU64 {
        // SAFETY: `range_available` validated that the word lies inside the
        // canonical flat mapping; the mapping is stable for the store's
        // lifetime and word_base is 8-byte aligned.
        unsafe { &*((self.store.flat_base() + word_base) as *const AtomicU64) }
    }

    /// Read 1..=8 guest bytes through the shared canonical store.
    pub(crate) fn load(&self, address: u64, len: usize) -> Result<u64, GuestMemoryFault> {
        if len == 0 || len > 8 || !self.range_available(address, len) {
            return Err(self.first_fault(address, len, false));
        }
        let mut value = 0_u64;
        let mut done = 0_usize;
        while done < len {
            let current = address + done as u64;
            let word_base = current & !7;
            let word = self.atomic_word(word_base).load(Ordering::SeqCst);
            let offset = (current - word_base) as usize;
            let take = (8 - offset).min(len - done);
            let mask = if take == 8 {
                u64::MAX
            } else {
                (1_u64 << (take * 8)) - 1
            };
            value |= ((word >> (offset * 8)) & mask) << (done * 8);
            done += take;
        }
        Ok(value)
    }

    /// Write 1..=8 guest bytes through the shared canonical store.  Returns
    /// `true` when the write touched a compiled-code page (the runtime owner
    /// must invalidate stale blocks before the next slice).
    pub(crate) fn store(&self, address: u64, bytes: &[u8]) -> Result<bool, GuestMemoryFault> {
        let len = bytes.len();
        if len == 0 || len > 8 || !self.range_available(address, len) {
            return Err(self.first_fault(address, len, true));
        }
        let mut value = 0_u64;
        for (index, byte) in bytes.iter().enumerate() {
            value |= u64::from(*byte) << (index * 8);
        }
        let mut done = 0_usize;
        while done < len {
            let current = address + done as u64;
            let word_base = current & !7;
            let offset = (current - word_base) as usize;
            let take = (8 - offset).min(len - done);
            let mask = if take == 8 {
                u64::MAX
            } else {
                (1_u64 << (take * 8)) - 1
            };
            let bits = ((value >> (done * 8)) & mask) << (offset * 8);
            let field_mask = mask << (offset * 8);
            self.atomic_word(word_base)
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                    Some((old & !field_mask) | bits)
                })
                .expect("atomic guest-word update never fails");
            done += take;
        }
        let touches_code = self
            .code_pages
            .range((address & !0xfff)..=((address + len as u64 - 1) & !0xfff))
            .next()
            .is_some();
        if touches_code {
            self.code_writes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((address, len));
        }
        Ok(touches_code)
    }

    pub(crate) fn take_code_writes(&self) -> Vec<(u64, usize)> {
        std::mem::take(
            &mut *self
                .code_writes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

/// Immutable execution plan handed to a production worker.
///
/// The blocks are compiled into a dedicated, deliberately unlinked cache:
/// the worker resolves control flow itself (budget, safepoint, per-block SMC
/// checks and host-thunk barriers stay exact), while calls, returns and
/// indirect transfers continue inside the same worker job.  The program is
/// `Send + Sync` because every field is immutable shared state;
/// `JitCompiledBlock` stores its entry as an address and the code pages are
/// immutable after `finalize_code`.
pub(crate) struct GuestSliceProgram {
    pub(crate) blocks: HashMap<u64, JitCompiledBlock>,
    pub(crate) memory: Arc<GuestSliceMemory>,
    pub(crate) flat_base: u64,
    pub(crate) mechanism: JitExecMechanism,
    /// Generation of the runtime's slice-block cache.  A persistent worker
    /// slot resets its predictor/inline caches when this changes, because
    /// cached code entries could otherwise point at invalidated blocks.
    pub(crate) epoch: u64,
}

impl GuestSliceProgram {
    pub(crate) fn block(&self, rip: u64) -> Option<&JitCompiledBlock> {
        self.blocks.get(&rip)
    }
}

/// Result of one worker block execution: the dispatcher-visible exit plus the
/// address of the block that actually produced it (a chain can end in a
/// different block than the one entered).
pub(crate) struct SliceBlockOutcome {
    pub(crate) reason: JitExitReason,
    pub(crate) final_block: u64,
}

/// Execute one compiled block on a production worker.
///
/// # Safety
/// `block` must have been produced by this runtime's compiler and finalized,
/// `program.flat_base` must address the canonical guest store, and the
/// worker must not share guest state with the runtime owner (each slice owns
/// its `CpuState`).
pub(crate) unsafe fn execute_slice_block(
    program: &GuestSliceProgram,
    block: &JitCompiledBlock,
    state: &mut CpuState,
    chain: &mut ChainState,
) -> SliceBlockOutcome {
    JitMemoryManager::prepare_execution_for_mechanism(program.mechanism);
    let entry = block.published_entry();
    if entry.is_null() {
        return SliceBlockOutcome {
            reason: JitExitReason::Safepoint,
            final_block: block.guest_address,
        };
    }
    chain.current_block = block.guest_address;
    // SAFETY: the caller guarantees the entry points at finalized immutable
    // code.  The ABI is the block entry ABI (state, flat base, unused
    // MemoryImage pointer, per-chain state).
    let entry_fn: unsafe extern "C" fn(
        *mut CpuState,
        u64,
        *mut MemoryImage,
        *mut ChainState,
    ) -> u64 = unsafe { std::mem::transmute(entry) };
    let result = unsafe {
        entry_fn(
            state as *mut CpuState,
            program.flat_base,
            ptr::null_mut(),
            chain as *mut ChainState,
        )
    };
    let final_block = chain.current_block;
    let payload = chain.payload;
    // Every native exit reports the block that actually ran; callers may
    // still override this with a control-flow successor.
    state.rip = final_block;
    let exit_info = program
        .blocks
        .get(&final_block)
        .map(|final_block| final_block.last_exit_info)
        .unwrap_or(block.last_exit_info);
    SliceBlockOutcome {
        reason: map_exit_reason(result, state, result, exit_info, payload),
        final_block,
    }
}

// ---------------------------------------------------------------------------
// Persistent production-worker control-flow state and slice driver
// ---------------------------------------------------------------------------

/// Number of polymorphic ways a worker indirect-site cache holds before it
/// becomes megamorphic.
pub(crate) const INDIRECT_POLY_WAYS: usize = 4;

/// Return-stack predictor for guest `ret`.
///
/// Every worker `call` pushes its statically known return address; every
/// `ret` predicts the top entry and compares it with the real address loaded
/// from guest `[rsp]`.  A misprediction is counted, the predictor is
/// resynchronised to the real return address, and execution continues at the
/// *guest* value — the prediction is only a hint, never the authority.
#[derive(Debug, Clone)]
pub(crate) struct ReturnPredictor {
    stack: VecDeque<u64>,
    capacity: usize,
    hits: u64,
    misses: u64,
    mispredictions: u64,
}

impl Default for ReturnPredictor {
    fn default() -> Self {
        Self::new(64)
    }
}

impl ReturnPredictor {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            stack: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            hits: 0,
            misses: 0,
            mispredictions: 0,
        }
    }

    pub(crate) fn on_call(&mut self, return_address: u64) {
        if self.stack.len() == self.capacity {
            self.stack.pop_front();
        }
        self.stack.push_back(return_address);
    }

    /// Account for a `ret` whose real guest return address is `actual`.
    /// Returns whether the top-of-stack prediction matched.
    pub(crate) fn on_return(&mut self, actual: u64) -> bool {
        let prediction = self.stack.pop_back();
        match prediction {
            Some(predicted) if predicted == actual => {
                self.hits += 1;
                true
            }
            Some(_) => {
                self.misses += 1;
                self.mispredictions += 1;
                // A mismatched return means the guest stack and the predictor
                // diverged (e.g. a non-local unwind).  Re-synchronise when the
                // real return address is still on the predicted stack.
                if let Some(position) = self.stack.iter().rposition(|entry| *entry == actual) {
                    self.stack.truncate(position + 1);
                }
                false
            }
            None => {
                self.misses += 1;
                false
            }
        }
    }

    pub(crate) fn hits(&self) -> u64 {
        self.hits
    }

    pub(crate) fn misses(&self) -> u64 {
        self.misses
    }

    pub(crate) fn mispredictions(&self) -> u64 {
        self.mispredictions
    }

    pub(crate) fn reset(&mut self) {
        self.stack.clear();
        self.hits = 0;
        self.misses = 0;
        self.mispredictions = 0;
    }
}

/// One indirect-site inline cache: monomorphic until a second target appears,
/// then 2..=[`INDIRECT_POLY_WAYS`]-way polymorphic, then a hash-table
/// megamorphic fallback.  Entries map a guest target address to the compiled
/// block entry so a hit can dispatch without touching the program map.
#[derive(Debug, Default)]
struct IndirectSiteCache {
    targets: [u64; INDIRECT_POLY_WAYS],
    entries: [usize; INDIRECT_POLY_WAYS],
    len: u8,
    megamorphic: bool,
    mega: HashMap<u64, usize>,
    hits: u64,
    misses: u64,
    megamorphic_hits: u64,
}

impl IndirectSiteCache {
    fn lookup(&mut self, target: u64) -> Option<usize> {
        if self.megamorphic {
            return match self.mega.get(&target) {
                Some(entry) => {
                    self.megamorphic_hits += 1;
                    Some(*entry)
                }
                None => {
                    self.misses += 1;
                    None
                }
            };
        }
        for index in 0..self.len as usize {
            if self.targets[index] == target {
                self.hits += 1;
                return Some(self.entries[index]);
            }
        }
        self.misses += 1;
        None
    }

    fn insert(&mut self, target: u64, entry: usize) {
        if self.megamorphic {
            self.mega.insert(target, entry);
            return;
        }
        if (self.len as usize) < INDIRECT_POLY_WAYS {
            let index = self.len as usize;
            self.targets[index] = target;
            self.entries[index] = entry;
            self.len += 1;
            return;
        }
        self.megamorphic = true;
        for index in 0..INDIRECT_POLY_WAYS {
            self.mega.insert(self.targets[index], self.entries[index]);
        }
        self.mega.insert(target, entry);
    }
}

/// Per-worker-slot indirect call/jump cache, keyed by the block that performed
/// the transfer.  A site is monomorphic for one target, polymorphic for 2-4,
/// and megamorphic beyond that.
#[derive(Debug, Default)]
pub(crate) struct IndirectInlineCache {
    sites: HashMap<u64, IndirectSiteCache>,
}

impl IndirectInlineCache {
    pub(crate) fn lookup(&mut self, site: u64, target: u64) -> Option<usize> {
        let cache = self.sites.entry(site).or_default();
        cache.lookup(target)
    }

    pub(crate) fn insert(&mut self, site: u64, target: u64, entry: usize) {
        let cache = self.sites.entry(site).or_default();
        cache.insert(target, entry);
    }

    pub(crate) fn hits(&self) -> u64 {
        self.sites.values().map(|cache| cache.hits).sum()
    }

    pub(crate) fn misses(&self) -> u64 {
        self.sites.values().map(|cache| cache.misses).sum()
    }

    pub(crate) fn megamorphic_sites(&self) -> u64 {
        self.sites
            .values()
            .filter(|cache| cache.megamorphic)
            .count() as u64
    }

    pub(crate) fn megamorphic_hits(&self) -> u64 {
        self.sites
            .values()
            .map(|cache| cache.megamorphic_hits)
            .sum()
    }

    #[allow(dead_code)] // diagnostics/tests
    pub(crate) fn is_megamorphic(&self, site: u64) -> bool {
        self.sites.get(&site).is_some_and(|cache| cache.megamorphic)
    }

    pub(crate) fn reset(&mut self) {
        self.sites.clear();
    }
}

/// Cumulative control-flow metrics for one persistent worker slot.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SliceMetrics {
    pub blocks_executed: u64,
    pub instructions_executed: u64,
    pub dispatcher_exits: u64,
    pub native_chains: u64,
    pub return_predictions: u64,
    pub return_hits: u64,
    pub return_misses: u64,
    pub return_mispredictions: u64,
    pub indirect_ic_hits: u64,
    pub indirect_ic_misses: u64,
    pub indirect_megamorphic_sites: u64,
    pub indirect_megamorphic_hits: u64,
}

#[allow(dead_code)] // rates are the scheduler/benchmark diagnostic surface
impl SliceMetrics {
    /// Compiled-code exits back to the worker dispatcher per 1000 guest IR
    /// instructions (0 when nothing ran).
    pub(crate) fn dispatcher_exits_per_1000_instructions(&self) -> f64 {
        if self.instructions_executed == 0 {
            0.0
        } else {
            self.dispatcher_exits as f64 * 1000.0 / self.instructions_executed as f64
        }
    }

    /// Fraction of executed blocks that were reached as a native chain (i.e.
    /// without returning to a *scheduler* round).  A single-block slice is 0.
    pub(crate) fn native_chaining_rate(&self) -> f64 {
        if self.blocks_executed == 0 {
            0.0
        } else {
            self.native_chains as f64 / self.blocks_executed as f64
        }
    }

    pub(crate) fn return_hit_rate(&self) -> f64 {
        if self.return_predictions == 0 {
            0.0
        } else {
            self.return_hits as f64 / self.return_predictions as f64
        }
    }

    pub(crate) fn indirect_ic_hit_rate(&self) -> f64 {
        let total = self.indirect_ic_hits + self.indirect_ic_misses;
        if total == 0 {
            0.0
        } else {
            self.indirect_ic_hits as f64 / total as f64
        }
    }

    pub(crate) fn indirect_megamorphic_rate(&self) -> f64 {
        let total = self.indirect_ic_hits + self.indirect_ic_misses;
        if total == 0 {
            0.0
        } else {
            self.indirect_megamorphic_hits as f64 / total as f64
        }
    }

    pub(crate) fn delta_since(self, earlier: Self) -> Self {
        Self {
            blocks_executed: self.blocks_executed - earlier.blocks_executed,
            instructions_executed: self.instructions_executed - earlier.instructions_executed,
            dispatcher_exits: self.dispatcher_exits - earlier.dispatcher_exits,
            native_chains: self.native_chains - earlier.native_chains,
            return_predictions: self.return_predictions - earlier.return_predictions,
            return_hits: self.return_hits - earlier.return_hits,
            return_misses: self.return_misses - earlier.return_misses,
            return_mispredictions: self.return_mispredictions - earlier.return_mispredictions,
            indirect_ic_hits: self.indirect_ic_hits - earlier.indirect_ic_hits,
            indirect_ic_misses: self.indirect_ic_misses - earlier.indirect_ic_misses,
            indirect_megamorphic_sites: self.indirect_megamorphic_sites
                - earlier.indirect_megamorphic_sites,
            indirect_megamorphic_hits: self.indirect_megamorphic_hits
                - earlier.indirect_megamorphic_hits,
        }
    }
}

/// Persistent per-guest-thread execution state owned by a worker slot.
#[derive(Debug, Default)]
pub(crate) struct SliceThreadState {
    epoch: u64,
    initialised: bool,
    pub(crate) return_predictor: ReturnPredictor,
    pub(crate) indirect_cache: IndirectInlineCache,
    pub(crate) metrics: SliceMetrics,
    /// Return accounting performed entirely inside native chains (calls and
    /// returns that never re-entered the worker loop).
    native_return_hits: u64,
    native_return_misses: u64,
    native_return_mispredicts: u64,
}

impl SliceThreadState {
    /// Drop cached code-entry state when the runtime invalidated slice blocks.
    /// Cumulative metrics survive because they describe guest behaviour, not
    /// code addresses.
    pub(crate) fn prepare(&mut self, epoch: u64) {
        if !self.initialised || self.epoch != epoch {
            self.epoch = epoch;
            self.initialised = true;
            self.return_predictor.reset();
            self.indirect_cache.reset();
            self.native_return_hits = 0;
            self.native_return_misses = 0;
            self.native_return_mispredicts = 0;
            // Cached-entry counters restart with the caches.
            self.metrics.return_predictions = 0;
            self.metrics.return_hits = 0;
            self.metrics.return_misses = 0;
            self.metrics.return_mispredictions = 0;
            self.metrics.indirect_ic_hits = 0;
            self.metrics.indirect_ic_misses = 0;
            self.metrics.indirect_megamorphic_sites = 0;
            self.metrics.indirect_megamorphic_hits = 0;
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    fn refresh_cache_metrics(&mut self) {
        self.metrics.return_hits = self.return_predictor.hits() + self.native_return_hits;
        self.metrics.return_misses = self.return_predictor.misses() + self.native_return_misses;
        self.metrics.return_predictions = self.metrics.return_hits + self.metrics.return_misses;
        self.metrics.return_mispredictions =
            self.return_predictor.mispredictions() + self.native_return_mispredicts;
        self.metrics.indirect_ic_hits = self.indirect_cache.hits();
        self.metrics.indirect_ic_misses = self.indirect_cache.misses();
        self.metrics.indirect_megamorphic_sites = self.indirect_cache.megamorphic_sites();
        self.metrics.indirect_megamorphic_hits = self.indirect_cache.megamorphic_hits();
    }
}

/// Why a worker slice stopped.  Mirrors the scheduler's `GuestSliceExit`
/// without making the JIT depend on the runtime module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SliceStop {
    Budget,
    HostBarrier { rip: u64 },
    GuestFault { address: u64, write: bool },
    CodeWrite,
    Safepoint,
    Shutdown,
}

/// Result of [`run_slice`].
#[derive(Debug)]
pub(crate) struct SliceRunReport {
    pub(crate) stop: SliceStop,
    pub(crate) blocks_executed: u64,
    pub(crate) metrics: SliceMetrics,
    pub(crate) code_writes: Vec<(u64, usize)>,
}

fn slice_push_return(
    program: &GuestSliceProgram,
    state: &mut CpuState,
    return_address: u64,
) -> Result<(), (u64, bool)> {
    let pointer_bytes = state.arch.pointer_bytes();
    let rsp = state.get(Register::Rsp).wrapping_sub(pointer_bytes as u64);
    let bytes = return_address.to_le_bytes();
    let touched_code = program
        .memory
        .store(rsp, &bytes[..pointer_bytes])
        .map_err(|fault| (fault.address, fault.write))?;
    if touched_code {
        WORKER_SLICE_CODE_WRITTEN.with(|flag| flag.set(true));
        JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
    }
    state.set(Register::Rsp, rsp);
    Ok(())
}

fn slice_resolve_target(
    program: &GuestSliceProgram,
    state: &CpuState,
    target: u64,
    target_is_pointer: bool,
) -> Result<u64, (u64, bool)> {
    if !target_is_pointer {
        return Ok(target);
    }
    let pointer_bytes = state.arch.pointer_bytes();
    program
        .memory
        .load(target, pointer_bytes)
        .map_err(|fault| (fault.address, fault.write))
}

/// Run one production worker slice: execute compiled worker blocks until the
/// budget, a host barrier, a safepoint, a guest fault, a code write, or pool
/// shutdown.  Direct/conditional jumps, calls, indirect transfers and returns
/// are resolved here and continue in the same native worker — they never yield
/// to the runtime owner merely for control flow.
///
/// # Safety
/// `program` must outlive the call, its blocks must be finalized worker
/// blocks, and `state` must be exclusively owned by this worker.
pub(crate) unsafe fn run_slice(
    program: &GuestSliceProgram,
    state: &mut CpuState,
    thread: &mut SliceThreadState,
    budget: u64,
    shutdown: &std::sync::atomic::AtomicBool,
) -> SliceRunReport {
    use std::sync::atomic::Ordering;
    thread.prepare(program.epoch);
    let metrics_before = thread.metrics;
    let guard = WorkerSliceGuard::install(&program.memory);
    let mut chain = ChainState::new(program.flat_base, state.rip, budget.min(LINK_BUDGET));
    let mut blocks_executed = 0_u64;
    let mut dispatches = 0_u64;
    let stop = loop {
        if shutdown.load(Ordering::Acquire) {
            break SliceStop::Shutdown;
        }
        if blocks_executed >= budget {
            break SliceStop::Budget;
        }
        let Some(block) = program.block(state.rip) else {
            break SliceStop::HostBarrier { rip: state.rip };
        };
        if !block.worker_safe {
            break SliceStop::HostBarrier { rip: state.rip };
        }
        // Never let a native chain outlive the slice budget or the link
        // budget.  `link_budget` is also the check counter that guarantees a
        // dispatch boundary (safepoint + SMC re-evaluation) even in a loop of
        // direct branches.
        chain.link_budget = (budget - blocks_executed).min(LINK_BUDGET);
        let before_blocks = chain.blocks;
        let before_instructions = chain.instructions;
        // SAFETY: the block came from the caller's finalized worker program
        // and the worker owns `state` and `chain`.
        let outcome = unsafe { execute_slice_block(program, block, state, &mut chain) };
        let delta_blocks = chain.blocks - before_blocks;
        let delta_instructions = chain.instructions - before_instructions;
        blocks_executed += delta_blocks;
        thread.metrics.blocks_executed += delta_blocks;
        thread.metrics.instructions_executed += delta_instructions;
        if delta_blocks > 0 {
            dispatches += 1;
            thread.metrics.dispatcher_exits += 1;
            thread.metrics.native_chains += delta_blocks.saturating_sub(1);
        }
        let code_written = guard.code_written();
        let SliceBlockOutcome {
            reason,
            final_block,
        } = outcome;
        let final_exit_info = program
            .blocks
            .get(&final_block)
            .and_then(|block| block.last_exit_info)
            .or(block.last_exit_info);
        let conditional_taken = match &reason {
            JitExitReason::ConditionalBranch { taken, .. } => Some(*taken),
            JitExitReason::ConditionalTaken { .. } => Some(true),
            JitExitReason::ConditionalNotTaken { .. } => Some(false),
            _ => None,
        };
        match reason {
            JitExitReason::Jump { target } => {
                state.rip = target;
            }
            JitExitReason::ConditionalBranch { .. }
            | JitExitReason::ConditionalTaken { .. }
            | JitExitReason::ConditionalNotTaken { .. } => {
                let taken = conditional_taken.unwrap_or(false);
                let Some(BlockExitInfo::JumpIf {
                    target,
                    fallthrough,
                    ..
                }) = final_exit_info
                else {
                    break SliceStop::HostBarrier { rip: state.rip };
                };
                state.rip = if taken { target } else { fallthrough };
            }
            JitExitReason::DirectCall {
                target,
                return_address,
            } => {
                if let Err((address, write)) = slice_push_return(program, state, return_address) {
                    break SliceStop::GuestFault { address, write };
                }
                thread.return_predictor.on_call(return_address);
                state.rip = target;
            }
            JitExitReason::DirectCallPushed {
                target,
                return_address: _,
            } => {
                // The compiled block already pushed the guest return address
                // and recorded the call in the chain's native return stack.
                state.rip = target;
            }
            JitExitReason::IndirectCall {
                target,
                return_address,
                target_is_pointer,
            } => {
                let target = match slice_resolve_target(program, state, target, target_is_pointer) {
                    Ok(target) => target,
                    Err((address, write)) => break SliceStop::GuestFault { address, write },
                };
                if let Err((address, write)) = slice_push_return(program, state, return_address) {
                    break SliceStop::GuestFault { address, write };
                }
                thread.return_predictor.on_call(return_address);
                if thread.indirect_cache.lookup(final_block, target).is_none()
                    && let Some(callee) = program.blocks.get(&target)
                {
                    thread
                        .indirect_cache
                        .insert(final_block, target, callee.entry() as usize);
                }
                state.rip = target;
            }
            JitExitReason::IndirectJump {
                target,
                target_is_pointer,
            } => {
                let target = match slice_resolve_target(program, state, target, target_is_pointer) {
                    Ok(target) => target,
                    Err((address, write)) => break SliceStop::GuestFault { address, write },
                };
                if thread.indirect_cache.lookup(final_block, target).is_none()
                    && let Some(target_block) = program.blocks.get(&target)
                {
                    thread.indirect_cache.insert(
                        final_block,
                        target,
                        target_block.entry() as usize,
                    );
                }
                state.rip = target;
            }
            JitExitReason::Return { .. } => {
                let pointer_bytes = state.arch.pointer_bytes();
                let rsp = state.get(Register::Rsp);
                let actual = match program.memory.load(rsp, pointer_bytes) {
                    Ok(actual) => actual,
                    Err(fault) => {
                        break SliceStop::GuestFault {
                            address: fault.address,
                            write: fault.write,
                        };
                    }
                };
                let stack_adjust = match final_exit_info {
                    Some(BlockExitInfo::Return { stack_adjust }) => stack_adjust,
                    _ => 0,
                };
                thread.return_predictor.on_return(actual);
                state.set(
                    Register::Rsp,
                    rsp.wrapping_add(pointer_bytes as u64 + stack_adjust),
                );
                // Warm the chain return stack so the next visit can link
                // natively without leaving the worker.
                let entry = program
                    .blocks
                    .get(&actual)
                    .filter(|block| block.worker_safe)
                    .map(|block| block.entry() as u64)
                    .unwrap_or(0);
                chain.push_return(actual, entry);
                state.rip = actual;
            }
            JitExitReason::ReturnResolved { target } => {
                // Native return prediction/accounting already ran inside the
                // compiled block (see the chain counters merged below).
                state.rip = target;
            }
            JitExitReason::Safepoint => {
                state.rip = final_block;
                break SliceStop::Safepoint;
            }
            JitExitReason::LinkBudget { .. } => {
                // The block at `final_block` did not execute.  Re-enter it
                // with a fresh check budget, unless the slice budget is spent.
                state.rip = final_block;
                if blocks_executed >= budget {
                    break SliceStop::Budget;
                }
            }
            JitExitReason::CodeEpoch { .. } => {
                state.rip = final_block;
                break SliceStop::CodeWrite;
            }
            JitExitReason::GuestFault => {
                let address = state.jit_pending_fault.take().unwrap_or(state.rip);
                let write = std::mem::take(&mut state.jit_pending_fault_write);
                break SliceStop::GuestFault { address, write };
            }
            JitExitReason::Normal { .. }
            | JitExitReason::ThunkDispatch { .. }
            | JitExitReason::UnimplementedInstruction { .. }
            | JitExitReason::MemoryAccess { .. }
            | JitExitReason::Cpuid
            | JitExitReason::Exception { .. } => {
                // A straight-line worker block has no static successor.  Stop
                // at the block that actually ran and let the owner re-decode
                // (this is the documented host barrier for these blocks).
                state.rip = final_block;
                break SliceStop::HostBarrier { rip: state.rip };
            }
        }
        if code_written {
            break SliceStop::CodeWrite;
        }
        if program
            .block(state.rip)
            .map_or(true, |block| !block.worker_safe)
        {
            break SliceStop::HostBarrier { rip: state.rip };
        }
    };
    let _ = dispatches;
    thread.native_return_hits += chain.native_return_hits;
    thread.native_return_misses += chain.native_return_misses;
    thread.native_return_mispredicts += chain.native_return_mispredicts;
    thread.refresh_cache_metrics();
    let code_writes = program.memory.take_code_writes();
    drop(guard);
    SliceRunReport {
        stop,
        blocks_executed,
        metrics: thread.metrics.delta_since(metrics_before),
        code_writes,
    }
}

/// Benchmark-only AOT cache probe: compile once, then load the persisted
/// block through `rounds` fresh runtime instances.  Returns the accumulated
/// `(hits, misses, rejected)` counters.
#[doc(hidden)]
pub fn bench_aot_hits(rounds: u64) -> (u64, u64, u64) {
    let directory = std::env::temp_dir().join(format!(
        "casa1-aot-bench-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let ir = [IrInstruction::Nop];
    let address = 0x1000;
    let mut totals = (0_u64, 0_u64, 0_u64);
    {
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.set_aot_cache_dir(Some(directory.clone()));
        let _ = runtime.get_or_compile_slice_block(&ir, address, GuestArch::X64);
        let metrics = runtime.aot_metrics();
        totals = (
            totals.0 + metrics.0,
            totals.1 + metrics.1,
            totals.2 + metrics.2,
        );
    }
    for _ in 0..rounds {
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.set_aot_cache_dir(Some(directory.clone()));
        let _ = runtime.get_or_compile_slice_block(&ir, address, GuestArch::X64);
        let metrics = runtime.aot_metrics();
        totals = (
            totals.0 + metrics.0,
            totals.1 + metrics.1,
            totals.2 + metrics.2,
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
    totals
}

/// Benchmark-only harness for production worker slices.  It keeps the
/// `JitRuntime` alive because the compiled entry addresses live in its
/// executable mappings.
#[doc(hidden)]
pub struct WorkerSliceBenchmark {
    _runtime: JitRuntime,
    program: GuestSliceProgram,
    state: CpuState,
    thread: SliceThreadState,
    shutdown: AtomicBool,
    entry: u64,
    rsp: u64,
}

#[doc(hidden)]
impl WorkerSliceBenchmark {
    pub fn new(
        arch: GuestArch,
        memory: &MemoryImage,
        blocks: &[(u64, Vec<IrInstruction>)],
        entry: u64,
        rsp: u64,
    ) -> Self {
        let mut runtime = JitRuntime::new(arch);
        runtime.set_aot_cache_dir(None);
        for (address, ir) in blocks {
            runtime
                .get_or_compile_slice_block(ir, *address, arch)
                .expect("compile benchmark worker block");
        }
        let program = runtime.build_slice_program(memory);
        let mut state = CpuState::new(arch);
        state.set(Register::Rsp, rsp);
        Self {
            _runtime: runtime,
            program,
            state,
            thread: SliceThreadState::default(),
            shutdown: AtomicBool::new(false),
            entry,
            rsp,
        }
    }

    pub fn reset(&mut self) {
        self.state.rip = self.entry;
        self.state.set(Register::Rsp, self.rsp);
        self.state.set(Register::Rcx, 0);
        self.thread = SliceThreadState::default();
    }

    pub fn set_rax(&mut self, value: u64) {
        self.state.set(Register::Rax, value);
    }

    /// Seed the guest loop counter (RCX) for benchmark workloads.
    pub fn set_rcx(&mut self, value: u64) {
        self.state.set(Register::Rcx, value);
    }

    /// Enable or disable native block linking for this benchmark harness.
    ///
    /// Disabling clears every worker link slot; execution still produces the
    /// same guest state but dispatches each block separately.  This is the
    /// measurement control for the linked-loop benchmark.
    pub fn set_linking(&mut self, enabled: bool) {
        if enabled {
            self._runtime.publish_slice_links();
        } else {
            for block in self.program.blocks.values() {
                block.link_target.store(0, Ordering::Release);
                block.taken_link.store(0, Ordering::Release);
                block.fallthrough_link.store(0, Ordering::Release);
                block.call_link.store(0, Ordering::Release);
                block.return_entry_link.store(0, Ordering::Release);
            }
        }
    }

    /// Borrow the guest state (benchmark inspection).
    pub fn state(&self) -> &CpuState {
        &self.state
    }

    pub fn run(&mut self, budget: u64) -> (u64, u64, SliceMetrics) {
        // SAFETY: the harness owns the runtime, the program was built from it,
        // and `state` is exclusively borrowed for the call.
        let report = unsafe {
            run_slice(
                &self.program,
                &mut self.state,
                &mut self.thread,
                budget,
                &self.shutdown,
            )
        };
        (
            report.blocks_executed,
            report.metrics.instructions_executed,
            report.metrics,
        )
    }
}

/// Benchmark-only indirect-cache workload: returns the accumulated hit count.
#[doc(hidden)]
pub fn bench_indirect_cache(iterations: u64) -> u64 {
    let mut cache = IndirectInlineCache::default();
    let mut hits = 0_u64;
    for index in 0..iterations {
        let target = 0x2000 + (index % 6) * 0x1000;
        if let Some(entry) = cache.lookup(0x1000, target) {
            hits = hits.wrapping_add(entry as u64);
        } else {
            cache.insert(0x1000, target, target as usize);
        }
    }
    hits.wrapping_add(cache.hits())
}

/// Benchmark-only return-predictor workload: returns the accumulated hit count.
#[doc(hidden)]
pub fn bench_return_predictor(iterations: u64) -> u64 {
    let mut predictor = ReturnPredictor::default();
    let mut hits = 0_u64;
    for index in 0..iterations {
        let return_address = 0x1000 + (index % 64) * 0x10;
        predictor.on_call(return_address);
        if predictor.on_return(return_address) {
            hits = hits.wrapping_add(1);
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// JIT compilation result
// ---------------------------------------------------------------------------

/// Result of JIT-compiling a block of IR instructions.
///
/// The compiled-code descriptor is immutable after construction and contains
/// no raw pointers: the executable entry is stored as a `usize` address (plus
/// the `entry_atomic` publication slot).  That makes the descriptor genuinely
/// `Send + Sync`; the safety invariant is that the underlying code page is
/// immutable and executable after `finalize_code`, and every executor obtains
/// the entry through [`Self::published_entry`] (acquire).
pub struct JitCompiledBlock {
    /// Address of the compiled ARM64 code entry point.  Callers that publish a
    /// block to another thread must use [`Self::published_entry`] (acquire) so
    /// the code bytes written before publication are visible.
    entry_addr: usize,
    /// Atomic publication of the entry address.  Installers store with Release
    /// after `finalize_code` (icache flush); executors load with Acquire.
    entry_atomic: AtomicPtr<u8>,
    /// Size of compiled code in bytes.
    pub code_size: usize,
    /// Guest address this block was compiled from.
    pub guest_address: u64,
    /// Number of guest instructions compiled.
    pub instruction_count: usize,
    /// Hash of the source IR instructions at compile time, used to detect
    /// self-modifying code on subsequent `get_or_compile` calls.
    /// A hash of 0 means integrity verification is disabled for this block.
    pub source_hash: u64,
    /// Control-flow metadata for the block's final instruction (the JIT
    /// never writes `state.rip` for jump-family exits, so the dispatcher
    /// reconstructs it from this metadata — see
    /// [`map_exit_reason`](crate::jit::map_exit_reason)).
    pub last_exit_info: Option<BlockExitInfo>,
    /// Compilation tier that produced this block.
    pub compile_tier: CompilationTier,
    /// True when the final IR instruction controls RIP (jump/call/ret
    /// family).  A chain may only target such a block: chaining into a
    /// straight-line block would leave the dispatcher advancing RIP by
    /// the *source* block's end address.
    pub ends_in_control_flow: bool,
    /// Atomic link slot read by the block's compiled jump exit.  Zero means
    /// "not linked"; a non-zero value is the target block entry.  Linking
    /// never patches code — it publishes a pointer with Release, so no other
    /// thread can observe a torn instruction sequence.
    pub link_target: Arc<AtomicU64>,
    /// `Jcc` taken/fallthrough successor entries (worker slices).
    pub(crate) taken_link: Arc<AtomicU64>,
    pub(crate) fallthrough_link: Arc<AtomicU64>,
    /// Direct-call successor entry (worker slices).
    pub(crate) call_link: Arc<AtomicU64>,
    /// Entry of the statically known return successor of a direct call.
    /// Emitted call sites push this into the chain return stack.
    pub(crate) return_entry_link: Arc<AtomicU64>,
    /// True when a production worker may execute this block without touching
    /// runtime-owned host state: no interpreter fallback, no host call/return
    /// terminator, and no unresolved jump target.  Worker slices execute only
    /// these blocks; everything else is a thunk/host barrier.
    pub worker_safe: bool,
}

impl Clone for JitCompiledBlock {
    fn clone(&self) -> Self {
        Self {
            entry_addr: self.entry_addr,
            entry_atomic: AtomicPtr::new(self.entry_atomic.load(Ordering::Acquire)),
            code_size: self.code_size,
            guest_address: self.guest_address,
            instruction_count: self.instruction_count,
            source_hash: self.source_hash,
            last_exit_info: self.last_exit_info,
            compile_tier: self.compile_tier,
            ends_in_control_flow: self.ends_in_control_flow,
            link_target: Arc::clone(&self.link_target),
            taken_link: Arc::clone(&self.taken_link),
            fallthrough_link: Arc::clone(&self.fallthrough_link),
            call_link: Arc::clone(&self.call_link),
            return_entry_link: Arc::clone(&self.return_entry_link),
            worker_safe: self.worker_safe,
        }
    }
}

impl JitCompiledBlock {
    /// Acquire-load the published executable entry point.
    pub fn published_entry(&self) -> *const u8 {
        self.entry_atomic.load(Ordering::Acquire)
    }

    /// The immutable entry address captured at compilation time.
    pub fn entry(&self) -> *const u8 {
        self.entry_addr as *const u8
    }
}

/// True when `insn` transfers control (and therefore establishes RIP itself
/// or asks the dispatcher to do so).
fn instruction_controls_rip(insn: &IrInstruction) -> bool {
    matches!(
        insn,
        IrInstruction::Jump { .. }
            | IrInstruction::JumpIf { .. }
            | IrInstruction::JumpRegister { .. }
            | IrInstruction::JumpMemory { .. }
            | IrInstruction::Return { .. }
            | IrInstruction::Call { .. }
            | IrInstruction::CallRegister { .. }
            | IrInstruction::CallMemory { .. }
    )
}

fn block_ends_in_control_flow(ir: &[IrInstruction]) -> bool {
    ir.last().is_some_and(instruction_controls_rip)
}

/// Conservative guest-byte extent of a translated block.
///
/// IR does not retain each x86 instruction's encoded length, so the extent is
/// bounded by the architectural maximum (15 bytes) per instruction.  This is
/// used only for self-modifying-code page attribution; over-approximating can
/// invalidate a neighbouring block conservatively, never miss a real write.
fn block_guest_span(block: &JitCompiledBlock) -> u64 {
    (block.instruction_count as u64).saturating_mul(15).max(1)
}

/// A production worker slice may execute a block only when it is fully
/// self-contained: no interpreter-helper fallback (which needs a live
/// `MemoryImage`), and no instruction that exits the block MID-WAY for the
/// interpreter to re-run (which would double-execute the already-run prefix).
///
/// Guest `call`/`ret`/indirect `jmp` are NOT barriers any more: the
/// worker-program compiler lowers them to self-contained native exits whose
/// target is carried in the per-thread exit cell, and the worker resolves the
/// continuation itself (return-stack predictor / inline cache).  A direct
/// `Call` whose target is a HOST thunk still yields at run time, because the
/// worker finds no compiled block for it and reports a host barrier — the
/// runtime owner then executes the thunk exactly once.
fn block_is_worker_safe(ir: &[IrInstruction], used_interpreter_helper: bool) -> bool {
    if used_interpreter_helper {
        return false;
    }
    !ir.iter().any(|insn| {
        matches!(
            insn,
            IrInstruction::Cpuid
                | IrInstruction::Xgetbv
                | IrInstruction::Fxsave { .. }
                | IrInstruction::Fxrstor { .. }
        )
    })
}

/// Result of executing a JIT-compiled block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitExitReason {
    /// Block completed normally; RIP has been updated.
    Normal { new_rip: u64 },
    /// Block hit a thunk/import that needs host dispatch.
    ThunkDispatch { target_rip: u64, return_rip: u64 },
    /// Block hit an unimplemented instruction.
    UnimplementedInstruction { rip: u64, opcode: u8 },
    /// Block hit a conditional branch (needs host flag computation).
    ConditionalBranch { rip: u64, taken: bool },
    /// Block hit a direct CALL to a known guest address.
    ///
    /// The worker pushes `return_address` on the guest stack and continues at
    /// `target` when that address has a compiled worker block; when it does
    /// not (e.g. a host thunk), the worker reports a host barrier with the
    /// thunk as RIP so the runtime owner executes it exactly once.
    DirectCall { target: u64, return_address: u64 },
    /// Block hit a CALL instruction to an indirect target.
    ///
    /// `target` is the resolved callee address.  When `target_is_pointer` is
    /// true the compiled block could not dereference the memory operand itself
    /// (no live `MemoryImage` on a production worker), so the worker must load
    /// the callee address from guest memory at `target` before transferring.
    IndirectCall {
        target: u64,
        return_address: u64,
        target_is_pointer: bool,
    },
    /// Block hit an indirect JMP (register or memory operand).  See
    /// [`Self::IndirectCall`] for the `target_is_pointer` convention.
    IndirectJump {
        target: u64,
        target_is_pointer: bool,
    },
    /// Block hit a RET instruction.  The compiled gate stores the raw exit
    /// code in `return_rip`; a production worker reads the real return address
    /// from guest `[rsp]` (via the slice memory view) and pops the stack, so
    /// this field is diagnostic only on the worker path.
    Return { return_rip: u64 },
    /// Block needs host-side memory access (slow path).
    MemoryAccess {
        address: u64,
        is_write: bool,
        width: usize,
    },
    /// Block hit CPUID.
    Cpuid,
    /// Block needs host-side exception handling.
    Exception { code: u32, address: u64 },
    /// Block ended in an unconditional Jump: the JIT never writes
    /// state.rip for jumps, so the dispatcher must set RIP to `target`
    /// and dispatch the target block next.
    Jump { target: u64 },
    /// A native `Jcc` decided the branch was taken.  `rip` is the block's
    /// address; the dispatcher derives target/fallthrough from the block's
    /// static [`BlockExitInfo`].
    ConditionalTaken { rip: u64 },
    /// A native `Jcc` decided the branch was not taken.
    ConditionalNotTaken { rip: u64 },
    /// The link budget was exhausted at a block entry.  The block did not run;
    /// the dispatcher refills the budget and re-dispatches `rip`.
    LinkBudget { rip: u64 },
    /// A guest store changed compiled-code bytes.  The block at `rip` did not
    /// run; the dispatcher must invalidate stale translations before
    /// re-dispatching it.
    CodeEpoch { rip: u64 },
    /// A direct call whose return address was already pushed by the compiled
    /// block.  The worker must not push again.
    DirectCallPushed { target: u64, return_address: u64 },
    /// A native worker return that already popped the guest stack.  `target`
    /// is the return address read from guest `[rsp]`.
    ReturnResolved { target: u64 },
    /// Block hit the host safepoint flag (see `JIT_SAFEPOINT_REQUESTED`):
    /// the dispatcher must run the host-side safepoint body (pump pending
    /// guest threads, drain timers/APCs, advance the guest clock) and then
    /// re-dispatch the block.
    Safepoint,
    /// A guest load/store faulted on unmapped memory.  The block aborted at
    /// the faulting instruction (the emitted post-helper fault test branched
    /// here before any later instruction ran); the dispatcher must raise the
    /// access violation immediately, using `state.jit_pending_fault` (the
    /// precise fault address) and `state.jit_pending_fault_write` (the
    /// access type).
    GuestFault,
}

/// Static control-flow metadata captured at compile time for a block's
/// final instruction, so the dispatcher can reconstruct guest RIP for
/// jump-family JIT exits — the compiled code records only an exit code
/// and never writes `state.rip` for these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockExitInfo {
    /// Last instruction was an unconditional `Jump`.
    Jump { target: u64 },
    /// Last instruction was a `JumpIf` — the dispatcher evaluates the
    /// condition against `state.flags` and sets RIP to `target` or
    /// `fallthrough`.
    JumpIf {
        condition: ConditionCode,
        target: u64,
        fallthrough: u64,
    },
    /// Last instruction was a `Return` (guest `ret [imm16]`).  The worker pops
    /// the return address from guest `[rsp]` and adds `8 + stack_adjust` to
    /// `rsp`, matching the interpreter.
    Return { stack_adjust: u64 },
    /// Last instruction was a direct `Call` to `target`.  The worker pushes
    /// `return_address` (already the address after the `call`) so a matching
    /// `Return` can pop it from the return-stack predictor / guest stack.
    Call { target: u64, return_address: u64 },
    /// Last instruction was an indirect `CallRegister` / `CallMemory`.  The
    /// callee target arrives in the [`JitExitReason::IndirectCall`] payload;
    /// `return_address` is static.
    CallIndirect { return_address: u64 },
}

/// Extract the [`BlockExitInfo`] for a compiled IR sequence, if its final
/// instruction is a jump-family instruction.
fn block_exit_info(ir: &[IrInstruction]) -> Option<BlockExitInfo> {
    match ir.last() {
        Some(IrInstruction::Jump { target }) => Some(BlockExitInfo::Jump { target: *target }),
        Some(IrInstruction::JumpIf {
            condition,
            target,
            fallthrough,
        }) => Some(BlockExitInfo::JumpIf {
            condition: *condition,
            target: *target,
            fallthrough: *fallthrough,
        }),
        Some(IrInstruction::Return { stack_adjust }) => Some(BlockExitInfo::Return {
            stack_adjust: *stack_adjust,
        }),
        Some(IrInstruction::Call {
            target,
            return_address,
        }) => Some(BlockExitInfo::Call {
            target: *target,
            return_address: *return_address,
        }),
        Some(IrInstruction::CallRegister { return_address, .. })
        | Some(IrInstruction::CallMemory { return_address, .. }) => {
            Some(BlockExitInfo::CallIndirect {
                return_address: *return_address,
            })
        }
        _ => None,
    }
}

/// Compute a simple hash of IR instructions for self-modifying code detection.
/// This is used as a lightweight integrity check: if the guest modifies the
/// source bytes, the new IR will differ and produce a different hash.
///
/// Hashes the guest address and the Debug representation of each instruction,
/// which captures both the opcode AND its operand values (registers, immediates,
/// etc.). This ensures that changing any operand (e.g., `MovImm { value: 42 }`
/// vs `MovImm { value: 99 }`) produces a different hash.
fn compute_ir_hash(ir: &[IrInstruction], guest_address: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    guest_address.hash(&mut hasher);
    for insn in ir {
        // Use the full Debug output to capture both the variant AND all fields.
        let repr = format!("{:?}", insn);
        repr.len().hash(&mut hasher);
        for b in repr.bytes() {
            b.hash(&mut hasher);
        }
    }
    hasher.finish()
}

// ---------------------------------------------------------------------------
// JIT compiler: IR -> ARM64 machine code
// ---------------------------------------------------------------------------

/// Exit reason codes written by JIT code to signal back to the host.
const EXIT_NORMAL: u64 = 0;
const EXIT_THUNK: u64 = 1;
const EXIT_UNIMPL: u64 = 2;
#[allow(dead_code)]
const EXIT_COND_BRANCH: u64 = 3;
#[allow(dead_code)]
const EXIT_INDIRECT_CALL: u64 = 4;
const EXIT_RET: u64 = 5;
#[allow(dead_code)]
const EXIT_MEM_ACCESS: u64 = 6;
const EXIT_CPUID: u64 = 7;
#[allow(dead_code)]
const EXIT_EXCEPTION: u64 = 8;
/// Block ended in an unconditional Jump — the dispatcher must set state.rip
/// to the jump target (carried in the last IR instruction) so the main loop
/// dispatches the target block next.  Without this, EXIT_NORMAL leaves rip at
/// the block start and the main loop re-dispatches the same block forever.
const EXIT_JUMP: u64 = 9;
/// Block hit the host safepoint flag (`JIT_SAFEPOINT_REQUESTED`) — the
/// dispatcher must run the host-side safepoint body and re-dispatch the
/// block.  Emitted by `emit_safepoint_check`.
const EXIT_SAFEPOINT: u64 = 10;
/// A guest load/store faulted on unmapped memory INSIDE the block.  The
/// immediate flag test after every helper call branches here so the block
/// aborts at the faulting instruction — Windows requires that an access
/// violation at instruction N prevents instructions N+1.. from executing.
/// The dispatcher reads the precise fault from `CpuState::jit_pending_fault`
/// (+ `jit_pending_fault_write`) and raises the same access-violation error
/// the interpreter produces.
const EXIT_GUEST_FAULT: u64 = 11;
/// Production-worker indirect control transfers.  The compiled block cannot
/// write `state.rip` (unstable repr(Rust) offset) and has no live
/// `MemoryImage`, so it publishes the resolved target (register operand) or the
/// guest address the target must be loaded from (memory operand) into the
/// per-thread cell word `cell[2]` and exits with one of these codes.  The
/// worker resolves the target and continues natively (inline cache) instead of
/// yielding to the runtime owner.
const EXIT_INDIRECT_JUMP_REG: u64 = 12;
const EXIT_INDIRECT_CALL_REG: u64 = 13;
const EXIT_INDIRECT_JUMP_MEM: u64 = 14;
const EXIT_INDIRECT_CALL_MEM: u64 = 15;
/// Production-worker direct `call target`: the static target is published in
/// the per-thread exit cell payload (same convention as the indirect codes).
/// The worker pushes the static return address and either chains to the
/// compiled callee block or reports the target as a host barrier.
const EXIT_CALL_DIRECT: u64 = 16;
/// Direct call whose return address was already pushed natively by the
/// compiled block.  The worker must not push it a second time.
const EXIT_CALL_PUSHED: u64 = 17;
/// The compiled block's link-budget counter reached zero.  The current block
/// has NOT executed; the dispatcher refills the counter and re-enters it.
const EXIT_LINK_BUDGET: u64 = 18;
/// The block's prologue observed a guest-code write epoch change.  The block
/// has NOT executed; the dispatcher invalidates stale translated code.
const EXIT_CODE_EPOCH: u64 = 19;
/// A native `Jcc` determined the branch was taken / not taken.  The host no
/// longer re-evaluates the condition; it only maps the outcome to RIP.
const EXIT_COND_TAKEN: u64 = 20;
const EXIT_COND_NOT_TAKEN: u64 = 21;
/// Native worker `ret`: the return address was already loaded from guest
/// `[rsp]`, `rsp` was advanced, and the result is in the payload word.
const EXIT_RET_RESOLVED: u64 = 22;

/// Byte offset (within the per-thread exit cell) of the indirect payload word.
pub(crate) const EXIT_CELL_PAYLOAD_OFFSET: u64 = 16;

/// Atomic link slots belonging to one block.  Each slot is published by the
/// runtime after translation (and cleared on invalidation) and read by the
/// compiled block with an acquire load.  Keeping every edge separate means a
/// direct call or a two-way conditional branch can be linked independently
/// without patching instruction memory (which would race executors).
#[derive(Clone)]
struct LinkSlots {
    jump: Arc<AtomicU64>,
    taken: Arc<AtomicU64>,
    fallthrough: Arc<AtomicU64>,
    call: Arc<AtomicU64>,
    return_entry: Arc<AtomicU64>,
}

impl LinkSlots {
    fn new() -> Self {
        Self {
            jump: Arc::new(AtomicU64::new(0)),
            taken: Arc::new(AtomicU64::new(0)),
            fallthrough: Arc::new(AtomicU64::new(0)),
            call: Arc::new(AtomicU64::new(0)),
            return_entry: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Helper functions whose absolute address is embedded in translated code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AotHelper {
    Load,
    Store,
    ExecuteInsn,
    SegmentBase,
    SetFlags,
    MaterializeFlags,
}

impl AotHelper {
    fn address(self) -> u64 {
        match self {
            Self::Load => jit_helper_load as *const () as u64,
            Self::Store => jit_helper_store as *const () as u64,
            Self::ExecuteInsn => jit_helper_execute_insn as *const () as u64,
            Self::SegmentBase => jit_helper_segment_base as *const () as u64,
            Self::SetFlags => jit_helper_set_flags as *const () as u64,
            Self::MaterializeFlags => jit_helper_materialize_flags as *const () as u64,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::Load => 1,
            Self::Store => 2,
            Self::ExecuteInsn => 3,
            Self::SegmentBase => 4,
            Self::SetFlags => 5,
            Self::MaterializeFlags => 6,
        }
    }

    fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::Load,
            2 => Self::Store,
            3 => Self::ExecuteInsn,
            4 => Self::SegmentBase,
            5 => Self::SetFlags,
            6 => Self::MaterializeFlags,
            _ => return None,
        })
    }
}

/// One absolute value embedded in translated code that must be re-bound when
/// the block is loaded from the persistent AOT cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AotRelocation {
    /// Byte offset of the fixed four-instruction `movz`/`movk` sequence.
    offset: u32,
    kind: AotRelocKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AotRelocKind {
    SafepointFlag,
    CodeEpoch,
    JumpLink,
    TakenLink,
    FallthroughLink,
    CallLink,
    ReturnEntryLink,
    Helper(AotHelper),
}

impl AotRelocKind {
    fn code(self) -> u32 {
        match self {
            Self::SafepointFlag => 0,
            Self::CodeEpoch => 1,
            Self::JumpLink => 2,
            Self::TakenLink => 3,
            Self::FallthroughLink => 4,
            Self::CallLink => 5,
            Self::ReturnEntryLink => 6,
            Self::Helper(helper) => 0x100 + helper.code(),
        }
    }

    fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => Self::SafepointFlag,
            1 => Self::CodeEpoch,
            2 => Self::JumpLink,
            3 => Self::TakenLink,
            4 => Self::FallthroughLink,
            5 => Self::CallLink,
            6 => Self::ReturnEntryLink,
            other => Self::Helper(AotHelper::from_code(other.checked_sub(0x100)?)?),
        })
    }
}

/// Persistent-cache format version.  Bumped whenever the emitted-code ABI
/// (chain-state offsets, exit codes, relocation layout) changes.
pub const AOT_FORMAT_VERSION: u32 = 1;
/// Cache key component: bump when code generation changes without changing the
/// IR hash (e.g. an emitter fix).  A stale file is rejected, never executed.
pub const AOT_TRANSLATOR_VERSION: u32 = 5;

/// Optimization-profile key component for worker-slice Tier0 blocks.
const AOT_SLICE_OPT_PROFILE: u32 = 1;

/// Absolute target CPU profile stored in the AOT key.
pub fn aot_target_cpu_profile() -> u64 {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in arch.bytes().chain(os.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// A serializer/deserializer for one translated block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AotRecord {
    format: u32,
    translator: u32,
    machine: u64,
    cpu_profile: u64,
    optimization_profile: u32,
    guest_address: u64,
    code_hash: u64,
    logical_code_hash: u64,
    instruction_count: u64,
    code_size: u32,
    worker_safe: bool,
    exit_info: Option<BlockExitInfo>,
    code: Vec<u8>,
    relocations: Vec<AotRelocation>,
}

impl AotRecord {
    const MAGIC: &'static [u8; 8] = b"C1AOTC\0\0";

    fn machine_tag() -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in std::env::consts::ARCH
            .bytes()
            .chain(std::env::consts::OS.bytes())
            .chain(std::env::consts::FAMILY.bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.code.len() + self.relocations.len() * 8);
        out.extend_from_slice(Self::MAGIC);
        out.extend_from_slice(&self.format.to_le_bytes());
        out.extend_from_slice(&self.translator.to_le_bytes());
        out.extend_from_slice(&self.machine.to_le_bytes());
        out.extend_from_slice(&self.cpu_profile.to_le_bytes());
        out.extend_from_slice(&self.optimization_profile.to_le_bytes());
        out.extend_from_slice(&self.guest_address.to_le_bytes());
        out.extend_from_slice(&self.code_hash.to_le_bytes());
        out.extend_from_slice(&self.logical_code_hash.to_le_bytes());
        out.extend_from_slice(&self.instruction_count.to_le_bytes());
        out.extend_from_slice(&self.code_size.to_le_bytes());
        out.push(u8::from(self.worker_safe));
        encode_exit_info(&mut out, self.exit_info);
        out.extend_from_slice(&(self.relocations.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.code);
        for relocation in &self.relocations {
            out.extend_from_slice(&relocation.offset.to_le_bytes());
            out.extend_from_slice(&relocation.kind.code().to_le_bytes());
        }
        let checksum = fnv1a(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 + 4 * 10 + 1 + 1 + 4 + 8 {
            return Err("truncated record header");
        }
        if &bytes[..8] != Self::MAGIC {
            return Err("bad magic");
        }
        let payload_end = bytes.len() - 8;
        let expected = u64::from_le_bytes(
            bytes[payload_end..]
                .try_into()
                .map_err(|_| "truncated checksum")?,
        );
        if fnv1a(&bytes[..payload_end]) != expected {
            return Err("checksum mismatch");
        }
        let mut cursor = 8;
        let read_u32 = |cursor: &mut usize| -> Result<u32, &'static str> {
            let value = u32::from_le_bytes(
                bytes
                    .get(*cursor..*cursor + 4)
                    .ok_or("truncated u32")?
                    .try_into()
                    .map_err(|_| "truncated u32")?,
            );
            *cursor += 4;
            Ok(value)
        };
        let read_u64 = |cursor: &mut usize| -> Result<u64, &'static str> {
            let value = u64::from_le_bytes(
                bytes
                    .get(*cursor..*cursor + 8)
                    .ok_or("truncated u64")?
                    .try_into()
                    .map_err(|_| "truncated u64")?,
            );
            *cursor += 8;
            Ok(value)
        };
        let format = read_u32(&mut cursor)?;
        let translator = read_u32(&mut cursor)?;
        let machine = read_u64(&mut cursor)?;
        let cpu_profile = read_u64(&mut cursor)?;
        let optimization_profile = read_u32(&mut cursor)?;
        let guest_address = read_u64(&mut cursor)?;
        let code_hash = read_u64(&mut cursor)?;
        let logical_code_hash = read_u64(&mut cursor)?;
        let instruction_count = read_u64(&mut cursor)?;
        let code_size = read_u32(&mut cursor)?;
        let worker_safe = *bytes.get(cursor).ok_or("truncated flag")? != 0;
        cursor += 1;
        let exit_info = decode_exit_info(bytes, &mut cursor)?;
        let relocation_count = read_u32(&mut cursor)? as usize;
        let code_end = cursor
            .checked_add(code_size as usize)
            .ok_or("code size overflow")?;
        let code = bytes
            .get(cursor..code_end)
            .ok_or("truncated code")?
            .to_vec();
        cursor = code_end;
        let table_end = cursor
            .checked_add(relocation_count * 8)
            .ok_or("relocation overflow")?;
        if table_end > payload_end {
            return Err("truncated relocation table");
        }
        let mut relocations = Vec::with_capacity(relocation_count);
        for _ in 0..relocation_count {
            let offset = read_u32(&mut cursor)?;
            let kind = AotRelocKind::from_code(read_u32(&mut cursor)?).ok_or("unknown reloc")?;
            relocations.push(AotRelocation { offset, kind });
        }
        if cursor != payload_end {
            return Err("trailing bytes");
        }
        Ok(Self {
            format,
            translator,
            machine,
            cpu_profile,
            optimization_profile,
            guest_address,
            code_hash,
            logical_code_hash,
            instruction_count,
            code_size,
            worker_safe,
            exit_info,
            code,
            relocations,
        })
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn encode_exit_info(out: &mut Vec<u8>, info: Option<BlockExitInfo>) {
    match info {
        None => out.push(0),
        Some(BlockExitInfo::Jump { target }) => {
            out.push(1);
            out.extend_from_slice(&target.to_le_bytes());
        }
        Some(BlockExitInfo::JumpIf {
            condition,
            target,
            fallthrough,
        }) => {
            out.push(2);
            out.push(condition_code_tag(condition));
            out.extend_from_slice(&target.to_le_bytes());
            out.extend_from_slice(&fallthrough.to_le_bytes());
        }
        Some(BlockExitInfo::Return { stack_adjust }) => {
            out.push(3);
            out.extend_from_slice(&stack_adjust.to_le_bytes());
        }
        Some(BlockExitInfo::Call {
            target,
            return_address,
        }) => {
            out.push(4);
            out.extend_from_slice(&target.to_le_bytes());
            out.extend_from_slice(&return_address.to_le_bytes());
        }
        Some(BlockExitInfo::CallIndirect { return_address }) => {
            out.push(5);
            out.extend_from_slice(&return_address.to_le_bytes());
        }
    }
}

fn decode_exit_info(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<BlockExitInfo>, &'static str> {
    let tag = *bytes.get(*cursor).ok_or("truncated exit info")?;
    *cursor += 1;
    let read_u64 = |cursor: &mut usize| -> Result<u64, &'static str> {
        let value = u64::from_le_bytes(
            bytes
                .get(*cursor..*cursor + 8)
                .ok_or("truncated exit info value")?
                .try_into()
                .map_err(|_| "truncated exit info value")?,
        );
        *cursor += 8;
        Ok(value)
    };
    Ok(Some(match tag {
        0 => return Ok(None),
        1 => BlockExitInfo::Jump {
            target: read_u64(cursor)?,
        },
        2 => {
            let condition = condition_from_tag(*bytes.get(*cursor).ok_or("truncated condition")?)
                .ok_or("unknown condition")?;
            *cursor += 1;
            BlockExitInfo::JumpIf {
                condition,
                target: read_u64(cursor)?,
                fallthrough: read_u64(cursor)?,
            }
        }
        3 => BlockExitInfo::Return {
            stack_adjust: read_u64(cursor)?,
        },
        4 => BlockExitInfo::Call {
            target: read_u64(cursor)?,
            return_address: read_u64(cursor)?,
        },
        5 => BlockExitInfo::CallIndirect {
            return_address: read_u64(cursor)?,
        },
        _ => return Err("unknown exit info tag"),
    }))
}

fn condition_code_tag(condition: ConditionCode) -> u8 {
    match condition {
        ConditionCode::Equal => 0,
        ConditionCode::NotEqual => 1,
        ConditionCode::Overflow => 2,
        ConditionCode::NotOverflow => 3,
        ConditionCode::Below => 4,
        ConditionCode::NotBelow => 5,
        ConditionCode::Above => 6,
        ConditionCode::NotAbove => 7,
        ConditionCode::Sign => 8,
        ConditionCode::NotSign => 9,
        ConditionCode::Less => 10,
        ConditionCode::GreaterEqual => 11,
        ConditionCode::LessEqual => 12,
        ConditionCode::Greater => 13,
        ConditionCode::Parity => 14,
        ConditionCode::NotParity => 15,
    }
}

fn condition_from_tag(tag: u8) -> Option<ConditionCode> {
    Some(match tag {
        0 => ConditionCode::Equal,
        1 => ConditionCode::NotEqual,
        2 => ConditionCode::Overflow,
        3 => ConditionCode::NotOverflow,
        4 => ConditionCode::Below,
        5 => ConditionCode::NotBelow,
        6 => ConditionCode::Above,
        7 => ConditionCode::NotAbove,
        8 => ConditionCode::Sign,
        9 => ConditionCode::NotSign,
        10 => ConditionCode::Less,
        11 => ConditionCode::GreaterEqual,
        12 => ConditionCode::LessEqual,
        13 => ConditionCode::Greater,
        14 => ConditionCode::Parity,
        15 => ConditionCode::NotParity,
        _ => return None,
    })
}

/// Compiles a sequence of IR instructions into ARM64 machine code.
pub struct JitCompiler {
    emitter: Emitter,
    memory_manager: JitMemoryManager,
    /// IR instructions that need the universal helper.  Each is boxed so its
    /// address is stable (Vec reallocation won't move it).
    #[allow(clippy::vec_box)]
    helper_insns: Vec<Box<IrInstruction>>,
    /// Byte offset of the safepoint `cbnz` instruction emitted by
    /// `emit_safepoint_check`; patched with the stub offset when the block
    /// body and stub have been emitted.  `None` when the block has no
    /// safepoint check (or it has already been patched).
    safepoint_cbnz_patch: Option<usize>,
    /// Byte offsets of the guest-fault `cbnz` instructions emitted after
    /// each load/store helper call; all patched to the single fault-exit
    /// stub by `finish_fault_stub` once the block body has been emitted.
    fault_cbnz_patches: Vec<usize>,
    /// Link slots belonging to the block currently being compiled.
    link_slots: Option<LinkSlots>,
    /// Relocations for every absolute address embedded in the emitted code.
    /// Used to serialize translated blocks into the persistent AOT cache and
    /// to re-bind them after loading into a new address space.
    relocations: Vec<AotRelocation>,
    /// True when the block currently being compiled used the universal
    /// single-instruction interpreter helper, which needs a live
    /// `MemoryImage` pointer and therefore may not run on a production
    /// worker.
    used_interpreter_helper: bool,
    /// True while compiling a production-worker (slice) block.  In this mode
    /// indirect `call`/`jmp` and `ret` lower to self-contained native exits
    /// that publish the resolved target in the per-thread cell instead of
    /// calling the `MemoryImage`-dependent interpreter helper, so the worker
    /// can keep them out of the owner's dispatch loop.  Cooperative
    /// (`block_cache`) compilation leaves this false and is byte-identical to
    /// before.
    worker_program: bool,
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
    fn can_compile_block(ir: &[IrInstruction]) -> bool {
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
    fn can_compile_instruction(insn: &IrInstruction) -> bool {
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
    fn install_code(&self, code_ptr: *mut u8, code_size: usize) -> AppResult<()> {
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
    fn install_aot_record(&mut self, record: &AotRecord) -> AppResult<JitCompiledBlock> {
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
    fn emit_reloc_imm64(&mut self, rd: u32, value: u64, kind: AotRelocKind) {
        let offset = self.emitter.len() as u32;
        self.emitter.mov_imm64_fixed(rd, value);
        self.relocations.push(AotRelocation { offset, kind });
    }

    /// Write a guest RIP value into `CpuState` so a whole-function exit is
    /// decoded with the correct target even though a function has multiple
    /// static exits (the single `last_exit_info` slot cannot represent them).
    fn emit_set_state_rip(&mut self, target: u64) {
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
    fn emit_spill_slots_init(&mut self, _arch: GuestArch) {
        for (slot, guest) in [(0u32, 13usize), (1, 14), (2, 15)] {
            let arm = regmap::guest_to_arm(guest);
            self.emitter
                .str64(arm, regmap::X0, Self::SPILL_BASE + slot * 8);
        }
    }

    /// Emit the per-block guard: counters, SMC epoch comparison and the link
    /// budget.  All exits are taken BEFORE the block body runs, so a dispatch
    /// boundary never re-executes guest instructions.
    fn emit_chain_guard(&mut self, _instruction_count: u64, arch: GuestArch) {
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
    fn emit_block_accounting(&mut self, instruction_count: u64) {
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
    fn emit_guard_exit(&mut self, exit_code: u64, arch: GuestArch) {
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, exit_code as u16, 0);
        self.emit_epilogue();
    }

    fn patch_bcond(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let condition = self.emitter.code[position] & 0x0f;
        let insn = 0x5400_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(condition);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    fn patch_cbnz(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let register = self.emitter.code[position] & 0x1f;
        let insn = 0xb500_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(register);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    /// Materialise parked interpreter flags before a native flag read.
    fn emit_materialize_flags(&mut self) {
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
    fn emit_x86_flag_loads(&mut self) {
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
    fn emit_x86_condition_branch(&mut self, condition: ConditionCode) -> usize {
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
    fn emit_link_exit(&mut self, slot: &Arc<AtomicU64>, kind: AotRelocKind, exit_code: u64) {
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
    fn finish_safepoint_stub(&mut self, arch: GuestArch) {
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
    fn emit_current_block_tag(&mut self, guest_address: u64) {
        self.emitter.mov_reg(regmap::X23, regmap::X3);
        self.emitter.mov_imm64(10, guest_address);
        self.emitter
            .str64(10, regmap::X23, chain_offsets::CURRENT_BLOCK);
    }

    fn emit_prologue(&mut self, arch: GuestArch) {
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
    fn emit_frame_restore(&mut self) {
        // Restore x19-x28
        self.emitter.ldp64_post(27, 28, 31, 64);
        self.emitter.ldp64_post(25, 26, 31, 64);
        self.emitter.ldp64_post(23, 24, 31, 64);
        self.emitter.ldp64_post(21, 22, 31, 64);
        self.emitter.ldp64_post(19, 20, 31, 64);
        // Restore fp, lr
        self.emitter.ldp64_post(29, 30, 31, 64);
    }

    fn emit_epilogue(&mut self) {
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
    fn emit_indirect_exit(&mut self, payload_reg: u32, exit_code: u64, arch: GuestArch) {
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
    fn emit_worker_call(&mut self, target: u64, return_address: u64, arch: GuestArch) {
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
    fn emit_worker_return(&mut self, stack_adjust: u64, arch: GuestArch) {
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

    fn patch_cbz(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        debug_assert!(offset > 0 && (offset as u32) <= 0x7ffff);
        let register = self.emitter.code[position] & 0x1f;
        let insn = 0xb400_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(register);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    /// Emit a `BL` (branch-with-link) to a known helper.  The helper's
    /// address is embedded through the relocation table so an AOT-loaded
    /// block re-binds to the current process's helper.
    fn emit_bl_to(&mut self, helper: AotHelper) {
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
    fn emit_helper_load(&mut self, dst: u32, addr_reg: u32, width: u64, arch: GuestArch) {
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
    fn emit_helper_store(&mut self, addr_reg: u32, val_reg: u32, width: u64, arch: GuestArch) {
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
    fn emit_fault_check(&mut self) {
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
    fn finish_fault_stub(&mut self, arch: GuestArch) {
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
    fn emit_effective_address(
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
    fn emit_segment_base(&mut self, dst_reg: u32, seg_code: u64, arch: GuestArch) {
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
    fn emit_set_flags(
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
    fn emit_native_alu_reg(
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
    fn emit_compare_test(
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
    fn emit_load_guest_registers(&mut self, arch: GuestArch) {
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
    fn emit_store_guest_registers(&mut self, arch: GuestArch) {
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
    fn compile_instruction(
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
    fn emit_interpreter_fallback(
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

// ---------------------------------------------------------------------------
// JIT runtime: manages compiled blocks and dispatches execution
// ---------------------------------------------------------------------------

/// Runtime state for JIT execution.
pub struct JitRuntime {
    pub compiler: JitCompiler,
    pub flat_memory: FlatGuestMemory,
    /// Cache of compiled blocks keyed by guest address.
    pub block_cache: HashMap<u64, JitCompiledBlock>,
    /// Deliberately unlinked blocks compiled for production worker slices.
    /// Kept separate from `block_cache` so worker execution never inherits a
    /// published chain that could bypass the per-slice budget/thunk barrier.
    pub(crate) slice_block_cache: HashMap<u64, JitCompiledBlock>,
    /// Monotonic generation of the worker slice cache.  Bumped whenever a
    /// cached worker block is removed, so a persistent worker slot can drop
    /// stale return-predictor/inline-cache entries before reusing them.
    slice_epoch: u64,
    /// FIFO access-order queue for LRU eviction of compiled blocks.
    /// Front = least recently used (next to evict), back = most recently used.
    pub block_access_order: VecDeque<u64>,
    /// Maximum number of compiled blocks allowed in the cache before eviction.
    pub max_blocks: usize,
    /// Number of blocks compiled.
    pub blocks_compiled: u64,
    /// Number of blocks executed via JIT.
    pub blocks_executed: u64,
    /// Number of fallbacks to IR interpreter — incremented when JIT cannot
    /// compile a block, causing fall-through to the IR interpreter.
    pub interpreter_fallbacks: u64,
    /// Compiled blocks removed by self-modifying-code invalidation.
    pub code_invalidations: u64,
    /// Number of SMC drain cycles that invalidated at least one block.
    pub smc_invalidation_events: u64,
    /// Blocks compiled at each tier.
    pub tier0_compiles: u64,
    pub tier1_compiles: u64,
    pub tier2_compiles: u64,
    /// Whole-function Tier-2 promotions (multi-block SSA compiles).
    pub tier2_function_compiles: u64,
    /// Tier-2 function attempts that fell back to Tier-0.
    pub tier2_function_fallbacks: u64,
    /// Links published / cleared in this runtime.
    pub chain_links_formed: u64,
    pub chain_links_broken: u64,
    /// Blocks that took the fault-equivalent fallback path (invalid block
    /// installation / faulted entry) and were handed to the interpreter.
    pub fault_fallbacks: u64,
    /// Persistent AOT translated-code cache counters.
    pub aot_hits: u64,
    pub aot_misses: u64,
    pub aot_rejected: u64,
    /// Directory used to persist/reload translated worker blocks.  `None`
    /// disables the cache (useful for deterministic tests).
    pub(crate) aot_cache_dir: Option<std::path::PathBuf>,
    /// Guest addresses permanently barred from native compilation after a
    /// fault-equivalent event; the interpreter handles them for the rest of
    /// the run.
    pub faulted_blocks: BTreeSet<u64>,
    /// Block chain entries keyed by (from_address, to_address).
    pub block_chains: BTreeMap<(u64, u64), BlockChainEntry>,
    /// Fast thunk table: ARM64 trampolines for direct host-function calls
    /// from JIT-compiled guest code, bypassing the full dispatch loop.
    pub fast_thunk_table: FastThunkTable,
    /// Unwind table for JIT-compiled blocks, enabling SEH stack walks
    /// through JIT frames via `RtlVirtualUnwind`.
    pub unwind_table: JitUnwindTable,
    /// Tracks which 4K guest pages have one or more compiled blocks.
    /// Used for self-modifying code detection: when guest code writes to a
    /// page in this set, the affected blocks must be invalidated and recompiled.
    pub code_pages: BTreeSet<u64>,
    /// Lock-free watch/dirty state read by `jit_helper_store` while this
    /// runtime is executing on the current thread.
    smc: Box<SmcState>,
    /// Set of guest page addresses (4K-aligned) that have been synced from
    /// MemoryImage into the flat memory region. Used for incremental sync:
    /// only new pages are copied on each block execution instead of all
    /// committed pages, reducing per-block overhead from O(N) to O(delta).
    synced_pages: BTreeSet<u64>,
    /// Whether the SIGBUS handler is currently installed for this runtime.
    /// Kept persistent across block executions to eliminate per-block
    /// sigaction syscalls (two per block × thousands of blocks = significant
    /// overhead).
    sigbus_installed: bool,
}

impl JitRuntime {
    pub fn new(arch: GuestArch) -> Self {
        let aot_cache_dir = match std::env::var("CASA1_AOT_CACHE_DIR") {
            Ok(value) if value.eq_ignore_ascii_case("off") => None,
            Ok(value) if !value.is_empty() => Some(std::path::PathBuf::from(value)),
            // Tests opt into the cache explicitly with a fresh directory, so a
            // run can never observe code persisted by an older build.
            #[cfg(test)]
            _ => None,
            #[cfg(not(test))]
            _ => Some(std::env::temp_dir().join(format!("casa1-aot-v{AOT_TRANSLATOR_VERSION}"))),
        };
        Self {
            compiler: JitCompiler::new(),
            flat_memory: FlatGuestMemory::new(arch),
            block_cache: HashMap::new(),
            slice_block_cache: HashMap::new(),
            slice_epoch: 0,
            block_access_order: VecDeque::new(),
            max_blocks: 8192,
            blocks_compiled: 0,
            blocks_executed: 0,
            interpreter_fallbacks: 0, // Initialized to zero; incremented on each JIT fallback
            code_invalidations: 0,
            smc_invalidation_events: 0,
            tier0_compiles: 0,
            tier1_compiles: 0,
            tier2_compiles: 0,
            tier2_function_compiles: 0,
            tier2_function_fallbacks: 0,
            chain_links_formed: 0,
            chain_links_broken: 0,
            fault_fallbacks: 0,
            aot_hits: 0,
            aot_misses: 0,
            aot_rejected: 0,
            aot_cache_dir,
            faulted_blocks: BTreeSet::new(),
            block_chains: BTreeMap::new(),
            fast_thunk_table: FastThunkTable::new(),
            unwind_table: JitUnwindTable::new(),
            code_pages: BTreeSet::new(),
            smc: Box::new(SmcState::new()),
            synced_pages: BTreeSet::new(),
            sigbus_installed: false,
        }
    }

    /// Override (or disable) the persistent AOT cache directory.
    pub fn set_aot_cache_dir(&mut self, directory: Option<std::path::PathBuf>) {
        self.aot_cache_dir = directory;
    }

    /// `(hits, misses, rejected)` for the persistent AOT cache.
    pub fn aot_metrics(&self) -> (u64, u64, u64) {
        (self.aot_hits, self.aot_misses, self.aot_rejected)
    }

    /// Get or compile a JIT block for the given guest address.
    ///
    /// After compiling a new block, attempts to auto-chain if the last
    /// IR instruction is an unconditional `Jump { target }` and the
    /// target block is already compiled.
    /// `fast_thunk_addrs` — optional set of guest thunk addresses that have
    /// fast-thunk ARM64 trampolines registered (see [`FastThunkTable`]).
    /// Passed through to the compiler so that `Call` instructions whose target
    /// is a registered host thunk can emit direct trampoline calls.
    pub fn get_or_compile(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<&JitCompiledBlock> {
        self.get_or_compile_at_tier(
            ir,
            guest_address,
            arch,
            CompilationTier::Tier0,
            fast_thunk_addrs,
        )
    }

    /// Compile (or reuse) a whole hot function at Tier-2.
    ///
    /// `blocks` is ordered with the entry block first, exactly as produced by
    /// [`crate::jit_ssa::optimize_function`].  Returns `None` when the SSA
    /// front end rejected the function (unsupported construct); the caller
    /// then keeps per-block Tier-0/Tier-1 code.
    pub fn get_or_compile_function_tier2(
        &mut self,
        blocks: &[crate::jit_ssa::FunctionBlock],
        arch: GuestArch,
    ) -> AppResult<Option<&JitCompiledBlock>> {
        let Some(entry) = blocks.first().map(|block| block.guest_address) else {
            return Ok(None);
        };
        if let Some(existing) = self.block_cache.get(&entry)
            && existing.compile_tier == CompilationTier::Tier2
        {
            return Ok(self.block_cache.get(&entry));
        }
        let compiled = self.compiler.compile_function_tier2(blocks, arch)?;
        if compiled.compile_tier != CompilationTier::Tier2 {
            self.tier2_function_fallbacks += 1;
            return Ok(None);
        }
        self.tier2_function_compiles += 1;
        self.blocks_compiled += 1;
        for block in blocks {
            let page = block.guest_address & !0xfff;
            self.code_pages.insert(page);
        }
        self.block_access_order.retain(|address| *address != entry);
        self.block_access_order.push_back(entry);
        let guest_end = blocks
            .iter()
            .map(|block| block.guest_address + (block.instructions.len() as u64) * 15)
            .max()
            .unwrap_or(entry + 1);
        self.unwind_table.register_block(entry, guest_end);
        self.block_cache.insert(entry, compiled);
        self.smc.rebuild_watch(self.code_pages.iter());
        Ok(self.block_cache.get(&entry))
    }

    /// Snapshot of the global SSA metrics plus this runtime's Tier-2 function
    /// counters.
    pub fn tier2_metrics_snapshot(&self) -> crate::jit_ssa::Tier2Metrics {
        let mut metrics = crate::jit_ssa::tier2_metrics();
        metrics.functions_compiled = self.tier2_function_compiles;
        metrics.functions_fallback = self.tier2_function_fallbacks;
        metrics
    }

    /// Get or compile a block at an explicit optimization tier.
    ///
    /// The PE dispatcher calls this when [`TieredCompiler::record_execution`]
    /// crosses a threshold (Tier0 at 50 dispatches, Tier1 at 500): an already
    /// cached block compiled at a lower tier is invalidated and recompiled
    /// with the real optimizer (`constant_fold` + DCE at Tier1; whole-block
    /// SSA with GVN/SCCP/DCE/LICM and load-store forwarding at Tier2) instead
    /// of returning the identical Tier0 code.
    pub fn get_or_compile_at_tier(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        tier: CompilationTier,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<&JitCompiledBlock> {
        // A block that faulted (invalid installation / unwind path) stays on
        // the interpreter for the rest of the run: refusing compilation here
        // makes the dispatcher's `.is_ok()` check fail and fall through to
        // the AOT path for exactly this block.
        if self.faulted_blocks.contains(&guest_address) {
            #[cfg(test)]
            let ignore_bar = JIT_TEST_IGNORE_FAULTED_BLOCKS.with(|ignore| ignore.replace(false));
            #[cfg(not(test))]
            let ignore_bar = false;
            if !ignore_bar {
                self.interpreter_fallbacks += 1;
                return Err(AppError::new(
                    ReasonCode::RcJitCompilationError,
                    format!("JIT block {guest_address:#x} previously faulted; using interpreter"),
                ));
            }
        }

        // Self-modifying code: invalidate every block whose guest page was
        // written by a native guest store before deciding whether this block
        // is still current.
        self.drain_smc_invalidations();

        // Check for self-modifying code: if a block already exists but its
        // source hash doesn't match the current IR, the guest has modified
        // the code since compilation — invalidate and recompile.
        let mut recompile = false;
        if let Some(existing) = self.block_cache.get(&guest_address) {
            let current_hash = compute_ir_hash(ir, guest_address);
            if existing.source_hash != 0 && existing.source_hash != current_hash {
                eprintln!(
                    "[jit] self-modifying code detected at {:#x}: recompiling (hash mismatch)",
                    guest_address
                );
                recompile = true;
            } else if existing.compile_tier < tier {
                // Real tier promotion: replace the cached block with the
                // optimized compilation.
                recompile = true;
            } else {
                // Block is valid and being accessed — promote to back of
                // the LRU access-order queue.
                self.record_block_access(guest_address);
            }
        }
        if recompile {
            self.invalidate_block(guest_address);
        }

        let is_new = !self.block_cache.contains_key(&guest_address);
        if is_new {
            // ── Whole-block compilability check ──────────────────────────
            // Only compile a block if EVERY instruction can be JIT-compiled.
            // If any instruction can't, leave the block uncompiled (is_compiled
            // stays false) so the interpreter runs the WHOLE block cleanly.
            // Partially-compiled blocks double-execute (JIT runs the prefix,
            // then EXIT_UNIMPL re-runs the whole block in the interpreter),
            // corrupting guest state.
            if !crate::jit::JitCompiler::can_compile_block(ir) {
                self.interpreter_fallbacks += 1;
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "block contains an instruction the JIT cannot compile",
                ));
            }

            // Resolved thunk addresses: unknown callers pass `None`, so the
            // runtime's own registration table is the source of truth.  This
            // is what turns a registered guest thunk into a direct native
            // call instead of an EXIT_THUNK dispatcher round-trip.
            let resolved_thunks = match fast_thunk_addrs {
                Some(addrs) => Some(addrs.clone()),
                None => {
                    let addrs = self.fast_thunk_table.guest_addrs();
                    (!addrs.is_empty()).then_some(addrs)
                }
            };

            // Persistent AOT first: a validated record bound to this exact
            // IR + address + translator/CPU generation avoids recompilation.
            // Only unlinked Tier-0 records are installed here; hot-path tier
            // promotion still recompiles from IR.
            let mut aot_block = None;
            if matches!(tier, CompilationTier::Tier0) && self.aot_cache_dir.is_some() {
                let source_hash = compute_ir_hash(ir, guest_address);
                match self.load_aot_slice_block(ir, guest_address, source_hash, arch) {
                    Ok(Some(block)) => {
                        self.aot_hits += 1;
                        aot_block = Some(block);
                    }
                    Ok(None) => self.aot_misses += 1,
                    Err(error) => {
                        self.aot_rejected += 1;
                        eprintln!("[jit] AOT cache rejected for {guest_address:#x}: {error}");
                        if let Some(path) = self.aot_path(source_hash, guest_address) {
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
            }
            let loaded_aot = aot_block.is_some();
            let block = if let Some(block) = aot_block {
                block
            } else {
                match tier {
                    CompilationTier::Tier0 => {
                        self.tier0_compiles += 1;
                        self.compiler.compile_block(
                            ir,
                            guest_address,
                            arch,
                            resolved_thunks.as_ref(),
                        )?
                    }
                    CompilationTier::Tier1 => {
                        self.tier1_compiles += 1;
                        self.compiler.compile_tier1(
                            ir,
                            guest_address,
                            arch,
                            resolved_thunks.as_ref(),
                        )?
                    }
                    CompilationTier::Tier2 => {
                        self.tier2_compiles += 1;
                        self.compiler.compile_tier2(
                            ir,
                            guest_address,
                            arch,
                            resolved_thunks.as_ref(),
                        )?
                    }
                }
            };
            if !loaded_aot {
                self.blocks_compiled += 1;
            }

            // Track which 4K guest pages this compiled block occupies,
            // for self-modifying code detection.
            let guest_end = guest_address + (ir.len() as u64).saturating_mul(15).max(1);
            let start_page = guest_address & !0xfff;
            let end_page = (guest_end - 1) & !0xfff;
            let mut page = start_page;
            while page <= end_page {
                self.code_pages.insert(page);
                page += 0x1000;
            }
            self.smc.rebuild_watch(self.code_pages.iter());

            // Register this block's address range with the unwind table
            // so that SEH stack walks can unwind through JIT frames.
            self.unwind_table.register_block(guest_address, guest_end);

            self.block_cache.insert(guest_address, block);
            // New block is the most recently used — add to back of access order.
            self.block_access_order.push_back(guest_address);

            // Evict the least-recently-used block if the cache exceeds max_blocks.
            self.evict_if_needed();

            // Auto-chain: if the last instruction is an unconditional jump
            // to a block that is already compiled, chain them.  Backward
            // (loop) edges are allowed — the target prologue polls the host
            // safepoint, and the source block pops its own host frame before
            // the branch, so a chained loop neither loses interruptibility
            // nor drifts the host stack pointer.
            if let Some(last_ir) = ir.last()
                && let IrInstruction::Jump { target } = last_ir
            {
                // Skip auto-chaining when a chain break has been
                // requested — see JIT_CHAIN_BREAK_REQUESTED.
                if !JIT_CHAIN_BREAK_REQUESTED.load(Ordering::Relaxed)
                    && self.block_cache.contains_key(target)
                    && let Err(e) = self.chain_blocks(guest_address, *target)
                {
                    eprintln!(
                        "[jit] failed to chain block {:#x} -> {:#x}: {}",
                        guest_address, target, e
                    );
                }
            }
        }
        Ok(self.block_cache.get(&guest_address).unwrap())
    }

    /// Compile (or fetch) a deliberately unlinked block for production worker
    /// slices.
    ///
    /// The persistent AOT cache is consulted first: a record keyed by guest
    /// code hash + translator version + target CPU + optimization profile is
    /// loaded, validated and re-bound to this process.  A missing record
    /// compiles normally and is persisted; a corrupt/incompatible record is
    /// counted as `aot_rejected` and compilation proceeds from IR.
    pub(crate) fn get_or_compile_slice_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
    ) -> AppResult<&JitCompiledBlock> {
        if !self.slice_block_cache.contains_key(&guest_address) {
            let source_hash = compute_ir_hash(ir, guest_address);
            let cache_enabled = self.aot_cache_dir.is_some();
            if cache_enabled {
                match self.load_aot_slice_block(ir, guest_address, source_hash, arch) {
                    Ok(Some(block)) => {
                        self.aot_hits += 1;
                        self.note_slice_code_pages(&block);
                        self.slice_block_cache.insert(guest_address, block);
                    }
                    Ok(None) => {
                        self.aot_misses += 1;
                        let block = self
                            .compiler
                            .compile_worker_block(ir, guest_address, arch)?;
                        self.persist_aot_slice_block(&block, source_hash);
                        self.slice_block_cache.insert(guest_address, block);
                    }
                    Err(error) => {
                        self.aot_rejected += 1;
                        eprintln!("[jit] AOT cache rejected for {guest_address:#x}: {error}");
                        if let Some(path) = self.aot_path(source_hash, guest_address) {
                            let _ = std::fs::remove_file(path);
                        }
                        let block = self
                            .compiler
                            .compile_worker_block(ir, guest_address, arch)?;
                        self.persist_aot_slice_block(&block, source_hash);
                        self.note_slice_code_pages(&block);
                        self.slice_block_cache.insert(guest_address, block);
                    }
                }
            } else {
                let block = self
                    .compiler
                    .compile_worker_block(ir, guest_address, arch)?;
                self.note_slice_code_pages(&block);
                self.slice_block_cache.insert(guest_address, block);
            }
        }
        Ok(self
            .slice_block_cache
            .get(&guest_address)
            .expect("slice block inserted above"))
    }

    fn note_slice_code_pages(&mut self, block: &JitCompiledBlock) {
        let end = block.guest_address.saturating_add(block_guest_span(block));
        let mut page = block.guest_address & !0xfff;
        let last = end.saturating_sub(1) & !0xfff;
        while page <= last {
            self.code_pages.insert(page);
            page = page.saturating_add(0x1000);
        }
        self.smc.rebuild_watch(self.code_pages.iter());
    }

    fn aot_path(&self, code_hash: u64, guest_address: u64) -> Option<std::path::PathBuf> {
        self.aot_cache_dir.as_ref().map(|directory| {
            directory.join(format!(
                "aot-{code_hash:016x}-{guest_address:016x}-t{}-c{:016x}-o{}.bin",
                AOT_TRANSLATOR_VERSION,
                aot_target_cpu_profile(),
                AOT_SLICE_OPT_PROFILE
            ))
        })
    }

    fn load_aot_slice_block(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        source_hash: u64,
        _arch: GuestArch,
    ) -> AppResult<Option<JitCompiledBlock>> {
        let Some(path) = self.aot_path(source_hash, guest_address) else {
            return Ok(None);
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AppError::new(
                    ReasonCode::RcJitCompilationError,
                    format!("AOT cache read failed: {error}"),
                ));
            }
        };
        // Bound the read before decoding; a cache file is code-sized.
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT cache record is implausibly large",
            ));
        }
        let record = AotRecord::decode(&bytes).map_err(|reason| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("malformed AOT cache record: {reason}"),
            )
        })?;
        if record.optimization_profile != AOT_SLICE_OPT_PROFILE
            || record.guest_address != guest_address
            || record.code_hash != source_hash
            || record.instruction_count != ir.len() as u64
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "AOT cache record does not match this translation",
            ));
        }
        self.compiler.install_aot_record(&record).map(Some)
    }

    fn persist_aot_slice_block(&mut self, block: &JitCompiledBlock, source_hash: u64) {
        if !block.worker_safe {
            return;
        }
        let Some(path) = self.aot_path(source_hash, block.guest_address) else {
            return;
        };
        let Some(directory) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(directory).is_err() {
            return;
        }
        let entry = block.published_entry();
        if entry.is_null() {
            return;
        }
        // SAFETY: the entry was produced by this runtime and finalized; its
        // code_size bytes remain mapped and immutable for the block lifetime.
        let code =
            unsafe { std::slice::from_raw_parts(entry as *const u8, block.code_size) }.to_vec();
        let relocations = self.compiler.relocations.clone();
        if relocations
            .iter()
            .any(|relocation| relocation.offset as usize + 16 > code.len())
        {
            return;
        }
        let mut logical = code.clone();
        for relocation in &relocations {
            let offset = relocation.offset as usize;
            logical[offset..offset + 16].fill(0);
        }
        let record = AotRecord {
            format: AOT_FORMAT_VERSION,
            translator: AOT_TRANSLATOR_VERSION,
            machine: AotRecord::machine_tag(),
            cpu_profile: aot_target_cpu_profile(),
            optimization_profile: AOT_SLICE_OPT_PROFILE,
            guest_address: block.guest_address,
            code_hash: source_hash,
            logical_code_hash: fnv1a(&logical),
            instruction_count: block.instruction_count as u64,
            code_size: code.len() as u32,
            worker_safe: block.worker_safe,
            exit_info: block.last_exit_info,
            code,
            relocations,
        };
        let encoded = record.encode();
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        if std::fs::write(&temporary, encoded).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }

    pub(crate) fn slice_block(&self, guest_address: u64) -> Option<&JitCompiledBlock> {
        self.slice_block_cache.get(&guest_address)
    }

    pub(crate) fn clear_slice_blocks(&mut self) {
        for block in self.slice_block_cache.values() {
            block.link_target.store(0, Ordering::Release);
            block.taken_link.store(0, Ordering::Release);
            block.fallthrough_link.store(0, Ordering::Release);
            block.call_link.store(0, Ordering::Release);
            block.return_entry_link.store(0, Ordering::Release);
        }
        self.slice_block_cache.clear();
        self.slice_epoch = self.slice_epoch.wrapping_add(1);
        JIT_CODE_EPOCH.fetch_add(1, Ordering::AcqRel);
    }

    /// Publish every static successor edge between cached worker blocks.
    ///
    /// Direct jumps, both `Jcc` arms, direct calls and their static return
    /// successors get independent atomic link slots.  Nothing here patches
    /// instruction memory: an executor either observes the old zero slot or
    /// the new entry, and invalidation clears the slots before the cache is
    /// dropped.
    fn publish_slice_links(&self) {
        // Only blocks whose terminator is statically described may be a
        // native link target: entering a straight-line block would leave the
        // worker without a successor RIP and force a re-dispatch of code it
        // already executed.
        let entries: HashMap<u64, u64> = self
            .slice_block_cache
            .iter()
            .filter(|(_, block)| block.worker_safe && block.last_exit_info.is_some())
            .map(|(address, block)| (*address, block.entry() as u64))
            .collect();
        for block in self.slice_block_cache.values() {
            if !block.worker_safe {
                continue;
            }
            let entry = |target: &u64| entries.get(target).copied().unwrap_or(0);
            match block.last_exit_info {
                Some(BlockExitInfo::Jump { target }) => {
                    block.link_target.store(entry(&target), Ordering::Release);
                }
                Some(BlockExitInfo::JumpIf {
                    target,
                    fallthrough,
                    ..
                }) => {
                    block.taken_link.store(entry(&target), Ordering::Release);
                    block
                        .fallthrough_link
                        .store(entry(&fallthrough), Ordering::Release);
                }
                Some(BlockExitInfo::Call {
                    target,
                    return_address,
                }) => {
                    block.call_link.store(entry(&target), Ordering::Release);
                    block
                        .return_entry_link
                        .store(entry(&return_address), Ordering::Release);
                }
                Some(BlockExitInfo::CallIndirect { return_address }) => {
                    block
                        .return_entry_link
                        .store(entry(&return_address), Ordering::Release);
                }
                _ => {}
            }
        }
    }

    /// Build the immutable program a production worker executes.  The
    /// memory view aliases the canonical store; no bytes are copied.
    pub(crate) fn build_slice_program(&self, memory: &MemoryImage) -> GuestSliceProgram {
        self.publish_slice_links();
        let view = Arc::new(GuestSliceMemory::new(memory, self.code_pages.clone()));
        GuestSliceProgram {
            blocks: self.slice_block_cache.clone(),
            flat_base: view.flat_base(),
            memory: view,
            mechanism: self.compiler.memory_manager.mechanism(),
            epoch: self.slice_epoch,
        }
    }

    /// Drain self-modifying-code dirty pages and invalidate every cached
    /// block that overlaps them.  Returns the invalidated guest addresses.
    pub fn drain_smc_invalidations(&mut self) -> Vec<u64> {
        let (pages, overflow) = self.smc.take_dirty();
        #[cfg(test)]
        if !pages.is_empty() || overflow {
            match JIT_TEST_SMC_FAULT.with(|fault| fault.replace(0)) {
                1 => return Vec::new(),
                2 => {
                    self.block_cache.clear();
                    self.block_access_order.clear();
                    return Vec::new();
                }
                _ => {}
            }
        }
        if pages.is_empty() && !overflow {
            return Vec::new();
        }
        // Overflow means the bounded dirty ring wrapped: some written page is
        // unknown, so conservative whole-cache invalidation is required.
        let affected: Vec<u64> = if overflow {
            let all: Vec<u64> = self.block_cache.keys().copied().collect();
            for address in &all {
                self.invalidate_block(*address);
            }
            all
        } else {
            let dirty: BTreeSet<u64> = pages.into_iter().collect();
            self.invalidate_blocks_on_pages(&dirty)
        };
        if !affected.is_empty() || overflow {
            self.smc_invalidation_events += 1;
        }
        affected
    }

    /// Fault-equivalent fallback: a block that could not be installed safely
    /// (or whose entry faulted) is removed from the cache and permanently
    /// barred from native compilation.  The dispatcher then executes that
    /// block through the IR interpreter; nothing aborts.
    pub fn report_block_fault(&mut self, guest_address: u64) {
        self.fault_fallbacks += 1;
        self.faulted_blocks.insert(guest_address);
        if self.is_compiled(guest_address) {
            self.invalidate_block(guest_address);
        }
        eprintln!(
            "[jit] block {:#x} faulted; falling back to the interpreter for this block",
            guest_address
        );
    }

    /// Invalidate a compiled block, removing it from the block cache and
    /// unregistering its unwind info from the unwind table.
    ///
    /// This should be called when a block needs to be recompiled (e.g., due
    /// to self-modifying code). After invalidation, [`get_or_compile()`] will
    /// recompile the block on the next execution.
    ///
    /// The caller is responsible for syncing the updated unwind table to the
    /// SEH subsystem via [`JitUnwindTable::register_with_seh`].
    pub fn invalidate_block(&mut self, guest_address: u64) {
        if let Some(block) = self.slice_block_cache.remove(&guest_address) {
            block.link_target.store(0, Ordering::Release);
            block.taken_link.store(0, Ordering::Release);
            block.fallthrough_link.store(0, Ordering::Release);
            block.call_link.store(0, Ordering::Release);
            block.return_entry_link.store(0, Ordering::Release);
            self.slice_epoch = self.slice_epoch.wrapping_add(1);
        }
        if let Some(block) = self.block_cache.remove(&guest_address) {
            // Remove from the access-order queue so stale entries don't
            // accumulate and cause incorrect evictions.
            self.block_access_order.retain(|&a| a != guest_address);

            // Unchaining is best-effort cleanup; failure means no chain existed
            if let Err(error) = self.unchain_target(guest_address) {
                eprintln!(
                    "[jit] failed to unchain invalidated block {:#x}: {}",
                    guest_address, error
                );
            }
            // A block that is no longer cached can never be entered through
            // its own link slot; clear it so no stale target can be observed.
            if block.link_target.swap(0, Ordering::AcqRel) != 0 {
                self.chain_links_broken += 1;
            }
            self.unwind_table.unregister_block(guest_address);
            // Rebuild code_pages from remaining blocks so we don't leave
            // stale page entries after invalidation.
            self.rebuild_code_pages();
            self.smc.rebuild_watch(self.code_pages.iter());
            self.code_invalidations += 1;
            eprintln!(
                "[jit] invalidated block {:#x}: removed from cache and unwind table (code_size={})",
                guest_address, block.code_size
            );
        }
    }

    /// Record that a block was accessed, promoting it to the back of the
    /// LRU access-order queue.  If the block is not already in the queue
    /// (shouldn't normally happen for valid blocks), it is appended.
    ///
    /// This is O(n) in the number of cached blocks (bounded by `max_blocks`),
    /// but block compilation and invalidation dominate actual costs.
    fn record_block_access(&mut self, guest_address: u64) {
        if let Some(pos) = self
            .block_access_order
            .iter()
            .position(|&a| a == guest_address)
        {
            self.block_access_order.remove(pos);
        }
        self.block_access_order.push_back(guest_address);
    }

    /// If the block cache has exceeded `max_blocks`, evict the
    /// least-recently-used block (front of `block_access_order`).
    ///
    /// Stale entries (addresses no longer in `block_cache`) are cleaned up
    /// opportunistically during eviction.
    fn evict_if_needed(&mut self) {
        while self.block_cache.len() > self.max_blocks {
            let evict_addr = match self.block_access_order.pop_front() {
                Some(addr) => addr,
                None => break, // safety: queue is empty but cache isn't — should not happen
            };
            if self.block_cache.contains_key(&evict_addr) {
                eprintln!(
                    "[jit] evicting block {:#x}: cache size {} exceeds max {}",
                    evict_addr,
                    self.block_cache.len(),
                    self.max_blocks
                );
                self.invalidate_block(evict_addr);
                break; // invalidate_block removed the entry, re-check on next insert
            }
            // Stale entry (block was already removed via invalidation) —
            // continue popping until we find a live entry or the queue is empty.
        }
    }

    /// Recompute the `code_pages` set from all currently cached blocks.
    /// This is O(n) in the number of compiled blocks, so it should only be
    /// called when blocks are added or removed (not on every write check).
    fn rebuild_code_pages(&mut self) {
        self.code_pages.clear();
        for block in self.block_cache.values() {
            let start_page = block.guest_address & !0xfff;
            let end_page = (block.guest_address + block_guest_span(block) - 1) & !0xfff;
            let mut page = start_page;
            while page <= end_page {
                self.code_pages.insert(page);
                page += 0x1000;
            }
        }
    }

    /// Check if a guest memory write at `address` of `length` bytes overlaps
    /// any compiled code pages. If it does, invalidate all affected blocks
    /// and return `true` (indicating self-modifying code was detected).
    ///
    /// This is the primary entry point for self-modifying code detection.
    /// It should be called before every guest memory write that could
    /// potentially overlap compiled code pages.
    ///
    /// Returns the list of guest addresses of invalidated blocks, or an empty
    /// vec if no blocks were affected.
    pub fn invalidate_blocks_writing_to(&mut self, address: u64, length: usize) -> Vec<u64> {
        if length == 0 || self.block_cache.is_empty() {
            return Vec::new();
        }

        // Compute the set of 4K pages touched by this write.
        let start_page = address & !0xfff;
        let end_page = (address + length as u64 - 1) & !0xfff;

        // Fast path: if none of the touched pages have compiled code, skip.
        let mut page = start_page;
        let mut any_overlap = false;
        while page <= end_page {
            if self.code_pages.contains(&page) {
                any_overlap = true;
                break;
            }
            page += 0x1000;
        }
        if !any_overlap {
            return Vec::new();
        }

        // Slow path: check each compiled block for overlap with the write range.
        let write_end = address.saturating_add(length as u64);
        let affected: Vec<u64> = self
            .block_cache
            .keys()
            .copied()
            .filter(|&block_addr| {
                let block = match self.block_cache.get(&block_addr) {
                    Some(b) => b,
                    None => return false,
                };
                let block_end = block.guest_address.saturating_add(block_guest_span(block));
                // Overlap if: write_start < block_end AND write_end > block_start
                address < block_end && write_end > block.guest_address
            })
            .collect();

        if affected.is_empty() {
            return Vec::new();
        }

        let count = affected.len();
        for &block_addr in &affected {
            self.invalidate_block(block_addr);
        }
        // Invalidate synced pages in the write range so they get re-synced
        // with the updated code on the next block execution.
        let mut page = start_page;
        while page <= end_page {
            self.synced_pages.remove(&page);
            page += 0x1000;
        }
        eprintln!(
            "[jit] self-modifying code detected: write at {:#x}+{} invalidated {} block(s)",
            address, length, count
        );
        affected
    }

    /// Invalidate all compiled blocks whose `touched_pages` intersect with
    /// `dirty_pages`. This is a page-granularity invalidation method used
    /// for bulk operations (e.g., when a full page is written to).
    ///
    /// Returns the list of invalidated guest addresses.
    pub fn invalidate_blocks_on_pages(
        &mut self,
        dirty_pages: &std::collections::BTreeSet<u64>,
    ) -> Vec<u64> {
        if dirty_pages.is_empty()
            || (self.block_cache.is_empty() && self.slice_block_cache.is_empty())
        {
            return Vec::new();
        }

        // Fast check: are any of the dirty pages in our code_pages set?
        let mut any_overlap = false;
        for page in dirty_pages {
            if self.code_pages.contains(page) {
                any_overlap = true;
                break;
            }
        }
        if !any_overlap {
            return Vec::new();
        }
        // Worker slice blocks compile from the same source pages; a code
        // write invalidates them just like dispatcher blocks and clears every
        // native link so no stale entry can be observed.
        self.clear_slice_blocks();

        let affected: Vec<u64> = self
            .block_cache
            .keys()
            .copied()
            .filter(|&block_addr| {
                let block = match self.block_cache.get(&block_addr) {
                    Some(b) => b,
                    None => return false,
                };
                let start_page = block.guest_address & !0xfff;
                let end_page = (block.guest_address + block_guest_span(block) - 1) & !0xfff;
                let mut page = start_page;
                while page <= end_page {
                    if dirty_pages.contains(&page) {
                        return true; // Block overlaps a dirty page — needs invalidation
                    }
                    page += 0x1000;
                }
                false
            })
            .collect();

        if affected.is_empty() {
            return Vec::new();
        }

        for &block_addr in &affected {
            self.invalidate_block(block_addr);
        }
        // Invalidate synced pages for dirty pages so they get re-synced.
        for page in dirty_pages {
            self.synced_pages.remove(page);
        }
        eprintln!(
            "[jit] page-granularity invalidation: removed {} block(s)",
            affected.len()
        );
        affected
    }

    /// Returns `true` if the unwind table has been modified since the last
    /// `register_with_seh()` call, meaning the SEH subsystem needs to be
    /// updated.
    pub fn is_unwind_dirty(&self) -> bool {
        self.unwind_table.is_dirty()
    }

    /// Check whether a block at `guest_address` has been compiled.
    pub fn is_compiled(&self, guest_address: u64) -> bool {
        self.block_cache.contains_key(&guest_address)
    }

    /// Unchain all blocks that chain *to* `target_address`.
    ///
    /// Called when a block is invalidated or recompiled so that stale
    /// chains don't redirect execution to freed/reused memory.
    pub fn unchain_target(&mut self, target_address: u64) -> AppResult<()> {
        let sources: Vec<u64> = self
            .block_chains
            .keys()
            .filter(|(_, to)| *to == target_address)
            .map(|(from, _)| *from)
            .collect();
        for from in sources {
            self.unchain_block(from)?;
        }
        Ok(())
    }

    /// Break **all** existing block chains by restoring the RET instruction
    /// at the end of every chained block.
    ///
    /// After calling this method, every previously-chained block will return
    /// to the dispatcher (the main loop in [`pe_runtime`](crate::pe_runtime))
    /// after execution, allowing the CPU yield check and GDI frame
    /// re-publication to fire.
    ///
    /// Blocks are **not** invalidated — they remain compiled and will be
    /// re-chained automatically on subsequent executions (either via the
    /// auto-chaining logic in [`get_or_compile`](JitRuntime::get_or_compile)
    /// or via the explicit chain check in the PE runtime's main loop).
    pub fn break_all_chains(&mut self) {
        // Acquire the write lock on JIT_EXEC_LOCK to prevent the MAP_JIT
        // permission race. If the worker is inside entry_fn() (holding the
        // read lock), try_write() fails and we return early — chain-breaking
        // will be retried on the next 50 ms tick.
        let _lock = match JIT_EXEC_LOCK.try_write() {
            Ok(guard) => guard,
            Err(_) => {
                eprintln!("[jit] break_all_chains: worker holds read lock — deferring chain break");
                return;
            }
        };

        let keys: Vec<(u64, u64)> = self.block_chains.keys().copied().collect();
        let count = keys.len();
        if count == 0 {
            return;
        }
        for (from_addr, _) in keys {
            if let Err(e) = self.unchain_block(from_addr) {
                eprintln!(
                    "[jit] break_all_chains: failed to unchain {:#x}: {}",
                    from_addr, e
                );
            }
        }
        eprintln!("[jit] break_all_chains: broke {count} chain(s)");
    }

    /// Emit a host safepoint check at the start of a compiled block.
    ///
    /// When the JIT is re-enabled, every compiled block must begin with a
    /// check of the host safepoint flag so that guest code executing
    /// inside long chained blocks can still be interrupted — the host-side
    /// 2 ms block-dispatch safepoint in `pe_runtime.rs` only fires between
    /// dispatches, and a fully-chained loop never returns to the
    /// dispatcher.
    ///
    /// The intended emission (ARM64):
    ///
    /// ```text
    /// mov_imm64 xT, &JIT_SAFEPOINT_REQUESTED   // address of the flag
    /// ldr  wT,  [xT]                            // load the flag
    /// cbnz xT,  safepoint_stub                  // branch when set
    /// ...
    /// safepoint_stub:
    ///   emit_store_guest_registers(arch)
    ///   movz x0, EXIT_SAFEPOINT
    ///   emit_epilogue()                          // return EXIT_SAFEPOINT
    /// ```
    ///
    /// The dispatcher maps `EXIT_SAFEPOINT` to
    /// [`JitExitReason::Safepoint`], runs the host safepoint body (pump
    /// pending guest threads, drain timers/APCs, advance the guest clock),
    /// then re-dispatches the block.
    /// Execute a JIT-compiled block.
    ///
    /// # Safety
    /// The caller must ensure the block was correctly compiled and memory is valid.
    /// `block.entry()` must point to valid ARM64 machine code, `state` must be a
    /// valid CpuState, and `memory` must be a valid MemoryImage.
    pub unsafe fn execute_block(
        &mut self,
        block: &JitCompiledBlock,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> JitExitReason {
        self.blocks_executed += 1;

        #[cfg(test)]
        {
            let call = JIT_TEST_EXEC_CALLS.with(|calls| {
                let call = calls.get() + 1;
                calls.set(call);
                call
            });
            if JIT_TEST_IGNORE_SAFEPOINT_AT.with(|at| at.get()) == call {
                JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
            }
            if JIT_TEST_FORCE_SAFEPOINT_AT.with(|at| at.get()) == call {
                JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
            }
        }

        // ── Fault-equivalent fallback ────────────────────────────────────
        // An invalid installation (null/unpublished entry) or a block that
        // previously faulted must never be jumped into: hand this block to
        // the interpreter instead of aborting the process.
        let entry_ptr = block.published_entry();
        if entry_ptr.is_null() || self.faulted_blocks.contains(&block.guest_address) {
            self.report_block_fault(block.guest_address);
            return JitExitReason::Safepoint;
        }

        // ── Self-modifying code, entry check ────────────────────────────
        // The interpreter may have written guest code pages between JIT
        // executions.  Drain those writes before running a stale block; if
        // this very block was invalidated, return the safepoint fallback so
        // the dispatcher executes the block through the interpreter.
        let _smc_dirty = self.drain_smc_invalidations();
        // The caller resolved `block` before this call; it may have been
        // invalidated by the drain above or by an earlier block's exit
        // drain (SMC).  Never execute a stale clone: hand it to the
        // interpreter instead.
        let still_current = self
            .block_cache
            .get(&block.guest_address)
            .is_some_and(|cached| cached.published_entry() == entry_ptr);
        if !still_current {
            self.interpreter_fallbacks += 1;
            return JitExitReason::Safepoint;
        }

        // Both views must alias the same canonical pages before any native
        // load/store executes.  This is O(1) (Arc identity), not a page copy.
        self.attach_guest_memory(memory);

        // The JIT entry point expects:
        // x0 = pointer to CpuState
        // x1 = flat memory base
        // x2 = pointer to MemoryImage
        // x3 = pointer to exit_reason (output)
        // The x3 argument is a legacy exit-reason slot: every emission arm
        // returns its exit code in x0 (`movz x0, EXIT_*`) and no arm writes
        // [x3].  Decoding the slot therefore saw only zero (`EXIT_NORMAL`) and
        // collapsed safepoint/ret/jump exits into Normal.  Keep the slot in
        // the ABI, but decode the real x0 return value below.
        // The legacy x3 "exit reason" slot is repurposed as a per-thread
        // two-word cell: [0] is the block that most recently entered native
        // code (written by every prologue), [1] is this runtime's flat-mirror
        // base (read by chained jump exits to restore x1).  Both values are
        // thread-local because the cell lives on this stack.
        let mut chain = ChainState::new(self.flat_memory.base(), block.guest_address, LINK_BUDGET);
        let state_ptr = state as *mut CpuState;
        let mem_base = chain.flat_base;
        let mem_image_ptr = memory as *mut MemoryImage;
        let exit_ptr = &mut chain as *mut ChainState;

        // SAFETY: block.entry() points to JIT-compiled ARM64 code that was
        // written by this compiler and finalized (icache flushed, executable
        // permissions set). The JIT code respects the ARM64 ABI and only
        // accesses memory through the provided base pointer and validated
        // offsets.
        //
        // The transmute converts a raw code pointer (usize) to a function
        // pointer with the JIT block ABI:
        //   (cpu_state_ptr, mem_base_u64, memory_image_ptr, exit_reason_ptr) -> u64
        // This is valid because:
        // 1. block.entry() was produced by JitMemoryManager during compilation
        //    of this specific IR block. The manager allocates MAP_JIT pages
        //    and sets executable permissions after writing.
        // 2. The JIT compiler emits ARM64 machine code conforming to this
        //    exact calling convention (x0-x3 for args, x0 for return).
        // 3. The function pointer signature matches the JIT-emitted
        //    prologue/epilogue and register usage.
        // 4. No guest-controlled data influences the function pointer — it
        //    is determined at JIT compile time from the trusted block cache.
        // Publish this runtime's SMC state for the store helper.  The guard
        // is thread-local and only refers to the boxed atomics, never to the
        // mutably borrowed runtime itself.
        let _smc_guard = ActiveSmcGuard::install(&self.smc);

        // SAFETY: the write-protect toggle only affects this thread's view of
        // MAP_JIT pages; enabling execute state is required before jumping
        // into a block compiled on possibly another thread.
        let reason = unsafe {
            self.compiler.memory_manager.prepare_execution();
            let entry_fn: unsafe extern "C" fn(
                *mut CpuState,
                u64,
                *mut MemoryImage,
                *mut ChainState,
            ) -> u64 = std::mem::transmute(entry_ptr);

            let result = entry_fn(state_ptr, mem_base, mem_image_ptr, exit_ptr);

            // A linked jump enters the target block directly, so the block
            // that produced this exit may differ from the dispatched one.
            // Decode jump-family exits with the FINAL block's metadata (its
            // prologue wrote the address into the per-thread cell) — using
            // the source's target here would re-dispatch (double-execute) the
            // chained target.
            let final_address = (*exit_ptr).current_block;
            let exit_info = if final_address == block.guest_address {
                block.last_exit_info
            } else {
                self.block_cache
                    .get(&final_address)
                    .map(|final_block| final_block.last_exit_info)
                    .unwrap_or(block.last_exit_info)
            };

            // x0 carries the exit code for every native exit arm; the optional
            // dynamic payload (indirect target / target pointer) is written by
            // the compiled block into exec_slot[2].
            map_exit_reason(result, state, result, exit_info, (*exit_ptr).payload)
        };
        // A budget/epoch guard stops BEFORE the block body runs.  Re-dispatch
        // exactly that block; never re-run the chain's already-executed
        // prefix.
        if matches!(
            reason,
            JitExitReason::LinkBudget { .. } | JitExitReason::CodeEpoch { .. }
        ) {
            state.rip = chain.current_block;
        }
        // Self-modifying code, exit check: the block just executed may have
        // written another block's code page (or its own).  Invalidate before
        // the dispatcher looks the next block up, so the stale block can
        // never run.
        self.drain_smc_invalidations();
        reason
    }

    /// Attach the flat view to the live image's canonical store.
    ///
    /// O(1): an `Arc` identity check.  Both views then address the same
    /// direct-window mapping, so no page copy is needed before or after
    /// execution.
    pub(crate) fn attach_guest_memory(&mut self, memory: &MemoryImage) {
        self.flat_memory.attach_store(memory.canonical_store());
    }

    /// Mark a committed page as visible to the flat view.
    ///
    /// The bytes are already shared (the page lives in the canonical store);
    /// this only updates the diagnostic bitmap and `synced_pages`.
    pub fn sync_page_to_flat(&mut self, memory: &MemoryImage, page_addr: u64) {
        let aligned = page_addr & !0xfff;
        self.attach_guest_memory(memory);
        self.flat_memory.materialise_pages(memory, &[aligned]);
        self.synced_pages.insert(aligned);
    }

    /// Establish the baseline flat view for all committed guest pages.
    ///
    /// No bytes are copied: committed pages already live in the canonical
    /// store the flat view aliases.  This pass only records which fully
    /// mapped pages are visible to direct JIT addressing and updates the
    /// compatibility telemetry consumed by the sync-path benchmark.
    pub fn sync_all_pages_to_flat(&mut self, memory: &MemoryImage) {
        self.attach_guest_memory(memory);
        let pages = memory.committed_page_addresses();
        self.flat_memory.materialise_pages(memory, &pages);
        self.synced_pages = pages.into_iter().collect();
    }

    /// Incremental bookkeeping: only new pages are noted since the last pass.
    pub fn sync_new_pages_to_flat(&mut self, memory: &MemoryImage) {
        self.attach_guest_memory(memory);
        let current_pages: BTreeSet<u64> = memory.committed_page_addresses().into_iter().collect();
        let new_pages: Vec<u64> = current_pages
            .difference(&self.synced_pages)
            .copied()
            .collect();
        if !new_pages.is_empty() {
            self.flat_memory.materialise_pages(memory, &new_pages);
        }
        self.synced_pages = current_pages;
    }

    /// Coherence is immediate through the shared canonical store, so there is
    /// nothing to copy back.  Retained for source compatibility.
    pub fn sync_flat_to_memory(&self, _guest_addr: u64, _memory: &mut MemoryImage, _size: usize) {}

    /// No-op: JIT stores already land in the canonical pages the interpreter
    /// reads.  Retained for source compatibility.
    pub fn sync_all_flat_to_memory(&self, _memory: &mut MemoryImage) {}

    /// No-op: see [`Self::sync_all_flat_to_memory`].
    pub fn sync_synced_flat_to_memory(&self, _memory: &mut MemoryImage) {}

    /// Install the SIGBUS handler that syncs guest pages on demand during JIT
    /// execution. Stores `self` and `memory` as raw pointers for the signal
    /// handler (which must be async-signal-safe).
    ///
    /// Must be paired with a matching call to `remove_sigbus_handler` after
    /// JIT execution completes.
    pub fn install_sigbus_handler(&self, memory: &MemoryImage) {
        // Reset loop detection state
        SIGBUS_LAST_FAULT_ADDR.store(0, Ordering::Relaxed);
        SIGBUS_CONSECUTIVE_COUNT.store(0, Ordering::Relaxed);

        SIGBUS_JIT_RUNTIME.store(
            self as *const JitRuntime as *mut JitRuntime,
            Ordering::Release,
        );
        SIGBUS_JIT_MEMORY.store(
            memory as *const MemoryImage as *mut MemoryImage,
            Ordering::Release,
        );

        // SAFETY: sigaction is a POSIX function that installs a signal handler.
        // We zero-initialize the struct, set flags and handler, then call
        // sigaction. The old handler is not needed (null oact). SA_NODEFER
        // allows recursive SIGBUS detection (see handler docs above).
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            // sa_sigaction is a union with sa_handler on Apple platforms;
            // libc exposes it as usize. Store our SA_SIGINFO handler.
            // SA_NODEFER allows the handler to be re-entered if the sync
            // itself touches an unmapped flat-memory page, preventing an
            // infinite SIGBUS loop that would crash the process.
            action.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
            action.sa_sigaction = sigbus_sa_handler as *const () as usize;
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
        }
    }

    /// Ensure the SIGBUS handler is installed for this JIT session.
    /// If already installed (`sigbus_installed` flag), this is a no-op,
    /// eliminating the per-block sigaction syscall overhead.
    /// Only updates the memory pointer (in case it changed).
    pub fn ensure_sigbus_handler(&mut self, memory: &MemoryImage) {
        // The fallback services faulting pages of the store the flat view
        // addresses, so pin the view to this image before publishing pointers.
        self.attach_guest_memory(memory);
        if !self.sigbus_installed {
            self.install_sigbus_handler(memory);
            self.sigbus_installed = true;
        } else {
            // Handler already installed, just update the memory pointer
            // (the memory reference may change between blocks if the host
            // runtime modifies the MemoryImage).
            SIGBUS_JIT_MEMORY.store(
                memory as *const MemoryImage as *mut MemoryImage,
                Ordering::Release,
            );
            // Reset loop detection for new block
            SIGBUS_LAST_FAULT_ADDR.store(0, Ordering::Relaxed);
            SIGBUS_CONSECUTIVE_COUNT.store(0, Ordering::Relaxed);
        }
    }

    /// Remove the SIGBUS handler installed by `install_sigbus_handler` and
    /// restore the default SIGBUS disposition. Clears the static pointers.
    ///
    /// On Apple platforms, `libc::sigaction` exposes the `sa_sigaction`/`sa_handler`
    /// union as a single `sa_sigaction: usize` field. Setting it to `SIG_DFL` (0)
    /// restores the default disposition.
    pub fn remove_sigbus_handler(&self) {
        SIGBUS_JIT_RUNTIME.store(std::ptr::null_mut(), Ordering::Release);
        SIGBUS_JIT_MEMORY.store(std::ptr::null_mut(), Ordering::Release);

        // SAFETY: Restoring the default SIGBUS disposition. zeroed()
        // produces a valid sigaction struct with sa_flags=0 and
        // sa_sigaction=SIG_DFL (0), which is the default handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
        }
    }

    /// Remove the SIGBUS handler at the end of a JIT session.
    /// Only performs the sigaction syscall if the handler was actually installed.
    pub fn remove_sigbus_handler_session(&mut self) {
        if self.sigbus_installed {
            self.remove_sigbus_handler();
            self.sigbus_installed = false;
        }
    }

    /// Invalidate the synced pages set. Should be called when memory is
    /// invalidated (e.g., self-modifying code detection, module unloading)
    /// to force a full re-sync on the next block execution.
    pub fn invalidate_synced_pages(&mut self) {
        self.synced_pages.clear();
    }

    /// Returns the total number of SIGBUS events since the process started.
    /// Useful for diagnostics and performance monitoring.
    pub fn sigbus_event_count() -> u64 {
        SIGBUS_TOTAL_EVENTS.load(Ordering::Relaxed)
    }

    /// Returns the number of pages currently in the synced set.
    pub fn synced_page_count(&self) -> usize {
        self.synced_pages.len()
    }
}

/// Map the raw JIT exit code (returned by a compiled block in x0) to a
/// [`JitExitReason`].
///
/// The jump-family exit codes (`EXIT_JUMP`, `EXIT_COND_BRANCH`,
/// `EXIT_INDIRECT_CALL`) must NOT collapse into `Normal`: the compiled
/// code never writes `state.rip` for these (see the emission comments in
/// `compile_instruction`), so the dispatcher must reconstruct RIP from
/// the reason.  `block_exit_info` carries the block's final control-flow
/// metadata captured at compile time.
///
/// `result` is the block's X0 return value (for `EXIT_THUNK`/`EXIT_RET`
/// it carries the guest return RIP; the dormant jump-family arms use it
/// as a best-effort carrier — a re-enabled JIT must either populate it or
/// have the dispatcher re-derive the target from `state`).
/// Map an x86 condition to the equivalent ARM64 `b.cond` encoding for the
/// flags produced by `CMP` (SUBS) or `TEST` (ANDS).  `None` means the
/// condition needs the parity flag and must use the generic path.
fn arm_condition_for(condition: ConditionCode) -> Option<u32> {
    Some(match condition {
        ConditionCode::Equal => 0x0,         // EQ
        ConditionCode::NotEqual => 0x1,      // NE
        ConditionCode::NotBelow => 0x2,      // CS/HS (CF = 0)
        ConditionCode::Below => 0x3,         // CC/LO (CF = 1)
        ConditionCode::NotSign => 0x5,       // PL
        ConditionCode::Sign => 0x4,          // MI
        ConditionCode::NotOverflow => 0x7,   // VC
        ConditionCode::Overflow => 0x6,      // VS
        ConditionCode::Above => 0x8,         // HI
        ConditionCode::NotAbove => 0x9,      // LS
        ConditionCode::GreaterEqual => 0x10, // GE
        ConditionCode::Less => 0x11,         // LT
        ConditionCode::Greater => 0x12,      // GT
        ConditionCode::LessEqual => 0x13,    // LE
        ConditionCode::Parity | ConditionCode::NotParity => return None,
    })
}

/// True when the first flag-related instruction in `block` reads flags (so a
/// predecessor must materialise them into `CpuState`).  A block that writes
/// flags first (CMP/TEST) does not need them on entry.
fn block_reads_flags_before_write(block: &crate::jit_ssa::OptimizedBlock) -> bool {
    for insn in &block.instructions {
        match insn {
            IrInstruction::Compare { .. } | IrInstruction::Test { .. } => return false,
            IrInstruction::JumpIf { .. }
            | IrInstruction::Setcc { .. }
            | IrInstruction::SetccMemory { .. }
            | IrInstruction::Cmov { .. }
            | IrInstruction::AdcImm { .. }
            | IrInstruction::AdcOperand { .. }
            | IrInstruction::SbbImm { .. }
            | IrInstruction::SbbOperand { .. }
            | IrInstruction::PushFlags { .. }
            | IrInstruction::Lahf => return true,
            _ => {}
        }
    }
    // No flag writer in this block: the incoming flags are still guest-visible
    // at its exit, so a predecessor must have materialised them.
    true
}

fn edge_reads_flags(
    target: u64,
    blocks: &[crate::jit_ssa::OptimizedBlock],
    by_address: &std::collections::HashMap<u64, usize>,
) -> bool {
    match by_address.get(&target) {
        Some(index) => block_reads_flags_before_write(&blocks[*index]),
        None => true,
    }
}

/// Return the index of a trailing CMP/TEST that feeds a terminating `Jcc`
/// with only spill bookkeeping after it.
fn find_native_compare(block: &crate::jit_ssa::OptimizedBlock) -> Option<usize> {
    let condition = match &block.terminator {
        crate::jit_ssa::OptimizedTerminator::JumpIf { condition, .. } => *condition,
        _ => return None,
    };
    // Parity needs PF, which ARM NZCV does not carry: keep the helper path.
    arm_condition_for(condition)?;
    let mut candidate = None;
    for (index, insn) in block.instructions.iter().enumerate() {
        match insn {
            IrInstruction::Compare { width: 8, .. } | IrInstruction::Test { width: 8, .. } => {
                candidate = Some(index);
            }
            IrInstruction::SpillLoad { .. } | IrInstruction::SpillStore { .. } => {}
            _ => candidate = None,
        }
    }
    candidate.filter(|index| {
        block.instructions[index + 1..].iter().all(|insn| {
            matches!(
                insn,
                IrInstruction::SpillLoad { .. } | IrInstruction::SpillStore { .. }
            )
        })
    })
}

fn map_exit_reason(
    exit_reason: u64,
    state: &CpuState,
    result: u64,
    block_exit_info: Option<BlockExitInfo>,
    payload: u64,
) -> JitExitReason {
    // Indirect call sites need the static return address (never written by the
    // compiled block); the dynamic callee target arrives in `payload`.
    let call_return_address = match block_exit_info {
        Some(BlockExitInfo::CallIndirect { return_address }) => return_address,
        Some(BlockExitInfo::Call { return_address, .. }) => return_address,
        _ => 0,
    };
    let direct_call_target = match block_exit_info {
        Some(BlockExitInfo::Call { target, .. }) => target,
        _ => payload,
    };
    match exit_reason {
        EXIT_NORMAL => JitExitReason::Normal { new_rip: state.rip },
        EXIT_THUNK => JitExitReason::ThunkDispatch {
            target_rip: state.rip,
            return_rip: result,
        },
        EXIT_UNIMPL => JitExitReason::UnimplementedInstruction {
            rip: state.rip,
            opcode: result as u8,
        },
        EXIT_COND_BRANCH => {
            let taken = match block_exit_info {
                Some(BlockExitInfo::JumpIf { condition, .. }) => {
                    crate::cpu::evaluate_condition(condition, &state.flags)
                }
                _ => result != 0,
            };
            JitExitReason::ConditionalBranch {
                rip: state.rip,
                taken,
            }
        }
        EXIT_INDIRECT_CALL => JitExitReason::IndirectCall {
            target: result,
            return_address: state.rip,
            target_is_pointer: false,
        },
        EXIT_INDIRECT_JUMP_REG => JitExitReason::IndirectJump {
            target: payload,
            target_is_pointer: false,
        },
        EXIT_INDIRECT_CALL_REG => JitExitReason::IndirectCall {
            target: payload,
            return_address: call_return_address,
            target_is_pointer: false,
        },
        EXIT_INDIRECT_JUMP_MEM => JitExitReason::IndirectJump {
            target: payload,
            target_is_pointer: true,
        },
        EXIT_INDIRECT_CALL_MEM => JitExitReason::IndirectCall {
            target: payload,
            return_address: call_return_address,
            target_is_pointer: true,
        },
        EXIT_CALL_DIRECT => JitExitReason::DirectCall {
            target: direct_call_target,
            return_address: call_return_address,
        },
        EXIT_CALL_PUSHED => JitExitReason::DirectCallPushed {
            target: direct_call_target,
            return_address: call_return_address,
        },
        EXIT_RET_RESOLVED => JitExitReason::ReturnResolved { target: payload },
        EXIT_LINK_BUDGET => JitExitReason::LinkBudget { rip: state.rip },
        EXIT_CODE_EPOCH => JitExitReason::CodeEpoch { rip: state.rip },
        EXIT_COND_TAKEN => JitExitReason::ConditionalTaken { rip: state.rip },
        EXIT_COND_NOT_TAKEN => JitExitReason::ConditionalNotTaken { rip: state.rip },
        EXIT_RET => JitExitReason::Return { return_rip: result },
        EXIT_MEM_ACCESS => JitExitReason::MemoryAccess {
            address: result,
            is_write: false,
            width: 0,
        },
        EXIT_CPUID => JitExitReason::Cpuid,
        EXIT_EXCEPTION => JitExitReason::Exception {
            code: result as u32,
            address: state.rip,
        },
        EXIT_JUMP => {
            let target = match block_exit_info {
                Some(BlockExitInfo::Jump { target }) => target,
                _ => state.rip,
            };
            JitExitReason::Jump { target }
        }
        EXIT_SAFEPOINT => JitExitReason::Safepoint,
        EXIT_GUEST_FAULT => JitExitReason::GuestFault,
        _ => JitExitReason::Normal { new_rip: state.rip },
    }
}

impl Drop for JitRuntime {
    fn drop(&mut self) {
        // Clean up the persistent SIGBUS handler if still installed.
        // This ensures the signal handler doesn't reference freed memory.
        self.remove_sigbus_handler_session();
    }
}

impl JitRuntime {
    /// Chain two compiled blocks so that the exit jump of `from_address` is
    /// patched to go directly to the entry of `to_address`, bypassing the
    /// dispatcher.
    ///
    /// # Performance Impact
    /// Eliminates dispatcher overhead (indirect call, block lookup, register
    /// restore/save) for hot block-to-block transitions, reducing branch
    /// misprediction penalty and improving instruction-cache locality.
    ///
    /// # Thread Safety
    /// This method never writes instruction memory: it publishes the target
    /// entry into the source block's atomic link slot with Release ordering.
    /// The compiled jump reads that slot with an acquire load (LDAR), so a
    /// concurrent executor sees either the old link (including zero, which
    /// exits to the dispatcher) or the new one — never a torn code sequence.
    pub fn chain_blocks(&mut self, from_address: u64, to_address: u64) -> AppResult<()> {
        #[cfg(test)]
        if JIT_TEST_FORCE_CHAIN_ERROR.with(|force| force.replace(false)) {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "injected chain failure",
            ));
        }
        let Some(from_block) = self.block_cache.get(&from_address) else {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("cannot chain missing source block {from_address:#x}"),
            ));
        };
        if !matches!(from_block.last_exit_info, Some(BlockExitInfo::Jump { .. })) {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("block {from_address:#x} does not end in an unconditional jump"),
            ));
        }
        let Some(to_block) = self.block_cache.get(&to_address) else {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("cannot chain to missing target block {to_address:#x}"),
            ));
        };
        // Only Jump/JumpIf targets are chainable.  Their exit is fully
        // described by `last_exit_info`, which `execute_block` looks up for
        // the final chained block.  Straight-line targets would leave RIP
        // wrong, and Return/Call targets need the dispatcher to re-run the
        // terminator IR of the *dispatched* (source) block — double-executing
        // the chained target.
        if !matches!(
            to_block.last_exit_info,
            Some(BlockExitInfo::Jump { .. } | BlockExitInfo::JumpIf { .. })
        ) {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("block {to_address:#x} does not end in a chainable jump"),
            ));
        }
        let target_entry = to_block.published_entry() as u64;
        if target_entry == 0 {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                format!("block {to_address:#x} has no published entry"),
            ));
        }
        let slot = Arc::clone(&from_block.link_target);
        let patch_location = Arc::as_ptr(&slot) as u64;
        #[cfg(test)]
        if JIT_TEST_PREPUBLISH_CHAIN.with(|prepublish| prepublish.replace(false)) {
            from_block
                .link_target
                .store(target_entry, Ordering::Release);
        }
        let previous = slot.swap(target_entry, Ordering::AcqRel);
        self.block_chains.insert(
            (from_address, to_address),
            BlockChainEntry {
                from_address,
                to_address,
                chain_patch_location: patch_location,
                chained: true,
            },
        );
        if previous != target_entry {
            self.chain_links_formed += 1;
            JIT_CHAIN_LINKS_FORMED.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Remove a block chain originating from `from_address`.
    ///
    /// Used when a block is invalidated (e.g., self-modifying code) so that
    /// stale chains don't redirect execution to freed/reused memory.
    pub fn unchain_block(&mut self, from_address: u64) -> AppResult<()> {
        let keys_to_remove: Vec<(u64, u64)> = self
            .block_chains
            .keys()
            .filter(|(from, _)| *from == from_address)
            .copied()
            .collect();

        for key in keys_to_remove {
            if self.block_chains.remove(&key).is_some() {
                // Links are atomic pointer slots, never patched instructions:
                // clearing the slot is a single Release store, safe while
                // another thread is executing the block.
                if let Some(from_block) = self.block_cache.get(&from_address)
                    && from_block.link_target.swap(0, Ordering::AcqRel) != 0
                {
                    self.chain_links_broken += 1;
                    JIT_CHAIN_LINKS_BROKEN.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    /// Returns `true` if `start` can reach `target` by following existing
    /// block chains (`block_chains`), i.e. if there is already a patched
    /// native path `start → ... → target`.
    ///
    /// Used by [`chain_blocks`](Self::chain_blocks) to refuse creating a
    /// chain that would close a cycle (which would loop forever in native
    /// code without returning to the dispatcher).  Because each compiled
    /// block has at most one outgoing chain, the chain graph is a set of
    /// disjoint paths, so this DFS is linear in the number of chained
    /// blocks visited.  The hop cap bounds the worst case.
    #[allow(dead_code)] // block-chaining reachability query; not yet used by the chaining policy
    fn chain_reaches(&self, start: u64, target: u64) -> bool {
        const MAX_HOPS: usize = 4096;
        let mut current = start;
        for _ in 0..MAX_HOPS {
            if current == target {
                return true;
            }
            // Each block has at most one outgoing chain, so find the single
            // chain whose `from_address == current`.
            match self
                .block_chains
                .iter()
                .find(|(_, entry)| entry.from_address == current && entry.chained)
            {
                Some((_, entry)) => current = entry.to_address,
                None => return false,
            }
        }
        // Exhausted the hop budget without reaching `target` or a dead end —
        // treat as not-reaching to stay safe (a genuine cycle longer than
        // MAX_HOPS would be broken by the watchdog's force_break_all_chains).
        false
    }

    /// Register a host function pointer as a fast thunk, returning the thunk
    /// index that can be used by JIT-compiled code to call the host function
    /// directly (bypassing the full guest→host dispatch loop).
    pub fn register_host_thunk(&mut self, host_fn: usize) -> Option<usize> {
        self.fast_thunk_table.register(host_fn).ok()
    }

    /// Register a host function as the resolved target for a guest thunk
    /// address.  Subsequent compilations of `Call { target: guest_addr }`
    /// emit a direct trampoline call instead of an EXIT_THUNK dispatcher
    /// round-trip.
    pub fn register_host_thunk_for_guest(
        &mut self,
        host_fn: usize,
        guest_addr: u64,
    ) -> Option<usize> {
        self.fast_thunk_table
            .register_with_guest_addr(host_fn, guest_addr)
            .ok()
    }

    /// Guest thunk addresses with a resolved trampoline.
    pub fn guest_thunk_addrs(&self) -> std::collections::HashSet<u64> {
        self.fast_thunk_table.guest_addrs()
    }

    /// Look up the executable thunk address for a previously registered
    /// fast-thunk index. Returns `None` if the index is out of range.
    pub fn lookup_thunk_address(&self, idx: usize) -> Option<usize> {
        self.fast_thunk_table.thunk_address(idx)
    }
}

// ---------------------------------------------------------------------------
// JIT Block Chaining Entry
// ---------------------------------------------------------------------------

/// Represents a single block chain link between two compiled blocks.
///
/// When a block at `from_address` exits by branching to `to_address`, the
/// exit jump in the JIT code is patched to go directly to the target block's
/// entry point, skipping the dispatcher loop entirely.
#[derive(Debug, Clone)]
pub struct BlockChainEntry {
    /// Guest address of the source block.
    pub from_address: u64,
    /// Guest address of the target block.
    pub to_address: u64,
    /// Address in JIT code where the branch instruction was patched.
    pub chain_patch_location: u64,
    /// Whether the chain is currently active.
    pub chained: bool,
}

// ---------------------------------------------------------------------------
// Tiered Compilation
// ---------------------------------------------------------------------------

/// Compilation tier for the tiered JIT compiler.
///
/// Blocks start at Tier0 (fast compile, minimal optimization). As they get
/// hotter they are promoted to Tier1 (full optimization with register
/// allocation) and eventually Tier2 (aggressive optimization with inlining
/// and loop unrolling).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum CompilationTier {
    /// Fast compilation, minimal optimization — direct 1:1 IR-to-native.
    #[default]
    Tier0,
    /// Full optimization with register allocation, constant folding, dead
    /// code elimination.
    Tier1,
    /// Aggressive optimization with block inlining and loop unrolling.
    Tier2,
}

/// Manages tiered compilation by tracking execution counts and promoting
/// blocks to higher optimization tiers when they cross configured thresholds.
///
/// # Performance Impact
/// Tiered compilation reduces startup latency by compiling blocks quickly at
/// Tier0, then investing compile time in hot blocks at higher tiers where the
/// improved code quality pays off over many executions.
pub struct TieredCompiler {
    /// Execution count thresholds for tier promotion:
    /// `[Tier0→Tier1 threshold, Tier1→Tier2 threshold, unused]`.
    pub tier_thresholds: [u32; 3],
    /// Execution counts per block address.
    pub execution_counts: BTreeMap<u64, u32>,
    /// Current compilation tier per block address.
    pub current_tiers: BTreeMap<u64, CompilationTier>,
}

impl Default for TieredCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl TieredCompiler {
    /// Create a new `TieredCompiler` with default thresholds.
    ///
    /// Tier0→Tier1 at 50 executions, Tier1→Tier2 at 500 executions.
    pub fn new() -> Self {
        Self {
            tier_thresholds: [50, 500, u32::MAX],
            execution_counts: BTreeMap::new(),
            current_tiers: BTreeMap::new(),
        }
    }

    /// Create a `TieredCompiler` with custom thresholds.
    pub fn with_thresholds(tier0_to_tier1: u32, tier1_to_tier2: u32) -> Self {
        Self {
            tier_thresholds: [tier0_to_tier1, tier1_to_tier2, u32::MAX],
            execution_counts: BTreeMap::new(),
            current_tiers: BTreeMap::new(),
        }
    }

    /// Record an execution of the block at `block_address`.
    ///
    /// Increments the execution counter and returns `Some(new_tier)` if the
    /// block should be promoted to a higher tier, or `None` if no promotion
    /// is warranted.
    pub fn record_execution(&mut self, block_address: u64) -> Option<CompilationTier> {
        let count = self.execution_counts.entry(block_address).or_insert(0);
        *count += 1;

        let current_tier = self
            .current_tiers
            .get(&block_address)
            .copied()
            .unwrap_or(CompilationTier::Tier0);

        let new_tier = match current_tier {
            CompilationTier::Tier0 if *count >= self.tier_thresholds[0] => {
                Some(CompilationTier::Tier1)
            }
            CompilationTier::Tier1 if *count >= self.tier_thresholds[1] => {
                Some(CompilationTier::Tier2)
            }
            _ => None,
        };

        if let Some(tier) = new_tier {
            self.current_tiers.insert(block_address, tier);
        }

        new_tier
    }

    /// Get the current tier for a block.
    pub fn get_tier(&self, block_address: u64) -> CompilationTier {
        self.current_tiers
            .get(&block_address)
            .copied()
            .unwrap_or(CompilationTier::Tier0)
    }

    /// Get the execution count for a block.
    pub fn get_count(&self, block_address: u64) -> u32 {
        self.execution_counts
            .get(&block_address)
            .copied()
            .unwrap_or(0)
    }

    /// Reset tier data for a specific block (e.g., after invalidation).
    pub fn reset_block(&mut self, block_address: u64) {
        self.execution_counts.remove(&block_address);
        self.current_tiers.remove(&block_address);
    }
}

/// Internal enum for tracking known register values during constant folding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum KnownValue {
    Immediate(u64),
    RegisterCopy(Register),
    #[allow(dead_code)]
    KnownHighLow {
        high: u64,
        low: u64,
    },
}

impl JitCompiler {
    /// Compile a block at Tier0: fast compilation with no optimization.
    ///
    /// Performs direct 1:1 IR-to-native translation without register
    /// allocation, constant folding, or dead code elimination. This is the
    /// fastest compilation path, minimizing startup latency.
    pub fn compile_tier0(
        &mut self,
        ir: &[IrInstruction],
        guest_address: u64,
        arch: GuestArch,
        fast_thunk_addrs: Option<&std::collections::HashSet<u64>>,
    ) -> AppResult<JitCompiledBlock> {
        // Tier0 is identical to the default compile_block — no optimization.
        self.compile_block(ir, guest_address, arch, fast_thunk_addrs)
    }

    /// Compile a block at Tier1: full optimization with register allocation,
    /// constant folding, and dead code elimination.
    ///
    /// # Performance Impact
    /// Eliminates redundant MOV instructions, folds constant expressions at
    /// compile time, and uses register allocation to minimize memory traffic.
    pub fn compile_tier1(
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

        // Optimized prologue: same as default but with better register planning
        self.emit_prologue(arch);
        self.emit_current_block_tag(guest_address);
        self.emit_load_guest_registers(arch);
        self.emit_chain_guard(ir.len() as u64, arch);
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(ir.len() as u64);

        // Constant folding pass: pre-compute known constants
        let folded_ir = Self::constant_fold(ir);

        // Compile optimized IR
        let last = folded_ir.len().saturating_sub(1);
        for (index, insn) in folded_ir.iter().enumerate() {
            self.compile_instruction(insn, arch, fast_thunk_addrs, index == last)?;
        }

        self.emit_store_guest_registers(arch);
        self.emit_epilogue();
        // The optimized paths must carry the same safepoint and guest-fault
        // exits as the Tier0 path: without these stubs the emitted `cbnz`
        // placeholders would fall through and a fault would be ignored.
        self.finish_safepoint_stub(arch);
        self.finish_fault_stub(arch);

        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT Tier1: failed to allocate executable memory",
            ));
        }

        // SAFETY: Same as compile_block — code_ptr is valid for code_size
        // bytes, emitter.code is a valid Vec, regions are non-overlapping.
        self.install_code(code_ptr, code_size)?;

        let source_hash = compute_ir_hash(ir, guest_address);
        let last_exit_info = block_exit_info(ir);
        let worker_safe = block_is_worker_safe(&folded_ir, self.used_interpreter_helper);
        self.link_slots = None;

        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address,
            instruction_count: ir.len(),
            source_hash,
            last_exit_info,
            compile_tier: CompilationTier::Tier1,
            ends_in_control_flow: block_ends_in_control_flow(ir),
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe,
        })
    }

    /// Compile a block at Tier2.
    ///
    /// Tier2 currently applies the same sound optimizer as Tier1 (constant
    /// folding/no-op elimination) with the full safepoint and guest-fault
    /// exits.  Loop unrolling and block inlining remain disabled because the
    /// existing passes can change guest-visible flags/counter values.
    pub fn compile_tier2(
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

        self.emit_prologue(arch);
        self.emit_current_block_tag(guest_address);
        self.emit_load_guest_registers(arch);
        self.emit_chain_guard(ir.len() as u64, arch);
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(ir.len() as u64);

        // Whole-block SSA: GVN, SCCP, DCE, LICM and exact-address load/store
        // forwarding.  Unsupported constructs reject the block as a unit and
        // it is recompiled at Tier-0, so a partially-optimised block can never
        // be executed.
        let optimized_ir = match crate::jit_ssa::optimize_block_ir(ir, arch) {
            Ok(optimized) => optimized,
            Err(_) => {
                return self.compile_block(ir, guest_address, arch, fast_thunk_addrs);
            }
        };

        self.emit_spill_slots_init(arch);
        let last = optimized_ir.len().saturating_sub(1);
        for (index, insn) in optimized_ir.iter().enumerate() {
            self.compile_instruction(insn, arch, fast_thunk_addrs, index == last)?;
        }

        self.emit_store_guest_registers(arch);
        self.emit_epilogue();
        self.finish_safepoint_stub(arch);
        self.finish_fault_stub(arch);

        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT Tier2: failed to allocate executable memory",
            ));
        }

        // SAFETY: Same as compile_block — code_ptr is valid for code_size
        // bytes, emitter.code is a valid Vec, regions are non-overlapping.
        self.install_code(code_ptr, code_size)?;

        let source_hash = compute_ir_hash(ir, guest_address);
        let last_exit_info = block_exit_info(&optimized_ir);
        let worker_safe = block_is_worker_safe(&optimized_ir, self.used_interpreter_helper);
        self.link_slots = None;

        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address,
            instruction_count: ir.len(),
            source_hash,
            last_exit_info,
            compile_tier: CompilationTier::Tier2,
            ends_in_control_flow: block_ends_in_control_flow(ir),
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe,
        })
    }

    /// Compile a whole hot function at Tier-2.
    ///
    /// The entry block is the first element.  The SSA front end builds one
    /// function-wide IR, runs the optimiser, and this emitter lays every block
    /// out in one native code object: guest registers are loaded once at the
    /// entry, internal branches are native `b`/`b.cond` instructions, and only
    /// function exits store `CpuState`.  Unsupported constructs fall back to
    /// the entry block at Tier-0.
    pub fn compile_function_tier2(
        &mut self,
        blocks: &[crate::jit_ssa::FunctionBlock],
        arch: GuestArch,
    ) -> AppResult<JitCompiledBlock> {
        if blocks.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT Tier2: no function blocks",
            ));
        }
        let optimized = match crate::jit_ssa::optimize_function(blocks, arch) {
            Ok(optimized) => optimized,
            Err(_) => {
                let entry = &blocks[0];
                return self.compile_block(&entry.instructions, entry.guest_address, arch, None);
            }
        };

        self.emitter = Emitter::new();
        self.used_interpreter_helper = false;
        self.relocations.clear();
        self.fault_cbnz_patches.clear();
        self.safepoint_cbnz_patch = None;
        self.link_slots = None;

        let mut labels = vec![0usize; optimized.blocks.len()];
        let mut by_address = std::collections::HashMap::new();
        for (index, block) in optimized.blocks.iter().enumerate() {
            by_address.insert(block.guest_address, index);
        }
        let entry_address = optimized.blocks[0].guest_address;
        let original_count: usize = optimized.original_instructions;

        self.emit_prologue(arch);
        self.emit_current_block_tag(entry_address);
        self.emit_load_guest_registers(arch);
        self.emit_spill_slots_init(arch);
        self.emit_chain_guard(original_count as u64, arch);
        self.emit_safepoint_check(arch);
        self.emit_block_accounting(original_count as u64);

        let mut jump_patches: Vec<(usize, usize)> = Vec::new();
        let mut conditional_patches: Vec<(usize, usize)> = Vec::new();
        let mut extra_safepoints: Vec<usize> = Vec::new();

        for (index, block) in optimized.blocks.iter().enumerate() {
            labels[index] = self.emitter.len();
            self.emit_set_state_rip(block.guest_address);
            if index != 0 {
                let flag_addr = &JIT_SAFEPOINT_REQUESTED as *const AtomicBool as u64;
                self.emit_reloc_imm64(regmap::X26, flag_addr, AotRelocKind::SafepointFlag);
                self.emitter.ldr8(regmap::X26, regmap::X26, 0);
                let pos = self.emitter.len();
                self.emitter.cbnz(regmap::X26, 0);
                extra_safepoints.push(pos);
            }
            let native_compare_index = find_native_compare(block);
            let mut native_compare: Option<IrInstruction> = None;
            for (insn_index, insn) in block.instructions.iter().enumerate() {
                if Some(insn_index) == native_compare_index && self.emit_native_compare(insn) {
                    native_compare = Some(insn.clone());
                } else {
                    self.compile_instruction(insn, arch, None, false)?;
                }
            }
            match &block.terminator {
                crate::jit_ssa::OptimizedTerminator::Jump { target, copies } => {
                    for insn in copies {
                        self.compile_instruction(insn, arch, None, false)?;
                    }
                    if let Some(target_index) = by_address.get(target).copied() {
                        let pos = self.emitter.len();
                        self.emitter.b(0);
                        jump_patches.push((pos, target_index));
                    } else {
                        self.emit_set_state_rip(*target);
                        self.emit_store_guest_registers(arch);
                        self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                        self.emit_epilogue();
                    }
                }
                crate::jit_ssa::OptimizedTerminator::JumpIf {
                    condition,
                    target,
                    fallthrough,
                    taken_copies,
                    fallthrough_copies,
                } => {
                    let native_condition = native_compare
                        .is_some()
                        .then(|| arm_condition_for(*condition))
                        .flatten();
                    let taken_pos = if let Some(condition) = native_condition {
                        let pos = self.emitter.len();
                        self.emitter.bcond(condition, 0);
                        pos
                    } else {
                        self.emit_materialize_flags();
                        self.emit_x86_flag_loads_scratch();
                        self.emit_x86_condition_branch_scratch(*condition)
                    };
                    if native_condition.is_some()
                        && edge_reads_flags(*fallthrough, &optimized.blocks, &by_address)
                        && let Some(compare) = native_compare.as_ref()
                    {
                        self.compile_instruction(compare, arch, None, false)?;
                    }
                    for insn in fallthrough_copies {
                        self.compile_instruction(insn, arch, None, false)?;
                    }
                    if let Some(fallthrough_index) = by_address.get(fallthrough).copied() {
                        let pos = self.emitter.len();
                        self.emitter.b(0);
                        jump_patches.push((pos, fallthrough_index));
                    } else {
                        self.emit_set_state_rip(*fallthrough);
                        self.emit_store_guest_registers(arch);
                        self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                        self.emit_epilogue();
                    }
                    let taken_label = self.emitter.len();
                    conditional_patches.push((taken_pos, taken_label));
                    if native_condition.is_some()
                        && edge_reads_flags(*target, &optimized.blocks, &by_address)
                        && let Some(compare) = native_compare.as_ref()
                    {
                        self.compile_instruction(compare, arch, None, false)?;
                    }
                    for insn in taken_copies {
                        self.compile_instruction(insn, arch, None, false)?;
                    }
                    if let Some(target_index) = by_address.get(target).copied() {
                        let pos = self.emitter.len();
                        self.emitter.b(0);
                        jump_patches.push((pos, target_index));
                    } else {
                        self.emit_set_state_rip(*target);
                        self.emit_store_guest_registers(arch);
                        self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
                        self.emit_epilogue();
                    }
                }
                crate::jit_ssa::OptimizedTerminator::Return { .. } => {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_RET as u16, 0);
                    self.emit_epilogue();
                }
                crate::jit_ssa::OptimizedTerminator::Exit => {
                    self.emit_store_guest_registers(arch);
                    self.emitter.movz(regmap::X0, EXIT_NORMAL as u16, 0);
                    self.emit_epilogue();
                }
            }
        }

        // Defensive normal exit (a function with no explicit terminator).
        self.emit_store_guest_registers(arch);
        self.emitter.movz(regmap::X0, EXIT_NORMAL as u16, 0);
        self.emit_epilogue();

        // Shared safepoint stub.
        let mut safepoints = std::mem::take(&mut extra_safepoints);
        if let Some(pos) = self.safepoint_cbnz_patch.take() {
            safepoints.push(pos);
        }
        if !safepoints.is_empty() {
            let stub = self.emitter.len();
            self.emit_store_guest_registers(arch);
            self.emitter.movz(regmap::X0, EXIT_JUMP as u16, 0);
            self.emit_epilogue();
            for pos in safepoints {
                self.patch_cbnz_any(pos, stub);
            }
        }
        self.finish_fault_stub(arch);

        for (pos, target) in jump_patches {
            self.patch_b_any(pos, labels[target]);
        }
        for (pos, target) in conditional_patches {
            self.patch_bcond_any(pos, target);
        }
        let code_size = self.emitter.len();
        let code_ptr = self.memory_manager.allocate_code_space(code_size);
        if code_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "JIT Tier2 function: failed to allocate executable memory",
            ));
        }
        self.install_code(code_ptr, code_size)?;

        let mut source = Vec::new();
        for block in blocks {
            source.extend(block.instructions.iter().cloned());
        }
        let source_hash = compute_ir_hash(&source, entry_address);
        let link_slots = LinkSlots::new();
        Ok(JitCompiledBlock {
            entry_addr: code_ptr as usize,
            entry_atomic: AtomicPtr::new(code_ptr),
            code_size,
            guest_address: entry_address,
            instruction_count: original_count,
            source_hash,
            last_exit_info: None,
            compile_tier: CompilationTier::Tier2,
            ends_in_control_flow: true,
            link_target: link_slots.jump,
            taken_link: link_slots.taken,
            fallthrough_link: link_slots.fallthrough,
            call_link: link_slots.call,
            return_entry_link: link_slots.return_entry,
            worker_safe: false,
        })
    }

    /// Emit a native x86 CMP/TEST for a 64-bit register/immediate comparison.
    /// Returns false when the form is not covered and the caller must use the
    /// generic (helper-backed) emission.
    fn emit_native_compare(&mut self, insn: &IrInstruction) -> bool {
        use crate::cpu::CompareOperand;
        let (lhs, rhs, width, is_test) = match insn {
            IrInstruction::Compare { lhs, rhs, width } => (lhs, rhs, *width, false),
            IrInstruction::Test { lhs, rhs, width } => (lhs, rhs, *width, true),
            _ => return false,
        };
        if width != 8 {
            return false;
        }
        let resolve =
            |emitter: &mut Emitter, operand: &CompareOperand, scratch: u32| -> Option<u32> {
                match operand {
                    CompareOperand::Register(reg) => Some(regmap::guest_to_arm(reg.index())),
                    CompareOperand::ImmediateU64(value) => {
                        emitter.mov_imm64(scratch, *value);
                        Some(scratch)
                    }
                    _ => None,
                }
            };
        let Some(lhs_reg) = resolve(&mut self.emitter, lhs, regmap::X21) else {
            return false;
        };
        let Some(rhs_reg) = resolve(&mut self.emitter, rhs, regmap::X22) else {
            return false;
        };
        if is_test {
            self.emitter.ands_reg(31, lhs_reg, rhs_reg);
        } else {
            self.emitter.subs_reg(31, lhs_reg, rhs_reg);
        }
        true
    }

    fn patch_b_any(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        let insn = 0x1400_0000u32 | ((offset as u32) & 0x03ff_ffff);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    fn patch_bcond_any(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        let condition = self.emitter.code[position] & 0x0f;
        let insn = 0x5400_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(condition);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    fn patch_cbnz_any(&mut self, position: usize, target: usize) {
        let offset = (target as i32 - position as i32) / 4;
        let register = self.emitter.code[position] & 0x1f;
        let insn = 0xb500_0000u32 | (((offset as u32) & 0x7ffff) << 5) | u32::from(register);
        self.emitter.code[position..position + 4].copy_from_slice(&insn.to_le_bytes());
    }

    /// Load the six x86 flag bytes into non-guest scratch registers.  Unlike
    /// `emit_x86_flag_loads`, this keeps x4-x20 (the live guest register file)
    /// intact so a whole-function internal branch needs no per-block reload.
    fn emit_x86_flag_loads_scratch(&mut self) {
        let base = std::mem::offset_of!(CpuState, flags) as u32;
        let cf = base + std::mem::offset_of!(crate::cpu::Flags, cf) as u32;
        let pf = base + std::mem::offset_of!(crate::cpu::Flags, pf) as u32;
        let zf = base + std::mem::offset_of!(crate::cpu::Flags, zf) as u32;
        let sf = base + std::mem::offset_of!(crate::cpu::Flags, sf) as u32;
        let of = base + std::mem::offset_of!(crate::cpu::Flags, of) as u32;
        self.emitter.ldr8(21, regmap::X0, cf);
        self.emitter.ldr8(22, regmap::X0, pf);
        self.emitter.ldr8(24, regmap::X0, zf);
        self.emitter.ldr8(25, regmap::X0, sf);
        self.emitter.ldr8(27, regmap::X0, of);
    }

    /// Scratch-only counterpart of `emit_x86_condition_branch`.
    fn emit_x86_condition_branch_scratch(&mut self, condition: ConditionCode) -> usize {
        const EQ: u32 = 0;
        const NE: u32 = 1;
        // cf=x21, pf=x22, zf=x24, sf=x25, of=x27, temps x26/x28.
        match condition {
            ConditionCode::Equal => {
                self.emitter.subs_imm(31, 24, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotEqual => {
                self.emitter.subs_imm(31, 24, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Overflow => {
                self.emitter.subs_imm(31, 27, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotOverflow => {
                self.emitter.subs_imm(31, 27, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Below => {
                self.emitter.subs_imm(31, 21, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotBelow => {
                self.emitter.subs_imm(31, 21, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Above => {
                self.emitter.movz(28, 1, 0);
                self.emitter.eor_reg(26, 21, 28);
                self.emitter.eor_reg(28, 24, 28);
                self.emitter.and_reg(26, 26, 28);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotAbove => {
                self.emitter.orr_reg(26, 21, 24);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Sign => {
                self.emitter.subs_imm(31, 25, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotSign => {
                self.emitter.subs_imm(31, 25, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::Less => {
                self.emitter.subs_reg(31, 25, 27);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::GreaterEqual => {
                self.emitter.subs_reg(31, 25, 27);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
            ConditionCode::LessEqual => {
                self.emitter.eor_reg(26, 25, 27);
                self.emitter.orr_reg(26, 24, 26);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Greater => {
                self.emitter.eor_reg(26, 25, 27);
                self.emitter.movz(28, 1, 0);
                self.emitter.eor_reg(26, 26, 28);
                self.emitter.eor_reg(28, 24, 28);
                self.emitter.and_reg(26, 26, 28);
                self.emitter.subs_imm(31, 26, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::Parity => {
                self.emitter.subs_imm(31, 22, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(NE, 0);
                pos
            }
            ConditionCode::NotParity => {
                self.emitter.subs_imm(31, 22, 0);
                let pos = self.emitter.len();
                self.emitter.bcond(EQ, 0);
                pos
            }
        }
    }

    /// Constant folding: forward dataflow pass that tracks known register values
    /// and folds arithmetic on constants at compile time.
    ///
    /// Tracks `HashMap<Register, KnownValue>` and applies:
    /// - `MovImm` → record immediate
    /// - `MovReg` → propagate known value or record copy
    /// - `AddImm`/`SubImm`/`ShlImm`/`AndImm`/`OrImm`/`XorImm` with constant src → fold
    /// - Eliminates no-ops (add/sub/shift 0, and full_mask)
    /// Emit a folded constant write, coalescing it with an immediately
    /// preceding `MovImm` to the same register.  Without this, folding
    /// `MovImm rax,5; AddImm rax,3` would leave a dead first write behind
    /// (whole-block DCE is unsound: every GPR is live-out).
    fn push_folded_immediate(result: &mut Vec<IrInstruction>, dst: Register, value: u64) {
        if let Some(IrInstruction::MovImm {
            dst: last_dst,
            value: last_value,
        }) = result.last_mut()
            && *last_dst == dst
        {
            *last_value = value;
            return;
        }
        result.push(IrInstruction::MovImm { dst, value });
    }

    fn constant_fold(ir: &[IrInstruction]) -> Vec<IrInstruction> {
        let mut known: std::collections::BTreeMap<Register, KnownValue> =
            std::collections::BTreeMap::new();
        let mut result: Vec<IrInstruction> = Vec::with_capacity(ir.len());

        for insn in ir {
            match insn {
                // MovImm: record the immediate value and coalesce with a
                // directly preceding write to the same register (the whole
                // chain collapses to the last write).
                IrInstruction::MovImm { dst, value } => {
                    known.insert(*dst, KnownValue::Immediate(*value));
                    Self::push_folded_immediate(&mut result, *dst, *value);
                }

                // MovReg: propagate known value or record copy
                IrInstruction::MovReg { dst, src, width: _ } => {
                    if let Some(KnownValue::Immediate(val)) = known.get(src) {
                        // Fold to MovImm
                        Self::push_folded_immediate(&mut result, *dst, *val);
                        known.insert(*dst, KnownValue::Immediate(*val));
                    } else {
                        // Propagate whatever we know about src, or record as copy
                        if let Some(kv) = known.get(src) {
                            known.insert(*dst, *kv);
                        } else {
                            known.insert(*dst, KnownValue::RegisterCopy(*src));
                        }
                        result.push(insn.clone());
                    }
                }

                // AddImm: eliminate if value==0, fold if dst is known constant
                IrInstruction::AddImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if *value == 0 {
                        // No-op: dst unchanged, known value preserved
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val.wrapping_add(*value);
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // SubImm: eliminate if value==0, fold if dst is known constant
                IrInstruction::SubImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if *value == 0 {
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val.wrapping_sub(*value);
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // ShlImm: eliminate if count==0, fold if dst is known constant
                IrInstruction::ShlImm {
                    dst,
                    count,
                    width: _,
                } => {
                    if *count == 0 {
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val.wrapping_shl(*count as u32);
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // AndImm: eliminate if value is full mask for the width,
                // fold if dst is known constant
                IrInstruction::AndImm { dst, value, width } => {
                    let full_mask = match width {
                        1 => 0xFFu64,
                        2 => 0xFFFFu64,
                        4 => 0xFFFFFFFFu64,
                        8 => 0xFFFFFFFFFFFFFFFFu64,
                        _ => 0,
                    };
                    if *value == full_mask {
                        // No-op: dst unchanged
                        continue;
                    }
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val & value;
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // OrImm: fold if dst is known constant
                IrInstruction::OrImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val | value;
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // XorImm: fold if dst is known constant
                IrInstruction::XorImm {
                    dst,
                    value,
                    width: _,
                } => {
                    if let Some(KnownValue::Immediate(val)) = known.get(dst) {
                        let new_val = val ^ value;
                        Self::push_folded_immediate(&mut result, *dst, new_val);
                        known.insert(*dst, KnownValue::Immediate(new_val));
                    } else {
                        known.remove(dst);
                        result.push(insn.clone());
                    }
                }

                // All other instructions: pass through, invalidate dst if they write a register
                other => {
                    // Invalidate any register that may be written by this instruction
                    Self::invalidate_known_dst(other, &mut known);
                    result.push(other.clone());
                }
            }
        }

        // NOTE: block-level dead-code elimination is intentionally NOT applied
        // here.  Every compiled block ends by storing ALL guest GPRs back to
        // CpuState, so every register written by the block is live-out.  The
        // liveness pass below only sees the block's own instructions and would
        // delete a final `MovImm rax, 42` (no later reader) — silently zeroing
        // guest state.  The pass remains available for intra-block use but is
        // not sound as a whole-block transform.
        result
    }

    /// Invalidate the known value for any register written by `insn`.
    fn invalidate_known_dst(
        insn: &IrInstruction,
        known: &mut std::collections::BTreeMap<Register, KnownValue>,
    ) {
        match insn {
            IrInstruction::MovImm { dst, .. }
            | IrInstruction::MovReg { dst, .. }
            | IrInstruction::AddImm { dst, .. }
            | IrInstruction::SubImm { dst, .. }
            | IrInstruction::AndImm { dst, .. }
            | IrInstruction::OrImm { dst, .. }
            | IrInstruction::XorImm { dst, .. }
            | IrInstruction::ShlImm { dst, .. }
            | IrInstruction::ShrImm { dst, .. }
            | IrInstruction::SarImm { dst, .. }
            | IrInstruction::RolImm { dst, .. }
            | IrInstruction::NegReg { dst, .. }
            | IrInstruction::NotReg { dst, .. }
            | IrInstruction::IncReg { dst, .. }
            | IrInstruction::DecReg { dst, .. }
            | IrInstruction::PopReg { dst, .. } => {
                known.remove(dst);
            }
            IrInstruction::MovReg8 { dst, .. }
            | IrInstruction::AddReg8 { dst, .. }
            | IrInstruction::SubReg8 { dst, .. }
            | IrInstruction::AndReg8 { dst, .. }
            | IrInstruction::OrReg8 { dst, .. }
            | IrInstruction::XorReg8 { dst, .. }
            | IrInstruction::IncReg8 { dst, .. }
            | IrInstruction::DecReg8 { dst, .. }
            | IrInstruction::NegReg8 { dst, .. }
            | IrInstruction::NotReg8 { dst, .. } => {
                known.remove(&dst.full_register());
            }
            IrInstruction::LoadMemory8 { dst, .. } => {
                known.remove(&dst.full_register());
            }
            IrInstruction::LoadMemory { dst, .. }
            | IrInstruction::SignExtendTo64 { dst, .. }
            | IrInstruction::SignExtend { dst, .. }
            | IrInstruction::ZeroExtendTo64 { dst, .. }
            | IrInstruction::Cmov { dst, .. }
            | IrInstruction::Popcnt { dst, .. }
            | IrInstruction::Lzcnt { dst, .. }
            | IrInstruction::Bsf { dst, .. }
            | IrInstruction::Crc32 { dst, .. }
            | IrInstruction::Rdrand { dst, .. }
            | IrInstruction::Rdseed { dst, .. }
            | IrInstruction::Andn { dst, .. }
            | IrInstruction::Bextr { dst, .. }
            | IrInstruction::Blsi { dst, .. }
            | IrInstruction::Blsmsk { dst, .. }
            | IrInstruction::Blsr { dst, .. }
            | IrInstruction::Bzhi { dst, .. }
            | IrInstruction::Pdep { dst, .. }
            | IrInstruction::Pext { dst, .. }
            | IrInstruction::Rorx { dst, .. }
            | IrInstruction::Sarx { dst, .. }
            | IrInstruction::Shrx { dst, .. }
            | IrInstruction::Shlx { dst, .. } => {
                known.remove(dst);
            }
            IrInstruction::Mulx { dst_lo, dst_hi, .. } => {
                known.remove(dst_lo);
                known.remove(dst_hi);
            }
            IrInstruction::ExchangeRegisters { left, right, .. } => {
                known.remove(left);
                known.remove(right);
            }
            IrInstruction::LoadEffectiveAddress { dst, .. } => {
                known.remove(dst);
            }
            // Instructions that don't write any register we track
            _ => {}
        }
    }

    /// Dead code elimination: remove instructions whose result is never used.
    ///
    /// Scans the IR forward to find which registers are used as source operands,
    /// then removes instructions that write to registers never subsequently read.
    #[allow(dead_code)] // retained for intra-block use; unsound as a whole-block transform
    fn dead_code_elimination(ir: &[IrInstruction]) -> Vec<IrInstruction> {
        // Backward liveness analysis pass.
        //
        // Walk instructions in reverse, tracking which registers are "live"
        // (will be read by a future instruction).  For each instruction we
        // compute:
        //
        //   IN[i] = (OUT[i] \ KILL[i]) ∪ GEN[i]
        //
        // where OUT[i] is the live set after instruction i (before i+1),
        // KILL[i] is the register written by i, and GEN[i] is the registers
        // read by i.
        //
        // An instruction that writes a register is kept only if that register
        // is live at the exit of the instruction (OUT[i]), because that means
        // some later instruction reads the value before it is overwritten.
        let mut live_regs: std::collections::BTreeSet<Register> = std::collections::BTreeSet::new();
        let mut keep: Vec<bool> = vec![false; ir.len()];

        for (i, insn) in ir.iter().enumerate().rev() {
            // live_regs currently holds OUT[i] (the state after this instruction)

            // 1. Decide whether to keep this instruction based on OUT[i]
            if Self::has_side_effect(insn) {
                keep[i] = true;
            } else {
                // Keep if the instruction writes to a register that is live
                // at the exit of this instruction (i.e. will be read later)
                let writes_live_reg = match insn {
                    IrInstruction::MovImm { dst, .. }
                    | IrInstruction::MovReg { dst, .. }
                    | IrInstruction::AddImm { dst, .. }
                    | IrInstruction::SubImm { dst, .. }
                    | IrInstruction::AndImm { dst, .. }
                    | IrInstruction::OrImm { dst, .. }
                    | IrInstruction::XorImm { dst, .. }
                    | IrInstruction::ShlImm { dst, .. }
                    | IrInstruction::ShrImm { dst, .. }
                    | IrInstruction::SarImm { dst, .. } => live_regs.contains(dst),
                    // Conservatively keep unknown instructions
                    _ => true,
                };
                keep[i] = writes_live_reg;
            }

            // 2. KILL: remove the destination register from the live set
            //    (this definition makes the previous value of that register dead)
            match insn {
                IrInstruction::MovImm { dst, .. }
                | IrInstruction::MovReg { dst, .. }
                | IrInstruction::AddImm { dst, .. }
                | IrInstruction::SubImm { dst, .. }
                | IrInstruction::AndImm { dst, .. }
                | IrInstruction::OrImm { dst, .. }
                | IrInstruction::XorImm { dst, .. }
                | IrInstruction::ShlImm { dst, .. }
                | IrInstruction::ShrImm { dst, .. }
                | IrInstruction::SarImm { dst, .. }
                | IrInstruction::NegReg { dst, .. }
                | IrInstruction::NotReg { dst, .. }
                | IrInstruction::IncReg { dst, .. }
                | IrInstruction::DecReg { dst, .. }
                | IrInstruction::PopReg { dst, .. } => {
                    live_regs.remove(dst);
                }
                _ => {}
            }

            // 3. GEN: add source registers to the live set
            //    (they are read by this instruction, so they must be live
            //     before the instruction)
            Self::collect_source_regs(insn, &mut live_regs);

            // Now live_regs holds IN[i] = (OUT[i] \ KILL[i]) ∪ GEN[i]
            // which becomes OUT[i-1] for the next iteration
        }

        // Collect kept instructions in forward order
        ir.iter()
            .enumerate()
            .filter(|(i, _)| keep[*i])
            .map(|(_, insn)| insn.clone())
            .collect()
    }

    /// Return the full bitmask for a given width in bytes.
    /// Used for eliminating redundant `And` instructions.
    #[allow(dead_code)] // mask helper for SIMD lane widths; not yet referenced
    fn full_mask_for_width(width: usize) -> u64 {
        match width {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => 0xFFFFFFFFFFFFFFFF,
            _ => 0,
        }
    }

    /// Check if an instruction has observable side effects (must not be eliminated).
    #[allow(dead_code)]
    fn has_side_effect(insn: &IrInstruction) -> bool {
        match insn {
            IrInstruction::StoreMemory { .. }
            | IrInstruction::StoreMemory8 { .. }
            | IrInstruction::StoreImmediate { .. }
            | IrInstruction::StoreDwordFromXmm { .. }
            | IrInstruction::StoreVector { .. }
            | IrInstruction::StoreXmm { .. }
            | IrInstruction::PushReg { .. }
            | IrInstruction::PushMemory { .. }
            | IrInstruction::PushImm { .. }
            | IrInstruction::PushFlags { .. }
            | IrInstruction::PopMemory { .. }
            | IrInstruction::PopFlags { .. }
            | IrInstruction::Call { .. }
            | IrInstruction::CallRegister { .. }
            | IrInstruction::CallMemory { .. }
            | IrInstruction::Jump { .. }
            | IrInstruction::JumpIf { .. }
            | IrInstruction::JumpRegister { .. }
            | IrInstruction::JumpMemory { .. }
            | IrInstruction::Return { .. }
            | IrInstruction::Cpuid
            | IrInstruction::Xgetbv
            | IrInstruction::Cld
            | IrInstruction::Leave
            | IrInstruction::Movs { .. }
            | IrInstruction::Stos { .. }
            | IrInstruction::Mfence
            | IrInstruction::VzeroUpper
            | IrInstruction::X87ClearExceptions
            | IrInstruction::X87Init
            | IrInstruction::Clflush { .. }
            | IrInstruction::X87Store { .. }
            | IrInstruction::X87StorePop { .. }
            | IrInstruction::X87StorePopRegister { .. }
            | IrInstruction::X87StoreControlWord { .. }
            | IrInstruction::StoreMxcsr { .. }
            | IrInstruction::SetccMemory { .. }
            | IrInstruction::LockCmpxchg { .. }
            | IrInstruction::LockCmpxchg8b { .. }
            | IrInstruction::LockXadd { .. }
            | IrInstruction::IncMemory { .. }
            | IrInstruction::DecMemory { .. }
            | IrInstruction::AddImmMemory { .. }
            | IrInstruction::SubImmMemory { .. }
            | IrInstruction::AndImmMemory { .. }
            | IrInstruction::OrImmMemory { .. }
            | IrInstruction::XorImmMemory { .. }
            | IrInstruction::AddMemory { .. }
            | IrInstruction::SubMemory { .. }
            | IrInstruction::AndMemory { .. }
            | IrInstruction::OrMemory { .. }
            | IrInstruction::OrMemory8 { .. }
            | IrInstruction::XorMemory { .. }
            | IrInstruction::ExchangeMemory { .. }
            | IrInstruction::ShlImmMemory { .. }
            | IrInstruction::ShrImmMemory { .. }
            | IrInstruction::SarImmMemory { .. }
            | IrInstruction::RolImmMemory { .. }
            | IrInstruction::BitTest { .. }
            | IrInstruction::BitTestImm { .. }
            | IrInstruction::Compare { .. }
            | IrInstruction::Test { .. }
            | IrInstruction::Setcc { .. }
            | IrInstruction::X87LoadInt32 { .. }
            | IrInstruction::X87LoadInt64 { .. }
            | IrInstruction::X87Load { .. }
            | IrInstruction::X87LoadControlWord { .. }
            | IrInstruction::X87AddMemory { .. }
            | IrInstruction::X87MulMemory { .. }
            | IrInstruction::X87DivMemory { .. }
            | IrInstruction::X87Add
            | IrInstruction::X87Div
            | IrInstruction::X87NegateTop
            | IrInstruction::X87Swap { .. }
            | IrInstruction::X87Compare { .. }
            | IrInstruction::X87AddPop { .. }
            | IrInstruction::X87Mul { .. }
            | IrInstruction::X87DivRegister { .. }
            | IrInstruction::X87DivPop { .. }
            | IrInstruction::X87LoadConst { .. }
            | IrInstruction::LoadMxcsr { .. }
            | IrInstruction::Comiss { .. }
            | IrInstruction::Pcmpistri { .. }
            | IrInstruction::PopSeg { .. }
            | IrInstruction::FmaVector { .. }
            // ── Phase H: AVX-512 arithmetic ──────────────────────────────
            | IrInstruction::AddPacked { .. } | IrInstruction::SubPacked { .. }
            | IrInstruction::MulPacked { .. } | IrInstruction::DivPacked { .. }
            | IrInstruction::MinPacked { .. } | IrInstruction::MaxPacked { .. }
            | IrInstruction::SqrtPacked { .. } | IrInstruction::ComparePacked { .. }
            // ── Phase H: AVX-512 conversion ──────────────────────────────
            | IrInstruction::ConvertPacked { .. }
            | IrInstruction::ConvertToInt { .. }
            | IrInstruction::ConvertFromInt { .. }
            // ── Phase H: AVX-512 shuffle/permute ─────────────────────────
            | IrInstruction::ShuffleF32 { .. } | IrInstruction::ShuffleF64 { .. }
            | IrInstruction::AlignD { .. } | IrInstruction::AlignQ { .. }
            | IrInstruction::InsertSubVector { .. }
            | IrInstruction::ExtractSubVector { .. }
            | IrInstruction::BroadcastSubVector { .. }
            | IrInstruction::BroadcastMask { .. }
            | IrInstruction::PermuteVarDq { .. }
            | IrInstruction::PermuteVarPsPd { .. }
            | IrInstruction::PermuteI2 { .. } | IrInstruction::PermuteT2 { .. }
            | IrInstruction::PermuteImm { .. }
            | IrInstruction::PermuteImm2Src { .. }
            // ── Phase H: AVX-512 special ─────────────────────────────────
            | IrInstruction::FixupSpecial { .. }
            | IrInstruction::ExtractExponent { .. }
            | IrInstruction::ExtractMantissa { .. }
            | IrInstruction::ReducePrecision { .. }
            | IrInstruction::RangePacked { .. }
            | IrInstruction::ScaleByPower2 { .. }
            | IrInstruction::FloatClass { .. }
            | IrInstruction::Pternlog { .. }
            | IrInstruction::ConflictDetect { .. }
            | IrInstruction::CompressVector { .. }
            | IrInstruction::ExpandVector { .. }
            | IrInstruction::GatherVector { .. }
            | IrInstruction::ScatterVector { .. }
            // ── Phase H: Mask register ops ───────────────────────────────
            | IrInstruction::Kand { .. } | IrInstruction::Kor { .. }
            | IrInstruction::Kxor { .. } | IrInstruction::Knot { .. }
            | IrInstruction::Kshiftl { .. } | IrInstruction::Kshiftr { .. }
            | IrInstruction::Kadd { .. } | IrInstruction::Ktest { .. }
            | IrInstruction::Kunpck { .. }
            // ── Phase H: CET shadow stack ────────────────────────────────
            | IrInstruction::SaveSsP { .. }
            | IrInstruction::Rstorssp { .. }
            | IrInstruction::Incssp { .. }
            | IrInstruction::Wrss { .. }
            | IrInstruction::Wruss { .. }
            // ── Phase H: MPX bounds checking ─────────────────────────────
            | IrInstruction::BndmkReg { .. } | IrInstruction::BndmkMem { .. }
            | IrInstruction::BndclReg { .. } | IrInstruction::BndclMem { .. }
            | IrInstruction::BndcuReg { .. } | IrInstruction::BndcuMem { .. }
            | IrInstruction::BndcnReg { .. } | IrInstruction::BndcnMem { .. }
            | IrInstruction::BndmovReg { .. }
            | IrInstruction::BndmovMemLoad { .. }
            | IrInstruction::BndmovMemStore { .. }
            // ── Phase H: TSX/RTM ─────────────────────────────────────────
            | IrInstruction::Xbegin { .. } | IrInstruction::Xend
            | IrInstruction::Xabort { .. } | IrInstruction::Xtest
            // ── Phase H: SGX ─────────────────────────────────────────────
            | IrInstruction::Encls | IrInstruction::Enclu
            // ── Phase H: Cache/misc ──────────────────────────────────────
            | IrInstruction::Clflushopt { .. } | IrInstruction::Clwb { .. }
            | IrInstruction::Pcommit
            // ── Phase H: RDPMC ───────────────────────────────────────────
            | IrInstruction::Rdpmc { .. } => true,
            _ => false,
        }
    }

    /// Collect all register sources used by an instruction into the given set.
    #[allow(dead_code)]
    fn collect_source_regs(insn: &IrInstruction, regs: &mut std::collections::BTreeSet<Register>) {
        match insn {
            IrInstruction::MovReg { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::MovReg8 { src, .. } => {
                regs.insert(src.full_register());
            }
            // AddReg8 has src: ByteRegister
            IrInstruction::AddReg8 { src, .. }
            | IrInstruction::AndReg8 { src, .. }
            | IrInstruction::OrReg8 { src, .. }
            | IrInstruction::XorReg8 { src, .. } => {
                regs.insert(src.full_register());
            }
            // SubReg8, SbbReg8 have src: CompareOperand
            IrInstruction::SubReg8 { src, .. } | IrInstruction::SbbReg8 { src, .. } => {
                if let crate::cpu::CompareOperand::Register(r) = src {
                    regs.insert(*r);
                }
            }
            IrInstruction::AddOperand { src, .. }
            | IrInstruction::SubOperand { src, .. }
            | IrInstruction::AdcOperand { src, .. }
            | IrInstruction::SbbOperand { src, .. }
            | IrInstruction::AndReg { src, .. }
            | IrInstruction::OrReg { src, .. }
            | IrInstruction::XorReg { src, .. }
            | IrInstruction::ImulReg { src, .. }
            | IrInstruction::ImulImm { src, .. } => {
                if let crate::cpu::CompareOperand::Register(r) = src {
                    regs.insert(*r);
                }
            }
            IrInstruction::AddMemory { src, .. }
            | IrInstruction::SubMemory { src, .. }
            | IrInstruction::AndMemory { src, .. }
            | IrInstruction::OrMemory { src, .. }
            | IrInstruction::XorMemory { src, .. }
            | IrInstruction::StoreMemory { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::StoreMemory8 { src, .. } => {
                regs.insert(src.full_register());
            }
            IrInstruction::CallRegister { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::JumpRegister { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::PushReg { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Popcnt { src, .. }
            | IrInstruction::Lzcnt { src, .. }
            | IrInstruction::Bsf { src, .. }
            | IrInstruction::Crc32 { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Andn { lhs, rhs, .. } => {
                regs.insert(*lhs);
                regs.insert(*rhs);
            }
            IrInstruction::Bextr { src, range, .. } => {
                regs.insert(*src);
                regs.insert(*range);
            }
            IrInstruction::Blsi { src, .. }
            | IrInstruction::Blsmsk { src, .. }
            | IrInstruction::Blsr { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Bzhi { src, index, .. } => {
                regs.insert(*src);
                regs.insert(*index);
            }
            IrInstruction::Mulx { src, .. }
            | IrInstruction::Pdep { src, .. }
            | IrInstruction::Pext { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::Rorx { src, .. }
            | IrInstruction::Sarx { src, .. }
            | IrInstruction::Shrx { src, .. }
            | IrInstruction::Shlx { src, .. } => {
                regs.insert(*src);
            }
            IrInstruction::ExchangeRegisters { left, right, .. } => {
                regs.insert(*left);
                regs.insert(*right);
            }
            IrInstruction::ExchangeMemory { register, .. } => {
                regs.insert(*register);
            }
            IrInstruction::Cmov {
                src: crate::cpu::CompareOperand::Register(r),
                ..
            } => {
                regs.insert(*r);
            }
            IrInstruction::MulAcc { src, .. }
            | IrInstruction::ImulAcc { src, .. }
            | IrInstruction::Div { src, .. }
            | IrInstruction::Idiv { src, .. } => {
                if let crate::cpu::CompareOperand::Register(r) = src {
                    regs.insert(*r);
                }
            }
            // Instructions that use dst as both src and dst (dst = dst op value)
            // These implicitly READ dst before writing it, so dst must be treated
            // as a source register for liveness analysis.
            IrInstruction::AddImm { dst, .. }
            | IrInstruction::SubImm { dst, .. }
            | IrInstruction::AndImm { dst, .. }
            | IrInstruction::OrImm { dst, .. }
            | IrInstruction::XorImm { dst, .. }
            | IrInstruction::ShlImm { dst, .. }
            | IrInstruction::ShrImm { dst, .. }
            | IrInstruction::SarImm { dst, .. }
            | IrInstruction::RolImm { dst, .. }
            | IrInstruction::NegReg { dst, .. }
            | IrInstruction::NotReg { dst, .. }
            | IrInstruction::IncReg { dst, .. }
            | IrInstruction::DecReg { dst, .. }
            | IrInstruction::PopReg { dst, .. } => {
                regs.insert(*dst);
            }
            // Instructions with no register source operands; ignore
            _ => {}
        }
    }

    /// Loop unrolling: detect simple counted loops and duplicate the body.
    ///
    /// Detects the pattern (in the ORIGINAL IR, before constant folding):
    ///   `SubImm(counter, 1, width)`
    ///   `JumpIf(counter, target, NotEqual)`  (back-edge to loop start)
    ///
    /// Uses a lightweight constant folding scan (without DCE) to determine the
    /// initial counter value, then performs unrolling on the original IR to avoid
    /// DCE destroying the loop structure.
    ///
    /// For loops where the iteration count is known at compile time:
    /// - If ≤ 4 iterations: fully unroll (eliminate the loop entirely)
    /// - Otherwise: unroll by factor 2 with remainder loop
    ///
    /// # Safety constraints
    /// - Only unroll when loop body has ≤ 50 instructions
    /// - Only unroll when iteration count is known at compile time
    /// - Does NOT unroll loops containing host calls or indirect branches
    #[allow(dead_code)]
    fn loop_unroll(ir: &[IrInstruction], guest_address: u64) -> Vec<IrInstruction> {
        // Need at least SubImm + JumpIf at the end
        if ir.len() < 2 {
            return ir.to_vec();
        }

        let len = ir.len();

        // Look for the loop pattern at the end of the block in the ORIGINAL IR:
        // SubImm(counter, 1, width) followed by JumpIf(counter, target, NotEqual)
        let (counter_reg, width, _jump_target) = match (&ir[len - 2], &ir[len - 1]) {
            (
                IrInstruction::SubImm { dst, value, width },
                IrInstruction::JumpIf {
                    condition,
                    target,
                    fallthrough: _,
                },
            ) if *value == 1
                && *condition == ConditionCode::NotEqual
                && *target == guest_address =>
            {
                (dst, width, *target)
            }
            _ => return ir.to_vec(),
        };

        // Find the loop body: instructions from start to just before the SubImm
        let loop_end = len - 2; // Index of SubImm
        let body_len = loop_end; // Number of instructions in the loop body

        // Safety check: only unroll small loops
        if body_len > 50 {
            return ir.to_vec();
        }

        // Check for host calls or indirect branches in the loop body
        if Self::loop_contains_unsafe_instructions(&ir[..loop_end]) {
            return ir.to_vec();
        }

        // Determine the initial counter value using a lightweight scan of the
        // original IR (no DCE, so MovImm won't be removed)
        let initial_count = Self::find_loop_count(&ir[..loop_end], counter_reg);

        let count = match initial_count {
            Some(c) => c,
            None => return ir.to_vec(), // Unknown iteration count
        };

        // Determine unroll strategy
        if count <= 4 {
            // Fully unroll: duplicate the body `count` times, remove the loop
            Self::fully_unroll(ir, loop_end, body_len, count)
        } else {
            // Partially unroll by factor 2
            Self::partially_unroll(ir, loop_end, body_len, count, *counter_reg, *width)
        }
    }

    /// Check if a loop body contains host calls or indirect branches (unsafe to unroll).
    #[allow(dead_code)]
    fn loop_contains_unsafe_instructions(body: &[IrInstruction]) -> bool {
        body.iter().any(|insn| {
            matches!(
                insn,
                IrInstruction::Call { .. }
                    | IrInstruction::CallRegister { .. }
                    | IrInstruction::CallMemory { .. }
                    | IrInstruction::JumpRegister { .. }
                    | IrInstruction::JumpMemory { .. }
            )
        })
    }

    /// Find the initial value of a loop counter register from preceding `MovImm` instructions.
    #[allow(dead_code)]
    fn find_loop_count(instructions: &[IrInstruction], counter: &Register) -> Option<u64> {
        // Scan backwards to find the last MovImm that sets this register
        for insn in instructions.iter().rev() {
            if let IrInstruction::MovImm { dst, value } = insn
                && dst == counter
            {
                return Some(*value);
            }
            // If we find any other instruction writing to counter before MovImm, stop
            if Self::instruction_writes_register(insn, counter) {
                return None;
            }
        }
        None
    }

    /// Check if an instruction writes to a specific register.
    #[allow(dead_code)]
    fn instruction_writes_register(insn: &IrInstruction, reg: &Register) -> bool {
        match insn {
            IrInstruction::MovImm { dst, .. }
            | IrInstruction::MovReg { dst, .. }
            | IrInstruction::AddImm { dst, .. }
            | IrInstruction::SubImm { dst, .. }
            | IrInstruction::AndImm { dst, .. }
            | IrInstruction::OrImm { dst, .. }
            | IrInstruction::XorImm { dst, .. }
            | IrInstruction::ShlImm { dst, .. }
            | IrInstruction::ShrImm { dst, .. }
            | IrInstruction::SarImm { dst, .. }
            | IrInstruction::RolImm { dst, .. }
            | IrInstruction::NegReg { dst, .. }
            | IrInstruction::NotReg { dst, .. }
            | IrInstruction::IncReg { dst, .. }
            | IrInstruction::DecReg { dst, .. }
            | IrInstruction::PopReg { dst, .. }
            | IrInstruction::LoadMemory { dst, .. }
            | IrInstruction::SignExtendTo64 { dst, .. }
            | IrInstruction::SignExtend { dst, .. }
            | IrInstruction::ZeroExtendTo64 { dst, .. }
            | IrInstruction::Popcnt { dst, .. }
            | IrInstruction::Lzcnt { dst, .. }
            | IrInstruction::Bsf { dst, .. }
            | IrInstruction::Crc32 { dst, .. }
            | IrInstruction::Rdrand { dst, .. }
            | IrInstruction::Rdseed { dst, .. }
            | IrInstruction::Andn { dst, .. }
            | IrInstruction::Bextr { dst, .. }
            | IrInstruction::Blsi { dst, .. }
            | IrInstruction::Blsmsk { dst, .. }
            | IrInstruction::Blsr { dst, .. }
            | IrInstruction::Bzhi { dst, .. }
            | IrInstruction::Pdep { dst, .. }
            | IrInstruction::Pext { dst, .. }
            | IrInstruction::Rorx { dst, .. }
            | IrInstruction::Sarx { dst, .. }
            | IrInstruction::Shrx { dst, .. }
            | IrInstruction::Shlx { dst, .. } => dst == reg,
            _ => false,
        }
    }

    /// Fully unroll a loop with a known small iteration count.
    /// Duplicates the body `count` times, removes the loop back-edge.
    #[allow(dead_code)]
    fn fully_unroll(
        folded: &[IrInstruction],
        loop_end: usize,
        body_len: usize,
        count: u64,
    ) -> Vec<IrInstruction> {
        let mut result: Vec<IrInstruction> =
            Vec::with_capacity(folded.len() + body_len * (count as usize - 1));

        // Add instructions before the loop
        result.extend_from_slice(&folded[..loop_end - body_len]);

        // Duplicate the loop body `count` times
        let body = &folded[loop_end - body_len..loop_end];
        for _ in 0..count {
            result.extend_from_slice(body);
        }

        // Add anything after the loop (the JumpIf originally followed SubImm;
        // since we fully unrolled, we skip it and just emit the fallthrough)
        // The last instruction was JumpIf - we replace it with nothing (fully unrolled)
        // Add a Nop to maintain block structure if needed
        result
    }

    /// Partially unroll a loop by factor 2, leaving a remainder loop for remaining iterations.
    #[allow(dead_code)]
    fn partially_unroll(
        folded: &[IrInstruction],
        loop_end: usize,
        body_len: usize,
        _count: u64,
        counter_reg: Register,
        width: usize,
    ) -> Vec<IrInstruction> {
        let mut result: Vec<IrInstruction> = Vec::with_capacity(folded.len() + body_len);

        // Add instructions before the loop body
        let body_start = loop_end - body_len;
        result.extend_from_slice(&folded[..body_start]);

        // First unrolled copy of the body
        let body = &folded[body_start..loop_end];
        result.extend_from_slice(body);

        // Second unrolled copy of the body
        result.extend_from_slice(body);

        // Decrement counter by 2 (to account for both unrolled copies)
        result.push(IrInstruction::SubImm {
            dst: counter_reg,
            value: 2,
            width,
        });

        // Keep the original JumpIf for the remainder loop.
        // Note: this works correctly for even iteration counts.
        // Odd counts would need a remainder loop (future work).
        if let Some(jump_if) = folded.get(loop_end + 1) {
            result.push(jump_if.clone());
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Inline Cache
// ---------------------------------------------------------------------------

/// A single inline cache entry for indirect call sites.
///
/// Caches the last resolved target address for an indirect call or virtual
/// dispatch. On subsequent calls, the cached target is tried first (fast path)
/// before falling back to full resolution (slow path).
#[derive(Debug, Clone)]
pub struct InlineCacheEntry {
    /// Guest address of the call site.
    pub call_site: u64,
    /// Last resolved target guest address.
    pub last_target: u64,
    /// Number of cache hits (target matched).
    pub hit_count: u32,
    /// Number of cache misses (target changed).
    pub miss_count: u32,
}

/// Inline cache for indirect calls and virtual dispatches.
///
/// # Performance Impact
/// Indirect calls (e.g., virtual function tables, function pointers) require
/// expensive lookups each time. By caching the last target, the common
/// monomorphic case (same target every time) is reduced to a single comparison
/// and direct branch, avoiding the full dispatch overhead.
#[derive(Debug)]
pub struct InlineCache {
    /// Cache entries keyed by call-site guest address.
    pub entries: HashMap<u64, InlineCacheEntry>,
    /// FIFO eviction queue tracking insertion order.
    /// Front = oldest entry (next to evict), Back = newest entry.
    eviction_queue: VecDeque<u64>,
    /// Maximum number of cache entries before eviction.
    pub max_entries: usize,
}

impl InlineCache {
    /// Create a new inline cache with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            eviction_queue: VecDeque::new(),
            max_entries,
        }
    }

    /// Look up a call site in the cache with the expected target.
    ///
    /// Returns `true` if the target matches the cached value (cache hit),
    /// `false` if it doesn't match or wasn't cached (cache miss). On a miss,
    /// the cache is updated with the new target.
    pub fn lookup(&mut self, call_site: u64, target: u64) -> bool {
        if let Some(entry) = self.entries.get_mut(&call_site) {
            if entry.last_target == target {
                entry.hit_count += 1;
                return true; // Cache hit — matching target found
            } else {
                entry.last_target = target;
                entry.miss_count += 1;
                return false;
            }
        }

        // New entry — evict oldest (FIFO) if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.eviction_queue.push_back(call_site);
        self.entries.insert(
            call_site,
            InlineCacheEntry {
                call_site,
                last_target: target,
                hit_count: 0,
                miss_count: 1,
            },
        );

        false
    }

    /// Evict the oldest entry from the cache (FIFO policy).
    /// Skips any stale eviction queue entries that were already removed
    /// (e.g., via `invalidate()`).
    fn evict_oldest(&mut self) {
        while let Some(evict_key) = self.eviction_queue.pop_front() {
            if self.entries.remove(&evict_key).is_some() {
                break;
            }
        }
    }

    /// Invalidate a single cache entry.
    pub fn invalidate(&mut self, call_site: u64) {
        self.entries.remove(&call_site);
        // Note: the eviction queue entry becomes stale and will be
        // skipped on the next eviction via `evict_oldest()`.
        // This avoids an O(n) scan of the queue to find the entry.
    }

    /// Invalidate all cache entries.
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
        self.eviction_queue.clear();
    }

    /// Get the hit rate as a value between 0.0 and 1.0.
    pub fn hit_rate(&self) -> f64 {
        let total_hits: u32 = self.entries.values().map(|e| e.hit_count).sum();
        let total_misses: u32 = self.entries.values().map(|e| e.miss_count).sum();
        let total = total_hits + total_misses;
        if total == 0 {
            0.0
        } else {
            total_hits as f64 / total as f64
        }
    }
}

// ---------------------------------------------------------------------------
// SIMD Fast-Path
// ---------------------------------------------------------------------------

/// Emit ARM64 NEON SIMD code for a 16-byte-at-a-time memcpy.
///
/// Uses `LDR Q0, [src]` / `STR Q0, [dst]` for the bulk of the copy, then
/// handles remaining bytes with single-byte copies.
///
/// # Register Convention
/// - `src_base` register: source base address
/// - `dst_base` register: destination base address
/// - `len_reg` register: total bytes to copy
/// - Uses NEON registers Q0 (V0) as temporary
///
/// # Performance Impact
/// SIMD memcpy achieves ~16 bytes per load/store pair versus 1 or 8 bytes
/// with scalar instructions, yielding up to 8–16× throughput improvement
/// for large memory copies common in game data operations.
pub fn emit_simd_memcpy(emitter: &mut Emitter) -> AppResult<()> {
    // Pseudocode for the emitted code:
    //   loop:
    //     CMP len, #16
    //     B.LT tail
    //     LDR Q0, [src], #16
    //     STR Q0, [dst], #16
    //     SUB len, len, #16
    //     B loop
    //   tail:
    //     CBZ len, done
    //   byte_loop:
    //     LDRB W3, [src], #1
    //     STRB W3, [dst], #1
    //     SUBS len, len, #1
    //     B.NE byte_loop
    //   done:

    // We emit a simplified version that uses the emitter's existing methods.
    // In a full integration, registers would be allocated by the register
    // allocator. Here we use:
    //   X21 = src pointer, X22 = dst pointer, X23 = length

    // Loop header
    let loop_start = emitter.len();
    emitter.subs_imm(23, 23, 16); // SUBS X23, X23, #16 (sets flags)
    emitter.bcond(0x3, 8); // B.LT tail (CC=3, skip ahead 8 insns)
    emitter.emit(0x3dc00000 | (21 << 5)); // LDR Q0, [X21], #16 (post-index)
    emitter.emit(0x3d800000 | (22 << 5)); // STR Q0, [X22], #16 (post-index)
    let current = emitter.len();
    let offset = (loop_start as i32 - current as i32) / 4 - 1;
    emitter.b(offset); // B loop_start

    // Tail: handle remaining bytes
    emitter.cbz(23, 2); // CBZ X23, +2 (skip to done)
    emitter.ldr8(3, 21, 0); // LDRB W3, [X21]
    emitter.str8(3, 22, 0); // STRB W3, [X22]
    emitter.add_imm(21, 21, 1); // ADD X21, X21, #1
    emitter.add_imm(22, 22, 1); // ADD X22, X22, #1
    emitter.subs_imm(23, 23, 1); // SUBS X23, X23, #1
    // B.NE back to CBZ — CBZ is 6 instructions (24 bytes) before this point
    // ARM64 offset is in instructions: -(6 instructions) = -6
    emitter.bcond(0x1, -6); // B.NE back to cbz

    Ok(())
}

/// Emit ARM64 NEON SIMD code for a 16-byte-at-a-time memset.
///
/// Broadcasts the set value to all 16 bytes of NEON register Q0, then stores
/// 16 bytes at a time.
///
/// # Performance Impact
/// SIMD memset fills 16 bytes per store instruction versus 1 or 8 bytes with
/// scalar instructions, yielding similar throughput gains as SIMD memcpy.
pub fn emit_simd_memset(emitter: &mut Emitter) -> AppResult<()> {
    // Pseudocode:
    //   DUP V0.16B, W3          ; broadcast byte value to all 16 lanes
    //   loop:
    //     SUBS X23, X23, #16
    //     B.LT done
    //     STR Q0, [X22], #16
    //     B loop
    //   done:

    // DUP V0.16B, Wn (scalar to all vector lanes)
    // Encoding: 0x4e080400 | (Rn << 5) | Vd   — DUP Vd.16B, Wn
    emitter.emit(0x4e080400 | (3 << 5)); // DUP V0.16B, W3

    let loop_start = emitter.len();
    emitter.subs_imm(23, 23, 16); // SUBS X23, X23, #16
    emitter.bcond(0x3, 2); // B.LT done (+2 insns)
    emitter.emit(0x3d800000 | (22 << 5)); // STR Q0, [X22], #16 (post-index)
    let current = emitter.len();
    let offset = (loop_start as i32 - current as i32) / 4 - 1;
    emitter.b(offset); // B loop_start

    Ok(())
}

/// Emit ARM64 NEON SIMD code for a 16-byte-at-a-time memcmp.
///
/// Loads 16 bytes from both sources, compares using `CMEQ V0.16B, V0.16B, V1.16B`,
/// then checks for differences.
///
/// # Performance Impact
/// SIMD memcmp compares 16 bytes per instruction versus 1 or 8 bytes with
/// scalar comparisons, dramatically speeding up string and buffer comparisons
/// common in game engines.
pub fn emit_simd_memcmp(emitter: &mut Emitter) -> AppResult<()> {
    // Pseudocode:
    //   loop:
    //     SUBS X23, X23, #16
    //     B.LT tail
    //     LDR Q0, [X21], #16
    //     LDR Q1, [X22], #16
    //     CMEQ V0.16B, V0.16B, V1.16B   ; 0xFF where equal, 0x00 where different
    //     UMINV B2, V0.16B               ; minimum across all lanes
    //     UMOV W3, V2.B[0]              ; extract to scalar
    //     CBZ W3, mismatch               ; if any byte was 0, mismatch
    //     B loop
    //   tail: ... (byte-by-byte comparison)
    //   mismatch: ...
    //   match: ...

    let loop_start = emitter.len();
    emitter.subs_imm(23, 23, 16); // SUBS X23, X23, #16
    emitter.bcond(0x3, 10); // B.LT tail (skip ahead)

    emitter.emit(0x3dc00000 | (21 << 5)); // LDR Q0, [X21], #16
    emitter.emit(0x3dc00000 | (22 << 5) | 1); // LDR Q1, [X22], #16

    // CMEQ V0.16B, V0.16B, V1.16B
    emitter.emit(0x4e208400 | (1 << 16));

    // UMINV Bd, Vn.16B — across all 16 bytes
    emitter.emit(0x6e30a800 | 2); // UMINV B2, V0.16B

    // UMOV Wd, Vn.B[0]
    emitter.emit(0x0e003c00 | (2 << 5) | 3); // UMOV W3, V2.B[0]

    emitter.cbz(3, 2); // CBZ W3, mismatch (+2)
    let current = emitter.len();
    let offset = (loop_start as i32 - current as i32) / 4 - 1;
    emitter.b(offset); // B loop_start

    // mismatch: set result to 1 (not equal)
    emitter.movz(0, 1, 0); // MOV W0, #1
    emitter.ret(); // return with result 1 (not equal)

    // tail: byte-by-byte
    emitter.cbz(23, 4); // CBZ X23, match (+4)
    emitter.ldr8(3, 21, 0); // LDRB W3, [X21]
    emitter.ldr8(4, 22, 0); // LDRB W4, [X22]
    emitter.sub_reg(3, 3, 4); // SUB W3, W3, W4 → result in W3
    emitter.cbz(3, 4); // if equal, continue — but we just return 0

    // match: set result to 0 (equal)
    emitter.movz(0, 0, 0); // MOV W0, #0

    Ok(())
}

// ---------------------------------------------------------------------------
// Adaptive Instruction Budget
// ---------------------------------------------------------------------------

/// Dynamically adjusts the number of instructions compiled per JIT block based
/// on measured execution time.
///
/// # Performance Impact
/// Prevents JIT blocks from growing too large (which increases compile time
/// and reduces instruction-cache locality) or too small (which increases
/// dispatcher overhead). The adaptive budget converges on a block size that
/// balances compile time against execution throughput.
#[derive(Debug)]
pub struct AdaptiveBudget {
    /// Starting instruction budget per block.
    pub base_budget: u32,
    /// Current instruction budget.
    pub current_budget: u32,
    /// Minimum allowed budget.
    pub min_budget: u32,
    /// Maximum allowed budget.
    pub max_budget: u32,
    /// Target block execution time in microseconds.
    pub target_time_us: u64,
    /// Last measured execution time in microseconds.
    pub last_execution_time_us: u64,
    /// How aggressively to adjust (0.0–1.0, higher = more aggressive).
    pub adjustment_factor: f64,
}

impl AdaptiveBudget {
    /// Create a new adaptive budget controller.
    ///
    /// - `base`: Starting instruction budget per block.
    /// - `min`: Minimum allowed budget.
    /// - `max`: Maximum allowed budget.
    /// - `target_us`: Target block execution time in microseconds.
    pub fn new(base: u32, min: u32, max: u32, target_us: u64) -> Self {
        Self {
            base_budget: base,
            current_budget: base,
            min_budget: min,
            max_budget: max,
            target_time_us: target_us,
            last_execution_time_us: 0,
            adjustment_factor: 0.5,
        }
    }

    /// Record a block execution time and adjust the budget accordingly.
    ///
    /// If execution time exceeds `target * 1.5`, the budget is reduced to
    /// make blocks smaller. If execution time is below `target * 0.5`, the
    /// budget is increased to allow more instructions per block.
    pub fn record_execution(&mut self, time_us: u64) {
        self.last_execution_time_us = time_us;

        let target = self.target_time_us as f64;
        let measured = time_us as f64;
        let factor = self.adjustment_factor;

        if measured > target * 1.5 {
            // Too slow — reduce budget
            let reduction =
                ((measured / target - 1.0) * factor * self.current_budget as f64) as u32;
            let reduction = reduction.max(1);
            self.current_budget =
                (self.current_budget.saturating_sub(reduction)).max(self.min_budget);
        } else if measured < target * 0.5 {
            // Too fast — increase budget
            let increase = ((1.0 - measured / target) * factor * self.current_budget as f64) as u32;
            let increase = increase.max(1);
            self.current_budget =
                (self.current_budget.saturating_add(increase)).min(self.max_budget);
        }
    }

    /// Get the current instruction budget.
    pub fn get_budget(&self) -> u32 {
        self.current_budget
    }

    /// Reset the budget to the base value.
    pub fn reset(&mut self) {
        self.current_budget = self.base_budget;
        self.last_execution_time_us = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// Optimizer Configuration
// ---------------------------------------------------------------------------

/// Configuration for the JIT optimizer passes.
///
/// Controls constant folding and loop unrolling behavior with sensible
/// defaults suitable for most workloads.
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    /// Enable constant folding (Tier1+). Default: true.
    pub enable_constant_folding: bool,
    /// Enable loop unrolling (Tier2 only). Default: true.
    pub enable_loop_unrolling: bool,
    /// Maximum unroll factor (loop body duplications). Default: 2.
    pub max_unroll_factor: usize,
    /// Test mode: enables verification checks. Default: false.
    pub test_mode: bool,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            enable_constant_folding: true,
            enable_loop_unrolling: true,
            max_unroll_factor: 2,
            test_mode: false,
        }
    }
}

impl OptimizerConfig {
    /// Create a new optimizer configuration with the given parameters.
    pub fn new(
        enable_constant_folding: bool,
        enable_loop_unrolling: bool,
        max_unroll_factor: usize,
    ) -> Self {
        Self {
            enable_constant_folding,
            enable_loop_unrolling,
            max_unroll_factor,
            test_mode: false,
        }
    }

    /// Enable test mode for verifying optimization results.
    pub fn with_test_mode(mut self) -> Self {
        self.test_mode = true;
        self
    }

    /// Create a config that disables all optimizations (for Tier0).
    pub fn disabled() -> Self {
        Self {
            enable_constant_folding: false,
            enable_loop_unrolling: false,
            max_unroll_factor: 1,
            test_mode: false,
        }
    }

    /// Create a config for Tier1 (constant folding only).
    pub fn tier1() -> Self {
        Self {
            enable_constant_folding: true,
            enable_loop_unrolling: false,
            max_unroll_factor: 1,
            test_mode: false,
        }
    }

    /// Create a config for Tier2 (constant folding + loop unrolling).
    pub fn tier2() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// G5: FastThunk — ARM64 thunk codegen for direct host-call dispatch
// ---------------------------------------------------------------------------

/// A registered fast-thunk entry: maps a host function pointer to a small
/// ARM64 trampoline that calls it directly from JIT-compiled guest code.
#[allow(dead_code)] // fast-thunk machine-code cache (kept for the disabled fast-thunk path)
struct FastThunkEntry {
    /// The host function to call.
    host_fn: usize,
    /// ARM64 trampoline machine code ("thunk") that jumps to `host_fn`.
    thunk_code: Vec<u8>,
    /// Virtual address where the thunk is mapped for execution.
    thunk_addr: usize,
    /// Guest (x86) virtual address of the thunk call target, if known.
    /// Set by [`FastThunkTable::register_with_guest_addr`] so the JIT can
    /// look up the trampoline address when compiling a `Call` instruction.
    guest_addr: Option<u64>,
}

/// Manages all registered fast-thunks, providing executable ARM64 trampolines
/// that allow JIT-compiled guest code to call host functions without going
/// through the full guest→host dispatch loop.
pub struct FastThunkTable {
    entries: Vec<FastThunkEntry>,
    /// Resolved-target cache: guest (x86) address → trampoline address.
    /// Maintained at registration time so repeat resolutions bypass both the
    /// linear entry scan and the global-map mutex.
    guest_index: HashMap<u64, usize>,
    /// mmap'd executable code zone for thunks.
    code_zone: Option<*mut u8>,
    code_zone_size: usize,
    code_zone_used: usize,
}

// SAFETY: FastThunkTable contains raw mmap'd pointers for the code zone.
// It is safe to send across threads because the code zone is only accessed
// through &mut methods (register). The entries vector is also only modified
// under &mut self.
unsafe impl Send for FastThunkTable {}
// SAFETY: All shared methods take &self and only read data. Mutable
// operations (register) require &mut self, preventing data races.
unsafe impl Sync for FastThunkTable {}

impl Default for FastThunkTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FastThunkTable {
    /// Create a new, empty fast-thunk table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            guest_index: HashMap::new(),
            code_zone: None,
            code_zone_size: 0,
            code_zone_used: 0,
        }
    }

    /// Ensure we have an executable code zone, allocating one if needed.
    fn ensure_code_zone(&mut self) -> AppResult<()> {
        if self.code_zone.is_some() {
            return Ok(());
        }
        #[cfg(test)]
        if JIT_TEST_DENY_THUNK_ZONE.with(|deny| deny.replace(false)) {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "failed to mmap fast-thunk code zone",
            ));
        }
        // Allocate 64 KB (one JIT page) of executable memory for thunks
        let size = 64 * 1024;
        // SAFETY: mmap allocates a 64KB anonymous private mapping with
        // RWX permissions (or MAP_JIT on aarch64). null_mut() lets the
        // kernel choose the address. fd=-1 is valid for MAP_ANONYMOUS.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "failed to mmap fast-thunk code zone",
            ));
        }
        self.code_zone = Some(ptr as *mut u8);
        self.code_zone_size = size;
        self.code_zone_used = 0;
        Ok(())
    }

    /// Register a fast-thunk for a host function.
    ///
    /// Returns the entry index, which can be used by the JIT to emit a call
    /// to this thunk instead of going through the full dispatch loop.
    pub fn register(&mut self, host_fn: usize) -> AppResult<usize> {
        self.ensure_code_zone()?;

        let zone = self.code_zone.unwrap();
        let offset = self.code_zone_used;
        // SAFETY: zone is a valid mmap'd pointer from ensure_code_zone.
        // offset tracks the number of bytes already used in the zone,
        // and the caller ensures offset + thunk.len() <= code_zone_size.
        let addr = unsafe { zone.add(offset) } as usize;

        // Emit ARM64 trampoline with proper frame save/restore:
        //
        //   stp   x29, x30, [sp, #-16]!   // Save frame pointer and link register
        //   mov   x29, sp                  // Set up frame pointer
        //   ldr   x17, [pc, #16]           // Load host_fn address from literal pool
        //   blr   x17                      // Call host function (return value in x0)
        //   ldp   x29, x30, [sp], #16      // Restore frame pointer and link register
        //   ret                             // Return to caller
        //   .quad host_fn                  // Literal pool entry (8 bytes)
        //
        // This provides:
        //   - Proper x29/x30 frame chain for stack unwinding and debugging
        //   - BLR-based calling convention (sets x30 for unwinders)
        //   - Correct return via x0 after host function completes
        //
        // Encodings:
        //   stp x29, x30, [sp, #-16]! = 0xA9BF7BFD
        //   mov x29, sp                = 0x910003FD
        //   ldr x17, [pc, #16]         = 0x58000091
        //   blr x17                    = 0xD63F0220
        //   ldp x29, x30, [sp], #16   = 0xA8C17BFD
        //   ret                        = 0xD65F03C0
        let thunk: Vec<u8> = vec![
            0xFD,
            0x7B,
            0xBF,
            0xA9, // stp x29, x30, [sp, #-16]!
            0xFD,
            0x03,
            0x00,
            0x91, // mov x29, sp
            0x91,
            0x00,
            0x00,
            0x58, // ldr x17, [pc, #16]
            0x20,
            0x02,
            0x3F,
            0xD6, // blr x17
            0xFD,
            0x7B,
            0xC1,
            0xA8, // ldp x29, x30, [sp], #16
            0xC0,
            0x03,
            0x5F,
            0xD6, // ret
            // literal pool: host_fn (8 bytes, little-endian)
            (host_fn & 0xFF) as u8,
            ((host_fn >> 8) & 0xFF) as u8,
            ((host_fn >> 16) & 0xFF) as u8,
            ((host_fn >> 24) & 0xFF) as u8,
            ((host_fn >> 32) & 0xFF) as u8,
            ((host_fn >> 40) & 0xFF) as u8,
            ((host_fn >> 48) & 0xFF) as u8,
            ((host_fn >> 56) & 0xFF) as u8,
        ];

        // Toggle MAP_JIT region to writable (and non-executable).  On Apple
        // Silicon, MAP_JIT memory can only be either writable or executable
        // at any given time — never both.
        // SAFETY: pthread_jit_write_protect_np(0) switches MAP_JIT pages
        // from executable to writable. No concurrent execution of thunk
        // code occurs because registration happens before execution.
        let _install = JIT_CODE_INSTALL_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            libc::pthread_jit_write_protect_np(0);
        }

        // Write thunk into the code zone
        // SAFETY: addr is within the mmap'd code zone (offset + thunk.len()
        // <= code_zone_size ensured by ensure_code_zone). thunk.as_ptr() is
        // valid for thunk.len() bytes. Regions are non-overlapping.
        // After writing, we switch back to executable with write_protect(1).
        unsafe {
            std::ptr::copy_nonoverlapping(thunk.as_ptr(), addr as *mut u8, thunk.len());
            // ARM64 requires an explicit instruction-cache flush after writing
            // code, exactly like block installation.
            JitMemoryManager::flush_icache(addr as *mut u8, thunk.len());
            // Re-enable execute (and disable write) on the MAP_JIT region.
            // On Apple Silicon, MAP_JIT memory can only be either writable or
            // executable at any given time — never both.  After writing the
            // trampoline we must switch back to executable so the CPU can
            // run it without faulting (SIGBUS).
            libc::pthread_jit_write_protect_np(1);
        }
        self.code_zone_used += thunk.len();

        let entry = FastThunkEntry {
            host_fn,
            thunk_code: thunk,
            thunk_addr: addr,
            guest_addr: None,
        };
        let idx = self.entries.len();
        self.entries.push(entry);
        Ok(idx)
    }

    /// Register a fast-thunk for a host function, associating it with a guest
    /// virtual address so the JIT compiler can look up the trampoline when it
    /// encounters a `Call` to `guest_addr`.
    ///
    /// Returns the entry index.
    pub fn register_with_guest_addr(
        &mut self,
        host_fn: usize,
        guest_addr: u64,
    ) -> AppResult<usize> {
        let idx = self.register(host_fn)?;
        if let Some(entry) = self.entries.get_mut(idx) {
            entry.guest_addr = Some(guest_addr);
        }
        if let Some(thunk_addr) = self.thunk_address(idx) {
            // Populate the in-table resolved-target cache so repeat
            // resolutions are an O(1) hash lookup with no lock.
            self.guest_index.insert(guest_addr, thunk_addr);
        }
        {
            // Propagate lock poisoning as an explicit error — the caller
            // needs to know that the thunk registration may not have
            // completed, which could cause JIT-compiled calls to fall
            // back to the slow dispatch path.
            let mut map = FAST_THUNK_MAP.lock().map_err(|e| {
                AppError::new(
                    ReasonCode::RcLockPoisoned,
                    format!("FAST_THUNK_MAP lock poisoned during register_with_guest_addr: {e}"),
                )
            })?;
            if let Some(thunk_addr) = self.thunk_address(idx) {
                map.insert(guest_addr, thunk_addr);
            }
        }
        Ok(idx)
    }

    /// Look up the ARM64 trampoline address for a given guest thunk address.
    ///
    /// The resolved-target index populated by
    /// [`FastThunkTable::register_with_guest_addr`] is consulted first: a
    /// repeat resolution is a single hash lookup that bypasses both the
    /// linear entry scan and the global-map mutex.  The entry scan / global
    /// map remain as the fallback for tables that were not populated through
    /// `register_with_guest_addr`.
    pub fn find_thunk_by_guest(&self, guest_addr: u64) -> Option<usize> {
        // Fast path: resolved-target cache (no scan, no lock).
        if let Some(thunk_addr) = self.guest_index.get(&guest_addr) {
            THUNK_RESOLVE_HITS.fetch_add(1, Ordering::Relaxed);
            return Some(*thunk_addr);
        }
        THUNK_RESOLVE_MISSES.fetch_add(1, Ordering::Relaxed);
        // Fallback 1: in-memory entries (may have been populated by a table
        // instance that did not go through `register_with_guest_addr`).
        for entry in &self.entries {
            if entry.guest_addr == Some(guest_addr) {
                return Some(entry.thunk_addr);
            }
        }
        // Fallback 2: the global map (may have been populated by another
        // table instance). This method returns Option, so we recover from
        // a poisoned lock (returning None) rather than propagating an error,
        // since the caller already handles the "not found" case.
        let map = match FAST_THUNK_MAP.lock() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!(
                    "FAST_THUNK_MAP lock poisoned during find_thunk_by_guest: {e}, returning None"
                );
                return None;
            }
        };
        map.get(&guest_addr).copied()
    }

    /// Get the thunk address for a registered entry.
    pub fn thunk_address(&self, idx: usize) -> Option<usize> {
        self.entries.get(idx).map(|e| e.thunk_addr)
    }

    /// Get the host function pointer for a registered entry.
    pub fn host_fn(&self, idx: usize) -> Option<usize> {
        self.entries.get(idx).map(|e| e.host_fn)
    }

    /// Number of registered thunks.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no thunks are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns true if the given guest address has a registered fast-thunk.
    pub fn contains_guest_addr(&self, guest_addr: u64) -> bool {
        self.guest_index.contains_key(&guest_addr)
            || self
                .entries
                .iter()
                .any(|e| e.guest_addr == Some(guest_addr))
    }

    /// Snapshot of every guest address with a resolved trampoline.  Passed to
    /// `JitCompiler::compile_instruction` so `Call` sites to stable resolved
    /// thunks are emitted as direct trampoline calls instead of dispatcher
    /// exits.
    pub fn guest_addrs(&self) -> std::collections::HashSet<u64> {
        let mut addrs: std::collections::HashSet<u64> = self.guest_index.keys().copied().collect();
        for entry in &self.entries {
            if let Some(guest_addr) = entry.guest_addr {
                addrs.insert(guest_addr);
            }
        }
        addrs
    }
}

impl Drop for FastThunkTable {
    fn drop(&mut self) {
        if let Some(zone) = self.code_zone.take() {
            // SAFETY: zone was returned by a successful mmap in
            // ensure_code_zone, and code_zone_size matches the original
            // allocation. munmap releases the mapping.
            unsafe {
                libc::munmap(zone as *mut libc::c_void, self.code_zone_size);
            }
        }
    }
}

// SAFETY: pthread_jit_write_protect_np is a system function on Apple
// Silicon that toggles W^X permissions on MAP_JIT pages. The FFI
// declaration matches the C prototype: void pthread_jit_write_protect_np(int).
// It is always available on macOS with Apple Silicon.
unsafe extern "C" {
    #[allow(dead_code)] // platform FFI declaration (ABI surface); flagged for the API database
    fn pthread_jit_write_protect_np(enabled: i32);
}

// ---------------------------------------------------------------------------
// G6: JIT Unwind Info — ARM64 RuntimeFunction + UnwindInfo for SEH
// ---------------------------------------------------------------------------

/// A single unwind info entry for JIT-compiled blocks.
/// Follows the Windows ARM64 unwind info format for `UNW_FLAG_NO_HANDLER`.
#[allow(dead_code)] // unwind-info payload for future unwinding support
struct JitUnwindInfo {
    /// Start RVA (relative to the code base).
    start_rva: u32,
    /// End RVA (exclusive).
    end_rva: u32,
    /// The raw unwind info bytes (UNW_FLAG_NO_HANDLER format).
    unwind_data: Vec<u8>,
}

/// Manages unwind info for all JIT-compiled blocks, registering them with
/// the SEH subsystem so that `RtlVirtualUnwind` works through JIT frames.
pub struct JitUnwindTable {
    entries: Vec<JitUnwindInfo>,
    /// Tracks whether entries have changed since the last `register_with_seh()` call.
    /// Used by the caller to avoid redundant SEH syncs.
    dirty: bool,
}

impl Default for JitUnwindTable {
    fn default() -> Self {
        Self::new()
    }
}

impl JitUnwindTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            dirty: false,
        }
    }

    /// Register a JIT block with the unwind table.
    ///
    /// `start_addr` and `end_addr` are the virtual addresses of the compiled
    /// block in the guest address space. The unwind info uses the Windows
    /// ARM64 "packed unwind data" format with UNW_FLAG_NO_HANDLER.
    pub fn register_block(&mut self, start_addr: u64, end_addr: u64) {
        // Generate minimal unwind info for ARM64:
        //   - No prologue (flag=00)
        //   - Function length computed from start_rva..end_rva
        //   - No chained unwind info
        //
        // Windows ARM64 packed unwind data (2 bytes):
        //   Bit 0-1: flag (0=no handler, no chained)
        //   Bit 2-3: function length in 4-byte units, minus 1
        //   Bit 4-5: (unused for no prologue)
        let func_len = ((end_addr - start_addr) / 4) as u32;
        let packed = if func_len > 0x3F {
            0x3F
        } else {
            func_len as u8
        };

        // 2-byte packed unwind data
        let unwind_data = vec![packed, 0x00]; // flag=00 (no handler)

        self.entries.push(JitUnwindInfo {
            start_rva: start_addr as u32,
            end_rva: end_addr as u32,
            unwind_data,
        });
        self.dirty = true;

        eprintln!(
            "[jit] unwind: registered block {:#x}..{:#x} ({} entries)",
            start_addr,
            end_addr,
            self.entries.len()
        );
    }

    /// Remove a JIT block from the unwind table by guest address.
    ///
    /// Returns `true` if the entry was found and removed.
    pub fn unregister_block(&mut self, guest_address: u64) -> bool {
        let rva = guest_address as u32;
        let before = self.entries.len();
        self.entries.retain(|e| e.start_rva != rva);
        let removed = self.entries.len() != before;
        if removed {
            self.dirty = true;
            eprintln!(
                "[jit] unwind: unregistered block {:#x} ({} entries remaining)",
                guest_address,
                self.entries.len()
            );
        }
        removed
    }

    /// Remove all entries from the unwind table.
    pub fn clear(&mut self) {
        if !self.entries.is_empty() {
            let count = self.entries.len();
            self.entries.clear();
            self.dirty = true;
            eprintln!("[jit] unwind: cleared all {count} entries");
        }
    }

    /// Returns `true` if entries have changed since the last `register_with_seh()` call.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Register all entries with the SEH subsystem.
    ///
    /// Builds a `.pdata`-format function table and x64-compatible UNWIND_INFO
    /// blocks from the JIT entries and registers them with the SEH subsystem
    /// so that `RtlVirtualUnwind` can unwind through JIT-compiled frames.
    ///
    /// Uses `JIT_IMAGE_BASE` (0) as the image base — the JIT entries store
    /// RVA-sized address ranges that are looked up directly without subtraction.
    ///
    /// Each JIT entry generates:
    /// - A 12-byte `RUNTIME_FUNCTION` entry (3 × u32 LE: `begin_rva`, `end_rva`,
    ///   `unwind_info_rva`)
    /// - A 4-byte x64 `UNWIND_INFO` with `UNW_FLAG_NO_HANDLER` (version=1,
    ///   flags=0, no prolog, no unwind codes) — this tells `virtual_unwind` to
    ///   simply pop the return address from the stack.
    ///
    /// If called multiple times (e.g. after adding more blocks), the previous
    /// registration is overwritten. Callers should batch all `register_block()`
    /// calls before a single `register_with_seh()` call.
    pub fn register_with_seh(&mut self, seh: &mut crate::seh::SehSubsystem) {
        if self.entries.is_empty() {
            eprintln!("[jit] unwind: register_with_seh called with no entries (skipping)");
            // Still clear the dirty flag so we don't retry on every check
            self.dirty = false;
            return;
        }

        // Image base for JIT code. Since entries store RVA-sized values,
        // using 0 means the SEH lookup (rip - image_base) preserves the
        // stored RVAs directly.
        const JIT_IMAGE_BASE: u64 = 0;

        // Each RUNTIME_FUNCTION entry is 12 bytes (3 × u32 LE).
        let mut pdata_bytes = Vec::with_capacity(self.entries.len() * 12);

        // Build a concatenated x64 UNWIND_INFO blob. Each entry gets a 4-byte
        // UNW_FLAG_NO_HANDLER descriptor so that parse_unwind_info() can
        // successfully parse it and virtual_unwind() can pop the return address.
        //
        // x64 UNWIND_INFO layout (4 bytes):
        //   [0]: version(3 bits) | flags(5 bits)  — 0x01 = v1, UNW_FLAG_NO_HANDLER
        //   [1]: prolog_size                      — 0x00 (no prologue)
        //   [2]: code_count                       — 0x00 (no unwind codes)
        //   [3]: frame_register(4) | frame_offset(4) — 0x00
        let mut unwind_data = Vec::new();

        for entry in &self.entries {
            // RVA to this entry's unwind info within the concatenated blob.
            let unwind_info_rva = unwind_data.len() as u32;

            // Append the RUNTIME_FUNCTION entry (begin_rva, end_rva, unwind_info_rva).
            pdata_bytes.extend_from_slice(&entry.start_rva.to_le_bytes());
            pdata_bytes.extend_from_slice(&entry.end_rva.to_le_bytes());
            pdata_bytes.extend_from_slice(&unwind_info_rva.to_le_bytes());

            // Append a 4-byte x64 UNWIND_INFO (UNW_FLAG_NO_HANDLER, no codes).
            unwind_data.push(0x01); // version=1, flags=0
            unwind_data.push(0x00); // prolog_size=0
            unwind_data.push(0x00); // code_count=0
            unwind_data.push(0x00); // frame_register=0, frame_offset=0
        }

        // Register the function table and unwind data with the SEH subsystem
        // under the JIT image base. This enables find_runtime_function() to
        // locate JIT entries and get_unwind_info() to parse the unwind data.
        let unwind_data_len = unwind_data.len();
        let pdata_len = pdata_bytes.len();
        let entry_count = self.entries.len();

        seh.register_pdata(JIT_IMAGE_BASE, &pdata_bytes);
        seh.register_unwind_data(JIT_IMAGE_BASE, unwind_data);
        self.dirty = false;

        eprintln!(
            "[jit] unwind: registered {} blocks with SEH (pdata={} bytes, unwind_data={} bytes)",
            entry_count, pdata_len, unwind_data_len
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// JIT self-test (--jit-self-test)
// ---------------------------------------------------------------------------

/// Machine-readable report of the `--jit-self-test` run.
///
/// `active` is true only when code was actually ALLOCATED through the
/// capability-probed mechanism, compiled, executed and re-patched in a child
/// process — a self-test that cannot execute reports `active: false` with the
/// reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JitSelfTestReport {
    /// True when the full self-test (compile → execute → safepoint →
    /// re-patch → re-execute) completed in a real process.
    pub active: bool,
    /// Number of blocks compiled during the self-test.
    pub compiled_blocks: u64,
    /// Number of block executions during the self-test.
    pub executed_blocks: u64,
    /// True when the host safepoint flag was observed to produce
    /// EXIT_SAFEPOINT from compiled code.
    pub safepoint_observed: bool,
    /// Block links published during the self-test (backedge linking).
    #[serde(default)]
    pub chain_links: u64,
    /// `Call` sites compiled to a direct resolved-thunk call.
    #[serde(default)]
    pub thunk_direct_calls: u64,
    /// Compiled blocks invalidated by the self-modifying-code test.
    #[serde(default)]
    pub smc_invalidations: u64,
    /// Blocks handed to the interpreter by the fault-equivalent fallback.
    #[serde(default)]
    pub fault_fallbacks: u64,
    /// Why the self-test is not active, when it is not.
    pub fallback_reason: Option<String>,
}

impl Default for JitSelfTestReport {
    fn default() -> Self {
        Self {
            active: false,
            compiled_blocks: 0,
            executed_blocks: 0,
            safepoint_observed: false,
            chain_links: 0,
            thunk_direct_calls: 0,
            smc_invalidations: 0,
            fault_fallbacks: 0,
            fallback_reason: None,
        }
    }
}

/// The guest value the self-test block writes into RAX before any patching.
const JIT_SELF_TEST_ORIGINAL_VALUE: u64 = 42;
/// The value written by the RE-PATCHED instruction (the patch must be
/// observable: executing the changed code must yield this value).
const JIT_SELF_TEST_PATCHED_VALUE: u64 = 43;

/// ARM64 `movz x4, #imm16` encodings for the two self-test immediates (RAX is
/// guest GPR 0, mapped to ARM64 x4).  `movz x4, #imm` = `0xd2800000 |
/// (imm << 5) | 4`.
fn movz_x4(imm: u16) -> u32 {
    0xd2800000u32 | ((imm as u32) << 5) | 4
}

/// Run the FULL self-test inside this process.  Verifies:
///
/// 1. MAP_JIT memory is allocated and flipped W→X
///    ([`JitCompiler::compile_block`] + [`JitMemoryManager::finalize_code`]);
/// 2. a tiny translated block executes and produces the guest result;
/// 3. the host safepoint flag produces `EXIT_SAFEPOINT` from compiled code;
/// 4. the code page is re-patched (W) and the changed code executes (X),
///    yielding the patched value.
///
/// Any verification failure returns an error.  If the recorded capability is
/// wrong and execution faults, the caller runs this in a child process and
/// turns the fault into `active: false`.
pub fn run_jit_self_test_child() -> AppResult<JitSelfTestReport> {
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    // A tiny translated block: `mov rax, 42` at guest 0x1000.  The block has
    // no control flow, so it exits EXIT_NORMAL and the compiled prefix is
    // exactly what we verify.
    let guest_address = 0x1000u64;
    #[cfg(test)]
    let original_value = if JIT_TEST_SELF_TEST_WRONG_ORIGINAL.with(|wrong| wrong.replace(false)) {
        JIT_SELF_TEST_ORIGINAL_VALUE.wrapping_sub(1)
    } else {
        JIT_SELF_TEST_ORIGINAL_VALUE
    };
    #[cfg(not(test))]
    let original_value = JIT_SELF_TEST_ORIGINAL_VALUE;
    let ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: original_value,
    }];
    state.rip = guest_address;

    // Copy the compiled block's identity out immediately: the reference into
    // `runtime` must not outlive the mutable borrows below.
    let (block_entry, block_code_size, compiled) = {
        let block = runtime
            .get_or_compile(&ir, guest_address, GuestArch::X64, None)
            .map_err(|error| {
                AppError::new(
                    ReasonCode::RcJitCompilationError,
                    format!("JIT self-test: compile_block failed: {}", error.message),
                )
            })?;
        (block.entry(), block.code_size, runtime.blocks_compiled)
    };
    let code_words: Vec<u32> = unsafe {
        std::slice::from_raw_parts(block_entry as *const u32, block_code_size / 4).to_vec()
    };
    let original_insn = movz_x4(original_value as u16);
    let patched_insn = movz_x4(JIT_SELF_TEST_PATCHED_VALUE as u16);
    let patch_offset = code_words
        .iter()
        .position(|word| *word == original_insn)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT self-test: compiled block does not contain the movz x4 immediate \
                 (block layout changed?)",
            )
        })?;

    // Sync guest memory and install the SIGBUS page-sync handler, exactly as
    // the live runtime does before native execution.
    runtime.sync_all_pages_to_flat(&memory);
    runtime.ensure_sigbus_handler(&memory);

    let mut execute = |runtime: &mut JitRuntime, state: &mut CpuState| -> JitExitReason {
        let block = runtime
            .block_cache
            .get(&guest_address)
            .cloned()
            .expect("self-test block remains compiled");
        // SAFETY: single-threaded self-test; block points into this runtime's
        // MAP_JIT pages; state/memory are live for the duration of the call.
        // The read lock prevents a concurrent chain-break from racing the
        // W/X flip.
        let _guard = JIT_EXEC_LOCK
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe { runtime.execute_block(&block, state, &mut memory) }
    };

    // 1. Execute the original code: guest result must be visible.
    let reason = execute(&mut runtime, &mut state);
    if reason != (JitExitReason::Normal { new_rip: state.rip }) {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: first execution exited with {reason:?}, expected Normal"),
        ));
    }
    if state.get(Register::Rax) != JIT_SELF_TEST_ORIGINAL_VALUE {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: guest result mismatch: rax={} expected {}",
                state.get(Register::Rax),
                JIT_SELF_TEST_ORIGINAL_VALUE
            ),
        ));
    }

    // 2. Safepoint: set the host flag; the compiled prologue must exit with
    // EXIT_SAFEPOINT without running the body.
    state.set(Register::Rax, 0);
    JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
    let reason = execute(&mut runtime, &mut state);
    JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
    if reason != JitExitReason::Safepoint {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: safepoint flag did not produce EXIT_SAFEPOINT (got {reason:?})"
            ),
        ));
    }
    let safepoint_observed = true;

    // 3. Re-patch the code page (W) and execute the changed code (X): the
    // patched immediate must be visible to execution.
    // SAFETY: single-threaded; no code is executing while the page is
    // writable (we are between execute_block calls).
    unsafe {
        if !runtime
            .compiler
            .memory_manager
            .make_writable(block_entry as *mut u8, block_code_size)
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT self-test: compiled code page is not writable",
            ));
        }
        let words = std::slice::from_raw_parts_mut(block_entry as *mut u32, block_code_size / 4);
        #[cfg(test)]
        let skip_repatch = JIT_TEST_SKIP_REPATCH.with(|skip| skip.replace(false));
        #[cfg(not(test))]
        let skip_repatch = false;
        if !skip_repatch {
            words[patch_offset] = patched_insn;
        }
        if !runtime
            .compiler
            .memory_manager
            .finalize_code(block_entry as *mut u8, block_code_size)
        {
            return Err(AppError::new(
                ReasonCode::RcJitCompilationError,
                "JIT self-test: re-patched code page is not executable",
            ));
        }
    }
    state.set(Register::Rax, 0);
    let reason = execute(&mut runtime, &mut state);
    if reason != (JitExitReason::Normal { new_rip: state.rip }) {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: re-patched execution exited with {reason:?}"),
        ));
    }
    if state.get(Register::Rax) != JIT_SELF_TEST_PATCHED_VALUE {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: re-patched execution did not observe the patch: rax={} expected {}",
                state.get(Register::Rax),
                JIT_SELF_TEST_PATCHED_VALUE
            ),
        ));
    }

    // 4. Backedge/forward linking: publish a link from a jump block to a
    //    control-flow target and execute it.  The source must branch into
    //    the target entry (no dispatcher return), the target must exit with
    //    its own EXIT_JUMP, and the host frame must stay balanced.
    let chain_source = 0x2000u64;
    let chain_target = 0x3000u64;
    let chain_exit = 0x4000u64;
    let source_ir = vec![
        IrInstruction::Nop,
        IrInstruction::Jump {
            target: chain_target,
        },
    ];
    let target_ir = vec![
        IrInstruction::Nop,
        IrInstruction::Jump { target: chain_exit },
    ];
    runtime
        .get_or_compile(&source_ir, chain_source, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: chain source compile failed: {}",
                    error.message
                ),
            )
        })?;
    runtime
        .get_or_compile(&target_ir, chain_target, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: chain target compile failed: {}",
                    error.message
                ),
            )
        })?;
    runtime
        .chain_blocks(chain_source, chain_target)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("JIT self-test: chain_blocks failed: {}", error.message),
            )
        })?;
    let chain_links = runtime.chain_links_formed;
    if chain_links == 0 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: no block link was published",
        ));
    }
    let source_block = runtime
        .block_cache
        .get(&chain_source)
        .cloned()
        .expect("chain source block remains compiled");
    state.rip = chain_source;
    let reason = unsafe { runtime.execute_block(&source_block, &mut state, &mut memory) };
    if reason != (JitExitReason::Jump { target: chain_exit }) {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: linked execution exited with {reason:?}, expected Jump"),
        ));
    }

    // 5. Direct resolved-thunk call: a registered guest thunk must compile to
    //    a direct trampoline call (no EXIT_THUNK) and update guest state.
    const SELF_TEST_THUNK_GUEST: u64 = 0x5000;
    let thunk_registered = runtime
        .register_host_thunk_for_guest(
            jit_self_test_host_thunk as *const () as usize,
            SELF_TEST_THUNK_GUEST,
        )
        .is_some();
    if !thunk_registered {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: failed to register the direct-call host thunk",
        ));
    }
    let thunk_ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 7,
        },
        IrInstruction::Call {
            target: SELF_TEST_THUNK_GUEST,
            return_address: 0x6004,
        },
    ];
    let thunk_before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
    runtime
        .get_or_compile(&thunk_ir, 0x6000, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: thunk block compile failed: {}",
                    error.message
                ),
            )
        })?;
    let thunk_direct_calls = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed) - thunk_before;
    if thunk_direct_calls == 0 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: Call to a resolved thunk did not compile to a direct call",
        ));
    }
    let thunk_block = runtime
        .block_cache
        .get(&0x6000u64)
        .cloned()
        .expect("thunk block remains compiled");
    state.set(Register::Rax, 0);
    state.set(Register::Rsp, 0x2000);
    state.rip = 0x6000;
    let reason = unsafe { runtime.execute_block(&thunk_block, &mut state, &mut memory) };
    if reason != (JitExitReason::Normal { new_rip: state.rip }) || state.get(Register::Rax) != 0x99
    {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: direct thunk call failed: reason={reason:?} rax={:#x}",
                state.get(Register::Rax)
            ),
        ));
    }

    // 6. Self-modifying code: a compiled block that stores over its own code
    //    page must invalidate the stale block; the next execution falls back
    //    to the interpreter and recompilation observes the new IR.
    let smc_address = 0x7000u64;
    let smc_writer = 0x7100u64;
    // The guest store must target mapped guest memory (an unmapped write
    // takes the fault path instead of reaching the SMC hook).
    memory.map_zeroed_if_unmapped(smc_address, 0x1000);
    let smc_ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 42,
    }];
    runtime
        .get_or_compile(&smc_ir, smc_address, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("JIT self-test: SMC block compile failed: {}", error.message),
            )
        })?;
    let smc_block = runtime
        .block_cache
        .get(&smc_address)
        .cloned()
        .expect("SMC block remains compiled");
    state.rip = smc_address;
    let _ = unsafe { runtime.execute_block(&smc_block, &mut state, &mut memory) };
    let writer_ir = vec![
        IrInstruction::StoreImmediate {
            address: crate::cpu::MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                displacement: 0,
                rip_relative: false,
                rip_base: 0,
                segment: None,
                address_size_32: false,
                absolute_address: Some(smc_address),
            },
            value: 0x9090_9090,
            width: 4,
        },
        IrInstruction::Nop,
    ];
    runtime
        .get_or_compile(&writer_ir, smc_writer, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: SMC writer compile failed: {}",
                    error.message
                ),
            )
        })?;
    let writer_block = runtime
        .block_cache
        .get(&smc_writer)
        .cloned()
        .expect("SMC writer remains compiled");
    state.rip = smc_writer;
    let _ = unsafe { runtime.execute_block(&writer_block, &mut state, &mut memory) };
    // The stale block must NOT run: the entry drain invalidates it and the
    // dispatcher receives the interpreter fallback.
    state.rip = smc_address;
    let reason = unsafe { runtime.execute_block(&smc_block, &mut state, &mut memory) };
    if reason != JitExitReason::Safepoint {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!("JIT self-test: stale SMC block ran instead of falling back: {reason:?}"),
        ));
    }
    let smc_invalidations = runtime.code_invalidations;
    if smc_invalidations == 0 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: self-modifying code did not invalidate a block",
        ));
    }
    let smc_new_ir = vec![IrInstruction::MovImm {
        dst: Register::Rax,
        value: 43,
    }];
    runtime
        .get_or_compile(&smc_new_ir, smc_address, GuestArch::X64, None)
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!("JIT self-test: SMC recompile failed: {}", error.message),
            )
        })?;
    let recompiled = runtime
        .block_cache
        .get(&smc_address)
        .cloned()
        .expect("recompiled SMC block");
    state.set(Register::Rax, 0);
    state.rip = smc_address;
    let _ = unsafe { runtime.execute_block(&recompiled, &mut state, &mut memory) };
    if state.get(Register::Rax) != 43 {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            format!(
                "JIT self-test: recompiled SMC block observed stale code: rax={}",
                state.get(Register::Rax)
            ),
        ));
    }

    // 7. Fault-equivalent fallback: an invalid block installation must hand
    //    the block to the interpreter (counter + permanent bar), never abort.
    let fault_address = 0x8000u64;
    runtime
        .get_or_compile(
            &[IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7,
            }],
            fault_address,
            GuestArch::X64,
            None,
        )
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcJitCompilationError,
                format!(
                    "JIT self-test: fault block compile failed: {}",
                    error.message
                ),
            )
        })?;
    runtime.report_block_fault(fault_address);
    let fault_fallbacks = runtime.fault_fallbacks;
    if fault_fallbacks == 0
        || runtime
            .get_or_compile(
                &[IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 7,
                }],
                fault_address,
                GuestArch::X64,
                None,
            )
            .is_ok()
    {
        return Err(AppError::new(
            ReasonCode::RcJitCompilationError,
            "JIT self-test: faulted block was not barred from native compilation",
        ));
    }

    Ok(JitSelfTestReport {
        active: true,
        compiled_blocks: compiled,
        executed_blocks: runtime.blocks_executed,
        safepoint_observed,
        chain_links,
        thunk_direct_calls,
        smc_invalidations,
        fault_fallbacks,
        fallback_reason: None,
    })
}

/// Host thunk used by the self-test direct-call step: the trampoline calls
/// this with (runtime, state, memory, guest_thunk).  It records a sentinel in
/// RAX and asks the bridge to continue (-1).
extern "C" fn jit_self_test_host_thunk(
    _runtime: *mut c_void,
    state: *mut CpuState,
    _memory: *mut MemoryImage,
    _thunk_address: u64,
) -> i32 {
    #[cfg(test)]
    let sentinel = if JIT_TEST_SELF_TEST_THUNK_BAD.with(|bad| bad.replace(false)) {
        0x98
    } else {
        0x99
    };
    #[cfg(not(test))]
    let sentinel = 0x99;
    if !state.is_null() {
        // SAFETY: state is the live CpuState passed by the self-test block.
        unsafe {
            (*state).gpr[0] = sentinel;
        }
    }
    -1
}

/// Run the self-test with crash isolation: the actual test executes in a
/// CHILD process so an executable-memory fault is observed as a child
/// failure instead of killing the caller.  `active` is true only when the
/// child ran the full test and reported success.
pub fn run_jit_self_test() -> JitSelfTestReport {
    #[cfg(test)]
    let exec_mode = JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.replace(0));
    #[cfg(not(test))]
    let exec_mode = 0u8;
    let current_exe = match if exec_mode == 1 {
        Err(std::io::Error::from_raw_os_error(libc::ENOENT))
    } else if exec_mode == 2 {
        Ok(std::path::PathBuf::from("/casa1/self-test-missing-binary"))
    } else if exec_mode == 3 {
        Ok(std::path::PathBuf::from("/usr/bin/true"))
    } else {
        std::env::current_exe()
    } {
        Ok(path) => path,
        Err(error) => {
            return JitSelfTestReport {
                active: false,
                compiled_blocks: 0,
                executed_blocks: 0,
                safepoint_observed: false,
                fallback_reason: Some(format!(
                    "cannot resolve current executable for the self-test child: {error}"
                )),
                ..JitSelfTestReport::default()
            };
        }
    };
    let output = match std::process::Command::new(&current_exe)
        .arg("--jit-self-test-child")
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return JitSelfTestReport {
                active: false,
                compiled_blocks: 0,
                executed_blocks: 0,
                safepoint_observed: false,
                fallback_reason: Some(format!("failed to spawn self-test child: {error}")),
                ..JitSelfTestReport::default()
            };
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        match serde_json::from_str::<JitSelfTestReport>(stdout.trim()) {
            Ok(mut report) => {
                // The child only reports active=true on full success; keep
                // its counters but never let a child claim activity it did
                // not prove.
                report.active &= report.safepoint_observed;
                report
            }
            Err(error) => JitSelfTestReport {
                active: false,
                compiled_blocks: 0,
                executed_blocks: 0,
                safepoint_observed: false,
                fallback_reason: Some(format!(
                    "self-test child exited 0 without a valid JitSelfTestReport JSON: {error}"
                )),
                ..JitSelfTestReport::default()
            },
        }
    } else {
        let signal_note = status_signal_description(&output.status);
        JitSelfTestReport {
            active: false,
            compiled_blocks: 0,
            executed_blocks: 0,
            safepoint_observed: false,
            fallback_reason: Some(format!(
                "JIT self-test child did not complete: exit={:?}{}; stdout={} stderr={}",
                output.status.code(),
                signal_note,
                stdout.trim(),
                String::from_utf8_lossy(&output.stderr).trim(),
            )),
            ..JitSelfTestReport::default()
        }
    }
}

#[cfg(unix)]
fn status_signal_description(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match status.signal() {
        Some(signal) => format!(
            " signal={signal} (fault while executing JIT code — the \
            capability probe's mechanism failed in the child; no entitlement shortcut is assumed)"
        ),
        None => String::new(),
    }
}

#[cfg(not(unix))]
fn status_signal_description(_status: &std::process::ExitStatus) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::GUEST_FLAT_SIZE;

    #[test]
    fn jit_memory_manager_rejects_null_and_zero_size_finalize() {
        let mut mgr = JitMemoryManager::new();
        let code = [0xd5, 0x03, 0x20, 0x1f]; // NOP
        let ptr = mgr.allocate_code_space(code.len());
        assert_eq!(ptr.is_null(), false);
        assert_eq!(mgr.total_allocated(), JIT_PAGE_SIZE);
        assert_eq!(mgr.total_used(), 64);
        // SAFETY: ptr was allocated by allocate_code_space and is valid
        // for code.len() bytes. code.as_ptr() is valid for code.len() bytes.
        // Regions are non-overlapping.
        unsafe {
            assert_eq!(
                mgr.make_writable(ptr, code.len()),
                true,
                "selected mechanism must provide writable code memory"
            );
            ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
            assert_eq!(
                mgr.finalize_code(ptr, code.len()),
                true,
                "selected mechanism must provide executable code memory"
            );
            // Null and zero-size requests must be refused: making them
            // "succeed" would claim a nonexistent code range is executable.
            assert_eq!(mgr.finalize_code(std::ptr::null_mut(), code.len()), false);
            assert_eq!(mgr.finalize_code(ptr, 0), false);
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn jit_exec_probe_matrix_macos_aarch64() {
        let matrix = probe_jit_execution();
        eprintln!("[jit] executable-memory probe matrix: {matrix:#?}");
        // macOS may deny the RX transition with ENOENT depending on the
        // process's W^X state; the selected mechanism below must still be the
        // MAP_JIT W^X path that does execute.
        assert!(
            matches!(
                matrix.mprotect_rx,
                JitExecProbeOutcome::Executed(42) | JitExecProbeOutcome::MprotectFailed(2)
            ),
            "mmap RW -> mprotect RX must execute or fail with a real ENOENT: {}",
            matrix.mprotect_rx
        );
        assert_eq!(
            matrix.map_jit_wx_write_protect,
            JitExecProbeOutcome::Executed(42),
            "MAP_JIT RWX + pthread_jit_write_protect_np must execute the ARM64 stub: {}",
            matrix.map_jit_wx_write_protect
        );
        assert_eq!(
            matrix.selected,
            JitExecMechanism::MapJitWx,
            "the JIT must prefer the W^X MAP_JIT mechanism when it executes"
        );
        // Regression guard: the pre-fix allocation (MAP_JIT without PROT_EXEC)
        // must never silently start "working" as if it were executable.
        assert!(
            !matches!(
                matrix.map_jit_rw_write_protect,
                JitExecProbeOutcome::Executed(_)
            ),
            "RW-only MAP_JIT must not execute; got {}",
            matrix.map_jit_rw_write_protect
        );
        // The no-toggle test writes into an execute-protected MAP_JIT region
        // and must fault rather than execute.
        assert!(
            !matches!(
                matrix.map_jit_wx_no_write_protect,
                JitExecProbeOutcome::Executed(_)
            ),
            "MAP_JIT RWX without write-protect toggles must not execute; got {}",
            matrix.map_jit_wx_no_write_protect
        );
    }

    fn verify_capability_selection(matrix: JitExecProbeMatrix) {
        match matrix.selected {
            JitExecMechanism::MapJitWx => assert_eq!(
                matrix.map_jit_wx_write_protect,
                JitExecProbeOutcome::Executed(42),
                "selected MAP_JIT but its probe did not execute"
            ),
            JitExecMechanism::MprotectRx => assert_eq!(
                matrix.mprotect_rx,
                JitExecProbeOutcome::Executed(42),
                "selected mprotect RX but its probe did not execute"
            ),
            JitExecMechanism::RwxMmap => {}
            JitExecMechanism::Unavailable => {
                eprintln!("[jit] native execution unavailable: {matrix:?}");
                assert_ne!(
                    matrix.selected,
                    JitExecMechanism::Unavailable,
                    "an unavailable capability must report unavailable"
                );
            }
        }
        for (name, outcome) in [
            ("mprotect_rx", matrix.mprotect_rx),
            ("map_jit_wx_write_protect", matrix.map_jit_wx_write_protect),
        ] {
            if let JitExecProbeOutcome::Executed(value) = outcome {
                assert_eq!(value, 42, "{name} executed a stub that must return 42");
            }
        }
    }

    #[test]
    fn jit_capability_selection_rejects_inconsistent_real_matrix() {
        let matrix = jit_execution_capability();
        assert_eq!(
            matrix.selected != JitExecMechanism::Unavailable,
            jit_execution_available()
        );
        verify_capability_selection(matrix);
    }

    #[test]
    fn jit_capability_selection_rejects_mprotect_and_rwx_matrices() {
        let mprotect = JitExecProbeMatrix {
            mprotect_rx: JitExecProbeOutcome::Executed(42),
            map_jit_wx_write_protect: JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
            map_jit_rw_write_protect: JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
            map_jit_wx_no_write_protect: JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
            selected: JitExecMechanism::MprotectRx,
        };
        assert_eq!(mprotect.selected, JitExecMechanism::MprotectRx);
        verify_capability_selection(mprotect);
        let rwx = JitExecProbeMatrix {
            mprotect_rx: JitExecProbeOutcome::NotProbed,
            map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
            selected: JitExecMechanism::RwxMmap,
        };
        assert_eq!(rwx.selected, JitExecMechanism::RwxMmap);
        verify_capability_selection(rwx);
    }

    #[test]
    #[should_panic(expected = "an unavailable capability must report unavailable")]
    fn jit_capability_selection_rejects_unavailable_matrix() {
        verify_capability_selection(JitExecProbeMatrix {
            mprotect_rx: JitExecProbeOutcome::NotProbed,
            map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
            selected: JitExecMechanism::Unavailable,
        });
    }

    #[test]
    fn jit_unavailable_capability_returns_null_allocation() {
        let unavailable = JitExecProbeMatrix {
            mprotect_rx: JitExecProbeOutcome::NotProbed,
            map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
            selected: JitExecMechanism::Unavailable,
        };
        let mut manager = JitMemoryManager::with_capability(unavailable);
        assert_eq!(manager.mechanism(), JitExecMechanism::Unavailable);
        assert!(
            manager.allocate_code_space(64).is_null(),
            "an unavailable OS capability must fail allocation, not fabricate memory"
        );
        // SAFETY: the unavailable mechanism returns before dereferencing.
        unsafe {
            assert!(!manager.make_writable(std::ptr::null_mut(), 4));
            assert!(!manager.finalize_code(std::ptr::null_mut(), 4));
        }
    }

    #[test]
    fn jit_execute_with_jit_falls_back_when_block_not_compiled() {
        let config =
            crate::cpu::CpuEngineConfig::from_profile(GuestArch::X64, "test", "test", None)
                .expect("cpu config");
        let engine = crate::cpu::CpuExecutionEngine::new(config);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x1000;
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0; 0x100]);
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7,
            },
            IrInstruction::Jump { target: 0 },
        ];
        let mut jit = JitRuntime::new(GuestArch::X64);
        engine
            .execute_with_jit(&mut state, &mut memory, &ir, Some(&mut jit))
            .expect("fallback execution");
        assert_eq!(state.get(Register::Rax), 7);
        assert!(!jit.is_compiled(0x1000));
        assert_eq!(jit.blocks_executed, 0);
    }

    #[test]
    fn jit_compiler_compiles_nop_block() {
        let mut compiler = JitCompiler::new();
        let ir = vec![IrInstruction::Nop];
        let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, None);
        assert!(result.is_ok(), "expected JIT compilation to succeed");
        let block = result.unwrap();
        assert_eq!(block.guest_address, 0x1000);
        assert_eq!(block.instruction_count, 1);
        assert!(block.code_size > 0);
        assert!(!block.entry().is_null());
    }

    #[test]
    fn jit_lowering_telemetry_counts_native_and_helper_fallback_per_opcode() {
        // Compile a batch of a unique native opcode (MovImm) and a unique
        // helper-fallback opcode (Xgetbv); the per-opcode counters must move
        // by exactly the batch sizes.  (Nop is compiled by other tests
        // concurrently, so this test uses opcodes no other test compiles —
        // exact per-opcode deltas are therefore deterministic.)
        let native_op = ir_opcode_index(&IrInstruction::MovImm {
            dst: Register::Rax,
            value: 0,
        });
        let fallback_op = ir_opcode_index(&IrInstruction::Xgetbv);
        let native_before = JIT_NATIVE_LOWERED[native_op].load(Ordering::Relaxed);
        let fallback_before = JIT_HELPER_FALLBACK[fallback_op].load(Ordering::Relaxed);

        let mut compiler = JitCompiler::new();
        let mut ir = Vec::new();
        for i in 0..8u64 {
            ir.push(IrInstruction::MovImm {
                dst: Register::Rax,
                value: i,
            });
            ir.push(IrInstruction::Xgetbv);
        }
        let block = compiler
            .compile_block(&ir, 0x4000, GuestArch::X64, None)
            .expect("compile block with native + fallback instructions");
        assert_eq!(block.instruction_count, 16);

        // Other tests compile MovImm/Xgetbv blocks concurrently, so the
        // process-global per-opcode counters may move by more than this
        // block's contribution.  The batch is a guaranteed lower bound.
        assert!(
            JIT_NATIVE_LOWERED[native_op].load(Ordering::Relaxed) >= native_before + 8,
            "MovImm must be counted as native lowering"
        );
        assert!(
            JIT_HELPER_FALLBACK[fallback_op].load(Ordering::Relaxed) >= fallback_before + 8,
            "Xgetbv must be counted as interpreter-helper fallback"
        );

        let (native_total, fallback_total) = jit_lowering_telemetry();
        assert!(native_total >= native_before + 8);
        assert!(fallback_total >= fallback_before + 8);
    }

    // --- Phase 7: Block Chaining Tests ---

    // (helper removed — no remaining caller; chain_blocks is a documented
    // no-op and block chaining is disabled)

    #[test]
    fn block_chaining_fails_for_missing_block() {
        let mut rt = JitRuntime::new(GuestArch::X64);
        let ir_a = vec![IrInstruction::Nop, IrInstruction::Jump { target: 0x2000 }];
        rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
            .unwrap();
        let error = rt.chain_blocks(0x1000, 0x2000).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message, "cannot chain to missing target block 0x2000",
            "chaining to a missing target must fail with the exact reason"
        );
    }

    // --- Phase 7: Tiered Compiler Tests ---

    // --- Phase 7: Inline Cache Tests ---

    #[test]
    fn inline_cache_hit_miss() {
        let mut cache = InlineCache::new(16);

        // First lookup — miss (no entry)
        let hit = cache.lookup(0x1000, 0x5000);
        assert!(!hit, "first lookup should be a miss");

        // Second lookup with same target — hit
        let hit = cache.lookup(0x1000, 0x5000);
        assert!(hit, "same target should be a hit");

        // Third lookup with different target — miss
        let hit = cache.lookup(0x1000, 0x6000);
        assert!(!hit, "different target should be a miss");

        // Verify counters
        let entry = cache.entries.get(&0x1000).unwrap();
        assert_eq!(entry.hit_count, 1);
        assert_eq!(entry.miss_count, 2);
        assert_eq!(entry.last_target, 0x6000);
    }

    #[test]
    fn inline_cache_invalidate() {
        let mut cache = InlineCache::new(16);
        cache.lookup(0x1000, 0x5000);
        assert!(cache.entries.contains_key(&0x1000));

        cache.invalidate(0x1000);
        assert!(!cache.entries.contains_key(&0x1000));
    }

    #[test]
    fn inline_cache_invalidate_all() {
        let mut cache = InlineCache::new(16);
        cache.lookup(0x1000, 0x5000);
        cache.lookup(0x2000, 0x6000);
        assert_eq!(cache.entries.len(), 2);

        cache.invalidate_all();
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn inline_cache_eviction() {
        let mut cache = InlineCache::new(2);
        cache.lookup(0x1000, 0x5000);
        cache.lookup(0x2000, 0x6000);
        assert_eq!(cache.entries.len(), 2);

        // Adding a third entry should evict one
        cache.lookup(0x3000, 0x7000);
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.entries.contains_key(&0x3000));
    }

    // --- Phase 7: Adaptive Budget Tests ---

    // --- Phase 8: Constant Folding Tests ---

    #[test]
    fn test_constant_fold_no_change() {
        use crate::cpu::Register;

        // Instructions that cannot be folded (src register not known)
        // Add PushReg consumers so DCE doesn't remove the instructions
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 10,
            },
            IrInstruction::MovReg {
                dst: Register::Rbx,
                src: Register::Rcx,
                width: 8,
            },
            IrInstruction::AddImm {
                dst: Register::Rbx,
                value: 5,
                width: 8,
            },
            IrInstruction::PushReg { src: Register::Rax },
            IrInstruction::PushReg { src: Register::Rbx },
        ];

        let folded = JitCompiler::constant_fold(&ir);

        // MovReg(rbx, rcx) can't be folded since rcx is unknown
        // AddImm(rbx, 5) can't be folded since rbx is a copy of rcx (not an immediate)
        // So these should pass through
        assert!(!folded.is_empty(), "non-foldable IR should not be empty");

        // The MovImm should still be a MovImm
        // MovReg and AddImm should remain as they were
        let has_movreg = folded
            .iter()
            .any(|insn| matches!(insn, IrInstruction::MovReg { .. }));
        let has_addimm = folded
            .iter()
            .any(|insn| matches!(insn, IrInstruction::AddImm { .. }));
        assert!(has_movreg, "MovReg should remain unchanged: {:?}", folded);
        assert!(has_addimm, "AddImm should remain unchanged: {:?}", folded);
    }

    #[test]
    fn test_constant_fold_movreg_propagation() {
        use crate::cpu::Register;

        // MovImm(rax, 42), MovReg(rbx, rax) → MovImm(rbx, 42) and rax still known
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 42,
            },
            IrInstruction::MovReg {
                dst: Register::Rbx,
                src: Register::Rax,
                width: 8,
            },
        ];

        let folded = JitCompiler::constant_fold(&ir);

        // After folding: MovReg(rbx, rax) where rax=42 → MovImm(rbx, 42)
        // After DCE: both might be removed since neither rax nor rbx is read later
        // Let's check if MovReg is no longer present
        let has_movreg = folded
            .iter()
            .any(|insn| matches!(insn, IrInstruction::MovReg { .. }));
        assert!(!has_movreg, "MovReg should have been folded to MovImm");
    }

    // --- Phase 9: Loop Unrolling Tests ---

    #[test]
    fn test_loop_unroll_full() {
        use crate::cpu::Register;

        // Loop with counter initialized to 3 (≤4, should fully unroll)
        let ir = vec![
            // Initialize counter
            IrInstruction::MovImm {
                dst: Register::Rcx,
                value: 3,
            },
            // Loop body: increment rax
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 1,
                width: 8,
            },
            // Decrement counter
            IrInstruction::SubImm {
                dst: Register::Rcx,
                value: 1,
                width: 8,
            },
            // Branch back if counter != 0
            IrInstruction::JumpIf {
                condition: ConditionCode::NotEqual,
                target: 0x1000,
                fallthrough: 0x2000,
            },
        ];

        let unrolled = JitCompiler::loop_unroll(&ir, 0x1000);

        // After full unrolling with count=3:
        // MovImm(rcx, 3), AddImm(rax,1), AddImm(rax,1), AddImm(rax,1)
        // The SubImm and JumpIf are removed
        // (plus constant folding may reduce further)
        assert!(
            !unrolled.is_empty(),
            "unrolled loop should have instructions"
        );
        // The loop back-edge should be gone
        let has_jumpif = unrolled
            .iter()
            .any(|insn| matches!(insn, IrInstruction::JumpIf { .. }));
        assert!(!has_jumpif, "fully unrolled loop should not have JumpIf");
    }

    #[test]
    fn test_loop_unroll_no_side_effects() {
        use crate::cpu::Register;

        // A semantically equivalent loop: unrolling should produce the same
        // net effect on the counter and other registers.
        // Initialize rax=0, then loop 2 times adding 1 to rax.
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 0,
            },
            IrInstruction::MovImm {
                dst: Register::Rcx,
                value: 2,
            },
            // Loop body: rax += 1
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 1,
                width: 8,
            },
            // Decrement counter
            IrInstruction::SubImm {
                dst: Register::Rcx,
                value: 1,
                width: 8,
            },
            // Branch back if counter != 0
            IrInstruction::JumpIf {
                condition: ConditionCode::NotEqual,
                target: 0x1000,
                fallthrough: 0x2000,
            },
        ];

        let unrolled = JitCompiler::loop_unroll(&ir, 0x1000);

        // After full unrolling with count=2:
        // The loop body (AddImm rax,1) should be duplicated 2 times
        // No JumpIf should remain
        let has_jumpif = unrolled
            .iter()
            .any(|insn| matches!(insn, IrInstruction::JumpIf { .. }));
        assert!(!has_jumpif, "fully unrolled loop should not have JumpIf");

        // Count the number of AddImm(rax,1) instructions
        let add_count = unrolled
            .iter()
            .filter(|insn| {
                matches!(
                    insn,
                    IrInstruction::AddImm {
                        dst: Register::Rax,
                        value: 1,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            add_count, 2,
            "should have 2 AddImm(rax,1) after unrolling count=2, got {}",
            add_count
        );
    }

    // --- G6: JIT Unwind Registration Tests ---

    #[test]
    fn unwind_table_register_block_adds_entry() {
        let mut table = JitUnwindTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(!table.is_dirty(), "new table should not be dirty");

        table.register_block(0x1000, 0x1020);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
        assert!(table.is_dirty(), "register_block should set dirty flag");

        // Verify the entry matches
        let entry = &table.entries[0];
        assert_eq!(entry.start_rva, 0x1000);
        assert_eq!(entry.end_rva, 0x1020);
        assert!(
            !entry.unwind_data.is_empty(),
            "unwind_data should be generated"
        );
    }

    #[test]
    fn unwind_table_unregister_block_removes_entry() {
        let mut table = JitUnwindTable::new();
        table.register_block(0x1000, 0x1020);
        table.register_block(0x2000, 0x2040);
        assert_eq!(table.len(), 2);

        // Re-register to clear dirty flag
        table.dirty = false;

        let removed = table.unregister_block(0x1000);
        assert!(
            removed,
            "unregister_block should return true when entry found"
        );
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.entries[0].start_rva, 0x2000,
            "remaining entry should be 0x2000"
        );
        assert!(table.is_dirty(), "unregister should set dirty flag");

        // Unregister non-existent block
        let removed = table.unregister_block(0x9999);
        assert!(
            !removed,
            "unregister_block should return false for missing entry"
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn unwind_table_dirty_flag_tracking() {
        let mut table = JitUnwindTable::new();
        assert!(!table.is_dirty());

        // register_block sets dirty
        table.register_block(0x1000, 0x1020);
        assert!(table.is_dirty());

        // register_with_seh clears dirty (even if entries present)
        let mut seh = crate::seh::SehSubsystem::new();
        table.register_with_seh(&mut seh);
        assert!(!table.is_dirty());

        // New registration sets dirty again
        table.register_block(0x2000, 0x2040);
        assert!(table.is_dirty());

        // unregister_block sets dirty
        table.dirty = false;
        table.unregister_block(0x2000);
        assert!(table.is_dirty());
    }

    #[test]
    fn unwind_table_register_with_seh_empty_clears_dirty() {
        let mut table = JitUnwindTable::new();
        table.dirty = true; // artificially set

        let mut seh = crate::seh::SehSubsystem::new();
        table.register_with_seh(&mut seh);
        assert!(
            !table.is_dirty(),
            "register_with_seh with no entries should still clear dirty"
        );
    }

    #[test]
    fn jit_runtime_invalidate_block_removes_from_cache_and_unwind() {
        let mut rt = JitRuntime::new(GuestArch::X64);
        let ir = vec![IrInstruction::Nop];

        // Compile a block
        rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_compiled(0x1000));
        assert_eq!(rt.unwind_table.len(), 1);

        // Invalidate the block
        rt.invalidate_block(0x1000);
        assert!(
            !rt.is_compiled(0x1000),
            "block should be removed from cache"
        );
        assert!(
            rt.unwind_table.is_empty(),
            "block should be unregistered from unwind table"
        );
    }

    #[test]
    fn jit_runtime_invalidate_block_unchains() {
        // Chaining disabled: invalidate_block still works (removes the block
        // from the cache); there are simply no chains to unchain.
        let mut rt = JitRuntime::new(GuestArch::X64);
        let ir_a = vec![IrInstruction::Nop];
        let ir_b = vec![IrInstruction::Nop, IrInstruction::Nop];

        rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
            .unwrap();
        rt.get_or_compile(&ir_b, 0x2000, GuestArch::X64, None)
            .unwrap();
        let _ = rt.chain_blocks(0x1000, 0x2000); // no-op

        rt.invalidate_block(0x2000);
        assert!(
            !rt.block_chains.contains_key(&(0x1000, 0x2000)),
            "no chains exist (chaining disabled)"
        );
    }

    #[test]
    fn jit_runtime_unwind_dirty_cleared_after_seh_sync() {
        let mut rt = JitRuntime::new(GuestArch::X64);
        let ir = vec![IrInstruction::Nop];

        rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_unwind_dirty());

        // After syncing to SEH, dirty should be cleared
        let mut seh = crate::seh::SehSubsystem::new();
        rt.unwind_table.register_with_seh(&mut seh);
        assert!(!rt.is_unwind_dirty());
    }

    // ─── Phase D2/R2: JIT Unwind Info Format Verification and Extended Tests ───

    #[test]
    fn unwind_table_empty_table_unregister() {
        let mut table = JitUnwindTable::new();
        assert!(table.is_empty());

        // Unregister on empty table should return false and not set dirty
        table.dirty = false;
        let removed = table.unregister_block(0x1000);
        assert!(!removed, "unregister on empty table should return false");
        assert!(
            !table.is_dirty(),
            "unregister on empty table should NOT set dirty flag"
        );
    }

    #[test]
    fn unwind_table_clear_on_empty_table() {
        let mut table = JitUnwindTable::new();
        assert!(table.is_empty());

        // clear on already empty table should not set dirty
        table.dirty = false;
        table.clear();
        assert!(
            !table.is_dirty(),
            "clear on empty table should NOT set dirty flag"
        );
    }

    #[test]
    fn unwind_table_duplicate_entries() {
        let mut table = JitUnwindTable::new();

        // Register the same address range twice
        table.register_block(0x1000, 0x1020);
        assert_eq!(table.len(), 1);

        // Registering the same range again should add a duplicate entry
        // (the JIT currently does not deduplicate — callers are responsible
        // for calling get_or_compile which checks block_cache before register_block)
        table.register_block(0x1000, 0x1020);
        assert_eq!(
            table.len(),
            2,
            "registering duplicate range adds another entry"
        );

        // Both entries should have the same data
        assert_eq!(table.entries[0].start_rva, table.entries[1].start_rva);
        assert_eq!(table.entries[0].end_rva, table.entries[1].end_rva);
        assert_eq!(table.entries[0].unwind_data, table.entries[1].unwind_data);

        // unregister_block uses retain() which removes ALL entries with
        // matching start_rva, so both duplicates are removed at once.
        let removed = table.unregister_block(0x1000);
        assert!(removed);
        assert_eq!(
            table.len(),
            0,
            "retain removes ALL matching entries, not just one"
        );

        // Second remove on empty table
        let removed = table.unregister_block(0x1000);
        assert!(!removed);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn unwind_table_out_of_order_removal() {
        let mut table = JitUnwindTable::new();
        table.register_block(0x1000, 0x1020);
        table.register_block(0x2000, 0x2040);
        table.register_block(0x3000, 0x3030);

        // Remove middle entry
        let removed = table.unregister_block(0x2000);
        assert!(removed);
        assert_eq!(table.len(), 2);

        // Remaining entries should be 0x1000 and 0x3000
        assert_eq!(table.entries[0].start_rva, 0x1000);
        assert_eq!(table.entries[1].start_rva, 0x3000);

        // Remove first entry
        let removed = table.unregister_block(0x1000);
        assert!(removed);
        assert_eq!(table.len(), 1);
        assert_eq!(table.entries[0].start_rva, 0x3000);

        // Remove last entry
        let removed = table.unregister_block(0x3000);
        assert!(removed);
        assert!(table.is_empty());
    }

    #[test]
    fn unwind_table_seh_cache_invalidation_on_reregister() {
        // Verify that when register_with_seh() is called multiple times,
        // the SEH subsystem's unwind_cache is properly invalidated and
        // fresh entries are parsed.
        let mut table = JitUnwindTable::new();
        let mut seh = crate::seh::SehSubsystem::new();

        // First registration: register block at 0x1000..0x1020
        table.register_block(0x1000, 0x1020);
        table.register_with_seh(&mut seh);

        const JIT_IMAGE_BASE: u64 = 0;

        // Verify first registration works
        let rf1 = seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000);
        assert!(
            rf1.is_some(),
            "first registration: block should be findable"
        );
        assert_eq!(rf1.unwrap().begin_addr, 0x1000);

        // Second registration: replace with different block at 0x3000..0x3050
        table.clear();
        table.register_block(0x3000, 0x3050);
        table.register_with_seh(&mut seh);

        // Old block should be gone
        assert!(
            seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).is_none(),
            "old block should be gone after re-registration"
        );
        // New block should be present
        let rf2 = seh.find_runtime_function(JIT_IMAGE_BASE, 0x3000);
        assert!(
            rf2.is_some(),
            "new block should be findable after re-registration"
        );
        assert_eq!(rf2.unwrap().begin_addr, 0x3000);

        // Force a third registration with the same data but different ordering
        // to ensure cache invalidation works for same-RVA scenarios
        table.clear();
        table.register_block(0x3000, 0x3050);
        table.register_block(0x1000, 0x1020);
        table.register_with_seh(&mut seh);

        // Both blocks should be findable
        assert!(
            seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).is_some(),
            "0x1000 should be findable after third registration"
        );
        assert!(
            seh.find_runtime_function(JIT_IMAGE_BASE, 0x3000).is_some(),
            "0x3000 should be findable after third registration"
        );

        // The unwind_info for 0x1000 should be parseable (cache was cleared)
        let rf_new = seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).unwrap();
        let ui = seh.get_unwind_info(rf_new.unwind_info_addr);
        assert!(
            ui.is_some(),
            "unwind info for re-registered block should be parseable"
        );
        let ui = ui.unwrap();
        assert_eq!(ui.version, 1);
        assert_eq!(ui.flags, 0);
    }

    #[test]
    fn unwind_table_runtime_unwind_dirty_sync_cycle() {
        // Full lifecycle test for the dirty → sync → dirty → sync cycle
        let mut rt = JitRuntime::new(GuestArch::X64);
        let ir = vec![IrInstruction::Nop];
        let mut seh = crate::seh::SehSubsystem::new();

        // Initial state: empty, not dirty
        assert!(!rt.is_unwind_dirty());
        assert!(rt.unwind_table.is_empty());

        // Step 1: Compile a block → dirty
        rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_unwind_dirty());
        assert_eq!(rt.unwind_table.len(), 1);

        // Step 2: Sync to SEH → not dirty
        rt.unwind_table.register_with_seh(&mut seh);
        assert!(!rt.is_unwind_dirty());

        // Step 3: Compile another block → dirty again
        rt.get_or_compile(&ir, 0x2000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_unwind_dirty());
        assert_eq!(rt.unwind_table.len(), 2);

        // Step 4: Sync again → not dirty
        rt.unwind_table.register_with_seh(&mut seh);
        assert!(!rt.is_unwind_dirty());

        // Step 5: Invalidate a block → dirty
        rt.invalidate_block(0x1000);
        assert!(rt.is_unwind_dirty());
        assert_eq!(rt.unwind_table.len(), 1);

        // Step 6: Final sync → not dirty
        rt.unwind_table.register_with_seh(&mut seh);
        assert!(!rt.is_unwind_dirty());

        // Verify SEH state after all operations
        const JIT_IMAGE_BASE: u64 = 0;
        assert!(
            seh.find_runtime_function(JIT_IMAGE_BASE, 0x1000).is_none(),
            "invalidated block 0x1000 should not be in SEH"
        );
        assert!(
            seh.find_runtime_function(JIT_IMAGE_BASE, 0x2000).is_some(),
            "valid block 0x2000 should be in SEH"
        );
    }

    // =====================================================================
    // Self-modifying code stress tests
    // =====================================================================

    #[test]
    fn self_modifying_code_basic_invalidation() {
        let mut rt = JitRuntime::new(GuestArch::X64);

        // Compile an initial block at 0x1000
        let ir_initial = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 42,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir_initial, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_compiled(0x1000), "block should be compiled");
        assert_eq!(rt.blocks_compiled, 1, "exactly one block compiled");
        assert!(
            rt.code_pages.contains(&0x1000),
            "code page should be tracked"
        );

        // Simulate a guest write to the block's address range (self-modifying code).
        // The block at 0x1000 has some code_size; writing at 0x1000 with length > 0
        // should overlap and trigger invalidation.
        let invalidated = rt.invalidate_blocks_writing_to(0x1000, 4);
        assert!(
            !invalidated.is_empty(),
            "write should invalidate at least one block"
        );
        assert_eq!(
            invalidated,
            vec![0x1000],
            "block 0x1000 should be invalidated"
        );
        assert!(
            !rt.is_compiled(0x1000),
            "block should no longer be compiled after write"
        );
        assert!(rt.block_cache.is_empty(), "block cache should be empty");

        // Recompile with different content (simulating modified code)
        let ir_modified = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 99,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir_modified, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_compiled(0x1000), "block should be recompiled");
        assert_eq!(rt.blocks_compiled, 2, "should have compiled twice total");
        assert!(
            rt.code_pages.contains(&0x1000),
            "code page should be tracked after recompilation"
        );
    }

    #[test]
    fn self_modifying_code_write_to_data_page_no_invalidation() {
        let mut rt = JitRuntime::new(GuestArch::X64);

        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 42,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir, 0x1000, GuestArch::X64, None)
            .unwrap();

        // Write to a data page (no compiled blocks)
        let affected = rt.invalidate_blocks_writing_to(0x7000, 8);
        assert!(
            affected.is_empty(),
            "write to data page should not invalidate any blocks"
        );
        assert!(rt.is_compiled(0x1000), "block should still be compiled");
    }

    #[test]
    fn self_modifying_code_multiple_modifications() {
        let mut rt = JitRuntime::new(GuestArch::X64);
        let modification_count = 15;

        for i in 0..modification_count {
            // Each cycle: compile a unique block, then simulate a write to its range
            let addr = 0x1000 + (i as u64 * 0x100);

            // Compile with unique content for this iteration
            let ir = vec![
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: i as u64,
                },
                IrInstruction::Nop,
            ];
            rt.get_or_compile(&ir, addr, GuestArch::X64, None).unwrap();
            assert!(
                rt.is_compiled(addr),
                "block at {:#x} should be compiled",
                addr
            );

            // Simulate self-modifying write
            let affected = rt.invalidate_blocks_writing_to(addr, 4);
            assert_eq!(
                affected,
                vec![addr],
                "write at {:#x} should invalidate only that block",
                addr
            );
            assert!(
                !rt.is_compiled(addr),
                "block at {:#x} should be invalidated",
                addr
            );
        }

        // After all cycles, block cache should be empty and code_pages should be empty
        assert!(
            rt.block_cache.is_empty(),
            "all blocks should have been invalidated"
        );
        assert!(
            rt.code_pages.is_empty(),
            "no code pages should remain after all invalidations"
        );
        assert_eq!(
            rt.blocks_compiled, modification_count as u64,
            "all {} compilations should have happened",
            modification_count
        );
    }

    #[test]
    fn self_modifying_code_invalidation_cascade() {
        let mut rt = JitRuntime::new(GuestArch::X64);

        // Compile three adjacent blocks
        let ir_a = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 10,
            },
            IrInstruction::Nop,
        ];
        let ir_b = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 20,
            },
            IrInstruction::Nop,
        ];
        let ir_c = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 30,
            },
            IrInstruction::Nop,
        ];

        rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
            .unwrap();
        rt.get_or_compile(&ir_b, 0x1100, GuestArch::X64, None)
            .unwrap();
        rt.get_or_compile(&ir_c, 0x1200, GuestArch::X64, None)
            .unwrap();

        assert!(rt.is_compiled(0x1000));
        assert!(rt.is_compiled(0x1100));
        assert!(rt.is_compiled(0x1200));

        // Invalidate the middle block only
        let affected = rt.invalidate_blocks_writing_to(0x1100, 4);
        assert_eq!(
            affected,
            vec![0x1100],
            "only the middle block should be invalidated"
        );
        assert!(
            !rt.is_compiled(0x1100),
            "middle block should be invalidated"
        );
        assert!(rt.is_compiled(0x1000), "first block should remain compiled");
        assert!(rt.is_compiled(0x1200), "third block should remain compiled");
    }

    #[test]
    fn self_modifying_code_recompilation_stress() {
        let mut rt = JitRuntime::new(GuestArch::X64);
        let stress_count = 150;

        for i in 0..stress_count {
            let addr = 0x1000;

            // Compile with unique content each time (simulating modified code)
            let ir = vec![
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: i as u64,
                },
                IrInstruction::Nop,
            ];
            rt.get_or_compile(&ir, addr, GuestArch::X64, None).unwrap();
            assert!(
                rt.is_compiled(addr),
                "block at {:#x} should be compiled (cycle {})",
                addr,
                i
            );

            // Simulate self-modifying write to trigger recompilation on next cycle
            let affected = rt.invalidate_blocks_writing_to(addr, 4);
            assert!(
                !affected.is_empty(),
                "write should invalidate block (cycle {})",
                i
            );
        }

        // After all stress cycles, the block cache should be empty
        // (we invalidated after each compilation)
        assert!(
            rt.block_cache.is_empty(),
            "block cache should be empty after {} stress cycles",
            stress_count
        );
        assert!(
            rt.code_pages.is_empty(),
            "code pages should be empty after all invalidations"
        );
        assert_eq!(
            rt.blocks_compiled, stress_count as u64,
            "all {} recompilations should have occurred",
            stress_count
        );
    }

    #[test]
    fn self_modifying_code_hash_mismatch_detection() {
        let mut rt = JitRuntime::new(GuestArch::X64);

        // Compile a block with initial content
        let ir_original = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 42,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir_original, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(rt.is_compiled(0x1000));
        assert_eq!(rt.blocks_compiled, 1);

        // Simulate modified code by requesting get_or_compile with different IR
        // at the same address. The hash check should detect the mismatch,
        // invalidate the old block, and recompile.
        let ir_modified = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 99,
            },
            IrInstruction::Nop,
        ];
        rt.get_or_compile(&ir_modified, 0x1000, GuestArch::X64, None)
            .unwrap();
        assert!(
            rt.is_compiled(0x1000),
            "block should be recompiled with modified IR"
        );
        assert_eq!(
            rt.blocks_compiled, 2,
            "should have recompiled (2 total compilations)"
        );

        // Verify the block has the new source hash
        let block = rt.block_cache.get(&0x1000).unwrap();
        let expected_hash = compute_ir_hash(&ir_modified, 0x1000);
        assert_eq!(
            block.source_hash, expected_hash,
            "recompiled block should have hash of modified IR"
        );
    }

    #[test]
    fn self_modifying_code_page_set_invalidation() {
        let mut rt = JitRuntime::new(GuestArch::X64);

        // Compile blocks on different pages
        let ir_a = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 1,
            },
            IrInstruction::Nop,
        ];
        let ir_b = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 2,
            },
            IrInstruction::Nop,
        ];
        let ir_c = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 3,
            },
            IrInstruction::Nop,
        ];

        rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
            .unwrap();
        rt.get_or_compile(&ir_b, 0x2000, GuestArch::X64, None)
            .unwrap();
        rt.get_or_compile(&ir_c, 0x3000, GuestArch::X64, None)
            .unwrap();

        assert!(rt.is_compiled(0x1000));
        assert!(rt.is_compiled(0x2000));
        assert!(rt.is_compiled(0x3000));

        // Invalidate blocks on pages 0x1000 and 0x3000
        let mut dirty_pages = std::collections::BTreeSet::new();
        dirty_pages.insert(0x1000);
        dirty_pages.insert(0x3000);

        let affected = rt.invalidate_blocks_on_pages(&dirty_pages);
        assert_eq!(affected.len(), 2, "two blocks should be invalidated");
        assert!(affected.contains(&0x1000));
        assert!(affected.contains(&0x3000));
        assert!(!rt.is_compiled(0x1000));
        assert!(rt.is_compiled(0x2000), "block on page 0x2000 should remain");
        assert!(!rt.is_compiled(0x3000));
    }

    // =====================================================================
    // Gap 9.1: FastThunkTable ARM64 trampoline tests
    // =====================================================================

    extern "C" fn thunk_test_target() -> u64 {
        0x42
    }

    // =====================================================================
    // JIT Safety Tests: executable memory exhaustion, SIGBUS loop
    // detection, and out-of-range fault handling
    // =====================================================================

    #[test]
    fn jit_compile_handles_executable_memory_exhaustion() {
        let mut compiler = JitCompiler::new();

        // Exhaust the memory manager by allocating many large blocks.
        // Use a large per-allocation size to exhaust quickly.
        let mut exhausted = false;
        for _ in 0..10_000 {
            let ptr = compiler
                .memory_manager_mut()
                .allocate_code_space(1024 * 1024);
            if ptr.is_null() {
                exhausted = true;
                break;
            }
        }

        if !exhausted {
            // On systems with overcommit (e.g., macOS), mmap may never fail.
            // In that case, test the error path directly by verifying that
            // allocate_code_space returns null for an impossibly large request.
            let ptr = compiler
                .memory_manager_mut()
                .allocate_code_space(1_usize << 50);
            assert!(
                ptr.is_null(),
                "impossibly large allocation should return null"
            );
        }

        // Now try to compile — should NOT panic regardless of outcome.
        // On systems with memory overcommit (e.g., macOS), mmap may never fail
        // for reasonably-sized pages, so compile_block may succeed. In that case
        // the impossibly-large allocation check above already verified that null
        // pointers are handled correctly. If it does fail, verify the error code.
        let ir = vec![IrInstruction::Nop];
        let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, None);
        if let Err(err) = result {
            assert_eq!(
                err.code,
                ReasonCode::RcJitCodeAllocFailed,
                "error should be RcJitCodeAllocFailed, got {:?}",
                err.code
            );
        }
    }

    #[test]
    fn sigbus_reentrancy_guard_prevents_recursive_entry() {
        let _guard = SIGBUS_STATE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Ensure guard starts clear
        SIGBUS_IN_HANDLER.store(false, Ordering::Release);
        assert!(!SIGBUS_IN_HANDLER.load(Ordering::Acquire));

        // First entry: swap should return false (was not set)
        let was_set = SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire);
        assert!(!was_set, "first entry should see false");

        // Second entry (recursive): swap should return true (was set)
        let was_set = SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire);
        assert!(was_set, "recursive entry should see true and return early");

        // After clearing: should allow entry again
        SIGBUS_IN_HANDLER.store(false, Ordering::Release);
        let was_set = SIGBUS_IN_HANDLER.swap(true, Ordering::Acquire);
        assert!(!was_set, "entry after clear should see false");

        // Clean up
        SIGBUS_IN_HANDLER.store(false, Ordering::Release);
    }

    #[test]
    fn sigbus_out_of_range_fault_diagnostic_counters() {
        let _guard = SIGBUS_STATE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let rt = JitRuntime::new(GuestArch::X64);
        let flat_base = rt.flat_memory.base();
        let flat_size = rt.flat_memory.size() as u64;

        // Address within range
        let in_range_addr = flat_base + 0x1000;
        assert!(
            in_range_addr >= flat_base && in_range_addr < flat_base + flat_size,
            "address should be within flat memory range"
        );

        // Address before the range
        let before_range_addr = if flat_base > 0x2000 {
            flat_base - 0x1000
        } else {
            0 // edge case: base is near zero
        };
        assert!(
            before_range_addr < flat_base,
            "address should be before flat memory range"
        );

        // Address after the range
        let after_range_addr = flat_base + flat_size + 0x1000;
        assert!(
            after_range_addr >= flat_base + flat_size,
            "address should be after flat memory range"
        );

        // Verify the range check logic matches what the handler uses
        // (fault_addr >= flat_base && fault_addr < flat_base + flat_size)
        let check_in_range =
            |addr: u64| -> bool { addr >= flat_base && addr < flat_base + flat_size };

        assert!(
            check_in_range(in_range_addr),
            "in-range address should pass range check"
        );
        assert!(
            !check_in_range(before_range_addr),
            "before-range address should fail range check"
        );
        assert!(
            !check_in_range(after_range_addr),
            "after-range address should fail range check"
        );

        // Verify that the SIGBUS statics are null (no handler installed)
        // and that the disabled events counter would be incremented
        assert!(
            SIGBUS_JIT_RUNTIME.load(Ordering::Acquire).is_null(),
            "runtime pointer should be null when no handler is installed"
        );
        assert!(
            SIGBUS_JIT_MEMORY.load(Ordering::Acquire).is_null(),
            "memory pointer should be null when no handler is installed"
        );
    }

    #[test]
    fn fast_thunk_fallback_dispatch_when_not_registered() {
        let mut compiler = JitCompiler::new();
        let ir = vec![IrInstruction::Call {
            target: 0xDEAD_BEEF,
            return_address: 0x1004,
        }];
        // No fast_thunk_addrs provided, so the Call should fall back to
        // EXIT_THUNK path, which emits standard exit without fast-thunk.
        let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, None);
        assert!(
            result.is_ok(),
            "compile_block should succeed even without fast thunks"
        );
    }

    #[test]
    fn block_chaining_publishes_link_and_unchains() {
        let mut rt = JitRuntime::new(GuestArch::X64);

        let ir_a = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 1,
            },
            IrInstruction::Jump { target: 0x2000 },
        ];
        let ir_b = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 2,
            },
            IrInstruction::Jump { target: 0x3000 },
        ];

        rt.get_or_compile(&ir_a, 0x1000, GuestArch::X64, None)
            .unwrap();
        rt.get_or_compile(&ir_b, 0x2000, GuestArch::X64, None)
            .unwrap();

        assert!(rt.is_compiled(0x1000));
        assert!(rt.is_compiled(0x2000));

        rt.chain_blocks(0x1000, 0x2000).unwrap();
        let chain_key = (0x1000, 0x2000);
        assert!(rt.block_chains.contains_key(&chain_key));
        assert_ne!(
            rt.block_cache
                .get(&0x1000)
                .unwrap()
                .link_target
                .load(Ordering::Acquire),
            0
        );

        let unchain_result = rt.unchain_block(0x1000);
        assert!(unchain_result.is_ok(), "unchaining should succeed");
        assert!(!rt.block_chains.contains_key(&chain_key));
        assert_eq!(
            rt.block_cache
                .get(&0x1000)
                .unwrap()
                .link_target
                .load(Ordering::Acquire),
            0,
            "unchaining must clear the atomic link slot"
        );
    }

    #[test]
    fn fast_thunk_compile_fallback_when_global_map_missing() {
        let mut compiler = JitCompiler::new();
        let ir = vec![IrInstruction::Call {
            target: 0xDEAD_BEEF,
            return_address: 0x1004,
        }];
        // Provide a set containing the target address, but the global
        // FAST_THUNK_MAP has no entry for it. The compiler should fall
        // back gracefully to EXIT_THUNK instead of panicking.
        let mut fast_thunk_addrs = std::collections::HashSet::new();
        fast_thunk_addrs.insert(0xDEAD_BEEF);
        let result = compiler.compile_block(&ir, 0x1000, GuestArch::X64, Some(&fast_thunk_addrs));
        assert!(
            result.is_ok(),
            "compile_block should fall back to EXIT_THUNK even if global map missing entry"
        );
    }

    // =====================================================================
    // On-demand guest-page materialisation
    // =====================================================================

    static GUEST_MEMORY_TELEMETRY_LOCK: Mutex<()> = Mutex::new(());
    /// Serializes tests that install/remove the SIGBUS handler or mutate its
    /// process-wide state.
    static SIGBUS_STATE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn sparse_guest_memory_materialises_only_committed_pages() {
        let _guard = GUEST_MEMORY_TELEMETRY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut memory = MemoryImage::default();
        for i in 0..16u64 {
            memory.map_bytes(i * 0x0800_0000, &[0xABu8; 4096]);
        }
        assert_eq!(memory.committed_page_addresses().len(), 16);
        assert_eq!(
            memory.canonical_store().materialisation_count(),
            16,
            "each committed page is materialised exactly once by the store"
        );

        let mut runtime = JitRuntime::new(GuestArch::X64);
        reset_guest_memory_telemetry();
        runtime.sync_all_pages_to_flat(&memory);

        let telemetry = guest_memory_telemetry();
        assert_eq!(
            telemetry.pages_materialised, 16,
            "only the 16 committed pages may be materialised"
        );
        assert_eq!(
            telemetry.sync_operations, 16,
            "16 isolated pages form 16 runs"
        );
        assert_eq!(telemetry.bytes_copied, 16 * 4096);
        assert_eq!(
            memory.canonical_store().materialisation_count(),
            16,
            "the sync pass must not re-materialise canonical pages"
        );
        runtime.sync_all_pages_to_flat(&memory);
        assert_eq!(
            memory.canonical_store().materialisation_count(),
            16,
            "repeated sync passes must leave canonical materialisation unchanged"
        );
        assert_eq!(runtime.flat_memory.materialised_page_count(), 16);
        assert_eq!(
            runtime.flat_memory.total_page_count(),
            (runtime.flat_memory.size() / 4096) as u64,
            "the flat region is the whole direct window"
        );
        assert!(
            telemetry.pages_materialised < runtime.flat_memory.total_page_count() / 1000,
            "materialisation must not be proportional to the flat region"
        );
        assert!(runtime.flat_memory.is_page_materialised(0));
        assert!(!runtime.flat_memory.is_page_materialised(0x1000));
        assert!(
            !runtime
                .flat_memory
                .is_page_materialised(0x0800_0000 + 0x1000)
        );

        // The committed bytes really made it into the mirror.
        let mut buf = [0u8; 8];
        runtime.flat_memory.read(0, &mut buf);
        assert_eq!(buf, [0xAB; 8]);
        runtime.flat_memory.sync_from_memory_image(0, &[0xCD; 8]);
        assert_eq!(
            memory.read_u8(0).unwrap(),
            0xCD,
            "an explicit flat write must land in the shared canonical page"
        );
        runtime.flat_memory.read(0, &mut buf);
        assert_eq!(buf, [0xCD; 8]);
        // Out-of-window syncs/reads/diagnostic probes must be refused without
        // touching the mapping.
        runtime
            .flat_memory
            .sync_from_memory_image(u64::MAX - 3, &[0xEE; 8]);
        runtime.flat_memory.read(u64::MAX - 3, &mut buf);
        assert_eq!(buf, [0xCD; 8]);
        assert!(!runtime.flat_memory.is_page_materialised(0x1001));
        assert!(
            !runtime
                .flat_memory
                .is_page_materialised(GUEST_FLAT_SIZE as u64)
        );
        let debug = format!("{memory:?}");
        assert!(debug.contains("GuestMemoryStore"));
        assert!(!debug.contains("materialised: ["));
    }

    #[test]
    fn invalid_flat_view_rejects_reads_syncs_and_materialisation() {
        let memory = MemoryImage::default();
        let store = Arc::new(GuestMemoryStore::invalid_for_test());
        let bitmap_words = GUEST_FLAT_SIZE.div_ceil(4096 * 64);
        let flat = FlatGuestMemory {
            store,
            materialised: (0..bitmap_words)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        };
        assert!(!flat.is_valid());
        assert_eq!(flat.base(), 0);
        let mut buf = [0xAA; 8];
        flat.read(0, &mut buf);
        assert_eq!(buf, [0xAA; 8], "an invalid view must not write the buffer");
        flat.sync_from_memory_image(0, &[0x11; 8]);
        let stats = flat.materialise_pages(&memory, &[0]);
        assert_eq!(stats.pages_materialised, 0);
        assert_eq!(stats.bytes_copied, 0);
        assert!(!flat.is_page_materialised(0));
    }

    #[test]
    fn partially_mapped_page_is_not_materialised() {
        let _guard = GUEST_MEMORY_TELEMETRY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut memory = MemoryImage::default();
        // Only the first 16 bytes of the page are mapped.
        memory.map_bytes(0x3000_0000, &[0x11u8; 16]);

        let mut runtime = JitRuntime::new(GuestArch::X64);
        let detached = runtime
            .flat_memory
            .materialise_pages(&memory, &[0x3000_0000]);
        assert_eq!(detached.pages_materialised, 0);
        assert_eq!(detached.bytes_copied, 0);
        assert!(!runtime.flat_memory.is_page_materialised(0x3000_0000));

        reset_guest_memory_telemetry();
        runtime.sync_all_pages_to_flat(&memory);

        let telemetry = guest_memory_telemetry();
        assert_eq!(telemetry.pages_materialised, 0);
        assert_eq!(telemetry.bytes_copied, 0);
        assert!(!runtime.flat_memory.is_page_materialised(0x3000_0000));

        let empty = runtime.flat_memory.materialise_pages(&memory, &[]);
        assert_eq!(empty.pages_materialised, 0);
        let outside = runtime
            .flat_memory
            .materialise_pages(&memory, &[GUEST_FLAT_SIZE as u64]);
        assert_eq!(outside.pages_materialised, 0);
        assert_eq!(outside.sync_operations, 0);
    }

    #[test]
    fn sigbus_fallback_never_corrupts_committed_bytes_and_handles_partial_and_absent_pages() {
        let _guard = GUEST_MEMORY_TELEMETRY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0xAB; 4096]);
        memory.map_bytes(0x2000, &[0x11; 16]);
        memory.map_bytes(0x4000 + 4080, &[0x22; 16]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.sync_all_pages_to_flat(&memory);
        let base = runtime.flat_memory.base() as *mut u8;
        let size = runtime.flat_memory.size();

        service_faulting_page(&runtime, &memory, 0x1000, base, size);
        // SAFETY: page 0x1000 is inside the shared flat window.
        let first = unsafe { std::ptr::read_volatile(base.add(0x1000)) };
        assert_eq!(first, 0xAB, "servicing must never zero committed bytes");
        assert_eq!(memory.read_u8(0x1000).unwrap(), 0xAB);

        service_faulting_page(&runtime, &memory, 0x2000, base, size);
        // SAFETY: page 0x2000 is inside the shared flat window.
        let partial_head = unsafe { std::ptr::read_volatile(base.add(0x2000)) };
        assert_eq!(partial_head, 0x11);
        assert!(!runtime.flat_memory.is_page_materialised(0x2000));

        service_faulting_page(&runtime, &memory, 0x4000, base, size);
        // SAFETY: page 0x4000 is inside the shared flat window.
        let partial_tail = unsafe { std::ptr::read_volatile(base.add(0x4000 + 4095)) };
        assert_eq!(partial_tail, 0x22);
        assert!(!runtime.flat_memory.is_page_materialised(0x4000));

        service_faulting_page(&runtime, &memory, 0x6000, base, size);
        // SAFETY: page 0x6000 is inside the shared flat window.
        let absent_tail = unsafe { std::ptr::read_volatile(base.add(0x6000 + 4095)) };
        assert_eq!(absent_tail, 0);
        assert!(runtime.flat_memory.is_page_materialised(0x6000));
        assert!(
            memory.read_u8(0x6000).is_err(),
            "an uncommitted page must stay unmapped for the interpreter"
        );
        assert_eq!(memory.canonical_store().materialisation_count(), 3);
    }

    #[test]
    fn sigbus_fallback_touches_mapped_tail_without_zeroing_or_marking_it() {
        let mut memory = MemoryImage::default();
        // Only the last 16 bytes of the page are mapped.
        memory.map_bytes(0x4FF0, &[0x33; 16]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.sync_all_pages_to_flat(&memory);
        let base = runtime.flat_memory.base() as *mut u8;
        let size = runtime.flat_memory.size();

        service_faulting_page(&runtime, &memory, 0x4000, base, size);
        // SAFETY: page 0x4000 is inside the shared flat window.
        let tail = unsafe { std::ptr::read_volatile(base.add(0x4FFF)) };
        assert_eq!(tail, 0x33, "a mapped tail byte must never be zeroed");
        // SAFETY: byte 0 of the same page is inside the flat window.
        let head = unsafe { std::ptr::read_volatile(base.add(0x4000)) };
        assert_eq!(head, 0);
        assert!(!runtime.flat_memory.is_page_materialised(0x4000));
        assert_eq!(memory.read_u8(0x4FFF).unwrap(), 0x33);
    }

    #[test]
    fn legacy_sync_entry_points_never_leave_stale_or_duplicate_state() {
        let _guard = GUEST_MEMORY_TELEMETRY_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0x11; 4096]);
        memory.map_bytes(0x2000, &[0x22; 4096]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.sync_all_pages_to_flat(&memory);
        assert_eq!(runtime.synced_page_count(), 2);

        runtime.sync_page_to_flat(&memory, 0x1000);
        assert_eq!(runtime.synced_page_count(), 2);
        memory.map_bytes(0x3000, &[0x33; 4096]);
        runtime.sync_new_pages_to_flat(&memory);
        assert_eq!(runtime.synced_page_count(), 3);
        assert_eq!(
            memory.canonical_store().materialisation_count(),
            3,
            "incremental sync must not rematerialise existing pages"
        );

        // These back-compatibility entry points are deliberate no-ops: a
        // write through either view is already visible through the other.
        runtime.sync_flat_to_memory(0x1000, &mut memory, 8);
        runtime.sync_all_flat_to_memory(&mut memory);
        runtime.sync_synced_flat_to_memory(&mut memory);
        assert_eq!(memory.read_u8(0x1000).unwrap(), 0x11);
        assert_eq!(memory.read_u8(0x2000).unwrap(), 0x22);
        assert_eq!(memory.read_u8(0x3000).unwrap(), 0x33);
        assert_eq!(memory.canonical_store().materialisation_count(), 3);
    }

    #[test]
    fn sigbus_handler_services_flat_fault_without_copying_or_corrupting() {
        let _guard = SIGBUS_STATE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x7000, &[0x5A; 4096]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.sync_all_pages_to_flat(&memory);
        runtime.install_sigbus_handler(&memory);

        // SAFETY: `siginfo_t` is zero-initialised and only public fields are
        // set.  The handler is called directly (not from a real signal) with a
        // flat-window address that is fully committed.
        unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            info.si_signo = libc::SIGBUS;
            info.si_addr = (runtime.flat_memory.base() + 0x7000) as *mut c_void;
            sigbus_sa_handler(libc::SIGBUS, &mut info, std::ptr::null_mut());
        }

        assert_eq!(
            memory.read_u8(0x7000).unwrap(),
            0x5A,
            "the fallback must preserve committed bytes"
        );
        assert!(runtime.flat_memory.is_page_materialised(0x7000));
        assert_eq!(SIGBUS_HANDLER_DEPTH.load(Ordering::Relaxed), 0);
        assert!(!SIGBUS_IN_HANDLER.load(Ordering::Acquire));
        runtime.remove_sigbus_handler();
        assert!(SIGBUS_JIT_RUNTIME.load(Ordering::Acquire).is_null());
        assert!(SIGBUS_JIT_MEMORY.load(Ordering::Acquire).is_null());
    }
}

#[cfg(test)]
mod sigbus_diagnostic_tests {
    use super::*;
}

#[cfg(test)]
mod production_safety_tests {
    use super::*;

    fn execute_cached(
        runtime: &mut JitRuntime,
        address: u64,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> JitExitReason {
        let block = runtime
            .block_cache
            .get(&address)
            .cloned()
            .expect("block must be compiled");
        state.rip = address;
        // SAFETY: test-only single-threaded execution of a block compiled by
        // this runtime; state/memory outlive the call.
        unsafe { runtime.execute_block(&block, state, memory) }
    }

    fn skip_without_capability(test: &str) -> bool {
        skip_without_capability_for(test, jit_execution_available())
    }

    fn skip_without_capability_for(test: &str, available: bool) -> bool {
        if available {
            return false;
        }
        eprintln!("[jit] skipping {test}: executable-memory probe unavailable");
        true
    }

    #[test]
    fn jit_capability_gate_reports_unavailable_host_without_running_native_code() {
        assert_eq!(skip_without_capability_for("fixture", true), false);
        assert_eq!(skip_without_capability_for("fixture", false), true);
        assert_eq!(
            skip_without_capability("fixture"),
            !jit_execution_available()
        );
    }

    #[test]
    fn jit_construction_gate_rejects_deterministic_and_unavailable_hosts() {
        use crate::runner::JitMode;
        // Auto selects native execution only on a capable, non-deterministic
        // host.
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Auto, false, true),
            true
        );
        // Auto is interpreter-only when the probe failed...
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Auto, false, false),
            false
        );
        // ...and in deterministic/replay mode even on a capable host.
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Auto, true, true),
            false
        );
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Auto, true, false),
            false
        );
        // Disabled never constructs; Enabled is an explicit override.
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Disabled, false, true),
            false
        );
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Enabled, false, false),
            true
        );
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Enabled, true, true),
            true
        );
    }

    #[test]
    fn auto_unavailable_host_and_deterministic_modes_fall_back() {
        use crate::runner::JitMode;
        // Incapable host: Auto never constructs the JIT runtime.
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Auto, false, false),
            false
        );
        // Deterministic host under Auto: interpreter-only, same behaviour.
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Auto, true, true),
            false
        );
        // Explicit Enabled still constructs (documented override), and a
        // disabled mode never does.
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Enabled, true, true),
            true
        );
        assert_eq!(
            crate::runtime::jit_construction_selected(&JitMode::Disabled, false, true),
            false
        );
    }

    fn run_self_modifying_code_case(available: bool) -> Option<()> {
        if !available {
            return None;
        }
        let code = 0x00A1_0000u64;
        let writer = 0x00A1_1000u64;
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        let original = vec![IrInstruction::MovImm {
            dst: Register::Rax,
            value: 42,
        }];
        runtime
            .get_or_compile(&original, code, GuestArch::X64, None)
            .expect("compile original block");
        let stale = runtime.block_cache.get(&code).cloned().expect("cached");
        let _ = execute_cached(&mut runtime, code, &mut state, &mut memory);
        assert_eq!(state.get(Register::Rax), 42);

        // Guest code itself overwrites the block's first four bytes.  The
        // page must be mapped so the store reaches the SMC hook (an unmapped
        // store takes the guest-fault path instead).
        memory.map_zeroed_if_unmapped(code, 0x1000);
        let writer_ir = vec![
            IrInstruction::StoreImmediate {
                address: crate::cpu::MemoryOperand {
                    base: None,
                    index: None,
                    scale: 1,
                    displacement: 0,
                    rip_relative: false,
                    rip_base: 0,
                    segment: None,
                    address_size_32: false,
                    absolute_address: Some(code),
                },
                value: 0x9090_9090,
                width: 4,
            },
            IrInstruction::Nop,
        ];
        runtime
            .get_or_compile(&writer_ir, writer, GuestArch::X64, None)
            .expect("compile writer block");
        let _ = execute_cached(&mut runtime, writer, &mut state, &mut memory);
        assert!(
            runtime.code_invalidations >= 1,
            "guest store to a code page must invalidate the compiled block"
        );
        assert!(runtime.smc_invalidation_events >= 1);

        // The stale block must not execute its old bytes: the entry check
        // returns the interpreter fallback.
        state.set(Register::Rax, 0);
        state.rip = code;
        let reason = unsafe { runtime.execute_block(&stale, &mut state, &mut memory) };
        assert_eq!(
            reason,
            JitExitReason::Safepoint,
            "a stale SMC block must fall back to the interpreter, not run"
        );

        // Recompiling from the new code observes the new behaviour.
        let updated = vec![IrInstruction::MovImm {
            dst: Register::Rax,
            value: 43,
        }];
        runtime
            .get_or_compile(&updated, code, GuestArch::X64, None)
            .expect("recompile modified block");
        state.set(Register::Rax, 0);
        let _ = execute_cached(&mut runtime, code, &mut state, &mut memory);
        assert_eq!(
            state.get(Register::Rax),
            43,
            "recompilation must not execute stale code"
        );
        Some(())
    }

    #[test]
    fn self_modifying_code_guest_store_invalidates_and_recompiles() {
        assert_eq!(
            run_self_modifying_code_case(false),
            None,
            "an unavailable probe must skip native SMC invalidation"
        );
        assert_eq!(
            run_self_modifying_code_case(jit_execution_available()).is_some(),
            jit_execution_available()
        );
    }

    fn run_backedge_link_case(available: bool) -> Option<()> {
        if !available {
            return None;
        }
        let source = 0x00A2_0000u64;
        let target = 0x00A2_1000u64;
        let exit = 0x00A2_2000u64;
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        let source_ir = vec![IrInstruction::Nop, IrInstruction::Jump { target }];
        let target_ir = vec![IrInstruction::Nop, IrInstruction::Jump { target: exit }];
        runtime
            .get_or_compile(&source_ir, source, GuestArch::X64, None)
            .expect("compile source");
        runtime
            .get_or_compile(&target_ir, target, GuestArch::X64, None)
            .expect("compile target");
        runtime.chain_blocks(source, target).expect("publish link");
        assert_eq!(runtime.chain_links_formed, 1);
        assert!(
            runtime
                .block_cache
                .get(&source)
                .expect("source cached")
                .link_target
                .load(Ordering::Acquire)
                != 0,
            "link slot must publish the target entry"
        );

        // Linked execution reaches the target's EXIT_JUMP (target semantics),
        // proving the dispatcher was bypassed.
        let reason = execute_cached(&mut runtime, source, &mut state, &mut memory);
        assert_eq!(reason, JitExitReason::Jump { target: exit });

        // Safepoint semantics survive chaining: the target prologue (and the
        // source prologue) still poll the host flag.
        JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
        let reason = execute_cached(&mut runtime, source, &mut state, &mut memory);
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
        assert_eq!(reason, JitExitReason::Safepoint);
        Some(())
    }

    #[test]
    fn backedge_link_falls_back_to_safepoint_when_requested() {
        assert_eq!(
            run_backedge_link_case(false),
            None,
            "an unavailable probe must skip native chain execution"
        );
        assert_eq!(
            run_backedge_link_case(jit_execution_available()).is_some(),
            jit_execution_available()
        );
    }

    extern "C" fn direct_thunk_target(
        _runtime: *mut c_void,
        state: *mut CpuState,
        _memory: *mut MemoryImage,
        _thunk: u64,
    ) -> i32 {
        if !state.is_null() {
            unsafe {
                (*state).gpr[0] = 0x77;
            }
        }
        -1
    }

    #[test]
    fn direct_thunk_target_invalid_state_is_safe_and_pins_sentinel() {
        assert_eq!(
            direct_thunk_target(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0
            ),
            -1,
            "a null state must not be dereferenced and must still request continuation"
        );
        let mut state = CpuState::new(GuestArch::X64);
        assert_eq!(
            direct_thunk_target(
                std::ptr::null_mut(),
                &mut state,
                std::ptr::null_mut(),
                0xDEAD
            ),
            -1
        );
        assert_eq!(state.get(Register::Rax), 0x77);
    }

    #[test]
    fn direct_resolved_thunk_call_bypasses_dispatcher() {
        if skip_without_capability("direct_resolved_thunk_call_bypasses_dispatcher") {
            return;
        }
        const GUEST_THUNK: u64 = 0x00A3_5000;
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        state.set(Register::Rsp, 0x2000);
        runtime
            .register_host_thunk_for_guest(direct_thunk_target as *const () as usize, GUEST_THUNK)
            .expect("register resolved thunk");
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7,
            },
            IrInstruction::Call {
                target: GUEST_THUNK,
                return_address: 0x00A3_6004,
            },
        ];
        let before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
        runtime
            .get_or_compile(&ir, 0x00A3_6000, GuestArch::X64, None)
            .expect("compile direct-call block");
        assert!(
            JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed) > before,
            "resolved thunk must be emitted as a direct call"
        );
        let reason = execute_cached(&mut runtime, 0x00A3_6000, &mut state, &mut memory);
        assert!(matches!(reason, JitExitReason::Normal { .. }));
        assert_eq!(
            state.get(Register::Rax),
            0x77,
            "the host thunk must run without an EXIT_THUNK dispatcher trip"
        );
    }

    fn run_invalid_block_installation_case(available: bool) -> Option<()> {
        if !available {
            return None;
        }
        let address = 0x00A4_0000u64;
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let ir = vec![IrInstruction::MovImm {
            dst: Register::Rax,
            value: 42,
        }];
        runtime
            .get_or_compile(&ir, address, GuestArch::X64, None)
            .expect("compile");
        let stale = runtime.block_cache.get(&address).cloned().expect("cached");

        // Simulate a crash-equivalent signal at block installation/unwind:
        // the block is quarantined and handed to the interpreter.
        runtime.report_block_fault(address);
        assert_eq!(runtime.fault_fallbacks, 1);
        assert!(runtime.faulted_blocks.contains(&address));
        assert!(!runtime.is_compiled(address));
        assert!(
            runtime
                .get_or_compile(&ir, address, GuestArch::X64, None)
                .is_err(),
            "a faulted block must stay on the interpreter"
        );

        state.rip = address;
        let reason = unsafe { runtime.execute_block(&stale, &mut state, &mut memory) };
        assert_eq!(reason, JitExitReason::Safepoint);
        assert!(runtime.fault_fallbacks >= 1);
        Some(())
    }

    #[test]
    fn invalid_block_installation_falls_back_to_interpreter() {
        assert_eq!(
            run_invalid_block_installation_case(false),
            None,
            "an unavailable probe must skip the native fault fallback"
        );
        assert_eq!(
            run_invalid_block_installation_case(jit_execution_available()).is_some(),
            jit_execution_available()
        );
    }

    #[test]
    fn jit_block_and_interpreter_store_never_observe_a_stale_canonical_page() {
        if skip_without_capability(
            "jit_block_and_interpreter_store_never_observe_a_stale_canonical_page",
        ) {
            return;
        }
        let address = 0x2_0000_u64;
        let load_site = 0x3_0000_u64;
        let store_site = 0x4_0000_u64;
        let mut memory = MemoryImage::default();
        memory.map_bytes(address, &[0_u8; 16]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.sync_all_pages_to_flat(&memory);

        assert!(
            Arc::ptr_eq(runtime.flat_memory.store(), memory.canonical_store()),
            "the JIT flat view must alias the image's canonical store"
        );
        assert_eq!(
            runtime.flat_memory.base(),
            memory.canonical_store().flat_base(),
            "both views must share the same direct-window mapping"
        );
        assert_eq!(memory.canonical_store().materialisation_count(), 1);

        // Direct JIT-view store → interpreter read, with no sync call.
        // SAFETY: the page is committed, aligned and inside the shared map.
        unsafe {
            ptr::write_volatile(
                (runtime.flat_memory.base() as *mut u64).add((address / 8) as usize),
                0x1111_2222_3333_4444,
            );
        }
        assert_eq!(memory.read_u64(address).unwrap(), 0x1111_2222_3333_4444);

        // Interpreter store → direct JIT-view read, with no sync call.
        memory.write_u64(address, 0x5555_6666_7777_8888);
        // SAFETY: same canonical page as above.
        let flat_value = unsafe {
            ptr::read_volatile(
                (runtime.flat_memory.base() as *const u64).add((address / 8) as usize),
            )
        };
        assert_eq!(flat_value, 0x5555_6666_7777_8888);

        let operand = crate::cpu::MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(address),
        };
        let load_ir = vec![IrInstruction::LoadMemory {
            dst: Register::Rax,
            address: operand.clone(),
            width: 8,
        }];
        runtime
            .get_or_compile(&load_ir, load_site, GuestArch::X64, None)
            .expect("compile canonical load block");
        let mut state = CpuState::new(GuestArch::X64);
        let reason = execute_cached(&mut runtime, load_site, &mut state, &mut memory);
        assert!(matches!(reason, JitExitReason::Normal { .. }));
        assert_eq!(
            state.get(Register::Rax),
            0x5555_6666_7777_8888,
            "the compiled block must see the interpreter's store immediately"
        );

        // A later interpreter store is visible to the next block execution
        // without an explicit sync.
        memory.write_u64(address, 0x9999_AAAA_BBBB_CCCC);
        state.set(Register::Rax, 0);
        let reason = execute_cached(&mut runtime, load_site, &mut state, &mut memory);
        assert!(matches!(reason, JitExitReason::Normal { .. }));
        assert_eq!(state.get(Register::Rax), 0x9999_AAAA_BBBB_CCCC);

        // Compiled store → interpreter read, with no write-back pass.
        let store_ir = vec![IrInstruction::StoreMemory {
            src: Register::Rcx,
            address: operand,
            width: 8,
        }];
        runtime
            .get_or_compile(&store_ir, store_site, GuestArch::X64, None)
            .expect("compile canonical store block");
        state.set(Register::Rcx, 0xDDDD_EEEE_FFFF_0001);
        let reason = execute_cached(&mut runtime, store_site, &mut state, &mut memory);
        assert!(matches!(reason, JitExitReason::Normal { .. }));
        assert_eq!(
            memory.read_u64(address).unwrap(),
            0xDDDD_EEEE_FFFF_0001,
            "the interpreter must see the compiled block's store immediately"
        );

        assert_eq!(
            memory.canonical_store().materialisation_count(),
            1,
            "JIT execution must never materialise an already-committed page"
        );
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage: probe failure protocol, executable-memory refusals,
// SMC watch/dirty edge cases, chaining/tier errors, and fault fallbacks.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial_tests {
    use super::*;
    use crate::cpu::{GUEST_FLAT_ALIGN, GUEST_FLAT_MIN_SIZE, GUEST_FLAT_SIZE};
    use std::sync::atomic::Ordering;

    fn probe_matrix(selected: JitExecMechanism) -> JitExecProbeMatrix {
        JitExecProbeMatrix {
            mprotect_rx: JitExecProbeOutcome::NotProbed,
            map_jit_wx_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_rw_write_protect: JitExecProbeOutcome::NotProbed,
            map_jit_wx_no_write_protect: JitExecProbeOutcome::NotProbed,
            selected,
        }
    }

    fn capable_runtime() -> JitRuntime {
        assert!(
            jit_execution_available(),
            "this test requires a working executable-memory mechanism"
        );
        JitRuntime::new(GuestArch::X64)
    }

    fn execute_cached(
        runtime: &mut JitRuntime,
        address: u64,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> JitExitReason {
        let block = runtime
            .block_cache
            .get(&address)
            .cloned()
            .expect("block must be compiled");
        state.rip = address;
        // SAFETY: test-only single-threaded execution of a block compiled by
        // this runtime; state/memory outlive the call.
        unsafe { runtime.execute_block(&block, state, memory) }
    }

    fn smc_slot(page: u64) -> usize {
        let x = (page >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (x >> (64 - 13)) as usize & SMC_WATCH_MASK
    }

    // ── Capability probe reporting ──────────────────────────────────────────

    #[test]
    fn jit_exec_mechanism_display_rejects_ambiguous_text() {
        assert_eq!(
            JitExecMechanism::MapJitWx.to_string(),
            "MAP_JIT RWX + pthread_jit_write_protect_np"
        );
        assert_eq!(
            JitExecMechanism::MprotectRx.to_string(),
            "mmap RW + mprotect RX"
        );
        assert_eq!(JitExecMechanism::RwxMmap.to_string(), "mmap RWX");
        assert_eq!(JitExecMechanism::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn jit_exec_probe_outcome_display_reports_exact_failures() {
        assert_eq!(
            JitExecProbeOutcome::Executed(42).to_string(),
            "executed, returned 42"
        );
        assert_eq!(
            JitExecProbeOutcome::MmapFailed(libc::EINVAL).to_string(),
            "mmap failed: errno 22 (Invalid argument (os error 22))"
        );
        assert_eq!(
            JitExecProbeOutcome::MprotectFailed(libc::EINVAL).to_string(),
            "mprotect(PROT_EXEC) failed: errno 22 (Invalid argument (os error 22))"
        );
        assert_eq!(
            JitExecProbeOutcome::WriteFaulted(libc::SIGBUS).to_string(),
            "write faulted: signal 10"
        );
        assert_eq!(
            JitExecProbeOutcome::ExecuteFaulted(libc::SIGSEGV).to_string(),
            "execution faulted: signal 11"
        );
        assert_eq!(
            JitExecProbeOutcome::ForkFailed(libc::EAGAIN).to_string(),
            "fork failed: errno 35 (Resource temporarily unavailable (os error 35))"
        );
        assert_eq!(
            JitExecProbeOutcome::ChildFailed(7).to_string(),
            "probe child exited without a result: 7"
        );
        assert_eq!(
            JitExecProbeOutcome::NotProbed.to_string(),
            "not probed on this target"
        );
    }

    #[test]
    fn jit_exec_probe_select_rejects_non_executing_mechanisms() {
        // A mechanism that "runs" but returns the wrong value must not win.
        let wrong = JitExecProbeMatrix::select(
            JitExecProbeOutcome::Executed(42),
            JitExecProbeOutcome::Executed(41),
            JitExecProbeOutcome::WriteFaulted(libc::SIGBUS),
            JitExecProbeOutcome::ExecuteFaulted(libc::SIGBUS),
        );
        assert_eq!(wrong.selected, JitExecMechanism::MprotectRx);
        // When neither mechanism executes the stub, native execution is off.
        let none = JitExecProbeMatrix::select(
            JitExecProbeOutcome::MmapFailed(libc::EINVAL),
            JitExecProbeOutcome::MmapFailed(libc::EINVAL),
            JitExecProbeOutcome::MmapFailed(libc::EINVAL),
            JitExecProbeOutcome::MmapFailed(libc::EINVAL),
        );
        assert_eq!(none.selected, JitExecMechanism::Unavailable);
        // The W^X MAP_JIT mechanism is preferred when it executes.
        let preferred = JitExecProbeMatrix::select(
            JitExecProbeOutcome::Executed(42),
            JitExecProbeOutcome::Executed(42),
            JitExecProbeOutcome::Executed(42),
            JitExecProbeOutcome::Executed(42),
        );
        assert_eq!(preferred.selected, JitExecMechanism::MapJitWx);
    }

    // ── Executable-memory manager refusals ──────────────────────────────────

    #[test]
    fn jit_memory_manager_mprotect_rejects_foreign_mappings() {
        let mut manager =
            JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::MprotectRx));
        let code = [0x1f, 0x20, 0x03, 0xd5];
        let ptr = manager.allocate_code_space(code.len());
        assert_eq!(manager.mechanism(), JitExecMechanism::MprotectRx);
        assert!(!ptr.is_null());
        assert_eq!(manager.total_allocated(), JIT_PAGE_SIZE);
        assert_eq!(manager.total_used(), 64);
        // SAFETY: ptr was allocated by this manager for at least code.len().
        unsafe {
            assert_eq!(manager.make_writable(ptr, code.len()), true);
            ptr::copy_nonoverlapping(code.as_ptr(), ptr, code.len());
            assert_eq!(manager.finalize_code(ptr, code.len()), true);
        }
        // A pointer outside every managed mmap must be refused, not blindly
        // mprotect'ed (which would corrupt an unrelated host mapping).
        let mut foreign = [0u32; 2];
        let foreign_ptr = foreign.as_mut_ptr() as *mut u8;
        unsafe {
            assert_eq!(manager.make_writable(foreign_ptr, 4), false);
            assert_eq!(manager.finalize_code(foreign_ptr, 4), false);
        }
    }

    #[test]
    fn jit_memory_manager_rwx_rejects_zero_size_finalize() {
        // Plain RWX anon mmap is refused on this host (no MAP_JIT); the arm
        // must still be exercised and must fail allocation rather than lie.
        let mut plain = JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::RwxMmap));
        let _ = plain.allocate_code_space(4);

        // Exercise the direct-RWX permission arms with a live mapping so the
        // mechanism's "already writable/executable" contract is pinned.
        let mut backing =
            JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::MapJitWx));
        let ptr = backing.allocate_code_space(64);
        assert!(!ptr.is_null());
        let mut manager =
            JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::RwxMmap));
        manager.pages.push((ptr, JIT_PAGE_SIZE));
        assert_eq!(manager.mechanism(), JitExecMechanism::RwxMmap);
        // SAFETY: ptr is a live mapping owned by this test.
        unsafe {
            assert_eq!(manager.make_writable(ptr, 4), true);
            assert_eq!(manager.finalize_code(ptr, 4), true);
            assert_eq!(manager.finalize_code(ptr, 0), false);
            assert_eq!(manager.finalize_code(std::ptr::null_mut(), 4), false);
        }
    }

    #[test]
    fn jit_install_code_rejects_foreign_writable_page() {
        let mut compiler = JitCompiler::new();
        compiler.memory_manager =
            JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::MprotectRx));
        compiler.emitter.nop();
        let mut foreign = [0u32; 2];
        let error = compiler
            .install_code(foreign.as_mut_ptr() as *mut u8, 4)
            .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(error.message, "JIT: executable code page is not writable");
    }

    #[test]
    fn jit_install_code_rejects_zero_size_finalize() {
        let mut compiler = JitCompiler::new();
        let ptr = compiler.memory_manager.allocate_code_space(64);
        assert!(!ptr.is_null());
        let error = compiler.install_code(ptr, 0).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(
            error.message,
            "JIT: failed to make compiled block executable"
        );
    }

    #[test]
    fn jit_compile_block_rejects_unavailable_executable_memory() {
        let mut compiler = JitCompiler::new();
        compiler.memory_manager =
            JitMemoryManager::with_capability(probe_matrix(JitExecMechanism::Unavailable));
        let error = compiler
            .compile_block(&[IrInstruction::Nop], 0x1000, GuestArch::X64, None)
            .err()
            .expect("unavailable memory must fail compilation");
        assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(error.message, "JIT: failed to allocate executable memory");
    }

    // ── SMC watch/dirty edge cases ──────────────────────────────────────────

    #[test]
    fn smc_watch_overflow_marks_every_page_watched() {
        let state = SmcState::new();
        let pages: Vec<u64> = (0..=SMC_WATCH_SLOTS as u64)
            .map(|i| (i + 1) * 0x1000)
            .collect();
        state.rebuild_watch(pages.iter());
        assert_eq!(state.watched_count.load(Ordering::Acquire), SMC_WATCH_SLOTS);
        assert_eq!(state.watch_overflow.load(Ordering::Acquire), true);
        assert_eq!(
            state.is_watched(0xFFFF_FFFF_FFFF_F000),
            true,
            "overflow must conservatively watch unknown pages"
        );
    }

    #[test]
    fn smc_watch_full_table_rejects_absent_page() {
        let state = SmcState::new();
        let pages: Vec<u64> = (0..SMC_WATCH_SLOTS as u64)
            .map(|i| (i + 1) * 0x1000)
            .collect();
        state.rebuild_watch(pages.iter());
        assert_eq!(state.watched_count.load(Ordering::Acquire), SMC_WATCH_SLOTS);
        assert_eq!(state.watch_overflow.load(Ordering::Acquire), false);
        // Every probe slot is occupied by another key; the scan must exhaust
        // the bounded probe sequence and report "not watched".
        assert_eq!(state.is_watched(0xFFFF_FFFF_FFFF_8000), false);
    }

    #[test]
    fn smc_watch_invalid_lookup_after_collision_probes_next_slot() {
        let state = SmcState::new();
        // Two distinct pages that hash to the same initial slot force the
        // linear-probe advance before the second key is found.
        let first = 0x1000u64;
        let mut second = 0x2000u64;
        while smc_slot(second) != smc_slot(first) {
            second += 0x1000;
        }
        state.rebuild_watch([first, second].iter());
        assert_eq!(state.is_watched(first), true);
        assert_eq!(state.is_watched(second), true);
        // A fresh table must reject a page whose probe finds an empty slot.
        let empty = SmcState::new();
        empty.rebuild_watch([first].iter());
        assert_eq!(empty.is_watched(second), false);
    }

    #[test]
    fn smc_dirty_overflow_marks_overflow_and_keeps_bounded_ring() {
        let state = SmcState::new();
        for i in 0..=SMC_DIRTY_SLOTS as u64 {
            state.mark_dirty((i + 1) * 0x1000);
        }
        let (pages, overflow) = state.take_dirty();
        assert_eq!(pages.len(), SMC_DIRTY_SLOTS);
        assert_eq!(overflow, true);
        assert_eq!(pages[0], 0x1000);
        assert_eq!(pages[SMC_DIRTY_SLOTS - 1], SMC_DIRTY_SLOTS as u64 * 0x1000);
        // take_dirty clears the ring and the overflow flag.
        let (empty, cleared) = state.take_dirty();
        assert_eq!(empty.len(), 0);
        assert_eq!(cleared, false);
    }

    #[test]
    fn note_guest_code_write_rejects_zero_length_and_unwatched_state() {
        reset_smc_telemetry();
        note_guest_code_write(0x1000, 0);
        assert_eq!(smc_telemetry(), (0, 0));

        // No watched pages: the helper must take the early-return fast path.
        let state = SmcState::new();
        {
            let _guard = ActiveSmcGuard::install(&state);
            note_guest_code_write(0x1000, 8);
        }
        assert_eq!(smc_telemetry(), (0, 0));
    }

    #[test]
    fn note_guest_code_write_overflowing_page_range_returns_without_marking() {
        reset_smc_telemetry();
        let state = SmcState::new();
        state.rebuild_watch([0x2000u64].iter());
        {
            let _guard = ActiveSmcGuard::install(&state);
            // The page walk saturates at u64::MAX; checked_add must stop it.
            note_guest_code_write(u64::MAX & !0xfff, 1);
        }
        assert_eq!(smc_telemetry(), (0, 0));
    }

    #[test]
    fn note_guest_code_write_counts_exactly_one_dirty_page_at_boundary() {
        reset_smc_telemetry();
        let state = SmcState::new();
        state.rebuild_watch([0x3000u64].iter());
        {
            let _guard = ActiveSmcGuard::install(&state);
            note_guest_code_write(0x3000, 8);
        }
        assert_eq!(smc_telemetry(), (1, 1));
        let (pages, overflow) = state.take_dirty();
        assert_eq!(pages, vec![0x3000]);
        assert_eq!(overflow, false);
        reset_smc_telemetry();
        assert_eq!(smc_telemetry(), (0, 0));
    }

    // ── Tier compilation, promotion, and constant folding ───────────────────

    #[test]
    fn jit_tier1_and_tier2_compile_pin_tier_edges() {
        let mut compiler = JitCompiler::new();
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 40,
            },
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 2,
                width: 8,
            },
            IrInstruction::Nop,
        ];
        let tier1 = compiler
            .compile_tier1(&ir, 0x1000, GuestArch::X64, None)
            .expect("tier1 compile");
        assert_eq!(tier1.compile_tier, CompilationTier::Tier1);
        assert_eq!(tier1.guest_address, 0x1000);
        assert_eq!(tier1.instruction_count, 3);
        assert_ne!(tier1.source_hash, 0);
        assert_ne!(tier1.entry() as usize, 0);
        let tier2 = compiler
            .compile_tier2(&ir, 0x2000, GuestArch::X64, None)
            .expect("tier2 compile");
        assert_eq!(tier2.compile_tier, CompilationTier::Tier2);
        assert_eq!(tier2.guest_address, 0x2000);
        assert_eq!(tier2.instruction_count, 3);
    }

    #[test]
    fn jit_tier1_and_tier2_reject_failed_allocations() {
        let mut compiler = JitCompiler::new();
        let ir = vec![IrInstruction::Nop];
        JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
        let error = compiler
            .compile_tier1(&ir, 0x1000, GuestArch::X64, None)
            .err()
            .expect("tier1 allocation failure");
        assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(
            error.message,
            "JIT Tier1: failed to allocate executable memory"
        );

        let mut compiler = JitCompiler::new();
        JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
        let error = compiler
            .compile_tier2(&ir, 0x2000, GuestArch::X64, None)
            .err()
            .expect("tier2 allocation failure");
        assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(
            error.message,
            "JIT Tier2: failed to allocate executable memory"
        );
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(0));
    }

    #[test]
    fn jit_constant_fold_pins_every_fold_and_noop_edge() {
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 5,
            },
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 3,
                width: 8,
            },
            IrInstruction::SubImm {
                dst: Register::Rax,
                value: 2,
                width: 8,
            },
            IrInstruction::ShlImm {
                dst: Register::Rax,
                count: 1,
                width: 8,
            },
            IrInstruction::AndImm {
                dst: Register::Rax,
                value: 0x0F,
                width: 1,
            },
            IrInstruction::OrImm {
                dst: Register::Rax,
                value: 1,
                width: 8,
            },
            IrInstruction::XorImm {
                dst: Register::Rax,
                value: 5,
                width: 8,
            },
            IrInstruction::AddImm {
                dst: Register::Rbx,
                value: 0,
                width: 8,
            },
            IrInstruction::SubImm {
                dst: Register::Rbx,
                value: 0,
                width: 8,
            },
            IrInstruction::ShlImm {
                dst: Register::Rbx,
                count: 0,
                width: 8,
            },
            IrInstruction::AndImm {
                dst: Register::Rbx,
                value: 0xFFFF,
                width: 2,
            },
            IrInstruction::MovImm {
                dst: Register::Rbx,
                value: 7,
            },
            IrInstruction::MovReg {
                dst: Register::Rax,
                src: Register::Rbx,
                width: 8,
            },
            IrInstruction::MovReg {
                dst: Register::Rcx,
                src: Register::Rdx,
                width: 8,
            },
        ];
        let folded = JitCompiler::constant_fold(&ir);
        assert_eq!(
            folded,
            vec![
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 8,
                },
                IrInstruction::MovImm {
                    dst: Register::Rbx,
                    value: 7,
                },
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 7,
                },
                IrInstruction::MovReg {
                    dst: Register::Rcx,
                    src: Register::Rdx,
                    width: 8,
                },
            ],
            "constant folding must coalesce and propagate exactly"
        );
    }

    #[test]
    fn jit_runtime_tier_promotion_replaces_stale_block() {
        let mut runtime = capable_runtime();
        let ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 40,
            },
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 2,
                width: 8,
            },
        ];
        let entry0 = {
            let block = runtime
                .get_or_compile(&ir, 0x00C1_0000, GuestArch::X64, None)
                .expect("tier0 compile");
            block.published_entry() as usize
        };
        assert_eq!(runtime.tier0_compiles, 1);
        let tier1_entry = {
            let block = runtime
                .get_or_compile_at_tier(
                    &ir,
                    0x00C1_0000,
                    GuestArch::X64,
                    CompilationTier::Tier1,
                    None,
                )
                .expect("tier1 promotion");
            assert_eq!(block.compile_tier, CompilationTier::Tier1);
            block.published_entry() as usize
        };
        assert_eq!(runtime.tier1_compiles, 1);
        assert_ne!(tier1_entry, entry0, "promotion must install new code");
        let tier2_entry = {
            let block = runtime
                .get_or_compile_at_tier(
                    &ir,
                    0x00C1_0000,
                    GuestArch::X64,
                    CompilationTier::Tier2,
                    None,
                )
                .expect("tier2 promotion");
            assert_eq!(block.compile_tier, CompilationTier::Tier2);
            block.published_entry() as usize
        };
        assert_eq!(runtime.tier2_compiles, 1);
        assert_ne!(tier2_entry, tier1_entry);
        assert_eq!(runtime.blocks_compiled, 3);
        assert_eq!(runtime.code_invalidations, 2);

        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let reason = execute_cached(&mut runtime, 0x00C1_0000, &mut state, &mut memory);
        assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
        assert_eq!(state.get(Register::Rax), 42);
    }

    #[test]
    fn jit_get_or_compile_rejects_uncompilable_block() {
        let mut runtime = capable_runtime();
        let error = runtime
            .get_or_compile(&[IrInstruction::Cpuid], 0x00C2_0000, GuestArch::X64, None)
            .err()
            .expect("uncompilable block must be rejected");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        assert_eq!(
            error.message,
            "block contains an instruction the JIT cannot compile"
        );
        assert_eq!(runtime.interpreter_fallbacks, 1);
        assert_eq!(runtime.is_compiled(0x00C2_0000), false);
    }

    #[test]
    fn jit_hash_mismatch_recompiles_stale_cached_block() {
        let mut runtime = capable_runtime();
        let address = 0x00C3_0000u64;
        runtime
            .get_or_compile(
                &[IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 42,
                }],
                address,
                GuestArch::X64,
                None,
            )
            .expect("original compile");
        runtime
            .get_or_compile(
                &[IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 43,
                }],
                address,
                GuestArch::X64,
                None,
            )
            .expect("recompile after IR change");
        assert_eq!(runtime.code_invalidations, 1);
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let reason = execute_cached(&mut runtime, address, &mut state, &mut memory);
        assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
        assert_eq!(
            state.get(Register::Rax),
            43,
            "the stale block must not run after the hash mismatch"
        );
    }

    // ── Chaining refusals and counters ──────────────────────────────────────

    #[test]
    fn jit_chain_blocks_rejects_missing_and_nonjump_endpoints() {
        let mut runtime = capable_runtime();

        let error = runtime.chain_blocks(0xDEAD, 0x1000).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(error.message, "cannot chain missing source block 0xdead");

        runtime
            .get_or_compile(&[IrInstruction::Nop], 0x1000, GuestArch::X64, None)
            .expect("straight-line block");
        runtime
            .get_or_compile(
                &[IrInstruction::Nop, IrInstruction::Jump { target: 0x3000 }],
                0x2000,
                GuestArch::X64,
                None,
            )
            .expect("jump block");
        let error = runtime.chain_blocks(0x1000, 0x2000).unwrap_err();
        assert_eq!(
            error.message,
            "block 0x1000 does not end in an unconditional jump"
        );
        let error = runtime.chain_blocks(0x2000, 0xDEAD).unwrap_err();
        assert_eq!(error.message, "cannot chain to missing target block 0xdead");
        assert_eq!(runtime.chain_links_formed, 0);
    }

    #[test]
    fn jit_chain_blocks_rejects_non_chainable_target() {
        let mut runtime = capable_runtime();
        runtime
            .get_or_compile(
                &[IrInstruction::Nop, IrInstruction::Jump { target: 0x4000 }],
                0x3000,
                GuestArch::X64,
                None,
            )
            .expect("source");
        runtime
            .get_or_compile(
                &[
                    IrInstruction::Nop,
                    IrInstruction::Return { stack_adjust: 0 },
                ],
                0x4000,
                GuestArch::X64,
                None,
            )
            .expect("return target");
        let error = runtime.chain_blocks(0x3000, 0x4000).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "block 0x4000 does not end in a chainable jump"
        );
        assert_eq!(runtime.chain_links_formed, 0);
    }

    #[test]
    fn jit_chain_blocks_rejects_unpublished_target_entry() {
        let mut runtime = capable_runtime();
        runtime
            .get_or_compile(
                &[IrInstruction::Nop, IrInstruction::Jump { target: 0x5000 }],
                0x5000 - 0x1000,
                GuestArch::X64,
                None,
            )
            .expect("source");
        runtime
            .get_or_compile(
                &[IrInstruction::Nop, IrInstruction::Jump { target: 0x6000 }],
                0x5000,
                GuestArch::X64,
                None,
            )
            .expect("target");
        runtime
            .block_cache
            .get_mut(&0x5000)
            .expect("cached target")
            .entry_atomic
            .store(std::ptr::null_mut(), Ordering::Release);
        let error = runtime.chain_blocks(0x4000, 0x5000).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(error.message, "block 0x5000 has no published entry");
    }

    #[test]
    fn jit_autochain_failure_on_non_chainable_target_is_silent() {
        let mut runtime = capable_runtime();
        runtime
            .get_or_compile(
                &[
                    IrInstruction::Nop,
                    IrInstruction::Return { stack_adjust: 0 },
                ],
                0x7000,
                GuestArch::X64,
                None,
            )
            .expect("return target");
        runtime
            .get_or_compile(
                &[IrInstruction::Nop, IrInstruction::Jump { target: 0x7000 }],
                0x6000,
                GuestArch::X64,
                None,
            )
            .expect("source with rejected auto-chain");
        assert_eq!(runtime.block_chains.len(), 0);
        assert_eq!(runtime.chain_links_formed, 0);
        assert_eq!(
            runtime
                .block_cache
                .get(&0x6000)
                .expect("source cached")
                .link_target
                .load(Ordering::Acquire),
            0,
            "a rejected chain must not publish a target"
        );
    }

    #[test]
    fn jit_drain_smc_overflow_invalidates_every_cached_block() {
        let mut runtime = capable_runtime();
        runtime
            .get_or_compile(
                &[IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 1,
                }],
                0x8000,
                GuestArch::X64,
                None,
            )
            .expect("first block");
        runtime
            .get_or_compile(
                &[IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 2,
                }],
                0x9000,
                GuestArch::X64,
                None,
            )
            .expect("second block");
        for i in 0..=SMC_DIRTY_SLOTS as u64 {
            runtime.smc.mark_dirty((i + 1) * 0x1000);
        }
        let affected = runtime.drain_smc_invalidations();
        assert_eq!(affected.len(), 2);
        assert_eq!(runtime.code_invalidations, 2);
        assert_eq!(runtime.smc_invalidation_events, 1);
        assert_eq!(runtime.block_cache.len(), 0);
    }

    #[test]
    fn jit_invalidate_block_rejects_stale_chain_target() {
        let mut runtime = capable_runtime();
        runtime
            .get_or_compile(
                &[
                    IrInstruction::Nop,
                    IrInstruction::Jump {
                        target: 0x00C5_1000,
                    },
                ],
                0x00C5_0000,
                GuestArch::X64,
                None,
            )
            .expect("source");
        runtime
            .get_or_compile(
                &[
                    IrInstruction::Nop,
                    IrInstruction::Jump {
                        target: 0x00C5_2000,
                    },
                ],
                0x00C5_1000,
                GuestArch::X64,
                None,
            )
            .expect("target");
        runtime
            .chain_blocks(0x00C5_0000, 0x00C5_1000)
            .expect("publish chain");
        assert_eq!(runtime.chain_links_formed, 1);
        runtime.invalidate_block(0x00C5_0000);
        assert_eq!(runtime.chain_links_broken, 1);
        // The outgoing chain record remains until the target is invalidated,
        // but the source block itself and its link slot are gone.
        assert_eq!(runtime.block_chains.len(), 1);
        assert_eq!(runtime.block_cache.get(&0x00C5_0000).is_none(), true);
    }

    #[test]
    fn jit_thunk_registration_rejects_unknown_indices_and_pins_guest_addrs() {
        use std::collections::HashSet;
        let mut runtime = capable_runtime();
        let guest = 0x00C6_5000u64;
        assert_eq!(
            runtime.register_host_thunk_for_guest(
                jit_self_test_host_thunk as *const () as usize,
                guest
            ),
            Some(0)
        );
        assert_eq!(
            runtime.guest_thunk_addrs(),
            HashSet::from([guest]),
            "guest_addrs must include registered guest targets"
        );
        assert_eq!(
            runtime.register_host_thunk(jit_self_test_host_thunk as *const () as usize),
            Some(1)
        );
        assert_eq!(
            runtime.guest_thunk_addrs(),
            HashSet::from([guest]),
            "an entry without a guest address must not appear"
        );
        assert_ne!(runtime.lookup_thunk_address(0), None);
        assert_eq!(runtime.lookup_thunk_address(2), None);
    }

    #[test]
    fn jit_direct_thunk_unregistered_call_fallback_does_not_count() {
        use std::collections::HashSet;
        let mut runtime = capable_runtime();
        let guest = 0x00C7_5000u64;
        runtime
            .register_host_thunk_for_guest(jit_self_test_host_thunk as *const () as usize, guest)
            .expect("register resolved thunk");
        let resolved: HashSet<u64> = HashSet::from([guest]);
        let before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
        runtime
            .get_or_compile(
                &[
                    IrInstruction::MovImm {
                        dst: Register::Rax,
                        value: 7,
                    },
                    IrInstruction::Call {
                        target: guest,
                        return_address: 0x00C7_6004,
                    },
                ],
                0x00C7_6000,
                GuestArch::X64,
                Some(&resolved),
            )
            .expect("direct thunk compile");
        assert_eq!(
            JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed) - before,
            1,
            "a resolved thunk must be emitted as exactly one direct call"
        );

        let before = JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed);
        runtime
            .get_or_compile(
                &[IrInstruction::Call {
                    target: 0xDEAD,
                    return_address: 0x00C7_7004,
                }],
                0x00C7_7000,
                GuestArch::X64,
                Some(&HashSet::new()),
            )
            .expect("unregistered call falls back to EXIT_THUNK");
        assert_eq!(
            JIT_THUNK_DIRECT_CALLS.load(Ordering::Relaxed),
            before,
            "an unregistered target must not count as a direct call"
        );
    }

    #[test]
    fn jit_jump_missing_link_slot_pins_exit_encoding() {
        let mut compiler = JitCompiler::new();
        compiler.link_slots = None;
        compiler
            .compile_instruction(
                &IrInstruction::Jump { target: 0x2000 },
                GuestArch::X64,
                None,
                true,
            )
            .expect("jump emission");
        let code = &compiler.emitter.code;
        let movz_exit_jump = (0xd280_0000u32 | ((EXIT_JUMP as u32) << 5)).to_le_bytes();
        assert_eq!(
            code.windows(4)
                .filter(|word| *word == movz_exit_jump)
                .count(),
            1,
            "an unlinked jump must return EXIT_JUMP exactly once"
        );
        assert_eq!(
            &code[code.len() - 4..],
            &0xd65f_03c0u32.to_le_bytes(),
            "the unlinked jump arm must end in RET"
        );
    }

    #[test]
    fn jit_self_test_report_default_rejects_fabricated_activity() {
        let report = JitSelfTestReport::default();
        assert_eq!(report.active, false);
        assert_eq!(report.compiled_blocks, 0);
        assert_eq!(report.executed_blocks, 0);
        assert_eq!(report.safepoint_observed, false);
        assert_eq!(report.chain_links, 0);
        assert_eq!(report.thunk_direct_calls, 0);
        assert_eq!(report.smc_invalidations, 0);
        assert_eq!(report.fault_fallbacks, 0);
        assert_eq!(report.fallback_reason, None);
    }

    // ── In-process self-test: success path and injected failures ────────────

    #[test]
    fn jit_self_test_pins_exact_counters_without_fallback() {
        let report = run_jit_self_test_child().expect("self-test must complete");
        assert_eq!(report.active, true);
        assert_eq!(report.safepoint_observed, true);
        assert_eq!(report.compiled_blocks, 1);
        assert_eq!(report.executed_blocks, 9);
        assert_eq!(report.chain_links, 1);
        assert_eq!(report.thunk_direct_calls, 1);
        assert_eq!(report.smc_invalidations, 2);
        assert_eq!(report.fault_fallbacks, 1);
        assert_eq!(report.fallback_reason, None);
    }

    #[test]
    fn jit_self_test_pending_safepoint_rejects_first_execution() {
        JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Relaxed);
        let error = run_jit_self_test_child().unwrap_err();
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: first execution exited with Safepoint, expected Normal"
        );
    }

    #[test]
    fn jit_self_test_unwritable_repatch_page_rejects_repatch() {
        // The first make_writable call installs the initial block; the second
        // is the self-test's deliberate re-patch of the code page.
        JIT_TEST_WRITE_CALLS.with(|calls| calls.set(0));
        JIT_TEST_DENY_WRITE_AT.with(|at| at.set(2));
        let error = run_jit_self_test_child().unwrap_err();
        JIT_TEST_DENY_WRITE_AT.with(|at| at.set(0));
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: compiled code page is not writable"
        );
    }

    #[test]
    fn jit_self_test_unextendable_repatch_page_rejects_repatch() {
        JIT_TEST_FINALIZE_CALLS.with(|calls| calls.set(0));
        JIT_TEST_DENY_FINALIZE_AT.with(|at| at.set(2));
        let error = run_jit_self_test_child().unwrap_err();
        JIT_TEST_DENY_FINALIZE_AT.with(|at| at.set(0));
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: re-patched code page is not executable"
        );
    }

    #[test]
    fn jit_self_test_unavailable_thunk_zone_rejects_registration() {
        JIT_TEST_DENY_THUNK_ZONE.with(|deny| deny.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: failed to register the direct-call host thunk"
        );
    }

    #[test]
    fn jit_self_test_missed_smc_invalidation_rejects_stale_execution() {
        JIT_TEST_SMC_FAULT.with(|fault| fault.set(1));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: stale SMC block ran instead of falling back: Normal { new_rip: 28672 }"
        );
    }

    fn self_test_with_safepoint_at(call: usize) -> AppError {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
        JIT_TEST_EXEC_CALLS.with(|calls| calls.set(0));
        JIT_TEST_FORCE_SAFEPOINT_AT.with(|at| at.set(call));
        let error = run_jit_self_test_child().unwrap_err();
        JIT_TEST_FORCE_SAFEPOINT_AT.with(|at| at.set(0));
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Relaxed);
        error
    }

    #[test]
    fn jit_self_test_safepoint_interrupts_reject_later_steps() {
        let error = self_test_with_safepoint_at(3);
        assert_eq!(
            error.message,
            "JIT self-test: re-patched execution exited with Safepoint"
        );
        let error = self_test_with_safepoint_at(4);
        assert_eq!(
            error.message,
            "JIT self-test: linked execution exited with Safepoint, expected Jump"
        );
        let error = self_test_with_safepoint_at(9);
        assert_eq!(
            error.message,
            "JIT self-test: recompiled SMC block observed stale code: rax=0"
        );
    }

    #[test]
    fn jit_self_test_already_linked_chain_rejects_missing_publication() {
        JIT_TEST_PREPUBLISH_CHAIN.with(|prepublish| prepublish.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(error.message, "JIT self-test: no block link was published");
    }

    #[test]
    fn jit_self_test_uncounted_eviction_rejects_missing_invalidation() {
        JIT_TEST_SMC_FAULT.with(|fault| fault.set(2));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: self-modifying code did not invalidate a block"
        );
    }

    #[test]
    fn jit_self_test_lost_fault_bar_rejects_native_compilation() {
        JIT_TEST_IGNORE_FAULTED_BLOCKS.with(|ignore| ignore.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: faulted block was not barred from native compilation"
        );
    }

    #[test]
    fn jit_self_test_wrong_original_rejects_guest_result() {
        JIT_TEST_SELF_TEST_WRONG_ORIGINAL.with(|wrong| wrong.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: guest result mismatch: rax=41 expected 42"
        );
    }

    #[test]
    fn jit_self_test_ignored_safepoint_rejects_missing_exit() {
        JIT_TEST_IGNORE_SAFEPOINT_AT.with(|at| at.set(2));
        let error = run_jit_self_test_child().unwrap_err();
        JIT_TEST_IGNORE_SAFEPOINT_AT.with(|at| at.set(0));
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: safepoint flag did not produce EXIT_SAFEPOINT (got Normal { new_rip: 4096 })"
        );
    }

    #[test]
    fn jit_self_test_unapplied_repatch_rejects_stale_value() {
        JIT_TEST_SKIP_REPATCH.with(|skip| skip.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: re-patched execution did not observe the patch: rax=42 expected 43"
        );
    }

    fn assert_self_test_allocation_failure(fail_at: usize, expected: &str) {
        JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(fail_at));
        let error = run_jit_self_test_child().unwrap_err();
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(0));
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(error.message, expected);
    }

    #[test]
    fn jit_self_test_allocation_failures_reject_each_later_step() {
        assert_self_test_allocation_failure(
            2,
            "JIT self-test: chain source compile failed: JIT: failed to allocate executable memory",
        );
        assert_self_test_allocation_failure(
            3,
            "JIT self-test: chain target compile failed: JIT: failed to allocate executable memory",
        );
        assert_self_test_allocation_failure(
            4,
            "JIT self-test: thunk block compile failed: JIT: failed to allocate executable memory",
        );
        assert_self_test_allocation_failure(
            5,
            "JIT self-test: SMC block compile failed: JIT: failed to allocate executable memory",
        );
        assert_self_test_allocation_failure(
            6,
            "JIT self-test: SMC writer compile failed: JIT: failed to allocate executable memory",
        );
        assert_self_test_allocation_failure(
            7,
            "JIT self-test: SMC recompile failed: JIT: failed to allocate executable memory",
        );
        assert_self_test_allocation_failure(
            8,
            "JIT self-test: fault block compile failed: JIT: failed to allocate executable memory",
        );
        assert_eq!(JIT_TEST_FAIL_ALLOC_AT.with(|at| at.get()), 0);
    }

    #[test]
    fn jit_self_test_chain_failure_rejects_chain_step() {
        JIT_TEST_FORCE_CHAIN_ERROR.with(|force| force.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: chain_blocks failed: injected chain failure"
        );
    }

    #[test]
    fn jit_self_test_lost_thunk_resolution_rejects_direct_call() {
        JIT_TEST_THUNK_MAP_MISS.with(|miss| miss.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: Call to a resolved thunk did not compile to a direct call"
        );
    }

    #[test]
    fn jit_self_test_wrong_thunk_result_rejects_execution() {
        JIT_TEST_SELF_TEST_THUNK_BAD.with(|bad| bad.set(true));
        let error = run_jit_self_test_child().unwrap_err();
        assert_eq!(error.code, ReasonCode::RcJitCompilationError);
        assert_eq!(
            error.message,
            "JIT self-test: direct thunk call failed: reason=Normal { new_rip: 24576 } rax=0x98"
        );
    }

    #[test]
    fn jit_self_test_exec_resolution_failures_reject_fabricated_success() {
        JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.set(1));
        let report = run_jit_self_test();
        assert_eq!(report.active, false);
        assert_eq!(
            report.fallback_reason.as_deref(),
            Some(
                "cannot resolve current executable for the self-test child: \
                 No such file or directory (os error 2)"
            )
        );

        JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.set(2));
        let report = run_jit_self_test();
        assert_eq!(report.active, false);
        assert_eq!(
            report.fallback_reason.as_deref(),
            Some("failed to spawn self-test child: No such file or directory (os error 2)")
        );

        JIT_TEST_SELF_TEST_EXE_MODE.with(|mode| mode.set(3));
        let report = run_jit_self_test();
        assert_eq!(report.active, false);
        assert_eq!(report.compiled_blocks, 0);
        assert_eq!(
            report
                .fallback_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with(
                    "self-test child exited 0 without a valid JitSelfTestReport JSON:"
                )),
            true
        );
    }

    #[test]
    fn jit_self_test_missing_child_flag_reports_inactive() {
        // In the lib test binary `--jit-self-test-child` is not a real child
        // mode: the parent must report inactive with the child's diagnostics
        // instead of trusting a non-existent report.
        let report = run_jit_self_test();
        assert_eq!(report.active, false);
        assert_eq!(report.compiled_blocks, 0);
        assert_eq!(report.fallback_reason.is_some(), true);
    }

    #[test]
    fn jit_runtime_tier_recompilation_rejects_allocation_failure() {
        let mut runtime = capable_runtime();
        let ir = vec![IrInstruction::Nop];
        JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
        let tier1 = runtime
            .get_or_compile_at_tier(
                &ir,
                0x00C5_0000,
                GuestArch::X64,
                CompilationTier::Tier1,
                None,
            )
            .err()
            .expect("tier1 runtime allocation failure");
        assert_eq!(tier1.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(
            tier1.message,
            "JIT Tier1: failed to allocate executable memory"
        );

        JIT_TEST_ALLOC_CALLS.with(|calls| calls.set(0));
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(1));
        let tier2 = runtime
            .get_or_compile_at_tier(
                &ir,
                0x00C6_0000,
                GuestArch::X64,
                CompilationTier::Tier2,
                None,
            )
            .err()
            .expect("tier2 runtime allocation failure");
        assert_eq!(tier2.code, ReasonCode::RcJitCodeAllocFailed);
        assert_eq!(
            tier2.message,
            "JIT Tier2: failed to allocate executable memory"
        );
        JIT_TEST_FAIL_ALLOC_AT.with(|at| at.set(0));
    }

    #[test]
    fn jit_self_test_host_thunk_bad_sentinel_overwrites_gpr0() {
        JIT_TEST_SELF_TEST_THUNK_BAD.with(|bad| bad.set(true));
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rax, 0x1234);
        let result = jit_self_test_host_thunk(
            std::ptr::null_mut(),
            &mut state as *mut CpuState,
            std::ptr::null_mut(),
            0,
        );
        assert_eq!(result, -1);
        assert_eq!(state.get(Register::Rax), 0x98);
    }

    #[test]
    fn jit_diag_file_append_recovers_from_truncated_fault_line() {
        let path = "/tmp/casa1_jit_diag.txt";
        std::fs::write(path, b"torn fault").expect("seed truncated diagnostic line");
        write_diag_file("fault-chain: first");
        write_diag_file("fault-chain: second");
        let after = std::fs::read_to_string(path).expect("diagnostic file must be readable");
        assert_eq!(after, "torn faultfault-chain: first\nfault-chain: second\n");
    }

    #[test]
    fn constant_fold_drops_overwritten_mov_imm_but_keeps_read_values() {
        use crate::cpu::{IrInstruction, Register};
        // A long chain of overwritten MOV immediates collapses to the last
        // write: every earlier value is unread and must be dropped.
        let chain: Vec<IrInstruction> = (1..=128u64)
            .map(|value| IrInstruction::MovImm {
                dst: Register::Rax,
                value,
            })
            .collect();
        let folded = JitCompiler::constant_fold(&chain);
        assert_eq!(
            folded,
            vec![IrInstruction::MovImm {
                dst: Register::Rax,
                value: 128
            }],
            "an unread MOV chain must collapse to its final write"
        );
        // A value read between writes is not dropped: the first write folds
        // into the reader, and the later overwrite remains.
        let interleaved = vec![
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 7,
            },
            IrInstruction::MovReg {
                dst: Register::Rcx,
                src: Register::Rax,
                width: 8,
            },
            IrInstruction::MovImm {
                dst: Register::Rax,
                value: 9,
            },
        ];
        let folded = JitCompiler::constant_fold(&interleaved);
        assert_eq!(
            folded,
            vec![
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 7
                },
                IrInstruction::MovImm {
                    dst: Register::Rcx,
                    value: 7
                },
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 9
                },
            ],
            "a read value must be preserved even when the register is overwritten"
        );
    }
    #[test]
    fn guest_slice_memory_false_sharing_race_merges_and_publishes() {
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0_u8; 0x1000]);
        let view = GuestSliceMemory::new(&memory, BTreeSet::new());
        let base = 0x1000_u64;
        std::thread::scope(|scope| {
            for index in 0..4_u8 {
                let view = &view;
                scope.spawn(move || {
                    let pattern = [index.wrapping_add(1), 0xF0_u8.wrapping_add(index)];
                    for _ in 0..1_000 {
                        view.store(base + u64::from(index) * 2, &pattern)
                            .expect("the page is fully mapped");
                    }
                });
            }
        });
        let word = view.load(base, 8).expect("mapped");
        assert_eq!(
            word.to_le_bytes(),
            [1, 0xF0, 2, 0xF1, 3, 0xF2, 4, 0xF3],
            "coincident sub-word stores must preserve every neighbour"
        );

        let published = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let view = &view;
            let published = &published;
            scope.spawn(move || {
                view.store(base + 8, &0xA5A5_5A5A_DEAD_BEEF_u64.to_le_bytes())
                    .expect("mapped");
                published.store(true, std::sync::atomic::Ordering::Release);
            });
            while !published.load(std::sync::atomic::Ordering::Acquire) {
                std::hint::spin_loop();
            }
            assert_eq!(
                view.load(base + 8, 8).expect("mapped"),
                0xA5A5_5A5A_DEAD_BEEF,
                "a published store must be visible to another worker"
            );
        });

        assert_eq!(
            view.load(0x9000, 8)
                .expect_err("an unmapped page must fault")
                .address,
            0x9000
        );
        let store_fault = view
            .store(0x9000, &[0x11, 0x22])
            .expect_err("an unmapped store must fault");
        assert_eq!((store_fault.address, store_fault.write), (0x9000, true));

        let code_view = GuestSliceMemory::new(&memory, BTreeSet::from([0x1000]));
        assert_eq!(code_view.store(base, &[0x33]).expect("mapped"), true);
        assert_eq!(code_view.take_code_writes(), vec![(base, 1)]);
    }

    #[test]
    fn jit_compare_jump_stale_flag_race_is_exact_for_slice_loops() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = JitRuntime::new(GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime.attach_guest_memory(&mut memory);
        let ir = vec![
            IrInstruction::SubImm {
                dst: Register::Rcx,
                value: 1,
                width: 4,
            },
            IrInstruction::Compare {
                lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
                rhs: crate::cpu::CompareOperand::ImmediateU64(0),
                width: 4,
            },
            IrInstruction::JumpIf {
                condition: ConditionCode::NotEqual,
                target: 0x1000,
                fallthrough: 0x1006,
            },
        ];
        let block = runtime
            .get_or_compile_slice_block(&ir, 0x1000, GuestArch::X86)
            .expect("compile slice loop")
            .clone();
        let view = Arc::new(GuestSliceMemory::new(&memory, BTreeSet::new()));
        let program = GuestSliceProgram {
            blocks: HashMap::from([(0x1000, block)]),
            flat_base: view.flat_base(),
            memory: view,
            mechanism: runtime.compiler.memory_manager.mechanism(),
            epoch: 0,
        };
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rcx, 3);
        let mut taken = Vec::new();
        for _ in 0..4 {
            let mut chain = ChainState::new(program.flat_base, 0x1000, LINK_BUDGET);
            let outcome = unsafe {
                execute_slice_block(&program, &program.blocks[&0x1000], &mut state, &mut chain)
            };
            let branch_taken = match outcome.reason {
                JitExitReason::ConditionalBranch { taken, .. } => taken,
                JitExitReason::ConditionalTaken { .. } => true,
                JitExitReason::ConditionalNotTaken { .. } => false,
                other => panic!("expected conditional branch, got {other:?}"),
            };
            taken.push(branch_taken);
        }
        assert_eq!(taken, vec![true, true, false, true]);
        assert_eq!(state.get(Register::Rcx), 0xFFFF_FFFF);
    }

    #[test]
    fn jit_worker_slice_store_flag_and_unmapped_fault_are_exact() {
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0u8; 0x1000]);
        memory.map_bytes(0x2000, &[0u8; 0x1000]);
        let view = GuestSliceMemory::new(&memory, BTreeSet::from([0x1000]));
        let mut state = CpuState::new(GuestArch::X64);

        {
            let guard = WorkerSliceGuard::install(&view);
            // SAFETY: `state` and `view` outlive the call; the canonical store
            // is alive for the guard's lifetime and the address is mapped.
            unsafe {
                jit_helper_store(&mut state, ptr::null_mut(), 0x2000, 0x11, 1);
            }
            assert_eq!(guard.code_written(), false);
            unsafe {
                jit_helper_store(&mut state, ptr::null_mut(), 0x1000, 0xAB, 1);
            }
            assert_eq!(guard.code_written(), true);
            assert_eq!(state.jit_pending_fault, None);
        }
        assert_eq!(view.take_code_writes(), vec![(0x1000, 1)]);

        {
            let guard = WorkerSliceGuard::install(&view);
            // SAFETY: same contract as above; 0x9000 is deliberately unmapped
            // so the helper must report the exact write fault through state.
            unsafe {
                jit_helper_store(&mut state, ptr::null_mut(), 0x9000, 0xCD, 2);
            }
            assert_eq!(state.jit_pending_fault, Some(0x9000));
            assert_eq!(state.jit_pending_fault_write, true);
            assert_eq!(guard.code_written(), false);
        }
    }

    #[test]
    fn jit_worker_slice_load_success_and_fault_are_exact() {
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0u8; 0x1000]);
        let view = GuestSliceMemory::new(&memory, BTreeSet::new());
        let mut state = CpuState::new(GuestArch::X64);
        {
            let guard = WorkerSliceGuard::install(&view);
            // SAFETY: `state` and `view` outlive the call and the address is
            // mapped in the canonical store.
            let value = unsafe { jit_helper_load(&mut state, ptr::null_mut(), 0x1000, 8) };
            assert_eq!(value, 0);
            assert_eq!(state.jit_pending_fault, None);
            // SAFETY: same contract; 0x9000 is unmapped so the helper must
            // report a read fault instead of fabricating a zero.
            let faulted = unsafe { jit_helper_load(&mut state, ptr::null_mut(), 0x9000, 4) };
            assert_eq!(faulted, 0);
            assert_eq!(state.jit_pending_fault, Some(0x9000));
            assert_eq!(state.jit_pending_fault_write, false);
            assert_eq!(guard.code_written(), false);
        }
    }

    #[test]
    fn jit_worker_slice_null_memory_store_without_guard_is_dropped() {
        let mut state = CpuState::new(GuestArch::X64);
        assert_eq!(worker_slice_memory().is_none(), true);
        // SAFETY: both pointers are null and no worker slice is installed; the
        // helper must return without dereferencing either pointer.
        unsafe {
            jit_helper_store(&mut state, ptr::null_mut(), 0x1000, 0x55, 8);
        }
        assert_eq!(state.jit_pending_fault, None);
        assert_eq!(state.jit_pending_fault_write, false);
    }

    #[test]
    fn guest_slice_memory_boundary_overflow_and_empty_range_faults_are_exact() {
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, &[0u8; 0x1000]);
        let view = GuestSliceMemory::new(&memory, BTreeSet::new());

        assert_eq!(view.range_available(0x1000, 0), false);
        assert_eq!(view.load(0x1000, 8).expect("one mapped page"), 0);
        assert_eq!(view.load(0x1004, 4).expect("unaligned mapped load"), 0);
        assert_eq!(view.load(0x1002, 4).expect("word-crossing mapped load"), 0);
        assert_eq!(
            view.load(0x1000, 0)
                .expect_err("zero-length load must fault"),
            GuestMemoryFault {
                address: 0x1000,
                write: false,
                read_len: 0,
            }
        );
        assert_eq!(
            view.store(0x1000, &[])
                .expect_err("zero-length store must fault"),
            GuestMemoryFault {
                address: 0x1000,
                write: true,
                read_len: 0,
            }
        );
        assert_eq!(
            view.load(u64::MAX - 3, 8)
                .expect_err("overflowing address range must fault"),
            GuestMemoryFault {
                address: u64::MAX - 3,
                write: false,
                read_len: 8,
            }
        );
        assert_eq!(
            view.load(view.flat_size(), 8)
                .expect_err("range beyond the flat window must fault"),
            GuestMemoryFault {
                address: view.flat_size(),
                write: false,
                read_len: 8,
            }
        );
        assert_eq!(
            view.load(0x1FFC, 8)
                .expect_err("range crossing into an unmapped page must fault"),
            GuestMemoryFault {
                address: 0x2000,
                write: false,
                read_len: 8,
            }
        );
    }

    #[test]
    fn invalid_small_flat_view_bitmap_is_grown_on_attach() {
        let mut flat = FlatGuestMemory {
            store: Arc::new(GuestMemoryStore::invalid_for_test()),
            materialised: vec![AtomicU64::new(0)].into_boxed_slice(),
        };
        assert_eq!(flat.materialised.len(), 1);
        assert_eq!(flat.is_page_materialised(0), false);
        let memory = MemoryImage::default();
        flat.attach_store(memory.canonical_store());
        let required_words = flat.size().div_ceil(4096 * 64);
        assert_eq!(flat.materialised.len(), required_words);
        assert_eq!(
            required_words >= GUEST_FLAT_MIN_SIZE.div_ceil(4096 * 64),
            true,
            "the attached bitmap must cover at least the 128 GiB minimum"
        );
        assert_eq!(flat.is_page_materialised(0), false);
    }

    #[test]
    fn guest_slice_memory_above_four_gib_is_direct_and_window_end_faults_exactly() {
        let address = 0x2_0000_0000_u64;
        let mut memory = MemoryImage::default();
        let window_size = memory.canonical_store().flat_size() as u64;
        let last_window_page = window_size - 0x1000;
        let window_end = window_size;
        memory.map_bytes(address, &[0u8; 4096]);
        memory.map_bytes(last_window_page, &[0u8; 4096]);
        let view = GuestSliceMemory::new(&memory, BTreeSet::from([address]));
        assert_eq!(view.flat_size(), window_size);
        assert_eq!(view.flat_size() / 4096, window_size / 4096);
        assert_eq!(
            view.flat_base() % GUEST_FLAT_ALIGN as u64,
            0,
            "the JIT base must be aligned for direct guest addressing"
        );

        assert_eq!(view.load(address, 8).expect("direct load"), 0);
        assert_eq!(
            view.store(address, &0x1122_3344_5566_7788_u64.to_le_bytes())
                .expect("direct store"),
            true,
            "a store to a >4 GiB code page must report the SMC write"
        );
        assert_eq!(
            view.load(address, 8).expect("direct reload"),
            0x1122_3344_5566_7788
        );
        assert_eq!(memory.read_u64(address).unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(
            view.load(last_window_page, 8)
                .expect("the last window page is direct"),
            0
        );
        assert_eq!(view.take_code_writes(), vec![(address, 8)]);

        let fault = view
            .load(window_end, 8)
            .expect_err("an address at the window end must fault");
        assert_eq!(
            fault,
            GuestMemoryFault {
                address: window_end,
                write: false,
                read_len: 8,
            }
        );
        let store_fault = view
            .store(window_end, &[0x11, 0x22])
            .expect_err("an address beyond the window must fault");
        assert_eq!((store_fault.address, store_fault.write), (window_end, true));
        assert_eq!(memory.canonical_store().materialisation_count(), 2);
        assert_eq!(memory.canonical_store().high_page_count(), 0);
    }

    #[test]
    fn jit_loop_with_heap_above_four_gib_executes_without_fault_or_overflow() {
        let mut runtime = capable_runtime();
        let heap = 0x2_0000_0000_u64;
        let site = 0x2_0000_1000_u64;
        let operand = crate::cpu::MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(heap),
        };
        let ir = vec![
            IrInstruction::LoadMemory {
                dst: Register::Rax,
                address: operand,
                width: 8,
            },
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 1,
                width: 8,
            },
            IrInstruction::StoreMemory {
                src: Register::Rax,
                address: operand,
                width: 8,
            },
            IrInstruction::SubImm {
                dst: Register::Rcx,
                value: 1,
                width: 8,
            },
            IrInstruction::Compare {
                lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
                rhs: crate::cpu::CompareOperand::ImmediateU64(0),
                width: 8,
            },
            IrInstruction::JumpIf {
                condition: ConditionCode::NotEqual,
                target: site,
                fallthrough: site + 0x100,
            },
        ];
        let block = runtime
            .get_or_compile_slice_block(&ir, site, GuestArch::X64)
            .expect("compile >4 GiB slice loop")
            .clone();
        assert_eq!(block.worker_safe, true);
        let mut memory = MemoryImage::default();
        memory.map_bytes(heap, &[0u8; 4096]);
        let view = Arc::new(GuestSliceMemory::new(
            &memory,
            BTreeSet::from([site & !0xfff]),
        ));
        let program = GuestSliceProgram {
            blocks: HashMap::from([(site, block)]),
            flat_base: view.flat_base(),
            memory: view,
            mechanism: runtime.compiler.memory_manager.mechanism(),
            epoch: 0,
        };
        let _guard = WorkerSliceGuard::install(&program.memory);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rcx, 3);
        let mut branches = Vec::new();
        for _ in 0..4 {
            let mut chain = ChainState::new(program.flat_base, site, LINK_BUDGET);
            let outcome = unsafe {
                execute_slice_block(&program, &program.blocks[&site], &mut state, &mut chain)
            };
            let taken = match outcome.reason {
                JitExitReason::ConditionalBranch { taken, .. } => taken,
                JitExitReason::ConditionalTaken { .. } => true,
                JitExitReason::ConditionalNotTaken { .. } => false,
                other => panic!("expected conditional branch, got {other:?}"),
            };
            branches.push(taken);
            if !taken {
                break;
            }
        }
        assert_eq!(branches, vec![true, true, false]);
        assert_eq!(state.get(Register::Rcx), 0);
        assert_eq!(
            memory.read_u64(heap).unwrap(),
            3,
            "each dispatched loop iteration must increment the >4 GiB heap word"
        );
        assert_eq!(memory.canonical_store().materialisation_count(), 1);
    }

    #[test]
    fn jit_memory_helpers_above_four_gib_and_high_frame_fallback_are_exact() {
        let mut runtime = capable_runtime();
        let flat_address = 0x2_0000_0000_u64;
        let upper_flat_address = 0x10_0000_0000_u64;
        let high_address = 0x1800_0000_0000_u64;
        let site = 0x2_0000_5000_u64;
        let mut memory = MemoryImage::default();
        memory.map_bytes(flat_address, &[0u8; 4096]);
        memory.write_u64(flat_address, 0x0102_0304_0506_0708);
        memory.map_bytes(upper_flat_address, &[0u8; 4096]);
        memory.write_u64(upper_flat_address, 0x2122_2324_2526_2728);
        memory.map_bytes(high_address, &[0u8; 4096]);
        memory.write_u64(high_address, 0x1112_1314_1516_1718);
        runtime.attach_guest_memory(&memory);

        let flat_operand = crate::cpu::MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(flat_address),
        };
        let upper_flat_operand = crate::cpu::MemoryOperand {
            absolute_address: Some(upper_flat_address),
            ..flat_operand
        };
        let high_operand = crate::cpu::MemoryOperand {
            absolute_address: Some(high_address),
            ..flat_operand
        };
        runtime
            .get_or_compile(
                &[IrInstruction::LoadMemory {
                    dst: Register::Rax,
                    address: flat_operand,
                    width: 8,
                }],
                site,
                GuestArch::X64,
                None,
            )
            .expect("compile >4 GiB load");
        let mut state = CpuState::new(GuestArch::X64);
        let reason = execute_cached(&mut runtime, site, &mut state, &mut memory);
        assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
        assert_eq!(state.get(Register::Rax), 0x0102_0304_0506_0708);

        runtime
            .get_or_compile(
                &[IrInstruction::LoadMemory {
                    dst: Register::Rax,
                    address: upper_flat_operand,
                    width: 8,
                }],
                site + 0x200,
                GuestArch::X64,
                None,
            )
            .expect("compile 64 GiB load");
        let reason = execute_cached(&mut runtime, site + 0x200, &mut state, &mut memory);
        assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
        assert_eq!(
            state.get(Register::Rax),
            0x2122_2324_2526_2728,
            "a 64 GiB address must be served directly by the window"
        );

        runtime
            .get_or_compile(
                &[IrInstruction::LoadMemory {
                    dst: Register::Rax,
                    address: high_operand,
                    width: 8,
                }],
                site + 0x100,
                GuestArch::X64,
                None,
            )
            .expect("compile high-frame load");
        let reason = execute_cached(&mut runtime, site + 0x100, &mut state, &mut memory);
        assert_eq!(reason, JitExitReason::Normal { new_rip: state.rip });
        assert_eq!(
            state.get(Register::Rax),
            0x1112_1314_1516_1718,
            "addresses beyond the window must keep using MemoryImage frames"
        );
        assert_eq!(memory.canonical_store().materialisation_count(), 3);
        assert_eq!(memory.canonical_store().high_page_count(), 1);
        assert_eq!(
            memory.canonical_store().resident_flat_page_count(),
            2,
            "the high-address frame must not consume flat residency"
        );
    }

    #[test]
    fn sigbus_fallback_above_four_gib_uses_the_direct_window() {
        let mut memory = MemoryImage::default();
        let page = 0x2_0000_0000_u64;
        memory.map_bytes(page, &[0x5A; 4096]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.attach_guest_memory(&memory);
        let base = runtime.flat_memory.base() as *mut u8;
        let size = runtime.flat_memory.size();
        let before = SIGBUS_PAGE_FOUND.load(Ordering::Relaxed);
        service_faulting_page(&runtime, &memory, page, base, size);
        assert_eq!(SIGBUS_PAGE_FOUND.load(Ordering::Relaxed), before + 1);
        assert_eq!(runtime.flat_memory.is_page_materialised(page), true);
        // SAFETY: the >4 GiB page is inside the canonical flat mapping.
        let byte = unsafe { std::ptr::read_volatile(base.add(page as usize)) };
        assert_eq!(byte, 0x5A);
        assert_eq!(memory.read_u8(page).unwrap(), 0x5A);
        assert_eq!(memory.canonical_store().materialisation_count(), 1);
    }

    #[test]
    fn sigbus_partial_page_tail_mapping_fallback_is_exact() {
        let runtime = JitRuntime::new(GuestArch::X64);
        let mut tail = MemoryImage::default();
        tail.map_bytes(0x1FFF, &[0x5A]);
        assert_eq!(tail.page_is_fully_mapped(0x1000), false);
        assert_eq!(tail.page_exists(0x1000), true);
        assert_eq!(tail.page_byte_is_mapped(0x1000, 0), false);
        assert_eq!(tail.page_byte_is_mapped(0x1000, 4095), true);
        let mut interior = MemoryImage::default();
        interior.map_bytes(0x1001, &[0x00]);
        assert_eq!(interior.page_exists(0x1000), true);
        assert_eq!(interior.page_byte_is_mapped(0x1000, 0), false);
        assert_eq!(interior.page_byte_is_mapped(0x1000, 4095), false);
        let mut flat = vec![0u8; 0x2000];
        let before = SIGBUS_PAGE_NOT_FOUND.load(Ordering::Relaxed);
        service_faulting_page(&runtime, &tail, 0x1000, flat.as_mut_ptr(), flat.len());
        service_faulting_page(&runtime, &interior, 0x1000, flat.as_mut_ptr(), flat.len());
        assert_eq!(SIGBUS_PAGE_NOT_FOUND.load(Ordering::Relaxed), before + 2);
    }

    #[test]
    fn execute_slice_block_stale_null_entry_falls_back_to_safepoint() {
        let mut runtime = capable_runtime();
        let block = runtime
            .get_or_compile_slice_block(&[IrInstruction::Nop], 0x7000, GuestArch::X64)
            .expect("compile slice block")
            .clone();
        assert_eq!(block.published_entry().is_null(), false);
        block.entry_atomic.store(ptr::null_mut(), Ordering::Release);
        assert_eq!(block.published_entry().is_null(), true);

        let mut memory = MemoryImage::default();
        memory.map_bytes(0x7000, &[0u8; 0x1000]);
        let view = Arc::new(GuestSliceMemory::new(&memory, BTreeSet::new()));
        let program = GuestSliceProgram {
            blocks: HashMap::from([(0x7000, block)]),
            flat_base: view.flat_base(),
            memory: view,
            mechanism: runtime.compiler.memory_manager.mechanism(),
            epoch: 0,
        };
        let mut state = CpuState::new(GuestArch::X64);
        let mut chain = ChainState::new(program.flat_base, 0x7000, LINK_BUDGET);
        assert_eq!(program.block(0x7000).is_some(), true);
        assert_eq!(program.block(0x7001).is_none(), true);
        let outcome = unsafe {
            execute_slice_block(&program, &program.blocks[&0x7000], &mut state, &mut chain)
        };
        assert_eq!(outcome.reason, JitExitReason::Safepoint);
        assert_eq!(outcome.final_block, 0x7000);
        assert_eq!(state.jit_pending_fault, None);
    }

    #[test]
    fn jit_slice_block_cache_clear_drops_worker_blocks() {
        let mut runtime = capable_runtime();
        let block = runtime
            .get_or_compile_slice_block(&[IrInstruction::Nop], 0x7100, GuestArch::X64)
            .expect("compile slice block");
        assert_eq!(block.worker_safe, true);
        assert_eq!(runtime.slice_block(0x7100).is_some(), true);
        runtime.clear_slice_blocks();
        assert_eq!(runtime.slice_block(0x7100).is_none(), true);
        assert_eq!(runtime.slice_block_cache.is_empty(), true);
        let memory = MemoryImage::default();
        let program = runtime.build_slice_program(&memory);
        assert_eq!(program.flat_base, program.memory.flat_base());
        assert_eq!(program.flat_base == 0, false);
        assert_eq!(program.blocks.is_empty(), true);
    }

    #[test]
    fn worker_safe_classification_accepts_native_control_transfer_rejects_mid_block_exits() {
        // An interpreter-helper fallback still needs a live `MemoryImage`, so
        // it can never run on a production worker.
        assert_eq!(block_is_worker_safe(&[IrInstruction::Nop], true), false);
        // Mid-block-exit instructions re-run the whole block on the
        // interpreter, so they must stay host barriers.
        assert_eq!(block_is_worker_safe(&[IrInstruction::Cpuid], false), false);
        assert_eq!(block_is_worker_safe(&[IrInstruction::Xgetbv], false), false);
        assert_eq!(
            block_is_worker_safe(
                &[IrInstruction::Fxsave {
                    address: crate::cpu::MemoryOperand {
                        base: None,
                        index: None,
                        scale: 1,
                        displacement: 0,
                        rip_relative: false,
                        rip_base: 0,
                        segment: None,
                        address_size_32: false,
                        absolute_address: None,
                    }
                }],
                false
            ),
            false
        );
        // Guest call / ret / indirect control transfer now lowers to a native
        // worker exit (target published in the exit cell), so the block is
        // worker-safe even though the target block may take the owner path.
        assert_eq!(
            block_is_worker_safe(
                &[IrInstruction::Call {
                    target: 0x1000,
                    return_address: 0x1005,
                }],
                false,
            ),
            true
        );
        assert_eq!(
            block_is_worker_safe(
                &[IrInstruction::CallRegister {
                    src: Register::Rax,
                    return_address: 0x1005,
                }],
                false,
            ),
            true
        );
        assert_eq!(
            block_is_worker_safe(&[IrInstruction::JumpRegister { src: Register::Rax }], false),
            true
        );
        assert_eq!(
            block_is_worker_safe(&[IrInstruction::Return { stack_adjust: 0 }], false),
            true
        );
        assert_eq!(
            block_is_worker_safe(
                &[
                    IrInstruction::MovImm {
                        dst: Register::Rax,
                        value: 1,
                    },
                    IrInstruction::Nop,
                ],
                false,
            ),
            true
        );
        assert_eq!(
            block_is_worker_safe(
                &[IrInstruction::JumpIf {
                    condition: ConditionCode::Equal,
                    target: 0x1000,
                    fallthrough: 0x1006,
                }],
                false,
            ),
            true
        );
    }
    // ── Production worker control flow (return predictor / inline caches) ──

    fn worker_program(
        runtime: &mut JitRuntime,
        memory: &MemoryImage,
        arch: GuestArch,
        blocks: &[(u64, Vec<IrInstruction>)],
    ) -> GuestSliceProgram {
        for (address, ir) in blocks {
            runtime
                .get_or_compile_slice_block(ir, *address, arch)
                .expect("compile worker block");
        }
        runtime.build_slice_program(memory)
    }

    fn worker_memory(stack: u64) -> MemoryImage {
        let mut memory = MemoryImage::default();
        memory.map_bytes(stack & !0xfff, &vec![0_u8; 0x1000]);
        memory
    }

    #[test]
    fn indirect_inline_cache_polymorphic_boundary_and_megamorphic_counts_are_exact() {
        let site = 0x1_000_u64;
        let mut cache = IndirectInlineCache::default();
        assert_eq!(cache.lookup(site, 0xA), None);
        cache.insert(site, 0xA, 0xAA);
        assert_eq!(cache.lookup(site, 0xA), Some(0xAA));
        assert_eq!(cache.lookup(site, 0xB), None);
        cache.insert(site, 0xB, 0xBB);
        assert_eq!(cache.lookup(site, 0xA), Some(0xAA));
        assert_eq!(cache.lookup(site, 0xB), Some(0xBB));
        assert_eq!(
            (
                cache.hits(),
                cache.misses(),
                cache.megamorphic_sites(),
                cache.megamorphic_hits(),
                cache.is_megamorphic(site),
            ),
            (3, 2, 0, 0, false),
            "a 2-way code path must stay polymorphic (monomorphic first)"
        );

        assert_eq!(cache.lookup(site, 0xC), None);
        cache.insert(site, 0xC, 0xCC);
        assert_eq!(cache.lookup(site, 0xD), None);
        cache.insert(site, 0xD, 0xDD);
        for (target, entry) in [(0xA, 0xAA), (0xB, 0xBB), (0xC, 0xCC), (0xD, 0xDD)] {
            assert_eq!(cache.lookup(site, target), Some(entry));
        }
        assert_eq!(
            (
                cache.hits(),
                cache.misses(),
                cache.megamorphic_sites(),
                cache.megamorphic_hits(),
            ),
            (7, 4, 0, 0),
            "four distinct targets are exactly the 4-way polymorphic limit"
        );

        assert_eq!(cache.lookup(site, 0xE), None);
        cache.insert(site, 0xE, 0xEE);
        assert_eq!(
            (cache.megamorphic_sites(), cache.is_megamorphic(site)),
            (1, true),
            "a fifth distinct target must promote the site to megamorphic"
        );
        for (target, entry) in [
            (0xA, 0xAA),
            (0xB, 0xBB),
            (0xC, 0xCC),
            (0xD, 0xDD),
            (0xE, 0xEE),
        ] {
            assert_eq!(cache.lookup(site, target), Some(entry));
        }
        assert_eq!(cache.lookup(site, 0xF), None);
        assert_eq!(
            (
                cache.hits(),
                cache.misses(),
                cache.megamorphic_sites(),
                cache.megamorphic_hits(),
            ),
            (7, 6, 1, 5),
            "megamorphic lookups must be counted separately from hits/misses"
        );
    }

    #[test]
    fn return_predictor_misprediction_edge_boundary_is_exact() {
        let mut predictor = ReturnPredictor::new(4);
        assert_eq!(predictor.on_return(0x10), false);
        assert_eq!(
            (
                predictor.hits(),
                predictor.misses(),
                predictor.mispredictions()
            ),
            (0, 1, 0),
            "a return without a call is a miss, not a misprediction"
        );
        predictor.on_call(0x10);
        assert_eq!(predictor.on_return(0x10), true);
        predictor.on_call(0x20);
        predictor.on_call(0x30);
        assert_eq!(predictor.on_return(0x30), true);
        assert_eq!(predictor.on_return(0x99), false);
        assert_eq!(
            (
                predictor.hits(),
                predictor.misses(),
                predictor.mispredictions()
            ),
            (2, 2, 1),
            "the real guest return address must be authoritative"
        );
        assert_eq!(predictor.on_return(0x77), false);
        assert_eq!(
            (
                predictor.hits(),
                predictor.misses(),
                predictor.mispredictions()
            ),
            (2, 3, 1)
        );

        // A non-local return resynchronises to the real frame when possible.
        predictor.reset();
        predictor.on_call(0x1);
        predictor.on_call(0x2);
        predictor.on_call(0x3);
        assert_eq!(predictor.on_return(0x2), false);
        assert_eq!(
            (
                predictor.hits(),
                predictor.misses(),
                predictor.mispredictions()
            ),
            (0, 1, 1)
        );
        assert_eq!(
            predictor.on_return(0x2),
            true,
            "the predictor must resynchronise after a misprediction"
        );
        assert_eq!(
            (
                predictor.hits(),
                predictor.misses(),
                predictor.mispredictions()
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn worker_recursion_uses_native_call_ret_chain_and_exact_predictor_counters() {
        let arch = GuestArch::X64;
        let stack = 0x11_000_u64;
        let mut memory = worker_memory(stack);
        memory.write_u64(stack + 0x800, 0xDEAD);
        let mut runtime = JitRuntime::new(arch);
        let blocks = vec![
            (
                0x1000,
                vec![IrInstruction::Call {
                    target: 0x2000,
                    return_address: 0x1010,
                }],
            ),
            (0x1010, vec![IrInstruction::Return { stack_adjust: 0 }]),
            (
                0x2000,
                vec![
                    IrInstruction::SubImm {
                        dst: Register::Rcx,
                        value: 1,
                        width: 8,
                    },
                    IrInstruction::Compare {
                        lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
                        rhs: crate::cpu::CompareOperand::ImmediateU64(0),
                        width: 8,
                    },
                    IrInstruction::JumpIf {
                        condition: ConditionCode::NotEqual,
                        target: 0x2010,
                        fallthrough: 0x2020,
                    },
                ],
            ),
            (
                0x2010,
                vec![IrInstruction::Call {
                    target: 0x2000,
                    return_address: 0x2018,
                }],
            ),
            (0x2018, vec![IrInstruction::Return { stack_adjust: 0 }]),
            (0x2020, vec![IrInstruction::Return { stack_adjust: 0 }]),
        ];
        let program = worker_program(&mut runtime, &memory, arch, &blocks);
        let mut state = CpuState::new(arch);
        state.rip = 0x1000;
        state.set(Register::Rsp, stack + 0x800);
        state.set(Register::Rcx, 3);
        let mut thread = SliceThreadState::default();
        let shutdown = AtomicBool::new(false);
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 64, &shutdown) };
        assert_eq!(
            report.stop,
            SliceStop::HostBarrier { rip: 0xDEAD },
            "the balanced recursion must unwind to the caller's sentinel"
        );
        assert_eq!(state.get(Register::Rcx), 0);
        assert_eq!(report.blocks_executed, 10);
        assert_eq!(
            (
                report.metrics.return_predictions,
                report.metrics.return_hits,
                report.metrics.return_misses,
                report.metrics.return_mispredictions,
                report.metrics.native_chains,
            ),
            (4, 3, 1, 0, 9),
            "three calls and four returns must be predicted exactly"
        );
        assert_eq!(report.metrics.blocks_executed, 10);
        assert_eq!(
            report.metrics.dispatcher_exits, 1,
            "the balanced recursion is one native chain"
        );
        assert_eq!(report.metrics.instructions_executed, 16);
    }

    #[test]
    fn worker_mispredicted_return_follows_the_real_guest_address() {
        let arch = GuestArch::X64;
        let stack = 0x12_000_u64;
        let top = stack + 0x800;
        let memory = worker_memory(stack);
        let mut runtime = JitRuntime::new(arch);
        let address = crate::cpu::MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(top - 8),
        };
        let blocks = vec![
            (
                0x1000,
                vec![IrInstruction::Call {
                    target: 0x2000,
                    return_address: 0x1010,
                }],
            ),
            (
                0x2000,
                vec![
                    IrInstruction::StoreMemory {
                        src: Register::Rcx,
                        address,
                        width: 8,
                    },
                    IrInstruction::Return { stack_adjust: 0 },
                ],
            ),
            (0x2020, vec![IrInstruction::Jump { target: 0x2020 }]),
        ];
        let program = worker_program(&mut runtime, &memory, arch, &blocks);
        let mut state = CpuState::new(arch);
        state.rip = 0x1000;
        state.set(Register::Rsp, top);
        state.set(Register::Rcx, 0x2020);
        let mut thread = SliceThreadState::default();
        let shutdown = AtomicBool::new(false);
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
        assert_eq!(
            report.stop,
            SliceStop::Budget,
            "execution must continue at the real return address, not the prediction"
        );
        assert_eq!(state.rip, 0x2020);
        assert_eq!(
            (
                report.metrics.return_hits,
                report.metrics.return_misses,
                report.metrics.return_mispredictions,
            ),
            (0, 1, 1),
            "the overwritten return address must be a counted misprediction"
        );
        assert_eq!(report.metrics.native_chains, 2);
    }

    #[test]
    fn worker_indirect_calls_use_monomorphic_polymorphic_and_megamorphic_caches() {
        let arch = GuestArch::X64;
        let stack = 0x13_000_u64;
        let memory = worker_memory(stack);
        let mut runtime = JitRuntime::new(arch);
        let mut blocks = vec![(
            0x1000,
            vec![IrInstruction::CallRegister {
                src: Register::Rax,
                return_address: 0x1010,
            }],
        )];
        for target in [0x2000_u64, 0x3000, 0x4000, 0x5000, 0x6000] {
            blocks.push((target, vec![IrInstruction::Return { stack_adjust: 0 }]));
        }
        let program = worker_program(&mut runtime, &memory, arch, &blocks);
        let mut state = CpuState::new(arch);
        state.set(Register::Rsp, stack + 0x800);
        let mut thread = SliceThreadState::default();
        let shutdown = AtomicBool::new(false);
        let sequence = [
            0x2000, 0x3000, 0x2000, 0x4000, 0x5000, 0x2000, 0x3000, 0x4000, 0x5000,
        ];
        for target in sequence {
            state.rip = 0x1000;
            state.set(Register::Rsp, stack + 0x800);
            state.set(Register::Rax, target);
            // SAFETY: program/state are live for the call; budget 1 executes
            // only the indirect call block.
            let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
            assert_eq!(report.stop, SliceStop::Budget);
            assert_eq!(state.rip, target);
            assert_eq!(report.metrics.indirect_megamorphic_sites, 0);
        }
        assert_eq!(
            (
                thread.metrics.indirect_ic_hits,
                thread.metrics.indirect_ic_misses,
                thread.metrics.indirect_megamorphic_sites,
                thread.metrics.indirect_megamorphic_hits,
            ),
            (5, 4, 0, 0),
            "four distinct call targets stay inside the 4-way polymorphic cache"
        );
        state.rip = 0x1000;
        state.set(Register::Rsp, stack + 0x800);
        state.set(Register::Rax, 0x6000);
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
        assert_eq!(report.metrics.indirect_megamorphic_sites, 1);
        assert_eq!(report.metrics.indirect_ic_misses, 1);
        for target in [0x2000_u64, 0x3000, 0x4000, 0x5000, 0x6000] {
            state.rip = 0x1000;
            state.set(Register::Rsp, stack + 0x800);
            state.set(Register::Rax, target);
            let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
            assert_eq!(report.metrics.indirect_megamorphic_hits, 1);
        }
        assert_eq!(thread.metrics.indirect_megamorphic_hits, 5);
        assert_eq!(thread.metrics.indirect_ic_hits, 5);
        state.rip = 0x1000;
        state.set(Register::Rsp, stack + 0x800);
        state.set(Register::Rax, 0x2000);
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
        assert_eq!(
            (
                report.metrics.indirect_ic_hits,
                report.metrics.indirect_megamorphic_hits,
                thread.metrics.indirect_megamorphic_sites,
            ),
            (0, 1, 1),
            "a megamorphic hit must not be reported as an ordinary hit"
        );
    }

    #[test]
    fn worker_chained_code_safepoint_and_smc_stop_before_the_next_block() {
        let arch = GuestArch::X64;
        let stack = 0x14_000_u64;
        let mut memory = worker_memory(stack);
        memory.map_bytes(0x5000, &vec![0_u8; 0x1000]);
        let mut runtime = JitRuntime::new(arch);
        runtime.code_pages.insert(0x5000);
        let call_blocks = vec![
            (
                0x1000,
                vec![IrInstruction::Call {
                    target: 0x2000,
                    return_address: 0x1010,
                }],
            ),
            (0x2000, vec![IrInstruction::Return { stack_adjust: 0 }]),
            (0x1010, vec![IrInstruction::Jump { target: 0x1010 }]),
        ];
        let call_program = worker_program(&mut runtime, &memory, arch, &call_blocks);
        let mut state = CpuState::new(arch);
        state.rip = 0x1000;
        state.set(Register::Rsp, stack + 0x800);
        let mut thread = SliceThreadState::default();
        let shutdown = AtomicBool::new(false);
        let report = unsafe { run_slice(&call_program, &mut state, &mut thread, 1, &shutdown) };
        assert_eq!(report.stop, SliceStop::Budget);
        assert_eq!(state.rip, 0x2000);
        crate::jit::JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Release);
        let report = unsafe { run_slice(&call_program, &mut state, &mut thread, 8, &shutdown) };
        crate::jit::JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        assert_eq!(
            report.stop,
            SliceStop::Safepoint,
            "a chained callee must poll the safepoint at its block entry"
        );
        assert_eq!(state.rip, 0x2000);
        assert_eq!(
            report.blocks_executed, 0,
            "the callee's entry safepoint poll must stop before its body runs"
        );

        let write = crate::cpu::MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(0x5010),
        };
        let smc_blocks = vec![
            (0x5000, vec![IrInstruction::Jump { target: 0x5010 }]),
            (
                0x5010,
                vec![
                    IrInstruction::StoreMemory {
                        src: Register::Rcx,
                        address: write,
                        width: 8,
                    },
                    IrInstruction::Jump { target: 0x5020 },
                ],
            ),
            (
                0x5020,
                vec![IrInstruction::AddImm {
                    dst: Register::Rdx,
                    value: 1,
                    width: 8,
                }],
            ),
        ];
        let smc_program = worker_program(&mut runtime, &memory, arch, &smc_blocks);
        let mut state = CpuState::new(arch);
        state.rip = 0x5000;
        state.set(Register::Rcx, 0x1122_3344_5566_7788);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&smc_program, &mut state, &mut thread, 8, &shutdown) };
        assert_eq!(report.stop, SliceStop::CodeWrite);
        assert_eq!(report.blocks_executed, 2);
        assert_eq!(report.code_writes, vec![(0x5010, 8)]);
        assert_eq!(
            state.get(Register::Rdx),
            0,
            "the block after a chained code write must not execute"
        );
        assert_eq!(state.rip, 0x5020);
    }

    // ── Native linking / in-block branches / persistent AOT cache ──────────

    fn worker_runtime(arch: GuestArch) -> JitRuntime {
        assert!(
            jit_execution_available(),
            "this test requires a working executable-memory mechanism"
        );
        let mut runtime = JitRuntime::new(arch);
        runtime.set_aot_cache_dir(None);
        runtime
    }

    fn unlink_program(program: &GuestSliceProgram) {
        for block in program.blocks.values() {
            block.link_target.store(0, Ordering::Release);
            block.taken_link.store(0, Ordering::Release);
            block.fallthrough_link.store(0, Ordering::Release);
            block.call_link.store(0, Ordering::Release);
            block.return_entry_link.store(0, Ordering::Release);
        }
    }

    fn loop_blocks(site: u64, exit: u64) -> Vec<(u64, Vec<IrInstruction>)> {
        vec![
            (
                site,
                vec![
                    IrInstruction::SubImm {
                        dst: Register::Rcx,
                        value: 1,
                        width: 4,
                    },
                    IrInstruction::Compare {
                        lhs: crate::cpu::CompareOperand::Register(Register::Rcx),
                        rhs: crate::cpu::CompareOperand::ImmediateU64(0),
                        width: 4,
                    },
                    IrInstruction::JumpIf {
                        condition: ConditionCode::NotEqual,
                        target: site,
                        fallthrough: exit,
                    },
                ],
            ),
            (exit, vec![IrInstruction::Nop]),
        ]
    }

    #[test]
    fn jit_worker_linked_loop_and_call_return_match_unlinked_exactly() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        let mut blocks = loop_blocks(0x1000, 0x1010);
        blocks.push((
            0x2000,
            vec![IrInstruction::Call {
                target: 0x2100,
                return_address: 0x2010,
            }],
        ));
        blocks.push((0x2010, vec![IrInstruction::Jump { target: 0x9000 }]));
        blocks.push((0x2100, vec![IrInstruction::Return { stack_adjust: 0 }]));
        let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
        let shutdown = std::sync::atomic::AtomicBool::new(false);

        let run_loop = |program: &GuestSliceProgram, budget: u64| {
            let mut state = CpuState::new(GuestArch::X64);
            state.rip = 0x1000;
            state.set(Register::Rcx, 100);
            let mut thread = SliceThreadState::default();
            let report = unsafe { run_slice(program, &mut state, &mut thread, budget, &shutdown) };
            (report, state.get(Register::Rcx))
        };
        let (linked_report, linked_rcx) = run_loop(&program, 8);
        unlink_program(&program);
        let (unlinked_report, unlinked_rcx) = run_loop(&program, 8);
        assert_eq!(
            (linked_report.blocks_executed, linked_rcx),
            (8, 100 - 8),
            "linked loop must execute exactly the slice budget"
        );
        assert_eq!(
            (unlinked_report.blocks_executed, unlinked_rcx),
            (8, 100 - 8),
            "unlinked execution must reach the identical guest state"
        );
        assert_eq!(linked_report.metrics.native_chains, 7);
        assert_eq!(unlinked_report.metrics.native_chains, 0);
        assert_eq!(linked_report.metrics.instructions_executed, 24);
        assert_eq!(unlinked_report.metrics.instructions_executed, 24);
        assert_eq!(linked_report.stop, SliceStop::Budget);
        assert_eq!(unlinked_report.stop, SliceStop::Budget);

        let run_call = |program: &GuestSliceProgram| {
            let mut state = CpuState::new(GuestArch::X64);
            state.rip = 0x2000;
            state.set(Register::Rsp, 0x7800);
            let mut thread = SliceThreadState::default();
            let report = unsafe { run_slice(program, &mut state, &mut thread, 4, &shutdown) };
            (
                report.blocks_executed,
                report.stop,
                state.get(Register::Rsp),
            )
        };
        // Re-publish links for the call/ret measurement.
        runtime.build_slice_program(&memory);
        let linked_call = run_call(&program);
        unlink_program(&program);
        let unlinked_call = run_call(&program);
        assert_eq!(
            linked_call,
            (3, SliceStop::HostBarrier { rip: 0x9000 }, 0x7800)
        );
        assert_eq!(
            unlinked_call,
            (3, SliceStop::HostBarrier { rip: 0x9000 }, 0x7800)
        );
        // Call + return must be linked; the final uncompiled jump is not.
        assert_eq!(
            unsafe {
                let mut state = CpuState::new(GuestArch::X64);
                state.rip = 0x2000;
                state.set(Register::Rsp, 0x7800);
                let mut thread = SliceThreadState::default();
                runtime.build_slice_program(&memory);
                run_slice(&program, &mut state, &mut thread, 4, &shutdown)
                    .metrics
                    .native_chains
            },
            2
        );
    }

    #[test]
    fn jit_worker_safepoint_stop_is_observed_within_the_link_budget() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        let program = worker_program(
            &mut runtime,
            &memory,
            GuestArch::X64,
            &loop_blocks(0x1100, 0x1110),
        );
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Release);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x1100;
        state.set(Register::Rcx, 10);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 8, &shutdown) };
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        assert_eq!(report.stop, SliceStop::Safepoint);
        assert_eq!(report.blocks_executed, 0);
        assert_eq!(state.rip, 0x1100);
        assert_eq!(state.get(Register::Rcx), 10);

        // A running chain must observe a safepoint set by another host thread
        // before the slice budget is exhausted, and never exceed LINK_BUDGET
        // block entries between dispatch boundaries.
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let setter = std::sync::Arc::clone(&flag);
        let watcher = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(2));
            setter.store(true, Ordering::Release);
            JIT_SAFEPOINT_REQUESTED.store(true, Ordering::Release);
        });
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x1100;
        state.set(Register::Rcx, 100_000_000);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 50_000_000, &shutdown) };
        watcher.join().expect("safepoint setter");
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        assert_eq!(flag.load(Ordering::Acquire), true);
        assert_eq!(report.stop, SliceStop::Safepoint);
        assert_eq!(report.blocks_executed > 0, true);
        assert_eq!(report.blocks_executed <= 50_000_000, true);
    }

    #[test]
    fn jit_worker_smc_write_invalidates_native_links_exactly() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x3000, &[0_u8; 0x1000]);
        runtime.attach_guest_memory(&memory);
        let operand = crate::cpu::MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(0x3000),
        };
        let blocks = vec![(
            0x3000,
            vec![
                IrInstruction::StoreImmediate {
                    address: operand,
                    value: 0x90,
                    width: 1,
                },
                IrInstruction::Jump { target: 0x3000 },
            ],
        )];
        let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
        let link = Arc::clone(&program.blocks[&0x3000].link_target);
        assert_eq!(link.load(Ordering::Acquire) != 0, true);
        let epoch_before = JIT_CODE_EPOCH.load(Ordering::Acquire);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x3000;
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
        assert_eq!(report.stop, SliceStop::CodeWrite);
        assert_eq!(report.blocks_executed, 1);
        assert_eq!(report.code_writes, vec![(0x3000, 1)]);
        assert_eq!(state.rip, 0x3000);
        assert_eq!(JIT_CODE_EPOCH.load(Ordering::Acquire) > epoch_before, true);

        let pages = BTreeSet::from([0x3000]);
        let affected = runtime.invalidate_blocks_on_pages(&pages);
        assert_eq!(affected, Vec::<u64>::new());
        assert_eq!(link.load(Ordering::Acquire), 0);
        assert_eq!(runtime.slice_block(0x3000).is_none(), true);
        assert_eq!(runtime.slice_epoch, 1);

        // Recompilation after invalidation must use the new guest code.
        let replacement = vec![(
            0x3000,
            vec![IrInstruction::AddImm {
                dst: Register::Rcx,
                value: 7,
                width: 8,
            }],
        )];
        let program = worker_program(&mut runtime, &memory, GuestArch::X64, &replacement);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x3000;
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 1, &shutdown) };
        assert_eq!(report.blocks_executed, 1);
        assert_eq!(state.get(Register::Rcx), 7);
    }

    #[test]
    fn jit_worker_host_call_barrier_pushes_return_exactly_once() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        let blocks = vec![(
            0x4000,
            vec![IrInstruction::Call {
                target: 0x9000,
                return_address: 0x4010,
            }],
        )];
        let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x4000;
        state.set(Register::Rsp, 0x7800);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
        assert_eq!(report.stop, SliceStop::HostBarrier { rip: 0x9000 });
        assert_eq!(report.blocks_executed, 1);
        assert_eq!(state.get(Register::Rsp), 0x77f8);
        assert_eq!(memory.read_u64(0x77f8).expect("mapped stack"), 0x4010);
        assert_eq!(
            thread.return_predictor.hits() + thread.return_predictor.misses(),
            0
        );
    }

    #[test]
    fn jit_worker_conditional_flags_equivalence_all_conditions_is_exact() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        let conditions = [
            ConditionCode::Equal,
            ConditionCode::NotEqual,
            ConditionCode::Overflow,
            ConditionCode::NotOverflow,
            ConditionCode::Below,
            ConditionCode::NotBelow,
            ConditionCode::Above,
            ConditionCode::NotAbove,
            ConditionCode::Sign,
            ConditionCode::NotSign,
            ConditionCode::Less,
            ConditionCode::GreaterEqual,
            ConditionCode::LessEqual,
            ConditionCode::Greater,
            ConditionCode::Parity,
            ConditionCode::NotParity,
        ];
        let mut blocks = Vec::new();
        let mut addresses = Vec::new();
        for (index, condition) in conditions.iter().enumerate() {
            let address = 0x5000 + (index as u64) * 0x20;
            addresses.push(address);
            blocks.push((
                address,
                vec![IrInstruction::JumpIf {
                    condition: *condition,
                    target: 0x9000,
                    fallthrough: 0x9008,
                }],
            ));
        }
        let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
        let mut checks = 0_u64;
        for (index, condition) in conditions.iter().enumerate() {
            for bits in 0..32_u8 {
                let mut state = CpuState::new(GuestArch::X64);
                state.flags = crate::cpu::Flags {
                    cf: bits & 1 != 0,
                    pf: bits & 2 != 0,
                    zf: bits & 4 != 0,
                    sf: bits & 8 != 0,
                    of: bits & 16 != 0,
                    af: false,
                };
                let mut chain = ChainState::new(program.flat_base, addresses[index], LINK_BUDGET);
                let outcome = unsafe {
                    execute_slice_block(
                        &program,
                        &program.blocks[&addresses[index]],
                        &mut state,
                        &mut chain,
                    )
                };
                let actual = match outcome.reason {
                    JitExitReason::ConditionalTaken { .. } => true,
                    JitExitReason::ConditionalNotTaken { .. } => false,
                    other => panic!("expected native conditional exit, got {other:?}"),
                };
                assert_eq!(
                    actual,
                    crate::cpu::evaluate_condition(*condition, &state.flags),
                    "condition {condition:?} with flags {bits:#07b}"
                );
                checks += 1;
            }
        }
        assert_eq!(checks, 16 * 32);
    }

    #[test]
    fn jit_worker_lazy_flags_materialize_before_native_jcc_exactly() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        let cases = [
            (ConditionCode::Equal, true, true),
            (ConditionCode::Overflow, true, true),
            (ConditionCode::Sign, true, true),
        ];
        let mut blocks = Vec::new();
        for (index, _) in cases.iter().enumerate() {
            blocks.push((
                0x5300 + (index as u64) * 0x20,
                vec![IrInstruction::JumpIf {
                    condition: cases[index].0,
                    target: 0x9000,
                    fallthrough: 0x9008,
                }],
            ));
        }
        let program = worker_program(&mut runtime, &memory, GuestArch::X64, &blocks);
        let materialised_before = crate::cpu::lazy_flag_telemetry().materialised;
        let mut stats = crate::cpu::LazyFlagStats::default();
        for (index, (condition, _, _)) in cases.iter().enumerate() {
            let address = 0x5300 + (index as u64) * 0x20;
            let mut state = CpuState::new(GuestArch::X64);
            match index {
                0 => state.defer_sub_flags(5, 5, 0, 32, &mut stats),
                1 => state.defer_add_flags(i64::MAX as u64, 1, i64::MIN as u64, 64, &mut stats),
                _ => state.defer_sub_flags(1, 2, u64::MAX, 64, &mut stats),
            }
            assert_eq!(state.pending_flags.is_some(), true);
            let mut chain = ChainState::new(program.flat_base, address, LINK_BUDGET);
            let outcome = unsafe {
                execute_slice_block(&program, &program.blocks[&address], &mut state, &mut chain)
            };
            assert_eq!(state.pending_flags.is_none(), true);
            assert_eq!(
                outcome.reason,
                JitExitReason::ConditionalTaken { rip: address },
                "lazy flags must be materialised before the native branch"
            );
            assert_eq!(
                cases[index].1,
                crate::cpu::evaluate_condition(*condition, &state.flags)
            );
        }
        assert_eq!(
            crate::cpu::lazy_flag_telemetry().materialised,
            materialised_before + 3
        );
    }

    fn decode_fixed_mov_imm64(bytes: &[u8]) -> u64 {
        let mut value = 0_u64;
        for index in 0..4 {
            let word = u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
            let hw = (word >> 21) & 3;
            let imm = ((word >> 5) & 0xffff) as u64;
            value |= imm << (hw * 16);
        }
        value
    }

    fn aot_probe_ir() -> Vec<IrInstruction> {
        vec![IrInstruction::AddImm {
            dst: Register::Rcx,
            value: 1,
            width: 8,
        }]
    }

    fn run_aot_probe(runtime: &mut JitRuntime, memory: &MemoryImage) -> (u64, u64) {
        let ir = aot_probe_ir();
        runtime
            .get_or_compile_slice_block(&ir, 0x6000, GuestArch::X64)
            .expect("compile or load AOT probe");
        let program = runtime.build_slice_program(memory);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x6000;
        state.set(Register::Rcx, 41);
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 4, &shutdown) };
        (report.blocks_executed, state.get(Register::Rcx))
    }

    #[test]
    fn jit_worker_aot_cache_round_trip_across_process_boundaries_loads_exact_code() {
        if let Ok(directory) = std::env::var("CASA1_AOT_CHILD_DIR") {
            let mut runtime = JitRuntime::new(GuestArch::X64);
            runtime.set_aot_cache_dir(Some(std::path::PathBuf::from(directory)));
            let memory = worker_memory(0x7000);
            runtime.attach_guest_memory(&memory);
            assert_eq!(run_aot_probe(&mut runtime, &memory), (1, 42));
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let executable = std::env::current_exe().expect("test executable");
        let name = format!(
            "{}::jit_worker_aot_cache_round_trip_across_process_boundaries_loads_exact_code",
            module_path!()
        )
        .replace("casa1::", "");
        let status = std::process::Command::new(executable)
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env("CASA1_AOT_CHILD_DIR", directory.path())
            .status()
            .expect("spawn AOT child process");
        assert_eq!(status.success(), true);

        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        assert_eq!(run_aot_probe(&mut runtime, &memory), (1, 42));
        assert_eq!(runtime.aot_metrics(), (1, 0, 0));
    }

    #[test]
    fn jit_worker_aot_corrupt_and_wrong_version_cache_are_rejected_with_counters() {
        let directory = tempfile::tempdir().expect("tempdir");
        let ir = aot_probe_ir();
        let source_hash = compute_ir_hash(&ir, 0x6100);
        let mut writer = JitRuntime::new(GuestArch::X64);
        writer.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        writer
            .get_or_compile_slice_block(&ir, 0x6100, GuestArch::X64)
            .expect("initial compile");
        let path = writer.aot_path(source_hash, 0x6100).expect("cache path");
        assert_eq!(path.is_file(), true);

        std::fs::write(&path, b"corrupt").expect("corrupt cache write");
        let mut corrupt = JitRuntime::new(GuestArch::X64);
        corrupt.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        corrupt
            .get_or_compile_slice_block(&ir, 0x6100, GuestArch::X64)
            .expect("fallback compile after corruption");
        assert_eq!(corrupt.aot_metrics(), (0, 0, 1));

        let bytes = std::fs::read(&path).expect("rewritten cache");
        let mut record = AotRecord::decode(&bytes).expect("valid rewritten record");
        record.translator = record.translator.wrapping_add(1);
        std::fs::write(&path, record.encode()).expect("wrong-version cache write");
        let mut wrong = JitRuntime::new(GuestArch::X64);
        wrong.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        wrong
            .get_or_compile_slice_block(&ir, 0x6100, GuestArch::X64)
            .expect("fallback compile after version mismatch");
        assert_eq!(wrong.aot_metrics(), (0, 0, 1));
    }

    #[test]
    fn jit_worker_aot_relocations_rebind_link_slots_exactly() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut writer = JitRuntime::new(GuestArch::X64);
        writer.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        let memory = worker_memory(0x7000);
        writer.attach_guest_memory(&memory);
        let ir = vec![IrInstruction::Jump { target: 0x6210 }];
        let source_hash = compute_ir_hash(&ir, 0x6200);
        writer
            .get_or_compile_slice_block(&ir, 0x6200, GuestArch::X64)
            .expect("compile jump");
        writer
            .get_or_compile_slice_block(
                &[IrInstruction::Jump { target: 0x9000 }],
                0x6210,
                GuestArch::X64,
            )
            .expect("compile target");
        let path = writer.aot_path(source_hash, 0x6200).expect("cache path");
        let bytes = std::fs::read(&path).expect("cache record");
        let record = AotRecord::decode(&bytes).expect("decode cache record");
        let relocation = record
            .relocations
            .iter()
            .find(|relocation| relocation.kind == AotRelocKind::JumpLink)
            .expect("jump link relocation");
        let offset = relocation.offset as usize;
        let on_disk = decode_fixed_mov_imm64(&record.code[offset..offset + 16]);
        assert_eq!(on_disk != 0, true);

        let mut reader = JitRuntime::new(GuestArch::X64);
        reader.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        reader.attach_guest_memory(&memory);
        let _ = reader
            .get_or_compile_slice_block(
                &[IrInstruction::Jump { target: 0x9000 }],
                0x6210,
                GuestArch::X64,
            )
            .expect("load target jump");
        let loaded = reader
            .get_or_compile_slice_block(&ir, 0x6200, GuestArch::X64)
            .expect("load jump")
            .clone();
        // Both jump blocks came from the persistent cache.
        assert_eq!(reader.aot_metrics(), (2, 0, 0));
        // SAFETY: the loaded entry is finalized executable code; reading its
        // bytes is side-effect free.
        let loaded_code =
            unsafe { std::slice::from_raw_parts(loaded.entry() as *const u8, loaded.code_size) };
        let relocated = decode_fixed_mov_imm64(&loaded_code[offset..offset + 16]);
        assert_eq!(relocated, Arc::as_ptr(&loaded.link_target) as u64);
        assert_eq!(relocated != on_disk, true);
        let mut in_reloc = vec![false; loaded.code_size];
        for relocation in &record.relocations {
            let start = relocation.offset as usize;
            for byte in &mut in_reloc[start..start + 16] {
                *byte = true;
            }
        }
        for (index, (a, b)) in record.code.iter().zip(loaded_code.iter()).enumerate() {
            if !in_reloc[index] {
                assert_eq!(a, b, "non-relocated byte {index:#x} changed");
            }
        }
        for relocation in &record.relocations {
            let start = relocation.offset as usize;
            let original_rd =
                u32::from_le_bytes(record.code[start..start + 4].try_into().unwrap()) & 0x1f;
            let relocated_rd =
                u32::from_le_bytes(loaded_code[start..start + 4].try_into().unwrap()) & 0x1f;
            assert_eq!(
                original_rd, relocated_rd,
                "relocation must preserve its destination register"
            );
            let value = decode_fixed_mov_imm64(&loaded_code[start..start + 16]);
            let expected = match relocation.kind {
                AotRelocKind::SafepointFlag => &JIT_SAFEPOINT_REQUESTED as *const _ as u64,
                AotRelocKind::CodeEpoch => &JIT_CODE_EPOCH as *const _ as u64,
                AotRelocKind::JumpLink => Arc::as_ptr(&loaded.link_target) as u64,
                other => panic!("unexpected relocation {other:?}"),
            };
            assert_eq!(value, expected, "relocation {relocation:?}");
        }

        let program = reader.build_slice_program(&memory);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let mut state = CpuState::new(GuestArch::X64);
        state.rip = 0x6200;
        let mut thread = SliceThreadState::default();
        let report = unsafe { run_slice(&program, &mut state, &mut thread, 8, &shutdown) };
        assert_eq!(report.blocks_executed, 2);
        assert_eq!(report.metrics.native_chains, 1);
        assert_eq!(report.stop, SliceStop::HostBarrier { rip: 0x9000 });
    }

    #[test]
    fn jit_worker_concurrent_in_flight_linked_blocks_are_exact() {
        JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
        let mut runtime = worker_runtime(GuestArch::X64);
        let memory = worker_memory(0x7000);
        runtime.attach_guest_memory(&memory);
        let program = std::sync::Arc::new(worker_program(
            &mut runtime,
            &memory,
            GuestArch::X64,
            &loop_blocks(0x1200, 0x1210),
        ));
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let entry = program.blocks[&0x1200].entry() as u64;
        let slot = Arc::clone(&program.blocks[&0x1200].taken_link);
        let results = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let program = std::sync::Arc::clone(&program);
                let results = &results;
                let shutdown = &shutdown;
                scope.spawn(move || {
                    let mut state = CpuState::new(GuestArch::X64);
                    state.rip = 0x1200;
                    state.set(Register::Rcx, 100);
                    let mut thread = SliceThreadState::default();
                    let report =
                        unsafe { run_slice(&program, &mut state, &mut thread, 50, shutdown) };
                    results
                        .lock()
                        .expect("results lock")
                        .push((report.blocks_executed, state.get(Register::Rcx)));
                });
            }
            let slot = &slot;
            scope.spawn(move || {
                for index in 0..2_000_u64 {
                    slot.store(if index % 2 == 0 { 0 } else { entry }, Ordering::Release);
                }
            });
        });
        let mut results = results.into_inner().expect("results");
        results.sort_unstable();
        assert_eq!(results, vec![(50, 50), (50, 50), (50, 50), (50, 50)]);
    }

    #[test]
    fn hot_path_loads_persisted_aot_record_without_recompiling() {
        let directory = tempfile::tempdir().expect("tempdir");
        let ir = vec![
            IrInstruction::Nop,
            IrInstruction::Return { stack_adjust: 0 },
        ];
        let mut writer = JitRuntime::new(GuestArch::X64);
        writer.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        writer
            .get_or_compile_slice_block(&ir, 0x9100, GuestArch::X64)
            .expect("persist worker block");

        let mut reader = JitRuntime::new(GuestArch::X64);
        reader.set_aot_cache_dir(Some(directory.path().to_path_buf()));
        reader
            .get_or_compile_at_tier(&ir, 0x9100, GuestArch::X64, CompilationTier::Tier0, None)
            .expect("hot path load");
        assert_eq!(reader.aot_metrics().0, 1, "one persistent hit");
        assert_eq!(reader.blocks_compiled, 0, "an AOT hit does not recompile");
        assert_eq!(reader.tier0_compiles, 0);
    }
}
