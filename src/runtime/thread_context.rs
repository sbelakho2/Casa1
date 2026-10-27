//! Per-guest-thread execution state.
//!
//! A [`GuestThreadContext`] owns everything that is *private to one runnable
//! guest thread*: its register/flag/FPU state, its JIT control-flow caches,
//! its TEB and TLS/FLS vectors, its Win32 last-error cache, its APC/exception
//! scratch and the dispatcher scratch slots a slice uses.  Nothing in this
//! type is shared with another guest thread.
//!
//! Process-wide state (canonical guest memory, the object manager, handles,
//! modules, the GPU device, the code/AOT cache and the process gate that
//! serializes host thunks) lives behind [`super::shared::ProcessShared`].
//! Guest execution therefore takes `&mut GuestThreadContext` plus
//! `&ProcessShared`; it never needs a `&mut PeHostRuntime`.
// The per-thread API is the concurrency boundary: several accessors are used
// by the adversarial concurrency tests and by the dispatcher migration still
// in flight, not by every production path yet.
#![allow(dead_code)]

use super::*;
use crate::cpu::{CpuState, GuestArch, Register};
use crate::jit::SliceThreadState;
use std::collections::BTreeMap;

/// TEB `LastErrorValue` offset for a guest architecture.
pub(crate) fn teb_last_error_offset(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => 0x68,
        GuestArch::X86 => 0x34,
    }
}

/// One runnable guest thread's private execution state.
///
/// The context is moved to a native worker for a slice and moved back on
/// completion, so it is never aliased: exactly one host thread owns it at a
/// time.  The process-shared memory it reads and writes is reachable through
/// [`super::shared::ProcessShared`].
pub(crate) struct GuestThreadContext {
    /// Win32 thread id (TID) of the guest thread.
    pub(crate) thread_id: u32,
    /// Win32 thread handle of the guest thread.
    pub(crate) handle: u32,
    /// Windows thread priority (maps to host QoS for a slice).
    pub(crate) priority: i32,
    /// Guest register/flag/FPU state — the thread's architectural machine.
    pub(crate) state: CpuState,
    /// Per-thread JIT control state: return predictor, indirect inline
    /// caches, slice epoch and cumulative metrics.  Cached code entries are
    /// private to the thread; the code itself is process-shared.
    pub(crate) control: SliceThreadState,
    /// Guest TEB base (also the `gs`/`fs` segment base for this thread).
    pub(crate) teb_base: u64,
    /// Guest TLS vector pointer for this thread.
    pub(crate) tls_vector_ptr: u64,
    /// Dynamic TLS slot values for this thread.
    pub(crate) tls_slots: BTreeMap<u32, u64>,
    /// Dynamic FLS slot values for this thread.
    pub(crate) fls_slots: BTreeMap<u32, u64>,
    /// Win32 `GetLastError`/`SetLastError` value.  While a thread runs this is
    /// the live value; it is parked into its TEB at `teb_last_error_offset`
    /// when the guest thread is switched out.
    pub(crate) last_error: u32,
    /// Whether this thread has APCs disabled (inside DLL init, alertable
    /// blocks).  APC queues themselves stay in the runtime's per-TID table
    /// until that subsystem is moved; this flag is the thread-local gate the
    /// delivery path reads.
    pub(crate) apc_disabled: bool,
    /// Pending guest exception code raised by this thread's slice (cleared by
    /// the owner when the exception is delivered).
    pub(crate) pending_exception: Option<u32>,
    /// Dispatcher scratch slots for the slice (never guest-visible, never
    /// shared).  The JIT slice driver may use these for transfer targets.
    pub(crate) dispatch_scratch: [u64; 4],
    /// Completed slice rounds on this context (diagnostics).
    pub(crate) slices: u64,
    /// Native worker that last ran this context (affinity hint).
    pub(crate) worker_index: Option<usize>,
}

/// A point-in-time copy of one guest thread's private state.  The scheduler
/// returns this for a completed slice so the owning (runtime) thread can see
/// the exact registers/TLS/last-error its worker produced without aliasing
/// the persistent worker slot.
#[derive(Debug, Clone)]
pub(crate) struct GuestThreadSnapshot {
    pub(crate) thread_id: u32,
    pub(crate) handle: u32,
    pub(crate) priority: i32,
    pub(crate) state: CpuState,
    pub(crate) teb_base: u64,
    pub(crate) tls_vector_ptr: u64,
    pub(crate) tls_slots: BTreeMap<u32, u64>,
    pub(crate) fls_slots: BTreeMap<u32, u64>,
    pub(crate) last_error: u32,
    pub(crate) apc_disabled: bool,
    pub(crate) pending_exception: Option<u32>,
    pub(crate) slices: u64,
    pub(crate) worker_index: Option<usize>,
}

impl GuestThreadContext {
    /// Create a context for `thread_id` starting from `state`.
    pub(crate) fn new(thread_id: u32, state: CpuState) -> Self {
        Self {
            thread_id,
            handle: thread_id,
            priority: 0,
            state,
            control: SliceThreadState::default(),
            teb_base: 0,
            tls_vector_ptr: 0,
            tls_slots: BTreeMap::new(),
            fls_slots: BTreeMap::new(),
            last_error: 0,
            apc_disabled: false,
            pending_exception: None,
            dispatch_scratch: [0; 4],
            slices: 0,
            worker_index: None,
        }
    }

    /// Build the execution context for a scheduler thread record.  `last_error`
    /// is the value the runtime cached for that thread (the TEB is the
    /// authoritative store across switches).
    pub(crate) fn from_pending(thread: &PendingGuestThread, last_error: u32) -> GuestThreadContext {
        Self {
            thread_id: thread.thread_id,
            handle: thread.handle,
            priority: 0,
            state: thread.state.clone(),
            control: SliceThreadState::default(),
            teb_base: thread.teb_base,
            tls_vector_ptr: thread.tls_vector_ptr,
            tls_slots: thread.tls_slots.clone(),
            fls_slots: thread.fls_slots.clone(),
            last_error,
            apc_disabled: false,
            pending_exception: None,
            dispatch_scratch: [0; 4],
            slices: 0,
            worker_index: None,
        }
    }

    /// Rebuild a runnable context from a completed-slice snapshot, preserving
    /// the thread's identity, TEB/TLS/FLS and last-error across rounds.
    pub(crate) fn from_snapshot(snapshot: &GuestThreadSnapshot) -> GuestThreadContext {
        GuestThreadContext {
            thread_id: snapshot.thread_id,
            handle: snapshot.handle,
            priority: snapshot.priority,
            state: snapshot.state.clone(),
            control: SliceThreadState::default(),
            teb_base: snapshot.teb_base,
            tls_vector_ptr: snapshot.tls_vector_ptr,
            tls_slots: snapshot.tls_slots.clone(),
            fls_slots: snapshot.fls_slots.clone(),
            last_error: snapshot.last_error,
            apc_disabled: snapshot.apc_disabled,
            pending_exception: snapshot.pending_exception,
            dispatch_scratch: [0; 4],
            slices: snapshot.slices,
            worker_index: snapshot.worker_index,
        }
    }

    /// Copy this context's guest-visible execution state back into its
    /// scheduler thread record after a slice round.  `last_error` is kept in
    /// the context; the pump parks it into the TEB on the next switch.
    pub(crate) fn write_back(&self, thread: &mut PendingGuestThread) {
        thread.state = self.state.clone();
        thread.tls_vector_ptr = self.tls_vector_ptr;
        thread.tls_slots = self.tls_slots.clone();
        thread.fls_slots = self.fls_slots.clone();
    }

    /// Adopt the freshly-submitted per-thread state while retaining this
    /// slot's warm JIT control caches and slice counters.  The runtime owner
    /// is authoritative for identity/TLS/last-error; the persistent worker
    /// slot is authoritative for the JIT caches.
    pub(crate) fn adopt(&mut self, fresh: GuestThreadContext) {
        self.thread_id = fresh.thread_id;
        self.handle = fresh.handle;
        self.priority = fresh.priority;
        self.state = fresh.state;
        self.teb_base = fresh.teb_base;
        self.tls_vector_ptr = fresh.tls_vector_ptr;
        self.tls_slots = fresh.tls_slots;
        self.fls_slots = fresh.fls_slots;
        self.last_error = fresh.last_error;
        self.apc_disabled = fresh.apc_disabled;
        self.pending_exception = fresh.pending_exception;
        self.dispatch_scratch = fresh.dispatch_scratch;
    }

    /// The guest stack pointer (per-architecture RSP/ESP).
    pub(crate) fn stack_pointer(&self) -> u64 {
        self.state.get(Register::Rsp)
    }

    /// Read this thread's own last-error value.
    pub(crate) fn last_error(&self) -> u32 {
        self.last_error
    }

    /// Set this thread's last-error value (never another thread's).
    pub(crate) fn set_last_error(&mut self, value: u32) {
        self.last_error = value;
    }

    /// Offset of the last-error slot inside this thread's TEB.
    pub(crate) fn teb_last_error_offset(&self) -> u64 {
        teb_last_error_offset(self.state.arch)
    }

    /// Point-in-time copy for a completed-slice report.
    pub(crate) fn snapshot(&self) -> GuestThreadSnapshot {
        GuestThreadSnapshot {
            thread_id: self.thread_id,
            handle: self.handle,
            priority: self.priority,
            state: self.state.clone(),
            teb_base: self.teb_base,
            tls_vector_ptr: self.tls_vector_ptr,
            tls_slots: self.tls_slots.clone(),
            fls_slots: self.fls_slots.clone(),
            last_error: self.last_error,
            apc_disabled: self.apc_disabled,
            pending_exception: self.pending_exception,
            slices: self.slices,
            worker_index: self.worker_index,
        }
    }
}
