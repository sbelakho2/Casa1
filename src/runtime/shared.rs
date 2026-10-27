//! Process-wide shared state handle for concurrent guest execution.
//!
//! [`ProcessShared`] is the *only* handle a guest-executing host thread needs
//! besides its private [`super::thread_context::GuestThreadContext`].  It
//! owns (or aliases) everything that is process-wide:
//!
//! * the canonical guest memory view ([`crate::jit::GuestSliceProgram`]'s
//!   `GuestSliceMemory`, which aliases the one canonical store the runtime's
//!   `MemoryImage` also uses — no copies),
//! * the process gate: a real mutex that serializes host/subsystem operations
//!   (host thunks, loader, handles, registry, GPU, object manager) so two
//!   guest threads can never mutate process-wide state concurrently,
//! * the cooperative shutdown flag and the published compiled-slice epoch.
//!
//! Guest instructions execute under `(&ProcessShared, &mut GuestThreadContext)`;
//! no closure over `PeHostRuntime` is needed to run translated code.  Guest
//! waits themselves stay on the scheduler's native `ParkSignal`
//! (condition-variable) path; this handle adds no second wait registry.
// Some process-shared primitives (TEB read helpers) are the concurrency API's
// public surface and are exercised by the adversarial scheduler tests even
// where today's host-thunk path still uses its own scheduler-side wait objects.
#![allow(dead_code)]

use crate::jit::{GuestSliceProgram, SliceStop};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Why one concurrent guest slice stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadSliceStop {
    Budget,
    HostBarrier { rip: u64 },
    GuestFault { address: u64, write: bool },
    CodeWrite,
    Safepoint,
    Shutdown,
}

/// Result of running one guest thread slice against the shared process state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestThreadRunReport {
    pub(crate) stop: ThreadSliceStop,
    pub(crate) blocks_executed: u64,
    pub(crate) code_writes: Vec<(u64, usize)>,
    pub(crate) metrics: crate::jit::SliceMetrics,
}

/// The process-wide handle shared by every guest-executing host thread.
pub(crate) struct ProcessShared {
    /// Serializes process-wide operations.  Guest-code slices never hold it;
    /// only a host-thunk/subsystem operation does.
    process_lock: Mutex<()>,
    /// Compiled worker program of the current dispatch round.  The runtime
    /// owner publishes it before submitting a round and clears it after; the
    /// blocks are immutable while published.
    program: RwLock<Option<Arc<GuestSliceProgram>>>,
    /// Cooperative stop for every in-flight and future slice.
    shutdown: AtomicBool,
    /// Slice-cache epoch published with the program (SMC invalidation).
    code_epoch: AtomicU64,
    /// Completed process-gate operations (diagnostics/tests).
    process_ops: AtomicU64,
}

impl std::fmt::Debug for ProcessShared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessShared")
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .field("code_epoch", &self.code_epoch.load(Ordering::Relaxed))
            .field("process_ops", &self.process_ops.load(Ordering::Relaxed))
            .finish()
    }
}

impl Default for ProcessShared {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessShared {
    pub(crate) fn new() -> Self {
        Self {
            process_lock: Mutex::new(()),
            program: RwLock::new(None),
            shutdown: AtomicBool::new(false),
            code_epoch: AtomicU64::new(0),
            process_ops: AtomicU64::new(0),
        }
    }

    /// Publish the compiled program for the next dispatch round.
    pub(crate) fn publish_program(&self, program: Arc<GuestSliceProgram>) {
        self.code_epoch.store(program.epoch, Ordering::Release);
        let mut slot = self
            .program
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(program);
    }

    /// Remove the current round's program (no further slices can start).
    pub(crate) fn clear_program(&self) {
        let mut slot = self
            .program
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = None;
    }

    pub(crate) fn current_program(&self) -> Option<Arc<GuestSliceProgram>> {
        self.program
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn code_epoch(&self) -> u64 {
        self.code_epoch.load(Ordering::Acquire)
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Re-open a process shared handle after its previous pool was dropped.
    pub(crate) fn reopen(&self) {
        self.shutdown.store(false, Ordering::Release);
    }

    pub(crate) fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Run one guest thread's compiled slice.  Takes only the thread's private
    /// context and this process-shared handle: the canonical memory, the
    /// compiled code and every cross-thread concern are reached through here.
    pub(crate) fn run_thread(
        &self,
        context: &mut super::thread_context::GuestThreadContext,
        budget: u64,
    ) -> GuestThreadRunReport {
        let Some(program) = self.current_program() else {
            return GuestThreadRunReport {
                stop: ThreadSliceStop::HostBarrier {
                    rip: context.state.rip,
                },
                blocks_executed: 0,
                code_writes: Vec::new(),
                metrics: context.control.metrics,
            };
        };
        // SAFETY: the published program's blocks are finalized and immutable
        // for the whole published round; the context is exclusively owned by
        // the calling worker; the canonical store is process-stable.
        let report = unsafe {
            crate::jit::run_slice(
                &program,
                &mut context.state,
                &mut context.control,
                budget,
                &self.shutdown,
            )
        };
        context.slices = context.slices.saturating_add(1);
        let stop = match report.stop {
            SliceStop::Budget => ThreadSliceStop::Budget,
            SliceStop::HostBarrier { rip } => ThreadSliceStop::HostBarrier { rip },
            SliceStop::GuestFault { address, write } => {
                ThreadSliceStop::GuestFault { address, write }
            }
            SliceStop::CodeWrite => ThreadSliceStop::CodeWrite,
            SliceStop::Safepoint => ThreadSliceStop::Safepoint,
            SliceStop::Shutdown => ThreadSliceStop::Shutdown,
        };
        GuestThreadRunReport {
            stop,
            blocks_executed: report.blocks_executed,
            code_writes: report.code_writes,
            metrics: report.metrics,
        }
    }

    /// Execute `operation` with the process gate held.  Two guest threads'
    /// host/subsystem operations are mutually exclusive; guest-code slices do
    /// not take the gate, so pure guest code still overlaps.
    pub(crate) fn with_process<R>(&self, operation: impl FnOnce() -> R) -> R {
        let _guard = self
            .process_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = operation();
        self.process_ops.fetch_add(1, Ordering::Relaxed);
        result
    }

    pub(crate) fn process_operations(&self) -> u64 {
        self.process_ops.load(Ordering::Relaxed)
    }

    /// Read guest bytes through the shared canonical store.
    pub(crate) fn guest_read(&self, address: u64, len: usize) -> Option<u64> {
        let program = self.current_program()?;
        program.memory.load(address, len).ok()
    }

    /// Write guest bytes through the shared canonical store.  Returns false
    /// when the range is not fully mapped in the shared view.
    pub(crate) fn guest_write(&self, address: u64, bytes: &[u8]) -> bool {
        let Some(program) = self.current_program() else {
            return false;
        };
        program.memory.store(address, bytes).is_ok()
    }

    /// Read this context's last-error slot from guest TEB memory (the
    /// authoritative per-thread store) through the shared view.
    pub(crate) fn teb_last_error(
        &self,
        context: &super::thread_context::GuestThreadContext,
    ) -> Option<u32> {
        if context.teb_base == 0 {
            return None;
        }
        self.guest_read(
            context.teb_base + super::thread_context::teb_last_error_offset(context.state.arch),
            4,
        )
        .map(|value| value as u32)
    }
}
