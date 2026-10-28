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

use super::HostThunk;
#[path = "dispatch/parallel_api.rs"]
mod parallel_api;
use crate::host_thunks::ThunkConcurrency;
use crate::jit::{GuestSliceProgram, SliceStop};
use parallel_api::WorkerApi;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Guest-visible process identity published for worker-side API calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerIdentity {
    pub(crate) process_id: u32,
    pub(crate) process_handle: u32,
}

/// The process-wide monotonic clock plus the deterministic-time domain.
#[derive(Clone)]
pub(crate) struct WorkerClock {
    pub(crate) clock: Arc<crate::anticheat::MonotonicClock>,
    pub(crate) dtm: bool,
    /// `GetTickCount64` of the deterministic guest clock at publication.
    pub(crate) deterministic_tick_ms: u64,
}

impl Default for WorkerClock {
    fn default() -> Self {
        Self {
            clock: Arc::new(crate::anticheat::MonotonicClock::new()),
            dtm: false,
            deterministic_tick_ms: 0,
        }
    }
}

/// Owner-published Windows version profile for `GetVersion*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerVersion {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) build: u32,
    pub(crate) service_pack_major: u16,
    pub(crate) service_pack_minor: u16,
    pub(crate) suite_mask: u16,
    pub(crate) product_type: u8,
}

/// Owner-published physical/virtual memory figures for `GlobalMemoryStatusEx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerMemoryStatus {
    pub(crate) total_phys: u64,
    pub(crate) avail_phys: u64,
    pub(crate) total_page: u64,
    pub(crate) avail_page: u64,
}

/// Read-mostly process state published for worker API execution.
#[derive(Clone)]
pub(crate) struct WorkerEnvironment {
    pub(crate) identity: WorkerIdentity,
    pub(crate) clock: WorkerClock,
    pub(crate) version: Option<WorkerVersion>,
    pub(crate) memory_status: Option<WorkerMemoryStatus>,
}

/// One registered thunk's worker-execution classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParallelThunk {
    pub(crate) api: Option<WorkerApi>,
    pub(crate) class: ThunkConcurrency,
    pub(crate) x86_arg_bytes: u64,
}

/// Published parallel-versus-barrier API dispatch split.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ApiDispatchMetrics {
    pub(crate) parallel_dispatched: u64,
    pub(crate) barrier_calls: u64,
}

/// Result of a worker's attempt to service a host barrier itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerApiAttempt {
    /// The address is not a registered host thunk (an uncompiled block).
    NotAThunk,
    /// The thunk ran to completion on the worker.
    Executed,
    /// The thunk is owner-only (or its worker path could not reproduce the
    /// owner semantics): run it on the owner barrier.
    Blocked,
}

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
    /// Guest process identity (pid/pseudo-handle) behind its own lock.
    identity: RwLock<WorkerIdentity>,
    /// The monotonic clock and deterministic-time domain behind its own lock.
    clock: RwLock<WorkerClock>,
    /// Published Windows version profile.
    version: RwLock<Option<WorkerVersion>>,
    /// Published host memory figures.
    memory_status: RwLock<Option<WorkerMemoryStatus>>,
    /// Worker-execution classification for every registered host thunk, keyed
    /// by guest thunk address for the current dispatch round.
    thunks: RwLock<BTreeMap<u64, ParallelThunk>>,
    /// Host thunks executed directly on a guest worker.
    parallel_api_calls: AtomicU64,
    /// Host thunks that yielded to the owner barrier.
    barrier_api_calls: AtomicU64,
}

impl std::fmt::Debug for ProcessShared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessShared")
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .field("code_epoch", &self.code_epoch.load(Ordering::Relaxed))
            .field("process_ops", &self.process_ops.load(Ordering::Relaxed))
            .field(
                "parallel_api_calls",
                &self.parallel_api_calls.load(Ordering::Relaxed),
            )
            .field(
                "barrier_api_calls",
                &self.barrier_api_calls.load(Ordering::Relaxed),
            )
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
            identity: RwLock::new(WorkerIdentity {
                process_id: 0,
                process_handle: 0,
            }),
            clock: RwLock::new(WorkerClock::default()),
            version: RwLock::new(None),
            memory_status: RwLock::new(None),
            thunks: RwLock::new(BTreeMap::new()),
            parallel_api_calls: AtomicU64::new(0),
            barrier_api_calls: AtomicU64::new(0),
        }
    }

    /// Publish the owner's read-mostly process state.  The owner is the only
    /// writer; workers take the per-subsystem read locks.
    pub(crate) fn publish_environment(&self, environment: WorkerEnvironment) {
        *self
            .identity
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = environment.identity;
        *self
            .clock
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = environment.clock;
        *self
            .version
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = environment.version;
        *self
            .memory_status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = environment.memory_status;
    }

    /// Replace only the guest process identity (read-mostly writer path).
    #[allow(dead_code)] // direct writer used by concurrency tests
    pub(crate) fn publish_identity(&self, identity: WorkerIdentity) {
        *self
            .identity
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = identity;
    }

    /// Publish the current round's thunk classification table.
    pub(crate) fn publish_parallel_thunks<'a>(
        &self,
        thunks: impl IntoIterator<Item = (u64, &'a HostThunk)>,
    ) {
        let table: BTreeMap<u64, ParallelThunk> = thunks
            .into_iter()
            .map(|(address, thunk)| (address, parallel_thunk(thunk)))
            .collect();
        *self
            .thunks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = table;
    }

    /// Publish one thunk (tests and targeted dispatch setup).
    #[allow(dead_code)] // used by worker-API concurrency tests
    pub(crate) fn publish_thunk(&self, address: u64, thunk: &HostThunk) {
        self.thunks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(address, parallel_thunk(thunk));
    }

    pub(crate) fn parallel_thunk(&self, address: u64) -> Option<ParallelThunk> {
        self.thunks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&address)
            .copied()
    }

    pub(crate) fn identity_snapshot(&self) -> WorkerIdentity {
        *self
            .identity
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn clock_snapshot(&self) -> WorkerClock {
        self.clock
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn version_snapshot(&self) -> Option<WorkerVersion> {
        *self
            .version
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn memory_status_snapshot(&self) -> Option<WorkerMemoryStatus> {
        *self
            .memory_status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Parallel-versus-barrier API dispatch split.
    pub(crate) fn api_dispatch_metrics(&self) -> ApiDispatchMetrics {
        ApiDispatchMetrics {
            parallel_dispatched: self.parallel_api_calls.load(Ordering::Relaxed),
            barrier_calls: self.barrier_api_calls.load(Ordering::Relaxed),
        }
    }

    /// Service a host barrier on the calling worker when the thunk is
    /// classified safe.  The caller must restore its context snapshot when
    /// the attempt is blocked.
    pub(crate) fn run_worker_api(
        &self,
        context: &mut super::thread_context::GuestThreadContext,
        memory: &dyn parallel_api::WorkerMemoryView,
        rip: u64,
    ) -> bool {
        self.try_execute_worker_api(context, memory, rip) == WorkerApiAttempt::Executed
    }

    fn try_execute_worker_api(
        &self,
        context: &mut super::thread_context::GuestThreadContext,
        memory: &dyn parallel_api::WorkerMemoryView,
        rip: u64,
    ) -> WorkerApiAttempt {
        let Some(entry) = self.parallel_thunk(rip) else {
            return WorkerApiAttempt::NotAThunk;
        };
        let saved_state = context.state.clone();
        let saved_last_error = context.last_error;
        if entry.class.allows_worker_execution()
            && parallel_api::invoke_parallel_api(self, context, memory, &entry)
        {
            self.parallel_api_calls.fetch_add(1, Ordering::Relaxed);
            WorkerApiAttempt::Executed
        } else {
            context.state = saved_state;
            context.last_error = saved_last_error;
            self.barrier_api_calls.fetch_add(1, Ordering::Relaxed);
            WorkerApiAttempt::Blocked
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
        let mut blocks_executed = 0_u64;
        let mut code_writes = Vec::new();
        let mut metrics = context.control.metrics;
        let stop = loop {
            let remaining = budget.saturating_sub(blocks_executed);
            if remaining == 0 {
                break ThreadSliceStop::Budget;
            }
            // SAFETY: the published program's blocks are finalized and
            // immutable for the whole published round; the context is
            // exclusively owned by the calling worker; the canonical store is
            // process-stable.
            let report = unsafe {
                crate::jit::run_slice(
                    &program,
                    &mut context.state,
                    &mut context.control,
                    remaining,
                    &self.shutdown,
                )
            };
            blocks_executed = blocks_executed.saturating_add(report.blocks_executed);
            code_writes.extend(report.code_writes);
            metrics = report.metrics;
            match report.stop {
                SliceStop::HostBarrier { rip } => {
                    // The barrier is either a concurrency-safe host thunk we
                    // can execute here, an owner-only thunk (count it and
                    // yield), or a block the worker could not compile
                    // (unchanged barrier semantics).
                    if self.try_execute_worker_api(context, program.memory.as_ref(), rip)
                        == WorkerApiAttempt::Executed
                    {
                        continue;
                    }
                    break ThreadSliceStop::HostBarrier { rip };
                }
                SliceStop::Budget => break ThreadSliceStop::Budget,
                SliceStop::GuestFault { address, write } => {
                    break ThreadSliceStop::GuestFault { address, write };
                }
                SliceStop::CodeWrite => break ThreadSliceStop::CodeWrite,
                SliceStop::Safepoint => break ThreadSliceStop::Safepoint,
                SliceStop::Shutdown => break ThreadSliceStop::Shutdown,
            }
        };
        context.slices = context.slices.saturating_add(1);
        // A safe thunk may have written a code page after the last slice call
        // drained the worker view's write log.
        code_writes.extend(program.memory.take_code_writes());
        GuestThreadRunReport {
            stop,
            blocks_executed,
            code_writes,
            metrics,
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

fn parallel_thunk(thunk: &HostThunk) -> ParallelThunk {
    ParallelThunk {
        api: parallel_api::worker_api(thunk),
        class: parallel_api::thunk_class(thunk),
        x86_arg_bytes: thunk.x86_arg_bytes(),
    }
}
