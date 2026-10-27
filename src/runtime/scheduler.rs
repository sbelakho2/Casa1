//! Cooperative guest scheduler: wait descriptors, satisfiability,
//! wait completion, parking, and the pending-thread pump.
//!
//! # Thread model
//!
//! Guest threads are scheduled cooperatively on the single host thread that
//! drives the run: [`pump_pending_guest_thread`] has `&mut PeHostRuntime`
//! exclusivity, so exactly one guest thread executes guest code at a time and
//! the mode is byte-for-byte deterministic.  A production multi-host-worker
//! mode cannot be layered on this module alone: the runtime is one monolithic
//! `&mut` engine (memory, win32 handles, JIT caches, D3D state), guest threads
//! share it, and `execute_guest_callback_inner` needs exclusive access to all
//! of it.  Worker-pool execution needs cross-file hooks (split `PeHostRuntime`
//! into `Arc`-shared subsystems + a locked guest-memory image, or per-worker
//! engines over shared guest memory) before it can run two guest threads on
//! two host threads without faking concurrency.  This module ships the real
//! scheduler-side half instead: wait/park/resume semantics (including the
//! completion-port wait) plus instrumentation that a pool can use.
use super::*;
use crate::runtime::object_manager::ObjectId;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

// TEB `LastErrorValue` offset for a guest architecture lives with the
// per-thread context (`thread_context.rs`), which is the module that owns
// per-thread execution state.

/// macOS QoS class constants (`sys/qos.h`).
const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
const QOS_CLASS_USER_INITIATED: u32 = 0x19;
const QOS_CLASS_DEFAULT: u32 = 0x15;
const QOS_CLASS_UTILITY: u32 = 0x11;
const QOS_CLASS_BACKGROUND: u32 = 0x09;

unsafe extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    fn pthread_get_qos_class_np(
        thread: *mut libc::c_void,
        qos_class: *mut u32,
        relative_priority: *mut i32,
    ) -> i32;
}

/// Map a Windows `SetThreadPriority` value onto the closest macOS QoS class.
fn qos_class_for_windows_priority(priority: i32) -> u32 {
    if priority >= 15 {
        QOS_CLASS_USER_INTERACTIVE
    } else if priority >= 2 {
        QOS_CLASS_USER_INITIATED
    } else if priority >= 0 {
        QOS_CLASS_DEFAULT
    } else if priority >= -2 {
        QOS_CLASS_UTILITY
    } else {
        QOS_CLASS_BACKGROUND
    }
}

/// Scoped QoS override for a guest thread slice; dropping restores the
/// worker thread's previous class.
struct GuestQosGuard {
    previous_class: u32,
    previous_relative: i32,
}

impl GuestQosGuard {
    fn apply(priority: i32) -> Self {
        let mut previous_class = QOS_CLASS_DEFAULT;
        let mut previous_relative = 0;
        // SAFETY: pthread_get_qos_class_np writes the two out parameters for
        // the calling thread; both pointers are valid.
        unsafe {
            pthread_get_qos_class_np(
                libc::pthread_self() as *mut libc::c_void,
                &raw mut previous_class,
                &raw mut previous_relative,
            );
            pthread_set_qos_class_self_np(qos_class_for_windows_priority(priority), 0);
        }
        Self {
            previous_class,
            previous_relative,
        }
    }
}

impl Drop for GuestQosGuard {
    fn drop(&mut self) {
        // SAFETY: restores the class captured on this same thread.
        unsafe {
            pthread_set_qos_class_self_np(self.previous_class, self.previous_relative);
        }
    }
}

/// Scheduler instrumentation.  Process-wide atomics keep the hot paths
/// lock-free; tests snapshot deltas so concurrently running tests cannot make
/// an absolute assertion flaky.
#[derive(Debug, Default)]
pub(crate) struct SchedulerCounters {
    /// Times the pump switched a host thread onto a runnable guest thread.
    pub(crate) guest_thread_switches: std::sync::atomic::AtomicU64,
    /// Wait descriptors parked through `park_for_wait` (main thread or pump).
    pub(crate) parked_waits: std::sync::atomic::AtomicU64,
    /// Parked completion-port waits resumed by handing a posted packet to the
    /// waiter (the scheduler-level wakeup; the port's own `waiter_wakeups`
    /// counts condition-variable notifies, which parked waits never use).
    pub(crate) completion_port_wakeups: std::sync::atomic::AtomicU64,
    /// Wall nanoseconds guest slices actually ran on host threads.
    pub(crate) host_worker_busy_nanos: std::sync::atomic::AtomicU64,
    /// Distinct host threads that have executed a guest slice.  Cooperative
    /// mode observes exactly the pumping thread; production mode observes one
    /// entry per native pool worker that executed a wait job.
    pub(crate) host_workers: std::sync::Mutex<Vec<std::thread::ThreadId>>,
    /// Real park-signal notifications delivered to a waiting thread (object
    /// signal, completion-port packet, cross-thread signal, APC).
    pub(crate) wakeups: std::sync::atomic::AtomicU64,
    /// Object-manager signal notifications that matched at least one parked
    /// waiter.
    pub(crate) object_wakeups: std::sync::atomic::AtomicU64,
    /// Production waits that completed because their host deadline expired.
    pub(crate) deadline_wakeups: std::sync::atomic::AtomicU64,
    /// Production waits woken by an alertable APC notification.
    pub(crate) apc_wakeups: std::sync::atomic::AtomicU64,
    /// Wait jobs that were re-parked because a wake did not satisfy the wait.
    pub(crate) repark_events: std::sync::atomic::AtomicU64,
    /// Times a wait job was executed by a different host worker than the
    /// guest thread's previous wait job.
    pub(crate) migrations: std::sync::atomic::AtomicU64,
    /// Wait-job starts that overlapped another active wait job (proof that
    /// two native workers held guest threads at the same time).
    pub(crate) worker_overlaps: std::sync::atomic::AtomicU64,
    /// Wait jobs active on native workers right now / high-water mark.
    pub(crate) active_worker_jobs: std::sync::atomic::AtomicU64,
    pub(crate) max_concurrent_worker_jobs: std::sync::atomic::AtomicU64,
    /// Historical cooperative idle-poll counter.  The cooperative pump is now
    /// event-driven and never increments it; production waits must also leave
    /// it untouched.  Retained so diagnostics/tests can prove no 1 ms tick
    /// remains.
    pub(crate) poll_iterations: std::sync::atomic::AtomicU64,
    /// Completion-port slice rechecks (a blocked IOCP wait re-enters the
    /// port's condition variable; never a 1 ms hot-path poll).
    pub(crate) port_rechecks: std::sync::atomic::AtomicU64,
}

/// Point-in-time copy of [`SchedulerCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchedulerCountersSnapshot {
    pub(crate) guest_thread_switches: u64,
    pub(crate) parked_waits: u64,
    pub(crate) completion_port_wakeups: u64,
    pub(crate) host_worker_busy_nanos: u64,
    pub(crate) host_workers_observed: usize,
    pub(crate) wakeups: u64,
    pub(crate) object_wakeups: u64,
    pub(crate) deadline_wakeups: u64,
    pub(crate) apc_wakeups: u64,
    pub(crate) repark_events: u64,
    pub(crate) migrations: u64,
    pub(crate) worker_overlaps: u64,
    pub(crate) active_worker_jobs: u64,
    pub(crate) max_concurrent_worker_jobs: u64,
    pub(crate) poll_iterations: u64,
    pub(crate) port_rechecks: u64,
}

impl SchedulerCounters {
    #[allow(dead_code)] // consumed by scheduler instrumentation tests
    pub(crate) fn snapshot(&self) -> SchedulerCountersSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        SchedulerCountersSnapshot {
            guest_thread_switches: self.guest_thread_switches.load(Relaxed),
            parked_waits: self.parked_waits.load(Relaxed),
            completion_port_wakeups: self.completion_port_wakeups.load(Relaxed),
            host_worker_busy_nanos: self.host_worker_busy_nanos.load(Relaxed),
            host_workers_observed: self
                .host_workers
                .lock()
                .map(|workers| workers.len())
                .unwrap_or(0),
            wakeups: self.wakeups.load(Relaxed),
            object_wakeups: self.object_wakeups.load(Relaxed),
            deadline_wakeups: self.deadline_wakeups.load(Relaxed),
            apc_wakeups: self.apc_wakeups.load(Relaxed),
            repark_events: self.repark_events.load(Relaxed),
            migrations: self.migrations.load(Relaxed),
            worker_overlaps: self.worker_overlaps.load(Relaxed),
            active_worker_jobs: self.active_worker_jobs.load(Relaxed),
            max_concurrent_worker_jobs: self.max_concurrent_worker_jobs.load(Relaxed),
            poll_iterations: self.poll_iterations.load(Relaxed),
            port_rechecks: self.port_rechecks.load(Relaxed),
        }
    }

    fn note_host_worker_slice(&self, elapsed: std::time::Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        self.host_worker_busy_nanos
            .fetch_add(elapsed.as_nanos().min(u128::from(u64::MAX)) as u64, Relaxed);
        let current = std::thread::current().id();
        if let Ok(mut workers) = self.host_workers.lock()
            && !workers.contains(&current)
        {
            workers.push(current);
        }
    }

    #[allow(dead_code)] // consumed by scheduler instrumentation tests
    pub(crate) fn host_worker_observed(&self, thread_id: std::thread::ThreadId) -> bool {
        self.host_workers
            .lock()
            .map(|workers| workers.contains(&thread_id))
            .unwrap_or(false)
    }

    /// Register the calling host thread as a scheduler worker without
    /// charging guest-slice time (a wait job blocks on a condition variable;
    /// that is not guest execution).
    fn note_host_worker_identity(&self) {
        let current = std::thread::current().id();
        if let Ok(mut workers) = self.host_workers.lock()
            && !workers.contains(&current)
        {
            workers.push(current);
        }
    }
}

pub(crate) static SCHEDULER_COUNTERS: SchedulerCounters = SchedulerCounters {
    guest_thread_switches: std::sync::atomic::AtomicU64::new(0),
    parked_waits: std::sync::atomic::AtomicU64::new(0),
    completion_port_wakeups: std::sync::atomic::AtomicU64::new(0),
    host_worker_busy_nanos: std::sync::atomic::AtomicU64::new(0),
    host_workers: std::sync::Mutex::new(Vec::new()),
    wakeups: std::sync::atomic::AtomicU64::new(0),
    object_wakeups: std::sync::atomic::AtomicU64::new(0),
    deadline_wakeups: std::sync::atomic::AtomicU64::new(0),
    apc_wakeups: std::sync::atomic::AtomicU64::new(0),
    repark_events: std::sync::atomic::AtomicU64::new(0),
    migrations: std::sync::atomic::AtomicU64::new(0),
    worker_overlaps: std::sync::atomic::AtomicU64::new(0),
    active_worker_jobs: std::sync::atomic::AtomicU64::new(0),
    max_concurrent_worker_jobs: std::sync::atomic::AtomicU64::new(0),
    poll_iterations: std::sync::atomic::AtomicU64::new(0),
    port_rechecks: std::sync::atomic::AtomicU64::new(0),
};

/// Bounded recheck interval for the cooperative idle pump when no finite
/// guest wait/yield deadline exists.  This is the only fallback tick: a real
/// state transition notifies [`PumpWake`] and wakes the pump immediately, so
/// the wait never polls a fixed 1 ms grid.
const PUMP_IDLE_FALLBACK: Duration = Duration::from_millis(16);

/// Cooperative idle-pump wake signal.
///
/// The pump records the current epoch before evaluating readiness and then
/// blocks on the condition variable with a deadline derived from the earliest
/// guest deadline.  Every path that can make a cooperative thread runnable
/// advances the epoch and notifies, so a wake that arrives before the wait
/// starts is observed by the predicate loop instead of being lost.
///
/// The mutex is held only while inspecting/updating the epoch and while
/// waiting (the condition variable releases it).  It is never held while
/// executing guest code or while taking the runtime's `&mut self`, so there is
/// no scheduler lock around guest execution.
#[derive(Debug)]
struct PumpWake {
    state: Mutex<PumpWakeState>,
    wake: Condvar,
}

#[derive(Debug)]
struct PumpWakeState {
    epoch: u64,
}

/// Result of one idle-pump wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpWakeOutcome {
    /// A notification newer than the observed epoch was delivered.
    Notified { epoch: u64 },
    /// The wait deadline expired without a newer notification.
    TimedOut { epoch: u64 },
}

impl PumpWake {
    const fn new() -> Self {
        Self {
            state: Mutex::new(PumpWakeState { epoch: 0 }),
            wake: Condvar::new(),
        }
    }

    fn epoch(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .epoch
    }

    /// Publish a wake.  The epoch always advances, even with no waiter, so a
    /// notification before the pump starts waiting is not lost.
    fn notify(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.epoch = state.epoch.wrapping_add(1);
        drop(state);
        self.wake.notify_all();
    }

    /// Block until the epoch differs from `observed`, or until `deadline`.
    /// The predicate (`epoch != observed`) is rechecked under the mutex after
    /// every wake, which closes the lost-wakeup window.
    fn wait_until(&self, observed: u64, deadline: Option<Instant>) -> PumpWakeOutcome {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if state.epoch != observed {
                return PumpWakeOutcome::Notified { epoch: state.epoch };
            }
            match deadline {
                None => {
                    state = self
                        .wake
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return PumpWakeOutcome::TimedOut { epoch: state.epoch };
                    }
                    let (guard, _) = self
                        .wake
                        .wait_timeout(state, deadline - now)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state = guard;
                }
            }
        }
    }
}

/// Process-wide cooperative pump wake.  Wakes may originate on native
/// workers, object-manager writers or background timer threads; a spurious
/// wake from another runtime in the same process only causes a readiness
/// recheck, never a semantic change.
static PUMP_WAKE: PumpWake = PumpWake::new();

fn pump_wake() -> &'static PumpWake {
    &PUMP_WAKE
}

/// Advance the cooperative idle-pump epoch and wake a blocked pump.  Safe to
/// call from any host thread; the wake is advisory (the pump always rechecks
/// its predicates under the runtime's exclusive ownership).
pub(crate) fn notify_pump_wake() {
    pump_wake().notify();
}

/// What a parked guest wait is waiting for.  The scheduler resumes the
/// thread only when the descriptor becomes satisfiable — object signals,
/// overlapped completion, pipe connection, completion-port packet, deadline
/// expiry or (alertable) APC delivery.
#[derive(Debug, Clone)]
pub(crate) enum WaitOperation {
    /// Sleep / SleepEx: no objects; resume at the deadline or via APC
    /// (alertable).  An infinite non-alertable sleep never resumes.
    Sleep,
    /// WaitForSingleObject[Ex] / WaitForMultipleObjects[Ex].
    Objects,
    /// GetOverlappedResult(TRUE): resume when the overlapped operation
    /// completes (no deadline — Windows gives this API no timeout).
    Overlapped {
        overlapped_id: u64,
        /// Guest pointer to the `lpNumberOfBytesTransferred` out-parameter.
        bytes_ptr: u64,
    },
    /// Blocking ConnectNamedPipe: resume when a client connects.
    PipeConnect { pipe_handle: u32 },
    /// CallNamedPipeW: resume when the server's response is queued in the
    /// pipe's server-to-client direction (or the server disconnected).
    PipeCall {
        /// Normalized pipe name (state-table key).
        name: String,
        /// Guest pointer to the response buffer (`lpOutBuffer`).
        out_ptr: u64,
        /// Capacity of the response buffer (`nOutBufferSize`).
        out_capacity: u32,
        /// Guest pointer to the bytes-read out-parameter.
        bytes_read_ptr: u64,
    },
    /// Blocking overlapped pipe ReadFile/WriteFile: resume when the pipe's
    /// read-direction queue has data (Read) or immediately (Write).
    PipeIo {
        pipe_handle: u32,
        kind: crate::win32::OverlappedKind,
        /// The typed overlapped request issued for this I/O (0 when the
        /// thunk parked without issuing one); completion is scoped to this
        /// request so sibling requests on the same handle stay pending.
        overlapped_id: u64,
        /// Guest pointer to the I/O buffer.
        buffer_ptr: u64,
        /// Requested transfer length.
        length: u32,
        /// Guest pointer to the bytes-read out-parameter.
        bytes_read_ptr: u64,
    },
    /// WaitNamedPipeW: resume when a server instance becomes available (or
    /// the deadline expires).
    PipeAvailable { name: String },
    /// GetQueuedCompletionStatus: resume when the port hands this guest
    /// thread a packet (or the deadline expires / the port closes).  The
    /// readiness probe is non-consuming and counter-neutral; the packet is
    /// taken with a zero-timeout dequeue on resume, so the shared dispatch
    /// host thread is never host-blocked.
    #[allow(dead_code)] // parked by the runtime's GQCS thunk
    CompletionPort {
        /// Completion-port handle.
        port: u32,
        /// Guest pointer to `lpNumberOfBytesTransferred` (0 when NULL).
        bytes_ptr: u64,
        /// Guest pointer to `lpCompletionKey` (0 when NULL).
        key_ptr: u64,
        /// Guest pointer to `lpOverlapped` (0 when NULL).
        overlapped_ptr: u64,
    },
    /// GetQueuedCompletionStatusEx: the batch form of the wait above.  The
    /// entries buffer uses the documented `OVERLAPPED_ENTRY` layout for the
    /// guest pointer size (32 bytes on x64, 16 on x86).
    #[allow(dead_code)] // parked by the runtime's GQCSEx thunk
    CompletionPortEx {
        /// Completion-port handle.
        port: u32,
        /// Guest pointer to the `OVERLAPPED_ENTRY` array.
        entries_ptr: u64,
        /// Entry capacity (`ulCount`); at least one entry is required.
        entry_count: u32,
        /// Guest pointer to `ulNumEntriesRemoved` (0 when NULL).
        removed_ptr: u64,
    },
}

/// A parked guest wait: the thread, the objects, the policy, the deadline
/// and the alertability, as one scheduler wait descriptor.
#[derive(Debug, Clone)]
pub(crate) struct GuestWait {
    pub(crate) objects: Vec<u32>,
    pub(crate) wait_all: bool,
    /// Guest-clock deadline ticks; `None` = infinite.
    pub(crate) deadline_ticks: Option<u64>,
    pub(crate) alertable: bool,
    pub(crate) operation: WaitOperation,
}

/// The result delivered to a resumed waiter.
#[allow(dead_code)] // wait-resume payload retained for future alertable waits
pub(crate) struct WaitResume {
    /// WAIT_OBJECT_0 (+ index for wait-any) / WAIT_TIMEOUT /
    /// WAIT_IO_COMPLETION / WAIT_ABANDONED_0.
    pub(crate) code: u32,
    /// Bytes transferred (overlapped completions).
    pub(crate) bytes: Option<u32>,
    /// Last-error value to publish on resume.
    pub(crate) last_error: Option<u32>,
}

// Test-only hook run after a completion-port readiness probe reports
// readable, before the pump's consumption pass.  It lets an adversarial test
// deterministically model a concurrent host consumer draining the packet
// between readiness and consumption (the real `Stolen` race).
#[cfg(test)]
thread_local! {
    static READABLE_PROBE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_readable_probe_hook(hook: impl FnOnce() + 'static) {
    READABLE_PROBE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_readable_probe_hook() {
    let hook = READABLE_PROBE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

impl PeHostRuntime {
    /// Non-consuming satisfiability of a parked thread's wait descriptor.
    /// Read-only (`&self`) so it can run inside the readiness scan.
    pub(crate) fn wait_satisfiable(&self, thread: &PendingGuestThread) -> bool {
        let Some(wait) = &thread.wait else {
            return false;
        };
        // Alertable waits complete through APC delivery.
        if wait.alertable
            && self
                .apc_queues
                .get(&u64::from(thread.thread_id))
                .is_some_and(|queue| queue.pending_count() > 0)
        {
            return true;
        }
        // Finite waits complete when the guest clock reaches the deadline.
        if let Some(deadline) = wait.deadline_ticks
            && self.win32.get_tick_count64() >= deadline
        {
            return true;
        }
        match &wait.operation {
            WaitOperation::Sleep => false,
            WaitOperation::Objects => {
                let satisfiable = |handle: &u32| {
                    self.win32
                        .handle_object_type(*handle)
                        .and_then(|object_type| {
                            self.win32.wait_object_satisfiable(
                                *handle,
                                object_type,
                                thread.thread_id,
                            )
                        })
                        .is_ok_and(|satisfaction| {
                            !matches!(satisfaction, crate::win32::WaitSatisfaction::NotSignaled)
                        })
                };
                if wait.wait_all {
                    wait.objects.iter().all(satisfiable)
                } else {
                    wait.objects.iter().any(satisfiable)
                }
            }
            WaitOperation::Overlapped { overlapped_id, .. } => {
                self.win32.overlapped_satisfiable(*overlapped_id)
            }
            WaitOperation::PipeConnect { pipe_handle } => {
                self.win32.pipe_is_connected(*pipe_handle)
            }
            WaitOperation::PipeCall { name, .. } => {
                self.win32.pipe_response_available(name) || self.win32.pipe_call_broken(name)
            }
            WaitOperation::PipeIo {
                pipe_handle,
                kind: crate::win32::OverlappedKind::Read,
                ..
            } => {
                self.win32.pipe_read_available(*pipe_handle)
                    || self.win32.pipe_peer_disconnected(*pipe_handle)
            }
            WaitOperation::PipeIo {
                kind: crate::win32::OverlappedKind::Write,
                ..
            } => true,
            WaitOperation::PipeIo {
                kind:
                    crate::win32::OverlappedKind::Connection
                    | crate::win32::OverlappedKind::DeviceControl,
                ..
            } => false,
            WaitOperation::PipeAvailable { name } => self.win32.named_pipe_server_exists(name),
            WaitOperation::CompletionPort { port, .. }
            | WaitOperation::CompletionPortEx { port, .. } => {
                let readable = self.completion_port_wait_ready(*port, thread.thread_id);
                #[cfg(test)]
                if readable {
                    run_readable_probe_hook();
                }
                readable
            }
        }
    }

    /// Non-consuming completion-port readiness for a parked waiter.  A handle
    /// that no longer resolves (closed, or recycled to another object) can
    /// never hand out a packet, so the waiter must wake and observe
    /// `ERROR_ABANDONED_WAIT_0` instead of sleeping forever.
    fn completion_port_wait_ready(&self, port: u32, guest_thread_id: u32) -> bool {
        match self.win32.completion_port_readable(port, guest_thread_id) {
            Ok(readable) => readable,
            Err(_) => true,
        }
    }
}

impl PeHostRuntime {
    /// Consume the wait atomically and produce the resume result.  Runs in
    /// the pump's run step (no guest code runs between the readiness pass
    /// and this call, so wait-all consumption is atomic).  `memory` lets
    /// pipe completions write their results into the guest buffers the
    /// parking thunk captured.
    pub(crate) fn complete_wait(
        &mut self,
        wait: &GuestWait,
        tid: u32,
        memory: &mut MemoryImage,
    ) -> AppResult<WaitResume> {
        // Alertable waits complete through APC delivery (WAIT_IO_COMPLETION):
        // the readiness pass detected a queued APC; the resume reports it.
        // The APC procs are delivered by the pump's run step before the
        // thread continues.
        if wait.alertable
            && self
                .apc_queues
                .get(&u64::from(tid))
                .is_some_and(|queue| queue.pending_count() > 0)
        {
            return Ok(WaitResume {
                code: crate::win32::WAIT_IO_COMPLETION,
                bytes: None,
                last_error: None,
            });
        }
        if let Some(deadline) = wait.deadline_ticks
            && self.win32.get_tick_count64() >= deadline
        {
            // Pipe waits report their timeout as FALSE + ERROR_SEM_TIMEOUT
            // (CallNamedPipeW / WaitNamedPipeW), everything else as
            // WAIT_TIMEOUT.
            if matches!(
                wait.operation,
                WaitOperation::PipeCall { .. } | WaitOperation::PipeAvailable { .. }
            ) {
                // A timed-out CallNamedPipeW abandons its instance: consume
                // any response that arrived before the deadline so the next
                // call on the same pipe never reads stale bytes.
                if let WaitOperation::PipeCall {
                    name, out_capacity, ..
                } = &wait.operation
                {
                    let _ = self.win32.take_pipe_response(name, *out_capacity);
                }
                return Ok(WaitResume {
                    code: 0,
                    bytes: None,
                    last_error: Some(ERROR_SEM_TIMEOUT),
                });
            }
            // GetQueuedCompletionStatus reports its timeout as FALSE +
            // WAIT_TIMEOUT (the WAIT_* code never becomes the return value).
            if matches!(
                wait.operation,
                WaitOperation::CompletionPort { .. } | WaitOperation::CompletionPortEx { .. }
            ) {
                return Ok(WaitResume {
                    code: 0,
                    bytes: None,
                    last_error: Some(crate::win32::WAIT_TIMEOUT),
                });
            }
            return Ok(WaitResume {
                code: crate::win32::WAIT_TIMEOUT,
                bytes: None,
                last_error: None,
            });
        }
        match &wait.operation {
            WaitOperation::Sleep => Ok(WaitResume {
                code: 0,
                bytes: None,
                last_error: None,
            }),
            WaitOperation::Objects => {
                if wait.wait_all {
                    match self.win32.evaluate_wait_all(&wait.objects, tid)? {
                        Some(status) => Ok(WaitResume {
                            code: status.code(),
                            bytes: None,
                            last_error: None,
                        }),
                        None => Ok(WaitResume {
                            code: crate::win32::WAIT_TIMEOUT,
                            bytes: None,
                            last_error: None,
                        }),
                    }
                } else {
                    for (index, &handle) in wait.objects.iter().enumerate() {
                        let object_type = self.win32.handle_object_type(handle)?;
                        let status =
                            self.win32
                                .wait_for_single_object_instant(handle, object_type, tid)?;
                        if !matches!(status, crate::win32::WaitStatus::Timeout) {
                            return Ok(WaitResume {
                                code: status.code().wrapping_add(index as u32),
                                bytes: None,
                                last_error: None,
                            });
                        }
                    }
                    Ok(WaitResume {
                        code: crate::win32::WAIT_TIMEOUT,
                        bytes: None,
                        last_error: None,
                    })
                }
            }
            WaitOperation::Overlapped {
                overlapped_id,
                bytes_ptr,
            } => {
                // A PENDING typed pipe Read completes from its direction
                // queue (the readiness pass woke us because data arrived or
                // the peer disconnected).
                if let Some(completion) = self.win32.try_complete_pending_pipe_io(*overlapped_id) {
                    if !completion.bytes.is_empty() && completion.buffer_ptr != 0 {
                        memory.map_bytes(completion.buffer_ptr, &completion.bytes);
                    }
                    if completion.bytes_read_ptr != 0 {
                        write_u32(
                            memory,
                            completion.bytes_read_ptr,
                            completion.bytes.len() as u32,
                        );
                    }
                    if *bytes_ptr != 0 {
                        write_u32(memory, *bytes_ptr, completion.bytes.len() as u32);
                    }
                    if completion.broken_pipe {
                        return Ok(WaitResume {
                            code: 0,
                            bytes: None,
                            last_error: Some(ERROR_BROKEN_PIPE),
                        });
                    }
                    return Ok(WaitResume {
                        code: 1, // TRUE
                        bytes: Some(completion.bytes.len() as u32),
                        last_error: None,
                    });
                }
                let result = self.win32.get_overlapped_result(*overlapped_id, false)?;
                if result.completed {
                    if *bytes_ptr != 0 {
                        write_u32(memory, *bytes_ptr, result.bytes_transferred);
                    }
                    Ok(WaitResume {
                        code: 1, // TRUE
                        bytes: Some(result.bytes_transferred),
                        last_error: None,
                    })
                } else if result.cancelled {
                    Ok(WaitResume {
                        code: 0,
                        bytes: None,
                        last_error: Some(ERROR_OPERATION_ABORTED),
                    })
                } else {
                    Ok(WaitResume {
                        code: crate::win32::WAIT_TIMEOUT,
                        bytes: None,
                        last_error: None,
                    })
                }
            }
            WaitOperation::PipeConnect { .. } => Ok(WaitResume {
                code: 1, // TRUE
                bytes: None,
                last_error: None,
            }),
            WaitOperation::PipeCall {
                name,
                out_ptr,
                out_capacity,
                bytes_read_ptr,
            } => {
                // The server disconnected while the caller waited: the call
                // fails with ERROR_BROKEN_PIPE.
                if self.win32.pipe_call_broken(name) {
                    return Ok(WaitResume {
                        code: 0,
                        bytes: None,
                        last_error: Some(ERROR_BROKEN_PIPE),
                    });
                }
                let response = self.win32.take_pipe_response(name, *out_capacity);
                let transferred = response.len().min(*out_capacity as usize);
                if transferred > 0 && *out_ptr != 0 {
                    memory.map_bytes(*out_ptr, &response[..transferred]);
                }
                if *bytes_read_ptr != 0 {
                    write_u32(memory, *bytes_read_ptr, transferred as u32);
                }
                Ok(WaitResume {
                    code: 1, // TRUE
                    bytes: Some(transferred as u32),
                    last_error: None,
                })
            }
            WaitOperation::PipeIo {
                pipe_handle,
                kind: crate::win32::OverlappedKind::Read,
                overlapped_id,
                buffer_ptr,
                length,
                bytes_read_ptr,
            } => {
                if self.win32.pipe_peer_disconnected(*pipe_handle) {
                    // Complete the pending request so a later
                    // GetOverlappedResult does not hang, then report the
                    // broken pipe.
                    let _ = self
                        .win32
                        .try_complete_pending_pipe_io_for_handle(*pipe_handle);
                    return Ok(WaitResume {
                        code: 0,
                        bytes: None,
                        last_error: Some(ERROR_BROKEN_PIPE),
                    });
                }
                let data = self.win32.pipe_read_sync(*pipe_handle, *length as usize);
                let transferred = data.len().min(*length as usize);
                if transferred > 0 && *buffer_ptr != 0 {
                    memory.map_bytes(*buffer_ptr, &data[..transferred]);
                }
                if *bytes_read_ptr != 0 {
                    write_u32(memory, *bytes_read_ptr, transferred as u32);
                }
                self.win32
                    .complete_pipe_io_request_id(*overlapped_id, transferred as u32)?;
                Ok(WaitResume {
                    code: 1, // TRUE
                    bytes: Some(transferred as u32),
                    last_error: None,
                })
            }
            WaitOperation::PipeIo {
                kind: crate::win32::OverlappedKind::Write,
                overlapped_id,
                ..
            } => {
                // The write already appended to the queue at issue time;
                // complete the matching pending request (usually already
                // completed synchronously).
                self.win32.complete_pipe_io_request_id(*overlapped_id, 0)?;
                Ok(WaitResume {
                    code: 1, // TRUE
                    bytes: None,
                    last_error: None,
                })
            }
            WaitOperation::PipeIo {
                kind:
                    crate::win32::OverlappedKind::Connection
                    | crate::win32::OverlappedKind::DeviceControl,
                ..
            } => Ok(WaitResume {
                code: crate::win32::WAIT_TIMEOUT,
                bytes: None,
                last_error: None,
            }),
            WaitOperation::PipeAvailable { .. } => Ok(WaitResume {
                code: 1, // TRUE
                bytes: None,
                last_error: None,
            }),
            WaitOperation::CompletionPort { .. } | WaitOperation::CompletionPortEx { .. } => {
                match self.take_completion_port_resume(&wait.operation, tid, memory)? {
                    Some(resume) => Ok(resume),
                    // The ready state was lost between the readiness pass
                    // and consumption (a real host-side consumer drained the
                    // port); the pump re-parks on this outcome.
                    None => Ok(WaitResume {
                        code: 0,
                        bytes: None,
                        last_error: Some(crate::win32::WAIT_TIMEOUT),
                    }),
                }
            }
        }
    }

    /// Consume one ready completion-port wait with a zero-timeout dequeue and
    /// build the resume result, writing the guest out-parameters.  `None`
    /// means the port had no packet left to hand out (the waiter must be
    /// re-parked, not resumed).  Runs with the waiter's guest-thread identity
    /// installed so the port's associated-thread concurrency accounting sees
    /// the right thread; never blocks the host thread.
    fn take_completion_port_resume(
        &mut self,
        operation: &WaitOperation,
        tid: u32,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<WaitResume>> {
        let previous_tid = self.win32.set_current_thread_id(tid);
        let outcome = self.dequeue_completion_port_resume(operation, memory);
        self.win32.set_current_thread_id(previous_tid);
        outcome
    }

    fn dequeue_completion_port_resume(
        &mut self,
        operation: &WaitOperation,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<WaitResume>> {
        use std::sync::atomic::Ordering::Relaxed;
        match operation {
            WaitOperation::CompletionPort {
                port,
                bytes_ptr,
                key_ptr,
                overlapped_ptr,
            } => match self.win32.get_queued_completion_status(*port, 0) {
                Ok(crate::win32::CompletionPortWaitOutcome::Packets(packets)) => {
                    let Some(packet) = packets.into_iter().next() else {
                        return Ok(None);
                    };
                    if *bytes_ptr != 0 {
                        write_u32(memory, *bytes_ptr, packet.bytes_transferred);
                    }
                    if *key_ptr != 0 {
                        write_guest_pointer(
                            memory,
                            *key_ptr,
                            packet.completion_key,
                            self.guest_arch,
                        )?;
                    }
                    if *overlapped_ptr != 0 {
                        write_guest_pointer(
                            memory,
                            *overlapped_ptr,
                            packet.overlapped,
                            self.guest_arch,
                        )?;
                    }
                    SCHEDULER_COUNTERS
                        .completion_port_wakeups
                        .fetch_add(1, Relaxed);
                    Ok(Some(WaitResume {
                        code: 1, // TRUE
                        bytes: Some(packet.bytes_transferred),
                        last_error: None,
                    }))
                }
                Ok(crate::win32::CompletionPortWaitOutcome::TimedOut) => Ok(None),
                Ok(crate::win32::CompletionPortWaitOutcome::Closed) | Err(_) => {
                    Ok(Some(Self::completion_port_closed_resume()))
                }
            },
            WaitOperation::CompletionPortEx {
                port,
                entries_ptr,
                entry_count,
                removed_ptr,
            } => match self.win32.get_queued_completion_status_ex(
                *port,
                (*entry_count).max(1) as usize,
                0,
            ) {
                Ok(crate::win32::CompletionPortWaitOutcome::Packets(packets))
                    if !packets.is_empty() =>
                {
                    let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
                    let entry_stride = pointer_bytes * 4;
                    for (index, packet) in packets.iter().enumerate() {
                        if *entries_ptr == 0 {
                            break;
                        }
                        let entry = *entries_ptr + index as u64 * entry_stride;
                        write_guest_pointer(memory, entry, packet.completion_key, self.guest_arch)?;
                        write_guest_pointer(
                            memory,
                            entry + pointer_bytes,
                            packet.overlapped,
                            self.guest_arch,
                        )?;
                        write_guest_pointer(
                            memory,
                            entry + pointer_bytes * 2,
                            packet.internal,
                            self.guest_arch,
                        )?;
                        write_u32(memory, entry + pointer_bytes * 3, packet.bytes_transferred);
                    }
                    if *removed_ptr != 0 {
                        write_u32(memory, *removed_ptr, packets.len() as u32);
                    }
                    SCHEDULER_COUNTERS
                        .completion_port_wakeups
                        .fetch_add(1, Relaxed);
                    Ok(Some(WaitResume {
                        code: 1, // TRUE
                        bytes: Some(packets.len() as u32),
                        last_error: None,
                    }))
                }
                Ok(crate::win32::CompletionPortWaitOutcome::Packets(_)) => Ok(None),
                Ok(crate::win32::CompletionPortWaitOutcome::TimedOut) => Ok(None),
                Ok(crate::win32::CompletionPortWaitOutcome::Closed) | Err(_) => {
                    Ok(Some(Self::completion_port_closed_resume()))
                }
            },
            _ => Ok(None),
        }
    }

    fn completion_port_closed_resume() -> WaitResume {
        WaitResume {
            code: 0,
            bytes: None,
            last_error: Some(crate::win32::ERROR_ABANDONED_WAIT_0),
        }
    }
}

impl PeHostRuntime {
    /// Park the current thread in the scheduler wait queue with `wait`.
    ///
    /// Pumped threads park via the cooperative-yield machinery (the pump
    /// requeues them with the descriptor).  The main loop's thread parks
    /// directly in the queue; the main loop then switches to pump-driven
    /// mode (see `run_pump_driven`) until the run ends.
    /// Park a pumped guest thread on a native worker when its wait has an
    /// event source.  Returns `None` after queueing the record (completion
    /// owns it), or the record itself when cooperative parking is required.
    fn park_pumped_thread_in_production(
        &mut self,
        mut pending_thread: PendingGuestThread,
    ) -> Option<PendingGuestThread> {
        pending_thread.state_machine = GuestThreadState::Waiting;
        let started = pending_thread
            .wait
            .as_ref()
            .is_some_and(|wait| self.start_production_wait(pending_thread.thread_id, wait));
        if started {
            self.pending_guest_threads.push_back(pending_thread);
            notify_pump_wake();
            None
        } else {
            Some(pending_thread)
        }
    }

    /// Last error recorded for a guest thread: its TEB when it has one, or
    /// the TEB-less fallback store used by synthetic harness threads.
    #[cfg(test)]
    pub(crate) fn guest_thread_last_error(
        &self,
        thread_id: u32,
        memory: &MemoryImage,
    ) -> Option<u32> {
        let thread = self
            .pending_guest_threads
            .iter()
            .rev()
            .find(|thread| thread.thread_id == thread_id);
        match thread {
            Some(thread) if thread.teb_base != 0 => memory
                .read_u32(thread.teb_base + teb_last_error_offset(self.guest_arch))
                .ok(),
            _ => self.fallback_last_errors.get(&thread_id).copied(),
        }
    }

    pub(crate) fn park_for_wait(&mut self, state: &mut CpuState, wait: GuestWait) {
        SCHEDULER_COUNTERS
            .parked_waits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.active_pumped_guest_thread.is_some() {
            self.pump_yield_with_wait = Some(wait);
            self.yield_pumped_guest_thread = true;
            return;
        }
        let handle = self.win32.current_thread_handle();
        let thread_id = self.win32.current_thread_id();
        let rsp = state.get(Register::Rsp);
        // In production mode the thread is parked on a native worker with a
        // real wake source; the record still lives in the pending queue so
        // suspend/terminate bookkeeping observes it.
        let _ = self.start_production_wait(thread_id, &wait);
        self.pending_guest_threads.push_back(PendingGuestThread {
            handle,
            thread_id,
            start_address: state.rip,
            parameter: 0,
            initial_rsp: rsp,
            started: true,
            suspended: 0,
            wake_tick: 0,
            teb_base: self.teb_base,
            tls_vector_ptr: self.tls_vector_ptr,
            tls_slots: self.tls_slots.clone(),
            fls_slots: self.fls_slots.clone(),
            state: state.clone(),
            state_machine: GuestThreadState::Waiting,
            exit_code_override: None,
            wait: Some(wait),
            wait_resume: None,
        });
        self.main_thread_parked = true;
        notify_pump_wake();
    }
}

impl PeHostRuntime {
    /// Pump-driven execution mode: the main thread is parked in the wait
    /// queue.  Run runnable guest threads, service timers/APCs, and advance
    /// the guest clock; the HOST blocks only when nothing is runnable, and
    /// wakes on a scheduler notification or the earliest guest deadline
    /// (never on a fixed 1 ms tick).  Returns the process exit code when the
    /// run ends (including the run deadline, which is harness cancellation —
    /// never a fake wait result).
    pub(crate) fn run_pump_driven(
        &mut self,
        memory: &mut MemoryImage,
        _steps: &mut u64,
        _instruction_budget: u64,
    ) -> AppResult<i32> {
        let mut exit_code = 0_i32;
        // Scratch guest state for timer-callback dispatch (the parked main
        // thread lives in the wait queue; timer callbacks run against this
        // throwaway context, matching the main loop's usage).
        let mut scratch_state = CpuState::new(self.guest_arch);
        scratch_state.segment_bases.fs = self.teb_base;
        loop {
            // Observe the wake epoch BEFORE evaluating readiness.  A
            // notification that arrives after this read advances the epoch,
            // so the idle wait below returns immediately instead of blocking
            // through the event; notifications that arrived before this read
            // are visible to the readiness checks below.  Together they close
            // the lost-wakeup window without a fixed polling tick.
            let wake_epoch = pump_wake().epoch();
            if RUN_DEADLINE_EXPIRED.load(std::sync::atomic::Ordering::Acquire) {
                crate::live::live_trace(
                    "[pe] run deadline reached in pump-driven mode — ending run with exit -2",
                );
                return Ok(-2);
            }
            // Terminated/detached threads no longer own a production wait;
            // then apply every native-worker completion (a woken thread runs
            // in this same iteration).
            self.prune_orphan_production_waits();
            if self.reap_production_completions(memory)? {
                continue;
            }
            let pump_outcome = self.pump_pending_guest_thread(memory)?;
            if let Some(code) = pump_outcome.process_exit {
                exit_code = code;
                break;
            }
            if self.pending_guest_threads.is_empty() && self.production_waits.is_empty() {
                // All threads exited (the main thread's exit is reported as
                // process_exit by the pump; this is the belt-and-braces end).
                break;
            }
            if self.poll_guest_timers()? {
                continue;
            }
            if self.drain_timer_work_queue(&mut scratch_state, memory)? {
                if let Some(code) = self.process_exit_requested {
                    exit_code = code as i32;
                    break;
                }
                continue;
            }
            if !pump_outcome.did_work {
                let cooperative_pending = self
                    .pending_guest_threads
                    .iter()
                    .any(|thread| !self.production_waits.contains_key(&thread.thread_id));
                if !self.production_waits.is_empty() && !cooperative_pending {
                    // Every parked thread is on a native worker: block on the
                    // completion condition variable.  The timeout is
                    // housekeeping only (run-deadline/timer/APC servicing);
                    // real wakeups are posted immediately by the workers.
                    let wait_started = Instant::now();
                    if let Some(scheduler) = self.production_scheduler.as_ref() {
                        let _ = scheduler.wait_for_completion(Some(PRODUCTION_HOUSEKEEPING));
                    }
                    let elapsed_ms =
                        wait_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                    if elapsed_ms > 0 {
                        self.win32.record_sleep_observation(elapsed_ms, elapsed_ms);
                    }
                } else {
                    // Nothing runnable and at least one cooperative wait:
                    // block until a scheduler notification or the earliest
                    // guest deadline.  Infinite waits use the bounded
                    // housekeeping fallback — there is no 1 ms tick.
                    let deadline = self
                        .next_cooperative_wake_deadline()
                        .unwrap_or_else(|| Instant::now() + PUMP_IDLE_FALLBACK);
                    let wait_started = Instant::now();
                    let _ = pump_wake().wait_until(wake_epoch, Some(deadline));
                    let elapsed_ms =
                        wait_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                    // Guest-visible time passed while the host waited; advance
                    // the guest clock by the observed host interval so finite
                    // deadlines progress without a polling tick.
                    if elapsed_ms > 0 {
                        self.win32.record_sleep_observation(elapsed_ms, elapsed_ms);
                    }
                }
            }
        }
        Ok(exit_code)
    }

    /// Host deadline of the earliest cooperative wake that is still in the
    /// future: a parked wait's guest timeout, a plain timeslice yield, or the
    /// next `SetTimer` expiry.  `None` means every pending cooperative wait is
    /// infinite and no guest timer is armed, so the idle pump uses its bounded
    /// housekeeping fallback instead.
    fn next_cooperative_wake_deadline(&self) -> Option<Instant> {
        let now_tick = self.win32.get_tick_count64();
        let host_now = Instant::now();
        let mut earliest: Option<Instant> = None;
        for thread in &self.pending_guest_threads {
            if self.production_waits.contains_key(&thread.thread_id) {
                continue;
            }
            let tick = match (&thread.wait, thread.state_machine) {
                (Some(wait), _) => wait.deadline_ticks,
                (None, GuestThreadState::Waiting | GuestThreadState::AlertableWaiting) => {
                    Some(thread.wake_tick)
                }
                _ => None,
            };
            let Some(tick) = tick else { continue };
            // An already-due tick would make the idle wait return instantly
            // forever; the readiness pass owns that transition (suspension and
            // exit gates included).
            if tick <= now_tick {
                continue;
            }
            let remaining = Duration::from_millis(tick.saturating_sub(now_tick));
            let candidate = host_now
                .checked_add(remaining)
                .unwrap_or_else(|| host_now + Duration::from_secs(24 * 60 * 60));
            if earliest.is_none_or(|current| candidate < current) {
                earliest = Some(candidate);
            }
        }
        // Guest `SetTimer` deadlines are cached by user32 (O(1) query), so the
        // idle pump includes them without scanning the timer table per block.
        if let Some(timeout) = self.user32.next_timer_timeout() {
            let candidate = host_now
                .checked_add(timeout)
                .unwrap_or_else(|| host_now + Duration::from_secs(24 * 60 * 60));
            if earliest.is_none_or(|current| candidate < current) {
                earliest = Some(candidate);
            }
        }
        earliest
    }
}

/// Outcome of the pre-run completion-port consumption pass.
enum CompletionPortPreconsume {
    /// The wait is not a completion-port wait (or completed through the
    /// deadline/APC channels): the normal `complete_wait` path handles it.
    Deferred,
    /// A packet was dequeued and the guest out-parameters were written.
    Resume(WaitResume),
    /// The readiness probe said the port was readable, but a concurrent
    /// consumer drained it before this pass: re-park instead of resuming.
    Stolen,
}

impl PeHostRuntime {
    /// Re-park a waiter whose completion packet was stolen between the
    /// readiness pass and the consumption pass.  No guest code ran; the
    /// enqueue and wake notification keep an idle pump aware of the
    /// transition.
    fn repark_stolen_completion_port_wait(
        &mut self,
        mut thread: PendingGuestThread,
    ) -> PumpOutcome {
        thread.state_machine = GuestThreadState::Waiting;
        self.pending_guest_threads.push_back(thread);
        notify_pump_wake();
        PumpOutcome {
            did_work: false,
            process_exit: None,
        }
    }

    /// Consume a ready completion-port wait before the pump mutates any state
    /// (see [`CompletionPortPreconsume`]).  Never host-blocks: the packet is
    /// taken with a zero-timeout dequeue.
    fn preconsume_completion_port_wait(
        &mut self,
        thread: &PendingGuestThread,
        memory: &mut MemoryImage,
    ) -> AppResult<CompletionPortPreconsume> {
        // A production completion already consumed the packet and recorded
        // the exact resume result: never consume a second packet here.
        if thread.wait_resume.is_some() {
            return Ok(CompletionPortPreconsume::Deferred);
        }
        let Some(wait) = thread.wait.as_ref() else {
            return Ok(CompletionPortPreconsume::Deferred);
        };
        if !matches!(
            wait.operation,
            WaitOperation::CompletionPort { .. } | WaitOperation::CompletionPortEx { .. }
        ) {
            return Ok(CompletionPortPreconsume::Deferred);
        }
        // Alertable APC delivery and deadline expiry take precedence over a
        // queued packet; `complete_wait` reports those results.
        if wait.alertable
            && self
                .apc_queues
                .get(&u64::from(thread.thread_id))
                .is_some_and(|queue| queue.pending_count() > 0)
        {
            return Ok(CompletionPortPreconsume::Deferred);
        }
        if let Some(deadline) = wait.deadline_ticks
            && self.win32.get_tick_count64() >= deadline
        {
            return Ok(CompletionPortPreconsume::Deferred);
        }
        match self.take_completion_port_resume(&wait.operation, thread.thread_id, memory)? {
            Some(resume) => Ok(CompletionPortPreconsume::Resume(resume)),
            None => Ok(CompletionPortPreconsume::Stolen),
        }
    }
}

/// Outcome of a `pump_pending_guest_thread` cycle.
pub(crate) struct PumpOutcome {
    /// Whether a guest thread was pumped (ran for a slice).
    pub(crate) did_work: bool,
    /// Process-exit code requested from within a pumped thread; when set the
    /// caller must propagate it as a thunk `Some(code)` result so the main
    /// loop terminates the guest run.
    pub(crate) process_exit: Option<i32>,
}

/// Per-thread result of a pump cycle, transferring the (possibly re-queued)
/// thread record and any process-exit request back to the pump's tail.
pub(crate) struct PumpedThreadOutcome {
    pub(crate) requeue: Option<PendingGuestThread>,
    pub(crate) process_exit: Option<i32>,
}

impl PeHostRuntime {
    /// Enqueue a guest thread that has just become pending and publish the
    /// scheduler wake.  Runtime-side thread creation goes through this helper
    /// so an idle cooperative pump cannot miss a newly created thread.
    pub(crate) fn enqueue_pending_guest_thread(&mut self, thread: PendingGuestThread) {
        self.pending_guest_threads.push_back(thread);
        notify_pump_wake();
    }

    /// Copy the subsystem's suspend count (the single source of truth) into
    /// the scheduler's pending-thread record for `thread_handle`.
    ///
    /// Called after every Win32/Nt suspend/resume mutation: the subsystem
    /// counter (`Win32Subsystem::suspend_thread` / `resume_thread`) is the
    /// ONLY place suspension is changed, and the per-thread scheduler record
    /// mirrors it, so the pump gate (`thread.suspended == 0`) can never
    /// disagree with the subsystem state.
    pub(crate) fn sync_pending_thread_suspend_count(&mut self, thread_handle: u32) {
        let Ok(thread_id) = self.win32.thread_id_for_handle(thread_handle) else {
            return;
        };
        let Ok(count) = self.win32.thread_suspend_count(thread_id) else {
            return;
        };
        for thread in &mut self.pending_guest_threads {
            if thread.thread_id == thread_id {
                let changed = thread.suspended != count;
                thread.suspended = count;
                if changed {
                    // A suspended thread becoming runnable is a progress
                    // transition: wake an idle pump instead of waiting for a
                    // fallback tick.
                    notify_pump_wake();
                }
                return;
            }
        }
    }

    pub(crate) fn pump_pending_guest_thread(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<PumpOutcome> {
        // Production mode: run compiled guest-code slices on native workers
        // first.  Threads that reach a host barrier are left for the
        // cooperative owner path below (thunk serialization).
        if let Some(outcome) = self.try_pump_parallel_slices(memory)? {
            return Ok(outcome);
        }
        let now = self.win32.get_tick_count64();
        // The state machine drives readiness: `Runnable` threads are ready;
        // `Waiting`/`AlertableWaiting` threads are only ready once their
        // wake_tick has expired; `Exiting` threads are mid-teardown inside
        // their own pump cycle (they never sit in the queue across cycles)
        // and `Exited` threads are gone.  A thread whose subsystem state has
        // already recorded an exit code is skipped REGARDLESS of its suspend
        // count — a terminated thread must never start, even if its
        // suspension was never released (and suspend/resume on it already
        // fails, so the counters can only stay put).
        let Some(ready_index) = self.pending_guest_threads.iter().position(|thread| {
            if self.production_waits.contains_key(&thread.thread_id) {
                // Parked on a native production worker: the completion pass
                // owns its readiness, not the cooperative predicate.
                return false;
            }
            thread.suspended == 0
                && !self.win32.thread_has_exited(thread.thread_id)
                && match thread.state_machine {
                    GuestThreadState::Waiting | GuestThreadState::AlertableWaiting => {
                        if thread.wait.is_some() {
                            // Scheduler wait descriptor: ready when the
                            // descriptor is satisfiable (non-consuming pass —
                            // the atomic consumption happens in the run step,
                            // and no guest code runs in between, so another
                            // waiter cannot steal the set).
                            self.wait_satisfiable(thread)
                        } else {
                            // Plain timeslice yield: ready at wake_tick.
                            thread.wake_tick <= now
                        }
                    }
                    GuestThreadState::Runnable => true,
                    GuestThreadState::Exiting | GuestThreadState::Exited => false,
                }
        }) else {
            return Ok(PumpOutcome {
                did_work: false,
                process_exit: None,
            });
        };
        let Some(mut pending_thread) = self.pending_guest_threads.remove(ready_index) else {
            return Ok(PumpOutcome {
                did_work: false,
                process_exit: None,
            });
        };

        // Completion-port waits consume their packet here, before any pump
        // state is mutated: if a concurrent host-side consumer drained the
        // port between the readiness pass and this point, the thread is
        // re-parked and the pump reports no work rather than resuming the
        // guest with a fabricated result.  Timeout and APC completion stay
        // with `complete_wait` so their precedence is exact.
        let preconsumed = self.preconsume_completion_port_wait(&pending_thread, memory)?;
        if matches!(preconsumed, CompletionPortPreconsume::Stolen) {
            return Ok(self.repark_stolen_completion_port_wait(pending_thread));
        }

        let previous_thread_id = self.win32.set_current_thread_id(pending_thread.thread_id);
        let previous_teb_base = self.teb_base;
        // Windows GetLastError/SetLastError are per-thread: the live value is
        // cached in `self.last_error` while a guest thread runs and parked in
        // its TEB (x64 +0x68, x86 +0x34) across a scheduler switch.
        let previous_last_error = self.last_error;
        if previous_teb_base != 0 {
            let _ = memory.write_u32(
                previous_teb_base + teb_last_error_offset(self.guest_arch),
                previous_last_error,
            );
        }
        let pumped_teb_base = pending_thread.teb_base;
        let pumped_thread_id = pending_thread.thread_id;
        let previous_tls_vector_ptr = self.tls_vector_ptr;
        let previous_tls_slots = self.tls_slots.clone();
        let previous_fls_slots = self.fls_slots.clone();
        // Nested pumps (GetMessageW → pump → thunk → pump) must restore the
        // outer pumped thread's identity, yield request and exit request;
        // otherwise a nested pump clobbers the outer thread's state.
        let previous_active_thread = self.active_pumped_guest_thread;
        let previous_yield_request = std::mem::replace(&mut self.yield_pumped_guest_thread, false);
        let previous_yield_wake_tick = self.yield_pumped_guest_thread_wake_tick.take();
        let previous_exit_request = self.pumped_thread_exit_requested.take();
        let previous_exit_detach =
            std::mem::replace(&mut self.pumped_thread_exit_with_detach, true);
        self.active_pumped_guest_thread = Some(pending_thread.handle);
        pending_thread.state_machine = GuestThreadState::Runnable;
        SCHEDULER_COUNTERS
            .guest_thread_switches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Use a regular block instead of an IIFE closure to save one stack frame
        // per recursion level in the GetMessageW → pump → execute_guest_callback_inner
        // → dispatch_import chain.
        let result = {
            self.teb_base = pending_thread.teb_base;
            self.last_error = if pending_thread.teb_base != 0 {
                memory
                    .read_u32(pending_thread.teb_base + teb_last_error_offset(self.guest_arch))
                    .unwrap_or(0)
            } else {
                self.fallback_last_errors
                    .get(&pumped_thread_id)
                    .copied()
                    .unwrap_or(0)
            };
            self.tls_vector_ptr = pending_thread.tls_vector_ptr;
            self.tls_slots = pending_thread.tls_slots.clone();
            self.fls_slots = pending_thread.fls_slots.clone();
            for (&slot, &value) in &self.tls_slots {
                self.sync_guest_tls_slot(memory, slot, value)?;
            }

            // Fire TLS thread-attach callbacks for all loaded modules.
            // These run in the context of the new thread, before the thread's
            // start function executes — matching Windows TLS callback ordering.
            {
                let mut tls_state = CpuState::new(GuestArch::X86);
                tls_state.segment_bases.fs = self.teb_base;
                // TLS callbacks run on the thread's own stack: a zeroed RSP
                // would wrap the synthetic callback frame to an unmapped
                // high address (the x86 CPU masks RSP to 32 bits while the
                // frame is written at the raw u64).  Place the frame 0x100
                // bytes below the thread's initial frame pointer instead.
                if self.guest_arch == GuestArch::X86 {
                    tls_state.set(
                        Register::Rsp,
                        pending_thread.initial_rsp.saturating_sub(0x100),
                    );
                }
                self.fire_tls_callbacks_for_all_modules(&mut tls_state, memory, DLL_THREAD_ATTACH)?;
            }

            let resume_rsp = pending_thread.started.then_some(pending_thread.initial_rsp);
            pending_thread.started = true;

            // Scheduler wait resume: the readiness pass determined the
            // descriptor is satisfiable; consume it atomically and apply the
            // result (RAX + last_error), then run the thread.  A production
            // worker may already have recorded the resume result; that path
            // must not re-consume the wait.
            let _resumed_from_wait = if let Some(resume) = pending_thread.wait_resume.take() {
                let wait = pending_thread.wait.take();
                if wait.as_ref().is_some_and(|wait| wait.alertable)
                    && resume.code == crate::win32::WAIT_IO_COMPLETION
                {
                    let continue_rip = pending_thread.state.rip;
                    let _ = self.deliver_current_thread_apcs(&mut pending_thread.state, memory)?;
                    pending_thread.state.rip = continue_rip;
                }
                pending_thread
                    .state
                    .set(Register::Rax, u64::from(resume.code));
                if let Some(error) = resume.last_error {
                    self.last_error = error;
                } else {
                    self.last_error = 0;
                }
                wait
            } else if let Some(wait) = pending_thread.wait.take() {
                let tid = pending_thread.thread_id;
                let resume = match preconsumed {
                    CompletionPortPreconsume::Resume(resume) => resume,
                    _ => self.complete_wait(&wait, tid, memory)?,
                };
                // Alertable waits complete via APC delivery: deliver queued
                // APCs in the thread's context before the wait result is
                // published (Windows runs the APC, then the wait reports
                // WAIT_IO_COMPLETION).
                if resume.code == crate::win32::WAIT_IO_COMPLETION {
                    // The APC procs run in the thread's context via the
                    // callback machinery, which ends with RIP at the
                    // synthetic return sentinel (0); restore the waiter's
                    // continuation address so it resumes after the wait
                    // call once delivery completes.
                    let continue_rip = pending_thread.state.rip;
                    let _ = self.deliver_current_thread_apcs(&mut pending_thread.state, memory)?;
                    pending_thread.state.rip = continue_rip;
                }
                pending_thread
                    .state
                    .set(Register::Rax, u64::from(resume.code));
                if let Some(error) = resume.last_error {
                    self.last_error = error;
                } else {
                    self.last_error = 0;
                }
                Some(wait)
            } else {
                None
            };

            // An ATTACH TLS callback may have called an explicit exit API
            // (ExitThread/_endthreadex/_endthread/TerminateThread on self)
            // before the thread's start routine ran.  Windows never runs the
            // start routine in that case (the thread was created and then
            // immediately exited), so skip the entry entirely — the
            // explicit-exit path below ends the thread without executing a
            // single entry slice.
            let exit_requested_by_attach = self.pumped_thread_exit_requested;
            let slice_started = std::time::Instant::now();
            let disposition = if let Some(code) = exit_requested_by_attach {
                GuestCallbackDisposition::Returned(code as u64)
            } else {
                self.execute_guest_callback_inner(
                    &mut pending_thread.state,
                    memory,
                    pending_thread.start_address,
                    &[pending_thread.parameter],
                    &format!(
                        "CreateThread thread_id={} start_address={:#x}",
                        pending_thread.thread_id, pending_thread.start_address
                    ),
                    true,
                    resume_rsp,
                )?
            };
            SCHEDULER_COUNTERS.note_host_worker_slice(slice_started.elapsed());

            // An explicit exit API (ExitThread/_endthreadex/_endthread/
            // TerminateThread) recorded its request in the runtime fields
            // before returning, so the pump can distinguish an explicit exit
            // (noreturn; exit-code override wins) from a plain return.
            let explicit_exit = self.pumped_thread_exit_requested.take();
            let explicit_exit_detach =
                std::mem::replace(&mut self.pumped_thread_exit_with_detach, true);
            let process_exit_pending = self.process_exit_requested.is_some();

            if process_exit_pending {
                // A process-exit API (ExitProcess / exit / _exit / abort /
                // TerminateProcess on the process) ran inside this pumped
                // thread.  Windows does not fire DLL_THREAD_DETACH for
                // threads during process exit; abandon every queued guest
                // thread and propagate the code to the main loop (which
                // breaks on a thunk's `Some(code)` result).
                for thread in &mut self.pending_guest_threads {
                    thread.state_machine = GuestThreadState::Exited;
                }
                self.pending_guest_threads.clear();
                pending_thread.state_machine = GuestThreadState::Exited;
                let code = match disposition {
                    GuestCallbackDisposition::Returned(exit_code) => exit_code as i32,
                    GuestCallbackDisposition::Yielded => {
                        self.process_exit_requested.unwrap_or(0) as i32
                    }
                };
                Ok((
                    PumpedThreadOutcome {
                        requeue: None,
                        process_exit: Some(code),
                    },
                    self.tls_slots.clone(),
                    self.fls_slots.clone(),
                ))
            } else if let Some(exit_code) = explicit_exit {
                // Explicit thread exit: the exit thunk is noreturn, so the
                // thread ends here.  ExitThread/_endthreadex fire
                // DLL_THREAD_DETACH; TerminateThread does not.
                pending_thread.state_machine = GuestThreadState::Exiting;
                // Materialize the explicit exit code onto the thread record.
                // The request path (`request_current_thread_exit`) recorded
                // it in `pumped_thread_exit_requested` while the thread was
                // executing (the record itself is unreachable from the
                // thunk); the pump now stores it as the durable
                // `exit_code_override` consumed by the exit-code selection
                // below.  While the thread is `Exiting`, GetExitCodeThread
                // still reports STILL_ACTIVE (the kernel exit code is only
                // published at the `Exited` transition, per Windows).
                pending_thread.exit_code_override = Some(exit_code);
                if explicit_exit_detach {
                    // Fire TLS thread-detach callbacks for all loaded modules.
                    // These run after the thread's start function exits, before
                    // the thread is torn down — matching Windows TLS callback ordering.
                    {
                        let mut tls_state = CpuState::new(GuestArch::X86);
                        tls_state.segment_bases.fs = self.teb_base;
                        if self.guest_arch == GuestArch::X86 {
                            tls_state.set(
                                Register::Rsp,
                                pending_thread.initial_rsp.saturating_sub(0x100),
                            );
                        }
                        self.fire_tls_callbacks_for_all_modules(
                            &mut tls_state,
                            memory,
                            DLL_THREAD_DETACH,
                        )?;
                    }
                }
                // A TLS DETACH callback may itself call an explicit exit
                // API.  The thread is already exiting, so the request needs
                // no new state transition — but it must be consumed here and
                // propagated into the exit-code selection instead of leaking
                // into the enclosing pump's exit-request slot (which would
                // corrupt the `previous_exit_request` restore in a nested
                // pump).
                if let Some(detach_code) = self.pumped_thread_exit_requested.take() {
                    pending_thread.exit_code_override = Some(detach_code);
                }
                let final_code = pending_thread.exit_code_override.unwrap_or(exit_code);
                self.win32
                    .set_thread_exit_code_by_id(pending_thread.thread_id, final_code)?;
                pending_thread.state_machine = GuestThreadState::Exited;
                Ok((
                    PumpedThreadOutcome {
                        requeue: None,
                        process_exit: None,
                    },
                    self.tls_slots.clone(),
                    self.fls_slots.clone(),
                ))
            } else {
                match disposition {
                    GuestCallbackDisposition::Returned(exit_code) => {
                        // Fire TLS thread-detach callbacks for all loaded modules.
                        // These run after the thread's start function exits, before
                        // the thread is torn down — matching Windows TLS callback ordering.
                        {
                            let mut tls_state = CpuState::new(GuestArch::X86);
                            tls_state.segment_bases.fs = self.teb_base;
                            if self.guest_arch == GuestArch::X86 {
                                tls_state.set(
                                    Register::Rsp,
                                    pending_thread.initial_rsp.saturating_sub(0x100),
                                );
                            }
                            self.fire_tls_callbacks_for_all_modules(
                                &mut tls_state,
                                memory,
                                DLL_THREAD_DETACH,
                            )?;
                        }
                        // A TLS DETACH callback may itself call an explicit
                        // exit API; propagate the request into the exit-code
                        // selection (and consume it so it cannot corrupt the
                        // enclosing pump's `previous_exit_request` restore).
                        if let Some(detach_code) = self.pumped_thread_exit_requested.take() {
                            pending_thread.exit_code_override = Some(detach_code);
                        }
                        let final_code = pending_thread
                            .exit_code_override
                            .unwrap_or(exit_code as u32);
                        self.win32
                            .set_thread_exit_code_by_id(pending_thread.thread_id, final_code)?;
                        // Steam run instrumentation (no behavior change): the
                        // thread procedure returned — a clean exit.
                        crate::steam_milestones::note_thread_normal_exit();
                        self.emit_event(crate::runtime_events::RuntimeEvent::ThreadExited {
                            thread_id: pending_thread.thread_id,
                        });
                        pending_thread.state_machine = GuestThreadState::Exited;
                        Ok((
                            PumpedThreadOutcome {
                                requeue: None,
                                process_exit: None,
                            },
                            self.tls_slots.clone(),
                            self.fls_slots.clone(),
                        ))
                    }
                    GuestCallbackDisposition::Yielded => {
                        pending_thread.tls_slots = self.tls_slots.clone();
                        pending_thread.fls_slots = self.fls_slots.clone();
                        pending_thread.wake_tick = self
                            .yield_pumped_guest_thread_wake_tick
                            .take()
                            .unwrap_or_else(|| self.win32.get_tick_count64());
                        // A blocking-wait thunk parked via
                        // `park_for_wait`; move the descriptor onto the
                        // requeued record so the readiness pass evaluates it.
                        pending_thread.wait = self.pump_yield_with_wait.take();
                        pending_thread.wait_resume = None;
                        // In production mode the record is owned by a native
                        // worker; otherwise it stays on the cooperative path.
                        let requeue = self.park_pumped_thread_in_production(pending_thread);
                        Ok((
                            PumpedThreadOutcome {
                                requeue,
                                process_exit: None,
                            },
                            self.tls_slots.clone(),
                            self.fls_slots.clone(),
                        ))
                    }
                }
            }
        };

        self.active_pumped_guest_thread = previous_active_thread;
        self.yield_pumped_guest_thread = previous_yield_request;
        self.yield_pumped_guest_thread_wake_tick = previous_yield_wake_tick;
        self.pumped_thread_exit_requested = previous_exit_request;
        self.pumped_thread_exit_with_detach = previous_exit_detach;
        let pumped_last_error = self.last_error;
        if pumped_teb_base != 0 {
            let _ = memory.write_u32(
                pumped_teb_base + teb_last_error_offset(self.guest_arch),
                pumped_last_error,
            );
        } else {
            self.fallback_last_errors
                .insert(pumped_thread_id, pumped_last_error);
        }
        let same_thread = (pumped_teb_base != 0 && pumped_teb_base == previous_teb_base)
            || pumped_thread_id == previous_thread_id;
        self.win32.set_current_thread_id(previous_thread_id);
        self.teb_base = previous_teb_base;
        self.last_error = if same_thread {
            // The pumped thread is the caller's own logical thread (a nested
            // pump): its newest last error must survive the restoration.
            pumped_last_error
        } else if previous_teb_base != 0 {
            memory
                .read_u32(previous_teb_base + teb_last_error_offset(self.guest_arch))
                .unwrap_or(previous_last_error)
        } else {
            previous_last_error
        };
        self.tls_vector_ptr = previous_tls_vector_ptr;

        match result {
            Ok((outcome, thread_tls_slots, thread_fls_slots)) => {
                let mut restored_tls_slots = previous_tls_slots.clone();
                restored_tls_slots.retain(|slot, _| thread_tls_slots.contains_key(slot));
                for slot in thread_tls_slots.keys().copied() {
                    restored_tls_slots.entry(slot).or_insert(0);
                }

                let mut restored_fls_slots = previous_fls_slots.clone();
                restored_fls_slots.retain(|slot, _| thread_fls_slots.contains_key(slot));
                for slot in thread_fls_slots.keys().copied() {
                    restored_fls_slots.entry(slot).or_insert(0);
                }

                let tls_slots_to_sync = previous_tls_slots
                    .keys()
                    .copied()
                    .chain(restored_tls_slots.keys().copied())
                    .collect::<BTreeSet<_>>();

                self.tls_slots = restored_tls_slots;
                self.fls_slots = restored_fls_slots;
                for slot in tls_slots_to_sync {
                    let value = self.tls_slots.get(&slot).copied().unwrap_or(0);
                    self.sync_guest_tls_slot(memory, slot, value)?;
                }
                if let Some(pending_thread) = outcome.requeue {
                    self.pending_guest_threads.push_back(pending_thread);
                    notify_pump_wake();
                }
                Ok(PumpOutcome {
                    did_work: true,
                    process_exit: outcome.process_exit,
                })
            }
            Err(error) => {
                self.tls_slots = previous_tls_slots;
                self.fls_slots = previous_fls_slots;
                for (&slot, &value) in &self.tls_slots {
                    self.sync_guest_tls_slot(memory, slot, value)?;
                }
                Err(error)
            }
        }
    }
}

// ── Production scheduling ──────────────────────────────────────────────────
//
// Cooperative mode (the default) runs every guest thread on the caller's host
// thread through `pump_pending_guest_thread`, which is byte-for-byte
// deterministic.  Production mode adds a bounded pool of native host workers:
// a guest thread that blocks in a mutex / event / semaphore / completion-port
// wait is handed to a worker as a wait job, parked on a real condition
// variable (object wake bus, port wait state, or an exact deadline) and woken
// by a real event — never by a 1 ms host poll.  The woken thread is re-queued
// for execution on the runtime thread, where wait consumption and guest-state
// mutation remain single-threaded and atomic.
//
// A guest *slice* still executes under the runtime's exclusive `&mut` engine;
// simultaneous guest-code execution would require splitting `PeHostRuntime`
// into shared `Arc`-locked subsystems (memory, win32 handles, JIT caches, D3D
// state).  Production mode therefore provides real native workers, real
// park/wake events and concurrent parked guest threads, with guest execution
// serialized by the runtime's single owner.

/// Which scheduler drives parked guest threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SchedulerMode {
    /// Deterministic cooperative pump on the runtime thread (test mode).
    Cooperative,
    /// Bounded native host worker pool for parked guest waits.
    Production { workers: usize },
}

impl SchedulerMode {
    pub(crate) fn worker_count(self) -> usize {
        match self {
            Self::Cooperative => 0,
            Self::Production { workers } => workers.clamp(1, MAX_PRODUCTION_WORKERS),
        }
    }
}

/// Bound on the production pool (also bounds host thread cost).
const MAX_PRODUCTION_WORKERS: usize = 64;
/// Compiled guest blocks a production worker executes before yielding the
/// guest thread back to the scheduler.  Bounds slice latency without a host
/// poll (the block prologue's safepoint check remains the hard interrupt).
const PRODUCTION_SLICE_BLOCKS: u64 = 512;
/// Upper bound on statically reachable blocks precompiled per worker round.
/// Bounds cold-start work for a large call graph; further targets are compiled
/// by later owner rounds as the slice reaches them.
const SLICE_REACHABLE_BLOCKS: usize = 256;
/// Upper bound on how long the runtime owner waits for one parallel slice
/// round; a stuck worker is a bug, not a scheduling policy.
const PRODUCTION_SLICE_TIMEOUT: Duration = Duration::from_secs(30);
/// Completion-port condition-variable slices.  A blocked IOCP wait re-enters
/// the port's own condvar (never a 1 ms hot-path poll); the slice only lets
/// the worker observe shutdown and alertable APC notifications.
const COMPLETION_PORT_WAIT_SLICE: Duration = Duration::from_millis(250);
const COMPLETION_PORT_ALERTABLE_SLICE: Duration = Duration::from_millis(10);
/// Idle housekeeping interval for the runtime thread while only production
/// waits remain: re-check the run deadline, guest timers and APCs.  Wakeups
/// themselves are condition-variable driven and are not gated by this.
const PRODUCTION_HOUSEKEEPING: Duration = Duration::from_millis(20);

/// Why a production wait job completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitWakeReason {
    ObjectSignaled,
    ObjectClosed,
    Deadline,
    Apc,
    ThreadExit,
    CompletionPort,
    PortClosed,
    PortTimedOut,
    Shutdown,
}

/// A park signal: one condition variable per parked guest thread.  A
/// generation counter closes the register-then-block race: notifications that
/// arrive before the worker starts waiting are observed immediately.
#[derive(Debug)]
struct ParkSignal {
    state: Mutex<ParkSignalState>,
    wake: Condvar,
}

#[derive(Debug)]
struct ParkSignalState {
    generation: u64,
    reason: Option<WaitWakeReason>,
}

impl ParkSignal {
    fn new() -> Self {
        Self {
            state: Mutex::new(ParkSignalState {
                generation: 0,
                reason: None,
            }),
            wake: Condvar::new(),
        }
    }

    fn generation(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation
    }

    fn notify(&self, reason: WaitWakeReason) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.reason.get_or_insert(reason);
        drop(state);
        SCHEDULER_COUNTERS
            .wakeups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match reason {
            WaitWakeReason::ObjectSignaled | WaitWakeReason::ObjectClosed => {
                SCHEDULER_COUNTERS
                    .object_wakeups
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            WaitWakeReason::Apc => {
                SCHEDULER_COUNTERS
                    .apc_wakeups
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        self.wake.notify_all();
    }

    /// Wait for a notification newer than `observed`.  `None` timeout waits
    /// indefinitely.  Returns the wake reason, or `None` on timeout.
    fn wait(&self, observed: u64, timeout: Option<Duration>) -> (u64, Option<WaitWakeReason>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        loop {
            if state.generation != observed {
                return (state.generation, state.reason);
            }
            match deadline {
                None => {
                    state = self
                        .wake
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return (state.generation, None);
                    }
                    let (guard, _) = self
                        .wake
                        .wait_timeout(state, deadline - now)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state = guard;
                }
            }
        }
    }
}

/// Cross-thread wake bus.  Object ids are process-global, so one bus can serve
/// every runtime; subscriptions are weak and pruned on notification, so a
/// finished wait never keeps a signal alive.
#[derive(Debug)]
struct WakeBus {
    state: Mutex<WakeBusState>,
}

#[derive(Debug, Default)]
struct WakeBusState {
    objects: BTreeMap<ObjectId, Vec<std::sync::Weak<ParkSignal>>>,
    threads: BTreeMap<u32, Vec<std::sync::Weak<ParkSignal>>>,
}

impl WakeBus {
    fn new() -> Self {
        Self {
            state: Mutex::new(WakeBusState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, WakeBusState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn subscribe_object(&self, id: ObjectId, signal: &Arc<ParkSignal>) {
        self.lock()
            .objects
            .entry(id)
            .or_default()
            .push(Arc::downgrade(signal));
    }

    fn subscribe_thread(&self, thread_id: u32, signal: &Arc<ParkSignal>) {
        self.lock()
            .threads
            .entry(thread_id)
            .or_default()
            .push(Arc::downgrade(signal));
    }

    fn collect(signals: &mut Vec<std::sync::Weak<ParkSignal>>) -> Vec<Arc<ParkSignal>> {
        let mut live = Vec::with_capacity(signals.len());
        let mut upgraded = Vec::with_capacity(signals.len());
        for weak in signals.drain(..) {
            if let Some(signal) = weak.upgrade() {
                upgraded.push(Arc::clone(&signal));
                live.push(weak);
            }
        }
        *signals = live;
        upgraded
    }

    fn notify_object(&self, id: ObjectId, closed: bool) {
        let signals = {
            let mut state = self.lock();
            match state.objects.get_mut(&id) {
                Some(signals) => Self::collect(signals),
                None => Vec::new(),
            }
        };
        let reason = if closed {
            WaitWakeReason::ObjectClosed
        } else {
            WaitWakeReason::ObjectSignaled
        };
        for signal in signals {
            signal.notify(reason);
        }
    }

    fn notify_thread(&self, thread_id: u32, reason: WaitWakeReason) {
        let signals = {
            let mut state = self.lock();
            match state.threads.get_mut(&thread_id) {
                Some(signals) => Self::collect(signals),
                None => Vec::new(),
            }
        };
        for signal in signals {
            signal.notify(reason);
        }
    }
}

static WAKE_BUS: std::sync::OnceLock<WakeBus> = std::sync::OnceLock::new();

fn wake_bus() -> &'static WakeBus {
    WAKE_BUS.get_or_init(WakeBus::new)
}

/// Object-manager hook: a waitable object changed state.  `closed` is set when
/// the object is being dropped (last handle closed).
pub(crate) fn notify_object_waiters(id: ObjectId, closed: bool) {
    if let Some(bus) = WAKE_BUS.get() {
        bus.notify_object(id, closed);
    }
    // A cooperative waiter is not parked on a `ParkSignal`; the pump must
    // recheck its readiness predicate even when no production waiter is
    // subscribed.
    notify_pump_wake();
}

/// Scheduler hook: wake a thread parked in an alertable wait (APC queued).
pub(crate) fn notify_thread_apc(thread_id: u32) {
    if let Some(bus) = WAKE_BUS.get() {
        bus.notify_thread(thread_id, WaitWakeReason::Apc);
    }
    notify_pump_wake();
}

/// Scheduler hook: wake waits on a terminating thread's kernel object.
pub(crate) fn notify_thread_exit(thread_id: u32) {
    if let Some(bus) = WAKE_BUS.get() {
        bus.notify_thread(thread_id, WaitWakeReason::ThreadExit);
    }
    notify_pump_wake();
}

#[derive(Debug)]
enum WaitJobKind {
    /// Event / mutex / semaphore set; the wake bus drives the wait.
    Objects,
    /// Deadline-only wait (Sleep / finite timeout with no event source).
    DeadlineOnly,
    /// Blocking completion-port dequeue on the port's own condition variable.
    CompletionPort {
        state: Arc<crate::win32::CompletionPortWaitState>,
        guest_thread_id: u32,
        max_packets: usize,
        alertable: bool,
    },
}

#[derive(Debug)]
struct WaitJob {
    job_id: u64,
    thread_id: u32,
    signal: Arc<ParkSignal>,
    observed_generation: u64,
    kind: WaitJobKind,
    deadline: Option<Instant>,
}

#[derive(Debug)]
struct WaitCompletion {
    job_id: u64,
    thread_id: u32,
    reason: WaitWakeReason,
    packets: Vec<crate::win32::IoCompletionPacket>,
}

#[derive(Default)]
struct ProductionState {
    queue: VecDeque<WaitJob>,
    completions: VecDeque<WaitCompletion>,
    slice_queue: VecDeque<GuestSliceJob>,
    slice_completions: VecDeque<GuestSliceCompletion>,
    /// Long-lived per-guest-thread worker slots.  A slot keeps the guest
    /// `CpuState` (including TEB/TLS bases), the return predictor, the
    /// indirect inline caches, the slice-cache generation, and the wait
    /// object across slice rounds, so a guest thread never restarts cold
    /// merely because a budget boundary was reached.
    slots: BTreeMap<u32, GuestThreadSlot>,
    shutdown: bool,
    active_jobs: usize,
    next_job_id: u64,
    next_slice_id: u64,
    last_worker_by_thread: BTreeMap<u32, usize>,
    signals: Vec<std::sync::Weak<ParkSignal>>,
}

struct ProductionShared {
    state: Mutex<ProductionState>,
    work_ready: Condvar,
    completion_ready: Condvar,
    /// Lock-free shutdown flag polled between worker-slice blocks (a native
    /// guest loop must stop even when it never returns to the dispatcher).
    shutdown: std::sync::atomic::AtomicBool,
}

/// Why a production guest-code slice stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestSliceExit {
    /// The per-slice block budget was exhausted; the thread is runnable.
    Budget,
    /// The next transfer needs the runtime owner: an uncompiled/dynamic
    /// target, a host thunk, or a block that is not worker-safe.  Native
    /// calls, returns, and indirect transfers do not reach this exit when
    /// their target was precompiled.  No host code ran on the worker.
    HostBarrier { rip: u64 },
    /// The guest load/store hit memory the worker view cannot service; the
    /// runtime owner retries it with the full page table/VM.
    GuestFault { address: u64, write: bool },
    /// A guest store touched a compiled-code page; the owner must invalidate
    /// stale blocks before the next slice.
    CodeWrite,
    /// The global host safepoint flag asked the block to yield.
    Safepoint,
    /// The pool was shutting down while the slice was running.
    Shutdown,
}

/// Per-guest-thread execution request for a production worker.
#[allow(dead_code)] // compatibility request shape used by diagnostics/tests
pub(crate) struct GuestSliceRequest {
    pub(crate) thread_id: u32,
    pub(crate) state: CpuState,
    /// Windows thread priority at submission time.
    pub(crate) priority: i32,
}

/// Result of executing one guest thread's slice on a production worker.
#[allow(dead_code)] // fields are the scheduler's public test/diagnostic surface
pub(crate) struct GuestSliceReport {
    pub(crate) thread_id: u32,
    pub(crate) state: CpuState,
    pub(crate) exit: GuestSliceExit,
    pub(crate) blocks_executed: u64,
    pub(crate) worker_index: usize,
    pub(crate) code_writes: Vec<(u64, usize)>,
    /// Control-flow counters accumulated by this slice round.
    pub(crate) metrics: crate::jit::SliceMetrics,
}

/// Result of executing one guest thread slice through the
/// `(&ProcessShared, &mut GuestThreadContext)` API.
#[allow(dead_code)] // fields are the scheduler's public test/diagnostic surface
pub(crate) struct GuestThreadRun {
    pub(crate) context: GuestThreadSnapshot,
    pub(crate) exit: GuestSliceExit,
    pub(crate) blocks_executed: u64,
    pub(crate) worker_index: usize,
    pub(crate) code_writes: Vec<(u64, usize)>,
    pub(crate) metrics: crate::jit::SliceMetrics,
}

/// A persistent worker slot for one guest thread.  It is removed from the
/// scheduler's slot map while a job runs on a worker and put back when the
/// job completes, so exactly one host thread owns the guest state at a time.
/// The slot's execution state is a [`GuestThreadContext`]: registers, flags,
/// TEB/TLS/FLS, last error, JIT control caches and dispatcher scratch are all
/// private to the guest thread; only [`ProcessShared`] is shared.
struct GuestThreadSlot {
    context: GuestThreadContext,
    /// Park signal of the current production wait, retained with the slot so
    /// the wait object survives a slice-budget boundary.
    wait: Option<Arc<ParkSignal>>,
}

impl GuestThreadSlot {
    fn new(thread_id: u32, state: CpuState) -> Self {
        Self {
            context: GuestThreadContext::new(thread_id, state),
            wait: None,
        }
    }

    fn from_context(context: GuestThreadContext) -> Self {
        Self {
            context,
            wait: None,
        }
    }

    fn thread_id(&self) -> u32 {
        self.context.thread_id
    }
}

/// Point-in-time view of a persistent worker slot (diagnostics/tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestSlotSnapshot {
    pub(crate) thread_id: u32,
    pub(crate) priority: i32,
    pub(crate) rip: u64,
    pub(crate) fs_base: u64,
    pub(crate) slices: u64,
    pub(crate) worker_index: Option<usize>,
    pub(crate) has_wait: bool,
    pub(crate) translation_epoch: u64,
    pub(crate) metrics: crate::jit::SliceMetrics,
}

struct GuestSliceJob {
    job_id: u64,
    slot: GuestThreadSlot,
    budget: u64,
    /// Optional simultaneous-start gate shared by all jobs of one round, so
    /// a multi-thread slice round really overlaps on the workers instead of
    /// serially finishing tiny slices before the next worker dequeues.
    start: Option<Arc<SliceStartGate>>,
}

/// Cancellable simultaneous-start gate.  A plain `Barrier` deadlocks if the
/// pool is dropped after only some of a round's jobs have been dequeued;
/// this gate wakes waiters when the pool shuts down.
struct SliceStartGate {
    remaining: Mutex<usize>,
    ready: Condvar,
}

impl SliceStartGate {
    fn new(count: usize) -> Self {
        Self {
            remaining: Mutex::new(count),
            ready: Condvar::new(),
        }
    }

    fn arrive_and_wait(&self, shutdown: &std::sync::atomic::AtomicBool) {
        let mut remaining = self
            .remaining
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *remaining == 0 {
            return;
        }
        *remaining -= 1;
        if *remaining == 0 {
            self.ready.notify_all();
            return;
        }
        while *remaining != 0 && !shutdown.load(std::sync::atomic::Ordering::Acquire) {
            let (guard, _) = self
                .ready
                .wait_timeout(remaining, Duration::from_millis(5))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            remaining = guard;
        }
    }
}

struct GuestSliceCompletion {
    job_id: u64,
    slot: GuestThreadSlot,
    exit: GuestSliceExit,
    blocks_executed: u64,
    worker_index: usize,
    code_writes: Vec<(u64, usize)>,
    metrics: crate::jit::SliceMetrics,
}

/// Bounded native host worker pool for parked guest waits.  Dropping the pool
/// shuts every worker down and joins it.
pub(crate) struct ProductionScheduler {
    shared: Arc<ProductionShared>,
    /// Process-wide state every native worker executes against.  Guest
    /// execution is `(&ProcessShared, &mut GuestThreadContext)`; the pool
    /// never hands a worker a `PeHostRuntime`.
    process_shared: Arc<ProcessShared>,
    workers: Vec<std::thread::JoinHandle<()>>,
    worker_count: usize,
}

impl ProductionScheduler {
    #[allow(dead_code)] // standalone-pool constructor used by scheduler tests
    pub(crate) fn new(workers: usize) -> Self {
        Self::with_process_shared(workers, Arc::new(ProcessShared::new()))
    }

    /// Create a pool whose workers execute against the runtime's one
    /// process-shared handle (canonical memory, process gate, code epoch).
    pub(crate) fn with_process_shared(workers: usize, process_shared: Arc<ProcessShared>) -> Self {
        let workers = workers.clamp(1, MAX_PRODUCTION_WORKERS);
        process_shared.reopen();
        let shared = Arc::new(ProductionShared {
            state: Mutex::new(ProductionState::default()),
            work_ready: Condvar::new(),
            completion_ready: Condvar::new(),
            shutdown: std::sync::atomic::AtomicBool::new(false),
        });
        let mut handles = Vec::with_capacity(workers);
        for index in 0..workers {
            let worker_shared = Arc::clone(&shared);
            let worker_process = Arc::clone(&process_shared);
            let handle = std::thread::Builder::new()
                .name(format!("casa1-guest-worker-{index}"))
                .spawn(move || production_worker(worker_shared, worker_process, index))
                .expect("spawn production scheduler worker");
            handles.push(handle);
        }
        Self {
            shared,
            process_shared,
            workers: handles,
            worker_count: workers,
        }
    }

    pub(crate) fn worker_count(&self) -> usize {
        self.worker_count
    }

    fn submit(
        &self,
        thread_id: u32,
        signal: Arc<ParkSignal>,
        observed_generation: u64,
        kind: WaitJobKind,
        deadline: Option<Instant>,
    ) -> u64 {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let job_id = state.next_job_id;
        state.next_job_id = state.next_job_id.wrapping_add(1);
        state.signals.push(Arc::downgrade(&signal));
        state.queue.push_back(WaitJob {
            job_id,
            thread_id,
            signal,
            observed_generation,
            kind,
            deadline,
        });
        drop(state);
        self.shared.work_ready.notify_one();
        job_id
    }

    #[allow(dead_code)] // request-shaped submission used by scheduler tests
    fn submit_slice(
        &self,
        thread_id: u32,
        state: CpuState,
        priority: i32,
        budget: u64,
        start: Option<Arc<SliceStartGate>>,
    ) -> u64 {
        let mut context = GuestThreadContext::new(thread_id, state);
        context.priority = priority;
        self.submit_context(context, budget, start)
    }

    /// Queue one guest thread's private context for a native worker.  This is
    /// the concurrency API's submission point: only the context and the
    /// process-shared handle cross the thread boundary.
    fn submit_context(
        &self,
        context: GuestThreadContext,
        budget: u64,
        start: Option<Arc<SliceStartGate>>,
    ) -> u64 {
        let thread_id = context.thread_id;
        let mut shared = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let job_id = shared.next_slice_id;
        shared.next_slice_id = shared.next_slice_id.wrapping_add(1);
        let slot = match shared.slots.remove(&thread_id) {
            Some(mut slot) => {
                slot.context.adopt(context);
                slot
            }
            None => GuestThreadSlot::from_context(context),
        };
        shared.slice_queue.push_back(GuestSliceJob {
            job_id,
            slot,
            budget,
            start,
        });
        drop(shared);
        self.shared.work_ready.notify_one();
        job_id
    }

    fn take_completions(&self) -> Vec<WaitCompletion> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.completions.drain(..).collect()
    }

    fn take_slice_completions(&self) -> Vec<GuestSliceCompletion> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.slice_completions.drain(..).collect()
    }

    /// Create a persistent slot for a guest thread that has not run a slice
    /// yet (for example a thread that blocks before its first slice).
    fn ensure_slot(&self, thread_id: u32, state: &CpuState) {
        let mut shared = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shared
            .slots
            .entry(thread_id)
            .or_insert_with(|| GuestThreadSlot::new(thread_id, state.clone()));
    }

    /// Retain the wait object on the guest thread's persistent slot.
    fn set_slot_wait(&self, thread_id: u32, signal: Arc<ParkSignal>) {
        let mut shared = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(slot) = shared.slots.get_mut(&thread_id) {
            slot.wait = Some(signal);
        }
    }

    /// Clear the wait object when the wait completes (or is abandoned).
    fn clear_slot_wait(&self, thread_id: u32) {
        let mut shared = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(slot) = shared.slots.get_mut(&thread_id) {
            slot.wait = None;
        }
    }

    /// Drop persistent slots for guest threads that no longer exist.  This is
    /// the termination wake for persistent state: the slot's wait object and
    /// JIT control caches are released with it.
    fn retire_slots(&self, live: &BTreeSet<u32>) {
        let mut shared = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shared.slots.retain(|thread_id, _| live.contains(thread_id));
    }

    /// Snapshot of one persistent slot (diagnostics/tests).
    #[allow(dead_code)] // exposed for scheduler diagnostics/tests
    pub(crate) fn slot_snapshot(&self, thread_id: u32) -> Option<GuestSlotSnapshot> {
        let shared = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shared.slots.get(&thread_id).map(|slot| GuestSlotSnapshot {
            thread_id: slot.context.thread_id,
            priority: slot.context.priority,
            rip: slot.context.state.rip,
            fs_base: slot.context.state.segment_bases.fs,
            slices: slot.context.slices,
            worker_index: slot.context.worker_index,
            has_wait: slot.wait.is_some(),
            translation_epoch: slot.context.control.epoch(),
            metrics: slot.context.control.metrics,
        })
    }

    fn wait_for_completion(&self, timeout: Option<Duration>) -> bool {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.completions.is_empty() {
            return true;
        }
        let predicate = |state: &mut ProductionState| {
            state.completions.is_empty() && state.slice_completions.is_empty() && !state.shutdown
        };
        match timeout {
            Some(timeout) => {
                let (guard, _) = self
                    .shared
                    .completion_ready
                    .wait_timeout_while(state, timeout, predicate)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state = guard;
            }
            None => {
                state = self
                    .shared
                    .completion_ready
                    .wait_while(state, predicate)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
        !state.completions.is_empty() || !state.slice_completions.is_empty()
    }

    /// Run one round of concurrent guest-code slices for the supplied
    /// per-thread contexts.  Each context is queued independently, so
    /// different guest threads execute on different native workers, then this
    /// (runtime-owner) thread collects every completion.  Host thunks never
    /// run here; a worker that reaches one reports
    /// [`GuestSliceExit::HostBarrier`] and the owner executes it exactly once.
    ///
    /// The immutable compiled program is published on the process-shared
    /// handle for the duration of the round, so a worker needs only
    /// `(&ProcessShared, &mut GuestThreadContext)` to execute guest code.
    pub(crate) fn run_thread_contexts(
        &self,
        contexts: Vec<GuestThreadContext>,
        program: Arc<crate::jit::GuestSliceProgram>,
        budget: u64,
    ) -> Vec<GuestThreadRun> {
        if contexts.is_empty() {
            return Vec::new();
        }
        self.process_shared.publish_program(program);
        let mut pending = BTreeSet::new();
        // Only gate rounds that fit the pool; extra jobs would deadlock a
        // barrier sized for all requests.
        let start = (contexts.len() > 1 && contexts.len() <= self.worker_count)
            .then(|| Arc::new(SliceStartGate::new(contexts.len())));
        for context in contexts {
            let id = self.submit_context(context, budget, start.as_ref().map(Arc::clone));
            pending.insert(id);
        }
        let mut runs = Vec::with_capacity(pending.len());
        while !pending.is_empty() {
            if !self.wait_for_completion(Some(PRODUCTION_SLICE_TIMEOUT)) {
                break;
            }
            for completion in self.take_slice_completions() {
                if pending.remove(&completion.job_id) {
                    let thread_id = completion.slot.thread_id();
                    let snapshot = completion.slot.context.snapshot();
                    // Return the persistent slot to the map so the next round
                    // reuses its predictor, inline caches and TEB/TLS state.
                    self.shared
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .slots
                        .insert(thread_id, completion.slot);
                    runs.push(GuestThreadRun {
                        exit: completion.exit,
                        blocks_executed: completion.blocks_executed,
                        worker_index: completion.worker_index,
                        code_writes: completion.code_writes,
                        metrics: completion.metrics,
                        context: snapshot,
                    });
                }
            }
            if self
                .shared
                .state
                .lock()
                .map(|state| state.shutdown)
                .unwrap_or(true)
            {
                break;
            }
        }
        self.process_shared.clear_program();
        runs
    }

    /// Compatibility wrapper used by the existing scheduler call sites/tests:
    /// convert lightweight requests into per-thread contexts, run the round,
    /// and return the historical report shape.
    #[allow(dead_code)] // request-shaped round used by scheduler tests
    pub(crate) fn run_guest_slices(
        &self,
        requests: Vec<GuestSliceRequest>,
        program: Arc<crate::jit::GuestSliceProgram>,
        budget: u64,
    ) -> Vec<GuestSliceReport> {
        let contexts: Vec<GuestThreadContext> = requests
            .into_iter()
            .map(|request| {
                let mut context = GuestThreadContext::new(request.thread_id, request.state);
                context.priority = request.priority;
                context
            })
            .collect();
        self.run_thread_contexts(contexts, program, budget)
            .into_iter()
            .map(|run| GuestSliceReport {
                thread_id: run.context.thread_id,
                state: run.context.state,
                exit: run.exit,
                blocks_executed: run.blocks_executed,
                worker_index: run.worker_index,
                code_writes: run.code_writes,
                metrics: run.metrics,
            })
            .collect()
    }

    #[allow(dead_code)] // used by scheduler tests to observe worker queueing
    fn active_job_count(&self) -> usize {
        self.shared
            .state
            .lock()
            .map(|state| state.active_jobs)
            .unwrap_or(0)
    }
}
impl Drop for ProductionScheduler {
    fn drop(&mut self) {
        self.shared
            .shutdown
            .store(true, std::sync::atomic::Ordering::Release);
        // In-flight slices poll `ProcessShared::shutdown` between blocks, so
        // a dropped pool must stop them too (guest blocks are unlinked and
        // never return to the dispatcher on their own).
        self.process_shared.request_shutdown();
        // Worker slice blocks are deliberately unlinked, so each block
        // returns to the worker dispatcher (which polls `shutdown`) within a
        // bounded number of instructions.  Do not set the process-wide
        // safepoint flag here: that would disturb unrelated JIT executions
        // after cooperative-mode switches.
        let signals = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.shutdown = true;
            std::mem::take(&mut state.signals)
        };
        for weak in signals {
            if let Some(signal) = weak.upgrade() {
                signal.notify(WaitWakeReason::Shutdown);
            }
        }
        self.shared.work_ready.notify_all();
        self.shared.completion_ready.notify_all();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

enum ProductionJob {
    Wait(WaitJob),
    Slice(GuestSliceJob),
}

/// Prefer a queued slice whose persistent slot last ran on this worker, so a
/// guest thread keeps its host-thread affinity (TLS-heavy code, predictor
/// warmth).  Falls back to the oldest job when no affine job is queued, which
/// prevents a busy affine worker from starving the thread.
fn pop_affine_slice(
    queue: &mut std::collections::VecDeque<GuestSliceJob>,
    worker_index: usize,
) -> Option<GuestSliceJob> {
    let affine = queue.iter().position(|job| {
        job.slot
            .context
            .worker_index
            .is_some_and(|assigned| assigned == worker_index)
    });
    match affine {
        Some(index) => queue.remove(index),
        None => queue.pop_front(),
    }
}

fn production_worker(
    shared: Arc<ProductionShared>,
    process_shared: Arc<ProcessShared>,
    worker_index: usize,
) {
    use std::sync::atomic::Ordering::Relaxed;
    SCHEDULER_COUNTERS.note_host_worker_identity();
    loop {
        let job = {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            loop {
                if state.shutdown {
                    return;
                }
                let thread_id;
                let job = if let Some(job) = pop_affine_slice(&mut state.slice_queue, worker_index)
                {
                    thread_id = job.slot.thread_id();
                    ProductionJob::Slice(job)
                } else if let Some(job) = state.queue.pop_front() {
                    thread_id = job.thread_id;
                    ProductionJob::Wait(job)
                } else {
                    state = shared
                        .work_ready
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    continue;
                };
                state.active_jobs = state.active_jobs.saturating_add(1);
                if let Some(previous) = state.last_worker_by_thread.insert(thread_id, worker_index)
                    && previous != worker_index
                {
                    SCHEDULER_COUNTERS.migrations.fetch_add(1, Relaxed);
                }
                break job;
            }
        };
        let active = SCHEDULER_COUNTERS
            .active_worker_jobs
            .fetch_add(1, Relaxed)
            .saturating_add(1);
        SCHEDULER_COUNTERS
            .max_concurrent_worker_jobs
            .fetch_max(active, Relaxed);
        if active > 1 {
            SCHEDULER_COUNTERS.worker_overlaps.fetch_add(1, Relaxed);
        }
        match job {
            ProductionJob::Wait(job) => {
                let completion = run_wait_job(job);
                let mut state = shared
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.active_jobs = state.active_jobs.saturating_sub(1);
                state.completions.push_back(completion);
            }
            ProductionJob::Slice(job) => {
                let completion =
                    run_guest_slice_job(job, &shared.shutdown, &process_shared, worker_index);
                let mut state = shared
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.active_jobs = state.active_jobs.saturating_sub(1);
                state.slice_completions.push_back(completion);
            }
        }
        SCHEDULER_COUNTERS.active_worker_jobs.fetch_sub(1, Relaxed);
        shared.completion_ready.notify_all();
        // The runtime owner may be blocked on the cooperative pump wake
        // signal (mixed cooperative/production waits), not on this pool's
        // completion condvar; completion insertion is a runnable transition
        // for it too.
        notify_pump_wake();
    }
}

fn run_guest_slice_job(
    mut job: GuestSliceJob,
    shutdown: &std::sync::atomic::AtomicBool,
    process_shared: &ProcessShared,
    worker_index: usize,
) -> GuestSliceCompletion {
    use std::sync::atomic::Ordering;
    if let Some(start) = job.start.as_ref() {
        start.arrive_and_wait(shutdown);
    }
    job.slot.context.worker_index = Some(worker_index);
    // Apply the guest thread's Windows priority as host QoS for the slice;
    // the guard restores the worker's previous class when it drops.
    let _qos = GuestQosGuard::apply(job.slot.context.priority);
    // The worker executes guest code with ONLY the process-shared handle and
    // the thread's private context.  No `PeHostRuntime` crosses the thread
    // boundary: canonical memory, the compiled program, the safepoint/shutdown
    // flag and the SMC epoch all live in `process_shared`.
    let report = process_shared.run_thread(&mut job.slot.context, job.budget);
    let exit = match report.stop {
        ThreadSliceStop::Budget => GuestSliceExit::Budget,
        ThreadSliceStop::HostBarrier { rip } => GuestSliceExit::HostBarrier { rip },
        ThreadSliceStop::GuestFault { address, write } => {
            GuestSliceExit::GuestFault { address, write }
        }
        ThreadSliceStop::CodeWrite => GuestSliceExit::CodeWrite,
        ThreadSliceStop::Safepoint => {
            // Same protocol as the blocking dispatcher: the request is
            // consumed when the block yields, unless the pool is shutting
            // down (Drop sets both).
            if !shutdown.load(Ordering::Acquire) {
                crate::jit::JIT_SAFEPOINT_REQUESTED.store(false, Ordering::Release);
            }
            GuestSliceExit::Safepoint
        }
        ThreadSliceStop::Shutdown => GuestSliceExit::Shutdown,
    };
    GuestSliceCompletion {
        job_id: job.job_id,
        slot: job.slot,
        exit,
        blocks_executed: report.blocks_executed,
        worker_index,
        code_writes: report.code_writes,
        metrics: report.metrics,
    }
}

fn run_wait_job(job: WaitJob) -> WaitCompletion {
    use std::sync::atomic::Ordering::Relaxed;
    let mut completion = WaitCompletion {
        job_id: job.job_id,
        thread_id: job.thread_id,
        reason: WaitWakeReason::Deadline,
        packets: Vec::new(),
    };
    match job.kind {
        WaitJobKind::CompletionPort {
            state,
            guest_thread_id,
            max_packets,
            alertable,
        } => {
            let slice = if alertable {
                COMPLETION_PORT_ALERTABLE_SLICE
            } else {
                COMPLETION_PORT_WAIT_SLICE
            };
            loop {
                let timeout = match job.deadline {
                    Some(deadline) => {
                        let now = Instant::now();
                        if now >= deadline {
                            completion.reason = WaitWakeReason::PortTimedOut;
                            SCHEDULER_COUNTERS.deadline_wakeups.fetch_add(1, Relaxed);
                            return completion;
                        }
                        Some((deadline - now).min(slice))
                    }
                    None => Some(slice),
                };
                match state.wait_dequeue_as(
                    crate::win32::CompletionPortThreadKey::Guest(guest_thread_id),
                    timeout,
                    max_packets,
                ) {
                    Ok(packets) => {
                        completion.reason = WaitWakeReason::CompletionPort;
                        completion.packets = packets;
                        return completion;
                    }
                    Err(crate::win32::CompletionPortWaitError::Closed) => {
                        completion.reason = WaitWakeReason::PortClosed;
                        return completion;
                    }
                    Err(crate::win32::CompletionPortWaitError::TimedOut) => {
                        if job.deadline.is_none() || alertable {
                            SCHEDULER_COUNTERS.port_rechecks.fetch_add(1, Relaxed);
                        }
                        if job
                            .deadline
                            .is_some_and(|deadline| Instant::now() >= deadline)
                        {
                            completion.reason = WaitWakeReason::PortTimedOut;
                            SCHEDULER_COUNTERS.deadline_wakeups.fetch_add(1, Relaxed);
                            return completion;
                        }
                        if alertable && job.signal.generation() != job.observed_generation {
                            completion.reason = WaitWakeReason::Apc;
                            return completion;
                        }
                    }
                }
                // Shutdown wakes CP workers through the signal as well.
                if job.signal.generation() != job.observed_generation {
                    completion.reason = job
                        .signal
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .reason
                        .unwrap_or(WaitWakeReason::Apc);
                    return completion;
                }
            }
        }
        WaitJobKind::Objects | WaitJobKind::DeadlineOnly => {
            let timeout = job.deadline.map(|deadline| {
                let now = Instant::now();
                if now >= deadline {
                    Duration::ZERO
                } else {
                    deadline - now
                }
            });
            let (_, reason) = job.signal.wait(job.observed_generation, timeout);
            completion.reason = match reason {
                Some(reason) => reason,
                None => {
                    SCHEDULER_COUNTERS.deadline_wakeups.fetch_add(1, Relaxed);
                    WaitWakeReason::Deadline
                }
            };
            completion
        }
    }
}

/// One parked guest thread's active production wait job.
pub(crate) struct ProductionWait {
    job_id: u64,
}

impl PeHostRuntime {
    /// Ensure the production worker has an unlinked compiled block for
    /// `rip`.  Returns `false` when the JIT is unavailable or the block is not
    /// worker-safe (the caller then keeps the thread on the cooperative
    /// owner path).
    fn ensure_slice_block(&mut self, memory: &mut MemoryImage, rip: u64) -> AppResult<bool> {
        if self.jit_runtime.is_none() {
            return Ok(false);
        }
        // A host thunk address is a host-dispatch barrier, not guest code:
        // only the runtime owner may execute it (exactly once).
        if self.host_thunks.contains_key(&rip) {
            return Ok(false);
        }
        if let Some(jit) = self.jit_runtime.as_ref()
            && let Some(block) = jit.slice_block(rip)
        {
            return Ok(block.worker_safe);
        }
        let config = crate::cpu::CpuEngineConfig::from_profile(
            self.guest_arch,
            &self.win32.ge().config.winver,
            env!("CARGO_PKG_VERSION"),
            None,
        )?; // coverage: unreachable — from_profile's only fallible field (virtualization) is skipped for a None profile
        let mut engine = crate::cpu::CpuExecutionEngine::new(config);
        let cached = decode_basic_block_cached(
            &mut engine,
            memory,
            &mut self.instruction_cache,
            &mut self.instruction_cache_lru,
            &mut self.instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            &mut self.basic_block_cache,
            &mut self.basic_block_cache_lru,
            &mut self.basic_block_cache_generation,
            BASIC_BLOCK_CACHE_LIMIT,
            rip,
        )?;
        let block = self
            .jit_runtime
            .as_mut()
            .expect("checked above")
            .get_or_compile_slice_block(&cached.translated.ir, rip, self.guest_arch)?;
        Ok(block.worker_safe)
    }

    /// Ensure a slice block and every statically reachable successor (jump,
    /// conditional branch, direct call) is compiled before a worker round.
    /// This is what lets `call`/`ret` chains continue natively inside one
    /// worker job instead of hitting an uncompiled-block barrier every hop.
    /// Dynamic targets (indirect call/jump/ret) are resolved by the worker
    /// and barrier only if the target was never compiled.
    fn ensure_slice_blocks_for(&mut self, memory: &mut MemoryImage, entry: u64) -> AppResult<bool> {
        let mut work = vec![entry];
        let mut seen = BTreeSet::new();
        let mut entry_safe = None;
        while let Some(rip) = work.pop() {
            if seen.len() >= SLICE_REACHABLE_BLOCKS || !seen.insert(rip) {
                continue;
            }
            if self.host_thunks.contains_key(&rip) {
                continue;
            }
            let safe = match self.ensure_slice_block(memory, rip) {
                Ok(safe) => safe,
                // A non-entry decode/compile failure is a runtime barrier for
                // that path, not a reason to abort the whole round.
                Err(error) if rip == entry => return Err(error),
                Err(_) => continue,
            };
            if rip == entry {
                entry_safe = Some(safe);
            }
            if !safe {
                continue;
            }
            let exit_info = self
                .jit_runtime
                .as_ref()
                .and_then(|jit| jit.slice_block(rip))
                .and_then(|block| block.last_exit_info);
            match exit_info {
                Some(crate::jit::BlockExitInfo::Jump { target }) => work.push(target),
                Some(crate::jit::BlockExitInfo::JumpIf {
                    target,
                    fallthrough,
                    ..
                }) => {
                    work.push(target);
                    work.push(fallthrough);
                }
                Some(crate::jit::BlockExitInfo::Call {
                    target,
                    return_address,
                }) => {
                    work.push(target);
                    // The continuation after the call is a static block too;
                    // precompiling it lets the callee's `ret` continue
                    // natively instead of hitting a cold-block barrier.
                    work.push(return_address);
                }
                Some(crate::jit::BlockExitInfo::CallIndirect { return_address }) => {
                    work.push(return_address);
                }
                _ => {}
            }
        }
        Ok(entry_safe.unwrap_or(false))
    }

    /// Execute one round of guest-code slices for the supplied guest threads
    /// on the production worker pool.  The runtime owner remains the only
    /// thread that touches runtime state: worker completions are returned for
    /// the owner to apply (thunks are never executed on a worker).
    #[allow(dead_code)] // request-shaped dispatch used by scheduler tests
    pub(crate) fn dispatch_parallel_guest_slices(
        &mut self,
        memory: &mut MemoryImage,
        requests: Vec<GuestSliceRequest>,
        budget: u64,
    ) -> AppResult<Vec<GuestSliceReport>> {
        let contexts: Vec<GuestThreadContext> = requests
            .into_iter()
            .map(|request| {
                let mut context = GuestThreadContext::new(request.thread_id, request.state);
                context.priority = request.priority;
                context
            })
            .collect();
        Ok(self
            .dispatch_parallel_thread_contexts(memory, contexts, budget)?
            .into_iter()
            .map(|run| GuestSliceReport {
                thread_id: run.context.thread_id,
                state: run.context.state,
                exit: run.exit,
                blocks_executed: run.blocks_executed,
                worker_index: run.worker_index,
                code_writes: run.code_writes,
                metrics: run.metrics,
            })
            .collect())
    }

    /// Execute one round of concurrent guest slices for explicit per-thread
    /// contexts.  This is the real concurrency entry point: the owner compiles
    /// the reachable blocks once, publishes the immutable program on
    /// [`ProcessShared`], and every context runs on a native worker against
    /// the shared canonical memory.  Worker completions are applied (and
    /// stale SMC pages invalidated) by the owner; no host thunk ever runs on a
    /// worker.
    pub(crate) fn dispatch_parallel_thread_contexts(
        &mut self,
        memory: &mut MemoryImage,
        contexts: Vec<GuestThreadContext>,
        budget: u64,
    ) -> AppResult<Vec<GuestThreadRun>> {
        if contexts.is_empty() {
            return Ok(Vec::new());
        }
        if self.production_scheduler.is_none() {
            return Ok(Vec::new());
        }
        for context in &contexts {
            self.ensure_slice_blocks_for(memory, context.state.rip)?;
        }
        let program = Arc::new(
            self.jit_runtime
                .as_ref()
                .expect("ensure_slice_block requires a JIT runtime")
                .build_slice_program(memory),
        );
        let scheduler = self.production_scheduler.as_ref().expect("checked above");
        let runs = scheduler.run_thread_contexts(contexts, program, budget);
        if let Some(jit) = self.jit_runtime.as_mut() {
            let mut wrote_code = false;
            let mut pages = BTreeSet::new();
            for run in &runs {
                if run.code_writes.is_empty() && matches!(run.exit, GuestSliceExit::CodeWrite) {
                    // A worker's SMC epoch guard fired without this program
                    // recording the exact store (e.g. the write came from a
                    // sibling program sharing the canonical store).  Invalidate
                    // conservatively at the guarded block's page.
                    let page = run.context.state.rip & !0xfff;
                    pages.insert(page);
                    wrote_code = true;
                }
                for &(address, length) in &run.code_writes {
                    let start = address & !0xfff;
                    let end = (address + length as u64 - 1) & !0xfff;
                    let mut page = start;
                    while page <= end {
                        pages.insert(page);
                        page += 0x1000;
                    }
                    wrote_code = true;
                }
            }
            if wrote_code {
                let _ = jit.invalidate_blocks_on_pages(&pages);
                // `invalidate_blocks_on_pages` clears slice links for an
                // overlapping page; a conservative epoch guard always does.
                jit.clear_slice_blocks();
            }
        } // coverage: unreachable — jit_runtime was required (unwrapped) before the dispatch, so this if-let cannot take its None path
        Ok(runs)
    }

    /// Production pump fast path.  When at least one runnable guest thread
    /// already has a worker-safe compiled slice, run every such thread on the
    /// native pool concurrently and requeue them at the barrier/budget.  Any
    /// thread that needs the runtime owner is left queued for the ordinary
    /// cooperative pump (which executes host thunks exactly once).
    fn try_pump_parallel_slices(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PumpOutcome>> {
        if !matches!(self.scheduler_mode, SchedulerMode::Production { .. })
            || self.production_scheduler.is_none()
            || self.jit_runtime.is_none()
            || !self.production_waits.is_empty()
        {
            return Ok(None);
        }
        let worker_limit = self.scheduler_mode.worker_count();
        let now = self.win32.get_tick_count64();
        let candidates: Vec<GuestThreadContext> = self
            .pending_guest_threads
            .iter()
            .filter(|thread| {
                thread.started
                    && thread.suspended == 0
                    && thread.state_machine == GuestThreadState::Runnable
                    && thread.wait.is_none()
                    && thread.wait_resume.is_none()
                    && !self.production_waits.contains_key(&thread.thread_id)
                    && !self.win32.thread_has_exited(thread.thread_id)
                    && thread.state.rip != 0
                    && thread.wake_tick <= now
            })
            .take(worker_limit)
            .map(|thread| {
                let last_error = if thread.teb_base != 0 {
                    memory
                        .read_u32(thread.teb_base + teb_last_error_offset(thread.state.arch))
                        .unwrap_or(0)
                } else {
                    self.fallback_last_errors
                        .get(&thread.thread_id)
                        .copied()
                        .unwrap_or(0)
                };
                let mut context = GuestThreadContext::from_pending(thread, last_error);
                context.priority = self.win32.thread_priority_by_id(thread.thread_id);
                context
            })
            .collect();
        let mut contexts = Vec::with_capacity(candidates.len());
        for context in candidates {
            // A block the slice compiler cannot handle is not an error: the
            // ordinary cooperative owner path executes it below.
            if matches!(self.ensure_slice_block(memory, context.state.rip), Ok(true)) {
                contexts.push(context);
            }
        }
        if contexts.is_empty() {
            return Ok(None);
        }
        let runs =
            self.dispatch_parallel_thread_contexts(memory, contexts, PRODUCTION_SLICE_BLOCKS)?;
        if runs.is_empty() {
            return Ok(None);
        }
        let mut processed = BTreeSet::new();
        for run in runs {
            if !processed.insert(run.context.thread_id) {
                continue;
            }
            let Some(index) = self
                .pending_guest_threads
                .iter()
                .position(|thread| thread.thread_id == run.context.thread_id)
            else {
                continue;
            };
            let Some(mut thread) = self.pending_guest_threads.remove(index) else {
                continue; // coverage: unreachable — index came from position() on the same unmodified Vec
            };
            thread.state = run.context.state;
            thread.tls_vector_ptr = run.context.tls_vector_ptr;
            if thread.teb_base != 0 {
                let _ = memory.write_u32(
                    thread.teb_base + teb_last_error_offset(thread.state.arch),
                    run.context.last_error,
                );
            } else {
                self.fallback_last_errors
                    .insert(thread.thread_id, run.context.last_error);
            }
            thread.state_machine = GuestThreadState::Runnable;
            self.pending_guest_threads.push_back(thread);
            notify_pump_wake();
        }
        Ok(Some(PumpOutcome {
            did_work: true,
            process_exit: None,
        }))
    }

    /// The scheduler mode this runtime is configured for.
    #[allow(dead_code)] // exposed for runtime diagnostics/tests
    pub(crate) fn scheduler_mode(&self) -> SchedulerMode {
        self.scheduler_mode
    }

    /// Select deterministic cooperative scheduling (default/test mode) or a
    /// bounded production worker pool.  Refuses to switch while guest waits
    /// are parked on the current mode's workers (the caller must let them
    /// drain or reset the runtime).
    pub(crate) fn set_scheduler_mode(&mut self, mode: SchedulerMode) -> bool {
        if !self.production_waits.is_empty() {
            return false;
        }
        match mode {
            SchedulerMode::Cooperative => {
                self.production_scheduler = None;
                self.scheduler_mode = SchedulerMode::Cooperative;
                true
            }
            SchedulerMode::Production { .. } => {
                let workers = mode.worker_count();
                let needs_pool = match self.production_scheduler.as_ref() {
                    Some(scheduler) => scheduler.worker_count() != workers,
                    None => true,
                };
                if needs_pool {
                    self.production_scheduler = Some(ProductionScheduler::with_process_shared(
                        workers,
                        Arc::clone(&self.process_shared),
                    ));
                }
                self.scheduler_mode = SchedulerMode::Production { workers };
                true
            }
        }
    }

    /// Instrumentation snapshot (process-wide atomics; tests use deltas).
    #[allow(dead_code)] // exposed for runtime diagnostics/tests
    pub(crate) fn scheduler_counters(&self) -> SchedulerCountersSnapshot {
        SCHEDULER_COUNTERS.snapshot()
    }

    /// Wake a guest thread parked on any alertable production wait after an
    /// APC was queued for it.
    pub(crate) fn notify_parked_apc(&self, thread_id: u32) {
        notify_thread_apc(thread_id);
    }

    fn production_wait_supported(&self, wait: &GuestWait) -> bool {
        match &wait.operation {
            WaitOperation::Sleep => true,
            WaitOperation::Objects => {
                !wait.objects.is_empty()
                    && wait.objects.iter().all(|handle| {
                        self.win32.describe_handle(*handle).is_ok_and(|descriptor| {
                            matches!(
                                descriptor.object_type,
                                crate::win32::ObjectType::Event
                                    | crate::win32::ObjectType::Mutex
                                    | crate::win32::ObjectType::Semaphore
                                    | crate::win32::ObjectType::Thread
                            )
                        })
                    })
            }
            WaitOperation::CompletionPort { port, .. }
            | WaitOperation::CompletionPortEx { port, .. } => {
                self.win32.io_completion_port_state(*port).is_ok()
            }
            _ => false,
        }
    }

    /// Hand a blocked guest thread to a native production worker.  Returns
    /// `false` when the wait has no event source the production pool can
    /// block on; the caller then keeps the cooperative pump path as a
    /// fallback (never loses the wait).
    fn start_production_wait(&mut self, thread_id: u32, wait: &GuestWait) -> bool {
        if !matches!(self.scheduler_mode, SchedulerMode::Production { .. }) {
            return false;
        }
        if !self.production_wait_supported(wait) {
            return false;
        }
        let signal = Arc::new(ParkSignal::new());
        let observed_generation = signal.generation();
        let now_tick = self.win32.get_tick_count64();
        let deadline = wait.deadline_ticks.map(|ticks| {
            let remaining = ticks.saturating_sub(now_tick);
            Instant::now()
                .checked_add(Duration::from_millis(remaining))
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(24 * 60 * 60))
        });
        let kind = match &wait.operation {
            WaitOperation::Sleep => {
                if wait.alertable {
                    wake_bus().subscribe_thread(thread_id, &signal);
                }
                WaitJobKind::DeadlineOnly
            }
            WaitOperation::Objects => {
                for handle in &wait.objects {
                    let Ok(descriptor) = self.win32.describe_handle(*handle) else {
                        return false; // coverage: unreachable (validated above, single owner)
                    };
                    match descriptor.object_type {
                        crate::win32::ObjectType::Thread => {
                            let Ok(target) = self.win32.thread_id_for_handle(*handle) else {
                                return false; // coverage: unreachable (thread handle validated)
                            };
                            wake_bus().subscribe_thread(target, &signal);
                        }
                        crate::win32::ObjectType::Event
                        | crate::win32::ObjectType::Mutex
                        | crate::win32::ObjectType::Semaphore => {
                            let Ok(id) = self.win32.handle_object_identity(*handle) else {
                                return false; // coverage: unreachable (handle validated)
                            };
                            wake_bus().subscribe_object(id, &signal);
                        }
                        _ => return false, // coverage: unreachable (type checked above)
                    }
                }
                if wait.alertable {
                    wake_bus().subscribe_thread(thread_id, &signal);
                }
                WaitJobKind::Objects
            }
            WaitOperation::CompletionPort { port, .. } => {
                let Ok(state) = self.win32.io_completion_port_state(*port) else {
                    return false; // coverage: unreachable (port validated above)
                };
                if wait.alertable {
                    wake_bus().subscribe_thread(thread_id, &signal);
                }
                WaitJobKind::CompletionPort {
                    state,
                    guest_thread_id: thread_id,
                    max_packets: 1,
                    alertable: wait.alertable,
                }
            }
            WaitOperation::CompletionPortEx {
                port, entry_count, ..
            } => {
                let Ok(state) = self.win32.io_completion_port_state(*port) else {
                    return false; // coverage: unreachable (port validated above)
                };
                if wait.alertable {
                    wake_bus().subscribe_thread(thread_id, &signal);
                }
                WaitJobKind::CompletionPort {
                    state,
                    guest_thread_id: thread_id,
                    max_packets: (*entry_count).max(1) as usize,
                    alertable: wait.alertable,
                }
            }
            _ => return false, // coverage: unreachable (supported() rejects it first)
        };
        let Some(scheduler) = self.production_scheduler.as_ref() else {
            return false; // coverage: unreachable (Production mode owns a pool)
        };
        let job_id = scheduler.submit(
            thread_id,
            Arc::clone(&signal),
            observed_generation,
            kind,
            deadline,
        );
        // A thread may block before its first slice: create its persistent
        // slot so the wait object (and later predictor/IC state) survives.
        if let Some(thread) = self
            .pending_guest_threads
            .iter()
            .find(|thread| thread.thread_id == thread_id)
        {
            let state = thread.state.clone();
            scheduler.ensure_slot(thread_id, &state);
        }
        scheduler.set_slot_wait(thread_id, signal);
        self.production_waits
            .insert(thread_id, ProductionWait { job_id });
        true
    }

    /// Drop wait-job bookkeeping for guest threads that are no longer parked
    /// (TerminateThread, process-exit abandonment).  Late completions for the
    /// removed job are ignored by the completion pass.
    fn prune_orphan_production_waits(&mut self) {
        let live: BTreeSet<u32> = self
            .pending_guest_threads
            .iter()
            .map(|thread| thread.thread_id)
            .collect();
        // Persistent slots outlive waits, so retire them on every pass (a
        // terminating thread may never have had a production wait).
        if let Some(scheduler) = self.production_scheduler.as_ref() {
            scheduler.retire_slots(&live);
        }
        if self.production_waits.is_empty() {
            return;
        }
        self.production_waits
            .retain(|thread_id, _| live.contains(thread_id));
    }

    /// Reap worker completions and re-queue their guest threads.  Runs on the
    /// runtime thread with exclusive access, so applying a wait result (and
    /// consuming a signal) is atomic with respect to guest execution.
    fn reap_production_completions(&mut self, memory: &mut MemoryImage) -> AppResult<bool> {
        let completions = match self.production_scheduler.as_ref() {
            Some(scheduler) => scheduler.take_completions(),
            None => return Ok(false),
        };
        let mut did_work = false;
        for completion in completions {
            did_work |= self.apply_production_completion(completion, memory)?;
        }
        if did_work {
            // Applying a completion re-queues a runnable guest thread; keep
            // the pump's wake epoch in step with that transition.
            notify_pump_wake();
        }
        Ok(did_work)
    }

    fn apply_production_completion(
        &mut self,
        completion: WaitCompletion,
        memory: &mut MemoryImage,
    ) -> AppResult<bool> {
        let Some(parked) = self.production_waits.get(&completion.thread_id) else {
            return Ok(false);
        };
        if parked.job_id != completion.job_id {
            return Ok(false);
        }
        let Some(index) = self
            .pending_guest_threads
            .iter()
            .position(|thread| thread.thread_id == completion.thread_id)
        else {
            // A terminated record is pruned before completions are applied.
            self.production_waits.remove(&completion.thread_id); // coverage: unreachable
            return Ok(false); // coverage: unreachable
        };
        let mut thread = self
            .pending_guest_threads
            .remove(index)
            .expect("checked parked thread index");
        self.production_waits.remove(&completion.thread_id);
        if let Some(scheduler) = self.production_scheduler.as_ref() {
            scheduler.clear_slot_wait(completion.thread_id);
        }
        let Some(wait) = thread.wait.clone() else {
            self.pending_guest_threads.push_back(thread); // coverage: unreachable
            notify_pump_wake(); // coverage: unreachable
            return Ok(true); // coverage: unreachable
        };
        let resume = match completion.reason {
            WaitWakeReason::CompletionPort => Some(self.completion_port_packets_resume(
                &wait.operation,
                completion.packets,
                memory,
            )?),
            WaitWakeReason::PortClosed => Some(Self::completion_port_closed_resume()),
            WaitWakeReason::PortTimedOut
            | WaitWakeReason::Deadline
            | WaitWakeReason::Apc
            | WaitWakeReason::ObjectSignaled
            | WaitWakeReason::ObjectClosed
            | WaitWakeReason::ThreadExit
            | WaitWakeReason::Shutdown => {
                // A worker deadline is real host time; bring the guest clock
                // to the same deadline before the (guest-clock-driven) wait
                // consumption pass evaluates the timeout.  Event wakeups do
                // not advance the clock.
                if matches!(
                    completion.reason,
                    WaitWakeReason::Deadline | WaitWakeReason::PortTimedOut
                ) && let Some(deadline_ticks) = wait.deadline_ticks
                {
                    let now = self.win32.get_tick_count64();
                    if deadline_ticks > now {
                        let elapsed = deadline_ticks - now;
                        self.win32.record_sleep_observation(elapsed, elapsed);
                    }
                }
                if self.wait_satisfiable(&thread) {
                    Some(self.complete_wait(&wait, completion.thread_id, memory)?)
                } else {
                    None
                }
            }
        };
        match resume {
            Some(resume) => {
                thread.wait_resume = Some(resume);
                thread.state_machine = GuestThreadState::Runnable;
                // A completion-port packet was already consumed by the
                // worker; the pump must never consume a second packet.
                if matches!(
                    completion.reason,
                    WaitWakeReason::CompletionPort | WaitWakeReason::PortClosed
                ) {
                    thread.wait = None;
                }
                self.pending_guest_threads.push_back(thread);
                notify_pump_wake();
            }
            None => {
                thread.state_machine = GuestThreadState::Waiting;
                self.pending_guest_threads.push_back(thread);
                let _ = self.start_production_wait(completion.thread_id, &wait);
                notify_pump_wake();
                SCHEDULER_COUNTERS
                    .repark_events
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(true)
    }

    /// Defensive empty-packet resume; production workers never submit an
    /// empty completion for a packet wait.
    #[rustfmt::skip]
    fn empty_packet_resume() -> WaitResume { // coverage: unreachable
        WaitResume { // coverage: unreachable
            code: 0, // coverage: unreachable
            bytes: None, // coverage: unreachable
            last_error: Some(crate::win32::WAIT_TIMEOUT), // coverage: unreachable
        } // coverage: unreachable
    } // coverage: unreachable

    /// Build a resume result from packets a production worker dequeued from a
    /// completion port.  Writes exactly the same guest out-parameters as the
    /// cooperative dequeue path.
    fn completion_port_packets_resume(
        &self,
        operation: &WaitOperation,
        packets: Vec<crate::win32::IoCompletionPacket>,
        memory: &mut MemoryImage,
    ) -> AppResult<WaitResume> {
        use std::sync::atomic::Ordering::Relaxed;
        match operation {
            WaitOperation::CompletionPort {
                bytes_ptr,
                key_ptr,
                overlapped_ptr,
                ..
            } => {
                let Some(packet) = packets.into_iter().next() else {
                    return Ok(Self::empty_packet_resume()); // coverage: unreachable
                };
                if *bytes_ptr != 0 {
                    write_u32(memory, *bytes_ptr, packet.bytes_transferred);
                }
                if *key_ptr != 0 {
                    write_guest_pointer(memory, *key_ptr, packet.completion_key, self.guest_arch)?;
                }
                if *overlapped_ptr != 0 {
                    write_guest_pointer(
                        memory,
                        *overlapped_ptr,
                        packet.overlapped,
                        self.guest_arch,
                    )?;
                }
                SCHEDULER_COUNTERS
                    .completion_port_wakeups
                    .fetch_add(1, Relaxed);
                Ok(WaitResume {
                    code: 1, // TRUE
                    bytes: Some(packet.bytes_transferred),
                    last_error: None,
                })
            }
            WaitOperation::CompletionPortEx {
                entries_ptr,
                removed_ptr,
                ..
            } => {
                if packets.is_empty() {
                    return Ok(Self::empty_packet_resume()); // coverage: unreachable
                }
                let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
                let entry_stride = pointer_bytes * 4;
                for (index, packet) in packets.iter().enumerate() {
                    if *entries_ptr == 0 {
                        break; // coverage: unreachable (caller always supplies entries)
                    }
                    let entry = *entries_ptr + index as u64 * entry_stride;
                    write_guest_pointer(memory, entry, packet.completion_key, self.guest_arch)?;
                    write_guest_pointer(
                        memory,
                        entry + pointer_bytes,
                        packet.overlapped,
                        self.guest_arch,
                    )?;
                    write_guest_pointer(
                        memory,
                        entry + pointer_bytes * 2,
                        packet.internal,
                        self.guest_arch,
                    )?;
                    write_u32(memory, entry + pointer_bytes * 3, packet.bytes_transferred);
                }
                if *removed_ptr != 0 {
                    write_u32(memory, *removed_ptr, packets.len() as u32);
                }
                SCHEDULER_COUNTERS
                    .completion_port_wakeups
                    .fetch_add(1, Relaxed);
                Ok(WaitResume {
                    code: 1, // TRUE
                    bytes: Some(packets.len() as u32),
                    last_error: None,
                })
            }
            _ => Ok(Self::empty_packet_resume()), // coverage: unreachable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use crate::pe_runtime::{HostThunk, NtThunkSession};

    const ENTRY_POINT: u64 = 0x41_100;
    const FLAG_PTR: u64 = 0x41_200;
    const THREAD_ID_PTR: u64 = 0x41_240;
    const BYTES_PTR: u64 = 0x41_300;
    const KEY_PTR: u64 = 0x41_308;
    const OVERLAPPED_PTR: u64 = 0x41_310;
    const ENTRIES_PTR: u64 = 0x41_400;
    const REMOVED_PTR: u64 = 0x41_480;
    const CONTINUATION_RSP: u64 = 0x10_F00;

    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn test_session() -> (tempfile::TempDir, NtThunkSession) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "scheduler-iocp",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("game environment");
        let mut session = NtThunkSession::new(ge);
        session.set_guest_arch(GuestArch::X86);
        (temp_dir, session)
    }

    fn map_cp_continuation(session: &mut NtThunkSession) {
        let mut bytes = vec![0x90_u8; 0x40];
        let mut routine = vec![0xC7, 0x05];
        routine.extend_from_slice(&(FLAG_PTR as u32).to_le_bytes());
        routine.extend_from_slice(&1_u32.to_le_bytes());
        routine.extend_from_slice(&[0x33, 0xC0, 0xC3]);
        bytes[..routine.len()].copy_from_slice(&routine);
        session.map_guest(ENTRY_POINT, &bytes);
        session.map_guest(FLAG_PTR, &[0_u8; 4]);
        session.map_guest(THREAD_ID_PTR, &[0_u8; 4]);
        session.map_guest(BYTES_PTR, &[0_u8; 4]);
        session.map_guest(KEY_PTR, &[0_u8; 8]);
        session.map_guest(OVERLAPPED_PTR, &[0_u8; 8]);
        session.map_guest(ENTRIES_PTR, &[0_u8; 32]);
        session.map_guest(REMOVED_PTR, &[0_u8; 4]);
    }

    fn cp_wait(port: u32, deadline_ticks: Option<u64>) -> GuestWait {
        GuestWait {
            objects: Vec::new(),
            wait_all: false,
            deadline_ticks,
            alertable: false,
            operation: WaitOperation::CompletionPort {
                port,
                bytes_ptr: BYTES_PTR,
                key_ptr: KEY_PTR,
                overlapped_ptr: OVERLAPPED_PTR,
            },
        }
    }

    fn cp_wait_ex(port: u32, entry_count: u32) -> GuestWait {
        GuestWait {
            objects: Vec::new(),
            wait_all: false,
            deadline_ticks: None,
            alertable: false,
            operation: WaitOperation::CompletionPortEx {
                port,
                entries_ptr: ENTRIES_PTR,
                entry_count,
                removed_ptr: REMOVED_PTR,
            },
        }
    }

    fn park_main_thread(session: &mut NtThunkSession, wait: GuestWait) {
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = ENTRY_POINT;
        state.set(Register::Rsp, CONTINUATION_RSP);
        state.segment_bases.fs = session.runtime.teb_base;
        session.runtime.park_for_wait(&mut state, wait);
    }

    fn parker_satisfiable(session: &NtThunkSession) -> bool {
        session
            .runtime
            .pending_guest_threads
            .iter()
            .any(|thread| session.runtime.wait_satisfiable(thread))
    }

    fn pump_once(session: &mut NtThunkSession) -> bool {
        session
            .runtime
            .pump_pending_guest_thread(&mut session.memory)
            .expect("pump")
            .did_work
    }

    fn read_u32_guest(session: &NtThunkSession, address: u64) -> u32 {
        u32::from_le_bytes(session.read_guest(address, 4).try_into().expect("u32 read"))
    }

    fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    fn test_packet(bytes: u32, key: u64, overlapped: u64) -> crate::win32::IoCompletionPacket {
        crate::win32::IoCompletionPacket {
            bytes_transferred: bytes,
            completion_key: key,
            overlapped,
            internal: 0,
        }
    }

    fn object_wait(handle: u32) -> GuestWait {
        GuestWait {
            objects: vec![handle],
            wait_all: false,
            deadline_ticks: None,
            alertable: false,
            operation: WaitOperation::Objects,
        }
    }

    /// Minimal synthetic pending record for scheduler deadline tests.  It has
    /// no wait descriptor, so its only deadline is `wake_tick`.
    fn synthetic_pending_thread(
        thread_id: u32,
        wake_tick: u64,
        state_machine: GuestThreadState,
    ) -> PendingGuestThread {
        PendingGuestThread {
            handle: thread_id,
            thread_id,
            start_address: ENTRY_POINT,
            parameter: 0,
            initial_rsp: CONTINUATION_RSP,
            started: true,
            suspended: 0,
            wake_tick,
            teb_base: 0,
            tls_vector_ptr: 0,
            tls_slots: BTreeMap::new(),
            fls_slots: BTreeMap::new(),
            state: CpuState::new(GuestArch::X86),
            state_machine,
            exit_code_override: None,
            wait: None,
            wait_resume: None,
        }
    }

    const RESUME_CODE_PTR: u64 = 0x42_580;
    const APC_ENTRY: u64 = 0x42_500;
    const APC_FLAG_PTR: u64 = 0x42_540;

    fn map_resume_code_probe(session: &mut NtThunkSession) {
        let mut bytes = Vec::new();
        // mov dword ptr [RESUME_CODE_PTR], eax
        bytes.push(0xA3);
        bytes.extend_from_slice(&(RESUME_CODE_PTR as u32).to_le_bytes());
        // mov dword ptr [FLAG_PTR], 1
        bytes.extend_from_slice(&[0xC7, 0x05]);
        bytes.extend_from_slice(&(FLAG_PTR as u32).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        // xor eax, eax; ret
        bytes.extend_from_slice(&[0x33, 0xC0, 0xC3]);
        session.map_guest(ENTRY_POINT, &bytes);
        session.map_guest(RESUME_CODE_PTR, &[0_u8; 4]);
        session.map_guest(FLAG_PTR, &[0_u8; 4]);
    }

    fn map_apc_callback(session: &mut NtThunkSession) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xC7, 0x05]);
        bytes.extend_from_slice(&(APC_FLAG_PTR as u32).to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(0xC3);
        session.map_guest(APC_ENTRY, &bytes);
        session.map_guest(APC_FLAG_PTR, &[0_u8; 4]);
    }

    fn wait_until_worker_active(session: &NtThunkSession, expected: usize) {
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while scheduler.active_job_count() < expected {
            assert!(
                std::time::Instant::now() < deadline,
                "native worker never picked up the parked guest wait"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn production_event_wait_wakes_with_latency_bound_and_zero_idle_polls_no_busy_wait() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event, created) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(!created);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );

        park_main_thread(&mut session, object_wait(event));
        let tid = session.runtime.pending_guest_threads[0].thread_id;
        assert_eq!(
            session.runtime.production_waits.len(),
            1,
            "the wait is owned by a native production job"
        );
        assert!(
            !pump_once(&mut session),
            "a production-parked wait never runs early"
        );
        wait_until_worker_active(&session, 1);
        let before = SCHEDULER_COUNTERS.snapshot();

        let signal_started = std::time::Instant::now();
        session.runtime.win32.set_event(event).expect("set event");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(
            scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))),
            "the native worker must report the wake"
        );
        let wake_latency = signal_started.elapsed();
        assert!(
            wake_latency < std::time::Duration::from_millis(500),
            "wake latency bound exceeded: {wake_latency:?}"
        );

        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap"),
            "the completion must resume the parked thread"
        );
        assert_eq!(session.runtime.production_waits.len(), 0);
        assert!(pump_once(&mut session), "the woken thread runs");
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert!(
            !session
                .runtime
                .win32
                .event_previous_state(event)
                .expect("event state"),
            "auto-reset event consumed exactly once"
        );

        let after = session.runtime.scheduler_counters();
        assert_eq!(after.wakeups, SCHEDULER_COUNTERS.snapshot().wakeups);
        assert_eq!(SchedulerMode::Cooperative.worker_count(), 0);
        assert_eq!(
            after.poll_iterations, before.poll_iterations,
            "a production event wait must not enter the 1 ms idle poll"
        );
        assert_ne!(
            after.wakeups, before.wakeups,
            "the native wakeup counter must advance"
        );
        assert_ne!(
            after.object_wakeups, before.object_wakeups,
            "the object-manager notification must reach a parked waiter"
        );
        let _ = tid;
    }

    #[test]
    fn production_worker_overlap_race_is_exact_on_two_host_workers() {
        let _guard = test_guard();
        let scheduler = ProductionScheduler::new(2);
        let before = SCHEDULER_COUNTERS.snapshot();
        let first = Arc::new(ParkSignal::new());
        let second = Arc::new(ParkSignal::new());
        let deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let first_id = scheduler.submit(
            101,
            Arc::clone(&first),
            0,
            WaitJobKind::DeadlineOnly,
            deadline,
        );
        let second_id = scheduler.submit(
            102,
            Arc::clone(&second),
            0,
            WaitJobKind::DeadlineOnly,
            deadline,
        );
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while scheduler.active_job_count() < 2 {
            assert!(
                std::time::Instant::now() < wait_deadline,
                "both guest waits must occupy native workers at the same time"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            scheduler.active_job_count(),
            2,
            "overlap proof: two guest waits active on two host workers"
        );
        first.notify(WaitWakeReason::ObjectSignaled);
        second.notify(WaitWakeReason::ObjectSignaled);
        let mut completions = Vec::new();
        let collect_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while completions.len() < 2 {
            assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
            completions.extend(scheduler.take_completions());
            assert!(
                std::time::Instant::now() < collect_deadline,
                "both workers must report their completion"
            );
        }
        assert_eq!(completions.len(), 2);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_ne!(
            after.worker_overlaps, before.worker_overlaps,
            "overlap accounting must observe concurrency"
        );
        let ids = completions
            .iter()
            .map(|completion| completion.job_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 2, "each wait job completes exactly once");
        assert_eq!(ids, BTreeSet::from([first_id, second_id]));
        assert_eq!(scheduler.active_job_count(), 0);
        drop(scheduler);
    }

    #[test]
    fn production_blocking_wait_and_shutdown_races_never_lose_a_worker() {
        let _guard = test_guard();
        // Blocking (no timeout) completion wait: covered by a late notifier.
        let scheduler = ProductionScheduler::new(1);
        let signal = Arc::new(ParkSignal::new());
        let job_id = scheduler.submit(
            201,
            Arc::clone(&signal),
            0,
            WaitJobKind::DeadlineOnly,
            Some(std::time::Instant::now() + std::time::Duration::from_secs(5)),
        );
        let notifier = {
            let signal = Arc::clone(&signal);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(15));
                signal.notify(WaitWakeReason::ObjectSignaled);
            })
        };
        assert!(
            scheduler.wait_for_completion(None),
            "an untimed completion wait must wake on the real event"
        );
        notifier.join().expect("notifier");
        let completions = scheduler.take_completions();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].job_id, job_id);
        drop(scheduler);

        // Dropping the pool must join a worker blocked inside the port's own
        // condvar, even with no packet and no deadline.
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let scheduler = ProductionScheduler::new(1);
        let signal = Arc::new(ParkSignal::new());
        let _ = scheduler.submit(
            202,
            signal,
            0,
            WaitJobKind::CompletionPort {
                state: port_state,
                guest_thread_id: 202,
                max_packets: 1,
                alertable: false,
            },
            None,
        );
        let active_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while scheduler.active_job_count() == 0 {
            assert!(std::time::Instant::now() < active_deadline);
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        let shutdown_started = std::time::Instant::now();
        drop(scheduler);
        assert!(
            shutdown_started.elapsed() < std::time::Duration::from_secs(2),
            "pool shutdown must wake/join a blocked IOCP worker"
        );
    }

    #[test]
    fn production_migration_counter_race_is_exact() {
        let _guard = test_guard();
        let scheduler = ProductionScheduler::new(2);
        let before = SCHEDULER_COUNTERS.snapshot();
        let first = Arc::new(ParkSignal::new());
        let first_id = scheduler.submit(
            301,
            Arc::clone(&first),
            0,
            WaitJobKind::DeadlineOnly,
            Some(std::time::Instant::now() + std::time::Duration::from_secs(5)),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while scheduler.active_job_count() < 1 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let second = Arc::new(ParkSignal::new());
        let second_id = scheduler.submit(
            301,
            Arc::clone(&second),
            0,
            WaitJobKind::DeadlineOnly,
            Some(std::time::Instant::now() + std::time::Duration::from_secs(5)),
        );
        while scheduler.active_job_count() < 2 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_ne!(
            SCHEDULER_COUNTERS.snapshot().migrations,
            before.migrations,
            "the same guest thread ran on two different host workers"
        );
        first.notify(WaitWakeReason::ObjectSignaled);
        second.notify(WaitWakeReason::ObjectSignaled);
        let mut ids = BTreeSet::new();
        while ids.len() < 2 {
            assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
            for completion in scheduler.take_completions() {
                ids.insert(completion.job_id);
            }
        }
        assert_eq!(ids, BTreeSet::from([first_id, second_id]));
        drop(scheduler);
    }

    #[test]
    fn production_contention_stress_has_exact_completion_invariants() {
        let _guard = test_guard();
        const JOBS: usize = 32;
        let scheduler = ProductionScheduler::new(4);
        let mut job_ids = BTreeSet::new();
        let mut signals = Vec::new();
        let deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
        for thread_id in 0..JOBS as u32 {
            let signal = Arc::new(ParkSignal::new());
            let job_id = scheduler.submit(
                thread_id,
                Arc::clone(&signal),
                0,
                WaitJobKind::DeadlineOnly,
                deadline,
            );
            assert!(job_ids.insert(job_id), "job ids are unique");
            signals.push(signal);
        }
        assert_eq!(job_ids.len(), JOBS);
        for signal in &signals {
            signal.notify(WaitWakeReason::ObjectSignaled);
        }

        let mut completed = BTreeSet::new();
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while completed.len() < JOBS {
            assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
            for completion in scheduler.take_completions() {
                assert_eq!(
                    completion.reason,
                    WaitWakeReason::ObjectSignaled,
                    "every job must observe its real wake, not a timeout"
                );
                assert!(
                    completed.insert(completion.job_id),
                    "a wait job must never complete twice"
                );
            }
            assert!(
                std::time::Instant::now() < wait_deadline,
                "contention stress lost a completion"
            );
        }
        assert_eq!(completed, job_ids);
        assert_eq!(scheduler.active_job_count(), 0);
        drop(scheduler);
    }

    #[test]
    fn production_port_close_race_wakes_with_abandoned_error_not_a_packet() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        park_main_thread(&mut session, cp_wait(port, None));
        wait_until_worker_active(&session, 1);
        let before = SCHEDULER_COUNTERS.snapshot();

        session
            .runtime
            .win32
            .close_handle(port)
            .expect("close port while parked");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(
            session.runtime.last_error,
            crate::win32::ERROR_ABANDONED_WAIT_0
        );
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(session.runtime.production_waits.len(), 0);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(
            after.completion_port_wakeups, before.completion_port_wakeups,
            "a closed port is not a packet handoff"
        );
        assert_eq!(
            after.poll_iterations, before.poll_iterations,
            "close wakeup is event-driven"
        );
    }

    #[test]
    fn production_pump_driven_completion_port_wake_is_event_driven_without_busy_wait() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        park_main_thread(&mut session, cp_wait(port, None));
        let before = SCHEDULER_COUNTERS.snapshot();

        let posted_at = Arc::new(std::sync::Mutex::new(None));
        let poster_state = Arc::clone(&port_state);
        let poster_posted_at = Arc::clone(&posted_at);
        let poster = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            *poster_posted_at.lock().unwrap() = Some(std::time::Instant::now());
            poster_state
                .post(test_packet(7, 0x5151, 0x6161))
                .expect("post packet");
        });

        let mut steps = 0_u64;
        let exit_code = session
            .runtime
            .run_pump_driven(&mut session.memory, &mut steps, 0)
            .expect("pump-driven run");
        poster.join().expect("poster");
        let posted_at = posted_at.lock().unwrap().expect("post timestamp");
        assert_eq!(exit_code, 0);
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(read_u32_guest(&session, BYTES_PTR), 7);
        assert_eq!(read_u32_guest(&session, KEY_PTR), 0x5151);
        assert_eq!(read_u32_guest(&session, OVERLAPPED_PTR), 0x6161);
        assert_eq!(port_state.queued_packet_count(), 0);
        let wake_latency = posted_at.elapsed();
        assert!(
            wake_latency < std::time::Duration::from_millis(500),
            "parked IOCP wake latency bound exceeded: {wake_latency:?}"
        );
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(
            after.poll_iterations, before.poll_iterations,
            "production pump-driven idle waiting must not use the 1 ms poll"
        );
        assert_eq!(session.runtime.production_waits.len(), 0);
    }

    #[test]
    fn production_mutex_release_wake_race_is_exact_without_busy_wait() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let before = SCHEDULER_COUNTERS.snapshot();
        let main_tid = session.runtime.win32.current_thread_id();
        let owner_tid = main_tid.wrapping_add(1);

        let mutex = session.runtime.win32.create_mutex(false, false);
        session.runtime.win32.set_current_thread_id(owner_tid);
        assert_eq!(
            session
                .runtime
                .win32
                .wait_for_single_object_instant(mutex, crate::win32::ObjectType::Mutex, owner_tid)
                .expect("acquire"),
            crate::win32::WaitStatus::Object0
        );
        session.runtime.win32.set_current_thread_id(main_tid);
        park_main_thread(&mut session, object_wait(mutex));
        wait_until_worker_active(&session, 1);
        session.runtime.win32.set_current_thread_id(owner_tid);
        session
            .runtime
            .win32
            .release_mutex(mutex)
            .expect("release mutex");
        session.runtime.win32.set_current_thread_id(main_tid);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        // The resumed waiter took ownership; ending the guest thread in the
        // pump (its continuation returned) abandons the owned mutex, so a
        // third thread observes WAIT_ABANDONED — proof the waiter acquired it.
        assert_eq!(
            session
                .runtime
                .win32
                .wait_for_single_object_instant(mutex, crate::win32::ObjectType::Mutex, owner_tid)
                .expect("mutex probe"),
            crate::win32::WaitStatus::Abandoned
        );

        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(
            after.poll_iterations, before.poll_iterations,
            "mutex wake is event-driven"
        );
        assert_ne!(after.object_wakeups, before.object_wakeups);
    }

    #[test]
    fn production_semaphore_release_wake_race_is_exact_without_busy_wait() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let before = SCHEDULER_COUNTERS.snapshot();
        let semaphore = session.runtime.win32.create_semaphore(0, 2, false);
        park_main_thread(&mut session, object_wait(semaphore));
        wait_until_worker_active(&session, 1);
        assert_eq!(
            session
                .runtime
                .win32
                .release_semaphore(semaphore, 1)
                .expect("release semaphore"),
            0,
            "the permit count was exhausted before release"
        );
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(
            read_u32_guest(&session, FLAG_PTR),
            1,
            "the semaphore waiter resumed"
        );
        assert_eq!(
            session
                .runtime
                .win32
                .release_semaphore(semaphore, 1)
                .expect("post-acquire count"),
            0,
            "the resumed waiter consumed the released permit"
        );
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(
            after.poll_iterations, before.poll_iterations,
            "semaphore wake is event-driven"
        );
        assert_ne!(after.object_wakeups, before.object_wakeups);
    }

    #[test]
    fn production_deadline_wake_race_advances_guest_clock_exactly() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_resume_code_probe(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let deadline = session.runtime.win32.get_tick_count64().saturating_add(30);
        let mut wait = object_wait(event);
        wait.deadline_ticks = Some(deadline);
        let before = SCHEDULER_COUNTERS.snapshot();
        let started = std::time::Instant::now();
        park_main_thread(&mut session, wait);
        wait_until_worker_active(&session, 1);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(
            read_u32_guest(&session, RESUME_CODE_PTR),
            crate::win32::WAIT_TIMEOUT
        );
        assert!(session.runtime.win32.get_tick_count64() >= deadline);
        assert_eq!(session.runtime.production_waits.len(), 0);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_ne!(after.deadline_wakeups, before.deadline_wakeups);
        assert_eq!(after.poll_iterations, before.poll_iterations);
    }

    #[test]
    fn production_alertable_apc_race_resumes_with_io_completion() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        map_apc_callback(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let mut wait = object_wait(event);
        wait.alertable = true;
        park_main_thread(&mut session, wait);
        wait_until_worker_active(&session, 1);
        let thread = &session.runtime.pending_guest_threads[0];
        let thread_handle = thread.handle;
        let tid = thread.thread_id;
        session
            .runtime
            .win32
            .queue_user_apc(thread_handle, APC_ENTRY, 0)
            .expect("queue APC");
        session
            .runtime
            .apc_queues
            .entry(u64::from(tid))
            .or_default()
            .queue_user_apc(APC_ENTRY, 0);
        let before = SCHEDULER_COUNTERS.snapshot();
        session.runtime.notify_parked_apc(tid);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(
            read_u32_guest(&session, APC_FLAG_PTR),
            1,
            "the APC callback ran before the wait reported"
        );
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_ne!(after.apc_wakeups, before.apc_wakeups);
        assert_eq!(after.poll_iterations, before.poll_iterations);
    }

    #[test]
    fn production_completion_port_alertable_apc_race_wakes_the_waiter() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        map_apc_callback(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("port");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let mut wait = cp_wait(port, None);
        wait.alertable = true;
        park_main_thread(&mut session, wait);
        wait_until_worker_active(&session, 1);
        let thread = &session.runtime.pending_guest_threads[0];
        let thread_handle = thread.handle;
        let tid = thread.thread_id;
        session
            .runtime
            .win32
            .queue_user_apc(thread_handle, APC_ENTRY, 0)
            .expect("queue APC");
        session
            .runtime
            .apc_queues
            .entry(u64::from(tid))
            .or_default()
            .queue_user_apc(APC_ENTRY, 0);
        let before = SCHEDULER_COUNTERS.snapshot();
        session.runtime.notify_parked_apc(tid);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, APC_FLAG_PTR), 1);
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_ne!(after.apc_wakeups, before.apc_wakeups);
        assert_ne!(after.port_rechecks, before.port_rechecks);
    }

    #[test]
    fn production_wait_all_repark_race_is_exact() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (first, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        let (second, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let before = SCHEDULER_COUNTERS.snapshot();
        let mut wait = object_wait(first);
        wait.objects = vec![first, second];
        wait.wait_all = true;
        park_main_thread(&mut session, wait);
        wait_until_worker_active(&session, 1);

        session.runtime.win32.set_event(first).expect("first event");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert_eq!(
            session.runtime.production_waits.len(),
            1,
            "a partial wait-all wake must re-park, never resume"
        );
        assert!(!pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 0);
        assert_ne!(
            SCHEDULER_COUNTERS.snapshot().repark_events,
            before.repark_events
        );

        session
            .runtime
            .win32
            .set_event(second)
            .expect("second event");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(session.runtime.production_waits.len(), 0);
    }

    #[test]
    fn production_sleep_wait_race_uses_native_deadline_worker() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let deadline = session.runtime.win32.get_tick_count64().saturating_add(30);
        let wait = GuestWait {
            objects: Vec::new(),
            wait_all: false,
            deadline_ticks: Some(deadline),
            alertable: true,
            operation: WaitOperation::Sleep,
        };
        let before = SCHEDULER_COUNTERS.snapshot();
        park_main_thread(&mut session, wait);
        wait_until_worker_active(&session, 1);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(session.runtime.production_waits.len(), 0);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_ne!(after.deadline_wakeups, before.deadline_wakeups);
        assert_eq!(after.poll_iterations, before.poll_iterations);

        // A deadline already in the past completes immediately (zero wait).
        let job = WaitJob {
            job_id: 0,
            thread_id: 0,
            signal: Arc::new(ParkSignal::new()),
            observed_generation: 0,
            kind: WaitJobKind::DeadlineOnly,
            deadline: Some(std::time::Instant::now()),
        };
        assert_eq!(run_wait_job(job).reason, WaitWakeReason::Deadline);
    }

    #[test]
    fn production_pumped_thread_dispatch_race_is_exact() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        // Create the record on the cooperative path, then hand it to the
        // production dispatcher exactly as the pump's yield branch does.
        park_main_thread(&mut session, object_wait(event));
        let record = session
            .runtime
            .pending_guest_threads
            .pop_back()
            .expect("parked record");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        assert!(
            session
                .runtime
                .park_pumped_thread_in_production(record)
                .is_none(),
            "a supported pumped wait is owned by a native worker"
        );
        assert_eq!(session.runtime.production_waits.len(), 1);
        assert_eq!(session.runtime.pending_guest_threads.len(), 1);
        wait_until_worker_active(&session, 1);
        session.runtime.win32.set_event(event).expect("set event");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);

        // An unsupported wait source must come back to the cooperative pump,
        // never lose the record, and never create a native wait job.
        let (_temp_dir2, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event2, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        park_main_thread(&mut session, object_wait(event2));
        let mut record = session
            .runtime
            .pending_guest_threads
            .pop_back()
            .expect("parked record");
        session.runtime.production_waits.remove(&record.thread_id);
        record.wait = Some(GuestWait {
            objects: Vec::new(),
            wait_all: false,
            deadline_ticks: None,
            alertable: false,
            operation: WaitOperation::PipeIo {
                pipe_handle: 0,
                kind: crate::win32::OverlappedKind::Read,
                overlapped_id: 0,
                buffer_ptr: 0,
                length: 0,
                bytes_read_ptr: 0,
            },
        });
        assert!(
            session
                .runtime
                .park_pumped_thread_in_production(record)
                .is_some(),
            "an unsupported wait stays on the cooperative path"
        );
        assert_eq!(session.runtime.production_waits.len(), 0);
    }

    #[test]
    fn production_completion_port_ex_race_writes_every_entry() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let mut ex_wait = cp_wait_ex(port, 1);
        ex_wait.alertable = true;
        // Queue the packet before the worker starts: a live worker may
        // (correctly) resume on the first available packet.
        port_state
            .post(test_packet(11, 0xAAA, 0xBBB))
            .expect("packet");
        assert_eq!(port_state.queued_packet_count(), 1);
        park_main_thread(&mut session, ex_wait);
        // The packet is already queued, so the worker may complete before we
        // could observe it active; wait for the completion, not the job slot.
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR), 0xAAA);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 4), 0xBBB);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 12), 11);
        assert_eq!(read_u32_guest(&session, REMOVED_PTR), 1);
        assert_eq!(port_state.queued_packet_count(), 0);

        // Multi-entry handoff is a pure write path; exercise it directly so
        // the assertion is independent of host scheduling.
        session.map_guest(ENTRIES_PTR, &[0_u8; 32]);
        session.map_guest(REMOVED_PTR, &[0_u8; 4]);
        let operation = WaitOperation::CompletionPortEx {
            port,
            entries_ptr: ENTRIES_PTR,
            entry_count: 4,
            removed_ptr: REMOVED_PTR,
        };
        let resume = session
            .runtime
            .completion_port_packets_resume(
                &operation,
                vec![test_packet(11, 0xAAA, 0xBBB), test_packet(22, 0xCCC, 0xDDD)],
                &mut session.memory,
            )
            .expect("multi-entry resume");
        assert_eq!(resume.code, 1);
        assert_eq!(resume.bytes, Some(2));
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR), 0xAAA);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 4), 0xBBB);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 12), 11);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 16), 0xCCC);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 20), 0xDDD);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 28), 22);
        assert_eq!(read_u32_guest(&session, REMOVED_PTR), 2);
    }

    #[test]
    fn production_completion_port_timeout_race_reports_wait_timeout() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let deadline = session.runtime.win32.get_tick_count64().saturating_add(25);
        let before = SCHEDULER_COUNTERS.snapshot();
        park_main_thread(&mut session, cp_wait(port, Some(deadline)));
        wait_until_worker_active(&session, 1);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(session.runtime.last_error, crate::win32::WAIT_TIMEOUT);
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(session.runtime.production_waits.len(), 0);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_ne!(after.deadline_wakeups, before.deadline_wakeups);
        assert_eq!(after.poll_iterations, before.poll_iterations);

        // A completion-port deadline already elapsed before the worker runs
        // completes immediately, without entering the port's condvar.
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let job = WaitJob {
            job_id: 0,
            thread_id: 0,
            signal: Arc::new(ParkSignal::new()),
            observed_generation: 0,
            kind: WaitJobKind::CompletionPort {
                state: port_state,
                guest_thread_id: 0,
                max_packets: 1,
                alertable: false,
            },
            deadline: Some(std::time::Instant::now()),
        };
        assert_eq!(run_wait_job(job).reason, WaitWakeReason::PortTimedOut);
    }

    #[test]
    fn production_thread_exit_race_wakes_join_without_polling() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let target = session.runtime.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let target_tid = session
            .runtime
            .win32
            .thread_id_for_handle(target)
            .expect("target thread id");
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let before = SCHEDULER_COUNTERS.snapshot();
        park_main_thread(&mut session, object_wait(target));
        wait_until_worker_active(&session, 1);
        session
            .runtime
            .win32
            .set_thread_exit_code_by_id(target_tid, 7)
            .expect("terminate target");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(
            session
                .runtime
                .win32
                .wait_for_single_object_instant(
                    target,
                    crate::win32::ObjectType::Thread,
                    session.runtime.win32.current_thread_id()
                )
                .expect("thread probe"),
            crate::win32::WaitStatus::Object0
        );
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(after.poll_iterations, before.poll_iterations);
    }

    #[test]
    fn production_mode_switch_race_refuses_while_wait_parked() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        park_main_thread(&mut session, object_wait(event));
        wait_until_worker_active(&session, 1);
        assert!(
            !session
                .runtime
                .set_scheduler_mode(SchedulerMode::Cooperative),
            "the mode switch must refuse while a wait is parked"
        );
        session.runtime.win32.set_event(event).expect("set event");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap")
        );
        assert!(pump_once(&mut session));
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Cooperative)
        );
        assert_eq!(session.runtime.scheduler_mode(), SchedulerMode::Cooperative);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
    }

    #[test]
    fn cooperative_pump_driven_idle_poll_race_remains_bounded() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        assert_eq!(session.runtime.scheduler_mode(), SchedulerMode::Cooperative);
        // A long finite deadline makes the fallback path unusable: the pump
        // can only complete before it if the real port post publishes a wake.
        let deadline = session
            .runtime
            .win32
            .get_tick_count64()
            .saturating_add(2_000);
        park_main_thread(&mut session, cp_wait(port, Some(deadline)));
        let before = SCHEDULER_COUNTERS.snapshot();
        let started = Instant::now();
        let poster_state = Arc::clone(&port_state);
        let poster = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            poster_state
                .post(test_packet(5, 0x7777, 0x8888))
                .expect("post");
            // No manual scheduler notification: CompletionPortWaitState::post
            // must publish the pump wake itself.
        });
        let mut steps = 0_u64;
        let exit_code = session
            .runtime
            .run_pump_driven(&mut session.memory, &mut steps, 0)
            .expect("cooperative pump run");
        poster.join().expect("poster");
        assert_eq!(exit_code, 0);
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(read_u32_guest(&session, BYTES_PTR), 5);
        // The only runnable transition was the poster's post after its 20 ms
        // delay; the idle pump must not resume before it, and must not wait for
        // the 500 ms guest deadline.
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(15),
            "the idle pump resumed before any wake source fired"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1_000),
            "the idle pump waited for the guest deadline instead of the real port post"
        );
        let after = SCHEDULER_COUNTERS.snapshot();
        assert!(
            after.poll_iterations == before.poll_iterations,
            "the cooperative idle pump is event-driven: no 1 ms poll ticks"
        );
    }

    #[test]
    fn pump_idle_wait_blocks_until_notified_and_never_returns_early() {
        let _guard = test_guard();
        let wake = Arc::new(PumpWake::new());
        let observed = wake.epoch();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = {
            let wake = Arc::clone(&wake);
            std::thread::spawn(move || {
                let outcome = wake.wait_until(observed, None);
                tx.send(outcome).expect("send idle-wait outcome");
            })
        };
        // No notification has been published: the wait must stay blocked.
        assert!(
            matches!(
                rx.recv_timeout(std::time::Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "the idle wait returned before any notification"
        );
        wake.notify();
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("idle wait must wake after the notification");
        assert_eq!(
            outcome,
            PumpWakeOutcome::Notified {
                epoch: observed.wrapping_add(1)
            }
        );
        waiter.join().expect("waiter thread");
    }

    #[test]
    fn pump_idle_deadline_timeout_returns_exact_timeout_state_not_early() {
        let _guard = test_guard();
        let wake = PumpWake::new();
        let observed = wake.epoch();
        let deadline = Instant::now() + std::time::Duration::from_millis(40);
        let outcome = wake.wait_until(observed, Some(deadline));
        assert_eq!(outcome, PumpWakeOutcome::TimedOut { epoch: observed });
        assert!(
            Instant::now() >= deadline,
            "the deadline wait returned before its exact timeout"
        );
    }

    #[test]
    fn pump_wake_before_wait_has_no_lost_wakeup_race() {
        let _guard = test_guard();
        let wake = PumpWake::new();
        let observed = wake.epoch();
        // The notification is published before the wait starts: the epoch
        // predicate must report it immediately instead of blocking until the
        // fallback deadline.
        wake.notify();
        let notified_epoch = observed.wrapping_add(1);
        assert_eq!(wake.epoch(), notified_epoch);
        let outcome = wake.wait_until(
            observed,
            Some(Instant::now() + std::time::Duration::from_millis(250)),
        );
        assert_eq!(
            outcome,
            PumpWakeOutcome::Notified {
                epoch: notified_epoch
            }
        );
    }

    #[test]
    fn cooperative_pump_driven_deadline_timeout_wakes_at_deadline_with_exact_state() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_resume_code_probe(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert_eq!(session.runtime.scheduler_mode(), SchedulerMode::Cooperative);
        let deadline = session.runtime.win32.get_tick_count64().saturating_add(25);
        let mut wait = object_wait(event);
        wait.deadline_ticks = Some(deadline);
        let before = SCHEDULER_COUNTERS.snapshot();
        let started = Instant::now();
        park_main_thread(&mut session, wait);
        let mut steps = 0_u64;
        let exit_code = session
            .runtime
            .run_pump_driven(&mut session.memory, &mut steps, 0)
            .expect("cooperative pump run");
        assert_eq!(exit_code, 0);
        assert_eq!(
            read_u32_guest(&session, RESUME_CODE_PTR),
            crate::win32::WAIT_TIMEOUT,
            "the timed-out wait resumes with the exact WAIT_TIMEOUT state"
        );
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert!(
            session.runtime.win32.get_tick_count64() >= deadline,
            "the pump resumed before the guest deadline"
        );
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(20),
            "the idle pump woke before its guest deadline"
        );
        let after = SCHEDULER_COUNTERS.snapshot();
        assert!(
            after.poll_iterations == before.poll_iterations,
            "a cooperative deadline wake must be event-driven, not a 1 ms poll"
        );
    }

    #[test]
    fn win32_completion_port_post_before_idle_wait_has_no_lost_wakeup_race() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");

        let observed = pump_wake().epoch();
        port_state
            .post(test_packet(3, 0x11, 0x22))
            .expect("post packet");
        let posted_epoch = pump_wake().epoch();
        assert_ne!(
            posted_epoch, observed,
            "a real port post must publish a pump wake"
        );
        let outcome = pump_wake().wait_until(
            observed,
            Some(Instant::now() + std::time::Duration::from_millis(250)),
        );
        match outcome {
            PumpWakeOutcome::Notified { epoch } => {
                assert_ne!(
                    epoch, observed,
                    "the post-before-wait notification was lost"
                )
            }
            PumpWakeOutcome::TimedOut { .. } => {
                panic!("the post-before-wait notification was lost")
            }
        }

        let observed = pump_wake().epoch();
        port_state.close();
        let closed_epoch = pump_wake().epoch();
        assert_ne!(
            closed_epoch, observed,
            "a port close must publish a pump wake"
        );
        let outcome = pump_wake().wait_until(
            observed,
            Some(Instant::now() + std::time::Duration::from_millis(250)),
        );
        match outcome {
            PumpWakeOutcome::Notified { epoch } => {
                assert_ne!(
                    epoch, observed,
                    "the close-before-wait notification was lost"
                )
            }
            PumpWakeOutcome::TimedOut { .. } => {
                panic!("the close-before-wait notification was lost")
            }
        }
    }

    #[test]
    fn cooperative_set_timer_deadline_timeout_wakes_at_expiry_without_early_wake() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let hwnd = 1;
        let timer_id = 7;
        assert!(
            session.runtime.user32.set_timer(hwnd, timer_id, 60, 0),
            "SetTimer must arm the guest timer"
        );
        let deadline = session
            .runtime
            .next_cooperative_wake_deadline()
            .expect("an armed guest timer is a cooperative wake deadline");
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            remaining >= std::time::Duration::from_millis(30),
            "the idle deadline fired early: {remaining:?}"
        );
        assert!(
            remaining <= std::time::Duration::from_millis(120),
            "the idle deadline missed the timer expiry: {remaining:?}"
        );
        // Wait exactly as the idle pump does, tolerating spurious wakeups.
        while Instant::now() < deadline {
            let observed = pump_wake().epoch();
            let _ = pump_wake().wait_until(observed, Some(deadline));
        }
        let expired = session.runtime.user32.poll_timers();
        assert_eq!(expired, vec![(hwnd, timer_id)]);
        // Win32 `SetTimer` re-arms a positive interval; the poll consumed the
        // first expiry and the cache must advance to the re-armed deadline.
        assert_eq!(session.runtime.user32.timer_count(), 1);
        assert!(
            session.runtime.user32.next_timer_timeout().is_some(),
            "the periodic timer must stay armed after the first expiry"
        );
        assert!(session.runtime.user32.kill_timer(hwnd, timer_id));
        assert_eq!(session.runtime.user32.next_timer_timeout(), None);
    }

    #[test]
    fn cooperative_pump_run_deadline_notification_wakes_cancellation_immediately() {
        let _guard = test_guard();
        struct ResetRunDeadline;
        impl Drop for ResetRunDeadline {
            fn drop(&mut self) {
                crate::runtime::RUN_DEADLINE_EXPIRED
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _reset = ResetRunDeadline;
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        // A far-future guest deadline: only the watchdog notification can end
        // this wait before two real seconds elapse.
        let deadline = session
            .runtime
            .win32
            .get_tick_count64()
            .saturating_add(2_000);
        let mut wait = object_wait(event);
        wait.deadline_ticks = Some(deadline);
        park_main_thread(&mut session, wait);
        let started = Instant::now();
        let canceller = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(30));
            crate::runtime::expire_run_deadline();
        });
        let mut steps = 0_u64;
        let exit_code = session
            .runtime
            .run_pump_driven(&mut session.memory, &mut steps, 0)
            .expect("cooperative pump run");
        crate::runtime::RUN_DEADLINE_EXPIRED.store(false, std::sync::atomic::Ordering::Release);
        canceller.join().expect("canceller");
        assert_eq!(exit_code, -2);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1_000),
            "run-deadline cancellation must wake the blocked pump immediately"
        );
    }

    #[test]
    fn scheduler_deadline_helper_skips_production_and_due_waits_race() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 1 }),
            "production mode must be selectable with no parked waits"
        );
        park_main_thread(&mut session, object_wait(event));
        assert_eq!(session.runtime.production_waits.len(), 1);
        let now = session.runtime.win32.get_tick_count64();
        session
            .runtime
            .enqueue_pending_guest_thread(synthetic_pending_thread(
                0xC1,
                now.saturating_add(200),
                GuestThreadState::Waiting,
            ));
        session
            .runtime
            .enqueue_pending_guest_thread(synthetic_pending_thread(
                0xC2,
                now,
                GuestThreadState::Waiting,
            ));
        session
            .runtime
            .enqueue_pending_guest_thread(synthetic_pending_thread(
                0xC3,
                now.saturating_add(9_000),
                GuestThreadState::Runnable,
            ));
        assert_eq!(session.runtime.pending_guest_threads.len(), 4);
        let deadline = session
            .runtime
            .next_cooperative_wake_deadline()
            .expect("a future cooperative yield is a deadline");
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            remaining >= std::time::Duration::from_millis(100),
            "a production/due wait shortened the deadline: {remaining:?}"
        );
        assert!(
            remaining <= std::time::Duration::from_millis(400),
            "the future cooperative yield was missed: {remaining:?}"
        );
        assert_eq!(
            session.runtime.scheduler_mode(),
            SchedulerMode::Production { workers: 1 }
        );
    }

    #[test]
    fn stolen_completion_port_repark_notification_race_is_exact() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 1)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        port_state
            .post(test_packet(13, 0x13, 0x31))
            .expect("post packet");
        let mut thread = synthetic_pending_thread(0xC1, 0, GuestThreadState::Waiting);
        thread.wait = Some(cp_wait(port, None));
        session.runtime.enqueue_pending_guest_thread(thread);
        // A concurrent host consumer drains the packet after the readiness
        // probe said readable but before the pump's consumption pass.
        let hook_state = Arc::clone(&port_state);
        set_readable_probe_hook(move || {
            let stolen = hook_state
                .try_dequeue_as(crate::win32::CompletionPortThreadKey::Guest(0xC1), 1)
                .expect("hook drains the packet");
            assert_eq!(stolen.len(), 1);
        });
        let observed = pump_wake().epoch();
        let outcome = session
            .runtime
            .pump_pending_guest_thread(&mut session.memory)
            .expect("pump stolen completion port wait");
        assert_eq!(outcome.did_work, false);
        assert_eq!(outcome.process_exit, None);
        assert_eq!(session.runtime.pending_guest_threads.len(), 1);
        assert_eq!(
            session.runtime.pending_guest_threads[0].state_machine,
            GuestThreadState::Waiting
        );
        assert_eq!(port_state.queued_packet_count(), 0, "the packet was stolen");
        assert_eq!(
            pump_wake().epoch(),
            observed.wrapping_add(1),
            "the stolen repark must publish exactly one wake"
        );
    }

    #[test]
    fn scheduler_suspend_resume_notification_race_is_exact() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let handle = session.runtime.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let thread_id = session
            .runtime
            .win32
            .thread_id_for_handle(handle)
            .expect("thread id");
        session
            .runtime
            .enqueue_pending_guest_thread(synthetic_pending_thread(
                thread_id,
                0,
                GuestThreadState::Waiting,
            ));
        session
            .runtime
            .win32
            .set_thread_suspend_count(thread_id, 1)
            .expect("suspend thread");
        let observed = pump_wake().epoch();
        session.runtime.sync_pending_thread_suspend_count(handle);
        assert_eq!(session.runtime.pending_guest_threads[0].suspended, 1);
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "a suspend-count change must wake an idle pump"
        );
        let observed = pump_wake().epoch();
        session
            .runtime
            .win32
            .set_thread_suspend_count(thread_id, 0)
            .expect("resume thread");
        session.runtime.sync_pending_thread_suspend_count(handle);
        assert_eq!(session.runtime.pending_guest_threads[0].suspended, 0);
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "a resume transition must wake an idle pump"
        );
        let observed = pump_wake().epoch();
        session.runtime.sync_pending_thread_suspend_count(handle);
        assert_eq!(
            pump_wake().epoch(),
            observed,
            "an unchanged suspend count must not publish a wake"
        );
    }

    #[test]
    fn scheduler_teb_last_error_switch_race_restores_exact_value() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let teb_main = 0x62_000_u64;
        let teb_pumped = 0x64_000_u64;
        session.map_guest(teb_main, &[0_u8; 0x1000]);
        session.map_guest(teb_pumped, &[0_u8; 0x1000]);
        session.runtime.teb_base = teb_main;
        session.runtime.last_error = 0x1234;
        let mut thread = synthetic_pending_thread(0xC1, 0, GuestThreadState::Runnable);
        thread.teb_base = teb_pumped;
        thread.state.rip = ENTRY_POINT;
        thread.state.set(Register::Rsp, CONTINUATION_RSP);
        thread.state.segment_bases.fs = teb_pumped;
        session.runtime.enqueue_pending_guest_thread(thread);
        assert!(pump_once(&mut session), "the TEB-bearing thread ran");
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(
            read_u32_guest(&session, teb_main + teb_last_error_offset(GuestArch::X86)),
            0x1234,
            "the outgoing thread's last error was not parked in its TEB"
        );
        assert_eq!(
            session.runtime.last_error, 0x1234,
            "the incoming thread's last error was not restored from its TEB"
        );
    }

    #[test]
    fn win32_completion_port_post_and_close_wake_real_waiter_and_pump_race() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 1)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let waiter_state = Arc::clone(&port_state);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            ready_tx.send(()).expect("waiter ready");
            waiter_state.wait_dequeue(Some(std::time::Duration::from_secs(2)), 1)
        });
        ready_rx.recv().expect("waiter startup");
        let observed = pump_wake().epoch();
        port_state
            .post(test_packet(6, 0x66, 0x6))
            .expect("post packet");
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "a post with a blocked port waiter must still wake the pump"
        );
        let packets = waiter.join().expect("waiter").expect("packet");
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].bytes_transferred, 6);

        let port2 = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 1)
            .expect("create second port");
        let port2_state = session
            .runtime
            .win32
            .io_completion_port_state(port2)
            .expect("second port state");
        let waiter2_state = Arc::clone(&port2_state);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter2 = std::thread::spawn(move || {
            ready_tx.send(()).expect("waiter ready");
            waiter2_state.wait_dequeue(None, 1)
        });
        ready_rx.recv().expect("waiter startup");
        let observed = pump_wake().epoch();
        port2_state.close();
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "a close with a blocked port waiter must still wake the pump"
        );
        let closed = waiter2.join().expect("waiter");
        assert!(
            matches!(closed, Err(crate::win32::CompletionPortWaitError::Closed)),
            "the blocked waiter must observe Closed"
        );
    }

    #[test]
    fn win32_completion_port_release_active_and_set_concurrency_notification_race() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 1)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let thread_a = crate::win32::CompletionPortThreadKey::Guest(0xA1);
        let thread_b = crate::win32::CompletionPortThreadKey::Guest(0xB2);
        let thread_c = crate::win32::CompletionPortThreadKey::Guest(0xC3);

        port_state.post(test_packet(1, 0x11, 0x1)).expect("post a");
        let packet_a = port_state.try_dequeue_as(thread_a, 1).expect("dequeue a");
        assert_eq!(packet_a.len(), 1);
        port_state.post(test_packet(2, 0x22, 0x2)).expect("post b");
        assert_eq!(
            port_state.readable_for(thread_b),
            false,
            "the only concurrency slot is held by thread a"
        );

        let observed = pump_wake().epoch();
        port_state.release_active_as(thread_a);
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "releasing the active slot must wake the pump"
        );
        assert_eq!(port_state.readable_for(thread_b), true);
        let packet_b = port_state.try_dequeue_as(thread_b, 1).expect("dequeue b");
        assert_eq!(packet_b.len(), 1);
        assert_eq!(packet_b[0].bytes_transferred, 2);

        port_state.post(test_packet(3, 0x33, 0x3)).expect("post c");
        let observed = pump_wake().epoch();
        port_state.set_concurrency(2);
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "raising concurrency must wake the pump"
        );
        assert_eq!(port_state.readable_for(thread_c), true);
        let packet_c = port_state.try_dequeue_as(thread_c, 1).expect("dequeue c");
        assert_eq!(packet_c.len(), 1);
        assert_eq!(packet_c[0].bytes_transferred, 3);

        // A real blocked port waiter exercises the waiters>0 branch in
        // set_concurrency: the queued packet becomes eligible when the limit
        // is raised, so both the port condvar and the pump must be woken.
        let port2 = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 1)
            .expect("create waiter port");
        let port2_state = session
            .runtime
            .win32
            .io_completion_port_state(port2)
            .expect("waiter port state");
        let thread_d = crate::win32::CompletionPortThreadKey::Guest(0xD4);
        port2_state.post(test_packet(4, 0x44, 0x4)).expect("post d");
        let packet_d = port2_state.try_dequeue_as(thread_d, 1).expect("dequeue d");
        assert_eq!(packet_d.len(), 1);
        let waiter_state = Arc::clone(&port2_state);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            ready_tx.send(()).expect("waiter ready");
            waiter_state.wait_dequeue(Some(std::time::Duration::from_secs(2)), 1)
        });
        ready_rx.recv().expect("waiter startup");
        let waiter_deadline = Instant::now() + std::time::Duration::from_secs(2);
        while port2_state.waiter_count() == 0 {
            assert!(
                Instant::now() < waiter_deadline,
                "the port waiter never registered"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        port2_state.post(test_packet(5, 0x55, 0x5)).expect("post e");
        let observed = pump_wake().epoch();
        port2_state.set_concurrency(2);
        assert_ne!(
            pump_wake().epoch(),
            observed,
            "raising concurrency with a blocked waiter must wake the pump"
        );
        let packets = waiter.join().expect("waiter").expect("waiter packet");
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].bytes_transferred, 5);
    }

    #[test]
    fn production_terminate_race_prunes_parked_wait_and_never_resumes() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        park_main_thread(&mut session, object_wait(event));
        wait_until_worker_active(&session, 1);

        let tid = session.runtime.pending_guest_threads[0].thread_id;
        let job_id = session
            .runtime
            .production_waits
            .get(&tid)
            .expect("parked job")
            .job_id;
        // A stale completion from an older/replaced job must not touch this
        // wait.
        assert!(
            !session
                .runtime
                .apply_production_completion(
                    WaitCompletion {
                        job_id: job_id.wrapping_add(1),
                        thread_id: tid,
                        reason: WaitWakeReason::ObjectSignaled,
                        packets: Vec::new(),
                    },
                    &mut session.memory,
                )
                .expect("stale completion")
        );
        assert_eq!(session.runtime.production_waits.len(), 1);
        // TerminateThread's queued-thread path removes the record; the
        // scheduler must drop the orphaned production wait instead of
        // letting the run loop wait forever.
        session
            .runtime
            .pending_guest_threads
            .retain(|thread| thread.thread_id != tid);
        session.runtime.prune_orphan_production_waits();
        assert_eq!(session.runtime.production_waits.len(), 0);

        session.runtime.win32.set_event(event).expect("set event");
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        assert!(scheduler.wait_for_completion(Some(std::time::Duration::from_secs(2))));
        assert!(
            !session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap"),
            "a completion for a terminated thread is ignored"
        );
        assert!(!pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 0);
        assert!(session.runtime.pending_guest_threads.is_empty());
        assert_eq!(session.runtime.production_waits.len(), 0);
    }

    #[test]
    fn deterministic_mode_stays_identical_without_stale_production_wakeups() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (event, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert_eq!(
            session.runtime.scheduler_mode(),
            SchedulerMode::Cooperative,
            "deterministic cooperative scheduling is the default"
        );
        assert!(session.runtime.production_scheduler.is_none());
        let before = SCHEDULER_COUNTERS.snapshot();
        // No production waiter is subscribed to this id (and the object is
        // "closed"): the wake bus must stay a no-op.
        let _ = wake_bus();
        notify_object_waiters(ObjectId(0xDEAD_BEEF), true);
        notify_object_waiters(ObjectId(0xDEAD_BEEF), false);

        park_main_thread(&mut session, object_wait(event));
        assert!(!pump_once(&mut session));
        session.runtime.win32.set_event(event).expect("set event");
        assert!(
            pump_once(&mut session),
            "cooperative pump resumes the waiter"
        );
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert!(session.runtime.production_waits.is_empty());
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(after.wakeups, before.wakeups);
        assert_eq!(after.migrations, before.migrations);
        assert_eq!(after.worker_overlaps, before.worker_overlaps);
        assert_eq!(after.poll_iterations, before.poll_iterations);
    }

    #[test]
    fn parked_completion_port_wait_resumes_when_packet_posted() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let before = SCHEDULER_COUNTERS.snapshot();

        park_main_thread(&mut session, cp_wait(port, None));
        assert_eq!(session.runtime.pending_guest_threads.len(), 1);
        assert!(!parker_satisfiable(&session), "no packet posted yet");
        assert!(!pump_once(&mut session), "parked wait must not run early");
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 0);

        // A REAL other host thread posts the completion after the waiter is
        // parked; the scheduler's wake points poll the non-consuming probe.
        let poster_state = std::sync::Arc::clone(&port_state);
        let poster = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            poster_state
                .post(test_packet(12, 0xCAFE, 0x0BEEF))
                .expect("post packet");
        });

        let wake_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !parker_satisfiable(&session) {
            assert!(
                std::time::Instant::now() < wake_deadline,
                "posted packet never woke the parked completion-port wait"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(pump_once(&mut session), "waiter must resume after the post");
        poster.join().expect("poster");

        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1, "continuation ran");
        assert_eq!(read_u32_guest(&session, BYTES_PTR), 12);
        assert_eq!(read_u32_guest(&session, KEY_PTR), 0xCAFE);
        assert_eq!(read_u32_guest(&session, OVERLAPPED_PTR), 0x0BEEF);
        assert_eq!(port_state.queued_packet_count(), 0, "packet consumed");
        assert!(session.runtime.pending_guest_threads.is_empty());

        let after = SCHEDULER_COUNTERS.snapshot();
        assert!(
            after.parked_waits > before.parked_waits,
            "parked-wait count"
        );
        assert!(
            after.guest_thread_switches > before.guest_thread_switches,
            "guest-thread switch count"
        );
        assert!(
            after.completion_port_wakeups > before.completion_port_wakeups,
            "completion-port wakeup count"
        );
        assert!(
            after.host_worker_busy_nanos > before.host_worker_busy_nanos,
            "host-worker utilisation"
        );
        assert!(SCHEDULER_COUNTERS.host_worker_observed(std::thread::current().id()));
    }

    #[test]
    fn parked_completion_port_wait_times_out_at_its_deadline() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let clock = session.runtime.win32.get_tick_count64();

        park_main_thread(&mut session, cp_wait(port, Some(clock + 50)));
        assert!(!parker_satisfiable(&session), "deadline not reached");
        assert!(
            !pump_once(&mut session),
            "nothing may run before the deadline"
        );

        session.advance_guest_clock(1_000);
        assert!(parker_satisfiable(&session), "deadline expired");
        assert!(pump_once(&mut session), "timed-out waiter must resume");

        assert_eq!(session.runtime.last_error, crate::win32::WAIT_TIMEOUT);
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1, "continuation ran");
        assert_eq!(
            read_u32_guest(&session, BYTES_PTR),
            0,
            "no bytes transferred"
        );
        assert_eq!(port_state.queued_packet_count(), 0);

        // The timed-out wait consumed nothing: a later post stays queued.
        port_state
            .post(test_packet(3, 0x1111, 0x2222))
            .expect("post after timeout");
        assert_eq!(port_state.queued_packet_count(), 1);
    }

    #[test]
    fn parked_completion_port_wait_wakes_with_abandoned_error_when_port_closes() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let before = SCHEDULER_COUNTERS.snapshot();

        park_main_thread(&mut session, cp_wait(port, None));
        assert!(!parker_satisfiable(&session));
        session
            .runtime
            .win32
            .close_handle(port)
            .expect("close port");

        assert!(
            parker_satisfiable(&session),
            "closed port must wake the waiter"
        );
        assert!(pump_once(&mut session));
        assert_eq!(
            session.runtime.last_error,
            crate::win32::ERROR_ABANDONED_WAIT_0
        );
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(
            after.completion_port_wakeups, before.completion_port_wakeups,
            "a closed port is not a packet wakeup"
        );
    }

    #[test]
    fn stolen_completion_port_packet_repark_never_resumes_the_waiter() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 4)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");

        park_main_thread(&mut session, cp_wait(port, None));
        port_state
            .post(test_packet(9, 0xAA, 0xBB))
            .expect("post packet");
        // A concurrent host-side consumer drains the packet between the
        // pump's readiness pass and its consumption pass.
        let drained = port_state.try_dequeue(1).expect("concurrent dequeue");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].bytes_transferred, 9);

        let mut thread = session
            .runtime
            .pending_guest_threads
            .pop_front()
            .expect("parked thread");
        let preconsume = session
            .runtime
            .preconsume_completion_port_wait(&thread, &mut session.memory)
            .expect("preconsume");
        assert!(matches!(preconsume, CompletionPortPreconsume::Stolen));
        // Re-park exactly like the pump's stolen-packet path does.
        thread.state_machine = GuestThreadState::Waiting;
        session.runtime.pending_guest_threads.push_back(thread);
        assert!(!pump_once(&mut session), "stolen waiter stays parked");
        assert_eq!(read_u32_guest(&session, FLAG_PTR), 0, "no guest code ran");
        assert!(!parker_satisfiable(&session));

        // A later real post hands the next packet to the still-parked waiter.
        port_state
            .post(test_packet(11, 0xCC, 0xDD))
            .expect("post again");
        assert!(parker_satisfiable(&session));
        assert!(pump_once(&mut session));
        assert_eq!(read_u32_guest(&session, BYTES_PTR), 11);
        assert_eq!(read_u32_guest(&session, KEY_PTR), 0xCC);
        assert_eq!(read_u32_guest(&session, OVERLAPPED_PTR), 0xDD);
    }
    const SLICE_CODE: u64 = 0x31_000;
    const SLICE_CODE_2: u64 = 0x32_000;
    const SLICE_COUNTER_A: u64 = 0x40_000;
    const SLICE_COUNTER_B: u64 = 0x40_008;
    const SLICE_STACK_A: u64 = 0x10_E00;
    const SLICE_STACK_B: u64 = 0x10_F00;
    const SLICE_THUNK_SLOT: u64 = 0x30_F00;
    const SLICE_CALL_CODE: u64 = 0x39_000;
    const SLICE_CALL_COUNTER: u64 = 0x42_000;

    fn install_jit(session: &mut NtThunkSession) {
        if session.runtime.jit_runtime.is_none() {
            session.runtime.jit_runtime = Some(crate::jit::JitRuntime::new(GuestArch::X86));
        }
    }

    fn loop_with_counter(counter: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        // mov eax, [counter]
        bytes.push(0xA1);
        bytes.extend_from_slice(&(counter as u32).to_le_bytes());
        // add eax, 1
        bytes.extend_from_slice(&[0x83, 0xC0, 0x01]);
        // mov [counter], eax
        bytes.push(0xA3);
        bytes.extend_from_slice(&(counter as u32).to_le_bytes());
        // sub ecx, 1; cmp ecx, 0 (the JIT emits real flag updates for
        // Compare even though SubImm itself does not maintain EFLAGS)
        bytes.extend_from_slice(&[0x83, 0xE9, 0x01, 0x83, 0xF9, 0x00]);
        // jnz loop_start (next rip 21, target 0 -> -21)
        bytes.extend_from_slice(&[0x75, 0xEB]);
        // ret (the loop fallthrough after ECX reaches zero)
        bytes.push(0xC3);
        bytes
    }

    fn push_guest_thread(
        session: &mut NtThunkSession,
        handle: u32,
        thread_id: u32,
        rip: u64,
        rsp: u64,
        ecx: u32,
    ) {
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = rip;
        state.set(Register::Rsp, rsp);
        state.set(Register::Rcx, u64::from(ecx));
        state.segment_bases.fs = session.runtime.teb_base;
        session
            .runtime
            .pending_guest_threads
            .push_back(PendingGuestThread {
                handle,
                thread_id,
                start_address: rip,
                parameter: 0,
                initial_rsp: rsp,
                started: true,
                suspended: 0,
                wake_tick: 0,
                teb_base: session.runtime.teb_base,
                tls_vector_ptr: session.runtime.tls_vector_ptr,
                tls_slots: BTreeMap::new(),
                fls_slots: BTreeMap::new(),
                state,
                state_machine: GuestThreadState::Runnable,
                exit_code_override: None,
                wait: None,
                wait_resume: None,
            });
    }

    fn session_pending_rips(session: &NtThunkSession) -> Vec<u64> {
        session
            .runtime
            .pending_guest_threads
            .iter()
            .map(|thread| thread.state.rip)
            .collect()
    }

    fn trace_calls(session: &NtThunkSession, category: &str, call_id: &str) -> usize {
        session
            .runtime
            .trace_events
            .iter()
            .filter(|event| event.category == category && event.call_id == call_id)
            .count()
    }

    #[test]
    fn production_slice_race_two_guest_loops_overlap_with_exact_counters() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_CODE, &loop_with_counter(SLICE_COUNTER_A));
        session.map_guest(SLICE_CODE_2, &loop_with_counter(SLICE_COUNTER_B));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        session.map_guest(SLICE_COUNTER_B, &[0_u8; 4]);
        push_guest_thread(&mut session, 0x200, 0xA1, SLICE_CODE, SLICE_STACK_A, 2_048);
        push_guest_thread(
            &mut session,
            0x201,
            0xA2,
            SLICE_CODE_2,
            SLICE_STACK_B,
            2_048,
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let requests = session
            .runtime
            .pending_guest_threads
            .iter()
            .map(|thread| GuestSliceRequest {
                thread_id: thread.thread_id,
                priority: 0,
                state: thread.state.clone(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.state.rip)
                .collect::<Vec<_>>(),
            vec![SLICE_CODE, SLICE_CODE_2]
        );
        let before = SCHEDULER_COUNTERS.snapshot();
        let reports = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, requests, 2_048)
            .expect("dispatch two production slices");
        let after = SCHEDULER_COUNTERS.snapshot();
        assert!(
            session
                .runtime
                .jit_runtime
                .as_ref()
                .expect("jit")
                .slice_block(SLICE_CODE)
                .expect("slice block A")
                .worker_safe,
            "loop block A must be worker-safe"
        );
        assert!(
            session
                .runtime
                .jit_runtime
                .as_ref()
                .expect("jit")
                .slice_block(SLICE_CODE_2)
                .expect("slice block B")
                .worker_safe,
            "loop block B must be worker-safe"
        );
        assert_eq!(reports.len(), 2, "both guest threads must produce a report");
        for report in &reports {
            assert!(
                matches!(report.exit, GuestSliceExit::Budget),
                "worker must run the loop block, got {:?} for thread {:#x}",
                report.exit,
                report.thread_id
            );
        }
        assert_eq!(
            reports
                .iter()
                .map(|report| report.blocks_executed)
                .sum::<u64>(),
            4_096,
            "each thread's slice must execute exactly its budget"
        );
        assert_eq!(read_u32_guest(&session, SLICE_COUNTER_A), 2_048);
        assert_eq!(read_u32_guest(&session, SLICE_COUNTER_B), 2_048);
        assert!(
            after.worker_overlaps > before.worker_overlaps,
            "two guest slices must occupy two host workers at the same time"
        );
        session.runtime.pending_guest_threads.clear();
    }

    /// x86 loop that atomically adds one to `counter` `edx` times:
    ///   mov ecx, 1 ; lock xadd [counter], ecx ; sub edx, 1 ; cmp edx, 0 ;
    ///   jnz loop ; ret
    fn lock_xadd_loop(counter: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0xF0, 0x0F, 0xC1, 0x0D]);
        bytes.extend_from_slice(&(counter as u32).to_le_bytes());
        bytes.extend_from_slice(&[0x83, 0xEA, 0x01]);
        bytes.extend_from_slice(&[0x83, 0xFA, 0x00]);
        let jump_from = bytes.len() + 2;
        bytes.extend_from_slice(&[0x75, (-(jump_from as i8)) as u8]);
        bytes.push(0xC3);
        bytes
    }

    fn loop_context(thread_id: u32, rip: u64, rsp: u64, iterations: u32) -> GuestThreadContext {
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = rip;
        state.set(Register::Rsp, rsp);
        state.set(Register::Rdx, u64::from(iterations));
        GuestThreadContext::new(thread_id, state)
    }

    fn rerun_contexts(
        session: &mut NtThunkSession,
        mut contexts: Vec<GuestThreadContext>,
        budget: u64,
        rounds: usize,
    ) -> Vec<GuestThreadSnapshot> {
        let mut snapshots: BTreeMap<u32, GuestThreadSnapshot> = BTreeMap::new();
        for _ in 0..rounds {
            if contexts.is_empty() {
                break;
            }
            let runs = session
                .runtime
                .dispatch_parallel_thread_contexts(&mut session.memory, contexts, budget)
                .expect("dispatch concurrent thread contexts");
            let mut unfinished = Vec::new();
            for run in runs {
                if run.context.state.rip == 0 {
                    snapshots.insert(run.context.thread_id, run.context);
                } else {
                    snapshots.insert(run.context.thread_id, run.context.clone());
                    unfinished.push(GuestThreadContext::from_snapshot(&run.context));
                }
            }
            contexts = unfinished;
        }
        snapshots.into_values().collect()
    }

    #[test]
    fn production_concurrent_lock_xadd_shared_counter_is_exact() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        const ITERATIONS: u32 = 100_000;
        session.map_guest(SLICE_CODE, &lock_xadd_loop(SLICE_COUNTER_A));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let contexts = vec![
            loop_context(0xE01, SLICE_CODE, SLICE_STACK_A, ITERATIONS),
            loop_context(0xE02, SLICE_CODE, SLICE_STACK_B, ITERATIONS),
        ];
        let before = SCHEDULER_COUNTERS.snapshot();
        let snapshots = rerun_contexts(&mut session, contexts, u64::from(ITERATIONS) + 8, 3);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(snapshots.len(), 2, "both guest threads must report");
        assert_eq!(
            read_u32_guest(&session, SLICE_COUNTER_A),
            ITERATIONS * 2,
            "two threads atomically incrementing one shared counter must produce the exact total"
        );
        assert_eq!(
            snapshots
                .iter()
                .filter(|snapshot| snapshot.state.rip == 0)
                .count(),
            2,
            "both loops must reach the guest return with RIP 0"
        );
        assert_ne!(
            after.worker_overlaps, before.worker_overlaps,
            "the two slices must genuinely overlap on two host workers"
        );
    }

    #[test]
    fn lock_xadd_native_helper_boundary_mapped_add_and_unmapped_fault_are_exact() {
        let _guard = test_guard();
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x10_000, &[0_u8; 0x1000]);
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rcx, 5);
        // SAFETY: live local CpuState/MemoryImage for the whole call; the
        // cooperative branch aliases the MemoryImage, never a null pointer.
        unsafe {
            crate::jit::jit_helper_lock_xadd(
                &mut state as *mut CpuState,
                &mut memory as *mut MemoryImage,
                0x10_100,
                3,
                4,
                Register::Rcx.index() as u64,
            );
        }
        assert_eq!(
            state.get(Register::Rcx),
            0,
            "xadd returns the original value"
        );
        assert_eq!(
            memory.read_u32(0x10_100).expect("counter mapped"),
            3,
            "xadd adds the source into the memory operand"
        );
        assert_eq!(state.jit_pending_fault, None);

        let unmapped = 0xDEAD_0000_u64;
        state.set(Register::Rcx, 7);
        // SAFETY: same live locals; the address is deliberately unmapped to
        // exercise the helper's precise fault channel.
        unsafe {
            crate::jit::jit_helper_lock_xadd(
                &mut state as *mut CpuState,
                &mut memory as *mut MemoryImage,
                unmapped,
                1,
                4,
                Register::Rcx.index() as u64,
            );
        }
        assert_eq!(
            state.jit_pending_fault,
            Some(unmapped),
            "an unmapped xadd must report the precise faulting address"
        );
        assert_eq!(state.jit_pending_fault_write, true);
        assert_eq!(
            state.get(Register::Rcx),
            7,
            "a faulted xadd must not modify the source register"
        );
    }

    #[test]
    fn concurrent_unaligned_atomic_rmw_across_words_is_exact() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(0x40_000 & !0xfff, &vec![0_u8; 0x1000]);
        let program = session
            .runtime
            .jit_runtime
            .as_ref()
            .expect("jit")
            .build_slice_program(&session.memory);
        let view = std::sync::Arc::clone(&program.memory);
        const WORKERS: u64 = 4;
        const PER_WORKER: u64 = 10_000;
        let mut workers = Vec::new();
        for _ in 0..WORKERS {
            let view = std::sync::Arc::clone(&view);
            workers.push(std::thread::spawn(move || {
                for _ in 0..PER_WORKER {
                    view.atomic_fetch_add(SLICE_COUNTER_A + 7, 1, 4)
                        .expect("mapped atomic range");
                }
            }));
        }
        for worker in workers {
            worker.join().expect("atomic RMW worker joined");
        }
        assert_eq!(
            read_u32_guest(&session, SLICE_COUNTER_A + 7),
            (WORKERS * PER_WORKER) as u32,
            "an unaligned word-crossing atomic RMW must never lose an update"
        );
        assert_eq!(
            read_u32_guest(&session, SLICE_COUNTER_A),
            0,
            "the RMW must preserve the bytes outside the 4-byte operand"
        );
    }

    #[test]
    fn production_two_parked_guest_threads_wake_simultaneously_without_deadlock() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let (first, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        let (second, _) = session
            .runtime
            .win32
            .create_event(false, false, false, None);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let mut first_thread = synthetic_pending_thread(0x901, 0, GuestThreadState::Waiting);
        first_thread.wait = Some(object_wait(first));
        let mut second_thread = synthetic_pending_thread(0x902, 0, GuestThreadState::Waiting);
        second_thread.wait = Some(object_wait(second));
        assert!(
            session
                .runtime
                .start_production_wait(0x901, &object_wait(first))
        );
        assert!(
            session
                .runtime
                .start_production_wait(0x902, &object_wait(second))
        );
        session
            .runtime
            .pending_guest_threads
            .push_back(first_thread);
        session
            .runtime
            .pending_guest_threads
            .push_back(second_thread);
        assert_eq!(
            session.runtime.production_waits.len(),
            2,
            "both guest waits must be owned by native workers simultaneously"
        );
        wait_until_worker_active(&session, 2);
        session
            .runtime
            .win32
            .set_event(first)
            .expect("signal first");
        session
            .runtime
            .win32
            .set_event(second)
            .expect("signal second");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !session.runtime.production_waits.is_empty() {
            let scheduler = session
                .runtime
                .production_scheduler
                .as_ref()
                .expect("production scheduler");
            assert!(
                scheduler.wait_for_completion(Some(std::time::Duration::from_millis(500))),
                "a native waiter must report its wake"
            );
            let _ = session
                .runtime
                .reap_production_completions(&mut session.memory)
                .expect("reap both waiter completions");
            assert!(
                std::time::Instant::now() < deadline,
                "two simultaneous guest waits must both wake (no deadlock)"
            );
        }
        assert_eq!(
            session.runtime.production_waits.len(),
            0,
            "both native wait jobs must complete"
        );
        assert_eq!(
            session
                .runtime
                .pending_guest_threads
                .iter()
                .filter(|thread| thread.wait_resume.is_some())
                .count(),
            2,
            "both parked guest threads must be resumed exactly once"
        );
    }

    #[test]
    fn production_process_gate_concurrent_operations_are_serialized() {
        let shared = std::sync::Arc::new(ProcessShared::new());
        let inside = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let shared = std::sync::Arc::clone(&shared);
            let inside = std::sync::Arc::clone(&inside);
            let peak = std::sync::Arc::clone(&peak);
            let completed = std::sync::Arc::clone(&completed);
            workers.push(std::thread::spawn(move || {
                use std::sync::atomic::Ordering;
                for _ in 0..500 {
                    shared.with_process(|| {
                        let current = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        std::thread::yield_now();
                        completed.fetch_add(1, Ordering::SeqCst);
                        inside.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            }));
        }
        for worker in workers {
            worker.join().expect("process-gate worker joined");
        }
        assert_eq!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            2_000,
            "every process operation must complete exactly once"
        );
        assert_eq!(
            peak.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "two guest threads must never hold the process gate concurrently"
        );
        assert_eq!(
            shared.process_operations(),
            2_000,
            "the process gate must account for every operation"
        );
    }

    #[test]
    fn production_concurrent_thread_start_and_exit_race_has_exact_totals() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        const ITERATIONS: u32 = 256;
        session.map_guest(SLICE_CODE, &lock_xadd_loop(SLICE_COUNTER_A));
        session.map_guest(SLICE_CODE_2, &lock_xadd_loop(SLICE_COUNTER_B));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        session.map_guest(SLICE_COUNTER_B, &[0_u8; 4]);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        // Two rounds of freshly-started guest threads; each round starts both
        // threads and lets them exit concurrently.
        for _ in 0..2 {
            let contexts = vec![
                loop_context(0xE11, SLICE_CODE, SLICE_STACK_A, ITERATIONS),
                loop_context(0xE12, SLICE_CODE_2, SLICE_STACK_B, ITERATIONS),
            ];
            let snapshots = rerun_contexts(&mut session, contexts, u64::from(ITERATIONS) + 8, 1);
            assert_eq!(
                snapshots
                    .iter()
                    .filter(|snapshot| snapshot.state.rip == 0)
                    .count(),
                2,
                "both starting threads must exit cleanly in the same round"
            );
        }
        assert_eq!(read_u32_guest(&session, SLICE_COUNTER_A), ITERATIONS * 2);
        assert_eq!(read_u32_guest(&session, SLICE_COUNTER_B), ITERATIONS * 2);
    }

    #[test]
    fn production_concurrent_contexts_isolate_tls_and_last_error() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        const ITERATIONS: u32 = 512;
        const TEB_A: u64 = 0x20_000;
        const TEB_B: u64 = 0x24_000;
        session.map_guest(SLICE_CODE, &lock_xadd_loop(SLICE_COUNTER_A));
        session.map_guest(SLICE_CODE_2, &lock_xadd_loop(SLICE_COUNTER_B));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        session.map_guest(SLICE_COUNTER_B, &[0_u8; 4]);
        session.map_guest(TEB_A, &[0_u8; 0x100]);
        session.map_guest(TEB_B, &[0_u8; 0x100]);
        session
            .memory
            .write_u32(TEB_A + teb_last_error_offset(GuestArch::X86), 0x1111);
        session
            .memory
            .write_u32(TEB_B + teb_last_error_offset(GuestArch::X86), 0x2222);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let mut first = loop_context(0xE21, SLICE_CODE, SLICE_STACK_A, ITERATIONS);
        first.teb_base = TEB_A;
        first.tls_vector_ptr = 0x20_080;
        first.tls_slots.insert(3, 0xAA00);
        first.last_error = 0x1111;
        let mut second = loop_context(0xE22, SLICE_CODE_2, SLICE_STACK_B, ITERATIONS);
        second.teb_base = TEB_B;
        second.tls_vector_ptr = 0x24_080;
        second.tls_slots.insert(3, 0xBB00);
        second.last_error = 0x2222;
        let snapshots = rerun_contexts(&mut session, vec![first, second], 256, 2);
        let by_thread: BTreeMap<u32, &GuestThreadSnapshot> = snapshots
            .iter()
            .map(|snapshot| (snapshot.thread_id, snapshot))
            .collect();
        assert_eq!(
            by_thread[&0xE21].last_error, 0x1111,
            "thread A's last error must stay private to thread A"
        );
        assert_eq!(
            by_thread[&0xE22].last_error, 0x2222,
            "thread B's last error must stay private to thread B"
        );
        assert_eq!(by_thread[&0xE21].tls_slots.get(&3), Some(&0xAA00));
        assert_eq!(by_thread[&0xE22].tls_slots.get(&3), Some(&0xBB00));
        assert_eq!(by_thread[&0xE21].teb_base, TEB_A);
        assert_eq!(by_thread[&0xE22].teb_base, TEB_B);
        assert_ne!(
            session
                .memory
                .read_u32(TEB_A + teb_last_error_offset(GuestArch::X86))
                .expect("TEB A readable"),
            session
                .memory
                .read_u32(TEB_B + teb_last_error_offset(GuestArch::X86))
                .expect("TEB B readable"),
            "the two threads' TEB last-error slots must never alias"
        );
    }

    #[test]
    fn production_concurrent_smc_code_writes_invalidate_both_blocks() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        // Each block stores to its own first instruction and jumps back to
        // itself; the worker must report the code write and the owner must
        // invalidate the stale compiled block for both threads in one round.
        for code in [SLICE_CODE, SLICE_CODE_2] {
            session.map_guest(code & !0xfff, &vec![0_u8; 0x1000]);
            let mut bytes = vec![0xC7, 0x05];
            bytes.extend_from_slice(&(code as u32).to_le_bytes());
            bytes.extend_from_slice(&0x9090_9090_u32.to_le_bytes());
            bytes.extend_from_slice(&[0xEB, 0xFE]);
            session.map_guest(code, &bytes);
        }
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let contexts = vec![
            loop_context(0xE31, SLICE_CODE, SLICE_STACK_A, 8),
            loop_context(0xE32, SLICE_CODE_2, SLICE_STACK_B, 8),
        ];
        let runs = session
            .runtime
            .dispatch_parallel_thread_contexts(&mut session.memory, contexts, 8)
            .expect("dispatch SMC writers");
        assert_eq!(runs.len(), 2);
        assert!(
            runs.iter()
                .all(|run| matches!(run.exit, GuestSliceExit::CodeWrite)),
            "both concurrent self-modifying writers must stop at the code write"
        );
        // The code-write log belongs to the process-shared canonical store, so
        // one completion may drain both threads' writes.  A sibling worker can
        // also observe the other thread's epoch bump before it executes its own
        // store, so the exact set is race-dependent; every recorded write must
        // still be one of the two code addresses, and at least one must be
        // recorded for the owner to invalidate.
        let writes: Vec<(u64, usize)> = runs
            .iter()
            .flat_map(|run| run.code_writes.iter().copied())
            .collect();
        assert!(
            !writes.is_empty(),
            "the owner must receive at least the concurrent code-write address"
        );
        assert_eq!(
            writes
                .iter()
                .filter(|(address, length)| {
                    (*address == SLICE_CODE || *address == SLICE_CODE_2) && *length == 4
                })
                .count(),
            writes.len(),
            "every recorded concurrent code write must be an exact 4-byte store on a code page"
        );
        let jit = session.runtime.jit_runtime.as_ref().expect("jit");
        assert!(jit.slice_block(SLICE_CODE).is_none());
        assert!(jit.slice_block(SLICE_CODE_2).is_none());
    }

    #[test]
    fn production_eight_concurrent_guest_threads_never_deadlock_and_count_exactly() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        const THREADS: u32 = 8;
        const ITERATIONS: u32 = 25_000;
        session.map_guest(SLICE_CODE, &lock_xadd_loop(SLICE_COUNTER_A));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 8 })
        );
        let contexts: Vec<GuestThreadContext> = (0..THREADS)
            .map(|index| {
                let rsp = 0x10_100 + u64::from(index) * 0x100;
                loop_context(0xE40 + index, SLICE_CODE, rsp, ITERATIONS)
            })
            .collect();
        let before = SCHEDULER_COUNTERS.snapshot();
        let snapshots = rerun_contexts(&mut session, contexts, u64::from(ITERATIONS) + 8, 3);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(snapshots.len(), THREADS as usize);
        assert_eq!(
            read_u32_guest(&session, SLICE_COUNTER_A),
            ITERATIONS * THREADS,
            "eight concurrent guest threads must produce the exact shared total"
        );
        assert_eq!(
            snapshots
                .iter()
                .filter(|snapshot| snapshot.state.rip == 0)
                .count(),
            THREADS as usize,
            "every guest thread must finish (no deadlock)"
        );
        assert!(
            after.max_concurrent_worker_jobs >= u64::from(THREADS),
            "all eight guest threads must run on host workers simultaneously"
        );
        assert!(after.worker_overlaps > before.worker_overlaps);
    }

    #[test]
    fn production_worker_barrier_never_double_dispatches_host_thunk() {
        // The owner's x86 thunk path runs the callback machinery, whose host
        // frames are deeper than the default 2 MiB test-thread stack.
        with_big_stack(|| {
            let _guard = test_guard();
            let (_temp_dir, mut session) = test_session();
            install_jit(&mut session);
            let thunk = session.alloc_thunk(HostThunk::GetTickCount64);
            assert!(
                thunk <= u64::from(u32::MAX),
                "x86 thunk address fits 32 bits"
            );
            // call dword ptr [SLICE_THUNK_SLOT] ; ret.  The x86 indirect-call
            // form is dispatched by the owner loop with explicit next-RIP
            // advancement, so the thunk must run exactly once.
            let mut code = vec![0xFF, 0x15];
            code.extend_from_slice(&(SLICE_THUNK_SLOT as u32).to_le_bytes());
            code.push(0xC3);
            session.map_guest(SLICE_CODE_2, &code);
            session.map_guest(SLICE_THUNK_SLOT, &(thunk as u32).to_le_bytes());
            push_guest_thread(&mut session, 0x300, 0xB1, SLICE_CODE_2, SLICE_STACK_B, 1);
            assert!(
                session
                    .runtime
                    .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
            );
            let before = trace_calls(&session, "time", "GetTickCount64");
            let request = GuestSliceRequest {
                thread_id: 0xB1,
                priority: 0,
                state: session.runtime.pending_guest_threads[0].state.clone(),
            };
            let reports = session
                .runtime
                .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 16)
                .expect("dispatch slice");
            assert_eq!(reports.len(), 1);
            assert_eq!(
                reports[0].exit,
                GuestSliceExit::HostBarrier { rip: thunk },
                "the worker resolves the indirect call target and yields at the thunk"
            );
            assert_eq!(
                reports[0].blocks_executed, 1,
                "the call block runs natively; only the thunk itself is owner work"
            );
            assert_eq!(
                reports[0].state.rip, thunk,
                "RIP points at the unresolved host thunk, with the return address already pushed"
            );
            assert_eq!(
                trace_calls(&session, "time", "GetTickCount64"),
                before,
                "a production worker must never run the host thunk"
            );
            session.runtime.pending_guest_threads[0].state = reports[0].state.clone();
            let mut rounds = 0;
            while pump_once(&mut session) {
                rounds += 1;
                assert!(rounds < 64, "the cooperative owner must finish the thread");
            }
            assert_eq!(
                trace_calls(&session, "time", "GetTickCount64"),
                before + 1,
                "the runtime owner executes the thunk exactly once"
            );
            assert_eq!(session.runtime.pending_guest_threads.len(), 0);
        });
    }

    #[test]
    fn cooperative_and_production_guest_loops_no_races_byte_identical() {
        let _guard = test_guard();
        let iterations = 300_u32;
        let (coop_dir, mut cooperative) = test_session();
        cooperative.map_guest(SLICE_CODE, &loop_with_counter(SLICE_COUNTER_A));
        cooperative.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        push_guest_thread(
            &mut cooperative,
            0x400,
            0xC1,
            SLICE_CODE,
            SLICE_STACK_A,
            iterations,
        );
        let mut rounds = 0;
        while pump_once(&mut cooperative) && rounds < 10_000 {
            rounds += 1;
        }
        assert_eq!(
            read_u32_guest(&cooperative, SLICE_COUNTER_A),
            iterations,
            "cooperative loop did not finish in {rounds} rounds"
        );
        let (prod_dir, mut production) = test_session();
        install_jit(&mut production);
        production.map_guest(SLICE_CODE, &loop_with_counter(SLICE_COUNTER_A));
        production.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        push_guest_thread(
            &mut production,
            0x401,
            0xC2,
            SLICE_CODE,
            SLICE_STACK_A,
            iterations,
        );
        assert!(
            production
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let request = GuestSliceRequest {
            thread_id: 0xC2,
            priority: 0,
            state: production.runtime.pending_guest_threads[0].state.clone(),
        };
        let reports = production
            .runtime
            .dispatch_parallel_guest_slices(&mut production.memory, vec![request], 512)
            .expect("production slice");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].state.rip, 0,
            "the worker chain must run all {iterations} iterations and the final ret (exit {:?})",
            reports[0].exit
        );
        assert_eq!(
            reports[0].exit,
            GuestSliceExit::HostBarrier { rip: 0 },
            "the completed loop returns to the zero stack sentinel"
        );
        production.runtime.pending_guest_threads[0].state = reports[0].state.clone();
        rounds = 0;
        while pump_once(&mut production) && rounds < 100 {
            rounds += 1;
        }
        assert_eq!(
            session_pending_rips(&production),
            Vec::<u64>::new(),
            "production thread did not exit after {rounds} rounds"
        );
        assert_eq!(
            read_u32_guest(&cooperative, SLICE_COUNTER_A),
            iterations,
            "cooperative result"
        );
        assert_eq!(
            read_u32_guest(&production, SLICE_COUNTER_A),
            iterations,
            "production result"
        );
        assert_eq!(
            read_u32_guest(&cooperative, SLICE_COUNTER_A),
            read_u32_guest(&production, SLICE_COUNTER_A)
        );
        assert_eq!(
            cooperative.read_guest(SLICE_COUNTER_A, 16),
            production.read_guest(SLICE_COUNTER_A, 16),
            "the canonical guest bytes must be identical in both modes"
        );
        drop(coop_dir);
        drop(prod_dir);
    }

    fn call_return_loop(counter: u64, iterations: u32) -> Vec<u8> {
        let mut code = Vec::new();
        // mov ecx, iterations
        code.push(0xB9);
        code.extend_from_slice(&iterations.to_le_bytes());
        // xor eax, eax
        code.extend_from_slice(&[0x31, 0xC0]);
        let loop_start = code.len() as u64;
        // call func (patched below)
        code.push(0xE8);
        let call_disp_at = code.len();
        code.extend_from_slice(&0i32.to_le_bytes());
        // sub ecx, 1; cmp ecx, 0; jnz loop_start
        code.extend_from_slice(&[0x83, 0xE9, 0x01, 0x83, 0xF9, 0x00]);
        code.push(0x75);
        let jnz_at = code.len();
        code.push(0);
        // mov [counter], eax; ret
        code.push(0xA3);
        code.extend_from_slice(&(counter as u32).to_le_bytes());
        code.push(0xC3);
        let func = code.len() as u64;
        // add eax, 1; ret
        code.extend_from_slice(&[0x83, 0xC0, 0x01, 0xC3]);
        let call_next = call_disp_at as u64 + 4;
        let call_disp = (func as i64 - call_next as i64) as i32;
        code[call_disp_at..call_disp_at + 4].copy_from_slice(&call_disp.to_le_bytes());
        let jnz_next = jnz_at as u64 + 1;
        let jnz_disp = (loop_start as i64 - jnz_next as i64) as i8;
        code[jnz_at] = jnz_disp as u8;
        code
    }

    #[test]
    fn production_worker_call_return_chain_no_races_matches_cooperative_exactly() {
        let _guard = test_guard();
        let iterations = 4_u32;
        let code = call_return_loop(SLICE_CALL_COUNTER, iterations);

        let (coop_dir, mut cooperative) = test_session();
        cooperative.map_guest(SLICE_CALL_CODE, &code);
        cooperative.map_guest(SLICE_CALL_COUNTER & !0xfff, &vec![0_u8; 0x1000]);
        cooperative.map_guest(SLICE_STACK_A & !0xfff, &[0_u8; 0x1000]);
        push_guest_thread(
            &mut cooperative,
            0xA10,
            0xD10,
            SLICE_CALL_CODE,
            SLICE_STACK_A,
            0,
        );
        let mut rounds = 0;
        while pump_once(&mut cooperative) && rounds < 10_000 {
            rounds += 1;
        }
        assert_eq!(
            read_u32_guest(&cooperative, SLICE_CALL_COUNTER),
            iterations,
            "cooperative call/ret loop must finish in {rounds} rounds"
        );

        let (prod_dir, mut production) = test_session();
        install_jit(&mut production);
        production.map_guest(SLICE_CALL_CODE, &code);
        production.map_guest(SLICE_CALL_COUNTER & !0xfff, &vec![0_u8; 0x1000]);
        production.map_guest(SLICE_STACK_A & !0xfff, &[0_u8; 0x1000]);
        push_guest_thread(
            &mut production,
            0xA11,
            0xD11,
            SLICE_CALL_CODE,
            SLICE_STACK_A,
            0,
        );
        assert!(
            production
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let request = GuestSliceRequest {
            thread_id: 0xD11,
            priority: 0,
            state: production.runtime.pending_guest_threads[0].state.clone(),
        };
        let reports = production
            .runtime
            .dispatch_parallel_guest_slices(&mut production.memory, vec![request], 4_096)
            .expect("production call/ret slice");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].blocks_executed,
            3 * u64::from(iterations) + 1,
            "the whole call/ret loop must run in one worker job"
        );
        assert_eq!(
            (
                reports[0].metrics.return_predictions,
                reports[0].metrics.return_hits,
                reports[0].metrics.return_misses,
                reports[0].metrics.return_mispredictions,
                reports[0].metrics.indirect_ic_hits,
                reports[0].metrics.indirect_ic_misses,
            ),
            (u64::from(iterations) + 1, u64::from(iterations), 1, 0, 0, 0),
            "one prediction per call plus the thread-return miss"
        );
        assert_eq!(
            reports[0].metrics.native_chains,
            3 * u64::from(iterations),
            "every block after the first is a native chain"
        );
        assert_eq!(
            reports[0].exit,
            GuestSliceExit::HostBarrier { rip: 0 },
            "the balanced chain unwinds to the zero return address and yields"
        );
        production.runtime.pending_guest_threads[0].state = reports[0].state.clone();
        rounds = 0;
        while pump_once(&mut production) && rounds < 100 {
            rounds += 1;
        }
        assert_eq!(
            production.runtime.pending_guest_threads.len(),
            0,
            "the guest thread must terminate after the chain"
        );
        assert_eq!(
            read_u32_guest(&cooperative, SLICE_CALL_COUNTER),
            read_u32_guest(&production, SLICE_CALL_COUNTER),
            "cooperative and production modes must produce identical bytes"
        );
        assert_eq!(
            cooperative.read_guest(SLICE_CALL_COUNTER, 4),
            production.read_guest(SLICE_CALL_COUNTER, 4)
        );
        assert_eq!(
            reports[0].state.get(Register::Rax),
            u64::from(iterations),
            "the final guest EAX is the loop count"
        );
        drop(coop_dir);
        drop(prod_dir);
    }

    #[test]
    fn production_worker_slots_persist_predictor_tls_and_wait_until_termination_wake() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_CALL_CODE, &call_return_loop(SLICE_CALL_COUNTER, 2));
        session.map_guest(SLICE_CALL_COUNTER & !0xfff, &vec![0_u8; 0x1000]);
        session.map_guest(SLICE_STACK_A & !0xfff, &[0_u8; 0x1000]);
        push_guest_thread(
            &mut session,
            0xA12,
            0xD12,
            SLICE_CALL_CODE,
            SLICE_STACK_A,
            0,
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let mut state = session.runtime.pending_guest_threads[0].state.clone();
        for round in 1..=3_u64 {
            let request = GuestSliceRequest {
                thread_id: 0xD12,
                priority: 0,
                state: state.clone(),
            };
            let reports = session
                .runtime
                .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 1)
                .expect("single-block worker round");
            assert_eq!(reports.len(), 1);
            state = reports[0].state.clone();
            let slot = session
                .runtime
                .production_scheduler
                .as_ref()
                .expect("production scheduler")
                .slot_snapshot(0xD12)
                .expect("persistent slot");
            assert_eq!(slot.thread_id, 0xD12);
            assert_eq!(slot.slices, round);
            assert_eq!(
                slot.fs_base, session.runtime.teb_base,
                "the slot must keep the guest TEB/TLS base"
            );
            assert_eq!(
                slot.metrics.blocks_executed, round,
                "metrics must accumulate on the persistent slot"
            );
            assert_eq!(slot.has_wait, false);
        }
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        scheduler.set_slot_wait(0xD12, Arc::new(ParkSignal::new()));
        assert_eq!(
            scheduler.slot_snapshot(0xD12).expect("slot").has_wait,
            true,
            "the wait object must live with the persistent slot"
        );
        scheduler.clear_slot_wait(0xD12);
        assert_eq!(
            scheduler.slot_snapshot(0xD12).expect("slot").has_wait,
            false
        );
        // Terminating the guest thread must retire its slot (the termination
        // wake releases the wait object and all JIT control state).
        session.runtime.pending_guest_threads.clear();
        session.runtime.prune_orphan_production_waits();
        assert_eq!(
            session
                .runtime
                .production_scheduler
                .as_ref()
                .expect("production scheduler")
                .slot_snapshot(0xD12),
            None,
            "an orphaned persistent slot must be retired with its thread"
        );
        session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler")
            .set_slot_wait(0xD12, Arc::new(ParkSignal::new()));
        assert_eq!(
            session
                .runtime
                .production_scheduler
                .as_ref()
                .expect("production scheduler")
                .slot_snapshot(0xD12)
                .is_none(),
            true,
            "a retired slot must not be resurrected by a stale wait"
        );
    }

    #[test]
    fn production_slice_close_race_shutdown_joins_active_guest_loop() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_CODE, &loop_with_counter(SLICE_COUNTER_A));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        push_guest_thread(
            &mut session,
            0x500,
            0xD1,
            SLICE_CODE,
            SLICE_STACK_A,
            u32::MAX,
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        assert!(
            session
                .runtime
                .ensure_slice_block(&mut session.memory, SLICE_CODE)
                .expect("compile shutdown loop"),
            "the shutdown loop block must be worker-safe"
        );
        let program = std::sync::Arc::new(
            session
                .runtime
                .jit_runtime
                .as_ref()
                .expect("jit")
                .build_slice_program(&session.memory),
        );
        let state = session.runtime.pending_guest_threads[0].state.clone();
        session.runtime.process_shared.publish_program(program);
        let scheduler = session
            .runtime
            .production_scheduler
            .as_ref()
            .expect("production scheduler");
        let _job = scheduler.submit_slice(0xD1, state, 0, u64::MAX, None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while scheduler.active_job_count() == 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let start = std::time::Instant::now();
        session.runtime.production_scheduler = None;
        assert_eq!(
            start.elapsed() < std::time::Duration::from_secs(5),
            true,
            "dropping the pool must join an active guest slice"
        );
        assert_eq!(session.runtime.production_scheduler.is_none(), true);
        crate::jit::JIT_SAFEPOINT_REQUESTED.store(false, std::sync::atomic::Ordering::Release);
    }
    #[test]
    fn production_thunk_serialization_stress_is_exactly_once_under_two_threads() {
        with_big_stack(|| {
            let _guard = test_guard();
            let (_temp_dir, mut session) = test_session();
            install_jit(&mut session);
            let thunk = session.alloc_thunk(HostThunk::GetTickCount64);
            assert!(thunk <= u64::from(u32::MAX));
            // call [slot]; sub ecx,1; cmp ecx,0; jnz call; ret
            let mut code = vec![0xFF, 0x15];
            code.extend_from_slice(&(SLICE_THUNK_SLOT as u32).to_le_bytes());
            code.extend_from_slice(&[0x83, 0xE9, 0x01, 0x83, 0xF9, 0x00, 0x75, 0xF2, 0xC3]);
            session.map_guest(SLICE_CODE_2, &code);
            session.map_guest(SLICE_THUNK_SLOT, &(thunk as u32).to_le_bytes());
            let iterations = 8_u32;
            push_guest_thread(
                &mut session,
                0x600,
                0xE1,
                SLICE_CODE_2,
                SLICE_STACK_A,
                iterations,
            );
            push_guest_thread(
                &mut session,
                0x601,
                0xE2,
                SLICE_CODE_2,
                SLICE_STACK_B,
                iterations,
            );
            assert!(
                session
                    .runtime
                    .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
            );
            let before = trace_calls(&session, "time", "GetTickCount64");
            let mut rounds = 0;
            while pump_once(&mut session) && rounds < 1_000 {
                rounds += 1;
            }
            assert_eq!(
                trace_calls(&session, "time", "GetTickCount64"),
                before + 2 * iterations as usize,
                "every guest call must dispatch its thunk exactly once"
            );
            assert_eq!(session.runtime.pending_guest_threads.len(), 0);
        });
    }
    #[test]
    fn production_pump_race_dispatches_two_guest_loops_to_two_workers() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_CODE, &loop_with_counter(SLICE_COUNTER_A));
        session.map_guest(SLICE_CODE_2, &loop_with_counter(SLICE_COUNTER_B));
        session.map_guest(SLICE_COUNTER_A, &[0_u8; 4]);
        session.map_guest(SLICE_COUNTER_B, &[0_u8; 4]);
        push_guest_thread(&mut session, 0x700, 0xF1, SLICE_CODE, SLICE_STACK_A, 10_000);
        push_guest_thread(
            &mut session,
            0x701,
            0xF2,
            SLICE_CODE_2,
            SLICE_STACK_B,
            10_000,
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let before = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(pump_once(&mut session), true);
        let after = SCHEDULER_COUNTERS.snapshot();
        assert_eq!(read_u32_guest(&session, SLICE_COUNTER_A), 512);
        assert_eq!(read_u32_guest(&session, SLICE_COUNTER_B), 512);
        assert!(
            after.worker_overlaps > before.worker_overlaps,
            "the production pump must overlap the two guest slices"
        );
        session.runtime.pending_guest_threads.clear();
    }
    #[test]
    fn production_worker_guest_fault_boundary_is_reported_to_the_owner() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        // mov eax, [0x9000]; jmp $ — the code page is mapped, the data page
        // is not.  A jump terminator keeps the block worker-safe (a ret
        // terminator would make the whole block a host barrier).
        let mut code = vec![0xA1];
        code.extend_from_slice(&0x9000_u32.to_le_bytes());
        code.extend_from_slice(&[0xEB, 0xFE]);
        session.map_guest(SLICE_CODE, &code);
        push_guest_thread(&mut session, 0x800, 0x1F1, SLICE_CODE, SLICE_STACK_A, 1);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let request = GuestSliceRequest {
            thread_id: 0x1F1,
            priority: 0,
            state: session.runtime.pending_guest_threads[0].state.clone(),
        };
        let reports = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 4)
            .expect("dispatch faulting slice");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].exit,
            GuestSliceExit::GuestFault {
                address: 0x9000,
                write: false
            }
        );
        assert_eq!(reports[0].blocks_executed, 1);
        session.runtime.pending_guest_threads.clear();
    }

    const SLICE_JUMP_CODE: u64 = 0x34_000;
    const SLICE_SAFEPOINT_CODE: u64 = 0x35_000;
    const SLICE_STRAIGHT_CODE: u64 = 0x36_000;
    const SLICE_JUMPIF_CODE: u64 = 0x37_000;
    const SLICE_CODE_WRITE_CODE: u64 = 0x38_000;

    fn fake_scheduler(worker_count: usize, shutdown: bool) -> ProductionScheduler {
        ProductionScheduler {
            shared: Arc::new(ProductionShared {
                state: Mutex::new(ProductionState {
                    shutdown,
                    ..ProductionState::default()
                }),
                work_ready: Condvar::new(),
                completion_ready: Condvar::new(),
                shutdown: std::sync::atomic::AtomicBool::new(shutdown),
            }),
            process_shared: Arc::new(ProcessShared::new()),
            workers: Vec::new(),
            worker_count,
        }
    }

    fn slice_program(session: &mut NtThunkSession, rip: u64) -> Arc<crate::jit::GuestSliceProgram> {
        install_jit(session);
        assert_eq!(
            session
                .runtime
                .ensure_slice_block(&mut session.memory, rip)
                .expect("compile slice block"),
            true,
            "the test block must be worker-safe"
        );
        Arc::new(
            session
                .runtime
                .jit_runtime
                .as_ref()
                .expect("jit runtime")
                .build_slice_program(&session.memory),
        )
    }

    fn slice_job(
        thread_id: u32,
        state: CpuState,
        program: Arc<crate::jit::GuestSliceProgram>,
        budget: u64,
    ) -> (GuestSliceJob, Arc<ProcessShared>) {
        let process_shared = Arc::new(ProcessShared::new());
        process_shared.publish_program(program);
        (
            GuestSliceJob {
                job_id: 0,
                slot: GuestThreadSlot::new(thread_id, state),
                budget,
                start: None,
            },
            process_shared,
        )
    }

    fn slice_completion(job_id: u64, thread_id: u32, state: CpuState) -> GuestSliceCompletion {
        GuestSliceCompletion {
            job_id,
            slot: GuestThreadSlot::new(thread_id, state),
            exit: GuestSliceExit::Budget,
            blocks_executed: 1,
            worker_index: 0,
            code_writes: Vec::new(),
            metrics: crate::jit::SliceMetrics::default(),
        }
    }

    #[test]
    fn production_slice_start_gate_over_arrival_race_returns_without_deadlock() {
        let _guard = test_guard();
        let gate = SliceStartGate::new(1);
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        gate.arrive_and_wait(&shutdown);
        gate.arrive_and_wait(&shutdown);
        assert_eq!(
            *gate
                .remaining
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            0,
            "an over-arrival must observe the already-emptied gate"
        );
        assert_eq!(
            shutdown.load(std::sync::atomic::Ordering::Acquire),
            false,
            "the over-arrival must not fake a shutdown"
        );
    }

    #[test]
    fn production_slice_round_shutdown_race_skips_all_worker_reports() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        session.map_guest(SLICE_JUMP_CODE, &[0xEB, 0xFE]);
        let program = slice_program(&mut session, SLICE_JUMP_CODE);
        let scheduler = fake_scheduler(1, true);
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = SLICE_JUMP_CODE;
        let reports = scheduler.run_guest_slices(
            vec![GuestSliceRequest {
                thread_id: 0x5A,
                priority: 0,
                state,
            }],
            program,
            4,
        );
        assert_eq!(
            reports.len(),
            0,
            "a shutdown round must never report a slice as executed"
        );
    }

    #[test]
    fn production_slice_round_shutdown_race_drains_completion_before_stop() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        session.map_guest(SLICE_JUMP_CODE, &[0xEB, 0xFE]);
        let program = slice_program(&mut session, SLICE_JUMP_CODE);
        let scheduler = fake_scheduler(1, true);
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = SLICE_JUMP_CODE;
        scheduler
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .completions
            .push_back(WaitCompletion {
                job_id: 7,
                thread_id: 0x5B,
                reason: WaitWakeReason::Deadline,
                packets: Vec::new(),
            });
        let reports = scheduler.run_guest_slices(
            vec![GuestSliceRequest {
                thread_id: 0x5B,
                priority: 0,
                state,
            }],
            program,
            4,
        );
        assert_eq!(
            reports.len(),
            0,
            "shutdown must stop the round even when a wait completion woke it"
        );
        assert_eq!(
            scheduler.take_completions().len(),
            1,
            "slice rounds must leave wait completions for the owner"
        );
    }

    #[test]
    fn slice_ensure_block_rejects_missing_jit_thunk_and_unmapped_rip() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        assert_eq!(
            session
                .runtime
                .ensure_slice_block(&mut session.memory, SLICE_JUMP_CODE)
                .expect("missing jit"),
            false,
            "a runtime without a JIT cannot produce worker slices"
        );
        install_jit(&mut session);
        let thunk = session.alloc_thunk(HostThunk::GetTickCount64);
        assert_eq!(
            session
                .runtime
                .ensure_slice_block(&mut session.memory, thunk)
                .expect("host thunk"),
            false,
            "a host thunk address is never worker guest code"
        );
        let error = session
            .runtime
            .ensure_slice_block(&mut session.memory, 0xDEAD_0000)
            .expect_err("an unmapped rip must fail decoding");
        assert_eq!(
            error.code,
            crate::reason::ReasonCode::RcUnimplInsn,
            "the decode failure must propagate to the caller"
        );
    }

    #[test]
    fn production_slice_dispatch_rejects_empty_or_missing_pool() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let empty = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, Vec::new(), 8)
            .expect("empty request set");
        assert_eq!(
            empty.len(),
            0,
            "an empty request set must dispatch no slices"
        );
        let request = GuestSliceRequest {
            thread_id: 0x6A,
            priority: 0,
            state: CpuState::new(GuestArch::X86),
        };
        let no_pool = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 8)
            .expect("missing pool");
        assert_eq!(
            no_pool.len(),
            0,
            "cooperative mode has no production pool to dispatch to"
        );
        assert_eq!(
            session.runtime.production_scheduler.is_none(),
            true,
            "the dispatch must not create a pool implicitly"
        );
    }

    #[test]
    fn production_slice_jump_exit_race_updates_rip_exactly_once() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_JUMP_CODE, &[0xEB, 0xFE]);
        push_guest_thread(&mut session, 0x900, 0x77, SLICE_JUMP_CODE, SLICE_STACK_A, 0);
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let request = GuestSliceRequest {
            thread_id: 0x77,
            priority: 0,
            state: session.runtime.pending_guest_threads[0].state.clone(),
        };
        let reports = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 1)
            .expect("jump slice");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].state.rip, SLICE_JUMP_CODE,
            "a jump exit must land on the jump target"
        );
        assert_eq!(
            reports[0].blocks_executed, 1,
            "the budget must stop the slice after the jump"
        );
        assert_eq!(
            reports[0].exit,
            GuestSliceExit::Budget,
            "the jump target re-enters the same worker-safe loop"
        );
        session.runtime.pending_guest_threads.clear();
    }

    #[test]
    fn production_slice_safepoint_exit_race_consumes_request() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_SAFEPOINT_CODE, &[0xEB, 0xFE]);
        push_guest_thread(
            &mut session,
            0x901,
            0x78,
            SLICE_SAFEPOINT_CODE,
            SLICE_STACK_A,
            0,
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        crate::jit::JIT_SAFEPOINT_REQUESTED.store(true, std::sync::atomic::Ordering::Release);
        let request = GuestSliceRequest {
            thread_id: 0x78,
            priority: 0,
            state: session.runtime.pending_guest_threads[0].state.clone(),
        };
        let reports = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 4)
            .expect("safepoint slice");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].exit,
            GuestSliceExit::Safepoint,
            "the worker must stop at the safepoint, not run guest code"
        );
        assert_eq!(
            reports[0].blocks_executed, 0,
            "the entry safepoint poll stops before the block body executes"
        );
        crate::jit::JIT_SAFEPOINT_REQUESTED.store(false, std::sync::atomic::Ordering::Release);
        session.runtime.pending_guest_threads.clear();
    }

    #[test]
    fn production_slice_straight_line_fallback_is_host_barrier() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        let ir = vec![crate::cpu::IrInstruction::MovImm {
            dst: Register::Rax,
            value: 0x1234,
        }];
        let block = session
            .runtime
            .jit_runtime
            .as_mut()
            .expect("jit runtime")
            .get_or_compile_slice_block(&ir, SLICE_STRAIGHT_CODE, GuestArch::X86)
            .expect("compile straight-line slice")
            .clone();
        let mut program = session
            .runtime
            .jit_runtime
            .as_ref()
            .expect("jit runtime")
            .build_slice_program(&session.memory);
        program.blocks.insert(SLICE_STRAIGHT_CODE, block);
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = SLICE_STRAIGHT_CODE;
        let (job, process_shared) = slice_job(0x79, state, Arc::new(program), 4);
        let completion = run_guest_slice_job(
            job,
            &std::sync::atomic::AtomicBool::new(false),
            &process_shared,
            0,
        );
        assert_eq!(
            completion.exit,
            GuestSliceExit::HostBarrier {
                rip: SLICE_STRAIGHT_CODE
            },
            "a straight-line exit must return to the runtime owner"
        );
        assert_eq!(
            completion.blocks_executed, 1,
            "the straight-line block executed exactly once"
        );
        assert_eq!(
            completion.slot.context.state.get(Register::Rax),
            0x1234,
            "the worker applied the block result before the barrier"
        );
    }

    #[test]
    fn production_slice_missing_exit_metadata_is_host_barrier() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        let ir = vec![crate::cpu::IrInstruction::JumpIf {
            condition: crate::cpu::ConditionCode::NotEqual,
            target: SLICE_JUMPIF_CODE + 0x20,
            fallthrough: SLICE_JUMPIF_CODE + 0x40,
        }];
        let mut block = session
            .runtime
            .jit_runtime
            .as_mut()
            .expect("jit runtime")
            .get_or_compile_slice_block(&ir, SLICE_JUMPIF_CODE, GuestArch::X86)
            .expect("compile conditional slice")
            .clone();
        block.last_exit_info = None;
        let mut program = session
            .runtime
            .jit_runtime
            .as_ref()
            .expect("jit runtime")
            .build_slice_program(&session.memory);
        program.blocks.insert(SLICE_JUMPIF_CODE, block);
        let mut state = CpuState::new(GuestArch::X86);
        state.rip = SLICE_JUMPIF_CODE;
        let (job, process_shared) = slice_job(0x7A, state, Arc::new(program), 4);
        let completion = run_guest_slice_job(
            job,
            &std::sync::atomic::AtomicBool::new(false),
            &process_shared,
            0,
        );
        assert_eq!(
            completion.exit,
            GuestSliceExit::HostBarrier {
                rip: SLICE_JUMPIF_CODE
            },
            "conditional exit metadata loss must never fabricate a RIP"
        );
        assert_eq!(
            completion.slot.context.state.rip, SLICE_JUMPIF_CODE,
            "the owner re-dispatches the original block address"
        );
    }

    #[test]
    fn production_slice_code_write_race_clears_stale_blocks() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        let mut code = vec![0xC7, 0x05];
        code.extend_from_slice(&(SLICE_CODE_WRITE_CODE as u32).to_le_bytes());
        code.extend_from_slice(&0x9090_9090_u32.to_le_bytes());
        code.extend_from_slice(&[0xEB, 0xFE]);
        session.map_guest(SLICE_CODE_WRITE_CODE & !0xfff, &vec![0_u8; 0x1000]);
        session.map_guest(SLICE_CODE_WRITE_CODE, &code);
        session
            .runtime
            .jit_runtime
            .as_mut()
            .expect("jit runtime")
            .code_pages
            .insert(SLICE_CODE_WRITE_CODE & !0xfff);
        push_guest_thread(
            &mut session,
            0x902,
            0x7B,
            SLICE_CODE_WRITE_CODE,
            SLICE_STACK_A,
            0,
        );
        assert!(
            session
                .runtime
                .set_scheduler_mode(SchedulerMode::Production { workers: 2 })
        );
        let request = GuestSliceRequest {
            thread_id: 0x7B,
            priority: 0,
            state: session.runtime.pending_guest_threads[0].state.clone(),
        };
        let reports = session
            .runtime
            .dispatch_parallel_guest_slices(&mut session.memory, vec![request], 4)
            .expect("code-write slice");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].exit,
            GuestSliceExit::CodeWrite,
            "a guest store to a compiled-code page must yield to the owner"
        );
        assert_eq!(
            reports[0].code_writes,
            vec![(SLICE_CODE_WRITE_CODE, 4)],
            "the exact code write must be reported for invalidation"
        );
        assert_eq!(
            session
                .runtime
                .jit_runtime
                .as_ref()
                .expect("jit runtime")
                .slice_block(SLICE_CODE_WRITE_CODE)
                .is_none(),
            true,
            "a code write must clear stale worker slice blocks"
        );
        session.runtime.pending_guest_threads.clear();
    }

    #[test]
    fn production_completion_port_shutdown_race_reports_signal_reason() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let signal = Arc::new(ParkSignal::new());
        let job = WaitJob {
            job_id: 3,
            thread_id: 0x7C,
            signal: Arc::clone(&signal),
            observed_generation: signal.generation(),
            kind: WaitJobKind::CompletionPort {
                state: port_state,
                guest_thread_id: 0x7C,
                max_packets: 1,
                alertable: false,
            },
            deadline: None,
        };
        let before = SCHEDULER_COUNTERS.snapshot();
        signal.notify(WaitWakeReason::Shutdown);
        let started = std::time::Instant::now();
        let completion = run_wait_job(job);
        assert_eq!(
            completion.reason,
            WaitWakeReason::Shutdown,
            "a shutdown notification must win after the port slice expires"
        );
        assert_eq!(
            completion.packets.len(),
            0,
            "a shutdown wake must not fabricate a packet"
        );
        assert_eq!(
            started.elapsed() < std::time::Duration::from_secs(2),
            true,
            "the worker must observe shutdown within one port slice"
        );
        assert_ne!(
            SCHEDULER_COUNTERS.snapshot().port_rechecks,
            before.port_rechecks,
            "the blocked port wait must recheck exactly once per slice"
        );
    }

    #[test]
    fn production_object_wait_rejects_unsupported_iocp_handle() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        assert_eq!(
            session
                .runtime
                .production_wait_supported(&object_wait(port)),
            false,
            "an IOCP handle is not a supported object-wait source"
        );
    }

    #[test]
    fn production_completion_port_invalid_pointer_race_propagates_error() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        map_cp_continuation(&mut session);
        let operation = WaitOperation::CompletionPort {
            port: 0,
            bytes_ptr: 0,
            key_ptr: KEY_PTR,
            overlapped_ptr: OVERLAPPED_PTR,
        };
        let mut packet = test_packet(1, 0x5151, 0x6161);
        packet.completion_key = 0x1_0000_0000;
        let error = session
            .runtime
            .completion_port_packets_resume(&operation, vec![packet], &mut session.memory)
            .err()
            .expect("a non-fitting x86 completion key must fail");
        assert_eq!(error.code, crate::reason::ReasonCode::RcUnimplInsn);
        let mut packet = test_packet(1, 0x5151, 0x6161);
        packet.overlapped = 0x1_0000_0000;
        let error = session
            .runtime
            .completion_port_packets_resume(&operation, vec![packet], &mut session.memory)
            .err()
            .expect("a non-fitting x86 overlapped pointer must fail");
        assert_eq!(error.code, crate::reason::ReasonCode::RcUnimplInsn);
        let operation_ex = WaitOperation::CompletionPortEx {
            port: 0,
            entries_ptr: ENTRIES_PTR,
            entry_count: 1,
            removed_ptr: REMOVED_PTR,
        };
        let mut packet = test_packet(1, 0xAAA, 0xBBB);
        packet.overlapped = 0x1_0000_0000;
        let error = session
            .runtime
            .completion_port_packets_resume(&operation_ex, vec![packet], &mut session.memory)
            .err()
            .expect("the second entry write must fail on a non-fitting pointer");
        assert_eq!(error.code, crate::reason::ReasonCode::RcUnimplInsn);
        let mut packet = test_packet(1, 0xAAA, 0xBBB);
        packet.internal = 0x1_0000_0000;
        let error = session
            .runtime
            .completion_port_packets_resume(&operation_ex, vec![packet], &mut session.memory)
            .err()
            .expect("the third entry write must fail on a non-fitting pointer");
        assert_eq!(error.code, crate::reason::ReasonCode::RcUnimplInsn);
        let resume = session
            .runtime
            .completion_port_packets_resume(
                &operation_ex,
                vec![test_packet(2, 0xAAA, 0xBBB)],
                &mut session.memory,
            )
            .expect("well-formed entry");
        assert_eq!(resume.code, 1);
        assert_eq!(resume.bytes, Some(1));
        assert_eq!(read_u32_guest(&session, REMOVED_PTR), 1);
        let no_optional_outputs = WaitOperation::CompletionPort {
            port: 0,
            bytes_ptr: 0,
            key_ptr: 0,
            overlapped_ptr: 0,
        };
        let resume = session
            .runtime
            .completion_port_packets_resume(
                &no_optional_outputs,
                vec![test_packet(2, 0xAAA, 0xBBB)],
                &mut session.memory,
            )
            .expect("NULL completion out-pointers");
        assert_eq!(resume.code, 1);
        assert_eq!(resume.bytes, Some(2));
    }

    #[test]
    fn production_packet_failure_race_propagates_through_completion_apply() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        push_guest_thread(&mut session, 0x903, 0x7D, ENTRY_POINT, CONTINUATION_RSP, 0);
        {
            let thread = session
                .runtime
                .pending_guest_threads
                .back_mut()
                .expect("parked record");
            thread.state_machine = GuestThreadState::Waiting;
            thread.wait = Some(GuestWait {
                objects: Vec::new(),
                wait_all: false,
                deadline_ticks: None,
                alertable: false,
                operation: WaitOperation::CompletionPort {
                    port,
                    bytes_ptr: 0,
                    key_ptr: KEY_PTR,
                    overlapped_ptr: 0,
                },
            });
        }
        session
            .runtime
            .production_waits
            .insert(0x7D, ProductionWait { job_id: 11 });
        let before = SCHEDULER_COUNTERS.snapshot();
        let mut packet = test_packet(3, 0x5151, 0x6161);
        packet.completion_key = 0x1_0000_0000;
        let error = session
            .runtime
            .apply_production_completion(
                WaitCompletion {
                    job_id: 11,
                    thread_id: 0x7D,
                    reason: WaitWakeReason::CompletionPort,
                    packets: vec![packet],
                },
                &mut session.memory,
            )
            .expect_err("a malformed completion key must fail the apply");
        assert_eq!(error.code, crate::reason::ReasonCode::RcUnimplInsn);
        assert_eq!(
            session.runtime.production_waits.len(),
            0,
            "the failed apply consumed the parked wait"
        );
        assert_eq!(
            session.runtime.pending_guest_threads.len(),
            0,
            "the failed apply must not requeue a thread with no resume result"
        );
        assert_eq!(
            SCHEDULER_COUNTERS.snapshot().completion_port_wakeups,
            before.completion_port_wakeups,
            "a failed out-parameter write is not a packet handoff"
        );
    }

    #[test]
    fn production_pump_slice_shutdown_race_reports_no_work() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_JUMP_CODE, &[0xEB, 0xFE]);
        push_guest_thread(&mut session, 0x904, 0x7E, SLICE_JUMP_CODE, SLICE_STACK_A, 0);
        session.runtime.scheduler_mode = SchedulerMode::Production { workers: 2 };
        session.runtime.production_scheduler = Some(fake_scheduler(2, true));
        let outcome = session
            .runtime
            .try_pump_parallel_slices(&mut session.memory)
            .expect("shutdown pump");
        assert_eq!(
            outcome.is_none(),
            true,
            "a slice round that reports nothing must fall back to the owner pump"
        );
        assert_eq!(
            session.runtime.pending_guest_threads.len(),
            1,
            "the runnable thread must stay queued for the owner"
        );
    }

    #[test]
    fn production_pump_slice_duplicate_completion_race_applies_once() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_JUMP_CODE, &[0xEB, 0xFE]);
        push_guest_thread(&mut session, 0x905, 0x7F, SLICE_JUMP_CODE, SLICE_STACK_A, 0);
        push_guest_thread(&mut session, 0x906, 0x7F, SLICE_JUMP_CODE, SLICE_STACK_B, 0);
        session.runtime.scheduler_mode = SchedulerMode::Production { workers: 2 };
        let scheduler = fake_scheduler(2, false);
        let mut applied = session.runtime.pending_guest_threads[0].state.clone();
        applied.rip = SLICE_JUMP_CODE + 2;
        scheduler
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .slice_completions
            .extend([
                slice_completion(0, 0x7F, applied.clone()),
                slice_completion(1, 0x7F, applied),
            ]);
        session.runtime.production_scheduler = Some(scheduler);
        let outcome = session
            .runtime
            .try_pump_parallel_slices(&mut session.memory)
            .expect("duplicate pump");
        assert_eq!(
            outcome
                .expect("duplicate reports still count as work")
                .did_work,
            true
        );
        assert_eq!(
            session.runtime.pending_guest_threads.len(),
            2,
            "neither duplicate record may be lost"
        );
        assert_eq!(
            session
                .runtime
                .pending_guest_threads
                .iter()
                .filter(|thread| thread.state.rip == SLICE_JUMP_CODE + 2)
                .count(),
            1,
            "a duplicate completion must update exactly one thread record"
        );
    }

    #[test]
    fn production_pump_slice_stale_completion_race_skips_unknown_thread() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        install_jit(&mut session);
        session.map_guest(SLICE_JUMP_CODE, &[0xEB, 0xFE]);
        push_guest_thread(&mut session, 0x907, 0x80, SLICE_JUMP_CODE, SLICE_STACK_A, 0);
        session.runtime.scheduler_mode = SchedulerMode::Production { workers: 2 };
        let scheduler = fake_scheduler(2, false);
        let mut stale_state = CpuState::new(GuestArch::X86);
        stale_state.rip = SLICE_JUMP_CODE + 0x40;
        scheduler
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .slice_completions
            .push_back(slice_completion(0, 0xDEAD, stale_state));
        session.runtime.production_scheduler = Some(scheduler);
        let outcome = session
            .runtime
            .try_pump_parallel_slices(&mut session.memory)
            .expect("stale pump");
        assert_eq!(
            outcome
                .expect("a stale report is still worker work")
                .did_work,
            true
        );
        assert_eq!(
            session.runtime.pending_guest_threads.len(),
            1,
            "a stale completion must not consume an unrelated thread"
        );
        assert_eq!(
            session.runtime.pending_guest_threads[0].thread_id, 0x80,
            "the live thread stays parked in the queue"
        );
    }

    #[test]
    fn production_completion_port_late_signal_race_repolls_without_busy_wait() {
        let _guard = test_guard();
        let (_temp_dir, mut session) = test_session();
        let port = session
            .runtime
            .win32
            .create_io_completion_port(None, None, 0, 0)
            .expect("create port");
        let port_state = session
            .runtime
            .win32
            .io_completion_port_state(port)
            .expect("port state");
        let signal = Arc::new(ParkSignal::new());
        let job = WaitJob {
            job_id: 4,
            thread_id: 0x83,
            signal: Arc::clone(&signal),
            observed_generation: signal.generation(),
            kind: WaitJobKind::CompletionPort {
                state: port_state,
                guest_thread_id: 0x83,
                max_packets: 1,
                alertable: false,
            },
            deadline: None,
        };
        let notifier = {
            let signal = Arc::clone(&signal);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                signal.notify(WaitWakeReason::ObjectSignaled);
            })
        };
        let before = SCHEDULER_COUNTERS.snapshot();
        let started = std::time::Instant::now();
        let completion = run_wait_job(job);
        notifier.join().expect("notifier");
        assert_eq!(
            completion.reason,
            WaitWakeReason::ObjectSignaled,
            "the late signal must be observed on the next slice recheck"
        );
        assert_eq!(
            completion.packets.len(),
            0,
            "the signal wake must not fabricate a packet"
        );
        assert_eq!(
            started.elapsed() < std::time::Duration::from_secs(2),
            true,
            "the recheck must be bounded by the port slice, not a busy poll"
        );
        assert_ne!(
            SCHEDULER_COUNTERS.snapshot().port_rechecks,
            before.port_rechecks,
            "an empty port slice must re-enter the port condition variable"
        );
    }

    #[test]
    fn cooperative_pumped_slice_yield_race_requeues_exactly_once() {
        with_big_stack(|| {
            let _guard = test_guard();
            let (_temp_dir, mut session) = test_session();
            let thunk = session.alloc_thunk(HostThunk::SwitchToThread);
            assert!(
                thunk <= u64::from(u32::MAX),
                "the x86 thunk address must fit 32 bits"
            );
            let mut code = vec![0xFF, 0x15];
            code.extend_from_slice(&(SLICE_THUNK_SLOT as u32).to_le_bytes());
            code.push(0xC3);
            session.map_guest(SLICE_CODE_2, &code);
            session.map_guest(SLICE_THUNK_SLOT, &(thunk as u32).to_le_bytes());
            push_guest_thread(&mut session, 0x908, 0x81, SLICE_CODE_2, SLICE_STACK_A, 0);
            push_guest_thread(&mut session, 0x909, 0x82, SLICE_CODE_2, SLICE_STACK_B, 0);
            let before = SCHEDULER_COUNTERS.snapshot();
            assert_eq!(pump_once(&mut session), true, "the yielding slice ran");
            assert_eq!(
                session.runtime.pending_guest_threads.len(),
                2,
                "a yielded pumped thread must be requeued exactly once"
            );
            assert_eq!(
                session
                    .runtime
                    .pending_guest_threads
                    .iter()
                    .filter(|thread| thread.state_machine == GuestThreadState::Waiting)
                    .count(),
                1,
                "only the yielding thread is parked in the wait queue"
            );
            assert_ne!(
                SCHEDULER_COUNTERS.snapshot().guest_thread_switches,
                before.guest_thread_switches,
                "the yield must count as one guest-thread switch"
            );
        });
    }

    #[test]
    fn guest_threads_keep_independent_last_errors_across_switches() {
        assert_eq!(teb_last_error_offset(GuestArch::X64), 0x68);
        assert_eq!(teb_last_error_offset(GuestArch::X86), 0x34);
        with_big_stack(|| {
            let _guard = test_guard();
            let (_temp_dir, mut session) = test_session();
            let thunk = session.alloc_thunk(HostThunk::SetLastError);
            session.map_guest(SLICE_THUNK_SLOT, &(thunk as u32).to_le_bytes());
            let code = |value: u32| {
                let mut bytes = vec![0x68];
                bytes.extend_from_slice(&value.to_le_bytes());
                bytes.extend_from_slice(&[0xFF, 0x15]);
                bytes.extend_from_slice(&(SLICE_THUNK_SLOT as u32).to_le_bytes());
                bytes.extend_from_slice(&[0x83, 0xC4, 0x04, 0xC3]);
                bytes
            };
            session.map_guest(SLICE_CODE, &code(111));
            session.map_guest(SLICE_CODE_2, &code(222));
            let teb_a = 0x62_000_u64;
            let teb_b = 0x64_000_u64;
            session.map_guest(teb_a, &[0_u8; 0x1000]);
            session.map_guest(teb_b, &[0_u8; 0x1000]);
            for (handle, thread_id, rip, rsp, teb) in [
                (0x500, 0xC1, SLICE_CODE, SLICE_STACK_A, teb_a),
                (0x501, 0xC2, SLICE_CODE_2, SLICE_STACK_B, teb_b),
            ] {
                let mut state = CpuState::new(GuestArch::X86);
                state.rip = rip;
                state.set(Register::Rsp, rsp);
                state.segment_bases.fs = teb;
                session
                    .runtime
                    .pending_guest_threads
                    .push_back(PendingGuestThread {
                        handle,
                        thread_id,
                        start_address: rip,
                        parameter: 0,
                        initial_rsp: rsp,
                        started: true,
                        suspended: 0,
                        wake_tick: 0,
                        teb_base: teb,
                        tls_vector_ptr: 0,
                        tls_slots: BTreeMap::new(),
                        fls_slots: BTreeMap::new(),
                        state,
                        state_machine: GuestThreadState::Runnable,
                        exit_code_override: None,
                        wait: None,
                        wait_resume: None,
                    });
            }
            assert!(pump_once(&mut session), "thread A ran");
            assert_eq!(
                read_u32_guest(&session, teb_a + 0x34),
                111,
                "thread A's last error is parked in its own TEB"
            );
            assert!(pump_once(&mut session), "thread B ran");
            assert_eq!(
                read_u32_guest(&session, teb_b + 0x34),
                222,
                "thread B's last error is independent"
            );
            assert_eq!(
                read_u32_guest(&session, teb_a + 0x34),
                111,
                "thread A's TEB was not overwritten by B"
            );
            assert_eq!(
                session.runtime.last_error, 0,
                "the scheduler restores the caller's last error"
            );
        });
    }

    #[test]
    fn guest_qos_guard_applies_and_restores_the_worker_class() {
        with_big_stack(|| {
            let read_class = || {
                let mut class = 0_u32;
                let mut relative = 0_i32;
                // SAFETY: both out pointers are valid for the calling thread.
                unsafe {
                    pthread_get_qos_class_np(
                        libc::pthread_self() as *mut libc::c_void,
                        &raw mut class,
                        &raw mut relative,
                    );
                }
                class
            };
            assert_eq!(
                qos_class_for_windows_priority(15),
                QOS_CLASS_USER_INTERACTIVE
            );
            assert_eq!(qos_class_for_windows_priority(2), QOS_CLASS_USER_INITIATED);
            assert_eq!(qos_class_for_windows_priority(1), QOS_CLASS_DEFAULT);
            assert_eq!(qos_class_for_windows_priority(0), QOS_CLASS_DEFAULT);
            assert_eq!(qos_class_for_windows_priority(-1), QOS_CLASS_UTILITY);
            assert_eq!(qos_class_for_windows_priority(-2), QOS_CLASS_UTILITY);
            assert_eq!(qos_class_for_windows_priority(-15), QOS_CLASS_BACKGROUND);
            assert_eq!(
                qos_class_for_windows_priority(99),
                QOS_CLASS_USER_INTERACTIVE
            );
            assert_eq!(qos_class_for_windows_priority(-99), QOS_CLASS_BACKGROUND);
            let before = read_class();
            {
                let _guard = GuestQosGuard::apply(15);
                assert_eq!(
                    read_class(),
                    QOS_CLASS_USER_INTERACTIVE,
                    "time-critical work runs at user-interactive QoS"
                );
            }
            assert_eq!(
                read_class(),
                before,
                "dropping the guard restores the worker's class"
            );
        });
    }
}
