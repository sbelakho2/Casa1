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
    /// mode observes exactly the pumping thread; a real worker pool would
    /// observe one entry per worker.
    pub(crate) host_workers: std::sync::Mutex<Vec<std::thread::ThreadId>>,
}

/// Point-in-time copy of [`SchedulerCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchedulerCountersSnapshot {
    pub(crate) guest_thread_switches: u64,
    pub(crate) parked_waits: u64,
    pub(crate) completion_port_wakeups: u64,
    pub(crate) host_worker_busy_nanos: u64,
    pub(crate) host_workers_observed: usize,
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
}

pub(crate) static SCHEDULER_COUNTERS: SchedulerCounters = SchedulerCounters {
    guest_thread_switches: std::sync::atomic::AtomicU64::new(0),
    parked_waits: std::sync::atomic::AtomicU64::new(0),
    completion_port_wakeups: std::sync::atomic::AtomicU64::new(0),
    host_worker_busy_nanos: std::sync::atomic::AtomicU64::new(0),
    host_workers: std::sync::Mutex::new(Vec::new()),
};

/// What a parked guest wait is waiting for.  The scheduler resumes the
/// thread only when the descriptor becomes satisfiable — object signals,
/// overlapped completion, pipe connection, completion-port packet, deadline
/// expiry or (alertable) APC delivery.
#[derive(Debug)]
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
                self.completion_port_wait_ready(*port, thread.thread_id)
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
    }
}

impl PeHostRuntime {
    /// Pump-driven execution mode: the main thread is parked in the wait
    /// queue.  Run runnable guest threads, service timers/APCs, and advance
    /// the guest clock; the HOST sleeps only when nothing is runnable, and
    /// only briefly (1 ms) so finite deadlines progress.  Returns the process
    /// exit code when the run ends (including the run deadline, which is
    /// harness cancellation — never a fake wait result).
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
            if RUN_DEADLINE_EXPIRED.load(std::sync::atomic::Ordering::Acquire) {
                crate::live::live_trace(
                    "[pe] run deadline reached in pump-driven mode — ending run with exit -2",
                );
                return Ok(-2);
            }
            let pump_outcome = self.pump_pending_guest_thread(memory)?;
            if let Some(code) = pump_outcome.process_exit {
                exit_code = code;
                break;
            }
            if self.pending_guest_threads.is_empty() {
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
                // Nothing runnable: the host sleeps briefly and the guest
                // clock advances so finite deadlines expire.
                std::thread::sleep(std::time::Duration::from_millis(1));
                self.win32.record_sleep_observation(1, 1);
            }
        }
        Ok(exit_code)
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
    /// Consume a ready completion-port wait before the pump mutates any state
    /// (see [`CompletionPortPreconsume`]).  Never host-blocks: the packet is
    /// taken with a zero-timeout dequeue.
    fn preconsume_completion_port_wait(
        &mut self,
        thread: &PendingGuestThread,
        memory: &mut MemoryImage,
    ) -> AppResult<CompletionPortPreconsume> {
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
                thread.suspended = count;
                return;
            }
        }
    }

    pub(crate) fn pump_pending_guest_thread(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<PumpOutcome> {
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
            pending_thread.state_machine = GuestThreadState::Waiting;
            self.pending_guest_threads.push_back(pending_thread);
            return Ok(PumpOutcome {
                did_work: false,
                process_exit: None,
            });
        }

        let previous_thread_id = self.win32.set_current_thread_id(pending_thread.thread_id);
        let previous_teb_base = self.teb_base;
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
            // result (RAX + last_error), then run the thread.
            let _resumed_from_wait = if let Some(wait) = pending_thread.wait.take() {
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
                        pending_thread.state_machine = GuestThreadState::Waiting;
                        Ok((
                            PumpedThreadOutcome {
                                requeue: Some(pending_thread),
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
        self.win32.set_current_thread_id(previous_thread_id);
        self.teb_base = previous_teb_base;
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

    /// Serialises the instrumentation tests so counter deltas are exact
    /// (the counters are process-wide by design; the port's packet counters
    /// are only touched by these tests, but wakeup deltas would otherwise
    /// race each other).
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

    /// `mov dword ptr [FLAG_PTR], 1; xor eax, eax; ret` — the wait
    /// continuation body: records that it ran and returns.
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

    /// Park the main guest thread through the REAL `park_for_wait` path with
    /// a continuation that resumes at [`ENTRY_POINT`].
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

    /// Guest-thread execution recurses into the interpreter, so thread-start
    /// tests run on the same 8 MiB scratch stack the runtime's own
    /// `with_big_stack` helper uses.
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
    fn parked_completion_port_ex_wait_resumes_with_batched_entries() {
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
        port_state
            .post(test_packet(5, 0xA1, 0xB1))
            .expect("post first");
        port_state
            .post(test_packet(6, 0xA2, 0xB2))
            .expect("post second");

        park_main_thread(&mut session, cp_wait_ex(port, 2));
        assert!(parker_satisfiable(&session));
        assert!(pump_once(&mut session));

        assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);
        assert_eq!(read_u32_guest(&session, REMOVED_PTR), 2);
        // x86 OVERLAPPED_ENTRY: key, overlapped, internal, bytes (4 bytes each).
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR), 0xA1);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 4), 0xB1);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 12), 5);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 16), 0xA2);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 20), 0xB2);
        assert_eq!(read_u32_guest(&session, ENTRIES_PTR + 28), 6);
        assert_eq!(port_state.queued_packet_count(), 0);
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

    #[test]
    fn cooperative_mode_runs_guest_threads_serially_on_the_pumping_host_thread() {
        with_big_stack(|| {
            let _guard = test_guard();
            let (_temp_dir, mut session) = test_session();
            map_cp_continuation(&mut session);
            let current_host = std::thread::current().id();
            let create_thread = session.alloc_thunk(HostThunk::CreateThread);
            for _ in 0..2 {
                let handle = session.call_x86(
                    create_thread,
                    &[0, 0, ENTRY_POINT as u32, 0, 0, THREAD_ID_PTR as u32],
                );
                assert_ne!(handle, 0, "CreateThread");
            }
            assert_eq!(session.runtime.pending_guest_threads.len(), 2);

            let before = SCHEDULER_COUNTERS.snapshot();
            assert!(pump_once(&mut session), "first queued thread runs");
            assert_eq!(session.runtime.pending_guest_threads.len(), 1);
            assert!(pump_once(&mut session), "second queued thread runs");
            assert!(session.runtime.pending_guest_threads.is_empty());
            assert_eq!(read_u32_guest(&session, FLAG_PTR), 1);

            let after = SCHEDULER_COUNTERS.snapshot();
            assert!(after.guest_thread_switches >= before.guest_thread_switches + 2);
            assert!(
                SCHEDULER_COUNTERS.host_worker_observed(current_host),
                "the pumping host thread executed the slices"
            );
            assert!(after.host_worker_busy_nanos > before.host_worker_busy_nanos);
        });
    }
}
