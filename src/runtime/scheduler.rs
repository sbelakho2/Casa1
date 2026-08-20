//! Cooperative guest scheduler: wait descriptors, satisfiability,
//! wait completion, parking, and the pending-thread pump.
use super::*;

/// What a parked guest wait is waiting for.  The scheduler resumes the
/// thread only when the descriptor becomes satisfiable — object signals,
/// overlapped completion, pipe connection, deadline expiry or (alertable)
/// APC delivery.
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
                let resume = self.complete_wait(&wait, tid, memory)?;
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
