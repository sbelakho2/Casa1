//! System threads, APCs, DPCs, interrupts and timers.

use super::*;

impl DriverIsland {
    /// Runs ready island system threads in resumable slices.  A slice yields
    /// at an island safepoint when its quantum expires, an interrupt is
    /// pending, termination is requested, or the guest blocks in a wait.
    /// Waiting threads are re-evaluated on every scheduler turn and woken by
    /// the exact object/deadline/APC transition.
    #[allow(dead_code)]
    pub(crate) fn pump_system_threads(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> usize {
        let inner = self.inner.clone();
        let _active = ActiveIsland::install(inner.clone());
        let mut ran = 0;
        loop {
            if self.pump_one_system_slice(runtime, memory) {
                ran += 1;
                if ran >= MAX_THREAD_SLICES {
                    break;
                }
                continue;
            }
            let deadline = inner.borrow().system_threads.next_wait_deadline();
            let Some(deadline) = deadline else {
                break;
            };
            let now = Instant::now();
            std::thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(50)),
            );
        }
        ran
    }

    /// Runs one scheduler turn: wake satisfied waits, run one ready slice,
    /// then service one pending virtual interrupt.  Exposed for tests that
    /// need to act between slices (handle close, termination, interrupt).
    #[allow(dead_code)]
    pub(crate) fn pump_one_system_slice(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> bool {
        let inner = self.inner.clone();
        let _active = ActiveIsland::install(inner.clone());
        self.wake_system_waits(runtime, memory);
        let next = { inner.borrow_mut().system_threads.take_next() };
        let Some(run) = next else {
            return false;
        };
        let wake_status = inner.borrow_mut().system_threads.take_wake_status(run.id);
        if wake_status == Some(crate::casak::status::STATUS_USER_APC) {
            self.deliver_system_apcs(runtime, memory, run.id);
        }
        self.run_thread_slice(runtime, memory, run, wake_status);
        let vector = { inner.borrow_mut().pending_interrupts.pop_front() };
        if let Some(vector) = vector {
            let _ = self.trigger_virtual_interrupt(runtime, memory, vector);
        }
        true
    }

    pub(crate) fn run_thread_slice(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        run: crate::casak::threads::RunnableThread,
        wake_status: Option<i32>,
    ) {
        let inner = self.inner.clone();
        let (mut cpu, resumed, previous_irql, thread_irql, quantum) = {
            let mut state = inner.borrow_mut();
            let resumed = state.thread_cpus.contains_key(&run.id);
            let mut cpu = state.thread_cpus.remove(&run.id).unwrap_or_else(|| {
                let mut cpu = CpuState::new(state.arch);
                cpu.set(Register::Rsp, run.stack_base + run.stack_size - 0x100);
                cpu
            });
            if let Some(status) = wake_status {
                cpu.set(Register::Rax, status as u32 as u64);
            }
            let thread_irql = state
                .system_threads
                .thread_record(run.id)
                .map_or(0, |record| record.irql);
            let previous_irql = state.kernel.irql;
            state.kernel.irql = thread_irql;
            state.current_system_thread = Some(run.id);
            state.slice_deadline = Some(Instant::now() + state.thread_quantum);
            let quantum = state.thread_quantum;
            (cpu, resumed, previous_irql, thread_irql, quantum)
        };
        let _ = (thread_irql, quantum);
        runtime.yield_pumped_guest_thread = false;
        let resume_rsp = resumed.then(|| cpu.get(Register::Rsp));
        let result = runtime.execute_guest_callback_inner(
            &mut cpu,
            memory,
            run.start_routine,
            &[run.context],
            "PsCreateSystemThread",
            true,
            resume_rsp,
        );
        {
            let mut state = inner.borrow_mut();
            state.current_system_thread = None;
            state.slice_deadline = None;
            let saved_irql = state.kernel.irql;
            state.kernel.irql = previous_irql;
            match result {
                Ok(crate::runtime::GuestCallbackDisposition::Returned(value)) => {
                    state.thread_cpus.remove(&run.id);
                    state.finish_system_thread(run.id, value as u32 as i32);
                }
                Ok(crate::runtime::GuestCallbackDisposition::Yielded) => {
                    let _ = state.system_threads.set_irql(run.id, saved_irql);
                    let terminated = state
                        .system_threads
                        .thread_record(run.id)
                        .and_then(|record| record.termination_requested)
                        .is_some();
                    if terminated {
                        state.thread_cpus.remove(&run.id);
                        state.finish_system_thread(run.id, STATUS_UNSUCCESSFUL);
                    } else if state.system_threads.wait_of(run.id).is_some() {
                        state.thread_cpus.insert(run.id, cpu);
                    } else {
                        state.thread_cpus.insert(run.id, cpu);
                        state.system_threads.requeue_current();
                    }
                }
                Err(_) => {
                    state.thread_cpus.remove(&run.id);
                    state.finish_system_thread(run.id, STATUS_UNSUCCESSFUL);
                }
            }
        }
    }

    pub(crate) fn deliver_system_apcs(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thread: ThreadId,
    ) {
        let inner = self.inner.clone();
        let apcs = {
            let mut state = inner.borrow_mut();
            state
                .system_threads
                .take_apcs_by_thread(thread)
                .unwrap_or_default()
        };
        for apc in apcs {
            let (arch, stack_base, stack_size) = {
                let state = inner.borrow();
                let record = state
                    .system_threads
                    .thread_record(thread)
                    .expect("an APC target has a scheduler record");
                (state.arch, record.stack_base, record.stack_size)
            };
            let mut cpu = CpuState::new(arch);
            cpu.set(Register::Rsp, stack_base + stack_size - 0x100);
            let _ = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                apc.routine,
                &[apc.context],
                "SystemThreadApc",
            );
        }
    }

    pub(crate) fn wake_system_waits(
        &mut self,
        _runtime: &mut PeHostRuntime,
        _memory: &mut MemoryImage,
    ) {
        let inner = self.inner.clone();
        let waits = { inner.borrow().system_threads.waiting_threads() };
        for (thread, wait) in waits {
            let (status, consume_event) = {
                let state = inner.borrow();
                match wait.target {
                    crate::casak::threads::WaitTarget::Thread(target) => {
                        let done = state
                            .system_threads
                            .thread_state(target)
                            .is_some_and(|state| {
                                state == crate::casak::threads::KernelThreadState::Terminated
                            });
                        (done.then_some(STATUS_SUCCESS), false)
                    }
                    crate::casak::threads::WaitTarget::Event(event) => {
                        let signaled = state
                            .kernel
                            .events
                            .get(&event)
                            .is_some_and(|record| record.signaled);
                        (signaled.then_some(STATUS_SUCCESS), true)
                    }
                }
            };
            let status = status.or_else(|| {
                wait.deadline
                    .filter(|deadline| Instant::now() >= *deadline)
                    .map(|_| STATUS_TIMEOUT)
            });
            let Some(status) = status else {
                continue;
            };
            let mut state = inner.borrow_mut();
            if consume_event
                && let crate::casak::threads::WaitTarget::Event(event) = wait.target
                && let Some(record) = state.kernel.events.get_mut(&event)
                && record.event_type == SYNCHRONIZATION_EVENT
            {
                record.signaled = false;
                *record
                    .gate
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
            }
            let _ = state.system_threads.wake(thread, status);
        }
    }

    /// Test/host helper: queue a virtual interrupt to be delivered at the next
    /// system-thread safepoint.
    #[allow(dead_code)]
    pub(crate) fn queue_virtual_interrupt(&mut self, vector: u32) {
        self.inner.borrow_mut().pending_interrupts.push_back(vector);
    }

    /// Test/host helper: queue an APC on a system thread.  Alertable waits are
    /// woken immediately; non-alertable waits keep blocking.
    #[allow(dead_code)]
    pub(crate) fn queue_system_thread_apc(
        &mut self,
        handle: SystemThreadHandle,
        routine: u64,
        context: u64,
    ) -> Result<(), i32> {
        self.inner
            .borrow_mut()
            .system_threads
            .queue_apc(handle, routine, context)
            .map(|_| ())
    }

    /// Test/host helper: cancel a blocked wait with `STATUS_CANCELLED`.
    #[allow(dead_code)]
    pub(crate) fn cancel_system_thread_wait(
        &mut self,
        handle: SystemThreadHandle,
    ) -> Result<(), i32> {
        self.inner
            .borrow_mut()
            .system_threads
            .cancel_wait(handle, crate::casak::status::STATUS_CANCELLED)
            .map(|_| ())
    }

    #[allow(dead_code)]
    pub(crate) fn set_thread_quantum(&mut self, quantum: Duration) {
        self.inner.borrow_mut().thread_quantum = quantum;
    }

    #[allow(dead_code)]
    pub(crate) fn system_thread_state(
        &self,
        handle: SystemThreadHandle,
    ) -> Option<crate::casak::threads::KernelThreadState> {
        let state = self.inner.borrow();
        let thread = state.system_threads.query(handle).ok()?.id;
        state.system_threads.thread_state(thread)
    }

    #[allow(dead_code)]
    pub(crate) fn system_thread_exit_status_by_id(
        &self,
        thread: ThreadId,
    ) -> Result<Option<i32>, i32> {
        self.inner.borrow().system_threads.exit_status_by_id(thread)
    }

    /// Waits for a system thread handle, pumping the scheduler.  `None`
    /// means the timeout elapsed; `Some(status)` is the exit code.
    #[allow(dead_code)]
    pub(crate) fn wait_system_thread(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        handle: SystemThreadHandle,
        timeout_ms: u64,
    ) -> Result<Option<i32>, i32> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.min(60_000));
        loop {
            if let Some(status) = self.inner.borrow().system_threads.exit_status(handle)? {
                return Ok(Some(status));
            }
            if timeout_ms == 0 {
                return Ok(None);
            }
            let ran = self.pump_system_threads(runtime, memory);
            if let Some(status) = self.inner.borrow().system_threads.exit_status(handle)? {
                return Ok(Some(status));
            }
            if ran == 0 || (timeout_ms != u64::MAX && Instant::now() >= deadline) {
                return Ok(None);
            }
        } // coverage: unreachable — every loop iteration returns
    }

    /// Terminates a system thread by handle.  A ready thread is detached
    /// immediately; a running thread exits at the end of its slice.
    #[allow(dead_code)]
    pub(crate) fn terminate_system_thread(
        &mut self,
        handle: SystemThreadHandle,
        exit_status: i32,
    ) -> Result<(), i32> {
        let mut state = self.inner.borrow_mut();
        let (thread, immediate) = state
            .system_threads
            .request_terminate(handle, exit_status)?;
        if immediate {
            state.thread_cpus.remove(&thread);
            let IslandState {
                process,
                system_threads,
                ..
            } = &mut *state;
            let _ = process.terminate_thread(system_threads, thread);
        }
        Ok(())
    }

    /// Signals a synthetic interrupt vector and runs every ISR (in connection
    /// order) until one handles it, then drains the DPC queue.  Returns 1 when
    /// handled, 0 when no ISR claimed it, or the exact failure status.
    #[allow(dead_code)]
    pub(crate) fn trigger_virtual_interrupt(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        vector: u32,
    ) -> AppResult<i32> {
        let inner = self.inner.clone();
        let _active = ActiveIsland::install(inner.clone());
        let objects = { inner.borrow().interrupts.vector_objects(vector) };
        if objects.is_empty() {
            return Ok(STATUS_NOT_FOUND);
        }
        let mut handled = false;
        for guest_object in objects {
            // A KMDF interrupt that is currently disabled (`WdfInterrupt-
            // Disable`) does not dispatch its ISR.
            let kmdf_disabled = {
                let state = inner.borrow();
                state
                    .kmdf
                    .interrupts
                    .get(&guest_object)
                    .is_some_and(|interrupt| interrupt.disabled > 0)
            };
            if kmdf_disabled {
                continue;
            }
            let ticket = {
                let mut state = inner.borrow_mut();
                match state.interrupts.begin_dispatch(guest_object) {
                    Ok(ticket) => ticket,
                    Err(_) => continue,
                }
            };
            {
                let mut state = inner.borrow_mut();
                state.kernel.irql = ticket.irql;
            }
            let arch = inner.borrow().arch;
            let mut cpu = CpuState::new(arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x400);
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                ticket.service_routine,
                &[ticket.guest_object, ticket.service_context],
                "InterruptServiceRoutine",
            );
            let claimed = matches!(result, Ok(value) if value as u32 != 0);
            {
                let mut state = inner.borrow_mut();
                state.kernel.irql = 0;
                let _ = state.interrupts.end_dispatch(ticket);
            }
            if claimed {
                handled = true;
                break;
            }
        }
        loop {
            let (calls, restore_irql) = {
                let mut state = inner.borrow_mut();
                (state.take_ready_dpcs(), state.kernel.irql)
            };
            if calls.is_empty() {
                break;
            }
            {
                inner.borrow_mut().kernel.irql = DISPATCH_LEVEL;
            }
            for call in calls {
                let arch = inner.borrow().arch;
                let mut cpu = CpuState::new(arch);
                cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x800);
                let _ = runtime
                    .execute_guest_callback(&mut cpu, memory, call.entry, &call.args, call.label);
            }
            inner.borrow_mut().kernel.irql = restore_irql;
        }
        Ok(if handled { 1 } else { 0 })
    }
}

impl IslandState {
    pub(crate) fn ke_initialize_dpc(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let dpc = guest_arg(state, memory, 0)?;
        let routine = guest_arg(state, memory, 1)?;
        let context = guest_arg(state, memory, 2)?;
        if dpc == 0 || routine == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        self.kernel.dpcs.insert(
            dpc,
            DpcState {
                routine,
                context,
                arg1: 0,
                arg2: 0,
                queued: false,
            },
        );
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn ke_insert_queue_dpc(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let dpc = guest_arg(state, memory, 0)?;
        let arg1 = guest_arg(state, memory, 1)?;
        let arg2 = guest_arg(state, memory, 2)?;
        let Some(entry) = self.kernel.dpcs.get_mut(&dpc) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        };
        if entry.queued {
            state.set(Register::Rax, 0);
            return Ok(None);
        }
        entry.queued = true;
        entry.arg1 = arg1;
        entry.arg2 = arg2;
        self.kernel.pending_dpcs.push_back(dpc);
        if self.kernel.irql < DISPATCH_LEVEL {
            let mut remaining = self.take_ready_dpcs();
            let restore_irql = self.kernel.irql;
            self.kernel.irql = DISPATCH_LEVEL;
            if let Some(first) = remaining.pop_front() {
                return Ok(Some(PendingGuestCall {
                    entry: first.entry,
                    args: first.args,
                    label: first.label,
                    purpose: PendingPurpose::Dpcs {
                        remaining,
                        restore_irql,
                        final_result: 1,
                    },
                }));
            }
        }
        state.set(Register::Rax, 1);
        Ok(None)
    }

    pub(crate) fn ke_remove_queue_dpc(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let dpc = guest_arg(state, memory, 0)?;
        let mut removed = false;
        if let Some(entry) = self.kernel.dpcs.get_mut(&dpc) {
            if entry.queued {
                entry.queued = false;
                removed = true;
            }
        }
        if removed {
            self.kernel.pending_dpcs.retain(|queued| *queued != dpc);
        }
        state.set(Register::Rax, u64::from(removed));
        Ok(())
    }

    /// Move every queued DPC into a guest callback, clearing its queued flag.
    pub(crate) fn take_ready_dpcs(&mut self) -> VecDeque<GuestCallback> {
        let mut calls = VecDeque::new();
        while let Some(dpc) = self.kernel.pending_dpcs.pop_front() {
            let entry = self
                .kernel
                .dpcs
                .get_mut(&dpc)
                .expect("pending DPC queue only holds initialized DPCs");
            debug_assert!(entry.queued, "pending DPC queue only holds queued DPCs");
            entry.queued = false;
            calls.push_back(GuestCallback {
                entry: entry.routine,
                args: vec![dpc, entry.context, entry.arg1, entry.arg2],
                label: "DeferredProcedureCall",
            });
        }
        calls
    }

    pub(crate) fn ps_get_current_process_id(&self, state: &mut CpuState) {
        let id = self
            .process
            .query_process(self.current_process)
            .expect("the island process is registered")
            .id;
        state.set(Register::Rax, u64::from(id.0));
    }

    pub(crate) fn ps_get_current_thread_id(&self, state: &mut CpuState) {
        let id = self
            .process
            .query_thread(self.current_thread)
            .expect("the island thread is registered")
            .id;
        state.set(Register::Rax, u64::from(id.0));
    }

    pub(crate) fn maybe_preempt(&mut self, runtime: &mut PeHostRuntime) {
        let Some(thread) = self.current_system_thread else {
            return;
        };
        if self.kernel.irql >= DISPATCH_LEVEL {
            return;
        }
        let Some(record) = self.system_threads.thread_record(thread) else {
            return;
        };
        let due = record.termination_requested.is_some()
            || !self.pending_interrupts.is_empty()
            || self
                .slice_deadline
                .is_some_and(|deadline| Instant::now() >= deadline);
        if due {
            runtime.yield_pumped_guest_thread = true;
        }
    }

    pub(crate) fn ps_create_system_thread(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_out = guest_arg(state, memory, 0)?;
        let _desired_access = guest_arg(state, memory, 1)?;
        let _object_attributes = guest_arg(state, memory, 2)?;
        let process_handle = guest_arg(state, memory, 3)?;
        let start_routine = guest_arg(state, memory, 4)?;
        let context = guest_arg(state, memory, 5)?;
        if handle_out == 0 || start_routine == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let pointer_bytes = self.arch.pointer_bytes() as u64;
        if !probe_guest_range(runtime, memory, handle_out, pointer_bytes, true) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        if !probe_guest_range(runtime, memory, start_routine, 1, false) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        if context != 0 && !probe_guest_range(runtime, memory, context, 1, false) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        let current_process_handle = u64::from(runtime.win32.current_process_handle());
        if process_handle != 0
            && process_handle != u64::MAX
            && process_handle != current_process_handle
        {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        let stack_size = 0x4000_u64;
        let stack_base = match self.arena.alloc(memory, stack_size as usize, 16) {
            Ok(base) => base,
            Err(_) => {
                set_status(state, STATUS_INSUFFICIENT_RESOURCES);
                return Ok(());
            }
        };
        let created = match self.system_threads.create(
            &mut self.process,
            self.current_process,
            start_routine,
            context,
            stack_base,
            stack_size,
        ) {
            Ok(created) => created,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        write_guest_pointer(memory, handle_out, created.handle.0, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn ps_terminate_system_thread(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let exit_status = guest_arg(state, memory, 0)? as u32 as i32;
        let status = self
            .system_threads
            .request_terminate_current(exit_status)
            .err()
            .unwrap_or(STATUS_SUCCESS);
        set_status(state, status);
        Ok(())
    }

    /// Validates and publishes one virtual interrupt object.  The guest
    /// `PKINTERRUPT` storage is allocated from the island arena.
    pub(crate) fn connect_interrupt_common(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        handle_out: u64,
        service_routine: u64,
        service_context: u64,
        spin_lock: u64,
        vector: u32,
        irql: u8,
        synchronize_irql: u8,
        mode: u32,
        share_vector: bool,
        affinity: u64,
    ) -> AppResult<()> {
        if handle_out == 0 || service_routine == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let pointer_bytes = self.arch.pointer_bytes() as u64;
        if !probe_guest_range(runtime, memory, handle_out, pointer_bytes, true) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        if !probe_guest_range(runtime, memory, service_routine, 1, false) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        if service_context != 0 && !probe_guest_range(runtime, memory, service_context, 1, false) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        if spin_lock != 0 && !probe_guest_range(runtime, memory, spin_lock, pointer_bytes, true) {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        }
        let guest_object = match self.arena.alloc(memory, 0x40, 16) {
            Ok(object) => object,
            Err(_) => {
                set_status(state, STATUS_INSUFFICIENT_RESOURCES);
                return Ok(());
            }
        };
        let request = ConnectRequest {
            guest_object,
            service_routine,
            service_context,
            spin_lock,
            vector,
            irql,
            synchronize_irql,
            mode,
            share_vector,
            affinity,
        };
        if let Err(status) = self.interrupts.connect(request) {
            set_status(state, status);
            return Ok(());
        }
        write_guest_pointer(memory, handle_out, guest_object, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn io_connect_interrupt(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_out = guest_arg(state, memory, 0)?;
        let service_routine = guest_arg(state, memory, 1)?;
        let service_context = guest_arg(state, memory, 2)?;
        let spin_lock = guest_arg(state, memory, 3)?;
        let vector = guest_arg(state, memory, 4)? as u32;
        let irql = guest_arg(state, memory, 5)? as u8;
        let synchronize_irql = guest_arg(state, memory, 6)? as u8;
        let mode = guest_arg(state, memory, 7)? as u32;
        let share_vector = guest_arg(state, memory, 8)? != 0;
        let affinity = guest_arg(state, memory, 9)?;
        self.connect_interrupt_common(
            runtime,
            state,
            memory,
            handle_out,
            service_routine,
            service_context,
            spin_lock,
            vector,
            irql,
            synchronize_irql,
            mode,
            share_vector,
            affinity,
        )
    }

    pub(crate) fn io_connect_interrupt_ex(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let parameters = guest_arg(state, memory, 0)?;
        if parameters == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let version = match memory
            .read_u32(parameters)
            .map_err(|_| STATUS_INVALID_PARAMETER)
            .and_then(InterruptManager::validate_version)
        {
            Ok(version) => version,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let pointer = self.arch.pointer_bytes() as u64;
        let object_offset = 8;
        let service_offset = object_offset + pointer;
        let context_offset = service_offset + pointer;
        let spin_offset = context_offset + pointer;
        let vector_offset = spin_offset + pointer;
        let irql_offset = vector_offset + 4;
        let sync_offset = irql_offset + 1;
        let mode_offset = sync_offset + 1;
        let share_offset = mode_offset + 1;
        let affinity_offset = share_offset + 1;
        let parsed = (|| -> Result<(u64, u64, u64, u64, u32, u8, u8, u32, bool, u64), i32> {
            let handle_out = read_guest_pointer(memory, parameters + object_offset, self.arch)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let service_routine =
                read_guest_pointer(memory, parameters + service_offset, self.arch)
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let service_context =
                read_guest_pointer(memory, parameters + context_offset, self.arch)
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let spin_lock = read_guest_pointer(memory, parameters + spin_offset, self.arch)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let vector = memory
                .read_u32(parameters + vector_offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let irql = memory
                .read_u8(parameters + irql_offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let synchronize_irql = memory
                .read_u8(parameters + sync_offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let mode = u32::from(
                memory
                    .read_u8(parameters + mode_offset)
                    .map_err(|_| STATUS_INVALID_PARAMETER)?,
            );
            let share_vector = memory
                .read_u8(parameters + share_offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)?
                != 0;
            let affinity = memory
                .read_u64(parameters + affinity_offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            if handle_out == 0 || service_routine == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            Ok((
                handle_out,
                service_routine,
                service_context,
                spin_lock,
                vector,
                irql,
                synchronize_irql,
                mode,
                share_vector,
                affinity,
            ))
        })();
        let (
            handle_out,
            service_routine,
            service_context,
            spin_lock,
            vector,
            irql,
            synchronize_irql,
            mode,
            share_vector,
            affinity,
        ) = match parsed {
            Ok(values) => values,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let _ = version;
        self.connect_interrupt_common(
            runtime,
            state,
            memory,
            handle_out,
            service_routine,
            service_context,
            spin_lock,
            vector,
            irql,
            synchronize_irql,
            mode,
            share_vector,
            affinity,
        )
    }

    pub(crate) fn io_disconnect_interrupt(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let interrupt = guest_arg(state, memory, 0)?;
        let status = match self.interrupts.disconnect(interrupt) {
            Ok(DisconnectOutcome::Deferred | DisconnectOutcome::Removed) => STATUS_SUCCESS,
            Err(status) => status,
        };
        set_status(state, status);
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn finish_system_thread(&mut self, thread: ThreadId, status: i32) {
        let SystemThreadManager { .. } = self.system_threads;
        let _ = self.system_threads.finish_current(status);
        let IslandState {
            process,
            system_threads,
            ..
        } = self;
        let _ = process.terminate_thread(system_threads, thread);
    }
}
