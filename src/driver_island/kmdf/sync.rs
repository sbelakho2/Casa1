//! KMDF object model.

use super::*;

impl IslandState {
    pub(crate) fn wdf_wait_lock_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let lock_out = guest_arg(state, memory, 1)?;
        if lock_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                lock_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::WaitLock, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            let driver = self.kmdf.driver_handle;
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.parent = Some(driver);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&driver) {
                object.children.insert(handle);
            }
        }
        self.kmdf.wait_locks.insert(
            handle,
            KmdfWaitLock {
                gate: Arc::new((Mutex::new(false), Condvar::new())),
            },
        );
        write_guest_pointer(memory, lock_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Resolve the optional `PLONGLONG` timeout.  A null pointer means
    /// infinite wait; negative values are relative 100 ns units and
    /// non-negative values are absolute 100 ns since 1601-01-01 (we treat a
    /// zero absolute as "try once", matching KMDF's documented behavior).
    pub(crate) fn wait_lock_timeout(
        &self,
        memory: &MemoryImage,
        pointer: u64,
    ) -> AppResult<Option<Duration>> {
        if pointer == 0 {
            return Ok(None);
        }
        let units = match self.arch {
            GuestArch::X64 => memory.read_u64(pointer)? as i64,
            GuestArch::X86 => i64::from(memory.read_u32(pointer)? as i32),
        };
        if units == 0 {
            return Ok(Some(Duration::ZERO));
        }
        let relative = if units < 0 {
            units.saturating_neg()
        } else {
            // Absolute deadlines are converted against the guest clock's
            // current UTC time; tests use relative timeouts.
            units
        };
        Ok(Some(Duration::from_nanos(
            (relative as u64).saturating_mul(100),
        )))
    }

    pub(crate) fn wait_lock_acquire_gate(
        &self,
        gate: &Arc<(Mutex<bool>, Condvar)>,
        timeout: Option<Duration>,
    ) -> i32 {
        let started = Instant::now();
        let (mutex, wake) = &**gate;
        let mut locked = match mutex.lock() {
            Ok(locked) => locked,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !*locked {
            *locked = true;
            return STATUS_SUCCESS;
        }
        let Some(timeout) = timeout else {
            while *locked {
                locked = match wake.wait(locked) {
                    Ok(locked) => locked,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
            *locked = true;
            return STATUS_SUCCESS;
        };
        if timeout.is_zero() {
            return STATUS_TIMEOUT;
        }
        let deadline = started + timeout;
        while *locked {
            let now = Instant::now();
            if now >= deadline {
                return STATUS_TIMEOUT;
            }
            let remaining = deadline - now;
            locked = match wake.wait_timeout(locked, remaining) {
                Ok((locked, _)) => locked,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        *locked = true;
        STATUS_SUCCESS
    }

    pub(crate) fn wdf_wait_lock_acquire(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let timeout_pointer = guest_arg(state, memory, 1)?;
        let timeout = self.wait_lock_timeout(memory, timeout_pointer)?;
        let Some(lock) = self.kmdf.wait_locks.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let already_held = lock.gate.0.lock().map(|locked| *locked).unwrap_or(false);
        let status = self.wait_lock_acquire_gate(&lock.gate, timeout);
        if already_held && status == STATUS_SUCCESS {
            self.kmdf.parked_acquires += 1;
        }
        set_status(state, status);
        Ok(())
    }

    pub(crate) fn wdf_wait_lock_release(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let Some(lock) = self.kmdf.wait_locks.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let (mutex, wake) = &*lock.gate;
        let mut locked = match mutex.lock() {
            Ok(locked) => locked,
            Err(poisoned) => poisoned.into_inner(),
        };
        *locked = false;
        drop(locked);
        wake.notify_all();
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_spin_lock_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let lock_out = guest_arg(state, memory, 1)?;
        if lock_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                lock_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::SpinLock, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        self.kmdf.spinlocks.insert(
            handle,
            KmdfSpinLock {
                held: false,
                raised_from: 0,
            },
        );
        write_guest_pointer(memory, lock_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_spin_lock_acquire(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::SpinLock) {
            set_status(state, status);
            return Ok(());
        }
        let lock = self
            .kmdf
            .spinlocks
            .get_mut(&handle)
            .expect("spin lock was validated");
        if lock.held {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        lock.held = true;
        lock.raised_from = self.kernel.irql;
        self.kernel.irql = self.kernel.irql.max(DISPATCH_LEVEL);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_spin_lock_release(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::SpinLock) {
            set_status(state, status);
            return Ok(());
        }
        let lock = self
            .kmdf
            .spinlocks
            .get_mut(&handle)
            .expect("spin lock was validated");
        if !lock.held {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        self.kernel.irql = lock.raised_from;
        lock.held = false;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_timer_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let config = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let timer_out = guest_arg(state, memory, 2)?;
        if timer_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                timer_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let (minimum, callback_offset, serialization_offset) = match self.arch {
            GuestArch::X64 => (0x18u64, 0x08u64, 0x10u64),
            GuestArch::X86 => (0x0Cu64, 0x04u64, 0x08u64),
        };
        if crate::host_thunks::validate_guest_pointer(memory, config, minimum as usize).is_err() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(config)? as u64;
        if size < minimum {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let evt_timer = read_guest_pointer(memory, config + callback_offset, self.arch)?;
        if evt_timer == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // `minimum` is at least `serialization_offset + 4` on both
        // architectures, so the field is always inside the validated span.
        let _automatic_serialization = memory.read_u32(config + serialization_offset)?;
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Timer, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.timers.insert(
            handle,
            KmdfTimer {
                config: KmdfTimerConfig { evt_timer },
                running: false,
                fired: 0,
                context_guest,
            },
        );
        write_guest_pointer(memory, timer_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_timer_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        let due_pointer = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::Timer) {
            set_status(state, status);
            return Ok(None);
        }
        if due_pointer == 0
            || crate::host_thunks::validate_guest_pointer(memory, due_pointer, 8).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let due = memory.read_u64(due_pointer)? as i64;
        let timer = self.kmdf.timers.get(&handle).expect("timer was validated");
        if timer.running {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        let (evt_timer, context_guest) = (timer.config.evt_timer, timer.context_guest);
        {
            let timer = self.kmdf.timers.get_mut(&handle).expect("timer");
            timer.running = true;
        }
        // A non-positive relative deadline means "fire now"; the real guest
        // callback executes synchronously after the shim returns.
        if due <= 0 {
            if let Some(timer) = self.kmdf.timers.get_mut(&handle) {
                timer.running = false;
                timer.fired += 1;
            }
            self.kmdf.timer_fires += 1;
            set_status(state, STATUS_SUCCESS);
            return Ok(Some(PendingGuestCall {
                entry: evt_timer,
                args: vec![handle, context_guest],
                label: "EvtTimerFunc",
                purpose: PendingPurpose::Callbacks {
                    remaining: Vec::new(),
                    dispatch_next: false,
                },
            }));
        }
        set_status(state, STATUS_SUCCESS);
        Ok(None)
    }

    pub(crate) fn wdf_timer_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let _wait = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::Timer) {
            set_status(state, status);
            return Ok(());
        }
        let timer = self
            .kmdf
            .timers
            .get_mut(&handle)
            .expect("timer was validated");
        let was_running = timer.running;
        timer.running = false;
        state.set(Register::Rax, u64::from(was_running));
        Ok(())
    }

    pub(crate) fn wdf_work_item_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let config = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let item_out = guest_arg(state, memory, 2)?;
        if item_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                item_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let (minimum, callback_offset, serialization_offset) = match self.arch {
            GuestArch::X64 => (0x18u64, 0x08u64, 0x10u64),
            GuestArch::X86 => (0x0Cu64, 0x04u64, 0x08u64),
        };
        if crate::host_thunks::validate_guest_pointer(memory, config, minimum as usize).is_err() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(config)? as u64;
        if size < minimum {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let evt_work_item = read_guest_pointer(memory, config + callback_offset, self.arch)?;
        if evt_work_item == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // `minimum` is at least `serialization_offset + 4` on both
        // architectures, so the field is always inside the validated span.
        let _automatic_serialization = memory.read_u32(config + serialization_offset)?;
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::WorkItem, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.work_items.insert(
            handle,
            KmdfWorkItem {
                config: KmdfWorkItemConfig { evt_work_item },
                queued: false,
                completed: 0,
                context_guest,
            },
        );
        write_guest_pointer(memory, item_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_work_item_enqueue(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::WorkItem) {
            set_status(state, status);
            return Ok(None);
        }
        let item = self
            .kmdf
            .work_items
            .get(&handle)
            .expect("work item was validated");
        if item.queued {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        let (evt_work_item, context_guest) = (item.config.evt_work_item, item.context_guest);
        if let Some(item) = self.kmdf.work_items.get_mut(&handle) {
            item.queued = true;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(Some(PendingGuestCall {
            entry: evt_work_item,
            args: vec![handle, context_guest],
            label: "EvtWorkItem",
            purpose: PendingPurpose::WorkItem { handle },
        }))
    }

    pub(crate) fn wdf_work_item_flush(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::WorkItem) {
            set_status(state, status);
            return Ok(());
        }
        // Work-item callbacks execute synchronously in this model, so a
        // successful enqueue has already completed by the time Flush is called.
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}
