//! Kernel services: pool, MDL, lookaside, spinlocks, IRQL, events, ETW.

use super::*;

impl IslandState {
    pub(crate) fn ex_allocate_pool(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let pool_type = guest_arg(state, memory, 0)? as u32;
        let size = guest_arg(state, memory, 1)? as usize;
        let tag_bits = guest_arg(state, memory, 2)? as u32;
        let tag = PoolTag::new(&tag_bits.to_le_bytes());
        if pool_type != NON_PAGED_POOL && pool_type != PAGED_POOL {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if pool_type == PAGED_POOL && self.kernel.irql >= DISPATCH_LEVEL {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if size == 0 || size > 0x100_0000 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let block = match self.pool.allocate(tag, size) {
            Ok(block) => block,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let guest = match self.arena.alloc(memory, size, 8) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.pool.free(block);
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        self.pool_blocks.insert(guest, block);
        state.set(Register::Rax, guest);
        Ok(())
    }

    pub(crate) fn ex_free_pool(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        let tag_bits = guest_arg(state, memory, 1)? as u32;
        let tag = PoolTag::new(&tag_bits.to_le_bytes());
        if let Some(block) = self.pool_blocks.remove(&guest) {
            if block.tag == tag {
                let _ = self.pool.free(block);
            } else {
                self.pool_blocks.insert(guest, block);
                state.set(Register::Rax, STATUS_INVALID_ADDRESS as i64 as u64);
                return Ok(());
            }
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    pub(crate) fn ex_allocate_pool_untagged(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let pool_type = guest_arg(state, memory, 0)? as u32;
        let size = guest_arg(state, memory, 1)? as usize;
        // Paged pool is not available above APC_LEVEL.  The kernel bugchecks
        // here; the island fails the allocation closed instead of handing out
        // pageable memory at dispatch level.
        if pool_type == PAGED_POOL && self.kernel.irql >= DISPATCH_LEVEL {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if pool_type != NON_PAGED_POOL && pool_type != PAGED_POOL {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if size == 0 || size > 0x100_0000 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let tag = PoolTag::new(b"None");
        let block = match self.pool.allocate(tag, size) {
            Ok(block) => block,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let guest = match self.arena.alloc(memory, size, 8) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.pool.free(block);
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        self.pool_blocks.insert(guest, block);
        state.set(Register::Rax, guest);
        Ok(())
    }

    pub(crate) fn ex_free_pool_untagged(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        if let Some(block) = self.pool_blocks.remove(&guest) {
            let _ = self.pool.free(block);
        }
        Ok(())
    }

    pub(crate) fn ke_get_current_irql(&self, state: &mut CpuState) {
        state.set(Register::Rax, u64::from(self.kernel.irql));
    }

    pub(crate) fn kf_raise_irql(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let new_irql = guest_arg(state, memory, 0)? as u8;
        if new_irql > HIGH_LEVEL {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if new_irql < self.kernel.irql {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        let previous = self.kernel.irql;
        self.kernel.irql = new_irql;
        state.set(Register::Rax, u64::from(previous));
        Ok(())
    }

    pub(crate) fn kf_lower_irql(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let new_irql = guest_arg(state, memory, 0)? as u8;
        if new_irql > self.kernel.irql {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        self.kernel.irql = new_irql;
        if new_irql >= DISPATCH_LEVEL {
            return Ok(None);
        }
        let mut remaining = self.take_ready_dpcs();
        if remaining.is_empty() {
            return Ok(None);
        }
        let restore_irql = self.kernel.irql;
        self.kernel.irql = DISPATCH_LEVEL;
        let first = remaining.pop_front().expect("non-empty queue");
        Ok(Some(PendingGuestCall {
            entry: first.entry,
            args: first.args,
            label: first.label,
            purpose: PendingPurpose::Dpcs {
                remaining,
                restore_irql,
                final_result: 0,
            },
        }))
    }

    pub(crate) fn ke_acquire_spin_lock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let lock = guest_arg(state, memory, 0)?;
        if lock == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if self.kernel.spinlocks.contains_key(&lock) || self.kernel.irql > DISPATCH_LEVEL {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        let previous = self.kernel.irql;
        self.kernel.spinlocks.insert(
            lock,
            SpinLockState {
                raised_from: previous,
            },
        );
        self.kernel.irql = DISPATCH_LEVEL;
        write_guest_pointer(memory, lock, 1, self.arch)?;
        state.set(Register::Rax, u64::from(previous));
        Ok(())
    }

    pub(crate) fn ke_release_spin_lock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let lock = guest_arg(state, memory, 0)?;
        let new_irql = guest_arg(state, memory, 1)? as u8;
        let Some(held) = self.kernel.spinlocks.get(&lock).copied() else {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        };
        if self.kernel.irql != DISPATCH_LEVEL || new_irql > held.raised_from {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        self.kernel.spinlocks.remove(&lock);
        self.kernel.irql = new_irql;
        write_guest_pointer(memory, lock, 0, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn ke_initialize_event(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let event = guest_arg(state, memory, 0)?;
        let event_type = guest_arg(state, memory, 1)? as u32;
        let initial = guest_arg(state, memory, 2)? != 0;
        if event == 0 || !matches!(event_type, NOTIFICATION_EVENT | SYNCHRONIZATION_EVENT) {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let gate = Arc::new((Mutex::new(initial), Condvar::new()));
        self.kernel.events.insert(
            event,
            KernelEvent {
                event_type,
                signaled: initial,
                gate,
            },
        );
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn ke_set_event(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let event = guest_arg(state, memory, 0)?;
        let Some((previous, gate)) = self
            .kernel
            .events
            .get(&event)
            .map(|record| (record.signaled, record.gate.clone()))
        else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if let Some(record) = self.kernel.events.get_mut(&event) {
            record.signaled = true;
        }
        *gate
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        gate.1.notify_all();
        state.set(Register::Rax, u64::from(previous));
        Ok(())
    }

    pub(crate) fn ke_reset_event(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let event = guest_arg(state, memory, 0)?;
        let Some((previous, gate)) = self
            .kernel
            .events
            .get(&event)
            .map(|record| (record.signaled, record.gate.clone()))
        else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if let Some(record) = self.kernel.events.get_mut(&event) {
            record.signaled = false;
        }
        *gate
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        state.set(Register::Rax, u64::from(previous));
        Ok(())
    }

    pub(crate) fn ke_read_state_event(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let event = guest_arg(state, memory, 0)?;
        let Some(record) = self.kernel.events.get(&event) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        state.set(Register::Rax, u64::from(record.signaled));
        Ok(())
    }

    pub(crate) fn ke_wait_for_single_object(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        if self.current_system_thread.is_some() {
            return self.ke_wait_system_thread(runtime, state, memory);
        }
        let object = guest_arg(state, memory, 0)?;
        let timeout_ptr = guest_arg(state, memory, 3)?;
        if let Ok(record) = self.system_threads.query(SystemThreadHandle(object)) {
            let status = if record.is_terminated() {
                STATUS_SUCCESS
            } else {
                STATUS_TIMEOUT
            };
            set_status(state, status);
            return Ok(());
        }
        let Some((event_type, signaled, gate)) = self
            .kernel
            .events
            .get(&object)
            .map(|event| (event.event_type, event.signaled, event.gate.clone()))
        else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if signaled {
            self.consume_event(event_type, object, gate);
            set_status(state, STATUS_SUCCESS);
            return Ok(());
        }
        if timeout_ptr == 0 {
            // An infinite wait needs a schedulable guest thread to make the
            // signal observable.  The island has no such scheduler, so it
            // fails closed instead of spinning forever.
            set_status(state, STATUS_NOT_SUPPORTED);
            return Ok(());
        }
        let raw = memory.read_u64(timeout_ptr)? as i64;
        let ticks = if raw < 0 {
            (-(raw as i128)) as u128
        } else {
            let now = system_time_100ns();
            (raw as u128).saturating_sub(now as u128)
        };
        if ticks == 0 {
            set_status(state, STATUS_TIMEOUT);
            return Ok(());
        }
        let wait_ms = ((ticks.saturating_add(TICKS_PER_MILLISECOND as u128 - 1))
            / TICKS_PER_MILLISECOND as u128)
            .min(MAX_DISPATCHER_WAIT_MS) as u64;
        let guard = gate
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (guard, _) = gate
            .1
            .wait_timeout(guard, Duration::from_millis(wait_ms))
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let signaled = *guard;
        drop(guard);
        if signaled {
            self.consume_event(event_type, object, gate);
            set_status(state, STATUS_SUCCESS);
        } else {
            set_status(state, STATUS_TIMEOUT);
        }
        Ok(())
    }

    pub(crate) fn consume_event(
        &mut self,
        event_type: u32,
        object: u64,
        gate: Arc<(Mutex<bool>, Condvar)>,
    ) {
        match event_type {
            SYNCHRONIZATION_EVENT => {
                if let Some(record) = self.kernel.events.get_mut(&object) {
                    record.signaled = false;
                }
                *gate
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
            }
            _ => {
                self.notification_waits += 1;
            }
        }
    }

    pub(crate) fn ke_wait_system_thread(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let object = guest_arg(state, memory, 0)?;
        let alertable = guest_arg(state, memory, 3)? != 0;
        let timeout_ptr = guest_arg(state, memory, 4)?;
        let thread = self
            .current_system_thread
            .expect("ke_wait_system_thread is only called for a running system thread");
        let target =
            if let Ok(target_record) = self.system_threads.query(SystemThreadHandle(object)) {
                if target_record.id == thread {
                    set_status(state, STATUS_INVALID_PARAMETER);
                    return Ok(());
                }
                if target_record.is_terminated() {
                    set_status(state, STATUS_SUCCESS);
                    return Ok(());
                }
                crate::casak::threads::WaitTarget::Thread(target_record.id)
            } else if let Some(event) = self.kernel.events.get(&object) {
                if event.signaled {
                    let event_type = event.event_type;
                    let gate = event.gate.clone();
                    self.consume_event(event_type, object, gate);
                    set_status(state, STATUS_SUCCESS);
                    return Ok(());
                }
                crate::casak::threads::WaitTarget::Event(object)
            } else {
                set_status(state, STATUS_INVALID_HANDLE);
                return Ok(());
            };
        let deadline = if timeout_ptr == 0 {
            None
        } else {
            let raw = memory.read_u64(timeout_ptr)? as i64;
            let ticks = if raw < 0 {
                (-(raw as i128)) as u128
            } else {
                let now = system_time_100ns();
                (raw as u128).saturating_sub(now as u128)
            };
            if ticks == 0 {
                set_status(state, STATUS_TIMEOUT);
                return Ok(());
            }
            let nanos = ticks.saturating_mul(100).min(u64::MAX as u128) as u64;
            Some(Instant::now() + Duration::from_nanos(nanos))
        };
        if alertable && self.system_threads.apc_pending(thread) {
            self.system_threads
                .set_pending_wake_status(thread, crate::casak::status::STATUS_USER_APC)
                .expect("the running thread has a scheduler record");
            state.set(Register::Rax, STATUS_PENDING as u32 as u64);
            runtime.yield_pumped_guest_thread = true;
            return Ok(());
        }
        self.system_threads
            .wait_current(crate::casak::threads::SystemWait {
                target,
                deadline,
                alertable,
            })
            .expect("the running thread can block");
        state.set(Register::Rax, STATUS_PENDING as u32 as u64);
        runtime.yield_pumped_guest_thread = true;
        Ok(())
    }

    pub(crate) fn ke_query_system_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let destination = guest_arg(state, memory, 0)?;
        if destination == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        memory.write_u64(destination, system_time_100ns());
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn io_allocate_mdl(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let virtual_address = guest_arg(state, memory, 0)?;
        let length = guest_arg(state, memory, 1)?;
        let secondary = guest_arg(state, memory, 2)?;
        let _charge_quota = guest_arg(state, memory, 3)?;
        let irp = guest_arg(state, memory, 4)?;
        if length == 0 || length > u64::from(u32::MAX) || virtual_address == 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        // Secondary/chained MDLs require IRP integration; the island fails
        // this closed rather than pretending the chain exists.
        if secondary != 0 || irp != 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let mdl_size = match self.arch {
            GuestArch::X86 => 0x20,
            GuestArch::X64 => 0x30,
        };
        let guest = match self.arena.alloc(memory, mdl_size, 8) {
            Ok(guest) => guest,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        write_mdl_header(memory, self.arch, guest, virtual_address, length, false)?;
        self.kernel.mdls.insert(
            guest,
            MdlState {
                virtual_address,
                byte_count: length,
                write_access: false,
                locked: false,
            },
        );
        state.set(Register::Rax, guest);
        Ok(())
    }

    pub(crate) fn mm_probe_and_lock_pages(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mdl = guest_arg(state, memory, 0)?;
        let access_mode = guest_arg(state, memory, 1)? as u8;
        let operation = guest_arg(state, memory, 2)? as u32;
        let Some(record) = self.kernel.mdls.get(&mdl).copied() else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if record.locked {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        if !matches!(
            operation,
            IO_READ_ACCESS | IO_WRITE_ACCESS | IO_MODIFY_ACCESS
        ) || !matches!(access_mode, KERNEL_MODE | USER_MODE)
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let write = operation != IO_READ_ACCESS;
        if !probe_guest_range(
            runtime,
            memory,
            record.virtual_address,
            record.byte_count,
            write,
        ) {
            set_status(state, STATUS_ACCESS_VIOLATION);
            return Ok(());
        }
        if let Some(record) = self.kernel.mdls.get_mut(&mdl) {
            record.locked = true;
            record.write_access = write;
        }
        write_mdl_header(
            memory,
            self.arch,
            mdl,
            record.virtual_address,
            record.byte_count,
            true,
        )
        .expect("guest-visible MDL header is always writable");
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn mm_unlock_pages(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let mdl = guest_arg(state, memory, 0)?;
        let Some(record) = self.kernel.mdls.get_mut(&mdl) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if !record.locked {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        record.locked = false;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn io_free_mdl(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let mdl = guest_arg(state, memory, 0)?;
        let Some(record) = self.kernel.mdls.get(&mdl) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if record.locked {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        self.kernel.mdls.remove(&mdl);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn mm_get_mdl_byte_count(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let mdl = guest_arg(state, memory, 0)?;
        let Some(record) = self.kernel.mdls.get(&mdl) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        state.set(Register::Rax, record.byte_count);
        Ok(())
    }

    pub(crate) fn ke_query_interrupt_time(&self, state: &mut CpuState) {
        state.set(Register::Rax, self.executive.interrupt_time());
    }

    pub(crate) fn etw_register(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider_pointer = guest_arg(state, memory, 0)?;
        let _enable_callback = guest_arg(state, memory, 1)?;
        let _callback_context = guest_arg(state, memory, 2)?;
        let handle_out = guest_arg(state, memory, 3)?;
        if provider_pointer == 0 || handle_out == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let mut guid = [0_u8; 16];
        if memory.read_into(provider_pointer, &mut guid).is_err() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let provider =
            match self
                .diagnostics
                .register_provider(ProviderGuid(guid), &self.driver_name, |_| {})
            {
                Ok(provider) => provider,
                Err(status) => {
                    set_status(state, status);
                    return Ok(());
                }
            };
        write_guest_pointer(memory, handle_out, provider.0, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn etw_unregister(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let status = self
            .diagnostics
            .unregister_provider(ProviderId(handle))
            .err()
            .unwrap_or(STATUS_SUCCESS);
        set_status(state, status);
        Ok(())
    }

    pub(crate) fn etw_write(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let descriptor_pointer = guest_arg(state, memory, 1)?;
        let data_pointer = guest_arg(state, memory, 2)?;
        let length = guest_arg(state, memory, 3)? as usize;
        if descriptor_pointer == 0 || length > 64 * 1024 || (length != 0 && data_pointer == 0) {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let level = match memory
            .read_u8(descriptor_pointer + 4)
            .map_err(|_| STATUS_INVALID_PARAMETER)
            .and_then(EventLevel::from_raw)
        {
            Ok(level) => level,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let keyword = memory
            .read_u64(descriptor_pointer + 8)
            .map_err(|_| STATUS_INVALID_PARAMETER)
            .unwrap_or(0);
        let provider = match self.diagnostics.provider_guid(ProviderId(handle)) {
            Ok(provider) => provider,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let mut payload = vec![0_u8; length];
        if length != 0 && memory.read_into(data_pointer, &mut payload).is_err() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let status = self
            .diagnostics
            .write_event(
                provider,
                EventDescriptor {
                    id: 0,
                    level,
                    keyword,
                },
                payload,
            )
            .err()
            .unwrap_or(STATUS_SUCCESS);
        set_status(state, status);
        Ok(())
    }

    pub(crate) fn nt_alpc_connect_port(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_out = guest_arg(state, memory, 0)?;
        let port_name_pointer = guest_arg(state, memory, 1)?;
        if handle_out == 0 || port_name_pointer == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let name = match read_unicode_string(memory, port_name_pointer, self.arch) {
            Ok((name, _, _)) => name,
            Err(_) => {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
        };
        let port = match self.alpc.connect(&name) {
            Ok(port) => port,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let handle = self.next_alpc_handle;
        self.next_alpc_handle += 1;
        self.alpc_handles.insert(handle, port);
        write_guest_pointer(memory, handle_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn ex_initialize_lookaside(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
        pool_type: u32,
    ) -> AppResult<()> {
        let lookaside = guest_arg(state, memory, 0)?;
        let allocate = guest_arg(state, memory, 1)?;
        let free = guest_arg(state, memory, 2)?;
        let _flags = guest_arg(state, memory, 3)? as u32;
        let size = guest_arg(state, memory, 4)? as usize;
        let tag_bits = guest_arg(state, memory, 5)? as u32;
        let depth = guest_arg(state, memory, 6)? as usize;
        if pool_type == PAGED_POOL && self.kernel.irql >= DISPATCH_LEVEL {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        if lookaside == 0 || size == 0 || size > 0x100_0000 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if allocate != 0 || free != 0 {
            // Custom allocate/free callbacks are guest functions the island
            // cannot safely re-enter from the pool path; fail closed.
            set_status(state, STATUS_NOT_SUPPORTED);
            return Ok(());
        }
        let tag = PoolTag::new(&tag_bits.to_le_bytes());
        let depth = depth.clamp(1, 256);
        self.kernel.lookasides.insert(
            lookaside,
            IslandLookaside {
                list: crate::casak::exec::LookasideList::new(
                    tag,
                    depth,
                    size.saturating_mul(depth),
                ),
                entry_size: size,
                guest_by_ptr: BTreeMap::new(),
                block_by_guest: BTreeMap::new(),
            },
        );
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn ex_allocate_from_lookaside(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        pool_type: u32,
    ) -> AppResult<()> {
        let lookaside = guest_arg(state, memory, 0)?;
        if pool_type == PAGED_POOL && self.kernel.irql >= DISPATCH_LEVEL {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let Some(list) = self.kernel.lookasides.get_mut(&lookaside) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let entry_size = list.entry_size;
        let block = match list.list.allocate(entry_size) {
            Ok(block) => block,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let guest = if let Some(guest) = list.guest_by_ptr.get(&block.ptr) {
            *guest
        } else {
            match self.arena.alloc(memory, entry_size, 8) {
                Ok(guest) => {
                    list.guest_by_ptr.insert(block.ptr, guest);
                    guest
                }
                Err(_) => {
                    let _ = list.list.free(block);
                    state.set(Register::Rax, 0);
                    return Ok(());
                }
            }
        };
        list.block_by_guest.insert(guest, block);
        state.set(Register::Rax, guest);
        Ok(())
    }

    pub(crate) fn ex_free_to_lookaside(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
        pool_type: u32,
    ) -> AppResult<()> {
        let lookaside = guest_arg(state, memory, 0)?;
        let entry = guest_arg(state, memory, 1)?;
        if pool_type == PAGED_POOL && self.kernel.irql >= DISPATCH_LEVEL {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        let Some(list) = self.kernel.lookasides.get_mut(&lookaside) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let Some(block) = list.block_by_guest.remove(&entry) else {
            set_status(state, STATUS_INVALID_ADDRESS);
            return Ok(());
        };
        match list.list.free(block) {
            Ok(()) => set_status(state, STATUS_SUCCESS),
            Err(status) => set_status(state, status),
        }
        Ok(())
    }
}

/// Write the guest-visible MDL header fields a driver reads directly.
pub(crate) fn write_mdl_header(
    memory: &mut MemoryImage,
    arch: GuestArch,
    mdl: u64,
    virtual_address: u64,
    byte_count: u64,
    locked: bool,
) -> AppResult<()> {
    let (size_offset, flags_offset, start_va_offset, count_offset, byte_offset_offset) = match arch
    {
        GuestArch::X86 => (0x04, 0x06, 0x10, 0x14, 0x18),
        GuestArch::X64 => (0x08, 0x0A, 0x20, 0x28, 0x2C),
    };
    const MDL_PAGES_LOCKED: u16 = 0x0002;
    let page_base = virtual_address & !0xFFF;
    memory.write_u16(mdl + size_offset, 0x20);
    memory.write_u16(
        mdl + flags_offset,
        if locked { MDL_PAGES_LOCKED } else { 0 },
    );
    write_guest_pointer(memory, mdl + start_va_offset, page_base, arch)?;
    memory.write_u32(mdl + count_offset, byte_count as u32);
    memory.write_u32(mdl + byte_offset_offset, (virtual_address & 0xFFF) as u32);
    Ok(())
}

/// Probe a guest range for read (and optionally write) access.  The runtime's
/// VM page protections are authoritative when the range is registered there;
/// the `MemoryImage` mapping is the fallback for raw test arenas.
pub(crate) fn probe_guest_range(
    runtime: &PeHostRuntime,
    memory: &MemoryImage,
    address: u64,
    length: u64,
    write: bool,
) -> bool {
    if address == 0 || length == 0 {
        return false;
    }
    let mut probe = vec![0_u8; length as usize];
    if memory.read_into(address, &mut probe).is_err() {
        return false;
    }
    if !write {
        return true;
    }
    let end = address.saturating_add(length - 1);
    let mut page = address & !0xFFF;
    while page <= end {
        if runtime.win32.address_space().is_mapped(page)
            && runtime
                .win32
                .address_space()
                .check_access(page, true, false)
                .is_err()
        {
            return false;
        }
        page = match page.checked_add(0x1000) {
            Some(next) => next,
            // canonical guest addresses cannot make page + 0x1000 overflow u64
            None => break, // coverage: unreachable
        };
    }
    true
}
