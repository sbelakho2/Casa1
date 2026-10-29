//! KMDF object model.

use super::*;

impl IslandState {
    /// `WdfInterruptCreate`: connects a line-based virtual interrupt whose
    /// ISR is the configured `EvtInterruptIsr`.
    pub(crate) fn wdf_interrupt_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let config = guest_arg(state, memory, 2)?;
        let interrupt_out = guest_arg(state, memory, 3)?;
        if !self.kmdf.devices.contains_key(&device)
            || interrupt_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                interrupt_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let mut parsed = KmdfInterruptConfig::default();
        if config != 0 {
            let pointer = self.arch.pointer_bytes() as u64;
            let (isr_offset, dpc_offset) = match self.arch {
                GuestArch::X64 => (8, 16),
                GuestArch::X86 => (4, 8),
            };
            let size = match crate::host_thunks::validate_guest_pointer(memory, config, 4) {
                Ok(()) => u64::from(memory.read_u32(config)?),
                Err(_) => {
                    set_status(state, STATUS_INVALID_PARAMETER);
                    return Ok(());
                }
            };
            if size >= isr_offset + pointer {
                parsed.evt_isr = read_guest_pointer(memory, config + isr_offset, self.arch)?;
            }
            if size >= dpc_offset + pointer {
                parsed.evt_dpc = read_guest_pointer(memory, config + dpc_offset, self.arch)?;
            }
        }
        if parsed.evt_isr == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Interrupt, attributes)?;
        self.attach_kmdf_parent(handle, device);
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        // Connect through the virtual controller with a private vector so
        // `trigger_virtual_interrupt` delivers the guest ISR.  Vectors are
        // allocated from 0x30 upward; exhaustion surfaces as the
        // controller's `STATUS_INVALID_PARAMETER`.
        let vector = 0x30 + self.kmdf.next_interrupt_vector;
        self.kmdf.next_interrupt_vector += 1;
        let request = ConnectRequest {
            guest_object: handle,
            service_routine: parsed.evt_isr,
            service_context: context_guest,
            spin_lock: 0,
            vector,
            irql: 3,
            synchronize_irql: 3,
            mode: 0,
            share_vector: false,
            affinity: 1,
        };
        if let Err(status) = self.interrupts.connect(request) {
            self.kmdf.objects.remove(&handle);
            set_status(state, status);
            return Ok(());
        }
        self.kmdf.interrupts.insert(
            handle,
            KmdfInterrupt {
                config: parsed,
                device,
                controller: u64::from(vector),
                context_guest,
                connected: true,
                disabled: 0,
                dpc_queued: 0,
            },
        );
        write_guest_pointer(memory, interrupt_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfInterruptQueueDpcForIsr`: queues the interrupt's
    /// `EvtInterruptDpc` at `DISPATCH_LEVEL`.
    pub(crate) fn wdf_interrupt_queue_dpc(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let interrupt = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(interrupt, KmdfObjectKind::Interrupt) {
            set_status(state, status);
            return Ok(None);
        }
        let (dpc, context_guest, disabled) = {
            let record = self
                .kmdf
                .interrupts
                .get(&interrupt)
                .expect("interrupt was validated");
            (record.config.evt_dpc, record.context_guest, record.disabled)
        };
        if dpc == 0 {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if disabled > 0 {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        if let Some(record) = self.kmdf.interrupts.get_mut(&interrupt) {
            record.dpc_queued += 1;
        }
        self.kmdf.interrupt_dpcs += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(Some(PendingGuestCall {
            entry: dpc,
            args: vec![interrupt, context_guest],
            label: "EvtInterruptDpc",
            purpose: PendingPurpose::Callbacks {
                remaining: Vec::new(),
                dispatch_next: false,
            },
        }))
    }

    /// `WdfInterruptAcquireLock`: raises IRQL to the interrupt's sync level;
    /// a recursive acquire is a driver bug (the real framework deadlocks),
    /// so the island fails closed with `STATUS_INVALID_DEVICE_STATE`.
    pub(crate) fn wdf_interrupt_acquire_lock(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let interrupt = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(interrupt, KmdfObjectKind::Interrupt) {
            set_status(state, status);
            return Ok(());
        }
        let held = self
            .kmdf
            .interrupt_locks
            .iter()
            .any(|(handle, held)| *handle == interrupt && *held);
        if held {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        self.kmdf.interrupt_locks.insert(interrupt, true);
        self.kernel.irql = self.kernel.irql.max(3);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfInterruptReleaseLock`.
    pub(crate) fn wdf_interrupt_release_lock(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let interrupt = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(interrupt, KmdfObjectKind::Interrupt) {
            set_status(state, status);
            return Ok(());
        }
        if self.kmdf.interrupt_locks.remove(&interrupt).is_none() {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        self.kernel.irql = 0;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfInterruptDisable`/`WdfInterruptEnable`: nests a disable counter;
    /// enabling an interrupt that is not disabled is a driver bug (the real
    /// framework asserts), so the island fails closed with
    /// `STATUS_INVALID_DEVICE_STATE`.
    pub(crate) fn wdf_interrupt_set_enabled(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
        enable: bool,
    ) -> AppResult<()> {
        let interrupt = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(interrupt, KmdfObjectKind::Interrupt) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .interrupts
            .get_mut(&interrupt)
            .expect("interrupt was validated");
        if enable {
            if record.disabled == 0 {
                set_status(state, STATUS_INVALID_DEVICE_STATE);
                return Ok(());
            }
            record.disabled -= 1;
        } else {
            record.disabled += 1;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfInterruptSynchronize`: runs the callback with the interrupt
    /// locked at its synchronization IRQL.  A disabled interrupt does not
    /// run the callback and the call returns FALSE (Rax=0).
    pub(crate) fn wdf_interrupt_synchronize(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let interrupt = guest_arg(state, memory, 0)?;
        let callback = guest_arg(state, memory, 1)?;
        let context = guest_arg(state, memory, 2)?;
        if let Err(status) = self.kmdf_expect_kind(interrupt, KmdfObjectKind::Interrupt) {
            set_status(state, status);
            return Ok(None);
        }
        if callback == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let record = self
            .kmdf
            .interrupts
            .get(&interrupt)
            .expect("interrupt was validated");
        if record.disabled > 0 {
            state.set(Register::Rax, 0);
            return Ok(None);
        }
        let context_guest = if context == 0 {
            record.context_guest
        } else {
            context
        };
        self.kernel.irql = self.kernel.irql.max(3);
        Ok(Some(PendingGuestCall {
            entry: callback,
            args: vec![interrupt, context_guest],
            label: "EvtInterruptSynchronize",
            purpose: PendingPurpose::InterruptSync,
        }))
    }
}
