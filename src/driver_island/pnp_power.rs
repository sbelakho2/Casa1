//! PnP and power state machine.

use super::*;

/// One guest callback in a PnP/power transition.  `required` callbacks fail
/// the transition when they return a negative NTSTATUS; informational ones
/// (void framework callbacks) only record their execution.
#[derive(Debug, Clone)]
pub(crate) struct PnpStep {
    pub(crate) entry: u64,
    pub(crate) args: Vec<u64>,
    pub(crate) label: &'static str,
    pub(crate) required: bool,
    pub(crate) rollback: Vec<GuestCallback>,
}

/// Device state applied when every step of a PnP/power transition succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PnpFinalState {
    Started,
    Stopped,
    Removed,
    Surprised,
    PowerD0,
    PowerD3,
}

impl DriverIsland {
    /// Deliver one real `IRP_MJ_PNP` IRP with `minor` to the device's PnP
    /// handler (the framework dispatch for a KMDF device).
    #[allow(dead_code)]
    pub(crate) fn dispatch_pnp(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        minor: u8,
    ) -> AppResult<(i32, usize)> {
        self.dispatch_irp_inner(
            runtime,
            memory,
            device_guest,
            IrpMajorFunction::Pnp,
            minor,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }

    /// Deliver one real `IRP_MJ_POWER`/`IRP_MN_SET_POWER` IRP that asks the
    /// device to enter `power_state` (`WdfPowerDeviceD0`/`WdfPowerDeviceD3`).
    #[allow(dead_code)]
    pub(crate) fn set_device_power(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        power_state: u32,
    ) -> AppResult<(i32, usize)> {
        self.dispatch_irp_inner(
            runtime,
            memory,
            device_guest,
            IrpMajorFunction::Power,
            IRP_MN_SET_POWER,
            Some(power_state),
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

impl IslandState {
    /// Parse `WDF_PNPPOWER_EVENT_CALLBACKS` for a device-init handle.  The
    /// `Size` member bounds which callbacks are honored, exactly like the
    /// forward-compatible KMDF structure contract.
    pub(crate) fn wdf_device_init_set_pnp_power_callbacks(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let callbacks = guest_arg(state, memory, 1)?;
        if !self.kmdf.device_inits.contains_key(&init)
            || callbacks == 0
            || crate::host_thunks::validate_guest_pointer(memory, callbacks, 4).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(callbacks)? as u64;
        if size < 4 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let pointer = self.arch.pointer_bytes() as u64;
        let offsets: [u64; 9] = match self.arch {
            GuestArch::X64 => [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x48, 0x50],
            GuestArch::X86 => [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x24, 0x28],
        };
        let mut parsed = KmdfPnpPowerCallbacks::default();
        let read = |offset: u64| -> AppResult<u64> {
            if size >= offset + pointer {
                read_guest_pointer(memory, callbacks + offset, self.arch)
            } else {
                Ok(0)
            }
        };
        parsed.prepare_hardware = read(offsets[0])?;
        parsed.release_hardware = read(offsets[1])?;
        parsed.d0_entry = read(offsets[2])?;
        parsed.d0_exit = read(offsets[3])?;
        parsed.self_managed_io_init = read(offsets[4])?;
        parsed.self_managed_io_suspend = read(offsets[5])?;
        parsed.self_managed_io_restart = read(offsets[6])?;
        parsed.self_managed_io_fini = read(offsets[7])?;
        parsed.surprise_removal = read(offsets[8])?;
        let init = self
            .kmdf
            .device_inits
            .get_mut(&init)
            .expect("device init was validated above");
        init.pnp_power = parsed;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_device_stop_idle(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let device = guest_arg(state, memory, 0)?;
        let _wait = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(device, KmdfObjectKind::Device) {
            set_status(state, status);
            return Ok(None);
        }
        let record = self
            .kmdf
            .devices
            .get_mut(&device)
            .expect("device was validated");
        if !record.started || record.removed || record.surprised {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        record.idle_refs = record.idle_refs.saturating_add(1);
        record.idle = false;
        record.power_state = WDF_POWER_DEVICE_D0;
        set_status(state, STATUS_SUCCESS);
        self.dispatch_next_queued(memory)
    }

    pub(crate) fn wdf_device_resume_idle(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let device = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(device, KmdfObjectKind::Device) {
            set_status(state, status);
            return Ok(None);
        }
        let _became_idle = {
            let record = self
                .kmdf
                .devices
                .get_mut(&device)
                .expect("device was validated");
            if !record.started || record.removed || record.surprised {
                set_status(state, STATUS_INVALID_DEVICE_STATE);
                return Ok(None);
            }
            if record.idle_refs == 0 {
                set_status(state, STATUS_INVALID_DEVICE_STATE);
                return Ok(None);
            }
            record.idle_refs -= 1;
            if record.idle_refs == 0 {
                record.idle = true;
                record.power_state = WDF_POWER_DEVICE_D3;
            }
            record.idle
        };
        set_status(state, STATUS_SUCCESS);
        // Entering idle parks power-managed queue dispatch until a later
        // `WdfDeviceStopIdle` returns the device to D0.
        Ok(None)
    }

    pub(crate) fn wdf_device_init_set_power_policy_ownership(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let owner = guest_arg(state, memory, 1)? != 0;
        let Some(record) = self.kmdf.device_inits.get_mut(&init) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        record.power_policy_owner = owner;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `IRP_MJ_PNP` framework dispatch.
    pub(crate) fn wdf_pnp_dispatch(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let irp_guest = guest_arg(state, memory, 0)?;
        let device_object = guest_arg(state, memory, 1)?;
        let Some(device) = self.kmdf.devices_by_object.get(&device_object).copied() else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let Some(minor) = self.irp_minor(memory, irp_guest) else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let (pnp, started, power_state, surprised, removed) = self
            .kmdf
            .devices
            .get(&device)
            .map(|record| {
                (
                    record.pnp_power,
                    record.started,
                    record.power_state,
                    record.surprised,
                    record.removed,
                )
            })
            .expect("a device object always maps to a live device");
        let mut steps = VecDeque::new();
        let final_state = match minor {
            IRP_MN_START_DEVICE => {
                self.kmdf.pnp_start_dispatches += 1;
                if started || surprised || removed {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                let release = GuestCallback {
                    entry: pnp.release_hardware,
                    args: vec![device],
                    label: "EvtDeviceReleaseHardware",
                };
                let d0_exit = GuestCallback {
                    entry: pnp.d0_exit,
                    args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                    label: "EvtDeviceD0Exit",
                };
                if pnp.prepare_hardware != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.prepare_hardware,
                        args: vec![device, 0, 0],
                        label: "EvtDevicePrepareHardware",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                if pnp.d0_entry != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.d0_entry,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3_FINAL)],
                        label: "EvtDeviceD0Entry",
                        required: true,
                        rollback: if release.entry != 0 {
                            vec![release.clone()]
                        } else {
                            Vec::new()
                        },
                    });
                }
                if pnp.self_managed_io_init != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_init,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoInit",
                        required: true,
                        rollback: [d0_exit, release]
                            .into_iter()
                            .filter(|callback| callback.entry != 0)
                            .collect(),
                    });
                }
                PnpFinalState::Started
            }
            IRP_MN_STOP_DEVICE => {
                self.kmdf.pnp_stop_dispatches += 1;
                if surprised || removed {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_STATE);
                }
                if !started || power_state != WDF_POWER_DEVICE_D0 {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                if pnp.self_managed_io_fini != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_fini,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoFini",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                if pnp.d0_exit != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.d0_exit,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                        label: "EvtDeviceD0Exit",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                if pnp.release_hardware != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.release_hardware,
                        args: vec![device],
                        label: "EvtDeviceReleaseHardware",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::Stopped
            }
            IRP_MN_REMOVE_DEVICE => {
                self.kmdf.pnp_remove_dispatches += 1;
                let object_guest = self
                    .kmdf
                    .devices
                    .get(&device)
                    .expect("device was resolved above")
                    .object_guest;
                if started {
                    if pnp.self_managed_io_fini != 0 {
                        steps.push_back(PnpStep {
                            entry: pnp.self_managed_io_fini,
                            args: vec![device],
                            label: "EvtDeviceSelfManagedIoFini",
                            required: false,
                            rollback: Vec::new(),
                        });
                    }
                    if pnp.d0_exit != 0 {
                        steps.push_back(PnpStep {
                            entry: pnp.d0_exit,
                            args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                            label: "EvtDeviceD0Exit",
                            required: false,
                            rollback: Vec::new(),
                        });
                    }
                    if pnp.release_hardware != 0 {
                        steps.push_back(PnpStep {
                            entry: pnp.release_hardware,
                            args: vec![device],
                            label: "EvtDeviceReleaseHardware",
                            required: false,
                            rollback: Vec::new(),
                        });
                    }
                }
                if let Some(record) = self.kmdf.devices.get_mut(&device) {
                    record.removed = true;
                }
                self.removed_device_objects.insert(object_guest);
                let mut callbacks = Vec::new();
                self.collect_delete_callbacks(device, &mut callbacks);
                for callback in callbacks {
                    steps.push_back(PnpStep {
                        entry: callback.entry,
                        args: callback.args,
                        label: callback.label,
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::Removed
            }
            IRP_MN_SURPRISE_REMOVAL => {
                self.kmdf.surprise_removals += 1;
                if !started || surprised || removed {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_STATE);
                }
                if pnp.surprise_removal != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.surprise_removal,
                        args: vec![device],
                        label: "EvtDeviceSurpriseRemoval",
                        required: true,
                        rollback: Vec::new(),
                    });
                }
                // The device is physically gone: every queue owned by it stops
                // dispatching, and queued/in-flight requests are canceled.
                self.quiesce_device_queues(memory, device, &mut steps)?;
                if pnp.release_hardware != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.release_hardware,
                        args: vec![device],
                        label: "EvtDeviceReleaseHardware",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::Surprised
            }
            _ => return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST),
        };
        self.begin_pnp_sequence(state, memory, device, irp_guest, steps, final_state)
    }

    /// Cancel every queued and in-flight request on a device's queues.  A
    /// registered cancel callback observes the request; otherwise the request
    /// completes with `STATUS_CANCELLED` exactly once.
    pub(crate) fn quiesce_device_queues(
        &mut self,
        memory: &mut MemoryImage,
        device: u64,
        steps: &mut VecDeque<PnpStep>,
    ) -> AppResult<()> {
        let queues = self
            .kmdf
            .queues
            .iter()
            .filter_map(|(handle, queue)| (queue.device == device).then_some(*handle))
            .collect::<Vec<_>>();
        for queue_handle in queues {
            let queue = self
                .kmdf
                .queues
                .get_mut(&queue_handle)
                .expect("queue handle came from the queue map");
            queue.stopped = true;
            queue.draining = false;
            let canceled_on_queue = queue.callbacks.canceled_on_queue;
            let queued = queue.queued.drain(..).collect::<Vec<_>>();
            let in_flight = std::mem::take(&mut queue.in_flight);
            for request in queued.into_iter().chain(in_flight) {
                self.kmdf.cancel_dispatches += 1;
                let (cancel_callback, outer_irp, completed) = {
                    let Some(request_state) = self.kmdf.requests.get_mut(&request) else {
                        continue;
                    };
                    request_state.queue = None;
                    request_state.canceled = true;
                    (
                        request_state.cancel_callback,
                        request_state.outer_irp_guest,
                        request_state.completed,
                    )
                };
                if completed {
                    continue;
                }
                if canceled_on_queue != 0 {
                    steps.push_back(PnpStep {
                        entry: canceled_on_queue,
                        args: vec![queue_handle, request],
                        label: "EvtIoCanceledOnQueue",
                        required: false,
                        rollback: Vec::new(),
                    });
                } else if cancel_callback != 0 {
                    steps.push_back(PnpStep {
                        entry: cancel_callback,
                        args: vec![request],
                        label: "EvtRequestCancel",
                        required: false,
                        rollback: Vec::new(),
                    });
                } else {
                    self.force_cancel_request(request);
                    self.write_irp_status(memory, outer_irp, STATUS_CANCELLED, 0)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn irp_minor(&self, memory: &MemoryImage, irp_guest: u64) -> Option<u8> {
        let stack = self.irp_stack_location(memory, irp_guest)?;
        memory.read_u8(stack + 1).ok()
    }

    pub(crate) fn irp_stack_location(&self, memory: &MemoryImage, irp_guest: u64) -> Option<u64> {
        if irp_guest == 0 {
            return None;
        }
        let offset = match self.arch {
            GuestArch::X64 => 0x98,
            GuestArch::X86 => 0x4C,
        };
        read_guest_pointer(memory, irp_guest + offset, self.arch)
            .ok()
            .filter(|stack| *stack != 0)
    }

    /// `IRP_MJ_POWER` framework dispatch for `IRP_MN_SET_POWER`.
    pub(crate) fn wdf_power_dispatch(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let irp_guest = guest_arg(state, memory, 0)?;
        let device_object = guest_arg(state, memory, 1)?;
        let Some(device) = self.kmdf.devices_by_object.get(&device_object).copied() else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let Some(stack) = self.irp_stack_location(memory, irp_guest) else {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        };
        let minor = memory.read_u8(stack + 1)?;
        let (type_offset, state_offset) = match self.arch {
            GuestArch::X64 => (0x08u64, 0x10u64),
            GuestArch::X86 => (0x04u64, 0x08u64),
        };
        let power_type = memory.read_u32(stack + type_offset)?;
        let target = memory.read_u32(stack + state_offset)?;
        if minor != IRP_MN_SET_POWER || power_type != POWER_STATE_TYPE_DEVICE {
            return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
        }
        let (pnp, started, power_state, surprised, removed) = self
            .kmdf
            .devices
            .get(&device)
            .map(|record| {
                (
                    record.pnp_power,
                    record.started,
                    record.power_state,
                    record.surprised,
                    record.removed,
                )
            })
            .expect("a device object always maps to a live device");
        let mut steps = VecDeque::new();
        let final_state = match target {
            WDF_POWER_DEVICE_D0 => {
                self.kmdf.power_d0_dispatches += 1;
                if surprised || removed {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_STATE);
                }
                if !started || power_state == WDF_POWER_DEVICE_D0 {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                if pnp.d0_entry != 0 {
                    let exit_rollback = (pnp.d0_exit != 0).then(|| GuestCallback {
                        entry: pnp.d0_exit,
                        args: vec![device, u64::from(power_state)],
                        label: "EvtDeviceD0Exit",
                    });
                    steps.push_back(PnpStep {
                        entry: pnp.d0_entry,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                        label: "EvtDeviceD0Entry",
                        required: true,
                        rollback: exit_rollback.into_iter().collect(),
                    });
                }
                if pnp.self_managed_io_restart != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_restart,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoRestart",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                PnpFinalState::PowerD0
            }
            WDF_POWER_DEVICE_D3 => {
                self.kmdf.power_d3_dispatches += 1;
                if surprised || removed {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_STATE);
                }
                if !started || power_state != WDF_POWER_DEVICE_D0 {
                    return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST);
                }
                if pnp.self_managed_io_suspend != 0 {
                    steps.push_back(PnpStep {
                        entry: pnp.self_managed_io_suspend,
                        args: vec![device],
                        label: "EvtDeviceSelfManagedIoSuspend",
                        required: false,
                        rollback: Vec::new(),
                    });
                }
                if pnp.d0_exit != 0 {
                    let entry_rollback = (pnp.d0_entry != 0).then(|| GuestCallback {
                        entry: pnp.d0_entry,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D0)],
                        label: "EvtDeviceD0Entry",
                    });
                    steps.push_back(PnpStep {
                        entry: pnp.d0_exit,
                        args: vec![device, u64::from(WDF_POWER_DEVICE_D3)],
                        label: "EvtDeviceD0Exit",
                        required: true,
                        rollback: entry_rollback.into_iter().collect(),
                    });
                }
                PnpFinalState::PowerD3
            }
            _ => return self.fail_pnp(state, memory, irp_guest, STATUS_INVALID_DEVICE_REQUEST),
        };
        self.begin_pnp_sequence(state, memory, device, irp_guest, steps, final_state)
    }

    pub(crate) fn fail_pnp(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        irp_guest: u64,
        status: i32,
    ) -> AppResult<Option<PendingGuestCall>> {
        self.write_irp_status(memory, irp_guest, status, 0)?;
        set_status(state, status);
        Ok(None)
    }

    pub(crate) fn begin_pnp_sequence(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        device: u64,
        irp_guest: u64,
        mut steps: VecDeque<PnpStep>,
        final_state: PnpFinalState,
    ) -> AppResult<Option<PendingGuestCall>> {
        if let Some(first) = steps.pop_front() {
            let rollback = VecDeque::from(first.rollback.clone());
            let current_required = first.required;
            return Ok(Some(PendingGuestCall {
                entry: first.entry,
                args: first.args,
                label: first.label,
                purpose: PendingPurpose::PnpSequence {
                    device,
                    irp_guest,
                    current_required,
                    remaining: steps,
                    rollback,
                    failure_status: None,
                    final_state,
                },
            }));
        }
        self.apply_pnp_final_state(device, final_state);
        self.purge_deleted_objects();
        self.write_irp_status(memory, irp_guest, STATUS_SUCCESS, 0)?;
        set_status(state, STATUS_SUCCESS);
        Ok(None)
    }

    pub(crate) fn apply_pnp_final_state(&mut self, device: u64, final_state: PnpFinalState) {
        if final_state == PnpFinalState::Removed {
            return;
        }
        let record = self
            .kmdf
            .devices
            .get_mut(&device)
            .expect("a PnP final state is applied only while the device exists");
        if final_state == PnpFinalState::Started {
            record.started = true;
            record.power_state = WDF_POWER_DEVICE_D0;
        } else if final_state == PnpFinalState::Stopped {
            record.started = false;
            record.power_state = WDF_POWER_DEVICE_D3;
        } else if final_state == PnpFinalState::Surprised {
            record.started = false;
            record.surprised = true;
            record.idle = true;
            record.power_state = WDF_POWER_DEVICE_D3;
        } else if final_state == PnpFinalState::PowerD0 {
            record.power_state = WDF_POWER_DEVICE_D0;
        } else if final_state == PnpFinalState::PowerD3 {
            record.power_state = WDF_POWER_DEVICE_D3;
        }
    }
}
