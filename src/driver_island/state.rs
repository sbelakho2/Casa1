//! Core island-state plumbing (DbgPrint, pending completion, unicode string).

use super::*;

impl IslandState {
    /// Add another `DbgPrint` entry to the runtime trace and island log.
    pub(crate) fn record_debug_print(&mut self, runtime: &mut PeHostRuntime, message: &str) {
        self.debug_log.push(message.to_string());
        let index = runtime.next_trace_index;
        runtime.trace_events.push(TraceEvent {
            event_index: index,
            category: "driver".to_string(),
            call_id: "DbgPrint".to_string(),
            parameters: BTreeMap::from([
                ("driver".to_string(), json!(self.driver_name)),
                ("message".to_string(), json!(message)),
            ]),
            return_value: json!(message.len()),
            get_last_error: None,
            side_effect_hashes: Vec::new(),
        });
        runtime.next_trace_index += 1;
    }

    pub(crate) fn finish_pending(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        purpose: PendingPurpose,
        callback_status: i32,
    ) -> AppResult<Option<PendingGuestCall>> {
        match purpose {
            PendingPurpose::DriverDeviceAdd => {
                set_status(state, callback_status);
            }
            PendingPurpose::IoTargetSend { pending } => {
                let (status, _) = self.finish_ioctl_send(memory, *pending)?;
                set_status(state, status);
            }
            PendingPurpose::IoDispatch { request } => {
                let (completed, status) = self
                    .kmdf
                    .requests
                    .get(&request)
                    .map(|request| (request.completed, request.status))
                    .unwrap_or((false, STATUS_INVALID_DEVICE_REQUEST));
                let status = if completed {
                    status
                } else {
                    self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
                    STATUS_PENDING
                };
                self.kmdf.current_request = 0;
                set_status(state, status);
                return self.dispatch_next_queued(memory);
            }
            PendingPurpose::FileDispatch { request } => {
                self.complete_kmdf_request(memory, request, STATUS_SUCCESS, 0)?;
                self.kmdf.current_request = 0;
                set_status(state, STATUS_SUCCESS);
                return self.dispatch_next_queued(memory);
            }
            PendingPurpose::PnpSequence {
                device,
                irp_guest,
                current_required,
                mut remaining,
                mut rollback,
                failure_status,
                final_state,
            } => {
                let mut failure = failure_status;
                if failure.is_none() && current_required && callback_status < 0 {
                    failure = Some(callback_status);
                }
                if let Some(status) = failure {
                    if let Some(call) = rollback.pop_front() {
                        return Ok(Some(PendingGuestCall {
                            entry: call.entry,
                            args: call.args,
                            label: call.label,
                            purpose: PendingPurpose::PnpSequence {
                                device,
                                irp_guest,
                                current_required: false,
                                remaining: VecDeque::new(),
                                rollback,
                                failure_status: Some(status),
                                final_state,
                            },
                        }));
                    }
                    self.purge_deleted_objects();
                    self.write_irp_status(memory, irp_guest, status, 0)?;
                    set_status(state, status);
                    return Ok(None);
                }
                if let Some(next) = remaining.pop_front() {
                    let rollback = VecDeque::from(next.rollback.clone());
                    let current_required = next.required;
                    return Ok(Some(PendingGuestCall {
                        entry: next.entry,
                        args: next.args,
                        label: next.label,
                        purpose: PendingPurpose::PnpSequence {
                            device,
                            irp_guest,
                            current_required,
                            remaining,
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
            }
            PendingPurpose::Callbacks {
                mut remaining,
                dispatch_next,
            } => {
                if !remaining.is_empty() {
                    let next = remaining.remove(0);
                    return Ok(Some(PendingGuestCall {
                        entry: next.entry,
                        args: next.args,
                        label: next.label,
                        purpose: PendingPurpose::Callbacks {
                            remaining,
                            dispatch_next,
                        },
                    }));
                }
                self.purge_deleted_objects();
                set_status(state, STATUS_SUCCESS);
                if dispatch_next {
                    return self.dispatch_next_queued(memory);
                }
            }
            PendingPurpose::WorkItem { handle } => {
                if let Some(item) = self.kmdf.work_items.get_mut(&handle) {
                    item.queued = false;
                    item.completed += 1;
                }
                self.kmdf.work_item_runs += 1;
                set_status(state, STATUS_SUCCESS);
            }
            PendingPurpose::InterruptSync => {
                if self.kernel.irql > 0 {
                    self.kernel.irql = 0;
                }
                // The synchronize callback ran; the framework call returns
                // TRUE.
                state.set(Register::Rax, 1);
            }
            PendingPurpose::ChildListScan { list, collection } => {
                let new_descriptions = self
                    .kmdf
                    .collections
                    .get(&collection)
                    .map(|collection| collection.items.clone())
                    .unwrap_or_default();
                // The temporary scan collection is a framework object with
                // no guest callbacks; detach it from the list and drop it.
                if let Some(object) = self.kmdf.objects.get_mut(&collection) {
                    object.deleted = true;
                    if let Some(parent) = object.parent {
                        if let Some(parent_object) = self.kmdf.objects.get_mut(&parent) {
                            parent_object.children.remove(&collection);
                        }
                    }
                }
                self.remove_object_domain(collection);
                let (arrived, removed) = match self.kmdf.child_lists.get_mut(&list) {
                    Some(record) => {
                        let previous = record.descriptions.clone();
                        let arrived = new_descriptions
                            .iter()
                            .filter(|description| !previous.contains(description))
                            .copied()
                            .collect::<Vec<_>>();
                        let removed = previous
                            .iter()
                            .filter(|description| !new_descriptions.contains(description))
                            .copied()
                            .collect::<Vec<_>>();
                        record.descriptions = new_descriptions;
                        record.arrivals += arrived.len() as u64;
                        record.removals += removed.len() as u64;
                        (arrived, removed)
                    }
                    None => (Vec::new(), Vec::new()),
                };
                self.kmdf.child_removals += removed.len() as u64;
                // PnP arrival/removal: a removed description's child PDO
                // goes through the same cancel-and-remove path as an
                // explicit `IRP_MN_REMOVE_DEVICE`; arrivals materialize as
                // child PDOs parented to the child list's FDO.
                let mut callbacks = Vec::new();
                for description in removed {
                    if let Some(device) = self.kmdf.child_devices.remove(&description) {
                        let queue_handles = self
                            .kmdf
                            .queues
                            .iter()
                            .filter_map(|(handle, queue)| {
                                (queue.device == device).then_some(*handle)
                            })
                            .collect::<Vec<_>>();
                        for queue_handle in queue_handles {
                            let queued = self
                                .kmdf
                                .queues
                                .get_mut(&queue_handle)
                                .map(|queue| {
                                    queue.stopped = true;
                                    queue.queued.drain(..).collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            for request in queued {
                                self.force_cancel_request(request);
                            }
                        }
                        if let Some(record) = self.kmdf.devices.get_mut(&device) {
                            record.removed = true;
                        }
                        if let Some(record) = self.kmdf.devices.get(&device) {
                            self.removed_device_objects.insert(record.object_guest);
                        }
                        self.collect_delete_callbacks(device, &mut callbacks);
                    }
                }
                for description in arrived {
                    // A bus child arrives as a child PDO whose instance ID
                    // is derived from the identification description.  A
                    // failed allocation aborts the scan with that status.
                    let device = match self.create_kmdf_child_pdo(memory, list, description) {
                        Ok(Ok(device)) => device,
                        Ok(Err(status)) => {
                            set_status(state, status);
                            return Ok(None);
                        }
                        Err(error) => return Err(error), // coverage: unreachable — the arena-backed child PDO allocation only fails for a driver-less island, which cannot host a child list.
                    };
                    self.kmdf.child_devices.insert(description, device);
                    self.kmdf.child_arrivals += 1;
                }
                // A live child list implies a loaded driver object.
                self.rebuild_device_chain(memory)?;
                self.purge_deleted_objects();
                set_status(state, STATUS_SUCCESS);
                return Ok(Self::callbacks_pending(callbacks, false));
            }
            PendingPurpose::Dpcs {
                mut remaining,
                restore_irql,
                final_result,
            } => {
                if let Some(next) = remaining.pop_front() {
                    return Ok(Some(PendingGuestCall {
                        entry: next.entry,
                        args: next.args,
                        label: next.label,
                        purpose: PendingPurpose::Dpcs {
                            remaining,
                            restore_irql,
                            final_result,
                        },
                    }));
                }
                self.kernel.irql = restore_irql;
                // `restore_irql` is below DISPATCH_LEVEL for every batch the
                // island builds, so newly queued DPCs from the callback are
                // immediately eligible.
                let mut next = self.take_ready_dpcs();
                if !next.is_empty() {
                    self.kernel.irql = DISPATCH_LEVEL;
                    let first = next.pop_front().expect("non-empty queue");
                    return Ok(Some(PendingGuestCall {
                        entry: first.entry,
                        args: first.args,
                        label: first.label,
                        purpose: PendingPurpose::Dpcs {
                            remaining: next,
                            restore_irql,
                            final_result,
                        },
                    }));
                }
                state.set(Register::Rax, final_result);
            }
        }
        Ok(None)
    }

    pub(crate) fn dbg_print(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let format = guest_arg(state, memory, 0)?;
        let format = read_ansi_z(memory, format, 4096)?;
        let mut args = Vec::new();
        for index in 1..8 {
            args.push(guest_arg(state, memory, index).unwrap_or(0));
        }
        let message = format_dbg_print(&format, &args, memory, self.arch);
        self.record_debug_print(runtime, &message);
        state.set(Register::Rax, message.len() as u64);
        Ok(())
    }

    pub(crate) fn rtl_init_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let destination = guest_arg(state, memory, 0)?;
        let source = guest_arg(state, memory, 1)?;
        if destination != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                destination,
                unicode_string_size(self.arch),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if destination != 0 {
            let text = read_utf16_z(memory, source, 0x4000)?;
            let length = (text.encode_utf16().count() * 2) as u16;
            write_unicode_string_header(
                memory,
                destination,
                length,
                length.saturating_add(2),
                source,
                self.arch,
            )?; // coverage: unreachable — write_unicode_string_header only performs infallible MemoryImage writes
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}
