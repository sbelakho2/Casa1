//! KMDF object model.

use super::*;

impl IslandState {
    pub(crate) fn wdf_io_queue_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let config = guest_arg(state, memory, 1)?;
        let attributes = guest_arg(state, memory, 2)?;
        let queue_out = guest_arg(state, memory, 3)?;
        if !self.kmdf.devices.contains_key(&device)
            || queue_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                queue_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let mut callbacks = KmdfQueueCallbacks::default();
        let mut dispatch_type = 0;
        let mut default_queue = false;
        let mut power_managed = false;
        if config != 0 {
            let minimum = match self.arch {
                GuestArch::X86 => 0x10,
                GuestArch::X64 => 0x18,
            };
            if crate::host_thunks::validate_guest_pointer(memory, config, minimum).is_err() {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            let size = memory.read_u32(config)? as u64;
            if size < 8 {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            dispatch_type = memory.read_u32(config + 4)?;
            let (allow_offset, default_offset, first_callback) = match self.arch {
                GuestArch::X64 => (0x0Cu64, 0x0Du64, 0x10u64),
                GuestArch::X86 => (0x0Cu64, 0x0Du64, 0x10u64),
            };
            if size > allow_offset {
                let _allow_zero_length = memory.read_u8(config + allow_offset)? != 0;
            }
            if size > default_offset {
                default_queue = memory.read_u8(config + default_offset)? != 0;
            }
            if size >= 0x0C {
                // `PowerManaged` is a `WDF_TRI_STATE` immediately after
                // `DispatchType`; `WdfTrue` makes the queue power-managed.
                power_managed = memory.read_u32(config + 0x08)? == 1;
            }
            let pointer = self.arch.pointer_bytes() as u64;
            let callbacks_table = [
                (0x00u64, &mut callbacks.default),
                (0x08, &mut callbacks.read),
                (0x10, &mut callbacks.write),
                (0x18, &mut callbacks.device_control),
                (0x20, &mut callbacks.internal_device_control),
                (0x28, &mut callbacks.stop),
                (0x30, &mut callbacks.resume),
                (0x38, &mut callbacks.canceled_on_queue),
            ];
            for (index, slot) in callbacks_table {
                let offset = first_callback + index;
                if size >= offset + pointer {
                    *slot = read_guest_pointer(memory, config + offset, self.arch)?;
                }
            }
        }
        if dispatch_type > 2 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Queue, attributes)?;
        self.attach_kmdf_parent(handle, device);
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.queues.insert(
            handle,
            KmdfQueue {
                device,
                callbacks,
                dispatch_type,
                default_queue,
                queued: VecDeque::new(),
                in_flight: BTreeSet::new(),
                stopped: false,
                draining: false,
                power_managed,
                context_guest,
            },
        );
        write_guest_pointer(memory, queue_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Lazily create the single `WDFFILEOBJECT` the island associates with
    /// this device's cleanup/close IRPs.
    pub(crate) fn ensure_file_object(
        &mut self,
        memory: &mut MemoryImage,
        device_handle: u64,
    ) -> AppResult<u64> {
        if let Some(existing) = self
            .kmdf
            .devices
            .get(&device_handle)
            .map(|device| device.file_object)
            .filter(|object| *object != 0)
        {
            return Ok(existing);
        }
        let object = self.create_kmdf_object(memory, KmdfObjectKind::FileObject, 0)?;
        if let Some(device) = self.kmdf.objects.get_mut(&device_handle) {
            device.children.insert(object);
        }
        if let Some(file) = self.kmdf.objects.get_mut(&object) {
            file.parent = Some(device_handle);
        }
        if let Some(device) = self.kmdf.devices.get_mut(&device_handle) {
            device.file_object = object;
        }
        Ok(object)
    }

    pub(crate) fn choose_queue(&self, device_handle: u64) -> Option<u64> {
        self.kmdf
            .queues
            .iter()
            .filter(|(_, queue)| queue.device == device_handle)
            .find(|(_, queue)| queue.default_queue)
            .or_else(|| {
                self.kmdf
                    .queues
                    .iter()
                    .find(|(_, queue)| queue.device == device_handle)
            })
            .map(|(handle, _)| *handle)
    }

    pub(crate) fn queue_callback(queue: &KmdfQueue, major: IrpMajorFunction) -> u64 {
        match major {
            IrpMajorFunction::Read => {
                if queue.callbacks.read != 0 {
                    queue.callbacks.read
                } else {
                    queue.callbacks.default
                }
            }
            IrpMajorFunction::Write => {
                if queue.callbacks.write != 0 {
                    queue.callbacks.write
                } else {
                    queue.callbacks.default
                }
            }
            IrpMajorFunction::DeviceControl => {
                if queue.callbacks.device_control != 0 {
                    queue.callbacks.device_control
                } else {
                    queue.callbacks.default
                }
            }
            _ => queue.callbacks.default,
        }
    }

    pub(crate) fn callback_call(
        queue_handle: u64,
        request_handle: u64,
        request: &KmdfRequest,
        entry: u64,
        label: &'static str,
    ) -> PendingGuestCall {
        let args = match request.major {
            IrpMajorFunction::Read | IrpMajorFunction::Write => vec![
                queue_handle,
                request_handle,
                u64::from(request.input_len.max(request.output_len)),
            ],
            IrpMajorFunction::DeviceControl => vec![
                queue_handle,
                request_handle,
                u64::from(request.output_len),
                u64::from(request.input_len),
                u64::from(request.io_control),
            ],
            _ => vec![queue_handle, request_handle],
        };
        PendingGuestCall {
            entry,
            args,
            label,
            purpose: PendingPurpose::IoDispatch {
                request: request_handle,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_kmdf_request(
        &mut self,
        memory: &mut MemoryImage,
        device_handle: u64,
        queue_handle: u64,
        major: IrpMajorFunction,
        io_control: u32,
        input_len: u32,
        output_len: u32,
        input_guest: u64,
        output_guest: u64,
        outer_irp_guest: u64,
    ) -> AppResult<Result<u64, i32>> {
        let Some(device) = self.kmdf.devices.get(&device_handle) else {
            return Ok(Err(STATUS_INVALID_DEVICE_REQUEST));
        };
        let casak = device.casak;
        let irp = match self.io.allocate_irp(
            casak,
            IrpParameterBlock::new(major, 0, input_len.max(output_len) as usize),
        ) {
            Ok(irp) => irp,
            Err(status) => return Ok(Err(status)),
        };
        if major == IrpMajorFunction::DeviceControl {
            let _ = self.io.set_stack_parameters(
                irp,
                casak,
                StackParameters::DeviceControl {
                    io_control_code: io_control,
                    input_length: input_len as usize,
                    output_length: output_len as usize,
                    output_offset: 0,
                },
            );
        } else if matches!(major, IrpMajorFunction::Read | IrpMajorFunction::Write) {
            let _ = self.io.set_stack_parameters(
                irp,
                casak,
                StackParameters::ReadWrite {
                    length: input_len.max(output_len) as usize,
                    byte_offset: 0,
                },
            );
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Request, 0)?;
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        let parent = if queue_handle != 0 {
            queue_handle
        } else {
            device_handle
        };
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.parent = Some(parent);
        }
        if let Some(object) = self.kmdf.objects.get_mut(&parent) {
            object.children.insert(handle);
        }
        self.kmdf.requests.insert(
            handle,
            KmdfRequest {
                irp,
                device: Some(device_handle),
                io_control,
                input_len,
                output_len,
                input_guest,
                output_guest,
                completed: false,
                status: STATUS_SUCCESS,
                information: 0,
                context_guest,
                queue: (queue_handle != 0).then_some(queue_handle),
                outer_irp_guest,
                major,
                target: None,
                canceled: false,
                cancelable: false,
                cancel_callback: 0,
                impersonating: false,
            },
        );
        self.kmdf.current_request = handle;
        Ok(Ok(handle))
    }

    pub(crate) fn wdf_dispatch(
        &mut self,
        major: IrpMajorFunction,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let irp_guest = guest_arg(state, memory, 0)?;
        let device_object = guest_arg(state, memory, 1)?;
        if irp_guest != 0 {
            self.kmdf.current_irp_guest = irp_guest;
        }
        let Some(device_handle) = self.kmdf.devices_by_object.get(&device_object).copied() else {
            self.write_outer_irp_status(memory, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let file_callback = self
            .kmdf
            .devices
            .get(&device_handle)
            .map_or(0, |device| match major {
                IrpMajorFunction::Cleanup => device.file_cleanup,
                IrpMajorFunction::Close => device.file_close,
                _ => 0,
            });
        if file_callback != 0 {
            let request = match self.new_kmdf_request(
                memory,
                device_handle,
                0,
                major,
                0,
                0,
                0,
                0,
                0,
                irp_guest,
            )? {
                Ok(request) => request,
                Err(status) => {
                    self.write_outer_irp_status(memory, status, 0)?;
                    set_status(state, status);
                    return Ok(None);
                }
            };
            let file_object = self.ensure_file_object(memory, device_handle)?;
            if major == IrpMajorFunction::Cleanup {
                self.kmdf.file_cleanup_dispatches += 1;
            } else {
                self.kmdf.file_close_dispatches += 1;
            }
            self.kmdf.current_request = request;
            self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
            set_status(state, STATUS_PENDING);
            return Ok(Some(PendingGuestCall {
                entry: file_callback,
                args: vec![device_handle, request, file_object],
                label: if major == IrpMajorFunction::Cleanup {
                    "EvtFileCleanup"
                } else {
                    "EvtFileClose"
                },
                purpose: PendingPurpose::FileDispatch { request },
            }));
        }
        let Some(queue_handle) = self.choose_queue(device_handle) else {
            self.write_outer_irp_status(memory, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let input_len = self.kmdf.current_input_len;
        let output_len = self.kmdf.current_output_len;
        let io_control = self.kmdf.current_io_control;
        let system_buffer = self.kmdf.current_system_buffer;
        let (input_guest, output_guest) = match major {
            IrpMajorFunction::Read => (0, system_buffer),
            IrpMajorFunction::Write => (system_buffer, 0),
            _ => (system_buffer, system_buffer),
        };
        let request = match self.new_kmdf_request(
            memory,
            device_handle,
            queue_handle,
            major,
            io_control,
            input_len,
            output_len,
            input_guest,
            output_guest,
            irp_guest,
        )? {
            Ok(request) => request,
            Err(status) => {
                self.write_outer_irp_status(memory, status, 0)?;
                set_status(state, status);
                return Ok(None);
            }
        };
        let queue = self.kmdf.queues.get(&queue_handle).cloned().expect("queue");
        let power_deferred = !self.queue_power_ready(&queue);
        let defer = queue.stopped
            || queue.dispatch_type == 2
            || (queue.dispatch_type == 0 && !queue.in_flight.is_empty())
            || power_deferred;
        if defer {
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.queued.push_back(request);
            }
            if power_deferred {
                self.kmdf.power_managed_defers += 1;
            }
            self.kmdf.queued_dispatches += 1;
            self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
            set_status(state, STATUS_PENDING);
            return Ok(None);
        }
        let entry = Self::queue_callback(&queue, major);
        if entry == 0 {
            let status = if matches!(major, IrpMajorFunction::Cleanup | IrpMajorFunction::Close) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_DEVICE_REQUEST
            };
            self.complete_kmdf_request(memory, request, status, 0)?;
            set_status(state, status);
            return Ok(None);
        }
        if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
            queue.in_flight.insert(request);
        }
        match major {
            IrpMajorFunction::Read => self.kmdf.read_dispatches += 1,
            IrpMajorFunction::Write => self.kmdf.write_dispatches += 1,
            IrpMajorFunction::DeviceControl => self.kmdf.ioctl_dispatches += 1,
            IrpMajorFunction::Cleanup => self.kmdf.cleanup_dispatches += 1,
            IrpMajorFunction::Close => self.kmdf.close_dispatches += 1,
            _ => {}
        }
        self.kmdf.current_request = request;
        self.write_outer_irp_status(memory, STATUS_PENDING, 0)?;
        let request_state = self.kmdf.requests.get(&request).expect("request").clone();
        let label = match major {
            IrpMajorFunction::Read => "EvtIoRead",
            IrpMajorFunction::Write => "EvtIoWrite",
            IrpMajorFunction::DeviceControl => "EvtIoDeviceControl",
            _ => "EvtIoDefault",
        };
        Ok(Some(Self::callback_call(
            queue_handle,
            request,
            &request_state,
            entry,
            label,
        )))
    }

    pub(crate) fn dispatch_next_queued(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        loop {
            let candidate = self.kmdf.queues.iter().find_map(|(handle, queue)| {
                if queue.dispatch_type == 2 {
                    return None;
                }
                if queue.stopped && !queue.draining {
                    return None;
                }
                if queue.dispatch_type == 0 && !queue.in_flight.is_empty() {
                    return None;
                }
                if !self.queue_power_ready(queue) {
                    return None;
                }
                queue
                    .queued
                    .front()
                    .copied()
                    .map(|request| (*handle, request))
            });
            let Some((queue_handle, request_handle)) = candidate else {
                for queue in self.kmdf.queues.values_mut() {
                    if queue.draining && queue.queued.is_empty() {
                        queue.draining = false;
                        queue.stopped = true;
                    }
                }
                return Ok(None);
            };
            let request = match self.kmdf.requests.get(&request_handle) {
                Some(request) => request.clone(),
                None => {
                    if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                        queue.queued.pop_front();
                    }
                    continue;
                }
            };
            let queue = self
                .kmdf
                .queues
                .get(&queue_handle)
                .cloned()
                .expect("queue handle comes from iterating the same map");
            let entry = Self::queue_callback(&queue, request.major);
            if entry == 0 {
                if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                    queue.queued.pop_front();
                }
                let status = if matches!(
                    request.major,
                    IrpMajorFunction::Cleanup | IrpMajorFunction::Close
                ) {
                    STATUS_SUCCESS
                } else {
                    STATUS_INVALID_DEVICE_REQUEST
                };
                self.complete_kmdf_request(memory, request_handle, status, 0)?;
                continue;
            }
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.queued.pop_front();
                queue.in_flight.insert(request_handle);
            }
            self.kmdf.queued_dispatches += 1;
            match request.major {
                IrpMajorFunction::Read => self.kmdf.read_dispatches += 1,
                IrpMajorFunction::Write => self.kmdf.write_dispatches += 1,
                IrpMajorFunction::DeviceControl => self.kmdf.ioctl_dispatches += 1,
                IrpMajorFunction::Cleanup => self.kmdf.cleanup_dispatches += 1,
                IrpMajorFunction::Close => self.kmdf.close_dispatches += 1,
                _ => {}
            }
            self.kmdf.current_request = request_handle;
            self.write_irp_status(memory, request.outer_irp_guest, STATUS_PENDING, 0)?;
            let label = match request.major {
                IrpMajorFunction::Read => "EvtIoRead",
                IrpMajorFunction::Write => "EvtIoWrite",
                IrpMajorFunction::DeviceControl => "EvtIoDeviceControl",
                _ => "EvtIoDefault",
            };
            return Ok(Some(Self::callback_call(
                queue_handle,
                request_handle,
                &request,
                entry,
                label,
            )));
        }
    }

    pub(crate) fn complete_kmdf_request(
        &mut self,
        memory: &mut MemoryImage,
        handle: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        let Some(request) = self.kmdf.requests.get_mut(&handle) else {
            return Ok(());
        };
        if request.completed {
            return Ok(());
        }
        request.completed = true;
        request.status = status;
        request.information = information;
        let irp = request.irp;
        let outer = request.outer_irp_guest;
        let queue = request.queue;
        let _ = self.io.complete_irp(irp, status, information);
        if let Some(queue_handle) = queue {
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.in_flight.remove(&handle);
                if queue.draining && queue.queued.is_empty() {
                    queue.draining = false;
                    queue.stopped = true;
                }
            }
        }
        if self.kmdf.current_request == handle {
            self.kmdf.current_request = 0;
        }
        self.write_irp_status(memory, outer, status, information)
    }

    pub(crate) fn wdf_queue_retrieve(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        found: bool,
    ) -> AppResult<()> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let (found_request, request_out) = if found {
            (guest_arg(state, memory, 1)?, guest_arg(state, memory, 2)?)
        } else {
            (0, guest_arg(state, memory, 1)?)
        };
        if request_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                request_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let request = if found {
            queue
                .queued
                .iter()
                .position(|request| *request == found_request)
                .and_then(|index| queue.queued.remove(index))
        } else {
            queue.queued.pop_front()
        };
        let Some(request) = request else {
            set_status(state, STATUS_NO_MORE_ENTRIES);
            return Ok(());
        };
        if let Some(request) = self.kmdf.requests.get_mut(&request) {
            request.queue = None;
        }
        self.kmdf.manual_retrievals += 1;
        write_guest_pointer(memory, request_out, request, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_queue_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        drain: bool,
        _synchronously: bool,
    ) -> AppResult<Option<PendingGuestCall>> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        queue.stopped = true;
        if drain {
            queue.draining = true;
        }
        let stop_callback = queue.callbacks.stop;
        let in_flight = queue
            .in_flight
            .iter()
            .chain(queue.queued.iter())
            .copied()
            .collect::<Vec<_>>();
        if in_flight.is_empty() && drain && queue.queued.is_empty() {
            queue.draining = false;
        }
        let mut callbacks = Vec::new();
        if stop_callback != 0 {
            for request in in_flight {
                self.kmdf.stop_dispatches += 1;
                callbacks.push(GuestCallback {
                    entry: stop_callback,
                    args: vec![queue_handle, request, 1],
                    label: "EvtIoStop",
                });
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(Self::callbacks_pending(callbacks, drain))
    }

    pub(crate) fn wdf_queue_purge(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        queue.stopped = true;
        queue.draining = false;
        let canceled_callback = queue.callbacks.canceled_on_queue;
        let queued = queue.queued.drain(..).collect::<Vec<_>>();
        let in_flight = std::mem::take(&mut queue.in_flight);
        let mut callbacks = Vec::new();
        for request in queued {
            self.kmdf.cancel_dispatches += 1;
            if canceled_callback != 0 {
                callbacks.push(GuestCallback {
                    entry: canceled_callback,
                    args: vec![queue_handle, request],
                    label: "EvtIoCanceledOnQueue",
                });
            } else {
                self.force_cancel_request(request);
                self.write_request_outer_status(memory, request, STATUS_CANCELLED, 0)?;
            }
        }
        for request in in_flight {
            self.kmdf.cancel_dispatches += 1;
            if canceled_callback != 0 {
                callbacks.push(GuestCallback {
                    entry: canceled_callback,
                    args: vec![queue_handle, request],
                    label: "EvtIoCanceledOnQueue",
                });
            } else {
                self.force_cancel_request(request);
                self.write_request_outer_status(memory, request, STATUS_CANCELLED, 0)?;
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(Self::callbacks_pending(callbacks, false))
    }

    pub(crate) fn wdf_queue_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let queue_handle = guest_arg(state, memory, 0)?;
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        queue.stopped = false;
        queue.draining = false;
        let resume_callback = queue.callbacks.resume;
        let in_flight = queue
            .in_flight
            .iter()
            .chain(queue.queued.iter())
            .copied()
            .collect::<Vec<_>>();
        let mut callbacks = Vec::new();
        if resume_callback != 0 {
            for request in in_flight {
                self.kmdf.resume_dispatches += 1;
                callbacks.push(GuestCallback {
                    entry: resume_callback,
                    args: vec![queue_handle, request],
                    label: "EvtIoResume",
                });
            }
        }
        set_status(state, STATUS_SUCCESS);
        if callbacks.is_empty() {
            // No EvtIoResume callback: queued requests still become eligible
            // as soon as the queue starts.
            return self.dispatch_next_queued(memory);
        }
        Ok(Self::callbacks_pending(callbacks, true))
    }

    pub(crate) fn callbacks_pending(
        callbacks: Vec<GuestCallback>,
        dispatch_next: bool,
    ) -> Option<PendingGuestCall> {
        let mut remaining = callbacks;
        if remaining.is_empty() {
            return None;
        }
        let first = remaining.remove(0);
        Some(PendingGuestCall {
            entry: first.entry,
            args: first.args,
            label: first.label,
            purpose: PendingPurpose::Callbacks {
                remaining,
                dispatch_next,
            },
        })
    }

    pub(crate) fn write_request_outer_status(
        &self,
        memory: &mut MemoryImage,
        request: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        if let Some(request) = self.kmdf.requests.get(&request) {
            self.write_irp_status(memory, request.outer_irp_guest, status, information)?;
        }
        Ok(())
    }

    pub(crate) fn wdf_request_cancel_queued(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let handle = guest_arg(state, memory, 0)?;
        let Some(request) = self.kmdf.requests.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        let Some(queue_handle) = request.queue else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let Some(index) = queue.queued.iter().position(|queued| *queued == handle) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        queue.queued.remove(index);
        let canceled_callback = queue.callbacks.canceled_on_queue;
        self.kmdf.cancel_dispatches += 1;
        if canceled_callback != 0 {
            set_status(state, STATUS_SUCCESS);
            return Ok(Self::callbacks_pending(
                vec![GuestCallback {
                    entry: canceled_callback,
                    args: vec![queue_handle, handle],
                    label: "EvtIoCanceledOnQueue",
                }],
                false,
            ));
        }
        self.force_cancel_request(handle);
        self.write_request_outer_status(memory, handle, STATUS_CANCELLED, 0)?;
        set_status(state, STATUS_CANCELLED);
        Ok(None)
    }

    /// True when a queue's power-managed gate currently allows dispatch.
    pub(crate) fn queue_power_ready(&self, queue: &KmdfQueue) -> bool {
        if !queue.power_managed {
            return true;
        }
        self.kmdf.devices.get(&queue.device).is_some_and(|device| {
            device.started
                && !device.removed
                && !device.surprised
                && !device.idle
                && device.power_state == WDF_POWER_DEVICE_D0
        })
    }

    pub(crate) fn wdf_request_forward_to_io_queue(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let request = guest_arg(state, memory, 0)?;
        let destination = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(None);
        }
        if let Err(status) = self.kmdf_expect_kind(destination, KmdfObjectKind::Queue) {
            set_status(state, status);
            return Ok(None);
        }
        let request_state = self
            .kmdf
            .requests
            .get(&request)
            .cloned()
            .expect("request was validated");
        if request_state.completed {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(None);
        }
        if request_state.queue == Some(destination) {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        let queue = self
            .kmdf
            .queues
            .get(&destination)
            .cloned()
            .expect("queue was validated");
        if request_state.device != Some(queue.device) {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if let Some(source) = request_state.queue {
            if let Some(source) = self.kmdf.queues.get_mut(&source) {
                source.queued.retain(|queued| *queued != request);
                source.in_flight.remove(&request);
            } // coverage: unreachable — deleting a queue force-cancels every request on it, so a stale source implies an already-completed request, which the completed check rejects before the sweep.
        }
        if let Some(request_state) = self.kmdf.requests.get_mut(&request) {
            request_state.queue = Some(destination);
        }
        self.kmdf.irp_forwards += 1;
        let power_deferred = !self.queue_power_ready(&queue);
        let defer = queue.stopped
            || queue.dispatch_type == 2
            || (queue.dispatch_type == 0 && !queue.in_flight.is_empty())
            || power_deferred;
        if defer {
            if let Some(queue) = self.kmdf.queues.get_mut(&destination) {
                queue.queued.push_back(request);
            }
            if power_deferred {
                self.kmdf.power_managed_defers += 1;
            }
            set_status(state, STATUS_SUCCESS);
            return Ok(None);
        }
        let entry = Self::queue_callback(&queue, request_state.major);
        if entry == 0 {
            self.complete_kmdf_request(memory, request, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if let Some(queue) = self.kmdf.queues.get_mut(&destination) {
            queue.in_flight.insert(request);
        }
        self.kmdf.current_request = request;
        self.write_irp_status(memory, request_state.outer_irp_guest, STATUS_PENDING, 0)?;
        set_status(state, STATUS_SUCCESS);
        Ok(Some(Self::callback_call(
            destination,
            request,
            &request_state,
            entry,
            "EvtIoForwarded",
        )))
    }

    /// `WdfDeviceEnqueueRequest`: place a driver-created request on the
    /// device's queue and dispatch it when the queue rules allow.
    pub(crate) fn wdf_device_enqueue_request(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let device_handle = guest_arg(state, memory, 0)?;
        let request_handle = guest_arg(state, memory, 1)?;
        if !self.kmdf.devices.contains_key(&device_handle) {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        let Some(request) = self.kmdf.requests.get(&request_handle).cloned() else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        if request.completed || request.queue.is_some() {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        let Some(queue_handle) = self.choose_queue(device_handle) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let queue = self
            .kmdf
            .queues
            .get(&queue_handle)
            .cloned()
            .expect("queue was selected from the queue map");
        let entry = Self::queue_callback(&queue, request.major);
        if entry == 0 {
            self.complete_kmdf_request(memory, request_handle, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if let Some(request) = self.kmdf.requests.get_mut(&request_handle) {
            request.queue = Some(queue_handle);
        }
        let defer = queue.stopped
            || queue.dispatch_type == 2
            || (queue.dispatch_type == 0 && !queue.in_flight.is_empty())
            || !self.queue_power_ready(&queue);
        if defer {
            if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
                queue.queued.push_back(request_handle);
            }
            if !self.queue_power_ready(&queue) {
                self.kmdf.power_managed_defers += 1;
            }
            self.kmdf.queued_dispatches += 1;
            set_status(state, STATUS_SUCCESS);
            return Ok(None);
        }
        if let Some(queue) = self.kmdf.queues.get_mut(&queue_handle) {
            queue.in_flight.insert(request_handle);
        }
        self.kmdf.current_request = request_handle;
        let request = self
            .kmdf
            .requests
            .get(&request_handle)
            .cloned()
            .expect("request was validated above");
        set_status(state, STATUS_SUCCESS);
        Ok(Some(Self::callback_call(
            queue_handle,
            request_handle,
            &request,
            entry,
            "EvtIoDeviceControl",
        )))
    }
}
