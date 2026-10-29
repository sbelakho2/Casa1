//! KMDF object model.

use super::*;

impl IslandState {
    pub(crate) fn force_cancel_request(&mut self, handle: u64) -> bool {
        let Some(request) = self.kmdf.requests.get_mut(&handle) else {
            return false;
        };
        if request.completed {
            return false;
        }
        request.completed = true;
        request.canceled = true;
        request.status = STATUS_CANCELLED;
        request.information = 0;
        let irp = request.irp;
        let _ = self.io.cancel_irp(irp);
        true
    }

    pub(crate) fn wdf_request_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let io_target = guest_arg(state, memory, 1)?;
        let request_out = guest_arg(state, memory, 2)?;
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
        let target_device = self.resolve_target_device(io_target);
        let Some(target) = target_device else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        };
        let Some(device) = self.kmdf.devices.get(&target) else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        };
        let irp = match self.io.allocate_irp(
            device.casak,
            IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 0),
        ) {
            Ok(irp) => irp,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Request, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            let parent = if self.kmdf.iotargets.contains_key(&io_target) {
                io_target
            } else {
                target
            };
            if let Some(object) = self.kmdf.objects.get_mut(&handle) {
                object.parent = Some(parent);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&parent) {
                object.children.insert(handle);
            }
        }
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.requests.insert(
            handle,
            KmdfRequest {
                irp,
                device: Some(target),
                io_control: 0,
                input_len: 0,
                output_len: 0,
                input_guest: 0,
                output_guest: 0,
                completed: false,
                status: STATUS_SUCCESS,
                information: 0,
                context_guest,
                queue: None,
                outer_irp_guest: 0,
                major: IrpMajorFunction::DeviceControl,
                target: (io_target != 0).then_some(io_target),
                canceled: false,
                cancelable: false,
                cancel_callback: 0,
                impersonating: false,
            },
        );
        write_guest_pointer(memory, request_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn resolve_target_device(&self, target: u64) -> Option<u64> {
        if target == 0 {
            // The documented default target: the driver's first device.
            return self.kmdf.devices.keys().next().copied();
        }
        if self.kmdf.devices.contains_key(&target) {
            return Some(target);
        }
        self.kmdf
            .iotargets
            .get(&target)
            .map(|iotarget| iotarget.device)
    }

    pub(crate) fn wdf_request_format_for_ioctl(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let target = guest_arg(state, memory, 1)?;
        let io_control = guest_arg(state, memory, 2)? as u32;
        let input_guest = guest_arg(state, memory, 3)?;
        let input_len = guest_arg(state, memory, 4)? as u32;
        let output_guest = guest_arg(state, memory, 5)?;
        let output_len = guest_arg(state, memory, 6)? as u32;
        let _options = guest_arg(state, memory, 7)?;
        let resolved_device = self.resolve_target_device(target);
        let Some(request) = self.kmdf.requests.get_mut(&request) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        request.io_control = io_control;
        request.input_guest = input_guest;
        request.input_len = input_len;
        request.output_guest = output_guest;
        request.output_len = output_len;
        request.target = Some(target);
        if resolved_device.is_some() {
            request.device = resolved_device;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_request_retrieve_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        input: bool,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let minimum = guest_arg(state, memory, 1)? as usize;
        let buffer_out = guest_arg(state, memory, 2)?;
        let length_out = guest_arg(state, memory, 3)?;
        let pointer_bytes = self.arch.pointer_bytes();
        if buffer_out == 0
            || length_out == 0
            || crate::host_thunks::validate_guest_pointer(memory, buffer_out, pointer_bytes)
                .is_err()
            || crate::host_thunks::validate_guest_pointer(memory, length_out, pointer_bytes)
                .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(request) = self.kmdf.requests.get(&request) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let (buffer, length) = if input {
            (request.input_guest, request.input_len)
        } else {
            (request.output_guest, request.output_len)
        };
        if minimum > length as usize || (minimum > 0 && buffer == 0) {
            set_status(state, STATUS_BUFFER_TOO_SMALL);
            return Ok(());
        }
        write_guest_pointer(memory, buffer_out, buffer, self.arch)?;
        write_guest_pointer(memory, length_out, u64::from(length), self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_request_complete(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        information: Option<usize>,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let status = guest_arg(state, memory, 1)? as u32 as i32;
        let information = information.unwrap_or(0);
        let Some(request) = self.kmdf.requests.get(&handle) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if request.completed {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        self.complete_kmdf_request(memory, handle, status, information)?;
        set_status(state, status);
        Ok(())
    }

    /// `WdfRequestCreateFromIrp`: wraps an existing WDM IRP in a
    /// `WDFREQUEST`.
    pub(crate) fn wdf_request_create_from_irp(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let irp = guest_arg(state, memory, 1)?;
        let request_out = guest_arg(state, memory, 2)?;
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
        let Some(irp_id) = self
            .irp_guests
            .iter()
            .find_map(|(id, guest)| (*guest == irp).then_some(*id))
        else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if self
            .kmdf
            .requests
            .values()
            .any(|request| request.irp == irp_id)
        {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Request, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        let context_guest = self
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
            .unwrap_or(handle + 0x80);
        self.kmdf.requests.insert(
            handle,
            KmdfRequest {
                irp: irp_id,
                device: None,
                io_control: 0,
                input_len: 0,
                output_len: 0,
                input_guest: 0,
                output_guest: 0,
                completed: false,
                status: STATUS_PENDING,
                information: 0,
                context_guest,
                queue: None,
                outer_irp_guest: irp,
                major: IrpMajorFunction::DeviceControl,
                target: None,
                canceled: false,
                cancelable: false,
                cancel_callback: 0,
                impersonating: false,
            },
        );
        write_guest_pointer(memory, request_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRequestImpersonate`: the request must be the one currently owned
    /// by the calling dispatch; impersonation levels above
    /// `SecurityDelegation` (3) are rejected.
    pub(crate) fn wdf_request_impersonate(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let level = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        if level > 3 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if self.kmdf.current_request != request {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        }
        let record = self
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request was validated");
        if record.completed {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        if record.impersonating {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        record.impersonating = true;
        self.kmdf.request_impersonations += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRequestStopImpersonating`.
    pub(crate) fn wdf_request_stop_impersonating(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request was validated");
        if !record.impersonating {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        record.impersonating = false;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRequestWdmGetIrp`: returns the guest IRP pointer in Rax.
    pub(crate) fn wdf_request_wdm_get_irp(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .requests
            .get(&request)
            .expect("request was validated");
        state.set(Register::Rax, record.outer_irp_guest);
        Ok(())
    }

    /// `WdfRequestSetInformation`.
    pub(crate) fn wdf_request_set_information(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let information = guest_arg(state, memory, 1)? as usize;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request was validated");
        if record.completed {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        record.information = information;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRequestForwardToParentDeviceIoQueue`: forwards a request from a
    /// child device up to its parent's queue.
    pub(crate) fn wdf_request_forward_to_parent(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let request = guest_arg(state, memory, 0)?;
        let parent_queue = guest_arg(state, memory, 1)?;
        let forward_action = guest_arg(state, memory, 2)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(None);
        }
        if forward_action > 2 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        if let Err(status) = self.kmdf_expect_kind(parent_queue, KmdfObjectKind::Queue) {
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
        let Some(device) = request_state.device else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let parent_device = self
            .kmdf
            .objects
            .get(&device)
            .and_then(|object| object.parent)
            .filter(|parent| self.kmdf.devices.contains_key(parent));
        let Some(parent_device) = parent_device else {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        let queue = self
            .kmdf
            .queues
            .get(&parent_queue)
            .cloned()
            .expect("queue was validated");
        if queue.device != parent_device {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        self.kmdf.parent_queue_forwards += 1;
        // Reuse the standard forward path against the parent's queue.
        if let Some(request_state) = self.kmdf.requests.get_mut(&request) {
            request_state.queue = Some(parent_queue);
        }
        if let Some(source) = request_state.queue {
            if let Some(source) = self.kmdf.queues.get_mut(&source) {
                source.queued.retain(|queued| *queued != request);
                source.in_flight.remove(&request);
            } // coverage: unreachable — a deleted source queue force-cancelled this request already; the completed check rejects it before the sweep.
        }
        let defer = queue.stopped
            || queue.dispatch_type == 2
            || (queue.dispatch_type == 0 && !queue.in_flight.is_empty());
        if defer {
            if let Some(queue) = self.kmdf.queues.get_mut(&parent_queue) {
                queue.queued.push_back(request);
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
        if let Some(queue) = self.kmdf.queues.get_mut(&parent_queue) {
            queue.in_flight.insert(request);
        }
        self.kmdf.current_request = request;
        self.write_irp_status(memory, request_state.outer_irp_guest, STATUS_PENDING, 0)?;
        set_status(state, STATUS_SUCCESS);
        Ok(Some(Self::callback_call(
            parent_queue,
            request,
            &request_state,
            entry,
            "EvtIoForwardedToParent",
        )))
    }

    pub(crate) fn wdf_request_format_for_read_write(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        read: bool,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let target = guest_arg(state, memory, 1)?;
        let descriptor = guest_arg(state, memory, 2)?;
        let offset = guest_arg(state, memory, 3)?;
        let file_object_out = guest_arg(state, memory, 4)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        let request_state = self
            .kmdf
            .requests
            .get(&request)
            .expect("request was validated");
        if request_state.completed {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        let resolved_target = self.resolve_target_device(target);
        if target != 0 && resolved_target.is_none() {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(());
        }
        let (pointer, length) = self.read_memory_descriptor(memory, descriptor)?;
        if offset > length as u64 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if file_object_out != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                file_object_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let buffer_guest = pointer.saturating_add(offset);
        let buffer_len = (length as u64).saturating_sub(offset) as u32;
        let request_state = self
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request was validated");
        request_state.major = if read {
            IrpMajorFunction::Read
        } else {
            IrpMajorFunction::Write
        };
        request_state.target = (target != 0).then_some(target);
        if read {
            request_state.output_guest = buffer_guest;
            request_state.output_len = buffer_len;
            request_state.input_guest = 0;
            request_state.input_len = 0;
        } else {
            request_state.input_guest = buffer_guest;
            request_state.input_len = buffer_len;
            request_state.output_guest = 0;
            request_state.output_len = 0;
        }
        if file_object_out != 0 {
            write_guest_pointer(memory, file_object_out, 0, self.arch)?;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_request_get_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let status = match self.kmdf.objects.get(&request) {
            None => STATUS_INVALID_HANDLE,
            Some(object) if object.kind != KmdfObjectKind::Request => STATUS_OBJECT_TYPE_MISMATCH,
            Some(_) => match self.kmdf.requests.get(&request) {
                Some(request) if request.completed => request.status,
                Some(_) => STATUS_PENDING,
                None => STATUS_INVALID_HANDLE, // coverage: unreachable — a Request-kind object keeps its record until purge, which removes the object entry in the same pass.
            },
        };
        set_status(state, status);
        Ok(())
    }

    pub(crate) fn wdf_request_is_canceled(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let canceled = matches!(
            self.kmdf.objects.get(&request).map(|object| object.kind),
            Some(KmdfObjectKind::Request)
        ) && self
            .kmdf
            .requests
            .get(&request)
            .is_some_and(|request| request.canceled || request.status == STATUS_CANCELLED);
        state.set(Register::Rax, u64::from(canceled));
        Ok(())
    }

    pub(crate) fn wdf_request_mark_cancelable(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        let callback = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        if callback == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let request_state = self
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request was validated");

        if request_state.completed || request_state.cancelable {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        request_state.cancelable = true;
        request_state.cancel_callback = callback;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_request_unmark_cancelable(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let request = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(request, KmdfObjectKind::Request) {
            set_status(state, status);
            return Ok(());
        }
        let request_state = self
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request was validated");

        if !request_state.cancelable {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        request_state.cancelable = false;
        request_state.cancel_callback = 0;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}
