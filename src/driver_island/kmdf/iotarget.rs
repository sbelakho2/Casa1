//! KMDF object model.

use super::*;

impl IslandState {
    pub(crate) fn wdf_device_get_iotarget(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        if !self.kmdf.devices.contains_key(&device) {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        let existing = self
            .kmdf
            .iotargets
            .iter()
            .find_map(|(handle, target)| (target.device == device).then_some(*handle));
        let target = if let Some(target) = existing {
            target
        } else {
            let target = self.create_kmdf_object(memory, KmdfObjectKind::IoTarget, 0)?;
            if let Some(object) = self.kmdf.objects.get_mut(&target) {
                object.parent = Some(device);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&device) {
                object.children.insert(target);
            }
            let context_guest = self
                .kmdf
                .objects
                .get(&target)
                .map(|object| object.context_guest)
                .unwrap_or(target + 0x80);
            self.kmdf.iotargets.insert(
                target,
                KmdfIoTarget {
                    device,
                    context_guest,
                },
            );
            target
        };
        state.set(Register::Rax, target);
        Ok(())
    }

    pub(crate) fn wdf_iotarget_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let target_out = guest_arg(state, memory, 2)?;
        if !self.kmdf.devices.contains_key(&device)
            || target_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                target_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let target = self.create_kmdf_object(memory, KmdfObjectKind::IoTarget, attributes)?;
        if self
            .kmdf
            .objects
            .get(&target)
            .is_some_and(|object| object.parent.is_none())
        {
            if let Some(object) = self.kmdf.objects.get_mut(&target) {
                object.parent = Some(device);
            }
            if let Some(object) = self.kmdf.objects.get_mut(&device) {
                object.children.insert(target);
            }
        }
        let context_guest = self
            .kmdf
            .objects
            .get(&target)
            .map(|object| object.context_guest)
            .unwrap_or(target + 0x80);
        self.kmdf.iotargets.insert(
            target,
            KmdfIoTarget {
                device,
                context_guest,
            },
        );
        write_guest_pointer(memory, target_out, target, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn read_memory_descriptor(
        &self,
        memory: &MemoryImage,
        descriptor: u64,
    ) -> AppResult<(u64, usize)> {
        if descriptor == 0 {
            return Ok((0, 0));
        }
        let _kind = memory.read_u32(descriptor)?;
        let (pointer_offset, length_offset) = match self.arch {
            GuestArch::X64 => (0x08u64, 0x10u64),
            GuestArch::X86 => (0x04, 0x08),
        };
        let pointer = read_guest_pointer(memory, descriptor + pointer_offset, self.arch)?;
        let length = read_guest_pointer(memory, descriptor + length_offset, self.arch)? as usize;
        Ok((pointer, length))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_ioctl_send(
        &mut self,
        memory: &mut MemoryImage,
        target: u64,
        request: u64,
        io_control: u32,
        input: &[u8],
        input_ptr: u64,
        output_ptr: u64,
        output_len: usize,
    ) -> AppResult<Option<PendingIoTargetSend>> {
        let Some(device_handle) = self.resolve_target_device(target) else {
            return Ok(None);
        };
        let Some(device) = self.kmdf.devices.get(&device_handle).cloned() else {
            return Ok(None);
        };
        let irp = match self.io.allocate_irp(
            device.casak,
            IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, input.len()),
        ) {
            Ok(irp) => irp,
            Err(_) => return Ok(None),
        };
        let _ = self.io.set_stack_parameters(
            irp,
            device.casak,
            StackParameters::DeviceControl {
                io_control_code: io_control,
                input_length: input.len(),
                output_length: output_len,
                output_offset: 0,
            },
        );
        let arch = self.arch;
        let irp_guest = self.arena.alloc(memory, irp_guest_size(arch) as usize, 8)?;
        let stack_guest = self.arena.alloc(memory, io_stack_location_size(arch), 8)?;
        let buffer_len = input.len().max(output_len);
        let system_buffer = if buffer_len > 0 {
            self.arena.alloc(memory, buffer_len, 8)?
        } else {
            0
        };
        if !input.is_empty() {
            memory.map_bytes(system_buffer, input);
        }
        build_guest_irp(
            memory,
            arch,
            irp_guest,
            stack_guest,
            system_buffer,
            device.object_guest,
            output_ptr,
            IrpMajorFunction::DeviceControl,
            0,
            None,
            io_control,
            input.len() as u32,
            output_len as u32,
            0,
        )?; // coverage: unreachable — build_guest_irp only performs infallible MemoryImage writes
        let handler = read_guest_pointer(
            memory,
            self.driver_object_guest
                + major_function_offset(arch)
                + IrpMajorFunction::DeviceControl.code() as u64 * arch.pointer_bytes() as u64,
            arch,
        )?;
        if handler == 0 || handler == self.default_dispatch {
            let _ = self.io.complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            return Ok(None);
        }
        let saved = (
            self.kmdf.current_irp_guest,
            self.kmdf.current_device_guest,
            self.kmdf.current_system_buffer,
            self.kmdf.current_input_len,
            self.kmdf.current_output_len,
            self.kmdf.current_io_control,
            self.kmdf.current_request,
        );
        self.kmdf.current_irp_guest = irp_guest;
        self.kmdf.current_device_guest = device.object_guest;
        self.kmdf.current_system_buffer = system_buffer;
        self.kmdf.current_input_len = input.len() as u32;
        self.kmdf.current_output_len = output_len as u32;
        self.kmdf.current_io_control = io_control;
        self.kmdf.current_request = 0;
        self.kmdf.iotarget_sends += 1;
        Ok(Some(PendingIoTargetSend {
            irp,
            irp_guest,
            entry: handler,
            device_object: device.object_guest,
            system_buffer,
            output_ptr,
            output_len,
            bytes_returned: 0,
            request,
            target,
            io_control,
            input_ptr,
            input_len: input.len() as u32,
            saved,
        }))
    }

    pub(crate) fn finish_ioctl_send(
        &mut self,
        memory: &mut MemoryImage,
        pending: PendingIoTargetSend,
    ) -> AppResult<(i32, usize)> {
        let arch = self.arch;
        let bytes_returned = pending.bytes_returned;
        let (guest_status, information) = match arch {
            GuestArch::X64 => (
                memory.read_u32(pending.irp_guest + 0x30)? as i32,
                memory.read_u64(pending.irp_guest + 0x40)? as usize,
            ),
            GuestArch::X86 => (
                memory.read_u32(pending.irp_guest + 0x18)? as i32,
                memory.read_u32(pending.irp_guest + 0x20)? as usize,
            ),
        };
        let _ = self.io.complete_irp(pending.irp, guest_status, information);
        if pending.output_len > 0 && pending.output_ptr != 0 && pending.system_buffer != 0 {
            let mut output = vec![0_u8; pending.output_len];
            if memory.read_into(pending.system_buffer, &mut output).is_ok() {
                memory.map_bytes(pending.output_ptr, &output);
            }
        }
        (
            self.kmdf.current_irp_guest,
            self.kmdf.current_device_guest,
            self.kmdf.current_system_buffer,
            self.kmdf.current_input_len,
            self.kmdf.current_output_len,
            self.kmdf.current_io_control,
            self.kmdf.current_request,
        ) = pending.saved;
        if pending.request != 0 {
            if let Some(request) = self.kmdf.requests.get_mut(&pending.request) {
                request.target = Some(pending.target);
                request.io_control = pending.io_control;
                request.input_guest = pending.input_ptr;
                request.input_len = pending.input_len;
                request.output_guest = pending.output_ptr;
                request.output_len = pending.output_len as u32;
            }
            self.apply_iotarget_result(memory, pending.request, guest_status, information)?;
        }
        if bytes_returned != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                bytes_returned,
                self.arch.pointer_bytes(),
            )
            .is_ok()
        {
            write_guest_pointer(memory, bytes_returned, information as u64, self.arch)?;
        }
        Ok((guest_status, information))
    }

    pub(crate) fn apply_iotarget_result(
        &mut self,
        memory: &mut MemoryImage,
        request: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        let Some(request_state) = self.kmdf.requests.get_mut(&request) else {
            return Ok(());
        };
        request_state.completed = true;
        request_state.status = status;
        request_state.information = information;
        let outer = request_state.outer_irp_guest;
        let irp = request_state.irp;
        let _ = self.io.complete_irp(irp, status, information);
        self.write_irp_status(memory, outer, status, information)
    }

    pub(crate) fn wdf_iotarget_send_ioctl(
        &mut self,
        _runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let target = guest_arg(state, memory, 0)?;
        let request = guest_arg(state, memory, 1)?;
        let io_control = guest_arg(state, memory, 2)? as u32;
        let input_descriptor = guest_arg(state, memory, 3)?;
        let output_descriptor = guest_arg(state, memory, 4)?;
        let _options = guest_arg(state, memory, 5)?;
        let bytes_returned = guest_arg(state, memory, 6)?;
        let (input_ptr, input_len) = self.read_memory_descriptor(memory, input_descriptor)?;
        let (output_ptr, output_len) = self.read_memory_descriptor(memory, output_descriptor)?;
        let mut input = vec![0_u8; input_len];
        if input_len > 0 && memory.read_into(input_ptr, &mut input).is_err() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let Some(mut pending) = self.prepare_ioctl_send(
            memory, target, request, io_control, &input, input_ptr, output_ptr, output_len,
        )?
        else {
            self.apply_iotarget_result(memory, request, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        pending.bytes_returned = bytes_returned;
        Ok(Some(PendingGuestCall {
            entry: pending.entry,
            args: vec![pending.irp_guest, pending.device_object],
            label: "WdfIoTargetSend",
            purpose: PendingPurpose::IoTargetSend {
                pending: Box::new(pending),
            },
        }))
    }

    pub(crate) fn wdf_iotarget_format_request(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let target = guest_arg(state, memory, 0)?;
        let request = guest_arg(state, memory, 1)?;
        let io_control = guest_arg(state, memory, 2)? as u32;
        let input_descriptor = guest_arg(state, memory, 3)?;
        let input_offset = guest_arg(state, memory, 4)?;
        let output_descriptor = guest_arg(state, memory, 5)?;
        let output_offset = guest_arg(state, memory, 6)?;
        let (input_ptr, input_len) = self.read_memory_descriptor(memory, input_descriptor)?;
        let (output_ptr, output_len) = self.read_memory_descriptor(memory, output_descriptor)?;
        let Some(request_state) = self.kmdf.requests.get_mut(&request) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        request_state.target = Some(target);
        request_state.io_control = io_control;
        request_state.input_guest = input_ptr.saturating_add(input_offset);
        request_state.input_len = input_len.saturating_sub(input_offset as usize) as u32;
        request_state.output_guest = output_ptr.saturating_add(output_offset);
        request_state.output_len = output_len.saturating_sub(output_offset as usize) as u32;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn wdf_request_send(
        &mut self,
        _runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let request = guest_arg(state, memory, 0)?;
        let target = guest_arg(state, memory, 1)?;
        let _options = guest_arg(state, memory, 2)?;
        let Some(request_state) = self.kmdf.requests.get(&request).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(None);
        };
        let target = if target != 0 {
            target
        } else {
            request_state.target.unwrap_or(0)
        };
        let mut input = vec![0_u8; request_state.input_len as usize];
        if !input.is_empty()
            && memory
                .read_into(request_state.input_guest, &mut input)
                .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let Some(pending) = self.prepare_ioctl_send(
            memory,
            target,
            request,
            request_state.io_control,
            &input,
            request_state.input_guest,
            request_state.output_guest,
            request_state.output_len as usize,
        )?
        else {
            self.apply_iotarget_result(memory, request, STATUS_INVALID_DEVICE_REQUEST, 0)?;
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        };
        Ok(Some(PendingGuestCall {
            entry: pending.entry,
            args: vec![pending.irp_guest, pending.device_object],
            label: "WdfRequestSend",
            purpose: PendingPurpose::IoTargetSend {
                pending: Box::new(pending),
            },
        }))
    }
}
