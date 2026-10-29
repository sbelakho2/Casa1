//! IRP dispatch and completion status publication.

use super::*;

impl DriverIsland {
    /// Build a real CasaK IRP and a guest `_IRP`/`IO_STACK_LOCATION`, then
    /// invoke the driver's real `MajorFunction` guest code with the guest IRP
    /// pointer.  Returns `(NTSTATUS, Information)`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_irp(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        major: IrpMajorFunction,
        io_control_code: u32,
        input_ptr: u64,
        input_len: u32,
        output_ptr: u64,
        output_len: u32,
        byte_offset: u64,
    ) -> AppResult<(i32, usize)> {
        self.dispatch_irp_inner(
            runtime,
            memory,
            device_guest,
            major,
            0,
            None,
            io_control_code,
            input_ptr,
            input_len,
            output_ptr,
            output_len,
            byte_offset,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_irp_inner(
        &self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        device_guest: u64,
        major: IrpMajorFunction,
        minor: u8,
        power_state: Option<u32>,
        io_control_code: u32,
        input_ptr: u64,
        input_len: u32,
        output_ptr: u64,
        output_len: u32,
        byte_offset: u64,
    ) -> AppResult<(i32, usize)> {
        let inner = self.inner.clone();
        let (arch, default_dispatch, irp, irp_guest, stack_guest, system_buffer_guest, handler) = {
            let mut state = inner.borrow_mut();
            if state.removed_device_objects.contains(&device_guest) {
                return Ok((STATUS_INVALID_DEVICE_REQUEST, 0));
            }
            let Some(casak_device) = state.device_ids.get(&device_guest).copied() else {
                return Ok((STATUS_INVALID_HANDLE, 0));
            };
            let buffer_len = if matches!(major, IrpMajorFunction::Pnp | IrpMajorFunction::Power) {
                0
            } else {
                input_len.max(output_len) as usize
            };
            let parameters = IrpParameterBlock::new(major, minor, input_len as usize);
            let irp = match state.io.allocate_irp(casak_device, parameters) {
                Ok(irp) => irp,
                Err(status) => return Ok((status, 0)),
            };
            if major == IrpMajorFunction::DeviceControl {
                let _ = state.io.set_stack_parameters(
                    irp,
                    casak_device,
                    crate::casak::io::StackParameters::DeviceControl {
                        io_control_code,
                        input_length: input_len as usize,
                        output_length: output_len as usize,
                        output_offset: 0,
                    },
                );
            } else if matches!(major, IrpMajorFunction::Read | IrpMajorFunction::Write) {
                let _ = state.io.set_stack_parameters(
                    irp,
                    casak_device,
                    crate::casak::io::StackParameters::ReadWrite {
                        length: input_len.max(output_len) as usize,
                        byte_offset,
                    },
                );
            }
            let arch = state.arch;
            let irp_guest = match state.arena.alloc(memory, irp_guest_size(arch) as usize, 8) {
                Ok(guest) => guest,
                Err(_) => {
                    let _ = state.io.complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
                }
            };
            let stack_guest = match state.arena.alloc(memory, io_stack_location_size(arch), 8) {
                Ok(guest) => guest,
                Err(_) => {
                    let _ = state.io.complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
                }
            };
            let system_buffer_guest = if buffer_len > 0 {
                match state.arena.alloc(memory, buffer_len, 8) {
                    Ok(guest) => guest,
                    Err(_) => {
                        let _ = state.io.complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
                        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
                    }
                }
            } else {
                0
            };
            if input_len > 0 {
                let mut input = vec![0_u8; input_len as usize];
                if memory.read_into(input_ptr, &mut input).is_err() {
                    let _ = state.io.complete_irp(irp, STATUS_ACCESS_VIOLATION, 0);
                    return Ok((STATUS_ACCESS_VIOLATION, 0));
                }
                memory.map_bytes(system_buffer_guest, &input);
            }
            if output_len > 0
                && (output_ptr == 0
                    || crate::host_thunks::validate_guest_pointer(
                        memory,
                        output_ptr,
                        output_len as usize,
                    )
                    .is_err())
            {
                let _ = state.io.complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
                return Ok((STATUS_INVALID_PARAMETER, 0));
            }
            let handler = read_guest_pointer(
                memory,
                state.driver_object_guest
                    + major_function_offset(arch)
                    + major.code() as u64 * arch.pointer_bytes() as u64,
                arch,
            )?;
            (
                arch,
                state.default_dispatch,
                irp,
                irp_guest,
                stack_guest,
                system_buffer_guest,
                handler,
            )
        };

        if handler == 0 || handler == default_dispatch {
            let _ = self
                .inner
                .borrow()
                .io
                .complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            return Ok((STATUS_INVALID_DEVICE_REQUEST, 0));
        }

        build_guest_irp(
            memory,
            arch,
            irp_guest,
            stack_guest,
            system_buffer_guest,
            device_guest,
            output_ptr,
            major,
            minor,
            power_state,
            io_control_code,
            input_len,
            output_len,
            byte_offset,
        )?;
        {
            let mut state = self.inner.borrow_mut();
            state.kmdf.current_irp_guest = irp_guest;
            state.kmdf.current_device_guest = device_guest;
            state.kmdf.current_system_buffer = system_buffer_guest;
            state.kmdf.current_input_len = input_len;
            state.kmdf.current_output_len = output_len;
            state.kmdf.current_io_control = io_control_code;
            state.kmdf.current_request = 0;
        }

        let status = {
            let _active = ActiveIsland::install(inner.clone());
            let mut cpu = CpuState::new(arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                handler,
                &[irp_guest, device_guest],
                "DriverMajorFunction",
            )?;
            result as u32 as i32
        };

        let (guest_status, information) = match arch {
            GuestArch::X64 => (
                memory.read_u32(irp_guest + 0x30)? as i32,
                memory.read_u64(irp_guest + 0x40)? as usize,
            ),
            GuestArch::X86 => (
                memory.read_u32(irp_guest + 0x18)? as i32,
                memory.read_u32(irp_guest + 0x20)? as usize,
            ),
        };
        let final_status = if status != guest_status {
            // The handler's return is authoritative when it differs from the
            // IoStatus block it wrote.
            status
        } else {
            guest_status
        };
        let _ = self
            .inner
            .borrow()
            .io
            .complete_irp(irp, final_status, information);
        {
            let mut state = self.inner.borrow_mut();
            state.kmdf.current_irp_guest = 0;
            state.kmdf.current_device_guest = 0;
            state.kmdf.current_system_buffer = 0;
            state.kmdf.current_request = 0;
        }
        if output_len > 0 && system_buffer_guest != 0 {
            let mut output = vec![0_u8; output_len as usize];
            if memory.read_into(system_buffer_guest, &mut output).is_ok() {
                memory.map_bytes(output_ptr, &output);
            }
        }
        Ok((final_status, information))
    }
}

pub(crate) fn irp_guest_size(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => 0x80,
        GuestArch::X64 => 0x100,
    }
}

pub(crate) fn io_stack_location_size(arch: GuestArch) -> usize {
    match arch {
        GuestArch::X86 => 0x24,
        GuestArch::X64 => 0x48,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_guest_irp(
    memory: &mut MemoryImage,
    arch: GuestArch,
    irp: u64,
    stack: u64,
    system_buffer: u64,
    device_object: u64,
    user_buffer: u64,
    major: IrpMajorFunction,
    minor: u8,
    power_state: Option<u32>,
    io_control_code: u32,
    input_length: u32,
    output_length: u32,
    byte_offset: u64,
) -> AppResult<()> {
    memory.write_u16(irp, IRP_TYPE);
    memory.write_u16(irp + 0x02, irp_guest_size(arch) as u16);
    let (system_buffer_offset, status_offset, information_offset, stack_pointer_offset) = match arch
    {
        GuestArch::X64 => (0x18, 0x30, 0x40, 0x98),
        GuestArch::X86 => (0x0C, 0x18, 0x20, 0x4C),
    };
    write_guest_pointer(memory, irp + system_buffer_offset, system_buffer, arch)?;
    memory.write_u32(irp + status_offset, STATUS_SUCCESS as u32);
    write_guest_pointer(
        memory,
        irp + status_offset + arch.pointer_bytes() as u64,
        0,
        arch,
    )?;
    write_guest_pointer(memory, irp + information_offset, 0, arch)?;
    let requestor_mode_offset = match arch {
        GuestArch::X64 => 0x48,
        GuestArch::X86 => 0x24,
    };
    memory.write_u8(irp + requestor_mode_offset, 1);
    let user_buffer_offset = match arch {
        GuestArch::X64 => 0x78,
        GuestArch::X86 => 0x40,
    };
    write_guest_pointer(memory, irp + user_buffer_offset, user_buffer, arch)?;
    write_guest_pointer(memory, irp + stack_pointer_offset, stack, arch)?;

    memory.write_u8(stack, major.code());
    memory.write_u8(stack + 1, minor);
    memory.write_u8(stack + 2, 0);
    memory.write_u8(stack + 3, 0);
    match arch {
        GuestArch::X64 => {
            match major {
                IrpMajorFunction::Power => {
                    memory.write_u32(stack + 0x08, POWER_STATE_TYPE_DEVICE);
                    memory.write_u32(stack + 0x10, power_state.unwrap_or(WDF_POWER_DEVICE_D0));
                }
                IrpMajorFunction::DeviceControl => {
                    memory.write_u32(stack + 0x08, output_length);
                    memory.write_u32(stack + 0x10, input_length);
                    memory.write_u32(stack + 0x18, io_control_code);
                    write_guest_pointer(memory, stack + 0x20, system_buffer, arch)?;
                }
                IrpMajorFunction::Read | IrpMajorFunction::Write => {
                    memory.write_u32(stack + 0x08, output_length.max(input_length));
                    memory.write_u32(stack + 0x0C, 0);
                    memory.write_u64(stack + 0x10, byte_offset);
                }
                _ => {}
            }
            write_guest_pointer(memory, stack + 0x20, device_object, arch)?;
        }
        GuestArch::X86 => {
            match major {
                IrpMajorFunction::Power => {
                    memory.write_u32(stack + 0x04, POWER_STATE_TYPE_DEVICE);
                    memory.write_u32(stack + 0x08, power_state.unwrap_or(WDF_POWER_DEVICE_D0));
                }
                IrpMajorFunction::DeviceControl => {
                    memory.write_u32(stack + 0x04, output_length);
                    memory.write_u32(stack + 0x08, input_length);
                    memory.write_u32(stack + 0x0C, io_control_code);
                    write_guest_pointer(memory, stack + 0x10, system_buffer, arch)?;
                }
                IrpMajorFunction::Read | IrpMajorFunction::Write => {
                    memory.write_u32(stack + 0x04, output_length.max(input_length));
                    memory.write_u32(stack + 0x08, 0);
                    memory.write_u64(stack + 0x0C, byte_offset);
                }
                _ => {}
            }
            write_guest_pointer(memory, stack + 0x14, device_object, arch)?;
        }
    }
    Ok(())
}

impl IslandState {
    pub(crate) fn write_outer_irp_status(
        &self,
        memory: &mut MemoryImage,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        self.write_irp_status(memory, self.kmdf.current_irp_guest, status, information)
    }

    pub(crate) fn write_irp_status(
        &self,
        memory: &mut MemoryImage,
        irp: u64,
        status: i32,
        information: usize,
    ) -> AppResult<()> {
        if irp == 0 {
            return Ok(());
        }
        let (status_offset, information_offset) = match self.arch {
            GuestArch::X64 => (0x30, 0x40),
            GuestArch::X86 => (0x18, 0x20),
        };
        memory.write_u32(irp + status_offset, status as u32);
        write_guest_pointer(
            memory,
            irp + information_offset,
            information as u64,
            self.arch,
        )
    }
}
