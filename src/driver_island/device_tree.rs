//! Device objects, symbolic links and the device tree.

use super::*;

impl IslandState {
    pub(crate) fn io_create_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let driver_object = guest_arg(state, memory, 0)?;
        let extension_size = guest_arg(state, memory, 1)? as usize;
        let name_pointer = guest_arg(state, memory, 2)?;
        let device_type = guest_arg(state, memory, 3)? as u32;
        let _characteristics = guest_arg(state, memory, 4)? as u32;
        let exclusive = guest_arg(state, memory, 5)? != 0;
        let output_pointer = guest_arg(state, memory, 6)?;
        if driver_object != self.driver_object_guest
            || output_pointer == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                output_pointer,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if extension_size > 0x10_0000 {
            set_status(state, STATUS_INSUFFICIENT_RESOURCES);
            return Ok(());
        }
        let raw_name = if name_pointer != 0 {
            read_unicode_string(memory, name_pointer, self.arch)?.0
        } else {
            String::new()
        };
        let raw_name = (!raw_name.is_empty()).then_some(raw_name);
        match self.create_device_object(memory, raw_name, extension_size, device_type, exclusive)? {
            Ok(guest) => {
                write_guest_pointer(memory, output_pointer, guest, self.arch)?;
                set_status(state, STATUS_SUCCESS);
            }
            Err(status) => set_status(state, status),
        }
        Ok(())
    }

    pub(crate) fn create_device_object(
        &mut self,
        memory: &mut MemoryImage,
        raw_name: Option<String>,
        extension_size: usize,
        device_type: u32,
        exclusive: bool,
    ) -> AppResult<Result<u64, i32>> {
        let driver_object = self.driver_object_guest;
        if driver_object == 0 {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        if extension_size > 0x10_0000 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        let device_name = raw_name
            .as_deref()
            .map(strip_device_prefix)
            .map(str::to_string);
        let mut flags = DeviceFlags::NONE;
        if exclusive {
            flags.insert(DeviceFlags::EXCLUSIVE);
        }
        let extension = DeviceExtension::with_bytes(vec![0_u8; extension_size]);
        let device =
            match self
                .io
                .create_device(self.casak_driver, device_name.as_deref(), extension, flags)
            {
                Ok(id) => id,
                Err(status) => return Ok(Err(status)),
            };

        let guest = match self.arena.alloc(memory, 0x180, 16) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.io.delete_device(device);
                return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
            }
        };
        let extension_guest = if extension_size > 0 {
            match self.arena.alloc(memory, extension_size, 8) {
                Ok(extension_guest) => extension_guest,
                Err(_) => {
                    let _ = self.io.delete_device(device);
                    return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
                }
            }
        } else {
            0
        };
        let arch = self.arch;
        match arch {
            GuestArch::X64 => {
                let previous_head = memory.read_u64(driver_object + 0x08)?;
                memory.write_u16(guest, DEVICE_OBJECT_TYPE);
                memory.write_u16(guest + 0x02, DEVICE_OBJECT_SIZE);
                memory.write_u32(guest + 0x04, 1);
                memory.write_u64(guest + 0x08, driver_object);
                memory.write_u64(guest + 0x10, previous_head);
                memory.write_u64(guest + 0x18, 0);
                memory.write_u64(guest + 0x20, 0);
                memory.write_u64(guest + 0x28, 0);
                memory.write_u32(guest + 0x30, 0);
                memory.write_u32(guest + 0x34, 0);
                memory.write_u64(guest + 0x38, 0);
                memory.write_u64(guest + 0x40, extension_guest);
                memory.write_u32(guest + 0x48, device_type);
                memory.write_u8(guest + 0x4C, 1);
                memory.write_u64(driver_object + 0x08, guest);
            }
            GuestArch::X86 => {
                let previous_head = read_guest_pointer(memory, driver_object + 0x04, arch)?;
                memory.write_u16(guest, DEVICE_OBJECT_TYPE);
                memory.write_u16(guest + 0x02, DEVICE_OBJECT_SIZE_X86);
                memory.write_u32(guest + 0x04, 1);
                write_guest_pointer(memory, guest + 0x08, driver_object, arch)?;
                write_guest_pointer(memory, guest + 0x0C, previous_head, arch)?;
                write_guest_pointer(memory, guest + 0x10, 0, arch)?;
                write_guest_pointer(memory, guest + 0x14, 0, arch)?;
                write_guest_pointer(memory, guest + 0x18, 0, arch)?;
                memory.write_u32(guest + 0x1C, 0);
                memory.write_u32(guest + 0x20, 0);
                write_guest_pointer(memory, guest + 0x24, 0, arch)?;
                write_guest_pointer(memory, guest + 0x28, extension_guest, arch)?;
                memory.write_u32(guest + 0x2C, device_type);
                memory.write_u8(guest + 0x30, 1);
                write_guest_pointer(memory, driver_object + 0x04, guest, arch)?;
            }
        }

        let full_name = device_name
            .as_deref()
            .map(|name| format!("\\Device\\{name}"))
            .unwrap_or_default();
        self.devices.push(IslandDevice {
            name: full_name,
            guest_pointer: guest,
            deleted: false,
        });
        self.device_ids.insert(guest, device);
        Ok(Ok(guest))
    }

    pub(crate) fn io_delete_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        let Some(device) = self.device_ids.remove(&guest) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let status = match self.io.delete_device(device) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        };
        if status == STATUS_SUCCESS {
            if let Some(record) = self
                .devices
                .iter_mut()
                .find(|record| record.guest_pointer == guest)
            {
                record.deleted = true;
            }
            self.rebuild_device_chain(memory)?;
        }
        set_status(state, status);
        Ok(())
    }

    pub(crate) fn rebuild_device_chain(&self, memory: &mut MemoryImage) -> AppResult<()> {
        let arch = self.arch;
        let link_offset = match arch {
            GuestArch::X86 => 0x0C,
            GuestArch::X64 => 0x10,
        };
        let head_offset = match arch {
            GuestArch::X86 => 0x04,
            GuestArch::X64 => 0x08,
        };
        let mut next = 0_u64;
        for device in self.devices.iter().rev() {
            if device.deleted || device.guest_pointer == 0 {
                continue;
            }
            write_guest_pointer(memory, device.guest_pointer + link_offset, next, arch)?;
            next = device.guest_pointer;
        }
        write_guest_pointer(memory, self.driver_object_guest + head_offset, next, arch)
    }

    pub(crate) fn io_create_symbolic_link(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let link_pointer = guest_arg(state, memory, 0)?;
        let target_pointer = guest_arg(state, memory, 1)?;
        let link = read_unicode_string(memory, link_pointer, self.arch)?.0;
        let target = read_unicode_string(memory, target_pointer, self.arch)?.0;
        if link.is_empty() || target.is_empty() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if self
            .symbolic_links
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(&link))
        {
            set_status(state, STATUS_OBJECT_NAME_COLLISION);
            return Ok(());
        }
        self.symbolic_links.push((link, target));
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn io_delete_symbolic_link(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let link_pointer = guest_arg(state, memory, 0)?;
        let link = read_unicode_string(memory, link_pointer, self.arch)?.0;
        let before = self.symbolic_links.len();
        self.symbolic_links
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(&link));
        if self.symbolic_links.len() == before {
            set_status(state, STATUS_OBJECT_NAME_NOT_FOUND);
        } else {
            set_status(state, STATUS_SUCCESS);
        }
        Ok(())
    }
}
