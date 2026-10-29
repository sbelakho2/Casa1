//! KMDF object model.

use super::*;

impl IslandState {
    pub(crate) fn wdf_driver_create(
        &mut self,
        runtime: &mut PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let driver_object = guest_arg(state, memory, 0)?;
        let _registry_path = guest_arg(state, memory, 1)?;
        let attributes = guest_arg(state, memory, 2)?;
        let config = guest_arg(state, memory, 3)?;
        let driver_out = guest_arg(state, memory, 4)?;
        if driver_object != self.driver_object_guest
            || driver_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                driver_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let (size_offset, add_offset, unload_offset, tag_offset, flags_offset, minimum_size) =
            match self.arch {
                GuestArch::X64 => (0u64, 8u64, 0x10u64, 0x18u64, 0x1Cu64, 0x20u64),
                GuestArch::X86 => (0, 4, 8, 0xC, 0x10, 0x14),
            };
        let mut evt_device_add = 0;
        let mut evt_driver_unload = 0;
        let mut driver_pool_tag = 0;
        let mut driver_init_flags = 0;
        if config != 0 {
            if crate::host_thunks::validate_guest_pointer(memory, config, minimum_size as usize)
                .is_err()
            {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(None);
            }
            let size = memory.read_u32(config + size_offset)? as u64;
            if size < minimum_size {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(None);
            }
            evt_device_add = read_guest_pointer(memory, config + add_offset, self.arch)?;
            if size >= unload_offset + self.arch.pointer_bytes() as u64 {
                evt_driver_unload = read_guest_pointer(memory, config + unload_offset, self.arch)?;
            } // coverage: unreachable — size >= minimum_size (0x20/0x14) always covers the 0x18/0x0C unload offset
            if size >= tag_offset + 4 {
                driver_pool_tag = memory.read_u32(config + tag_offset)?;
            } // coverage: unreachable — size >= minimum_size (0x20/0x14) always covers the 0x1C/0x10 tag offset
            if size >= flags_offset + 4 {
                driver_init_flags = memory.read_u32(config + flags_offset)?;
            } // coverage: unreachable — size >= minimum_size equals the 0x20/0x14 flags end, so this condition is always true
        }

        let dispatches = [
            (IrpMajorFunction::Read, DriverShim::WdfEvtIoReadDispatch),
            (IrpMajorFunction::Write, DriverShim::WdfEvtIoWriteDispatch),
            (
                IrpMajorFunction::DeviceControl,
                DriverShim::WdfEvtIoDeviceControlDispatch,
            ),
            (
                IrpMajorFunction::Cleanup,
                DriverShim::WdfEvtIoCleanupDispatch,
            ),
            (IrpMajorFunction::Close, DriverShim::WdfEvtIoCloseDispatch),
            (IrpMajorFunction::Pnp, DriverShim::WdfEvtPnpDispatch),
            (IrpMajorFunction::Power, DriverShim::WdfEvtPowerDispatch),
        ];
        // `WdfDriverInitNoDispatchOverride` leaves the driver's own
        // MajorFunction table untouched.
        if driver_init_flags & 0x2 == 0 {
            for (major, shim) in dispatches {
                let address = if let Some(address) =
                    self.kmdf.framework_dispatches.get(&major.code()).copied()
                {
                    address
                } else {
                    let address = allocate_shim(runtime, shim);
                    self.kmdf.framework_dispatches.insert(major.code(), address);
                    address
                };
                if major == IrpMajorFunction::DeviceControl {
                    self.kmdf.framework_dispatch = address;
                }
                let major_offset = major_function_offset(self.arch)
                    + major.code() as u64 * self.arch.pointer_bytes() as u64;
                write_guest_pointer(memory, driver_object + major_offset, address, self.arch)?;
            }
        }

        let driver_handle = self.create_kmdf_object(memory, KmdfObjectKind::Driver, attributes)?;
        self.kmdf.driver_handle = driver_handle;
        self.kmdf.driver_object_guest = driver_object;
        self.kmdf.evt_driver_device_add = evt_device_add;
        self.kmdf.evt_driver_unload = evt_driver_unload;
        self.kmdf.driver_pool_tag = driver_pool_tag;
        self.kmdf.driver_init_flags = driver_init_flags;
        write_guest_pointer(memory, driver_out, driver_handle, self.arch)?;
        if evt_device_add == 0 {
            set_status(state, STATUS_SUCCESS);
            return Ok(None);
        }
        let device_init = self.create_kmdf_object(memory, KmdfObjectKind::DeviceInit, 0)?;
        if let Some(object) = self.kmdf.objects.get_mut(&device_init) {
            object.parent = Some(driver_handle);
        }
        if let Some(driver) = self.kmdf.objects.get_mut(&driver_handle) {
            driver.children.insert(device_init);
        }
        self.kmdf.device_inits.insert(
            device_init,
            KmdfDeviceInit {
                device_type: 0,
                io_type: 0,
                name: None,
                pnp_power: KmdfPnpPowerCallbacks::default(),
                file_object: KmdfFileObjectConfig::default(),
                is_pdo: false,
                power_policy_owner: false,
                parent_device: None,
                device_id: None,
                hardware_ids: Vec::new(),
                compatible_ids: Vec::new(),
                instance_id: None,
                is_control: false,
            },
        );
        Ok(Some(PendingGuestCall {
            entry: evt_device_add,
            args: vec![driver_handle, device_init],
            label: "EvtDriverDeviceAdd",
            purpose: PendingPurpose::DriverDeviceAdd,
        }))
    }

    pub(crate) fn wdf_device_init_set_device_type(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let device_type = guest_arg(state, memory, 1)? as u32;
        match self.kmdf.device_inits.get_mut(&init) {
            Some(init) => {
                init.device_type = device_type;
                set_status(state, STATUS_SUCCESS);
            }
            None => set_status(state, STATUS_INVALID_PARAMETER),
        }
        Ok(())
    }

    pub(crate) fn wdf_device_init_set_io_type(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let io_type = guest_arg(state, memory, 1)? as u32;
        match self.kmdf.device_inits.get_mut(&init) {
            Some(init) => {
                init.io_type = io_type;
                set_status(state, STATUS_SUCCESS);
            }
            None => set_status(state, STATUS_INVALID_PARAMETER),
        }
        Ok(())
    }

    pub(crate) fn wdf_device_init_assign_name(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let name = guest_arg(state, memory, 1)?;
        let (text, _, _) = read_unicode_string(memory, name, self.arch)?;
        match self.kmdf.device_inits.get_mut(&init) {
            Some(init) => {
                init.name = (!text.is_empty()).then_some(text);
                set_status(state, STATUS_SUCCESS);
            }
            None => set_status(state, STATUS_INVALID_PARAMETER),
        }
        Ok(())
    }

    pub(crate) fn wdf_device_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let init_argument = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let device_out = guest_arg(state, memory, 2)?;
        if device_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                device_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // Accept both `&DeviceInit` (the documented KMDF form) and the init
        // handle itself.
        let mut init_handle = init_argument;
        if let Ok(value) = read_guest_pointer(memory, init_argument, self.arch) {
            if self.kmdf.device_inits.contains_key(&value) {
                init_handle = value;
            }
        }
        let Some(init) = self.kmdf.device_inits.get(&init_handle).cloned() else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        // A control device named `\DosDevices\<link>` (or `\??\<link>`)
        // creates the device under `\Device\<link>` and registers the
        // symbolic link — the KMDF control-device helper contract.
        let control_link = init
            .name
            .as_deref()
            .and_then(|name| {
                name.strip_prefix("\\DosDevices\\")
                    .or_else(|| name.strip_prefix("\\??\\"))
                    .filter(|link| !link.is_empty())
                    .map(str::to_string)
            })
            .map(|link| {
                let target = format!("\\Device\\{link}");
                (link, target)
            });
        let device_name = match &control_link {
            Some((_, target)) => Some(target.clone()),
            None => init.name.clone(),
        };
        let guest =
            match self.create_device_object(memory, device_name, 0, init.device_type, false)? {
                Ok(guest) => guest,
                Err(status) => {
                    set_status(state, status);
                    return Ok(());
                }
            };
        let casak = *self
            .device_ids
            .get(&guest)
            .expect("island device ids are inserted before their guest handle is returned");
        let name = self
            .devices
            .iter()
            .rev()
            .find(|device| device.guest_pointer == guest)
            .map(|device| device.name.clone())
            .unwrap_or_default();
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Device, attributes)?;
        if self
            .kmdf
            .objects
            .get(&handle)
            .is_some_and(|object| object.parent.is_none())
        {
            let parent = init
                .parent_device
                .filter(|parent| self.kmdf.devices.contains_key(parent))
                .unwrap_or(self.kmdf.driver_handle);
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
        self.kmdf.devices.insert(
            handle,
            KmdfDevice {
                object_guest: guest,
                casak,
                name,
                context_guest,
                pnp_power: init.pnp_power,
                file_cleanup: init.file_object.evt_file_cleanup,
                file_close: init.file_object.evt_file_close,
                file_object: 0,
                power_state: WDF_POWER_DEVICE_D3,
                started: false,
                removed: false,
                surprised: false,
                idle: false,
                idle_refs: 0,
                device_id: init.device_id,
                hardware_ids: init.hardware_ids,
                compatible_ids: init.compatible_ids,
                instance_id: init.instance_id,
                is_control: init.is_control,
                control_finished: false,
            },
        );
        self.kmdf.devices_by_object.insert(guest, handle);
        if let Some((link, target)) = control_link {
            if !self
                .symbolic_links
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(&link))
            {
                self.symbolic_links
                    .push((format!("\\DosDevices\\{link}"), target));
                self.kmdf.symbolic_links_created += 1;
            }
        }
        write_guest_pointer(memory, device_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Attach a newly created KMDF object to its device when the caller did
    /// not specify a pre-existing parent.
    pub(crate) fn attach_kmdf_parent(&mut self, handle: u64, device: u64) {
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            if object.parent.is_none() {
                object.parent = Some(device);
                if let Some(parent) = self.kmdf.objects.get_mut(&device) {
                    parent.children.insert(handle);
                }
            }
        }
    }

    pub(crate) fn wdf_device_wdm_get_device_object(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        match self.kmdf.devices.get(&device) {
            Some(device) => state.set(Register::Rax, device.object_guest),
            None => set_status(state, STATUS_INVALID_HANDLE),
        }
        Ok(())
    }

    /// `WdfControlDeviceInitAllocate`: allocates a `WDFDEVICE_INIT` for a
    /// non-PnP control device.
    pub(crate) fn wdf_control_device_init_allocate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let driver = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        if driver != self.kmdf.driver_handle {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        let init = self.create_kmdf_object(memory, KmdfObjectKind::DeviceInit, attributes)?;
        if let Some(object) = self.kmdf.objects.get_mut(&init) {
            object.parent = Some(driver);
        }
        if let Some(object) = self.kmdf.objects.get_mut(&driver) {
            object.children.insert(init);
        }
        self.kmdf.device_inits.insert(
            init,
            KmdfDeviceInit {
                device_type: 0,
                io_type: 0,
                name: None,
                pnp_power: KmdfPnpPowerCallbacks::default(),
                file_object: KmdfFileObjectConfig::default(),
                is_pdo: false,
                power_policy_owner: false,
                parent_device: None,
                device_id: None,
                hardware_ids: Vec::new(),
                compatible_ids: Vec::new(),
                instance_id: None,
                is_control: true,
            },
        );
        state.set(Register::Rax, init);
        Ok(())
    }

    /// `WdfControlFinishInitializing`: marks a control device ready; a
    /// double finish or a non-control device fails with
    /// `STATUS_INVALID_DEVICE_STATE`.
    pub(crate) fn wdf_control_finish_initializing(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(device, KmdfObjectKind::Device) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .devices
            .get_mut(&device)
            .expect("device was validated");
        if !record.is_control || record.removed || record.control_finished {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        record.control_finished = true;
        self.kmdf.control_devices_finished += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Parse `WDF_FILEOBJECT_CONFIG`: EvtFileCleanup/EvtFileClose map onto
    /// `IRP_MJ_CLEANUP`/`IRP_MJ_CLOSE` dispatch.
    pub(crate) fn wdf_device_init_set_file_object_config(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let config = guest_arg(state, memory, 1)?;
        let _attributes = guest_arg(state, memory, 2)?;
        if !self.kmdf.device_inits.contains_key(&init)
            || config == 0
            || crate::host_thunks::validate_guest_pointer(memory, config, 4).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let size = memory.read_u32(config)? as u64;
        let minimum = match self.arch {
            GuestArch::X64 => 0x10,
            GuestArch::X86 => 0x08,
        };
        if size < minimum {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let pointer = self.arch.pointer_bytes() as u64;
        let (close_offset, cleanup_offset) = match self.arch {
            GuestArch::X64 => (0x10, 0x18),
            GuestArch::X86 => (0x08, 0x0C),
        };
        let evt_file_close = if size >= close_offset + pointer {
            read_guest_pointer(memory, config + close_offset, self.arch)?
        } else {
            0
        };
        let evt_file_cleanup = if size >= cleanup_offset + pointer {
            read_guest_pointer(memory, config + cleanup_offset, self.arch)?
        } else {
            0
        };
        let init = self
            .kmdf
            .device_inits
            .get_mut(&init)
            .expect("device init was validated above");
        init.file_object = KmdfFileObjectConfig {
            evt_file_cleanup,
            evt_file_close,
        };
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfPdoInitAllocate`: mint a PDO device-init owned by `parent`.
    pub(crate) fn wdf_pdo_init_allocate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let parent = guest_arg(state, memory, 0)?;
        if !self.kmdf.devices.contains_key(&parent) {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        let init = self.create_kmdf_object(memory, KmdfObjectKind::DeviceInit, 0)?;
        if let Some(object) = self.kmdf.objects.get_mut(&init) {
            object.parent = Some(parent);
        }
        if let Some(object) = self.kmdf.objects.get_mut(&parent) {
            object.children.insert(init);
        }
        self.kmdf.device_inits.insert(
            init,
            KmdfDeviceInit {
                device_type: 0,
                io_type: 0,
                name: None,
                pnp_power: KmdfPnpPowerCallbacks::default(),
                file_object: KmdfFileObjectConfig::default(),
                is_pdo: true,
                power_policy_owner: false,
                parent_device: Some(parent),
                device_id: None,
                hardware_ids: Vec::new(),
                compatible_ids: Vec::new(),
                instance_id: None,
                is_control: false,
            },
        );
        state.set(Register::Rax, init);
        Ok(())
    }

    /// `WdfPdoInitAssignDeviceID`/`WdfPdoInitAssignInstanceID`.
    pub(crate) fn wdf_pdo_init_set_id(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        instance: bool,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let string = guest_arg(state, memory, 1)?;
        let Some(text) = self.read_valid_unicode_string(memory, string) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if text.is_empty() || text.len() > 0x100 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(record) = self.kmdf.device_inits.get_mut(&init) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if !record.is_pdo {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if instance {
            record.instance_id = Some(text);
        } else {
            record.device_id = Some(text);
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfPdoInitAddHardwareID`/`WdfPdoInitAddCompatibleID`.
    pub(crate) fn wdf_pdo_init_add_id(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        compatible: bool,
    ) -> AppResult<()> {
        let init = guest_arg(state, memory, 0)?;
        let string = guest_arg(state, memory, 1)?;
        let Some(text) = self.read_valid_unicode_string(memory, string) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if text.is_empty() || text.len() > 0x100 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(record) = self.kmdf.device_inits.get_mut(&init) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if !record.is_pdo {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let list = if compatible {
            &mut record.compatible_ids
        } else {
            &mut record.hardware_ids
        };
        if list.len() >= 16 {
            set_status(state, STATUS_INSUFFICIENT_RESOURCES);
            return Ok(());
        }
        list.push(text);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}
