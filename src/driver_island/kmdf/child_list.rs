//! KMDF object model.

use super::*;

impl IslandState {
    /// Create the child PDO that materializes an arrived bus child.  The
    /// instance ID is derived from the identification description so PnP
    /// identity is stable across scans.  Returns `Err(status)` when the
    /// underlying device allocation fails.
    pub(crate) fn create_kmdf_child_pdo(
        &mut self,
        memory: &mut MemoryImage,
        list: u64,
        description: u64,
    ) -> AppResult<Result<u64, i32>> {
        let fdo = self
            .kmdf
            .child_lists
            .get(&list)
            .map(|record| record.device)
            .unwrap_or(self.kmdf.driver_handle);
        let instance = format!("CasaChild{description:X}");
        let guest = match self.create_device_object(memory, Some(instance), 0, 0, false)? {
            Ok(guest) => guest,
            Err(status) => return Ok(Err(status)),
        };
        let casak = *self
            .device_ids
            .get(&guest)
            .expect("child device ids are inserted with their guest handle");
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Device, 0)?;
        if let Some(object) = self.kmdf.objects.get_mut(&handle) {
            object.parent = Some(fdo);
        }
        if let Some(object) = self.kmdf.objects.get_mut(&fdo) {
            object.children.insert(handle);
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
                name: format!("\\Device\\CasaChild{description:X}"),
                context_guest,
                pnp_power: KmdfPnpPowerCallbacks::default(),
                file_cleanup: 0,
                file_close: 0,
                file_object: 0,
                power_state: WDF_POWER_DEVICE_D0,
                started: true,
                removed: false,
                surprised: false,
                idle: false,
                idle_refs: 0,
                device_id: None,
                hardware_ids: Vec::new(),
                compatible_ids: Vec::new(),
                instance_id: None,
                is_control: false,
                control_finished: false,
            },
        );
        self.kmdf.devices_by_object.insert(guest, handle);
        Ok(Ok(handle))
    }

    /// `WdfChildListCreate`.
    pub(crate) fn wdf_child_list_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let config = guest_arg(state, memory, 2)?;
        let list_out = guest_arg(state, memory, 3)?;
        if !self.kmdf.devices.contains_key(&device)
            || list_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                list_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let mut evt_enumerate_children = 0u64;
        if config != 0 {
            let pointer = self.arch.pointer_bytes() as u64;
            let callback_offset = match self.arch {
                GuestArch::X64 => 8,
                GuestArch::X86 => 4,
            };
            let size = match crate::host_thunks::validate_guest_pointer(memory, config, 4) {
                Ok(()) => u64::from(memory.read_u32(config)?),
                Err(_) => {
                    set_status(state, STATUS_INVALID_PARAMETER);
                    return Ok(());
                }
            };
            // `WDF_CHILD_LIST_CONFIG`: u32 Size, then padding to the
            // pointer alignment, then `EvtChildListEnumerateChildren`.
            if size >= callback_offset + pointer {
                evt_enumerate_children =
                    read_guest_pointer(memory, config + callback_offset, self.arch)?;
            }
        }
        if evt_enumerate_children == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::ChildList, attributes)?;
        self.attach_kmdf_parent(handle, device);
        self.kmdf.child_lists.insert(
            handle,
            KmdfChildList {
                device,
                evt_enumerate_children,
                descriptions: Vec::new(),
                arrivals: 0,
                removals: 0,
            },
        );
        write_guest_pointer(memory, list_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfChildListGetFirst`: creates an iterator at position zero.
    pub(crate) fn wdf_child_list_get_first(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let list = guest_arg(state, memory, 0)?;
        let iterator_out = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(list, KmdfObjectKind::ChildList) {
            set_status(state, status);
            return Ok(());
        }
        if iterator_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                iterator_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::ChildIterator, 0)?;
        // The iterator belongs to the child list's device, not the list
        // itself, so deleting the list leaves a stale iterator behind for
        // the removal sweep to invalidate.
        let device = self
            .kmdf
            .child_lists
            .get(&list)
            .map(|record| record.device)
            .unwrap_or(self.kmdf.driver_handle);
        self.attach_kmdf_parent(handle, device);
        self.kmdf
            .child_iterators
            .insert(handle, KmdfChildIterator { list, position: 0 });
        write_guest_pointer(memory, iterator_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfChildListGetNext`: returns the next identification description
    /// handle in Rax, or 0 at the end of iteration.
    pub(crate) fn wdf_child_list_get_next(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let iterator = guest_arg(state, memory, 0)?;
        let child_out = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(iterator, KmdfObjectKind::ChildIterator) {
            set_status(state, status);
            return Ok(());
        }
        let Some(record) = self.kmdf.child_iterators.get_mut(&iterator) else {
            // The child list was deleted and the stale-iterator sweep
            // dropped this iterator's position.
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let next = self
            .kmdf
            .child_lists
            .get(&record.list)
            .and_then(|list| list.descriptions.get(record.position).copied());
        match next {
            Some(description) => {
                record.position += 1;
                if child_out != 0 {
                    write_guest_pointer(memory, child_out, description, self.arch)?;
                }
                state.set(Register::Rax, 1);
            }
            None => state.set(Register::Rax, 0),
        }
        Ok(())
    }

    /// `WdfChildListGetChildCount`.
    pub(crate) fn wdf_child_list_get_count(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let list = guest_arg(state, memory, 0)?;
        match self.kmdf_expect_kind(list, KmdfObjectKind::ChildList) {
            Ok(()) => {}
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        }
        let record = self
            .kmdf
            .child_lists
            .get(&list)
            .expect("child list was validated");
        state.set(Register::Rax, record.descriptions.len() as u64);
        Ok(())
    }

    /// `WdfEvtChildListScanDispatch`: runs `EvtChildListEnumerateChildren`
    /// with a temporary `WDFCOLLECTION`; the completion applies the PnP
    /// arrival/removal diff.
    pub(crate) fn wdf_child_list_scan(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<PendingGuestCall>> {
        let list = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(list, KmdfObjectKind::ChildList) {
            set_status(state, status);
            return Ok(None);
        }
        let (enumerate, device) = {
            let record = self
                .kmdf
                .child_lists
                .get(&list)
                .expect("child list was validated");
            (record.evt_enumerate_children, record.device)
        };
        let collection = self.create_kmdf_object(memory, KmdfObjectKind::Collection, 0)?;
        self.attach_kmdf_parent(collection, list);
        self.kmdf.collections.insert(
            collection,
            KmdfCollection {
                items: Vec::new(),
                max_size: 1024,
            },
        );
        let _ = device;
        set_status(state, STATUS_SUCCESS);
        Ok(Some(PendingGuestCall {
            entry: enumerate,
            args: vec![list, collection],
            label: "EvtChildListEnumerateChildren",
            purpose: PendingPurpose::ChildListScan { list, collection },
        }))
    }

    /// `WdfCmResourceListCreate`: allocates a guest-visible
    /// `CM_PARTIAL_RESOURCE_LIST` with `descriptor_count` partial resource
    /// descriptors.
    pub(crate) fn wdf_cm_resource_list_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let descriptor_count = guest_arg(state, memory, 1)? as usize;
        let list_out = guest_arg(state, memory, 2)?;
        if descriptor_count == 0
            || descriptor_count > 64
            || list_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                list_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // `CM_PARTIAL_RESOURCE_LIST`: u32 Version, u32 Revision, u32 Count,
        // then `CM_PARTIAL_RESOURCE_DESCRIPTOR` records (16 bytes each).
        let bytes = 12 + descriptor_count * 16;
        let guest = self.arena.alloc(memory, bytes, 8)?;
        memory.map_bytes(guest, &vec![0_u8; bytes]);
        memory.write_u32(guest, 2);
        memory.write_u32(guest + 4, 1);
        memory.write_u32(guest + 8, descriptor_count as u32);
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::CmResourceList, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        self.kmdf.cm_resource_lists.insert(
            handle,
            KmdfCmResourceList {
                guest,
                descriptors: descriptor_count,
            },
        );
        write_guest_pointer(memory, list_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfCmResourceListGetDescriptor`: returns the guest pointer of the
    /// descriptor at `index`, or NULL for an out-of-range index.
    pub(crate) fn wdf_cm_resource_list_get_descriptor(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let list = guest_arg(state, memory, 0)?;
        let index = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(list, KmdfObjectKind::CmResourceList) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .cm_resource_lists
            .get(&list)
            .expect("resource list was validated");
        let descriptor = usize::try_from(index)
            .ok()
            .filter(|index| *index < record.descriptors)
            .map(|index| record.guest + 12 + (index as u64) * 16)
            .unwrap_or(0);
        // Returns the descriptor pointer (or NULL) in Rax.
        state.set(Register::Rax, descriptor);
        Ok(())
    }

    /// `WdfCmResourceListGetCount`.
    pub(crate) fn wdf_cm_resource_list_get_count(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let list = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(list, KmdfObjectKind::CmResourceList) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .cm_resource_lists
            .get(&list)
            .expect("resource list was validated");
        state.set(Register::Rax, record.descriptors as u64);
        Ok(())
    }
}
