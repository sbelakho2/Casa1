//! KMDF object model.

use super::*;

impl IslandState {
    /// `WdfUsbTargetDeviceCreate`: parses a real USB configuration
    /// descriptor (interface and endpoint descriptors) supplied through the
    /// island's `WDF_USB_DEVICE_CREATE_CONFIG` layout: `Size` (u32),
    /// `UsbVersion` (u16), `VendorId` (u16), `ProductId` (u16), and — at the
    /// first pointer-aligned offset — a pointer to a raw configuration
    /// descriptor whose `wTotalLength` bytes are validated.
    pub(crate) fn wdf_usb_target_device_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let device = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let config = guest_arg(state, memory, 2)?;
        let usb_out = guest_arg(state, memory, 3)?;
        if !self.kmdf.devices.contains_key(&device)
            || usb_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                usb_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let mut usb_version = 0x0200u16;
        let mut vendor_id = 0u16;
        let mut product_id = 0u16;
        let mut endpoints = Vec::new();
        if config != 0 {
            let pointer = self.arch.pointer_bytes() as u64;
            if crate::host_thunks::validate_guest_pointer(memory, config, 16).is_err() {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            let size = memory.read_u32(config)?;
            if size < 16 {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            usb_version = memory.read_u16(config + 4)?;
            vendor_id = memory.read_u16(config + 6)?;
            product_id = memory.read_u16(config + 8)?;
            // The raw configuration-descriptor pointer follows the fixed
            // header at the first pointer-aligned offset.
            let descriptor_pointer = if u64::from(size) >= 16 + pointer {
                read_guest_pointer(memory, config + 16, self.arch)?
            } else {
                0
            };
            if descriptor_pointer != 0 {
                match self.parse_usb_configuration(memory, descriptor_pointer) {
                    Ok(parsed) => endpoints = parsed,
                    Err(status) => {
                        set_status(state, status);
                        return Ok(());
                    }
                }
            }
        }
        if endpoints.is_empty() {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::UsbTarget, attributes)?;
        self.attach_kmdf_parent(handle, device);
        self.kmdf.usb_targets.insert(
            handle,
            KmdfUsbTarget {
                device,
                usb_version,
                vendor_id,
                product_id,
                endpoints,
                stalled: BTreeSet::new(),
                aborted: BTreeSet::new(),
                staged: BTreeMap::new(),
                transfers: 0,
                transferred_bytes: 0,
            },
        );
        write_guest_pointer(memory, usb_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Parse a raw USB configuration descriptor (`USB_CONFIGURATION_
    /// DESCRIPTOR` + `USB_INTERFACE_DESCRIPTOR` + `USB_ENDPOINT_DESCRIPTOR`
    /// records) into the endpoint table.  Malformed lengths, wrong
    /// descriptor types, out-of-range endpoint numbers, and control
    /// endpoint zero are rejected with the exact status.
    pub(crate) fn parse_usb_configuration(
        &self,
        memory: &MemoryImage,
        start: u64,
    ) -> Result<Vec<KmdfUsbEndpoint>, i32> {
        const USB_DT_CONFIG: u8 = 2;
        const USB_DT_INTERFACE: u8 = 4;
        const USB_DT_ENDPOINT: u8 = 5;
        let read_u8 = |offset: u64| {
            memory
                .read_u8(start + offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)
        };
        let read_u16 = |offset: u64| {
            memory
                .read_u16(start + offset)
                .map_err(|_| STATUS_INVALID_PARAMETER)
        };
        if crate::host_thunks::validate_guest_pointer(memory, start, 9).is_err() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if read_u8(0)? != 9 || read_u8(1)? != USB_DT_CONFIG {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let total = u64::from(read_u16(2)?);
        if total < 9 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if crate::host_thunks::validate_guest_pointer(memory, start, total as usize).is_err() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut endpoints = Vec::new();
        let mut offset = 9u64;
        while offset < total {
            let length = u64::from(read_u8(offset)?);
            let descriptor_type = read_u8(offset + 1)?;
            if length < 2 || offset + length > total {
                return Err(STATUS_INVALID_PARAMETER);
            }
            match descriptor_type {
                USB_DT_INTERFACE => {
                    if length < 9 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                }
                USB_DT_ENDPOINT => {
                    if length < 7 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    let address = read_u8(offset + 2)?;
                    // Endpoint zero is the default control endpoint; it is
                    // never a configured pipe.
                    let number = address & 0x0F;
                    if number == 0 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    endpoints.push(KmdfUsbEndpoint {
                        address,
                        attributes: read_u8(offset + 3)?,
                        max_packet: read_u16(offset + 4)?,
                        interval: read_u8(offset + 6)?,
                    });
                    if endpoints.len() > 16 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                }
                _ => {}
            }
            offset += length;
        }
        Ok(endpoints)
    }

    /// `WdfUsbTargetDeviceGetInformation`.
    pub(crate) fn wdf_usb_target_get_information(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let usb = guest_arg(state, memory, 0)?;
        let info_out = guest_arg(state, memory, 1)?;
        if let Err(status) = self.kmdf_expect_kind(usb, KmdfObjectKind::UsbTarget) {
            set_status(state, status);
            return Ok(());
        }
        if info_out == 0
            || crate::host_thunks::validate_guest_pointer(memory, info_out, 16).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let record = self
            .kmdf
            .usb_targets
            .get(&usb)
            .cloned()
            .expect("usb target was validated");
        memory.write_u16(info_out, record.usb_version);
        memory.write_u16(info_out + 2, record.vendor_id);
        memory.write_u16(info_out + 4, record.product_id);
        memory.write_u32(info_out + 8, record.endpoints.len() as u32);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfUsbInterfaceGetConfiguredPipe`: creates a `WDFPIPE` over the
    /// configuration's endpoint at `pipe_index`.
    pub(crate) fn wdf_usb_get_configured_pipe(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let usb = guest_arg(state, memory, 0)?;
        let pipe_index = guest_arg(state, memory, 1)? as u32;
        let pipe_out = guest_arg(state, memory, 2)?;
        let _pipe_info_out = guest_arg(state, memory, 3)?;
        if let Err(status) = self.kmdf_expect_kind(usb, KmdfObjectKind::UsbTarget) {
            set_status(state, status);
            return Ok(());
        }
        if pipe_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                pipe_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let endpoint = {
            let record = self
                .kmdf
                .usb_targets
                .get(&usb)
                .expect("usb target was validated");
            let Some(endpoint) = record.endpoints.get(pipe_index as usize).copied() else {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            };
            endpoint
        };
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::UsbPipe, 0)?;
        self.attach_kmdf_parent(handle, usb);
        self.kmdf.usb_pipes.insert(
            handle,
            KmdfUsbPipe {
                target: usb,
                endpoint_index: pipe_index,
                in_endpoint: endpoint.address & 0x80 != 0,
                bulk: endpoint.attributes & 0x03 == 0x02,
                max_packet: endpoint.max_packet,
            },
        );
        write_guest_pointer(memory, pipe_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Shared body of `WdfUsbTargetPipeReadPipe`/`WritePipe`: validates the
    /// pipe, direction, stall/abort state, and length, then moves data
    /// between the guest buffer and the endpoint's staged device buffer.
    pub(crate) fn wdf_usb_pipe_transfer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        read: bool,
    ) -> AppResult<Option<PendingGuestCall>> {
        let pipe = guest_arg(state, memory, 0)?;
        let request_handle = guest_arg(state, memory, 1)?;
        let buffer = guest_arg(state, memory, 2)?;
        let length = guest_arg(state, memory, 3)? as usize;
        if let Err(status) = self.kmdf_expect_kind(pipe, KmdfObjectKind::UsbPipe) {
            set_status(state, status);
            return Ok(None);
        }
        let pipe_record = *self.kmdf.usb_pipes.get(&pipe).expect("pipe was validated");
        {
            let target = self
                .kmdf
                .usb_targets
                .get(&pipe_record.target)
                .expect("pipe target exists");
            if target.stalled.contains(&pipe_record.endpoint_index) {
                set_status(state, STATUS_INVALID_DEVICE_STATE);
                return Ok(None);
            }
            if target.aborted.contains(&pipe_record.endpoint_index) {
                set_status(state, STATUS_CANCELLED);
                return Ok(None);
            }
        }
        if read && !pipe_record.in_endpoint {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if !read && pipe_record.in_endpoint {
            set_status(state, STATUS_INVALID_DEVICE_REQUEST);
            return Ok(None);
        }
        if length == 0 || length > 0x1_0000 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        if buffer == 0
            || crate::host_thunks::validate_guest_pointer(memory, buffer, length).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(None);
        }
        let endpoint_index = pipe_record.endpoint_index;
        let target = self
            .kmdf
            .usb_targets
            .get_mut(&pipe_record.target)
            .expect("target was validated");
        let moved = if read {
            let staged = target.staged.entry(endpoint_index).or_default();
            let take = length.min(staged.len());
            let bytes: Vec<u8> = staged.drain(..take).collect();
            for (offset, byte) in bytes.iter().enumerate() {
                memory.write_u8(buffer + offset as u64, *byte);
            }
            for offset in take..length {
                memory.write_u8(buffer + offset as u64, 0);
            }
            take
        } else {
            let bytes = (0..length as u64)
                .map(|offset| memory.read_u8(buffer + offset))
                .collect::<AppResult<Vec<_>>>()?;
            let staged = target.staged.entry(endpoint_index).or_default();
            staged.extend_from_slice(&bytes);
            length
        };
        target.transfers += 1;
        target.transferred_bytes += moved as u64;
        self.kmdf.usb_transfers += 1;
        // The transferred length is reported through the request's
        // `Information`, matching the synchronous KMDF pipe APIs.
        if let Some(request) = self.kmdf.requests.get_mut(&request_handle) {
            if !request.completed {
                request.information = moved;
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(None)
    }

    /// `WdfUsbTargetPipeAbortPipe`: subsequent transfers fail with
    /// `STATUS_CANCELLED` until the pipe is reset.
    pub(crate) fn wdf_usb_pipe_abort(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let pipe = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(pipe, KmdfObjectKind::UsbPipe) {
            set_status(state, status);
            return Ok(());
        }
        let pipe_record = *self.kmdf.usb_pipes.get(&pipe).expect("pipe was validated");
        let target = self
            .kmdf
            .usb_targets
            .get_mut(&pipe_record.target)
            .expect("pipe target exists");
        target.aborted.insert(pipe_record.endpoint_index);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfUsbTargetPipeResetPipe`: clears stall and abort state.
    pub(crate) fn wdf_usb_pipe_reset(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let pipe = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(pipe, KmdfObjectKind::UsbPipe) {
            set_status(state, status);
            return Ok(());
        }
        let pipe_record = *self.kmdf.usb_pipes.get(&pipe).expect("pipe was validated");
        let target = self
            .kmdf
            .usb_targets
            .get_mut(&pipe_record.target)
            .expect("pipe target exists");
        target.stalled.remove(&pipe_record.endpoint_index);
        target.aborted.remove(&pipe_record.endpoint_index);
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfUsbTargetPipeGetType`: `WDF_USB_PIPE_TYPE` from the endpoint
    /// attributes (1 Control, 2 Isochronous, 3 Bulk, 4 Interrupt).
    pub(crate) fn wdf_usb_pipe_get_type(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let pipe = guest_arg(state, memory, 0)?;
        if let Err(status) = self.kmdf_expect_kind(pipe, KmdfObjectKind::UsbPipe) {
            set_status(state, status);
            return Ok(());
        }
        let pipe_record = *self.kmdf.usb_pipes.get(&pipe).expect("pipe was validated");
        let target = self
            .kmdf
            .usb_targets
            .get(&pipe_record.target)
            .expect("pipe target exists");
        let attributes = target
            .endpoints
            .get(pipe_record.endpoint_index as usize)
            .expect("pipe endpoint exists")
            .attributes;
        let pipe_type = match attributes & 0x03 {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => 4,
        };
        // `WdfUsbTargetPipeGetType` returns the type in Rax; no status write
        // on the success path.
        state.set(Register::Rax, pipe_type);
        Ok(())
    }
}
