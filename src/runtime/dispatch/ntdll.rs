//! Stage-4 NTDLL dispatch wiring: one dispatch method per Nt*/Rtl* host
//! thunk, called from the `dispatch_import` match arms in
//! `crate::runtime::mod` (this module is a child of the runtime module, so
//! it shares the runtime's guest-memory helpers, error mapping and
//! scheduler machinery).
//!
//! Layer contract (see [`crate::ntdll`]):
//! - NTSTATUS is the ONLY result domain here — `NtStatus` values go into
//!   RAX and IO_STATUS_BLOCKs; nothing crosses into Win32 error codes.
//! - Memory ops go through the canonical VM (`self.vm`) and the checked
//!   accessors; raw pages are materialized ONLY for commit operations.
//! - Waits park through the guest scheduler's wait descriptors
//!   ([`GuestWait`] + the `parked_wait` epilogue) — never host blocking.

use super::super::*;
use crate::ntdll as nt;
use crate::pe::ImportSymbol;

impl PeHostRuntime {
    /// The SHARED device/IOCTL dispatch: the Win32 `DeviceIoControl` thunk
    /// and the Nt* `NtDeviceIoControlFile` thunk route through this one
    /// table (one device dispatch — never two).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_device_io_control_common(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        handle: u32,
        io_code: u32,
        _in_buffer: u64,
        _in_size: u32,
        out_buffer: u64,
        out_size: u32,
        bytes_ret_ptr: u64,
    ) -> AppResult<()> {
        // Common IOCTL codes used by applications in VM context
        match io_code {
            // FSCTL_SET_SPARSE (mark file as sparse)
            0x000900C4 => {
                if bytes_ret_ptr != 0 {
                    write_u32(memory, bytes_ret_ptr, 0);
                }
                state.set(Register::Rax, 1); // TRUE
            }
            // FSCTL_SET_ZERO_DATA (zero a range in sparse file)
            0x000980C8 => {
                if bytes_ret_ptr != 0 {
                    write_u32(memory, bytes_ret_ptr, 0);
                }
                state.set(Register::Rax, 1); // TRUE
            }
            // IOCTL_DISK_GET_DRIVE_GEOMETRY
            0x00070000 => {
                // DISK_GEOMETRY: Cylinders(8), MediaType(4), TracksPerCylinder(4), SectorsPerTrack(4), BytesPerSector(4) = 24 bytes
                if out_buffer != 0 && out_size >= 24 {
                    write_u64(memory, out_buffer, 1000); // Cylinders
                    write_u32(memory, out_buffer + 8, 0x07); // FixedMedia = 7
                    write_u32(memory, out_buffer + 12, 64); // TracksPerCylinder
                    write_u32(memory, out_buffer + 16, 32); // SectorsPerTrack
                    write_u32(memory, out_buffer + 20, 512); // BytesPerSector
                    if bytes_ret_ptr != 0 {
                        write_u32(memory, bytes_ret_ptr, 24);
                    }
                }
                state.set(Register::Rax, 1); // TRUE
            }
            // IOCTL_CDROM_GET_DRIVE_GEOMETRY
            0x00070004 => {
                if out_buffer != 0 && out_size >= 24 {
                    write_u64(memory, out_buffer, 0); // Cylinders
                    write_u32(memory, out_buffer + 8, 0x02); // RemovableMedia = 2
                    write_u32(memory, out_buffer + 12, 1); // TracksPerCylinder
                    write_u32(memory, out_buffer + 16, 1); // SectorsPerTrack
                    write_u32(memory, out_buffer + 20, 2048); // BytesPerSector (CD-ROM)
                    if bytes_ret_ptr != 0 {
                        write_u32(memory, bytes_ret_ptr, 24);
                    }
                }
                state.set(Register::Rax, 1); // TRUE
            }
            // IOCTL_STORAGE_CHECK_VERIFY2 (check if media is present)
            0x00074000 => {
                if bytes_ret_ptr != 0 {
                    write_u32(memory, bytes_ret_ptr, 0);
                }
                state.set(Register::Rax, 1); // TRUE (media is present)
            }
            // IOCTL_STORAGE_GET_DEVICE_NUMBER
            0x002D0000 => {
                // STORAGE_DEVICE_NUMBER: DeviceType(4), DeviceNumber(4), PartitionNumber(4) = 12 bytes
                if out_buffer != 0 && out_size >= 12 {
                    write_u32(memory, out_buffer, 0x07); // FILE_DEVICE_DISK
                    write_u32(memory, out_buffer + 4, 0); // DeviceNumber
                    write_u32(memory, out_buffer + 8, 1); // PartitionNumber
                    if bytes_ret_ptr != 0 {
                        write_u32(memory, bytes_ret_ptr, 12);
                    }
                }
                state.set(Register::Rax, 1); // TRUE
            }
            // IOCTL_STORAGE_GET_MEDIA_TYPES_EX
            0x000D0004 => {
                // Return minimal DEVICE_MEDIA_INFO
                if out_buffer != 0 && out_size >= 8 {
                    write_u32(memory, out_buffer, 0x0B); // StorageMediaType = FixedMedium
                    write_u32(memory, out_buffer + 4, 0); // DeviceSpecific
                    if bytes_ret_ptr != 0 {
                        write_u32(memory, bytes_ret_ptr, 8);
                    }
                }
                state.set(Register::Rax, 1); // TRUE
            }
            // Unknown/unsupported IOCTL — return FALSE with ERROR_INVALID_FUNCTION
            _ => {
                emit_live_ui_debug(format!(
                    "DeviceIoControl: unhandled IOCTL {io_code:#x} on handle {handle:#x}"
                ));
                if bytes_ret_ptr != 0 {
                    write_u32(memory, bytes_ret_ptr, 0);
                }
                self.last_error = ERROR_INVALID_FUNCTION;
                state.set(Register::Rax, 0); // FALSE
            }
        }
        Ok(())
    }

    // ── Memory: Nt*VirtualMemory ────────────────────────────────────────────

    /// `NtAllocateVirtualMemory` — reserve/commit through the canonical VM
    /// and materialize the committed pages.
    pub(crate) fn dispatch_nt_allocate_virtual_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let base_address_ptr = guest_call_arg(state, memory, 1)?;
        let zero_bits = guest_call_arg_u32(state, memory, 2)?;
        let region_size_ptr = guest_call_arg(state, memory, 3)?;
        let allocation_type = guest_call_arg_u32(state, memory, 4)?;
        let protect = guest_call_arg_u32(state, memory, 5)?;

        let base_in = if base_address_ptr != 0 {
            read_guest_pointer(memory, base_address_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        let size_in = if region_size_ptr != 0 {
            read_guest_pointer(memory, region_size_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        match nt::memory::nt_allocate_virtual_memory(
            self.win32.address_space_mut(),
            base_in,
            zero_bits,
            size_in,
            allocation_type,
            protect,
        ) {
            Ok((base, size)) => {
                if allocation_type & nt::MEM_COMMIT != 0 {
                    memory.map_bytes(base, &vec![0_u8; size as usize]);
                }
                if base_address_ptr != 0 {
                    write_guest_pointer(memory, base_address_ptr, base, self.guest_arch)?;
                }
                if region_size_ptr != 0 {
                    write_guest_pointer(memory, region_size_ptr, size, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtFreeVirtualMemory` — release/decommit through the canonical VM and
    /// unmap the raw pages; the in/out base + size are zeroed on success
    /// (Windows semantics).
    pub(crate) fn dispatch_nt_free_virtual_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let base_address_ptr = guest_call_arg(state, memory, 1)?;
        let region_size_ptr = guest_call_arg(state, memory, 2)?;
        let free_type = guest_call_arg_u32(state, memory, 3)?;

        let base_in = if base_address_ptr != 0 {
            read_guest_pointer(memory, base_address_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        let size_in = if region_size_ptr != 0 {
            read_guest_pointer(memory, region_size_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        match nt::memory::nt_free_virtual_memory(
            self.win32.address_space_mut(),
            base_in,
            size_in,
            free_type,
        ) {
            Ok((_base, range)) => {
                // Unmap the raw pages of the affected range (the canonical
                // VM state is already updated by the layer).
                if range > 0 && base_in != 0 {
                    memory.unmap_range(base_in & crate::vm::VM_PAGE_MASK, range as usize);
                }
                if base_address_ptr != 0 {
                    write_guest_pointer(memory, base_address_ptr, 0, self.guest_arch)?;
                }
                if region_size_ptr != 0 {
                    write_guest_pointer(memory, region_size_ptr, 0, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtProtectVirtualMemory` — page-granular protection change on the
    /// canonical VM; the old protection is reported through
    /// `old_protect_ptr`.
    pub(crate) fn dispatch_nt_protect_virtual_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let base_address_ptr = guest_call_arg(state, memory, 1)?;
        let region_size_ptr = guest_call_arg(state, memory, 2)?;
        let new_protect = guest_call_arg_u32(state, memory, 3)?;
        let old_protect_ptr = guest_call_arg(state, memory, 4)?;

        let base_in = if base_address_ptr != 0 {
            read_guest_pointer(memory, base_address_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        let size_in = if region_size_ptr != 0 {
            read_guest_pointer(memory, region_size_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        match nt::memory::nt_protect_virtual_memory(
            self.win32.address_space_mut(),
            base_in,
            size_in,
            new_protect,
        ) {
            Ok((_range, old_protection)) => {
                if old_protect_ptr != 0 {
                    write_u32(memory, old_protect_ptr, old_protection);
                }
                if region_size_ptr != 0 {
                    write_guest_pointer(memory, region_size_ptr, 0, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryVirtualMemory` (MemoryBasicInformation) — the canonical VM
    /// answers with the coalesced run exactly like the Win32 VirtualQuery.
    pub(crate) fn dispatch_nt_query_virtual_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let address = guest_call_arg(state, memory, 1)?;
        let info_class = guest_call_arg_u32(state, memory, 2)?;
        let buffer = guest_call_arg(state, memory, 3)?;
        let length = guest_call_arg(state, memory, 4)?;
        let return_length_ptr = guest_call_arg(state, memory, 5)?;

        if info_class != 0 {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
            );
            return Ok(());
        }
        const REQUIRED: u64 = 48;
        if length < REQUIRED {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
            );
            return Ok(());
        }
        let info = nt::memory::nt_query_virtual_memory(self.win32.address_space(), address);
        let bytes = info.serialize_x64();
        memory.map_bytes(buffer, &bytes);
        if return_length_ptr != 0 {
            write_guest_pointer(memory, return_length_ptr, REQUIRED, self.guest_arch)?;
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtReadVirtualMemory` — checked read; never creates pages.
    pub(crate) fn dispatch_nt_read_virtual_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let base_address = guest_call_arg(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg(state, memory, 3)?;
        let bytes_read_ptr = guest_call_arg(state, memory, 4)?;

        let mut bytes = vec![0_u8; length as usize];
        match nt::memory::nt_read_virtual_memory(memory, base_address, &mut bytes) {
            Ok(read) => {
                if read > 0 && buffer != 0 {
                    memory.map_bytes(buffer, &bytes[..read]);
                }
                if bytes_read_ptr != 0 {
                    write_guest_pointer(memory, bytes_read_ptr, read as u64, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtWriteVirtualMemory` — checked write; never creates pages.
    pub(crate) fn dispatch_nt_write_virtual_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let base_address = guest_call_arg(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg(state, memory, 3)?;
        let bytes_written_ptr = guest_call_arg(state, memory, 4)?;

        let mut bytes = vec![0_u8; length as usize];
        if length > 0 && nt::memory::nt_read_virtual_memory(memory, buffer, &mut bytes).is_err() {
            // An unmapped source buffer is an access violation on the read.
            state.set(Register::Rax, u64::from(nt::STATUS_ACCESS_VIOLATION.raw()));
            return Ok(());
        }
        match nt::memory::nt_write_virtual_memory(memory, base_address, &bytes) {
            Ok(written) => {
                if bytes_written_ptr != 0 {
                    write_guest_pointer(
                        memory,
                        bytes_written_ptr,
                        written as u64,
                        self.guest_arch,
                    )?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    // ── Objects: NtClose / NtDuplicateObject / NtQueryObject ───────────────

    /// `NtClose` — close through the object manager's close semantics.
    pub(crate) fn dispatch_nt_close(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        self.ads_handles.remove(&handle);
        let status = nt::object::nt_close(&mut self.win32, handle);
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtDuplicateObject` — duplicate into the target process with
    /// DUPLICATE_SAME_ACCESS / DUPLICATE_CLOSE_SOURCE semantics.
    pub(crate) fn dispatch_nt_duplicate_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let source_process_handle = guest_call_arg_u32(state, memory, 0)?;
        let source_handle = guest_call_arg_u32(state, memory, 1)?;
        let target_process_handle = guest_call_arg_u32(state, memory, 2)?;
        let target_handle_ptr = guest_call_arg(state, memory, 3)?;
        let desired_access = guest_call_arg_u32(state, memory, 4)?;
        let handle_attributes = guest_call_arg_u32(state, memory, 5)?;
        let options = guest_call_arg_u32(state, memory, 6)?;

        if target_handle_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            return Ok(());
        }
        match nt::object::nt_duplicate_object(
            &mut self.win32,
            source_process_handle,
            source_handle,
            target_process_handle,
            desired_access,
            handle_attributes,
            options,
        ) {
            Ok(duplicated) => {
                write_u32(memory, target_handle_ptr, duplicated);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryObject` — ObjectBasicInformation / ObjectNameInformation /
    /// ObjectTypeInformation.
    pub(crate) fn dispatch_nt_query_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        let info_class = guest_call_arg_u32(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg(state, memory, 3)?;
        let return_length_ptr = guest_call_arg(state, memory, 4)?;

        if nt::object::validate_object_information_class(info_class).is_err() {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
            );
            return Ok(());
        }
        match info_class {
            nt::OBJECT_BASIC_INFORMATION_CLASS => {
                const REQUIRED: u64 = 40;
                match nt::object::nt_query_object_basic(&self.win32, handle) {
                    Ok(info) => {
                        if length < REQUIRED {
                            state.set(
                                Register::Rax,
                                u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                            );
                            return Ok(());
                        }
                        memory.map_bytes(buffer, &info.serialize_x64());
                        if return_length_ptr != 0 {
                            write_guest_pointer(
                                memory,
                                return_length_ptr,
                                REQUIRED,
                                self.guest_arch,
                            )?;
                        }
                        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                    }
                    Err(status) => {
                        state.set(Register::Rax, u64::from(status.raw()));
                    }
                }
            }
            nt::OBJECT_NAME_INFORMATION_CLASS => {
                // The name info is a UNICODE_STRING; the live handle table
                // does not expose object names, so the header reports an
                // empty name (the canonical object-manager namespace
                // integration will fill it).
                const REQUIRED: u64 = 16;
                if length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                if buffer != 0 {
                    write_unicode_header(memory, buffer, 0, 0, 0, self.guest_arch);
                    if return_length_ptr != 0 {
                        write_guest_pointer(memory, return_length_ptr, REQUIRED, self.guest_arch)?;
                    }
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::OBJECT_TYPE_INFORMATION_CLASS => {
                // OBJECT_TYPE_INFORMATION: the TypeName UNICODE_STRING at
                // offset 0, then the counter block (the header subset
                // through ValidAccessMask is zeroed).
                const HEADER: u64 = 0x44;
                match nt::object::nt_query_object_type_information(&self.win32, handle) {
                    Ok(type_name) => {
                        let name_bytes = type_name.encode_utf16().count() as u64 * 2;
                        let required = HEADER + name_bytes;
                        if length < required {
                            state.set(
                                Register::Rax,
                                u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                            );
                            return Ok(());
                        }
                        if buffer != 0 {
                            memory.map_bytes(buffer, &vec![0_u8; required as usize]);
                            write_unicode_header(
                                memory,
                                buffer,
                                buffer + HEADER,
                                name_bytes as u16,
                                (name_bytes + 2) as u16,
                                self.guest_arch,
                            );
                            for (index, unit) in type_name.encode_utf16().enumerate() {
                                write_u16(memory, buffer + HEADER + index as u64 * 2, unit);
                            }
                            if return_length_ptr != 0 {
                                write_guest_pointer(
                                    memory,
                                    return_length_ptr,
                                    required,
                                    self.guest_arch,
                                )?;
                            }
                        }
                        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                    }
                    Err(status) => {
                        state.set(Register::Rax, u64::from(status.raw()));
                    }
                }
            }
            _ => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    // ── Synchronization: events + waits ─────────────────────────────────────

    /// `NtCreateEvent` — create/open an event in the live object namespace.
    pub(crate) fn dispatch_nt_create_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let _desired_access = guest_call_arg_u32(state, memory, 1)?;
        let object_attributes = guest_call_arg(state, memory, 2)?;
        let event_type = guest_call_arg_u32(state, memory, 3)?;
        let initial_state = guest_call_arg_u32(state, memory, 4)? != 0;

        let name = object_attributes_name(memory, object_attributes, self.guest_arch)?;
        match nt::sync::nt_create_event(
            &mut self.win32,
            event_type,
            initial_state,
            Some(name.as_str()),
        ) {
            Ok((handle, _existed)) => {
                if handle_ptr != 0 {
                    write_u32(memory, handle_ptr, handle);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtSetEvent` — signal; the previous state is reported out.
    pub(crate) fn dispatch_nt_set_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        let previous_state_ptr = guest_call_arg(state, memory, 1)?;
        match nt::sync::nt_set_event(&mut self.win32, handle) {
            Ok(previous) => {
                if previous_state_ptr != 0 {
                    write_u32(memory, previous_state_ptr, u32::from(previous));
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtClearEvent` — reset; the previous state is reported out.
    pub(crate) fn dispatch_nt_clear_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        let previous_state_ptr = guest_call_arg(state, memory, 1)?;
        match nt::sync::nt_clear_event(&mut self.win32, handle) {
            Ok(previous) => {
                if previous_state_ptr != 0 {
                    write_u32(memory, previous_state_ptr, u32::from(previous));
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtWaitForSingleObject` — one consuming poll, then park in the
    /// scheduler wait queue (never host blocking).  The timeout is a
    /// relative 100 ns interval; `u64::MAX` is infinite.
    pub(crate) fn dispatch_nt_wait_for_single_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        let alertable = guest_call_arg(state, memory, 1)? != 0;
        let timeout_100ns = guest_call_arg(state, memory, 2)?;
        if handle == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
            self.last_error = 0;
            return Ok(());
        }
        // Documented divergence (shared with WaitForSingleObject): the
        // ACTIVE pumped thread can never reach `Exited` while dispatching.
        if self.active_pumped_guest_thread == Some(handle) {
            state.set(Register::Rax, u64::from(nt::STATUS_TIMEOUT.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let object_type = match self.win32.handle_object_type(handle) {
            Ok(object_type) => object_type,
            Err(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        let status = match self.win32.wait_for_single_object_instant(
            handle,
            object_type,
            self.win32.current_thread_id(),
        ) {
            Ok(status) => status,
            Err(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        if !matches!(status, crate::win32::WaitStatus::Timeout) {
            // STATUS_WAIT_0 / STATUS_ABANDONED_WAIT_0 / STATUS_USER_APC —
            // the same numeric domain as the Win32 wait codes.
            state.set(Register::Rax, u64::from(status.code()));
            self.last_error = 0;
        } else if timeout_100ns == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_TIMEOUT.raw()));
            self.last_error = 0;
        } else {
            let now = self.win32.get_tick_count64();
            self.parked_wait = Some(GuestWait {
                objects: vec![handle],
                wait_all: false,
                deadline_ticks: nt::sync::timeout_100ns_to_ticks(timeout_100ns)
                    .map(|ms| now.saturating_add(ms)),
                alertable,
                operation: WaitOperation::Objects,
            });
            // Fall through: the dispatch epilogue parks the thread.
        }
        Ok(())
    }

    /// `NtWaitForMultipleObjects` — wait-any / wait-all with the atomic
    /// scheduler consumption.
    pub(crate) fn dispatch_nt_wait_for_multiple_objects(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let count = guest_call_arg_u32(state, memory, 0)?;
        let handles_ptr = guest_call_arg(state, memory, 1)?;
        let wait_all = guest_call_arg_u32(state, memory, 2)? != 0;
        let alertable = guest_call_arg(state, memory, 3)? != 0;
        let timeout_100ns = guest_call_arg(state, memory, 4)?;

        if count == 0 || handles_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let mut handles = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            handles.push(read_u32(memory, handles_ptr + index as u64 * 4)?);
        }
        let mut satisfied: Option<(u32, u32)> = None;
        if wait_all {
            match self
                .win32
                .evaluate_wait_all(&handles, self.win32.current_thread_id())
            {
                Ok(Some(status)) => satisfied = Some((status.code(), 0)),
                Ok(None) => {}
                Err(_) => {
                    state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                    self.last_error = 0;
                    return Ok(());
                }
            }
        } else {
            for (index, &handle) in handles.iter().enumerate() {
                let object_type = match self.win32.handle_object_type(handle) {
                    Ok(object_type) => object_type,
                    Err(_) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                        self.last_error = 0;
                        return Ok(());
                    }
                };
                let status = match self.win32.wait_for_single_object_instant(
                    handle,
                    object_type,
                    self.win32.current_thread_id(),
                ) {
                    Ok(status) => status,
                    Err(_) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                        self.last_error = 0;
                        return Ok(());
                    }
                };
                if !matches!(status, crate::win32::WaitStatus::Timeout) {
                    satisfied = Some((status.code(), index as u32));
                    break;
                }
            }
        }
        if let Some((code, index)) = satisfied {
            state.set(Register::Rax, u64::from(code.wrapping_add(index)));
            self.last_error = 0;
        } else if timeout_100ns == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_TIMEOUT.raw()));
            self.last_error = 0;
        } else {
            let now = self.win32.get_tick_count64();
            self.parked_wait = Some(GuestWait {
                objects: handles,
                wait_all,
                deadline_ticks: nt::sync::timeout_100ns_to_ticks(timeout_100ns)
                    .map(|ms| now.saturating_add(ms)),
                alertable,
                operation: WaitOperation::Objects,
            });
            // Fall through: the dispatch epilogue parks the thread.
        }
        Ok(())
    }

    /// `NtDelayExecution` — scheduler sleep (alertable); never host
    /// blocking for the parked duration.
    pub(crate) fn dispatch_nt_delay_execution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let alertable = guest_call_arg(state, memory, 0)? != 0;
        let delay_interval = guest_call_arg(state, memory, 1)?;
        if delay_interval == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let apc_delivered = if alertable {
            self.deliver_current_thread_apcs(state, memory)?
        } else {
            false
        };
        if apc_delivered {
            state.set(Register::Rax, u64::from(nt::STATUS_USER_APC.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let now = self.win32.get_tick_count64();
        self.parked_wait = Some(GuestWait {
            objects: Vec::new(),
            wait_all: false,
            deadline_ticks: nt::sync::timeout_100ns_to_ticks(delay_interval)
                .map(|ms| now.saturating_add(ms)),
            alertable,
            operation: WaitOperation::Sleep,
        });
        // Fall through: the dispatch epilogue parks the thread.
        Ok(())
    }

    // ── Sections ────────────────────────────────────────────────────────────

    /// `NtCreateSection` — create a section object (pagefile- or
    /// file-backed) in the live object namespace.
    pub(crate) fn dispatch_nt_create_section(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let _desired_access = guest_call_arg_u32(state, memory, 1)?;
        let object_attributes = guest_call_arg(state, memory, 2)?;
        let maximum_size_ptr = guest_call_arg(state, memory, 3)?;
        let section_page_protection = guest_call_arg_u32(state, memory, 4)?;
        let _allocation_attributes = guest_call_arg_u32(state, memory, 5)?;
        let file_handle_raw = guest_call_arg_u32(state, memory, 6)?;

        let name = object_attributes_name(memory, object_attributes, self.guest_arch)?;
        let maximum_size = if maximum_size_ptr != 0 {
            read_u64(memory, maximum_size_ptr).unwrap_or(0)
        } else {
            0
        };
        let file_handle = if file_handle_raw == 0 || file_handle_raw == u32::MAX {
            None
        } else {
            Some(file_handle_raw)
        };
        match nt::loader::nt_create_section(
            &mut self.win32,
            Some(name.as_str()),
            maximum_size,
            section_page_protection,
            file_handle,
        ) {
            Ok(handle) => {
                if handle_ptr != 0 {
                    write_u32(memory, handle_ptr, handle);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtMapViewOfSection` — map a view; registers the mapping in the
    /// canonical VM so the address space stays consistent.
    pub(crate) fn dispatch_nt_map_view_of_section(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let section_handle = guest_call_arg_u32(state, memory, 1)?;
        let base_address_ptr = guest_call_arg(state, memory, 2)?;
        let _zero_bits = guest_call_arg_u32(state, memory, 3)?;
        let _commit_size = guest_call_arg(state, memory, 4)?;
        let section_offset_ptr = guest_call_arg(state, memory, 5)?;
        let view_size_ptr = guest_call_arg(state, memory, 6)?;
        let _inherit_disposition = guest_call_arg_u32(state, memory, 7)?;
        let _allocation_type = guest_call_arg_u32(state, memory, 8)?;
        let protect = guest_call_arg_u32(state, memory, 9)?;

        let offset = if section_offset_ptr != 0 {
            read_u64(memory, section_offset_ptr).unwrap_or(0)
        } else {
            0
        };
        let view_size = if view_size_ptr != 0 {
            read_u64(memory, view_size_ptr).unwrap_or(0)
        } else {
            0
        };
        match nt::loader::nt_map_view_of_section(&mut self.win32, section_handle, offset, view_size)
        {
            Ok((base, actual_size)) => {
                // Register the mapping in the canonical VM (the same address
                // space the interpreter/JIT validate against).
                if base != 0 && actual_size > 0 {
                    let protection = nt::protection_from_page_flags(protect);
                    self.win32.address_space_mut().register(
                        base,
                        actual_size,
                        crate::vm::VmRegionKind::Private,
                    );
                    self.win32
                        .address_space_mut()
                        .commit(base, actual_size, protection, false);
                }
                if base_address_ptr != 0 {
                    write_guest_pointer(memory, base_address_ptr, base, self.guest_arch)?;
                }
                if view_size_ptr != 0 {
                    write_guest_pointer(memory, view_size_ptr, actual_size, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtUnmapViewOfSection` — release a mapped view.
    pub(crate) fn dispatch_nt_unmap_view_of_section(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let base_address = guest_call_arg(state, memory, 1)?;
        let status = match nt::loader::nt_unmap_view_of_section(&mut self.win32, base_address) {
            Ok(()) => nt::STATUS_SUCCESS,
            Err(status) => status,
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtQuerySection` (BasicInformation).
    pub(crate) fn dispatch_nt_query_section(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let section_handle = guest_call_arg_u32(state, memory, 0)?;
        let info_class = guest_call_arg_u32(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg(state, memory, 3)?;
        let return_length_ptr = guest_call_arg(state, memory, 4)?;

        match nt::loader::nt_query_section(&self.win32, section_handle, info_class) {
            Ok(info) => {
                const REQUIRED: u64 = 48;
                if length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                memory.map_bytes(buffer, &info.serialize_x64());
                if return_length_ptr != 0 {
                    write_guest_pointer(memory, return_length_ptr, REQUIRED, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    // ── Files ───────────────────────────────────────────────────────────────

    /// `NtCreateFile` — the full open path onto the shared file layer.
    pub(crate) fn dispatch_nt_create_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let desired_access = guest_call_arg_u32(state, memory, 1)?;
        let object_attributes = guest_call_arg(state, memory, 2)?;
        let io_status_block = guest_call_arg(state, memory, 3)?;
        let _allocation_size_ptr = guest_call_arg(state, memory, 4)?;
        let file_attributes = guest_call_arg_u32(state, memory, 5)?;
        let share_access = guest_call_arg_u32(state, memory, 6)?;
        let create_disposition = guest_call_arg_u32(state, memory, 7)?;
        let create_options = guest_call_arg_u32(state, memory, 8)?;
        let _ea_buffer = guest_call_arg(state, memory, 9)?;
        let _ea_length = guest_call_arg_u32(state, memory, 10)?;

        let raw_name = object_attributes_name(memory, object_attributes, self.guest_arch)?;
        let inheritable = object_attributes_inheritable(memory, object_attributes, self.guest_arch);
        if raw_name.is_empty() {
            // Windows: an empty object name is an invalid parameter.
            write_io_status_block(
                state,
                memory,
                io_status_block,
                nt::STATUS_INVALID_PARAMETER,
                0,
                self.guest_arch,
            )?;
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let normalized = nt::file::normalize_nt_object_name(&raw_name);
        // Named pipes route through the pipe client opener (same as the
        // Win32 CreateFileW path).
        if normalized.starts_with("\\\\.\\pipe\\") || normalized.starts_with("\\\\?\\pipe\\") {
            match self.win32.open_named_pipe_client(&normalized, inheritable) {
                Ok(handle) => {
                    if handle_ptr != 0 {
                        write_u32(memory, handle_ptr, handle);
                    }
                    write_io_status_block(
                        state,
                        memory,
                        io_status_block,
                        nt::STATUS_SUCCESS,
                        1,
                        self.guest_arch,
                    )?;
                    state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                    self.last_error = 0;
                    return Ok(());
                }
                Err(_) => {
                    let status = nt::STATUS_OBJECT_NAME_NOT_FOUND;
                    write_io_status_block(
                        state,
                        memory,
                        io_status_block,
                        status,
                        0,
                        self.guest_arch,
                    )?;
                    state.set(Register::Rax, u64::from(status.raw()));
                    self.last_error = 0;
                    return Ok(());
                }
            }
        }
        let path = resolve_guest_path(&self.current_directory, &normalized);
        match nt::file::nt_create_file(
            &mut self.win32,
            &path,
            desired_access,
            share_access,
            create_disposition,
            create_options,
            file_attributes,
            inheritable,
        ) {
            Ok(handle) => {
                if handle_ptr != 0 {
                    write_u32(memory, handle_ptr, handle);
                }
                write_io_status_block(
                    state,
                    memory,
                    io_status_block,
                    nt::STATUS_SUCCESS,
                    1,
                    self.guest_arch,
                )?;
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                write_io_status_block(state, memory, io_status_block, status, 0, self.guest_arch)?;
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtDeviceIoControlFile` — routed through the same device/IOCTL
    /// dispatch the Win32 DeviceIoControl thunk uses.
    pub(crate) fn dispatch_nt_device_io_control_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let file_handle = guest_call_arg_u32(state, memory, 0)?;
        let _event = guest_call_arg(state, memory, 1)?;
        let _apc_routine = guest_call_arg(state, memory, 2)?;
        let _apc_context = guest_call_arg(state, memory, 3)?;
        let io_status_block = guest_call_arg(state, memory, 4)?;
        let io_control_code = guest_call_arg_u32(state, memory, 5)?;
        let input_buffer = guest_call_arg(state, memory, 6)?;
        let input_length = guest_call_arg_u32(state, memory, 7)?;
        let output_buffer = guest_call_arg(state, memory, 8)?;
        let output_length = guest_call_arg_u32(state, memory, 9)?;

        let info_offset = match self.guest_arch {
            GuestArch::X64 => 8_u64,
            GuestArch::X86 => 4_u64,
        };
        let bytes_ret_ptr = if io_status_block != 0 {
            io_status_block + info_offset
        } else {
            0
        };
        self.dispatch_device_io_control_common(
            state,
            memory,
            file_handle,
            io_control_code,
            input_buffer,
            input_length,
            output_buffer,
            output_length,
            bytes_ret_ptr,
        )?;
        let succeeded = state.get(Register::Rax) == 1;
        let information = if bytes_ret_ptr != 0 {
            read_u32(memory, bytes_ret_ptr).unwrap_or(0)
        } else {
            0
        };
        if succeeded {
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            write_io_status_block(
                state,
                memory,
                io_status_block,
                nt::STATUS_SUCCESS,
                u64::from(information),
                self.guest_arch,
            )?;
        } else {
            let status = nt::dos_error_to_nt_status(self.last_error);
            write_io_status_block(state, memory, io_status_block, status, 0, self.guest_arch)?;
            state.set(Register::Rax, u64::from(status.raw()));
        }
        Ok(())
    }

    // ── Registry ────────────────────────────────────────────────────────────

    /// `NtCreateKey` — create/open a key in the shared registry store.
    pub(crate) fn dispatch_nt_create_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let desired_access = guest_call_arg_u32(state, memory, 1)?;
        let object_attributes = guest_call_arg(state, memory, 2)?;
        let _title_index = guest_call_arg_u32(state, memory, 3)?;
        let _class_ptr = guest_call_arg(state, memory, 4)?;
        let _create_options = guest_call_arg_u32(state, memory, 5)?;
        let _security_descriptor = guest_call_arg(state, memory, 6)?;
        let disposition_ptr = guest_call_arg(state, memory, 7)?;

        let name = object_attributes_name(memory, object_attributes, self.guest_arch)?;
        let root = registry_root_from_attributes(memory, object_attributes, self.guest_arch);
        let (subkey, root_handle) = split_registry_name(&name, root);
        match nt::registry::nt_create_key(
            &mut self.win32,
            root_handle,
            &subkey,
            desired_access,
            self.guest_arch == GuestArch::X64,
        ) {
            Ok((handle, disposition)) => {
                if handle_ptr != 0 {
                    write_u32(memory, handle_ptr, handle);
                }
                if disposition_ptr != 0 {
                    write_u32(memory, disposition_ptr, disposition);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtOpenKey` — open an existing key.
    pub(crate) fn dispatch_nt_open_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let desired_access = guest_call_arg_u32(state, memory, 1)?;
        let object_attributes = guest_call_arg(state, memory, 2)?;

        let name = object_attributes_name(memory, object_attributes, self.guest_arch)?;
        let root = registry_root_from_attributes(memory, object_attributes, self.guest_arch);
        let (subkey, root_handle) = split_registry_name(&name, root);
        match nt::registry::nt_open_key(
            &mut self.win32,
            root_handle,
            &subkey,
            desired_access,
            self.guest_arch == GuestArch::X64,
        ) {
            Ok(handle) => {
                if handle_ptr != 0 {
                    write_u32(memory, handle_ptr, handle);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryValueKey` — read a value from the shared store.
    pub(crate) fn dispatch_nt_query_value_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let value_name_ptr = guest_call_arg(state, memory, 1)?;
        let info_class = guest_call_arg_u32(state, memory, 2)?;
        let buffer = guest_call_arg(state, memory, 3)?;
        let length = guest_call_arg(state, memory, 4)?;
        let result_length_ptr = guest_call_arg(state, memory, 5)?;

        let value_name = if value_name_ptr != 0 {
            nt::rtl::read_unicode_string(memory, value_name_ptr, self.guest_arch)
                .map_err(nt_status_into_app)?
        } else {
            String::new()
        };
        match nt::registry::nt_query_value_key(
            &self.win32,
            key_handle,
            &value_name,
            info_class,
            length,
        ) {
            Ok((body, required, too_small)) => {
                if result_length_ptr != 0 {
                    write_guest_pointer(memory, result_length_ptr, required, self.guest_arch)?;
                }
                if too_small {
                    state.set(Register::Rax, u64::from(nt::STATUS_BUFFER_OVERFLOW.raw()));
                } else {
                    if buffer != 0 {
                        memory.map_bytes(buffer, &body);
                    }
                    state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                }
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtSetValueKey` — write a value into the shared store.
    pub(crate) fn dispatch_nt_set_value_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let value_name_ptr = guest_call_arg(state, memory, 1)?;
        let _title_index = guest_call_arg_u32(state, memory, 2)?;
        let value_type = guest_call_arg_u32(state, memory, 3)?;
        let data_ptr = guest_call_arg(state, memory, 4)?;
        let data_length = guest_call_arg_u32(state, memory, 5)?;

        let value_name = if value_name_ptr != 0 {
            nt::rtl::read_unicode_string(memory, value_name_ptr, self.guest_arch)
                .map_err(nt_status_into_app)?
        } else {
            String::new()
        };
        let data = if data_ptr == 0 || data_length == 0 {
            Vec::new()
        } else {
            memory.read_bytes(data_ptr, data_length as usize)?
        };
        let status =
            nt::registry::nt_set_value_key(&self.win32, key_handle, &value_name, value_type, &data);
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtDeleteValueKey` / `NtDeleteKey`.
    pub(crate) fn dispatch_nt_delete_value_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let value_name_ptr = guest_call_arg(state, memory, 1)?;
        let value_name = if value_name_ptr != 0 {
            nt::rtl::read_unicode_string(memory, value_name_ptr, self.guest_arch)
                .map_err(nt_status_into_app)?
        } else {
            String::new()
        };
        let status = nt::registry::nt_delete_value_key(&self.win32, key_handle, &value_name);
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtDeleteKey`.
    pub(crate) fn dispatch_nt_delete_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let status = nt::registry::nt_delete_key(&self.win32, key_handle);
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtEnumerateKey` — enumerate subkeys.
    pub(crate) fn dispatch_nt_enumerate_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let info_class = guest_call_arg_u32(state, memory, 2)?;
        let buffer = guest_call_arg(state, memory, 3)?;
        let length = guest_call_arg(state, memory, 4)?;
        let result_length_ptr = guest_call_arg(state, memory, 5)?;

        match nt::registry::nt_enumerate_key(&self.win32, key_handle, index) {
            Ok(name) => {
                let body = serialize_key_basic_information(&name);
                let required = body.len() as u64;
                if result_length_ptr != 0 {
                    write_guest_pointer(memory, result_length_ptr, required, self.guest_arch)?;
                }
                if info_class != nt::KEY_BASIC_INFORMATION_CLASS {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                    );
                } else if length < required {
                    state.set(Register::Rax, u64::from(nt::STATUS_BUFFER_OVERFLOW.raw()));
                } else {
                    if buffer != 0 {
                        memory.map_bytes(buffer, &body);
                    }
                    state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                }
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtEnumerateValueKey` — enumerate values (basic + full classes).
    pub(crate) fn dispatch_nt_enumerate_value_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let info_class = guest_call_arg_u32(state, memory, 2)?;
        let buffer = guest_call_arg(state, memory, 3)?;
        let length = guest_call_arg(state, memory, 4)?;
        let result_length_ptr = guest_call_arg(state, memory, 5)?;

        match nt::registry::nt_enumerate_value_key(&self.win32, key_handle, index) {
            Ok(name) => {
                let body = match info_class {
                    nt::KEY_VALUE_BASIC_INFORMATION_CLASS => {
                        let mut body = Vec::new();
                        body.extend_from_slice(&0u32.to_le_bytes()); // TitleIndex
                        body.extend_from_slice(&nt::REG_SZ.to_le_bytes()); // Type
                        let name_bytes = name.encode_utf16().count() as u32 * 2;
                        body.extend_from_slice(&name_bytes.to_le_bytes());
                        body.extend(name.encode_utf16().flat_map(|u| u.to_le_bytes()));
                        body
                    }
                    nt::KEY_VALUE_FULL_INFORMATION_CLASS => {
                        // Reuse the query path for the value's data.
                        let (hive, key_path, view) =
                            match nt::registry::key_handle_target(&self.win32, key_handle, true) {
                                Ok(target) => target,
                                Err(status) => {
                                    state.set(Register::Rax, u64::from(status.raw()));
                                    return Ok(());
                                }
                            };
                        let stored = self
                            .win32
                            .registry_get_value(&hive, &key_path, &name, view)?
                            .unwrap_or_else(|| crate::ge::StoredRegistryValue {
                                value_type: "REG_NONE".to_string(),
                                data: serde_json::json!([]),
                            });
                        let data =
                            nt::registry::encode_registry_value_data(&stored).unwrap_or_default();
                        let value_type =
                            nt::registry::registry_value_type_to_win32(&stored.value_type);
                        let name_bytes = name.encode_utf16().count() as u32 * 2;
                        let data_offset = (12 + name_bytes as u64 + 7) & !7;
                        let mut body = Vec::new();
                        body.extend_from_slice(&0u32.to_le_bytes());
                        body.extend_from_slice(&value_type.to_le_bytes());
                        body.extend_from_slice(&(data_offset as u32).to_le_bytes());
                        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
                        body.extend_from_slice(&name_bytes.to_le_bytes());
                        body.extend(name.encode_utf16().flat_map(|u| u.to_le_bytes()));
                        while !(body.len() as u64).is_multiple_of(8) {
                            body.push(0);
                        }
                        body.extend_from_slice(&data);
                        body
                    }
                    _ => {
                        state.set(
                            Register::Rax,
                            u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                        );
                        return Ok(());
                    }
                };
                let required = body.len() as u64;
                if result_length_ptr != 0 {
                    write_guest_pointer(memory, result_length_ptr, required, self.guest_arch)?;
                }
                if length < required {
                    state.set(Register::Rax, u64::from(nt::STATUS_BUFFER_OVERFLOW.raw()));
                } else {
                    if buffer != 0 {
                        memory.map_bytes(buffer, &body);
                    }
                    state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                }
            }
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryKey` — KeyBasicInformation / KeyNameInformation.
    pub(crate) fn dispatch_nt_query_key(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key_handle = guest_call_arg_u32(state, memory, 0)?;
        let info_class = guest_call_arg_u32(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg(state, memory, 3)?;
        let result_length_ptr = guest_call_arg(state, memory, 4)?;

        let full_name = match nt::registry::nt_query_key_name(&self.win32, key_handle) {
            Ok(name) => name,
            Err(status) => {
                state.set(Register::Rax, u64::from(status.raw()));
                return Ok(());
            }
        };
        let body = match info_class {
            nt::KEY_BASIC_INFORMATION_CLASS => {
                // LastWriteTime(8) + TitleIndex(4) + NameLength(4) + Name.
                let mut body = Vec::new();
                body.extend_from_slice(&0u64.to_le_bytes());
                body.extend_from_slice(&0u32.to_le_bytes());
                let name_bytes = full_name.encode_utf16().count() as u32 * 2;
                body.extend_from_slice(&name_bytes.to_le_bytes());
                body.extend(full_name.encode_utf16().flat_map(|u| u.to_le_bytes()));
                body
            }
            nt::KEY_NAME_INFORMATION_CLASS => {
                // NameLength(4) + Name.
                let mut body = Vec::new();
                let name_bytes = full_name.encode_utf16().count() as u32 * 2;
                body.extend_from_slice(&name_bytes.to_le_bytes());
                body.extend(full_name.encode_utf16().flat_map(|u| u.to_le_bytes()));
                body
            }
            _ => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                );
                return Ok(());
            }
        };
        let required = body.len() as u64;
        if result_length_ptr != 0 {
            write_guest_pointer(memory, result_length_ptr, required, self.guest_arch)?;
        }
        if length < required {
            state.set(Register::Rax, u64::from(nt::STATUS_BUFFER_OVERFLOW.raw()));
        } else {
            if buffer != 0 {
                memory.map_bytes(buffer, &body);
            }
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        }
        self.last_error = 0;
        Ok(())
    }

    // ── Process / thread ────────────────────────────────────────────────────

    /// `NtQueryInformationProcess` — the guest-process identity surface.
    pub(crate) fn dispatch_nt_query_information_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _process_handle = guest_call_arg(state, memory, 0)?;
        let info_class = guest_call_arg_u32(state, memory, 1)?;
        let info_ptr = guest_call_arg(state, memory, 2)?;
        let info_length = guest_call_arg(state, memory, 3)?;
        let return_length_ptr = guest_call_arg(state, memory, 4)?;

        if nt::process::validate_process_information_class(info_class).is_err() {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
            );
            return Ok(());
        }
        let write_return_length = |memory: &mut MemoryImage, length: u32| {
            if return_length_ptr != 0 {
                write_u32(memory, return_length_ptr, length);
            }
        };
        match info_class {
            nt::PROCESS_BASIC_INFORMATION_CLASS => {
                let required = nt::process::NtProcessBasicInformation::size_for(
                    self.guest_arch == GuestArch::X64,
                );
                if info_length < required {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // ExitStatus: STATUS_PENDING while running; the process
                // object's recorded exit code once terminated.
                let process_handle = self.win32.current_process_handle();
                let exit_status = self
                    .win32
                    .process_state(process_handle)
                    .ok()
                    .and_then(|process_state| process_state.exit_code)
                    .unwrap_or_else(|| nt::STATUS_PENDING.raw());
                let info = nt::process::NtProcessBasicInformation {
                    exit_status,
                    peb_base_address: self.peb_base,
                    affinity_mask: 0xFF,
                    base_priority: 8,
                    // The GUEST pid — never the host's POSIX pid.
                    unique_process_id: u64::from(self.guest_pid),
                    inherited_from_unique_process_id: 0,
                };
                let bytes = if self.guest_arch == GuestArch::X64 {
                    info.serialize_x64().to_vec()
                } else {
                    info.serialize_x86().to_vec()
                };
                memory.map_bytes(info_ptr, &bytes);
                write_return_length(memory, required as u32);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::PROCESS_DEBUG_PORT_CLASS => {
                if info_length >= 4 {
                    write_u32(memory, info_ptr, 0);
                }
                write_return_length(memory, 4);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::PROCESS_IMAGE_FILE_NAME_CLASS => {
                // The current process image path as a UNICODE_STRING.
                let image_path =
                    resolve_full_guest_path(&self.current_directory, &self.main_module_name);
                let wide_bytes: Vec<u8> = image_path
                    .encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                let string_len = wide_bytes.len() as u16;
                let required = 8 + u64::from(string_len);
                if info_length < required {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                write_u16(memory, info_ptr, string_len);
                write_u16(memory, info_ptr + 2, string_len);
                let buffer_ptr = info_ptr + 8;
                let _ = write_guest_pointer(memory, info_ptr + 4, buffer_ptr, self.guest_arch);
                memory.map_bytes(buffer_ptr, &wide_bytes);
                write_return_length(memory, required as u32);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::PROCESS_PROTECTION_INFORMATION_CLASS => {
                const SIZE: u64 = 8;
                if info_length < SIZE {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                write_u32(memory, info_ptr, 0);
                write_u32(memory, info_ptr + 4, 0);
                write_return_length(memory, SIZE as u32);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::PROCESS_MITIGATION_POLICY_CLASS => {
                const SIZE: u64 = 4;
                if info_length < SIZE {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                write_u32(memory, info_ptr, 1);
                write_return_length(memory, SIZE as u32);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            _ => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryInformationThread` — the guest-thread identity surface.
    pub(crate) fn dispatch_nt_query_information_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let info_class = guest_call_arg_u32(state, memory, 1)?;
        let info_ptr = guest_call_arg(state, memory, 2)?;
        let info_length = guest_call_arg(state, memory, 3)?;
        let return_length_ptr = guest_call_arg(state, memory, 4)?;

        if nt::thread::validate_thread_information_class(info_class).is_err() {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
            );
            return Ok(());
        }
        match info_class {
            nt::THREAD_BASIC_INFORMATION_CLASS => {
                let required = nt::thread::NtThreadBasicInformation::size_for(
                    self.guest_arch == GuestArch::X64,
                );
                if info_length < required {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                let thread_id = match self.win32.thread_id_for_handle(thread_handle) {
                    Ok(thread_id) => thread_id,
                    Err(_) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                        return Ok(());
                    }
                };
                let teb_base = self
                    .pending_guest_threads
                    .iter()
                    .find(|thread| thread.handle == thread_handle)
                    .map(|thread| thread.teb_base)
                    .unwrap_or(self.teb_base);
                let exit_status = self
                    .win32
                    .get_exit_code_thread(thread_handle)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| nt::STATUS_PENDING.raw());
                let priority = self.win32.get_thread_priority(thread_handle).unwrap_or(0);
                let info = nt::thread::NtThreadBasicInformation {
                    exit_status,
                    teb_base_address: teb_base,
                    unique_process_id: u64::from(self.guest_pid),
                    unique_thread_id: u64::from(thread_id),
                    affinity_mask: 0xFF,
                    priority,
                    base_priority: 0,
                };
                let bytes = if self.guest_arch == GuestArch::X64 {
                    info.serialize_x64().to_vec()
                } else {
                    info.serialize_x86().to_vec()
                };
                memory.map_bytes(info_ptr, &bytes);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, required as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_TIMES_CLASS => {
                const REQUIRED: u64 = 32;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // CreationTime/ExitTime/KernelTime/UserTime — derived from
                // the SAME guest-clock domain as GetThreadTimes (they share
                // the helper, so the two APIs always agree).
                let times = crate::runtime::guest_thread_times_filetimes(self.dtm);
                memory.map_bytes(info_ptr, &vec![0_u8; REQUIRED as usize]);
                write_u64(memory, info_ptr, times[0]);
                write_u64(memory, info_ptr + 8, times[1]);
                write_u64(memory, info_ptr + 16, times[2]);
                write_u64(memory, info_ptr + 24, times[3]);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_IS_TERMINATED_CLASS => {
                const REQUIRED: u64 = 4;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // BOOLEAN as ULONG (Windows: "q: ULONG"): 1 once the thread
                // has terminated, 0 while it is alive.  Consistent with
                // GetExitCodeThread (STILL_ACTIVE until an exit code is
                // recorded).
                let thread_id = self.win32.thread_id_for_handle(thread_handle);
                let terminated = thread_id.is_ok_and(|id| self.win32.thread_has_exited(id));
                write_u32(memory, info_ptr, u32::from(terminated));
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_AFFINITY_MASK_CLASS => {
                const REQUIRED: u64 = 8;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                write_u64(memory, info_ptr, 0xFF);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_PRIORITY_CLASS => {
                const REQUIRED: u64 = 4;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                let priority = self.win32.get_thread_priority(thread_handle).unwrap_or(0);
                write_i32(memory, info_ptr, priority);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_BASE_PRIORITY_CLASS => {
                const REQUIRED: u64 = 4;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // The process base priority — consistent with the value
                // reported by ThreadBasicInformation (no process-priority
                // model exists, so it is 0).
                write_i32(memory, info_ptr, 0);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS => {
                const REQUIRED_X64: u64 = 8;
                const REQUIRED_X86: u64 = 4;
                let required = if self.guest_arch == GuestArch::X64 {
                    REQUIRED_X64
                } else {
                    REQUIRED_X86
                };
                if info_length < required {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // The queued guest thread's start routine; 0 for threads
                // with no scheduler record (e.g. the main thread).
                let start_address = self
                    .pending_guest_threads
                    .iter()
                    .find(|thread| thread.handle == thread_handle)
                    .map(|thread| thread.start_address)
                    .unwrap_or(0);
                write_guest_pointer(memory, info_ptr, start_address, self.guest_arch)?;
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, required as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_AM_I_LAST_THREAD_CLASS => {
                const REQUIRED: u64 = 4;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // 1 when the queried thread is the only live thread in the
                // process (the main thread plus every queued guest thread
                // make up the live set).
                let thread_id = self.win32.thread_id_for_handle(thread_handle);
                let is_last = match thread_id {
                    Ok(thread_id) => {
                        !self
                            .pending_guest_threads
                            .iter()
                            .any(|thread| thread.thread_id != thread_id)
                            && (self.win32.current_thread_id() == thread_id
                                || !self
                                    .pending_guest_threads
                                    .iter()
                                    .any(|thread| thread.thread_id == thread_id))
                    }
                    Err(_) => false,
                };
                write_u32(memory, info_ptr, u32::from(is_last));
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_PRIORITY_BOOST_CLASS => {
                const REQUIRED: u64 = 4;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // Windows default: dynamic priority boost enabled (1).
                write_u32(memory, info_ptr, 1);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_HIDE_FROM_DEBUGGER_CLASS => {
                const REQUIRED: u64 = 1;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // BOOLEAN: the thread is not hidden from debuggers.
                memory.map_bytes(info_ptr, &[0_u8; 1]);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::THREAD_SUSPEND_COUNT_CLASS => {
                const REQUIRED: u64 = 4;
                if info_length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // The subsystem suspend count — the single source of truth
                // the scheduler mirrors, so this always agrees with the
                // pump gate.
                let count = self
                    .win32
                    .thread_id_for_handle(thread_handle)
                    .ok()
                    .and_then(|thread_id| self.win32.thread_suspend_count(thread_id).ok())
                    .unwrap_or(0);
                write_u32(memory, info_ptr, count);
                if return_length_ptr != 0 {
                    write_u32(memory, return_length_ptr, REQUIRED as u32);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            _ => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtGetContextThread` — serialize the target thread's integer/control
    /// registers into the guest CONTEXT (per the guest's ContextFlags).
    pub(crate) fn dispatch_nt_get_context_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let context_ptr = guest_call_arg(state, memory, 1)?;
        if context_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            return Ok(());
        }
        // The target thread's saved state (or the live state when the
        // handle is not a queued guest thread — including the current one).
        let target: Option<&CpuState> = if thread_handle == self.win32.current_thread_handle() {
            None
        } else {
            self.pending_guest_threads
                .iter()
                .find(|thread| thread.handle == thread_handle)
                .map(|thread| &thread.state)
        };
        let source_state = target.unwrap_or(state);
        capture_context_into_guest(memory, source_state, context_ptr, self.guest_arch);
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtSetContextThread` — apply the guest CONTEXT to the target thread.
    pub(crate) fn dispatch_nt_set_context_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let context_ptr = guest_call_arg(state, memory, 1)?;
        if context_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            return Ok(());
        }
        let is_current = thread_handle == self.win32.current_thread_handle();
        if is_current {
            apply_context_from_guest(memory, state, context_ptr, self.guest_arch);
        } else if let Some(thread) = self
            .pending_guest_threads
            .iter_mut()
            .find(|thread| thread.handle == thread_handle)
        {
            apply_context_from_guest(memory, &mut thread.state, context_ptr, self.guest_arch);
        } else {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtSuspendThread` — real suspend count at the scheduler level: the
    /// pump skips suspended threads until every suspension is released.
    ///
    /// The subsystem is the ONLY counter mutation (`win32.suspend_thread`
    /// validates THREAD_SUSPEND_RESUME and returns the true previous
    /// count); the scheduler record then syncs FROM the subsystem, so the
    /// Win32 and Nt paths on the same thread are interchangeable and the
    /// two counters can never disagree.
    pub(crate) fn dispatch_nt_suspend_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let previous_count_ptr = guest_call_arg(state, memory, 1)?;
        match self.win32.suspend_thread(thread_handle) {
            Ok(previous) => {
                self.sync_pending_thread_suspend_count(thread_handle);
                if previous_count_ptr != 0 {
                    write_u32(memory, previous_count_ptr, previous);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(_) => {
                // Windows: suspending a terminated thread reports
                // STATUS_THREAD_IS_TERMINATING (0xC000004A); every other
                // failure (invalid handle / access) reports
                // STATUS_INVALID_HANDLE.
                let terminated = self
                    .win32
                    .thread_id_for_handle(thread_handle)
                    .is_ok_and(|thread_id| self.win32.thread_has_exited(thread_id));
                state.set(
                    Register::Rax,
                    u64::from(if terminated {
                        nt::STATUS_THREAD_IS_TERMINATING.raw()
                    } else {
                        nt::STATUS_INVALID_HANDLE.raw()
                    }),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtResumeThread` — decrement the scheduler suspend count.
    ///
    /// Same single-source-of-truth contract as `NtSuspendThread`: the
    /// subsystem decrements and returns the previous count, and the
    /// scheduler record syncs from it.
    pub(crate) fn dispatch_nt_resume_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let previous_count_ptr = guest_call_arg(state, memory, 1)?;
        match self.win32.resume_thread(thread_handle) {
            Ok(previous) => {
                self.sync_pending_thread_suspend_count(thread_handle);
                if previous_count_ptr != 0 {
                    write_u32(memory, previous_count_ptr, previous);
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(_) => {
                // Terminated threads report STATUS_THREAD_IS_TERMINATING
                // (0xC000004A); every other failure reports
                // STATUS_INVALID_HANDLE.
                let terminated = self
                    .win32
                    .thread_id_for_handle(thread_handle)
                    .is_ok_and(|thread_id| self.win32.thread_has_exited(thread_id));
                state.set(
                    Register::Rax,
                    u64::from(if terminated {
                        nt::STATUS_THREAD_IS_TERMINATING.raw()
                    } else {
                        nt::STATUS_INVALID_HANDLE.raw()
                    }),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtTerminateProcess` — the process exit path (current process ends
    /// the run; other process objects record their exit code).
    pub(crate) fn dispatch_nt_terminate_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<i32>> {
        let process_handle = guest_call_arg_u32(state, memory, 0)?;
        let exit_status = guest_call_arg_u32(state, memory, 1)?;
        let is_current =
            process_handle == u32::MAX || process_handle == self.win32.current_process_handle();
        if is_current {
            // NtCurrentProcess / the current process: request process exit.
            self.process_exit_requested = Some(exit_status);
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            self.last_error = 0;
            return Ok(Some(exit_status as i32));
        }
        match self.win32.terminate_process(process_handle, exit_status) {
            Ok(()) => {
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
            }
        }
        self.last_error = 0;
        Ok(None)
    }

    /// `NtTerminateThread` — the thread exit path (termination does not
    /// fire DLL_THREAD_DETACH, per Windows).
    pub(crate) fn dispatch_nt_terminate_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<i32>> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let exit_status = guest_call_arg_u32(state, memory, 1)?;
        if thread_handle == u32::MAX || thread_handle == self.win32.current_thread_handle() {
            // NtCurrentThread: terminate the calling thread.
            self.request_current_thread_exit(exit_status, false);
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            self.last_error = 0;
            return Ok(Some(exit_status as i32));
        }
        let target_tid = match self.win32.thread_id_for_handle(thread_handle) {
            Ok(thread_id) => thread_id,
            Err(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                self.last_error = 0;
                return Ok(None);
            }
        };
        // A queued (not-yet-run) guest thread is terminated outright.
        self.pending_guest_threads
            .retain(|thread| thread.thread_id != target_tid);
        match self.win32.terminate_thread(thread_handle, exit_status) {
            Ok(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            Err(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
            }
        }
        self.last_error = 0;
        Ok(None)
    }

    /// `NtCreateThreadEx` — thread creation with the guest thread machinery.
    pub(crate) fn dispatch_nt_create_thread_ex(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle_ptr = guest_call_arg(state, memory, 0)?;
        let _desired_access = guest_call_arg_u32(state, memory, 1)?;
        let _object_attributes = guest_call_arg(state, memory, 2)?;
        let _process_handle = guest_call_arg(state, memory, 3)?;
        let start_address = guest_call_arg(state, memory, 4)?;
        let parameter = guest_call_arg(state, memory, 5)?;
        let create_suspended = guest_call_arg_u32(state, memory, 6)? != 0;
        let _stack_zero_bits = guest_call_arg_u32(state, memory, 7)?;
        let _stack_commit = guest_call_arg(state, memory, 8)?;
        let stack_reserve = guest_call_arg(state, memory, 9)?;

        let thread_handle = self.win32.create_thread(
            crate::win32::ThreadPlan {
                exit_code: None,
                priority: 0,
                signaled: false,
            },
            false,
        );
        let thread_id = self.win32.thread_id_for_handle(thread_handle)?;
        if self.guest_arch == GuestArch::X86 && start_address != 0 {
            let mut pending_thread = self.prepare_guest_thread_entry(
                memory,
                thread_handle,
                stack_reserve,
                start_address,
                parameter,
            )?;
            if create_suspended {
                // NtCreateThreadEx(create_suspended): the suspension is
                // recorded in BOTH the subsystem ThreadState (the single
                // source of truth) and the scheduler record.
                pending_thread.suspended = 1;
                let _ = self.win32.set_thread_suspend_count(thread_id, 1);
            }
            self.pending_guest_threads.push_back(pending_thread);
        }
        if thread_handle_ptr != 0 {
            write_u32(memory, thread_handle_ptr, thread_handle);
        }
        self.emit_event(crate::runtime_events::RuntimeEvent::ThreadCreated { thread_id });
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtSetInformationThread` — ThreadPriority / ThreadAffinityMask.
    pub(crate) fn dispatch_nt_set_information_thread(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_handle = guest_call_arg_u32(state, memory, 0)?;
        let info_class = guest_call_arg_u32(state, memory, 1)?;
        let info_ptr = guest_call_arg(state, memory, 2)?;
        let info_length = guest_call_arg(state, memory, 3)?;

        if nt::thread::validate_set_thread_information_class(info_class).is_err() {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
            );
            return Ok(());
        }
        match info_class {
            nt::THREAD_PRIORITY_CLASS => {
                if info_length < 4 {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                let priority = read_u32(memory, info_ptr)? as i32;
                match self.win32.set_thread_priority(thread_handle, priority) {
                    Ok(()) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                    }
                    Err(_) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                    }
                }
            }
            nt::THREAD_AFFINITY_MASK_CLASS => {
                if info_length < 8 {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                // The configured topology is a single 8-CPU group; any
                // subset of the full mask is accepted (the cooperative
                // scheduler does not model per-CPU affinity).
                let _affinity = read_u64(memory, info_ptr)?;
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            _ => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    // ── System / time ───────────────────────────────────────────────────────

    /// `NtQuerySystemInformation` — the configured guest topology + clock.
    pub(crate) fn dispatch_nt_query_system_information(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let info_class = guest_call_arg_u32(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg(state, memory, 2)?;
        let return_length_ptr = guest_call_arg(state, memory, 3)?;

        if nt::system::validate_system_information_class(info_class).is_err() {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
            );
            return Ok(());
        }
        match info_class {
            nt::SYSTEM_BASIC_INFORMATION_CLASS => {
                const REQUIRED: u64 = 100;
                if length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                memory.map_bytes(
                    buffer,
                    &nt::system::serialize_system_basic_information_x64(8),
                );
                if return_length_ptr != 0 {
                    write_guest_pointer(memory, return_length_ptr, REQUIRED, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::SYSTEM_TIME_OF_DAY_INFORMATION_CLASS => {
                const REQUIRED: u64 = 48;
                if length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                let current = current_guest_filetime_ticks(self.dtm) as i64;
                let info = nt::system::NtSystemTimeOfDayInformation {
                    boot_time: 0,
                    current_time: current,
                    time_zone_bias: 0,
                    time_zone_id: 1,
                };
                memory.map_bytes(buffer, &info.serialize_x64());
                if return_length_ptr != 0 {
                    write_guest_pointer(memory, return_length_ptr, REQUIRED, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_CLASS => {
                // 8 processors × 48 bytes (the GetSystemInfo topology).
                const REQUIRED: u64 = 384;
                if length < REQUIRED {
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                let ticks = self.win32.get_tick_count64().saturating_mul(10_000) as i64;
                let info = nt::system::NtProcessorPerformanceInformation {
                    idle_time: 0,
                    kernel_time: ticks / 4,
                    user_time: ticks - ticks / 4,
                    dpc_time: 0,
                    interrupt_time: 0,
                    interrupt_count: 0,
                };
                for index in 0..8_u64 {
                    memory.map_bytes(buffer + index * 48, &info.serialize_x64());
                }
                if return_length_ptr != 0 {
                    write_guest_pointer(memory, return_length_ptr, REQUIRED, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            _ => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_INVALID_INFO_CLASS.raw()),
                );
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryPerformanceCounter` — the guest counter + frequency.
    pub(crate) fn dispatch_nt_query_performance_counter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let counter_ptr = guest_call_arg(state, memory, 0)?;
        let frequency_ptr = guest_call_arg(state, memory, 1)?;
        if counter_ptr != 0 {
            write_u64(memory, counter_ptr, self.win32.query_performance_counter());
        }
        if frequency_ptr != 0 {
            write_u64(
                memory,
                frequency_ptr,
                self.win32.query_performance_frequency(),
            );
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryTimerResolution` — the configured guest timer resolution.
    pub(crate) fn dispatch_nt_query_timer_resolution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let minimum_ptr = guest_call_arg(state, memory, 0)?;
        let maximum_ptr = guest_call_arg(state, memory, 1)?;
        let current_ptr = guest_call_arg(state, memory, 2)?;
        if minimum_ptr != 0 {
            write_u32(
                memory,
                minimum_ptr,
                nt::system::TIMER_MINIMUM_RESOLUTION_100NS,
            );
        }
        if maximum_ptr != 0 {
            write_u32(
                memory,
                maximum_ptr,
                nt::system::TIMER_MAXIMUM_RESOLUTION_100NS,
            );
        }
        if current_ptr != 0 {
            write_u32(
                memory,
                current_ptr,
                nt::system::TIMER_MAXIMUM_RESOLUTION_100NS,
            );
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtSetTimerResolution` — accept the request and report the actual
    /// resolution (the guest clock's resolution is not host-visible).
    pub(crate) fn dispatch_nt_set_timer_resolution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let desired = guest_call_arg_u32(state, memory, 0)?;
        let _set = guest_call_arg(state, memory, 1)? != 0;
        let actual_ptr = guest_call_arg(state, memory, 2)?;
        let actual = desired.clamp(
            nt::system::TIMER_MINIMUM_RESOLUTION_100NS,
            nt::system::TIMER_MAXIMUM_RESOLUTION_100NS,
        );
        if actual_ptr != 0 {
            write_u32(memory, actual_ptr, actual);
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtQuerySystemTime` — the guest FILETIME.
    pub(crate) fn dispatch_nt_query_system_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let filetime_ptr = guest_call_arg(state, memory, 0)?;
        if filetime_ptr != 0 {
            write_u64(memory, filetime_ptr, current_guest_filetime_ticks(self.dtm));
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    // ── Rtl ─────────────────────────────────────────────────────────────────

    /// `RtlInitUnicodeString`.
    pub(crate) fn dispatch_rtl_init_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let destination = guest_call_arg(state, memory, 0)?;
        let source = guest_call_arg(state, memory, 1)?;
        if destination != 0 {
            let _ = nt::rtl::rtl_init_unicode_string(memory, destination, source, self.guest_arch);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlInitAnsiString`.
    pub(crate) fn dispatch_rtl_init_ansi_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let destination = guest_call_arg(state, memory, 0)?;
        let source = guest_call_arg(state, memory, 1)?;
        if destination != 0 {
            let _ = nt::rtl::rtl_init_ansi_string(memory, destination, source, self.guest_arch);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlFreeUnicodeString`.
    pub(crate) fn dispatch_rtl_free_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let string = guest_call_arg(state, memory, 0)?;
        if string != 0 {
            let _ = nt::rtl::rtl_free_string_header(memory, string);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlFreeAnsiString`.
    pub(crate) fn dispatch_rtl_free_ansi_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let string = guest_call_arg(state, memory, 0)?;
        if string != 0 {
            let _ = nt::rtl::rtl_free_string_header(memory, string);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlCompareUnicodeString` — <0 / 0 / >0.
    pub(crate) fn dispatch_rtl_compare_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let first = guest_call_arg(state, memory, 0)?;
        let second = guest_call_arg(state, memory, 1)?;
        let case_insensitive = guest_call_arg(state, memory, 2)? != 0;
        let result = nt::rtl::rtl_compare_unicode_string(
            memory,
            first,
            second,
            case_insensitive,
            self.guest_arch,
        )
        .unwrap_or(0);
        state.set(Register::Rax, result as u64);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlEqualUnicodeString` — boolean.
    pub(crate) fn dispatch_rtl_equal_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let first = guest_call_arg(state, memory, 0)?;
        let second = guest_call_arg(state, memory, 1)?;
        let case_insensitive = guest_call_arg(state, memory, 2)? != 0;
        let result = nt::rtl::rtl_equal_unicode_string(
            memory,
            first,
            second,
            case_insensitive,
            self.guest_arch,
        )
        .unwrap_or(false);
        state.set(Register::Rax, u64::from(result));
        self.last_error = 0;
        Ok(())
    }

    /// `RtlGetVersion` — the configured Windows version (the same profile
    /// the Win32 GetVersionExW / VerifyVersionInfoW thunks report).
    pub(crate) fn dispatch_rtl_get_version(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let version_ptr = guest_call_arg(state, memory, 0)?;
        if version_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            return Ok(());
        }
        let version = guest_version_info_from_profile(&self.win32.ge().config.winver)?;
        let info = nt::rtl::NtOsVersionInfo {
            major: version.major,
            minor: version.minor,
            build: version.build,
            platform_id: version.platform_id,
            service_pack_major: version.service_pack_major,
            service_pack_minor: version.service_pack_minor,
            suite_mask: version.suite_mask,
            product_type: version.product_type,
        };
        memory.map_bytes(version_ptr, &info.serialize_ex_x64(""));
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `RtlCaptureContext` — save the integer/control registers.
    pub(crate) fn dispatch_rtl_capture_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let context_ptr = guest_call_arg(state, memory, 0)?;
        if context_ptr != 0 {
            capture_context_into_guest(memory, state, context_ptr, self.guest_arch);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlRestoreContext` — restore the guest state from the CONTEXT.
    pub(crate) fn dispatch_rtl_restore_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let context_ptr = guest_call_arg(state, memory, 0)?;
        let _exception_record_ptr = guest_call_arg(state, memory, 1)?;
        if context_ptr != 0 {
            apply_context_from_guest(memory, state, context_ptr, self.guest_arch);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlLookupFunctionEntry` — the x64 unwind lookup against the
    /// registered `.pdata` tables of the mapped image.
    pub(crate) fn dispatch_rtl_lookup_function_entry(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let control_pc = guest_call_arg(state, memory, 0)?;
        let image_base_ptr = guest_call_arg(state, memory, 1)?;
        let _history_table = guest_call_arg(state, memory, 2)?;
        if image_base_ptr != 0 {
            write_guest_pointer(
                memory,
                image_base_ptr,
                self.mapped_image_base,
                self.guest_arch,
            )?;
        }
        if self.guest_arch != GuestArch::X64 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let rva = control_pc.saturating_sub(self.mapped_image_base);
        let Some(function) = self
            .seh
            .find_runtime_function(self.mapped_image_base, rva as u32)
        else {
            state.set(Register::Rax, 0);
            self.last_error = 0;
            return Ok(());
        };
        // Materialize the RUNTIME_FUNCTION (BeginAddress, EndAddress,
        // UnwindData — three RVAs) in guest memory so the caller can read
        // the entry like a kernel-provided one.
        let (begin_addr, end_addr, unwind_info_addr) = (
            function.begin_addr,
            function.end_addr,
            function.unwind_info_addr,
        );
        let entry = self.alloc_zeroed(memory, 12, 4)?;
        write_u32(memory, entry, begin_addr);
        write_u32(memory, entry + 4, end_addr);
        write_u32(memory, entry + 8, unwind_info_addr);
        state.set(Register::Rax, entry);
        self.last_error = 0;
        Ok(())
    }

    /// `RtlRaiseException` — dispatch through the runtime's SEH machinery
    /// (the same dispatch the RaiseException thunk uses).
    pub(crate) fn dispatch_rtl_raise_exception(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<i32>> {
        let record_ptr = guest_call_arg(state, memory, 0)?;
        if record_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            return Ok(None);
        }
        let code = read_u32(memory, record_ptr).unwrap_or(0);
        let flags = read_u32(memory, record_ptr + 4).unwrap_or(0);
        let address =
            match self.guest_arch {
                GuestArch::X64 => read_guest_pointer(memory, record_ptr + 0x10, self.guest_arch)
                    .unwrap_or(state.rip),
                GuestArch::X86 => read_guest_pointer(memory, record_ptr + 0x0C, self.guest_arch)
                    .unwrap_or(state.rip),
            };
        // EH_UNWINDING (0x02) means this is called during stack unwinding —
        // it is a signal, not a dispatch.
        if flags & 0x02 != 0 {
            state.set(Register::Rax, u64::from(code));
            self.last_error = 0;
            return Ok(None);
        }
        let handled = if self.guest_arch == GuestArch::X86 {
            self.dispatch_x86_exception(state, memory, code, 0, "RtlRaiseException")?
        } else if self.guest_arch == GuestArch::X64 {
            let ctx = x64_context_from_state(state);
            let mem_ref: &MemoryImage = memory;
            let stack_reader =
                |addr: u64, buf: &mut [u8]| -> bool { mem_ref.read_into(addr, buf).is_ok() };
            let handled = self
                .seh
                .dispatch(code, 0, &ctx, self.mapped_image_base, &stack_reader)
                .is_ok();
            let pending_veh = crate::seh::drain_pending_guest_veh();
            for (veh_callback, veh_record, veh_context) in &pending_veh {
                self.invoke_guest_veh_callback(
                    state,
                    memory,
                    *veh_callback,
                    veh_record,
                    veh_context,
                )?;
            }
            handled
        } else {
            false
        };
        if handled {
            state.set(Register::Rax, u64::from(code));
            self.last_error = 0;
            Ok(None)
        } else {
            self.unhandled_guest_exception = Some(code);
            self.emit_event(crate::runtime_events::RuntimeEvent::GuestException {
                code,
                guest_pc: state.rip,
                thread_id: self.win32.current_thread_id(),
            });
            state.set(Register::Rax, u64::from(code));
            self.process_exit_requested = Some(code);
            let _ = address;
            Ok(Some(code as i32))
        }
    }

    /// `RtlAllocateHeap` — adapter onto the runtime heap (the same
    /// bump-allocator the Win32 HeapAlloc thunk drives).
    pub(crate) fn dispatch_rtl_allocate_heap(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let heap = guest_call_arg(state, memory, 0)?;
        let flags = guest_call_arg_u32(state, memory, 1)?;
        let bytes = guest_call_arg(state, memory, 2)? as usize;
        if heap != PROCESS_HEAP_HANDLE {
            state.set(Register::Rax, 0);
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(());
        }
        match self.alloc_heap(memory, bytes.max(1), (flags & HEAP_ZERO_MEMORY) != 0) {
            Ok(address) => {
                state.set(Register::Rax, address);
                self.last_error = 0;
            }
            Err(_) => {
                state.set(Register::Rax, 0);
                self.last_error = ERROR_NOT_ENOUGH_MEMORY;
            }
        }
        Ok(())
    }

    /// `RtlFreeHeap` — adapter onto the runtime heap.
    pub(crate) fn dispatch_rtl_free_heap(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let heap = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let address = guest_call_arg(state, memory, 2)?;
        let freed = if heap == PROCESS_HEAP_HANDLE {
            self.heap_allocations.remove(&address).is_some()
        } else {
            false
        };
        state.set(Register::Rax, u64::from(freed));
        self.last_error = 0;
        Ok(())
    }

    /// `RtlSizeHeap` — adapter onto the runtime heap.
    pub(crate) fn dispatch_rtl_size_heap(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let heap = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let address = guest_call_arg(state, memory, 2)?;
        let size = if heap == PROCESS_HEAP_HANDLE {
            self.heap_allocations
                .get(&address)
                .map(|size| *size as u64)
                .unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        state.set(Register::Rax, size);
        self.last_error = 0;
        Ok(())
    }

    // ── Ldr loader surface (crate::ntdll::ldr) ─────────────────────────────
    // The Ldr layer is the NTDLL-native surface ABOVE the loader machinery:
    // the dispatch arms below read the guest protocol (UNICODE_STRING /
    // ANSI_STRING names, out-pointers, NTSTATUS results) and delegate to
    // the ONE loader implementation in crate::ntdll::ldr.

    /// `LdrLoadDll` — resolve through the shared loader machinery
    /// (synthetic + real-dll paths); a newly loaded module's
    /// `DLL_PROCESS_ATTACH` + TLS callbacks queue in load order (FIFO);
    /// an already loaded module returns the same handle with only a
    /// refcount increment.
    pub(crate) fn dispatch_ldr_load_dll(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _search_path = guest_call_arg(state, memory, 0)?;
        let _dll_characteristics = guest_call_arg(state, memory, 1)?;
        let dll_name = guest_call_arg(state, memory, 2)?;
        let module_handle_ptr = guest_call_arg(state, memory, 3)?;

        let name = match crate::ntdll::rtl::read_unicode_string(memory, dll_name, self.guest_arch) {
            Ok(name) => name,
            Err(status) => {
                if module_handle_ptr != 0 {
                    write_guest_pointer(memory, module_handle_ptr, 0, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(status.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        let status = match self.ldr_load_dll(&name) {
            Ok(handle) => {
                if module_handle_ptr != 0 {
                    write_guest_pointer(memory, module_handle_ptr, handle, self.guest_arch)?;
                }
                nt::STATUS_SUCCESS
            }
            Err(status) => {
                if module_handle_ptr != 0 {
                    write_guest_pointer(memory, module_handle_ptr, 0, self.guest_arch)?;
                }
                status
            }
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrUnloadDll` — refcount--; at 0 queue `DLL_PROCESS_DETACH`
    /// (+ TLS callbacks) and remove the module.  The main module is never
    /// unloaded.
    pub(crate) fn dispatch_ldr_unload_dll(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let module_handle = guest_call_arg(state, memory, 0)?;
        let status = match self.ldr_unload_dll(module_handle) {
            Ok(()) => nt::STATUS_SUCCESS,
            Err(status) => status,
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrGetDllHandle` — lookup only; NEVER loads.  Not-found is
    /// `STATUS_DLL_NOT_FOUND`.
    pub(crate) fn dispatch_ldr_get_dll_handle(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _search_path = guest_call_arg(state, memory, 0)?;
        let _dll_characteristics = guest_call_arg(state, memory, 1)?;
        let dll_name = guest_call_arg(state, memory, 2)?;
        let module_handle_ptr = guest_call_arg(state, memory, 3)?;

        let name = match crate::ntdll::rtl::read_unicode_string(memory, dll_name, self.guest_arch) {
            Ok(name) => name,
            Err(status) => {
                if module_handle_ptr != 0 {
                    write_guest_pointer(memory, module_handle_ptr, 0, self.guest_arch)?;
                }
                state.set(Register::Rax, u64::from(status.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        let status = match self.ldr_get_dll_handle(&name) {
            Ok(handle) => {
                if module_handle_ptr != 0 {
                    write_guest_pointer(memory, module_handle_ptr, handle, self.guest_arch)?;
                }
                nt::STATUS_SUCCESS
            }
            Err(status) => {
                if module_handle_ptr != 0 {
                    write_guest_pointer(memory, module_handle_ptr, 0, self.guest_arch)?;
                }
                status
            }
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrGetProcedureAddress` — resolve by name (`ANSI_STRING`) or by
    /// ordinal through the shared `resolve_proc_address` machinery; unknown
    /// exports are `STATUS_ENTRYPOINT_NOT_FOUND`.
    pub(crate) fn dispatch_ldr_get_procedure_address(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let module_handle = guest_call_arg(state, memory, 0)?;
        let procedure_name = guest_call_arg(state, memory, 1)?;
        let ordinal = guest_call_arg_u32(state, memory, 2)?;
        let procedure_address_ptr = guest_call_arg(state, memory, 3)?;

        let symbol = if ordinal != 0 {
            if ordinal > u16::MAX as u32 {
                // Windows ordinals are 16-bit; anything larger cannot exist.
                if procedure_address_ptr != 0 {
                    write_guest_pointer(memory, procedure_address_ptr, 0, self.guest_arch)?;
                }
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_ENTRYPOINT_NOT_FOUND.raw()),
                );
                self.last_error = 0;
                return Ok(());
            }
            ImportSymbol::ByOrdinal {
                ordinal: ordinal as u16,
            }
        } else {
            match crate::ntdll::rtl::read_ansi_string_struct(
                memory,
                procedure_name,
                self.guest_arch,
            ) {
                Ok(name) if !name.is_empty() => ImportSymbol::ByName { hint: 0, name },
                _ => {
                    // Both the name pointer and the ordinal are missing.
                    if procedure_address_ptr != 0 {
                        write_guest_pointer(memory, procedure_address_ptr, 0, self.guest_arch)?;
                    }
                    state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
                    self.last_error = 0;
                    return Ok(());
                }
            }
        };

        // Dynamic-import instrumentation: LdrGetProcedureAddress is a
        // canonical runtime import-resolution path — record the resolved
        // (DLL, name) pair so import coverage accounts for it.
        let symbol_name = match &symbol {
            ImportSymbol::ByName { name, .. } => name.clone(),
            ImportSymbol::ByOrdinal { ordinal } => format!("ordinal#{ordinal}"),
        };
        let module_name = self
            .module_names_by_handle
            .get(&module_handle)
            .cloned()
            .or_else(|| {
                (module_handle == self.mapped_image_base && !self.main_module_name.is_empty())
                    .then(|| self.main_module_name.clone())
            })
            .unwrap_or_default();
        record_dynamic_import(&module_name, &symbol_name);

        let (status, address) = match self.ldr_get_procedure_address(module_handle, symbol) {
            Ok(address) => (nt::STATUS_SUCCESS, address),
            Err(status) => (status, 0),
        };
        if procedure_address_ptr != 0 {
            write_guest_pointer(memory, procedure_address_ptr, address, self.guest_arch)?;
        }
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrLockLoaderLock` — the loader-lock protocol: flag/cookie
    /// validation, then the reentrant acquire (the cooperative model is
    /// always acquirable).
    pub(crate) fn dispatch_ldr_lock_loader_lock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let flags = guest_call_arg_u32(state, memory, 0)?;
        let disposition_ptr = guest_call_arg(state, memory, 1)?;
        let cookie_ptr = guest_call_arg(state, memory, 2)?;

        if flags & !nt::LDR_LOCK_LOADER_LOCK_FLAG_MASK != 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        if cookie_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        if flags & nt::LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY != 0 && disposition_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let (cookie, disposition) = self.ldr_lock_loader_lock();
        if disposition_ptr != 0 {
            write_u32(memory, disposition_ptr, disposition);
        }
        write_guest_pointer(memory, cookie_ptr, cookie, self.guest_arch)?;
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrUnlockLoaderLock` — release one reentrancy level of the loader
    /// lock (cookie validated; NULL cookie is a no-op success).
    pub(crate) fn dispatch_ldr_unlock_loader_lock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let flags = guest_call_arg_u32(state, memory, 0)?;
        let cookie = guest_call_arg(state, memory, 1)?;
        if flags & !nt::LDR_UNLOCK_LOADER_LOCK_FLAG_MASK != 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let status = match self.ldr_unlock_loader_lock(cookie) {
            Ok(()) => nt::STATUS_SUCCESS,
            Err(status) => status,
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrAddRefDll` — the refcount primitive (PIN pins the module).
    pub(crate) fn dispatch_ldr_add_ref_dll(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let flags = guest_call_arg_u32(state, memory, 0)?;
        let module_handle = guest_call_arg(state, memory, 1)?;
        let status = match self.ldr_add_ref_dll(flags, module_handle) {
            Ok(()) => nt::STATUS_SUCCESS,
            Err(status) => status,
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `LdrRemoveRefDll` — the refcount primitive mirror (PIN unpins).
    pub(crate) fn dispatch_ldr_remove_ref_dll(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let flags = guest_call_arg_u32(state, memory, 0)?;
        let module_handle = guest_call_arg(state, memory, 1)?;
        let status = match self.ldr_remove_ref_dll(flags, module_handle) {
            Ok(()) => nt::STATUS_SUCCESS,
            Err(status) => status,
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }
}

// ── Module-local helpers shared by the dispatch arms ────────────────────────

/// Convert an Nt-layer NTSTATUS into the runtime's error type (the dispatch
/// arms surface guest-string/parse failures as AppErrors).
fn nt_status_into_app(status: nt::NtStatus) -> AppError {
    AppError::new(
        ReasonCode::RcInvalidParameter,
        format!("Nt* argument parse failed: {status}"),
    )
}

/// Read the ObjectName UNICODE_STRING of an OBJECT_ATTRIBUTES structure.
fn object_attributes_name(
    memory: &MemoryImage,
    attributes: u64,
    arch: GuestArch,
) -> AppResult<String> {
    if attributes == 0 {
        return Ok(String::new());
    }
    let name_ptr = match arch {
        GuestArch::X64 => read_guest_pointer(memory, attributes + 16, arch)?,
        GuestArch::X86 => read_guest_pointer(memory, attributes + 8, arch)?,
    };
    if name_ptr == 0 {
        return Ok(String::new());
    }
    crate::ntdll::rtl::read_unicode_string(memory, name_ptr, arch).map_err(|_| {
        AppError::new(
            ReasonCode::RcGuestStringInvalid,
            "bad OBJECT_ATTRIBUTES name",
        )
    })
}

/// The RootDirectory handle of an OBJECT_ATTRIBUTES structure.
#[allow(dead_code)]
fn object_attributes_root(memory: &MemoryImage, attributes: u64, arch: GuestArch) -> u32 {
    if attributes == 0 {
        return 0;
    }
    let root_ptr = match arch {
        GuestArch::X64 => read_guest_pointer(memory, attributes + 8, arch),
        GuestArch::X86 => read_guest_pointer(memory, attributes + 4, arch),
    };
    root_ptr.unwrap_or(0) as u32
}

/// Whether the OBJECT_ATTRIBUTES carries OBJ_INHERIT.
fn object_attributes_inheritable(memory: &MemoryImage, attributes: u64, arch: GuestArch) -> bool {
    if attributes == 0 {
        return false;
    }
    let attrs_offset = match arch {
        GuestArch::X64 => 24_u64,
        GuestArch::X86 => 16_u64,
    };
    read_u32(memory, attributes + attrs_offset).unwrap_or(0) & nt::OBJ_INHERIT != 0
}

/// Resolve the registry root handle for Nt* registry calls: the
/// OBJECT_ATTRIBUTES.RootDirectory when present, else the NT absolute name's
/// hive prefix, else the current-user root.
fn registry_root_from_attributes(memory: &MemoryImage, attributes: u64, arch: GuestArch) -> u32 {
    if attributes != 0 {
        let root_ptr = match arch {
            GuestArch::X64 => read_guest_pointer(memory, attributes + 8, arch),
            GuestArch::X86 => read_guest_pointer(memory, attributes + 4, arch),
        };
        if let Ok(root) = root_ptr
            && root != 0
        {
            return root as u32;
        }
    }
    0
}

/// Split an NT registry name into (subkey, root-handle): absolute
/// `\Registry\Machine\...` / `\Registry\User\...` names pick their hive.
fn split_registry_name(name: &str, root: u32) -> (String, u32) {
    use crate::ntdll::registry::HKEY_CURRENT_USER;
    use crate::ntdll::registry::HKEY_LOCAL_MACHINE;
    if let Some(rest) = name.strip_prefix("\\Registry\\Machine") {
        return (
            rest.trim_start_matches('\\').to_string(),
            HKEY_LOCAL_MACHINE,
        );
    }
    if let Some(rest) = name.strip_prefix("\\Registry\\User") {
        return (rest.trim_start_matches('\\').to_string(), HKEY_CURRENT_USER);
    }
    if name.starts_with('\\') && root == 0 {
        // A bare NT absolute name without a hive prefix defaults to the
        // current user hive with the leading separator stripped.
        return (name.trim_start_matches('\\').to_string(), HKEY_CURRENT_USER);
    }
    (
        name.to_string(),
        if root == 0 { HKEY_CURRENT_USER } else { root },
    )
}

/// Write an IO_STATUS_BLOCK: `{ Status: i32, Information: uptr }`.
fn write_io_status_block(
    state: &mut CpuState,
    memory: &mut MemoryImage,
    io_status_block: u64,
    status: nt::NtStatus,
    information: u64,
    arch: GuestArch,
) -> AppResult<()> {
    if io_status_block == 0 {
        return Ok(());
    }
    write_u32(memory, io_status_block, status.raw());
    match arch {
        GuestArch::X64 => write_u64(memory, io_status_block + 8, information),
        GuestArch::X86 => write_u32(memory, io_status_block + 4, information as u32),
    }
    let _ = state;
    Ok(())
}

/// Write a UNICODE_STRING header at `string_ptr` referencing `buffer_ptr`.
fn write_unicode_header(
    memory: &mut MemoryImage,
    string_ptr: u64,
    buffer_ptr: u64,
    length: u16,
    maximum_length: u16,
    arch: GuestArch,
) {
    memory.write_u16(string_ptr, length);
    memory.write_u16(string_ptr + 2, maximum_length);
    match arch {
        GuestArch::X64 => {
            memory.write_u64(string_ptr + 8, buffer_ptr);
        }
        GuestArch::X86 => {
            memory.write_u32(string_ptr + 4, buffer_ptr as u32);
        }
    }
}

/// Serialize a KEY_BASIC_INFORMATION body for NtEnumerateKey.
fn serialize_key_basic_information(name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u64.to_le_bytes()); // LastWriteTime
    body.extend_from_slice(&0u32.to_le_bytes()); // TitleIndex
    let name_bytes = name.encode_utf16().count() as u32 * 2;
    body.extend_from_slice(&name_bytes.to_le_bytes());
    body.extend(name.encode_utf16().flat_map(|u| u.to_le_bytes()));
    body
}

/// Build the X64Context the SEH subsystem consumes from the live state.
fn x64_context_from_state(state: &CpuState) -> crate::seh::X64Context {
    crate::seh::X64Context {
        rax: state.gpr[0],
        rcx: state.gpr[1],
        rdx: state.gpr[2],
        rbx: state.gpr[3],
        rsp: state.gpr[4],
        rbp: state.gpr[5],
        rsi: state.gpr[6],
        rdi: state.gpr[7],
        r8: state.gpr[8],
        r9: state.gpr[9],
        r10: state.gpr[10],
        r11: state.gpr[11],
        r12: state.gpr[12],
        r13: state.gpr[13],
        r14: state.gpr[14],
        r15: state.gpr[15],
        rip: state.rip,
        xmm: {
            let mut xmm = [crate::seh::Xmm128::default(); 16];
            for (index, slot) in xmm.iter_mut().enumerate() {
                *slot = crate::seh::Xmm128 {
                    low: state.xmm[index].low,
                    high: state.xmm[index].high,
                };
            }
            xmm
        },
    }
}

/// Compute the guest-visible EFLAGS bits from the modelled flags.
fn guest_eflags(state: &CpuState) -> u64 {
    let mut eflags = 0x2_u64; // bit 1 is always set
    if state.flags.cf {
        eflags |= 0x1;
    }
    if state.flags.pf {
        eflags |= 0x4;
    }
    if state.flags.af {
        eflags |= 0x10;
    }
    if state.flags.zf {
        eflags |= 0x40;
    }
    if state.flags.sf {
        eflags |= 0x80;
    }
    if state.flags.of {
        eflags |= 0x800;
    }
    eflags
}

/// Apply guest EFLAGS bits back onto the modelled flags.
fn apply_guest_eflags(state: &mut CpuState, eflags: u64) {
    state.flags.cf = eflags & 0x1 != 0;
    state.flags.pf = eflags & 0x4 != 0;
    state.flags.af = eflags & 0x10 != 0;
    state.flags.zf = eflags & 0x40 != 0;
    state.flags.sf = eflags & 0x80 != 0;
    state.flags.of = eflags & 0x800 != 0;
}

/// Capture the integer/control register subset into a guest CONTEXT.
fn capture_context_into_guest(
    memory: &mut MemoryImage,
    source: &CpuState,
    context_ptr: u64,
    arch: GuestArch,
) {
    match arch {
        GuestArch::X64 => {
            let flags = memory
                .read_u64(context_ptr + nt::thread::X64_CONTEXT_FLAGS_OFFSET)
                .unwrap_or(nt::thread::CONTEXT_FULL as u64);
            if flags & nt::thread::CONTEXT_INTEGER as u64 != 0 {
                for (register, offset) in nt::thread::X64_CONTEXT_GPR_OFFSETS.iter().enumerate() {
                    write_u64(memory, context_ptr + offset, source.gpr[register]);
                }
            }
            if flags & nt::thread::CONTEXT_CONTROL as u64 != 0 {
                write_u64(
                    memory,
                    context_ptr + nt::thread::X64_CONTEXT_RIP_OFFSET,
                    source.rip,
                );
                write_u64(
                    memory,
                    context_ptr + nt::thread::X64_CONTEXT_RSP_OFFSET,
                    source.gpr[4],
                );
                write_u64(
                    memory,
                    context_ptr + nt::thread::X64_CONTEXT_EFLAGS_OFFSET,
                    guest_eflags(source),
                );
            }
        }
        GuestArch::X86 => {
            let flags = memory
                .read_u32(context_ptr + nt::thread::X86_CONTEXT_FLAGS_OFFSET)
                .unwrap_or(0x10007);
            let integer = flags & 0x2 != 0;
            let control = flags & 0x1 != 0;
            if integer {
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EDI_OFFSET,
                    source.gpr[7] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_ESI_OFFSET,
                    source.gpr[6] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EBX_OFFSET,
                    source.gpr[3] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EDX_OFFSET,
                    source.gpr[2] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_ECX_OFFSET,
                    source.gpr[1] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EAX_OFFSET,
                    source.gpr[0] as u32,
                );
            }
            if control {
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EBP_OFFSET,
                    source.gpr[5] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EIP_OFFSET,
                    source.rip as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_ESP_OFFSET,
                    source.gpr[4] as u32,
                );
                write_u32(
                    memory,
                    context_ptr + nt::thread::X86_CONTEXT_EFLAGS_OFFSET,
                    guest_eflags(source) as u32,
                );
            }
        }
    }
}

/// Apply a guest CONTEXT onto the live/pending CpuState.
fn apply_context_from_guest(
    memory: &MemoryImage,
    target: &mut CpuState,
    context_ptr: u64,
    arch: GuestArch,
) {
    match arch {
        GuestArch::X64 => {
            let flags = memory
                .read_u64(context_ptr + nt::thread::X64_CONTEXT_FLAGS_OFFSET)
                .unwrap_or(nt::thread::CONTEXT_FULL as u64);
            if flags & nt::thread::CONTEXT_INTEGER as u64 != 0 {
                for (register, offset) in nt::thread::X64_CONTEXT_GPR_OFFSETS.iter().enumerate() {
                    if let Ok(value) = memory.read_u64(context_ptr + offset) {
                        target.gpr[register] = value;
                    }
                }
            }
            if flags & nt::thread::CONTEXT_CONTROL as u64 != 0 {
                if let Ok(rip) = memory.read_u64(context_ptr + nt::thread::X64_CONTEXT_RIP_OFFSET) {
                    target.rip = rip;
                }
                if let Ok(eflags) =
                    memory.read_u64(context_ptr + nt::thread::X64_CONTEXT_EFLAGS_OFFSET)
                {
                    apply_guest_eflags(target, eflags);
                }
            }
        }
        GuestArch::X86 => {
            let flags = memory
                .read_u32(context_ptr + nt::thread::X86_CONTEXT_FLAGS_OFFSET)
                .unwrap_or(0x10007);
            if flags & 0x2 != 0 {
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EDI_OFFSET)
                {
                    target.gpr[7] = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_ESI_OFFSET)
                {
                    target.gpr[6] = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EBX_OFFSET)
                {
                    target.gpr[3] = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EDX_OFFSET)
                {
                    target.gpr[2] = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_ECX_OFFSET)
                {
                    target.gpr[1] = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EAX_OFFSET)
                {
                    target.gpr[0] = u64::from(value);
                }
            }
            if flags & 0x1 != 0 {
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EBP_OFFSET)
                {
                    target.gpr[5] = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EIP_OFFSET)
                {
                    target.rip = u64::from(value);
                }
                if let Ok(value) = memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_ESP_OFFSET)
                {
                    target.gpr[4] = u64::from(value);
                }
                if let Ok(eflags) =
                    memory.read_u32(context_ptr + nt::thread::X86_CONTEXT_EFLAGS_OFFSET)
                {
                    apply_guest_eflags(target, u64::from(eflags));
                }
            }
        }
    }
}
