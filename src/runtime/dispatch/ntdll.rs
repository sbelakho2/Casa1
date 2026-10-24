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
use super::final_scraps::{
    native_child_host_pid, native_child_launch_cancel_suspended, native_child_launch_resume_claim,
    native_child_launch_unclaim, native_child_terminate_host,
    native_child_thread_handles_for_process, native_child_thread_info, native_child_thread_retain,
    native_child_thread_take, section_image_register,
};
use crate::casak::introspection as kintro;
use crate::ntdll as nt;
use crate::pe::ImportSymbol;

/// `SEC_IMAGE` — the `NtCreateSection` allocation attribute that creates an
/// image section (the section carries the PE image of its backing file).
const SEC_IMAGE: u32 = 0x0100_0000;

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
        in_buffer: u64,
        in_size: u32,
        out_buffer: u64,
        out_size: u32,
        bytes_ret_ptr: u64,
    ) -> AppResult<()> {
        // The handle must be a live kernel object (Windows fails IOCTLs on
        // invalid handles with ERROR_INVALID_HANDLE before touching the
        // control code).
        if handle == 0 || self.win32.handle_object_type(handle).is_err() {
            if bytes_ret_ptr != 0 {
                write_u32(memory, bytes_ret_ptr, 0);
            }
            self.last_error = ERROR_INVALID_HANDLE;
            state.set(Register::Rax, 0); // FALSE
            return Ok(());
        }
        // Helper: report success with N bytes returned.
        macro_rules! done {
            ($returned:expr) => {{
                if bytes_ret_ptr != 0 {
                    write_u32(memory, bytes_ret_ptr, $returned);
                }
                self.last_error = 0;
                state.set(Register::Rax, 1); // TRUE
                return Ok(());
            }};
        }
        // The guest disk geometry the runtime models: 512 GB fixed disk,
        // 512-byte sectors, 32 sectors per track, 64 tracks per cylinder.
        const DISK_BYTES: u64 = 512 * 1024 * 1024 * 1024;
        const SECTORS_PER_TRACK: u32 = 32;
        const TRACKS_PER_CYLINDER: u32 = 64;
        const BYTES_PER_SECTOR: u32 = 512;
        const CYLINDERS: u64 = DISK_BYTES
            / (BYTES_PER_SECTOR as u64 * SECTORS_PER_TRACK as u64 * TRACKS_PER_CYLINDER as u64);
        // Common IOCTL codes used by applications in VM context
        match io_code {
            // FSCTL_SET_SPARSE (mark file as sparse)
            0x000900C4 => done!(0),
            // FSCTL_SET_ZERO_DATA (zero a range in sparse file)
            0x000980C8 => done!(0),
            // FSCTL_GET_COMPRESSION — the file's compression state (u16).
            0x0009003C => {
                if out_buffer != 0 && out_size >= 2 {
                    write_u16(memory, out_buffer, 0); // COMPRESSION_FORMAT_NONE
                    done!(2);
                }
                done!(0);
            }
            // FSCTL_SET_COMPRESSION — set the compression state.
            0x0009C040 => done!(0),
            // FSCTL_IS_VOLUME_DIRTY — BOOL (0 = clean).
            0x00090078 => {
                if out_buffer != 0 && out_size >= 4 {
                    write_u32(memory, out_buffer, 0);
                    done!(4);
                }
                done!(0);
            }
            // FSCTL_LOCK_VOLUME / FSCTL_UNLOCK_VOLUME — the guest volume is
            // exclusively owned by this process; both succeed.
            0x00090018 | 0x0009001C => done!(0),
            // FSCTL_QUERY_ALLOCATED_RANGES — every byte of the sparse file
            // is allocated (one full-range entry).
            0x000940CF => {
                if out_buffer != 0 && out_size >= 16 {
                    write_u64(memory, out_buffer, 0); // FileOffset
                    write_u64(memory, out_buffer + 8, DISK_BYTES); // Length
                    done!(16);
                }
                done!(0);
            }
            // IOCTL_DISK_GET_DRIVE_GEOMETRY
            0x00070000 => {
                // DISK_GEOMETRY: Cylinders(8), MediaType(4), TracksPerCylinder(4), SectorsPerTrack(4), BytesPerSector(4) = 24 bytes
                if out_buffer != 0 && out_size >= 24 {
                    write_u64(memory, out_buffer, CYLINDERS);
                    write_u32(memory, out_buffer + 8, 0x07); // FixedMedia = 7
                    write_u32(memory, out_buffer + 12, TRACKS_PER_CYLINDER);
                    write_u32(memory, out_buffer + 16, SECTORS_PER_TRACK);
                    write_u32(memory, out_buffer + 20, BYTES_PER_SECTOR);
                    done!(24);
                }
                done!(0);
            }
            // IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            0x00070050 => {
                // DISK_GEOMETRY_EX: DISK_GEOMETRY (24) + DiskSize (8) + 4 pad.
                if out_buffer != 0 && out_size >= 36 {
                    write_u64(memory, out_buffer, CYLINDERS);
                    write_u32(memory, out_buffer + 8, 0x07); // FixedMedia
                    write_u32(memory, out_buffer + 12, TRACKS_PER_CYLINDER);
                    write_u32(memory, out_buffer + 16, SECTORS_PER_TRACK);
                    write_u32(memory, out_buffer + 20, BYTES_PER_SECTOR);
                    write_u64(memory, out_buffer + 24, DISK_BYTES); // DiskSize
                    memory.map_bytes(out_buffer + 32, &[0_u8; 4]); // pad
                    done!(36);
                }
                done!(0);
            }
            // IOCTL_DISK_GET_LENGTH_INFO — the disk size in bytes.
            0x0007405C => {
                if out_buffer != 0 && out_size >= 8 {
                    write_u64(memory, out_buffer, DISK_BYTES);
                    done!(8);
                }
                done!(0);
            }
            // IOCTL_DISK_GET_PARTITION_INFO_EX — one primary partition.
            0x00070048 => {
                // PARTITION_INFORMATION_EX: PartitionStyle(4) + union
                // (MBR: 16 bytes — starting offset 8, length 8, partition
                // type 1, boot indicator 1, hidden sectors 4) + 4 pad = 24.
                if out_buffer != 0 && out_size >= 24 {
                    write_u32(memory, out_buffer, 0); // PARTITION_STYLE_MBR
                    write_u64(memory, out_buffer + 4, 0); // StartingOffset
                    write_u64(memory, out_buffer + 12, DISK_BYTES); // PartitionLength
                    memory.write_u8(out_buffer + 20, 0x07); // MBR type NTFS
                    memory.map_bytes(out_buffer + 21, &[0_u8; 3]);
                    done!(24);
                }
                done!(0);
            }
            // IOCTL_CDROM_GET_DRIVE_GEOMETRY
            0x00070004 => {
                if out_buffer != 0 && out_size >= 24 {
                    write_u64(memory, out_buffer, 0); // Cylinders
                    write_u32(memory, out_buffer + 8, 0x02); // RemovableMedia = 2
                    write_u32(memory, out_buffer + 12, 1); // TracksPerCylinder
                    write_u32(memory, out_buffer + 16, 1); // SectorsPerTrack
                    write_u32(memory, out_buffer + 20, 2048); // BytesPerSector (CD-ROM)
                    done!(24);
                }
                done!(0);
            }
            // IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX
            0x0007004F => {
                if out_buffer != 0 && out_size >= 36 {
                    write_u64(memory, out_buffer, 0);
                    write_u32(memory, out_buffer + 8, 0x02); // RemovableMedia
                    write_u32(memory, out_buffer + 12, 1);
                    write_u32(memory, out_buffer + 16, 1);
                    write_u32(memory, out_buffer + 20, 2048);
                    write_u64(memory, out_buffer + 24, 470 * 1024 * 1024); // 470 MB disc
                    memory.map_bytes(out_buffer + 32, &[0_u8; 4]);
                    done!(36);
                }
                done!(0);
            }
            // IOCTL_STORAGE_CHECK_VERIFY2 (check if media is present)
            0x00074000 => done!(0),
            // IOCTL_STORAGE_GET_DEVICE_NUMBER
            0x002D0000 => {
                // STORAGE_DEVICE_NUMBER: DeviceType(4), DeviceNumber(4), PartitionNumber(4) = 12 bytes
                if out_buffer != 0 && out_size >= 12 {
                    write_u32(memory, out_buffer, 0x07); // FILE_DEVICE_DISK
                    write_u32(memory, out_buffer + 4, 0); // DeviceNumber
                    write_u32(memory, out_buffer + 8, 1); // PartitionNumber
                    done!(12);
                }
                done!(0);
            }
            // IOCTL_STORAGE_GET_DEVICE_NUMBER_EX
            0x002D5000 => {
                if out_buffer != 0 && out_size >= 12 {
                    write_u32(memory, out_buffer, 0x07); // DeviceType
                    write_u32(memory, out_buffer + 4, 0); // DeviceNumber
                    write_u32(memory, out_buffer + 8, 1); // PartitionNumber
                    done!(12);
                }
                done!(0);
            }
            // IOCTL_STORAGE_GET_MEDIA_TYPES_EX
            0x000D0004 => {
                // Return minimal DEVICE_MEDIA_INFO
                if out_buffer != 0 && out_size >= 8 {
                    write_u32(memory, out_buffer, 0x0B); // StorageMediaType = FixedMedium
                    write_u32(memory, out_buffer + 4, 0); // DeviceSpecific
                    done!(8);
                }
                done!(0);
            }
            // IOCTL_STORAGE_QUERY_PROPERTY — the property-query family:
            // STORAGE_DEVICE_DESCRIPTOR (0) and STORAGE_DEVICE_NUMBER_PROPERTY (2).
            0x002D1400 => {
                let property_id = if in_buffer != 0 && in_size >= 4 {
                    read_guest_u32(memory, in_buffer).unwrap_or(0)
                } else {
                    0
                };
                match property_id {
                    0 => {
                        // STORAGE_DEVICE_DESCRIPTOR (no strings attached).
                        if out_buffer != 0 && out_size >= 64 {
                            write_u32(memory, out_buffer, 48); // Version
                            write_u32(memory, out_buffer + 4, 48); // Size
                            memory.write_u8(out_buffer + 8, 0x07); // DeviceType: FILE_DEVICE_DISK
                            memory.write_u8(out_buffer + 9, 0); // DeviceTypeModifier
                            memory.write_u8(out_buffer + 10, 0); // RemovableMedia
                            memory.write_u8(out_buffer + 11, 1); // CommandQueueing
                            memory.map_bytes(out_buffer + 12, &[0_u8; 36]);
                            done!(48);
                        }
                        done!(0);
                    }
                    2 => {
                        // STORAGE_DEVICE_NUMBER_PROPERTY.
                        if out_buffer != 0 && out_size >= 12 {
                            write_u32(memory, out_buffer, 0x07); // DeviceType
                            write_u32(memory, out_buffer + 4, 0); // DeviceNumber
                            write_u32(memory, out_buffer + 8, 1); // PartitionNumber
                            done!(12);
                        }
                        done!(0);
                    }
                    _ => {
                        self.last_error = ERROR_INVALID_PARAMETER;
                        state.set(Register::Rax, 0);
                        if bytes_ret_ptr != 0 {
                            write_u32(memory, bytes_ret_ptr, 0);
                        }
                    }
                }
            }
            // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS — the volume spans the
            // whole disk partition.
            0x00560000 => {
                if out_buffer != 0 && out_size >= 24 {
                    write_u32(memory, out_buffer, 1); // NumberOfDiskExtents
                    write_u32(memory, out_buffer + 4, 0); // DiskNumber
                    write_u64(memory, out_buffer + 8, 0); // StartingOffset
                    write_u64(memory, out_buffer + 16, DISK_BYTES); // ExtentLength
                    done!(24);
                }
                done!(0);
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
    ///
    /// PAIR CONTRACT (VirtualAlloc ↔ NtAllocateVirtualMemory): BOTH surfaces
    /// mutate the ONE canonical [`crate::vm::VirtualMemory`] through the
    /// same `reserve`/`commit` primitives and the same
    /// PAGE_* → VmProtection conversion, so the Win32 VirtualAlloc thunk and
    /// this dispatch write identical state (the section50 cross-surface
    /// test pins VirtualAlloc → NtQueryVirtualMemory agreement).
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
        if crate::driver_island::close_directory_object(self, handle) {
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            self.last_error = 0;
            return Ok(());
        }
        if crate::driver_island::close_island_device_handle(self, handle) {
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            self.last_error = 0;
            return Ok(());
        }
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

    // ── Directory objects + volume information ──────────────────────────────

    /// `NtOpenDirectoryObject` — open the root object directory `\`, one of
    /// the live top-level directories (`\Device`, `\Driver`, `\GLOBAL??`,
    /// `\??`) or a real per-object subtree (`\Device\<name>`,
    /// `\Driver\<name>`, including deeper device paths).
    ///
    /// The names in those directories are enumerated live from the driver
    /// island registry: devices the loaded islands created, the loaded
    /// drivers themselves and the symbolic links they installed.  An unknown
    /// child of an existing directory is `STATUS_OBJECT_NAME_NOT_FOUND`; a
    /// name whose parent directory does not exist is
    /// `STATUS_OBJECT_PATH_NOT_FOUND` (never a fabricated handle).
    pub(crate) fn dispatch_nt_open_directory_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_ptr = guest_call_arg(state, memory, 0)?;
        let _desired_access = guest_call_arg_u32(state, memory, 1)?;
        let object_attributes = guest_call_arg(state, memory, 2)?;
        if handle_ptr == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let raw_name = match object_attributes_name(memory, object_attributes, self.guest_arch) {
            Ok(name) => name,
            Err(_) => {
                state.set(
                    Register::Rax,
                    u64::from(nt::STATUS_OBJECT_NAME_INVALID.raw()),
                );
                self.last_error = 0;
                return Ok(());
            }
        };
        let path = raw_name.replace('/', "\\");
        let path = {
            let mut trimmed = path.trim_matches('\0').trim().to_string();
            if trimmed.len() > 1 {
                while trimmed.ends_with('\\') {
                    trimmed.pop();
                }
            }
            trimmed
        };
        if path.is_empty() {
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_OBJECT_NAME_INVALID.raw()),
            );
            self.last_error = 0;
            return Ok(());
        }
        let namespace = crate::driver_island::island_namespace(self);
        if let Some(directory) = crate::driver_island::canonical_directory_name(&namespace, &path) {
            let handle = crate::driver_island::open_directory_object(self, &directory);
            write_guest_pointer(memory, handle_ptr, u64::from(handle), self.guest_arch)?;
            state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            self.last_error = 0;
            return Ok(());
        }
        // A missing child of an existing directory is NAME_NOT_FOUND; a name
        // whose immediate parent is itself absent is PATH_NOT_FOUND.
        let (parent, _child) = path.rsplit_once('\\').unwrap_or(("", path.as_str()));
        let parent_exists = parent.is_empty()
            || parent == "\\"
            || crate::driver_island::canonical_directory_name(&namespace, parent).is_some();
        let status = if parent_exists {
            nt::STATUS_OBJECT_NAME_NOT_FOUND
        } else {
            nt::STATUS_OBJECT_PATH_NOT_FOUND
        };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtQueryDirectoryObject` — enumerate one directory object.
    ///
    /// The output is an array of `OBJECT_DIRECTORY_INFORMATION` records
    /// (`UNICODE_STRING Name; UNICODE_STRING TypeName;`) followed by the
    /// strings; `Context` is the resumable index.  Enumeration reads the live
    /// island registry on every call, so a device deleted, a child removed or
    /// a driver unloaded between calls disappears from the next result.  The
    /// root reports the four top-level namespaces; per-device subtrees report
    /// real child device objects and per-driver subtrees report the live
    /// devices the driver created.
    pub(crate) fn dispatch_nt_query_directory_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg_u32(state, memory, 2)?;
        let return_single = guest_call_arg_u32(state, memory, 3)? != 0;
        let restart = guest_call_arg_u32(state, memory, 4)? != 0;
        let context_ptr = guest_call_arg(state, memory, 5)?;
        let return_length_ptr = guest_call_arg(state, memory, 6)?;

        let Some(directory) = crate::driver_island::directory_object_path(self, handle) else {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
            self.last_error = 0;
            return Ok(());
        };
        if context_ptr == 0 && !restart {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        if buffer == 0 && length != 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let index = if restart {
            0
        } else {
            read_u32(memory, context_ptr)? as usize
        };
        let namespace = crate::driver_island::island_namespace(self);
        let entries = crate::driver_island::directory_entries(&namespace, &directory);
        if index >= entries.len() {
            if context_ptr != 0 {
                write_u32(memory, context_ptr, index as u32);
            }
            if return_length_ptr != 0 {
                write_u32(memory, return_length_ptr, 0);
            }
            state.set(Register::Rax, u64::from(nt::STATUS_NO_MORE_ENTRIES.raw()));
            self.last_error = 0;
            return Ok(());
        }

        let header = match self.guest_arch {
            GuestArch::X64 => 32_u64,
            GuestArch::X86 => 16_u64,
        };
        let mut chosen: Vec<(String, String, u64, u64)> = Vec::new();
        let mut name_bytes = 0_u64;
        let mut required = 0_u64;
        for (name, type_name) in entries.iter().skip(index) {
            let name_units: Vec<u16> = name.encode_utf16().collect();
            let type_units: Vec<u16> = type_name.encode_utf16().collect();
            let name_len = name_units.len() as u64 * 2;
            let type_len = type_units.len() as u64 * 2;
            let candidate_headers = (chosen.len() as u64 + 1) * header;
            let candidate = candidate_headers + name_bytes + name_len + type_len;
            if candidate > u64::from(length) {
                if chosen.is_empty() {
                    required = candidate;
                }
                break;
            }
            chosen.push((name.clone(), type_name.clone(), name_len, type_len));
            name_bytes += name_len + type_len;
            if return_single {
                break;
            }
        }
        if chosen.is_empty() {
            if return_length_ptr != 0 {
                write_u32(memory, return_length_ptr, required as u32);
            }
            state.set(Register::Rax, u64::from(nt::STATUS_BUFFER_TOO_SMALL.raw()));
            self.last_error = 0;
            return Ok(());
        }

        let total = chosen.len() as u64 * header + name_bytes;
        memory.map_bytes(buffer, &vec![0_u8; total as usize]);
        let mut string_cursor = buffer + chosen.len() as u64 * header;
        for (entry_index, (name, type_name, name_len, type_len)) in chosen.iter().enumerate() {
            let entry = buffer + entry_index as u64 * header;
            let name_ptr = string_cursor;
            string_cursor += name_len;
            let type_ptr = string_cursor;
            string_cursor += type_len;
            write_unicode_header(
                memory,
                entry,
                name_ptr,
                *name_len as u16,
                *name_len as u16,
                self.guest_arch,
            );
            let type_entry = entry
                + match self.guest_arch {
                    GuestArch::X64 => 16,
                    GuestArch::X86 => 8,
                };
            write_unicode_header(
                memory,
                type_entry,
                type_ptr,
                *type_len as u16,
                *type_len as u16,
                self.guest_arch,
            );
            for (unit_index, unit) in name.encode_utf16().enumerate() {
                write_u16(memory, name_ptr + unit_index as u64 * 2, unit);
            }
            for (unit_index, unit) in type_name.encode_utf16().enumerate() {
                write_u16(memory, type_ptr + unit_index as u64 * 2, unit);
            }
        }
        let next = index + chosen.len();
        if context_ptr != 0 {
            write_u32(memory, context_ptr, next as u32);
        }
        if return_length_ptr != 0 {
            write_u32(memory, return_length_ptr, total as u32);
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// The host volume's creation time as Windows FILETIME ticks.
    ///
    /// The probe walks from `host_path` up to its mount root (the nearest
    /// ancestor on the same device) and reads the host-published birth time
    /// (`st_birthtime` on macOS, the value IOKit/diskutil expose when they
    /// publish one).  If the host genuinely does not publish it — or the path
    /// does not exist — the caller must report `STATUS_NOT_SUPPORTED` rather
    /// than inventing a zero.
    pub(crate) fn host_volume_creation_time_ticks(host_path: &std::path::Path) -> Option<u64> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !host_path.exists() {
                return None;
            }
            let device = std::fs::metadata(host_path).ok()?.dev();
            let mut root = host_path.to_path_buf();
            while let Some(parent) = root.parent() {
                match std::fs::metadata(parent) {
                    Ok(metadata) if metadata.dev() == device => root = parent.to_path_buf(),
                    _ => break,
                }
            }
            let created = std::fs::metadata(&root).ok()?.created().ok()?;
            let duration = created.duration_since(std::time::UNIX_EPOCH).ok()?;
            Some(
                WINDOWS_EPOCH_OFFSET_100NS
                    .saturating_add(duration.as_nanos().div_euclid(100) as u64),
            )
        }
        #[cfg(not(unix))]
        {
            let _ = host_path;
            None
        }
    }

    /// `FILE_FS_VOLUME_INFORMATION` with the real creation time, serial,
    /// label and object support flag.  A volume whose creation time the host
    /// does not publish is `STATUS_NOT_SUPPORTED`, never a zeroed field.
    pub(crate) fn serialize_file_fs_volume_information(
        disk: &crate::hardware_identity::DiskIdentity,
        creation_ticks: Option<u64>,
    ) -> Result<Vec<u8>, nt::NtStatus> {
        let creation = creation_ticks.ok_or(nt::STATUS_NOT_SUPPORTED)?;
        let label: Vec<u16> = disk.volume_name.encode_utf16().collect();
        let mut bytes = vec![0_u8; 20 + label.len() * 2];
        bytes[0..8].copy_from_slice(&creation.to_le_bytes());
        bytes[8..12].copy_from_slice(&disk.volume_serial.to_le_bytes());
        bytes[12..16].copy_from_slice(&((label.len() * 2) as u32).to_le_bytes());
        bytes[16] = 1; // SupportsObjects: the volume holds real file objects.
        for (index, unit) in label.iter().enumerate() {
            bytes[20 + index * 2..20 + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        Ok(bytes)
    }

    /// `FILE_FS_OBJECTID_INFORMATION` with the real volume object id and
    /// extended info derived from the host-published volume UUID.  A volume
    /// with no published UUID is `STATUS_NOT_SUPPORTED`, never a zeroed id.
    pub(crate) fn serialize_file_fs_object_id_information(
        disk: &crate::hardware_identity::DiskIdentity,
    ) -> Result<Vec<u8>, nt::NtStatus> {
        if disk.volume_uuid.is_empty() {
            return Err(nt::STATUS_NOT_SUPPORTED);
        }
        let mut bytes = vec![0_u8; 64];
        let object_id = crate::anticheat::sha256(
            format!("casa1-volume-object-id:{}", disk.volume_uuid).as_bytes(),
        );
        bytes[0..16].copy_from_slice(&object_id[0..16]);
        let extended = crate::anticheat::sha256(
            format!(
                "casa1-volume-extended-object-id:{}:{:08X}",
                disk.volume_uuid, disk.volume_serial
            )
            .as_bytes(),
        );
        bytes[16..48].copy_from_slice(&extended);
        let extended_tail = crate::anticheat::sha256(
            format!("casa1-volume-extended-object-id-2:{}", disk.volume_uuid).as_bytes(),
        );
        bytes[48..64].copy_from_slice(&extended_tail[0..16]);
        Ok(bytes)
    }

    /// `NtQueryVolumeInformationFile` — the real volume identity/storage
    /// facts for the volume holding `FileHandle`.
    ///
    /// Identity (label, serial, filesystem, object id) comes from the ONE
    /// process-wide hardware identity; storage (allocation units, sector
    /// geometry) comes from the host `statvfs` accounting the Win32
    /// `GetDiskFreeSpace*` surface also reads.  A handle that is not a file
    /// handle is `STATUS_OBJECT_TYPE_MISMATCH`; an unknown handle is
    /// `STATUS_INVALID_HANDLE`.
    pub(crate) fn dispatch_nt_query_volume_information_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg_u32(state, memory, 0)?;
        let io_status_block = guest_call_arg(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg_u32(state, memory, 3)?;
        let info_class = guest_call_arg_u32(state, memory, 4)?;

        let arch = self.guest_arch;
        let finish = |state: &mut CpuState,
                      memory: &mut MemoryImage,
                      status: nt::NtStatus,
                      information: u64|
         -> AppResult<()> {
            write_io_status_block(state, memory, io_status_block, status, information, arch)?;
            state.set(Register::Rax, u64::from(status.raw()));
            Ok(())
        };
        if io_status_block == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let object_type = match self.win32.handle_object_type(handle) {
            Ok(object_type) => object_type,
            Err(_) => {
                self.last_error = 0;
                return finish(state, memory, nt::STATUS_INVALID_HANDLE, 0);
            }
        };
        if object_type != crate::runtime::object_manager::ObjectType::File {
            self.last_error = 0;
            return finish(state, memory, nt::STATUS_OBJECT_TYPE_MISMATCH, 0);
        }
        let file_path = match self.win32.file_state(handle) {
            Ok(file) => file.normalized_path,
            Err(_) => {
                self.last_error = 0;
                return finish(state, memory, nt::STATUS_INVALID_HANDLE, 0);
            }
        };
        if buffer == 0 {
            self.last_error = 0;
            return finish(state, memory, nt::STATUS_INVALID_PARAMETER, 0);
        }
        let identity = crate::hardware_identity::host_identity();
        let Some(disk) = identity.disks.first() else {
            self.last_error = 0;
            return finish(state, memory, nt::STATUS_NOT_SUPPORTED, 0);
        };
        let capacity = match self.win32.volume_capacity(Some(&file_path)) {
            Ok(capacity) => capacity,
            Err(_) => {
                self.last_error = 0;
                return finish(state, memory, nt::STATUS_OBJECT_PATH_NOT_FOUND, 0);
            }
        };
        let creation_ticks = self
            .win32
            .ge()
            .host_path_for_windows_path(&file_path)
            .ok()
            .and_then(|host_path| Self::host_volume_creation_time_ticks(&host_path));

        // FILE_FS_VOLUME_INFORMATION
        const FS_VOLUME: u32 = 1;
        const FS_SIZE: u32 = 3;
        const FS_DEVICE: u32 = 4;
        const FS_ATTRIBUTE: u32 = 5;
        const FS_FULL_SIZE: u32 = 7;
        const FS_OBJECT_ID: u32 = 8;
        const FS_VOLUME_FLAGS: u32 = 10;
        const FS_SECTOR_SIZE: u32 = 11;
        const FILE_DEVICE_DISK: u32 = 7;
        const FILE_DEVICE_IS_MOUNTED: u32 = 0x10;
        const FILE_REMOVABLE_MEDIA: u32 = 0x1;
        const FILE_CASE_PRESERVED_NAMES: u32 = 0x2;
        const FILE_UNICODE_ON_DISK: u32 = 0x4;

        let bytes = match info_class {
            FS_VOLUME => match Self::serialize_file_fs_volume_information(disk, creation_ticks) {
                Ok(bytes) => bytes,
                Err(status) => {
                    self.last_error = 0;
                    return finish(state, memory, status, 0);
                }
            },
            FS_SIZE => {
                let mut bytes = vec![0_u8; 24];
                bytes[0..8].copy_from_slice(&capacity.total_clusters.to_le_bytes());
                bytes[8..16].copy_from_slice(&capacity.free_clusters.to_le_bytes());
                bytes[16..20].copy_from_slice(&capacity.sectors_per_cluster.to_le_bytes());
                bytes[20..24].copy_from_slice(&capacity.bytes_per_sector.to_le_bytes());
                bytes
            }
            FS_DEVICE => {
                let mut bytes = vec![0_u8; 8];
                bytes[0..4].copy_from_slice(&FILE_DEVICE_DISK.to_le_bytes());
                let characteristics = FILE_DEVICE_IS_MOUNTED
                    | if disk.removable {
                        FILE_REMOVABLE_MEDIA
                    } else {
                        0
                    };
                bytes[4..8].copy_from_slice(&characteristics.to_le_bytes());
                bytes
            }
            FS_ATTRIBUTE => {
                let name: Vec<u16> = disk.filesystem.encode_utf16().collect();
                let mut bytes = vec![0_u8; 12 + name.len() * 2];
                let attributes = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
                bytes[0..4].copy_from_slice(&attributes.to_le_bytes());
                bytes[4..8].copy_from_slice(&255_i32.to_le_bytes());
                bytes[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
                for (index, unit) in name.iter().enumerate() {
                    bytes[12 + index * 2..12 + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
                }
                bytes
            }
            FS_FULL_SIZE => {
                let mut bytes = vec![0_u8; 32];
                bytes[0..8].copy_from_slice(&capacity.total_clusters.to_le_bytes());
                bytes[8..16].copy_from_slice(&capacity.free_clusters.to_le_bytes());
                bytes[16..24].copy_from_slice(&capacity.free_clusters.to_le_bytes());
                bytes[24..28].copy_from_slice(&capacity.sectors_per_cluster.to_le_bytes());
                bytes[28..32].copy_from_slice(&capacity.bytes_per_sector.to_le_bytes());
                bytes
            }
            FS_OBJECT_ID => match Self::serialize_file_fs_object_id_information(disk) {
                Ok(bytes) => bytes,
                Err(status) => {
                    self.last_error = 0;
                    return finish(state, memory, status, 0);
                }
            },
            FS_VOLUME_FLAGS => vec![0_u8; 4],
            FS_SECTOR_SIZE => {
                let mut bytes = vec![0_u8; 24];
                bytes[0..4].copy_from_slice(&capacity.bytes_per_sector.to_le_bytes());
                bytes[4..8].copy_from_slice(&capacity.bytes_per_sector.to_le_bytes());
                bytes
            }
            _ => {
                self.last_error = 0;
                return finish(state, memory, nt::STATUS_INVALID_INFO_CLASS, 0);
            }
        };
        if u64::from(length) < bytes.len() as u64 {
            self.last_error = 0;
            return finish(
                state,
                memory,
                nt::STATUS_INFO_LENGTH_MISMATCH,
                bytes.len() as u64,
            );
        }
        memory.map_bytes(buffer, &bytes);
        self.last_error = 0;
        finish(state, memory, nt::STATUS_SUCCESS, bytes.len() as u64)
    }

    // ── Attestation: nonce challenge, signed quote, provider verification ────

    /// The install identity store backing guest attestation enrollment.
    fn attestation_store(&self) -> crate::anticheat::InstallIdentityStore {
        crate::anticheat::InstallIdentityStore::open(self.win32.ge().root.join("attestation"))
    }

    /// Bring one provider's persisted enrollment/revocation into the live
    /// registry before a verification decision.
    fn sync_attestation_provider(&mut self, provider_id: &str) {
        let store = self.attestation_store();
        if store.is_revoked(provider_id) {
            self.anticheat.attestation.revoke_provider(provider_id);
        }
        if self.anticheat.attestation.provider(provider_id).is_none()
            && let Ok(Some(key)) = store.load_provider(provider_id)
        {
            let _ = self.anticheat.attestation.register_provider(key);
        }
    }

    /// `NtAttestationEnrollProvider` — enroll a real provider public key.
    ///
    /// `(ProviderId UTF-8*, PublicKey SPKI DER*, KeyLength, TTL ms)`.  The id
    /// is validated before it becomes an install-store file name, the key
    /// must parse as a P-256 SubjectPublicKeyInfo, and the enrollment is
    /// persisted before it becomes trusted.  A duplicate id is
    /// `STATUS_OBJECT_NAME_COLLISION`, a malformed id/key is
    /// `STATUS_INVALID_PARAMETER`, and a revoked id is
    /// `STATUS_ACCESS_DENIED`.  A zero TTL means no expiry.
    pub(crate) fn dispatch_nt_attestation_enroll_provider(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider_ptr = guest_call_arg(state, memory, 0)?;
        let key_ptr = guest_call_arg(state, memory, 1)?;
        let key_length = guest_call_arg_u32(state, memory, 2)?;
        let ttl_ms = guest_call_arg(state, memory, 3)?;

        let provider = match read_c_string(memory, provider_ptr) {
            Ok(provider) if crate::anticheat::is_valid_provider_id(&provider) => provider,
            _ => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        if key_ptr == 0 || key_length == 0 || key_length as usize > 4096 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let mut public_key = vec![0_u8; key_length as usize];
        memory.read_into(key_ptr, &mut public_key)?;

        let store = self.attestation_store();
        if store.is_revoked(&provider) {
            self.anticheat.attestation.revoke_provider(&provider);
            state.set(
                Register::Rax,
                u64::from(crate::anticheat::attestation_ntstatus(
                    &crate::anticheat::AttestationError::RevokedProvider,
                )),
            );
            self.last_error = 0;
            return Ok(());
        }
        let duplicate = self.anticheat.attestation.provider(&provider).is_some()
            || store.load_provider(&provider).ok().flatten().is_some();
        if duplicate {
            state.set(
                Register::Rax,
                u64::from(crate::anticheat::attestation_ntstatus(
                    &crate::anticheat::AttestationError::DuplicateProvider,
                )),
            );
            self.last_error = 0;
            return Ok(());
        }
        let now = self.anticheat.clock.tick_count64();
        let valid_until_ms = (ttl_ms != 0).then(|| now.saturating_add(ttl_ms));
        let key = match store.enroll_provider_key(&provider, &public_key, valid_until_ms, now) {
            Ok(key) => key,
            Err(error) => {
                state.set(
                    Register::Rax,
                    u64::from(crate::anticheat::attestation_ntstatus(&error)),
                );
                self.last_error = 0;
                return Ok(());
            }
        };
        self.anticheat
            .attestation
            .register_provider(key)
            .expect("enrollment prechecks duplicate and revocation");
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtAttestationRevokeProvider` — revoke a provider and persist the
    /// revocation.  An unknown id is `STATUS_OBJECT_NAME_NOT_FOUND`; an
    /// already-revoked id succeeds (revocation is idempotent).
    pub(crate) fn dispatch_nt_attestation_revoke_provider(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let provider_ptr = guest_call_arg(state, memory, 0)?;
        let provider = match read_c_string(memory, provider_ptr) {
            Ok(provider) if crate::anticheat::is_valid_provider_id(&provider) => provider,
            _ => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        let store = self.attestation_store();
        let known = self.anticheat.attestation.provider(&provider).is_some()
            || store.load_provider(&provider).ok().flatten().is_some();
        if !known {
            state.set(
                Register::Rax,
                u64::from(crate::anticheat::attestation_ntstatus(
                    &crate::anticheat::AttestationError::UnknownProvider,
                )),
            );
            self.last_error = 0;
            return Ok(());
        }
        if let Err(error) = store.revoke_provider(&provider) {
            state.set(
                Register::Rax,
                u64::from(crate::anticheat::attestation_ntstatus(&error)),
            );
            self.last_error = 0;
            return Ok(());
        }
        self.anticheat.attestation.revoke_provider(&provider);
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtAttestationChallenge` — issue a real nonce challenge.
    ///
    /// `(Verifier UTF-8*, TTL ms, Challenge out*, Challenge length,
    /// Required* )`.  The nonce comes from the OS CSPRNG and the issue time
    /// from the runtime's monotonic guest clock; a zero TTL or empty
    /// verifier is `STATUS_INVALID_PARAMETER`, a short buffer is
    /// `STATUS_INFO_LENGTH_MISMATCH` with the exact required size.
    pub(crate) fn dispatch_nt_attestation_challenge(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let verifier_ptr = guest_call_arg(state, memory, 0)?;
        let ttl_ms = guest_call_arg(state, memory, 1)?;
        let output = guest_call_arg(state, memory, 2)?;
        let output_length = guest_call_arg_u32(state, memory, 3)?;
        let required_ptr = guest_call_arg(state, memory, 4)?;

        if output == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let verifier = match read_c_string(memory, verifier_ptr) {
            Ok(verifier) if !verifier.is_empty() => verifier,
            _ => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        if ttl_ms == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let required = crate::anticheat::ATTESTATION_CHALLENGE_WIRE_SIZE;
        if (output_length as usize) < required {
            if required_ptr != 0 {
                write_u32(memory, required_ptr, required as u32);
            }
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
            );
            self.last_error = 0;
            return Ok(());
        }
        let challenge = crate::anticheat::Challenge::new(
            &verifier,
            ttl_ms,
            self.anticheat.clock.tick_count64(),
        );
        let bytes = crate::anticheat::challenge_to_wire(&challenge);
        memory.map_bytes(output, &bytes);
        if required_ptr != 0 {
            write_u32(memory, required_ptr, required as u32);
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtAttestationQuote` — sign a real measurement of the Casa1 build for
    /// a guest-supplied challenge.
    ///
    /// `(Challenge*, Challenge length, Provider UTF-8*, Quote out*, Quote
    /// length, Required*)`.  The signing key is derived from the persisted
    /// install identity and registered as that provider's real P-256 key; a
    /// malformed challenge is `STATUS_INVALID_PARAMETER`, a short quote
    /// buffer is `STATUS_INFO_LENGTH_MISMATCH`.
    pub(crate) fn dispatch_nt_attestation_quote(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let challenge_ptr = guest_call_arg(state, memory, 0)?;
        let challenge_length = guest_call_arg_u32(state, memory, 1)?;
        let provider_ptr = guest_call_arg(state, memory, 2)?;
        let output = guest_call_arg(state, memory, 3)?;
        let output_length = guest_call_arg_u32(state, memory, 4)?;
        let required_ptr = guest_call_arg(state, memory, 5)?;

        let mut challenge_bytes = vec![0_u8; crate::anticheat::ATTESTATION_CHALLENGE_WIRE_SIZE];
        if challenge_ptr == 0
            || (challenge_length as usize) < crate::anticheat::ATTESTATION_CHALLENGE_WIRE_SIZE
        {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        memory.read_into(challenge_ptr, &mut challenge_bytes)?;
        let challenge = match crate::anticheat::challenge_from_wire(&challenge_bytes) {
            Ok(challenge) => challenge,
            Err(error) => {
                state.set(
                    Register::Rax,
                    u64::from(crate::anticheat::attestation_ntstatus(&error)),
                );
                self.last_error = 0;
                return Ok(());
            }
        };
        let provider = match read_c_string(memory, provider_ptr) {
            Ok(provider) if !provider.is_empty() => provider,
            _ => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        if output == 0 {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        if self.anticheat.attestation_key.is_none() {
            let install_id = crate::hardware_identity::host_identity()
                .install
                .install_id
                .clone();
            match crate::anticheat::install_attestation_key(&install_id) {
                Ok(key) => self.anticheat.attestation_key = Some(key),
                Err(error) => {
                    state.set(
                        Register::Rax,
                        u64::from(crate::anticheat::attestation_ntstatus(&error)),
                    );
                    self.last_error = 0;
                    return Ok(());
                }
            }
        }
        let key = self
            .anticheat
            .attestation_key
            .as_ref()
            .expect("the signing key was just installed");
        let now = self.anticheat.clock.tick_count64();
        if self.anticheat.attestation.provider(&provider).is_none() {
            let provider_key = crate::anticheat::ProviderKey {
                provider_id: provider.clone(),
                public_key_spki: key.public_key_spki(),
                registered_at_ms: now,
                valid_until_ms: None,
            };
            if let Err(error) = self.anticheat.attestation.register_provider(provider_key) {
                state.set(
                    Register::Rax,
                    u64::from(crate::anticheat::attestation_ntstatus(&error)),
                );
                self.last_error = 0;
                return Ok(());
            }
        }
        let measurement = crate::anticheat::measure_casa1_build();
        let quote = key.sign_quote(&provider, &measurement, &challenge.nonce);
        let bytes = match serde_json::to_vec(&quote) {
            Ok(bytes) => bytes,
            Err(_) => {
                state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
                self.last_error = 0;
                return Ok(());
            }
        };
        if bytes.len() > output_length as usize {
            if required_ptr != 0 {
                write_u32(memory, required_ptr, bytes.len() as u32);
            }
            state.set(
                Register::Rax,
                u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
            );
            self.last_error = 0;
            return Ok(());
        }
        memory.map_bytes(output, &bytes);
        if required_ptr != 0 {
            write_u32(memory, required_ptr, bytes.len() as u32);
        }
        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtAttestationVerify` — verify a quote against a challenge.
    ///
    /// `(Challenge*, Challenge length, Quote*, Quote length)` returns the
    /// exact NTSTATUS from [`crate::anticheat::attestation_ntstatus`].  A
    /// fresh runtime with no registered provider returns
    /// `STATUS_NOT_SUPPORTED`; a forged, mismatched, expired or replayed
    /// quote never reports success.
    pub(crate) fn dispatch_nt_attestation_verify(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let challenge_ptr = guest_call_arg(state, memory, 0)?;
        let challenge_length = guest_call_arg_u32(state, memory, 1)?;
        let quote_ptr = guest_call_arg(state, memory, 2)?;
        let quote_length = guest_call_arg_u32(state, memory, 3)?;

        if challenge_ptr == 0
            || quote_ptr == 0
            || (challenge_length as usize) < crate::anticheat::ATTESTATION_CHALLENGE_WIRE_SIZE
            || quote_length == 0
        {
            state.set(Register::Rax, u64::from(nt::STATUS_INVALID_PARAMETER.raw()));
            self.last_error = 0;
            return Ok(());
        }
        let mut challenge_bytes = vec![0_u8; crate::anticheat::ATTESTATION_CHALLENGE_WIRE_SIZE];
        memory.read_into(challenge_ptr, &mut challenge_bytes)?;
        let challenge = match crate::anticheat::challenge_from_wire(&challenge_bytes) {
            Ok(challenge) => challenge,
            Err(error) => {
                state.set(
                    Register::Rax,
                    u64::from(crate::anticheat::attestation_ntstatus(&error)),
                );
                self.last_error = 0;
                return Ok(());
            }
        };
        let mut quote_bytes = vec![0_u8; quote_length as usize];
        memory.read_into(quote_ptr, &mut quote_bytes)?;
        let quote: crate::anticheat::Quote = match serde_json::from_slice(&quote_bytes) {
            Ok(quote) => quote,
            Err(_) => {
                state.set(
                    Register::Rax,
                    u64::from(crate::anticheat::attestation_ntstatus(
                        &crate::anticheat::AttestationError::MalformedQuote,
                    )),
                );
                self.last_error = 0;
                return Ok(());
            }
        };
        let expected = crate::anticheat::measure_casa1_build();
        let now = self.anticheat.clock.tick_count64();
        self.sync_attestation_provider(&quote.provider_id);
        let status =
            match self
                .anticheat
                .attestation
                .verify_quote(&quote, &challenge, Some(&expected), now)
            {
                Ok(_) => nt::STATUS_SUCCESS,
                Err(error) => {
                    nt::NtStatus::from_raw(crate::anticheat::attestation_ntstatus(&error))
                }
            };
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    // ── Synchronization: events + waits ─────────────────────────────────────

    /// `NtCreateEvent` — create/open an event in the live object namespace.
    ///
    /// PAIR CONTRACT (CreateEventW/OpenEventW ↔ NtCreateEvent): the ONE
    /// object manager resolves named events across every prefix spelling;
    /// `NtCreateEvent` with a matching name OPENS the existing object (the
    /// OBJ_OPENIF role the Win32 OpenEventW thunk plays through
    /// `win32.open_event`), and the auto-reset consumption on wait is the
    /// object manager's canonical transition visible to both surfaces (see
    /// the section50 cross-surface test).
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
            // Zero timeout is a poll: it never enters the alertable state.
            state.set(Register::Rax, u64::from(nt::STATUS_TIMEOUT.raw()));
            self.last_error = 0;
        } else if alertable && self.deliver_current_thread_apcs(state, memory)? {
            // The wait would block; deliver the thread's pending APCs in
            // FIFO order through the guest callback machinery and report
            // STATUS_USER_APC instead of parking.
            state.set(Register::Rax, u64::from(nt::STATUS_USER_APC.raw()));
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
    ///
    /// A file-backed section created with `SEC_IMAGE` whose file is a real
    /// PE image is recorded as an image section (keyed by the section's
    /// object id), so `NtCreateProcess` can resolve the returned handle —
    /// through any duplicate/alias of it — to the child image.  Every other
    /// section stays a plain data section.
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
        let allocation_attributes = guest_call_arg_u32(state, memory, 5)?;
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
                // Image section: the backing file is a real PE image, so
                // record the section's object identity → image guest path
                // for NtCreateProcess.  A SEC_IMAGE request over a non-PE
                // file is not an image section; it stays unrecorded and
                // NtCreateProcess answers STATUS_INVALID_IMAGE_FORMAT.
                if allocation_attributes & SEC_IMAGE != 0
                    && let Some(file_handle) = file_handle
                    && let Ok(file_state) = self.win32.file_state(file_handle)
                    && let Ok(object_id) = self.win32.handle_object_identity(handle)
                    && let Ok(host_path) = self
                        .win32
                        .guest_path_to_host_path(&file_state.normalized_path)
                    && is_pe_image(&host_path).unwrap_or(false)
                {
                    section_image_register(
                        self.guest_pid,
                        object_id.0,
                        &file_state.normalized_path,
                    );
                }
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
        // Island device namespace: a loaded driver's `\Device\...` path (or
        // its symbolic link) opens a handle whose I/O is dispatched to the
        // driver's real MajorFunction.
        if let Some(status) =
            crate::driver_island::nt_open_island_device(self, memory, &raw_name, handle_ptr)
        {
            let status = nt::NtStatus::from_raw(status as u32);
            if status == nt::STATUS_SUCCESS {
                write_io_status_block(state, memory, io_status_block, status, 1, self.guest_arch)?;
            } else {
                write_io_status_block(state, memory, io_status_block, status, 0, self.guest_arch)?;
            }
            state.set(Register::Rax, u64::from(status.raw()));
            self.last_error = 0;
            return Ok(());
        }
        // An unknown `\Device\...` name is outside the file namespace.
        if normalized.to_ascii_lowercase().starts_with("\\device\\") {
            let status = nt::STATUS_OBJECT_NAME_NOT_FOUND;
            write_io_status_block(state, memory, io_status_block, status, 0, self.guest_arch)?;
            state.set(Register::Rax, u64::from(status.raw()));
            self.last_error = 0;
            return Ok(());
        }
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

        if crate::driver_island::is_island_device_handle(self, file_handle) {
            let result = crate::driver_island::dispatch_island_device_io(
                self,
                memory,
                file_handle,
                crate::casak::io::IrpMajorFunction::DeviceControl,
                io_control_code,
                input_buffer,
                input_length,
                output_buffer,
                output_length,
                0,
            )?;
            if let Some((status, information)) = result {
                let status = nt::NtStatus::from_raw(status as u32);
                write_io_status_block(
                    state,
                    memory,
                    io_status_block,
                    status,
                    information as u64,
                    self.guest_arch,
                )?;
                state.set(Register::Rax, u64::from(status.raw()));
                self.last_error = 0;
                return Ok(());
            }
        }
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

    /// `NtReadFile` — island device handles dispatch `IRP_MJ_READ` to the
    /// driver's real MajorFunction; ordinary file handles use the file layer.
    pub(crate) fn dispatch_nt_read_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let file_handle = guest_call_arg_u32(state, memory, 0)?;
        let io_status_block = guest_call_arg(state, memory, 4)?;
        let buffer = guest_call_arg(state, memory, 5)?;
        let length = guest_call_arg_u32(state, memory, 6)?;
        let byte_offset_ptr = guest_call_arg(state, memory, 7)?;
        let byte_offset = if byte_offset_ptr != 0 {
            read_guest_pointer(memory, byte_offset_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        if crate::driver_island::is_island_device_handle(self, file_handle) {
            let result = crate::driver_island::dispatch_island_device_io(
                self,
                memory,
                file_handle,
                crate::casak::io::IrpMajorFunction::Read,
                0,
                0,
                0,
                buffer,
                length,
                byte_offset,
            )?;
            if let Some((status, information)) = result {
                let status = nt::NtStatus::from_raw(status as u32);
                write_io_status_block(
                    state,
                    memory,
                    io_status_block,
                    status,
                    information as u64,
                    self.guest_arch,
                )?;
                state.set(Register::Rax, u64::from(status.raw()));
                self.last_error = 0;
                return Ok(());
            }
        }
        let status = nt::STATUS_INVALID_HANDLE;
        write_io_status_block(state, memory, io_status_block, status, 0, self.guest_arch)?;
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
        Ok(())
    }

    /// `NtWriteFile` — island device handles dispatch `IRP_MJ_WRITE` to the
    /// driver's real MajorFunction.
    pub(crate) fn dispatch_nt_write_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let file_handle = guest_call_arg_u32(state, memory, 0)?;
        let io_status_block = guest_call_arg(state, memory, 4)?;
        let buffer = guest_call_arg(state, memory, 5)?;
        let length = guest_call_arg_u32(state, memory, 6)?;
        let byte_offset_ptr = guest_call_arg(state, memory, 7)?;
        let byte_offset = if byte_offset_ptr != 0 {
            read_guest_pointer(memory, byte_offset_ptr, self.guest_arch).unwrap_or(0)
        } else {
            0
        };
        if crate::driver_island::is_island_device_handle(self, file_handle) {
            let result = crate::driver_island::dispatch_island_device_io(
                self,
                memory,
                file_handle,
                crate::casak::io::IrpMajorFunction::Write,
                0,
                buffer,
                length,
                0,
                0,
                byte_offset,
            )?;
            if let Some((status, information)) = result {
                let status = nt::NtStatus::from_raw(status as u32);
                write_io_status_block(
                    state,
                    memory,
                    io_status_block,
                    status,
                    information as u64,
                    self.guest_arch,
                )?;
                state.set(Register::Rax, u64::from(status.raw()));
                self.last_error = 0;
                return Ok(());
            }
        }
        let status = nt::STATUS_INVALID_HANDLE;
        write_io_status_block(state, memory, io_status_block, status, 0, self.guest_arch)?;
        state.set(Register::Rax, u64::from(status.raw()));
        self.last_error = 0;
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
            nt::PROCESS_DEBUG_PORT_CLASS
            | nt::process::PROCESS_DEBUG_OBJECT_HANDLE_CLASS
            | nt::process::PROCESS_DEBUG_FLAGS_CLASS => {
                let value = match self.anticheat.debug.query_information_process(info_class) {
                    Ok(value) => value,
                    Err(status) => {
                        state.set(Register::Rax, u64::from(status));
                        return Ok(());
                    }
                };
                let required = match info_class {
                    nt::process::PROCESS_DEBUG_FLAGS_CLASS => 4,
                    _ if self.guest_arch == GuestArch::X64 => 8,
                    _ => 4,
                };
                if info_length < required {
                    write_return_length(memory, required as u32);
                    state.set(
                        Register::Rax,
                        u64::from(nt::STATUS_INFO_LENGTH_MISMATCH.raw()),
                    );
                    return Ok(());
                }
                if info_class == nt::process::PROCESS_DEBUG_FLAGS_CLASS {
                    write_u32(memory, info_ptr, value as u32);
                } else {
                    write_guest_pointer(memory, info_ptr, value, self.guest_arch)?;
                }
                write_return_length(memory, required as u32);
                state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
            }
            nt::process::PROCESS_IMAGE_FILE_NAME_CLASS => {
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
                // A host-launched native child thread reports the CHILD
                // process id and the child thread's real TEB; a thread of
                // this runtime reports this runtime's pid/TEB.
                let child_thread = native_child_thread_info(self.guest_pid, thread_handle);
                let teb_base = child_thread
                    .as_ref()
                    .map(|info| info.teb_base)
                    .or_else(|| {
                        self.pending_guest_threads
                            .iter()
                            .find(|thread| thread.handle == thread_handle)
                            .map(|thread| thread.teb_base)
                    })
                    .unwrap_or(self.teb_base);
                let unique_process_id = child_thread
                    .as_ref()
                    .map(|info| info.process_id)
                    .unwrap_or(self.guest_pid);
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
                    unique_process_id: u64::from(unique_process_id),
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
                // The start routine the thread was created with: the queued
                // guest thread's start routine, or a host-launched native
                // child thread's real Win32StartAddress; 0 for threads with
                // no start record (e.g. the main thread).
                let start_address = self
                    .pending_guest_threads
                    .iter()
                    .find(|thread| thread.handle == thread_handle)
                    .map(|thread| thread.start_address)
                    .or_else(|| {
                        native_child_thread_info(self.guest_pid, thread_handle)
                            .map(|info| info.start_address)
                    })
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
                let thread_id = match self.win32.thread_id_for_handle(thread_handle) {
                    Ok(thread_id) => thread_id,
                    Err(_) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                        return Ok(());
                    }
                };
                let hidden = self
                    .anticheat
                    .debug
                    .query_information_thread(
                        thread_id,
                        crate::anticheat::THREAD_HIDE_FROM_DEBUGGER,
                    )
                    .unwrap_or(0);
                memory.map_bytes(info_ptr, &[hidden as u8]);
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
                if previous == 1 {
                    // The suspension is fully released: a CREATE_SUSPENDED
                    // first thread of a deferred native child starts the
                    // deferred host run now.
                    self.launch_deferred_native_child_on_resume(thread_handle)?;
                }
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

    /// Start the deferred host run of a `CREATE_SUSPENDED` native child when
    /// its first thread's suspension count reaches zero.  A host run that
    /// cannot start is reported in the trace and the start routine falls
    /// back to the runtime's guest thread scheduler (bare-entry scheduling),
    /// exactly like an immediate `NtCreateThreadEx` whose spawn failed.
    fn launch_deferred_native_child_on_resume(&mut self, thread_handle: u32) -> AppResult<()> {
        let Some(info) = native_child_thread_info(self.guest_pid, thread_handle) else {
            return Ok(());
        };
        let Some(claim) =
            native_child_launch_resume_claim(self.guest_pid, info.process_id, thread_handle)
        else {
            return Ok(());
        };
        let pending =
            native_child_thread_take(self.guest_pid, thread_handle).map(|(_, thread)| thread);
        match self.spawn_native_child_image(&claim) {
            Ok(()) => {
                if let Some(pending) = pending {
                    native_child_thread_retain(
                        self.guest_pid,
                        thread_handle,
                        info.process_id,
                        pending,
                    );
                }
            }
            Err(error) => {
                native_child_launch_unclaim(self.guest_pid, info.process_id);
                self.push_trace(
                    "process",
                    "NtResumeThread",
                    BTreeMap::from([
                        ("thread_handle".to_string(), json!(thread_handle)),
                        ("process_id".to_string(), json!(info.process_id)),
                        ("failure".to_string(), json!(error.message)),
                    ]),
                    json!("STATUS_SUCCESS"),
                );
                if let Some(mut pending) = pending {
                    pending.suspended = 0;
                    self.pending_guest_threads.push_back(pending);
                }
            }
        }
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
                // A native `NtCreateProcess` child: cancel any deferred host
                // launch, kill an already-spawned host child, and end the
                // child's recorded guest threads so thread handles observe
                // the termination.  Every one of these is a no-op for a
                // process this runtime did not create through NtCreateProcess.
                if let Ok(child) = self.win32.process_state(process_handle) {
                    let child_pid = child.process_id;
                    let host_pid = native_child_host_pid(self.guest_pid, child_pid);
                    let host_killed = native_child_terminate_host(self.guest_pid, child_pid);
                    for thread_handle in
                        native_child_thread_handles_for_process(self.guest_pid, child_pid)
                    {
                        let _ = native_child_thread_take(self.guest_pid, thread_handle);
                        let _ = self.win32.terminate_thread(thread_handle, exit_status);
                    }
                    if host_pid.is_some() || host_killed {
                        self.push_trace(
                            "process",
                            "NtTerminateProcess",
                            BTreeMap::from([
                                ("process_id".to_string(), json!(child_pid)),
                                ("host_pid".to_string(), json!(host_pid)),
                                ("host_killed".to_string(), json!(host_killed)),
                            ]),
                            json!(format!("{exit_status:#x}")),
                        );
                    }
                }
                // Wake every waiter on the process object with the exit code
                // this termination recorded.
                let _ = self
                    .win32
                    .set_process_exit_code_and_notify(process_handle, exit_status);
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
        // Terminating the CREATE_SUSPENDED first thread of a deferred native
        // child means the child can never launch: cancel the deferred host
        // run before dropping the thread record.
        if let Some((process_id, _)) = native_child_thread_take(self.guest_pid, thread_handle)
            && native_child_launch_cancel_suspended(self.guest_pid, process_id, thread_handle)
        {
            self.push_trace(
                "process",
                "NtTerminateThread",
                BTreeMap::from([
                    ("thread_handle".to_string(), json!(thread_handle)),
                    ("process_id".to_string(), json!(process_id)),
                    ("deferred_launch".to_string(), json!("cancelled")),
                ]),
                json!(format!("{exit_status:#x}")),
            );
        }
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
            nt::THREAD_HIDE_FROM_DEBUGGER_CLASS => {
                let thread_id = match self.win32.thread_id_for_handle(thread_handle) {
                    Ok(thread_id) => thread_id,
                    Err(_) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_INVALID_HANDLE.raw()));
                        return Ok(());
                    }
                };
                match self.anticheat.debug.set_information_thread(
                    thread_id,
                    crate::anticheat::THREAD_HIDE_FROM_DEBUGGER,
                    info_length as usize,
                ) {
                    Ok(()) => {
                        state.set(Register::Rax, u64::from(nt::STATUS_SUCCESS.raw()));
                    }
                    Err(status) => {
                        state.set(Register::Rax, u64::from(status));
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
                // The configured guest topology (8 processors / 0xFF mask /
                // 4 KiB pages / 0x10000 granularity) — the SAME numbers the
                // Win32 GetSystemInfo / GetNativeSystemInfo thunks write
                // (write_system_info); the ntdll serializer is pinned
                // against the Win32 topology by the section50 test.
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
                // The ONE guest system-time derivation — the same value
                // GetSystemTimeAsFileTime reports (live: host wall clock;
                // deterministic: the guest clock, advancing in lockstep
                // with GetTickCount64).
                let current = guest_filetime_ticks(&self.win32) as i64;
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
                // Every other class is served from the LIVE kernel state
                // (loader tables, the one handle table, the guest scheduler's
                // thread set and the guest clock) through the CasaK
                // introspection serializer.  A class the serializer does not
                // back with real state is STATUS_INVALID_INFO_CLASS, never a
                // fabricated value; a short buffer is
                // STATUS_INFO_LENGTH_MISMATCH with the exact required length.
                let mut snapshot = self.build_kernel_snapshot(memory);
                if info_class == kintro::SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS {
                    // The caller supplies (ProviderSignature, TableID) in the
                    // input buffer; the output echoes them with the real
                    // table payload (empty when Casa1 exposes no table).
                    snapshot.firmware_provider = read_u32(memory, buffer)?;
                    snapshot.firmware_table_id = read_u32(memory, buffer + 4)?;
                    // RSMB is the SMBIOS provider the Win32
                    // GetSystemFirmwareTable thunk serves from the SAME
                    // hardware identity; ACPI tables are genuinely absent.
                    const RSMB: u32 = 0x5253_4D42;
                    if snapshot.firmware_provider == RSMB {
                        snapshot.firmware_table = crate::hardware_identity::build_smbios_table(
                            crate::hardware_identity::host_identity(),
                        );
                    }
                }
                let result = if info_class == kintro::SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS
                    && self.guest_arch == GuestArch::X86
                {
                    // The 32-bit extended layout is a real, distinct ABI
                    // (0xB8-byte process record, 0x60-byte extended thread
                    // record), never the x64 layout with truncated pointers.
                    match kintro::serialize_extended_process_information_x86(
                        &snapshot.processes,
                        buffer,
                    ) {
                        Some(bytes) => {
                            let required = bytes.len() as u64;
                            if length < required {
                                kintro::SysInfoSerialized {
                                    status: kintro::STATUS_INFO_LENGTH_MISMATCH,
                                    required,
                                    bytes: Vec::new(),
                                }
                            } else {
                                kintro::SysInfoSerialized {
                                    status: kintro::STATUS_SUCCESS,
                                    required,
                                    bytes,
                                }
                            }
                        }
                        None => kintro::SysInfoSerialized {
                            status: kintro::STATUS_NOT_SUPPORTED,
                            required: 0,
                            bytes: Vec::new(),
                        },
                    }
                } else {
                    kintro::serialize_system_information(info_class, &snapshot, length, buffer)
                };
                match result.status {
                    kintro::STATUS_SUCCESS => {
                        memory.map_bytes(buffer, &result.bytes);
                        if return_length_ptr != 0 {
                            write_guest_pointer(
                                memory,
                                return_length_ptr,
                                result.required,
                                self.guest_arch,
                            )?;
                        }
                    }
                    kintro::STATUS_INFO_LENGTH_MISMATCH => {
                        if return_length_ptr != 0 {
                            write_guest_pointer(
                                memory,
                                return_length_ptr,
                                result.required,
                                self.guest_arch,
                            )?;
                        }
                    }
                    _ => {}
                }
                state.set(Register::Rax, u64::from(result.status as u32));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// Build a plain-value snapshot of the LIVE kernel state for the
    /// introspection serializers.  Every field is read from a canonical
    /// table — the loader's module tables (base addresses and sizes are the
    /// real mappings), the single Win32 handle table, the guest scheduler's
    /// threads, the guest VM accounting and the guest clock — so the
    /// serialized structures are internally consistent with the rest of the
    /// runtime (see [`crate::casak::introspection`]).
    pub(crate) fn build_kernel_snapshot(&self, memory: &MemoryImage) -> kintro::KernelSnapshot {
        let system_time = guest_filetime_ticks(&self.win32) as i64;
        let uptime_100ns = self.win32.get_tick_count64().saturating_mul(10_000);
        let boot_time = system_time.saturating_sub(uptime_100ns as i64);
        let committed = self.win32.address_space().committed_bytes();
        let times = crate::runtime::guest_thread_times_filetimes(self.dtm);

        // ── Modules: the loader's real image tables ─────────────────────────
        let dlls: Vec<(u64, u32, String, u16, u32)> = self
            .dll_info_table
            .iter()
            .map(|(handle, info)| {
                (
                    *handle,
                    info.image_size as u32,
                    info.module_name.clone(),
                    info.load_count.min(u16::MAX as u32) as u16,
                    info.entry_point_rva,
                )
            })
            .collect();
        let modules = kintro::assemble_modules(
            self.mapped_image_base,
            self.mapped_image_size as u32,
            &self.main_module_path,
            &self.main_module_name,
            &dlls,
            &self.module_names_by_handle,
        );

        // ── Handles: every live handle in the one Win32 handle table ────────
        let mut handles: Vec<kintro::KernelHandle> = Vec::new();
        let next = self.win32.next_handle_value();
        for value in (4..next).step_by(4) {
            let Ok((descriptor, object)) =
                self.win32.describe_handle(value).and_then(|descriptor| {
                    self.win32
                        .handle_object_identity(value)
                        .map(|object| (descriptor, object))
                })
            else {
                continue;
            };
            handles.push(kintro::KernelHandle {
                handle: value,
                object: object.0,
                process_id: self.guest_pid,
                access: descriptor.access_mask,
                object_type_index: kintro::object_type_index(descriptor.object_type),
                pointer_count: descriptor.refcount,
                handle_count: 1,
            });
        }

        // ── Processes / threads: the real guest thread + process set ────────
        let pending: Vec<(u32, u64, u32, u64, u64, u64)> = self
            .pending_guest_threads
            .iter()
            .map(|thread| {
                let (stack_base, stack_limit) =
                    teb_stack_bounds(memory, thread.teb_base, self.guest_arch).unwrap_or((0, 0));
                (
                    thread.thread_id,
                    thread.start_address,
                    thread.suspended,
                    thread.teb_base,
                    stack_base,
                    stack_limit,
                )
            })
            .collect();
        // The main thread's stack is the region the run loop maps and the
        // TEB records.  A runtime with no TEB (a bare unit runtime) still has
        // the real main-stack region mapped; a TEB that exists but records no
        // bounds is NOT silently replaced (the extended query refuses it).
        let main_stack = if self.teb_base == 0 {
            let limit = stack_base_for_arch(self.guest_arch);
            (limit + STACK_SIZE as u64, limit)
        } else {
            teb_stack_bounds(memory, self.teb_base, self.guest_arch).unwrap_or((0, 0))
        };
        let threads = kintro::assemble_threads(
            (self.win32.current_thread_id(), self.teb_base),
            main_stack,
            &pending,
            times,
        );
        let mut toolhelp: Vec<(u32, String)> = self
            .win32
            .create_toolhelp_snapshot()
            .processes
            .into_iter()
            .map(|entry| (entry.process_id, entry.executable))
            .collect();
        // The toolhelp snapshot enumerates process *objects*; this runtime's
        // own process is always part of the real process set even before a
        // process handle exists, so it is reported from the loader's image
        // name when the snapshot has no entry for it.
        if !toolhelp.iter().any(|(pid, _)| *pid == self.guest_pid) {
            toolhelp.push((self.guest_pid, self.main_module_name.clone()));
        }
        let processes = kintro::assemble_processes(
            self.guest_pid,
            std::process::id(),
            handles.len() as u32,
            &threads,
            &toolhelp,
            times,
            committed,
        );

        // ── Pool / page file: real guest VM accounting ──────────────────────
        let committed_pages = (committed / 4096).min(u64::from(u32::MAX)) as u32;
        kintro::KernelSnapshot {
            processor_count: 8,
            active_processor_mask: self.process_affinity_mask,
            system_time,
            boot_time,
            range_start: kintro::system_range_start(self.guest_arch == GuestArch::X64),
            modules,
            processes,
            handles,
            pool_tags: Vec::new(),
            pool_used_bytes: committed,
            pool_budget_bytes: committed,
            lookaside: Vec::new(),
            debugger_present: self.debugger_present,
            debugger_enabled: self.debugger_present,
            // Casa1 enforces no code-integrity policy on its own images: the
            // truthful options word is zero (no CI enforcement).
            code_integrity_options: 0,
            firmware_provider: 0,
            firmware_table_id: 0,
            firmware_table: Vec::new(),
            page_file_path: "C:\\pagefile.sys".to_string(),
            page_file_total_pages: committed_pages,
            page_file_in_use_pages: committed_pages,
            page_file_peak_pages: committed_pages,
            installed_memory_bytes: committed,
        }
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
    ///
    /// DOMAIN CONTRACT: the 1 ms minimum (10 000 × 100 ns) is the
    /// millisecond granularity the Win32 timeGetTime clock exposes, and the
    /// 15.6 ms maximum is the classic Windows timer period — the two
    /// surfaces describe the same timer domain (timeBeginPeriod is a
    /// cooperative no-op on both).
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

    /// `NtQuerySystemTime` — the guest FILETIME, from the SAME single
    /// derivation the Win32 GetSystemTimeAsFileTime thunk reads (live: host
    /// wall clock; deterministic: the guest clock, in lockstep with
    /// GetTickCount64).  The Nt path never invents its own epoch or base.
    pub(crate) fn dispatch_nt_query_system_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let filetime_ptr = guest_call_arg(state, memory, 0)?;
        if filetime_ptr != 0 {
            write_u64(memory, filetime_ptr, guest_filetime_ticks(&self.win32));
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
            self.dispatch_x86_exception(state, memory, code, 0, "RtlRaiseException", &[])?
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

/// Read a thread's real stack bounds from its TEB.
///
/// x64: `StackBase` at +0x08 and `StackLimit` at +0x10.  x86: `StackBase` at
/// +0x04 and `StackLimit` at +0x08.  Returns `None` when the TEB is not
/// mapped or records no bounds, so callers can refuse to fabricate them.
fn teb_stack_bounds(memory: &MemoryImage, teb_base: u64, arch: GuestArch) -> Option<(u64, u64)> {
    if teb_base == 0 {
        return None;
    }
    let (base, limit) = match arch {
        GuestArch::X64 => (
            memory.read_u64(teb_base + 0x08).ok()?,
            memory.read_u64(teb_base + 0x10).ok()?,
        ),
        GuestArch::X86 => (
            u64::from(memory.read_u32(teb_base + 0x04).ok()?),
            u64::from(memory.read_u32(teb_base + 0x08).ok()?),
        ),
    };
    (base != 0 && limit != 0 && base > limit).then_some((base, limit))
}

/// The live anti-cheat state of one guest runtime: the debugger-attach state
/// machine and the single monotonic clock every timing surface reads.
///
/// Every Win32/Nt* arm that answers an anti-debug, timing or attestation
/// question must read this state so the API families cannot disagree.
pub(crate) struct GuestAnticheatState {
    /// Debugger attach/detach, debug objects and per-thread contexts.
    pub(crate) debug: crate::anticheat::AntiDebugSurface,
    /// The one monotonic clock (measured counter frequency, invariant TSC).
    pub(crate) clock: std::sync::Arc<crate::anticheat::MonotonicClock>,
    /// Trusted attestation providers registered for this guest runtime.
    pub(crate) attestation: crate::anticheat::AttestationRegistry,
    /// The real signing key the quote thunk uses (derived lazily from the
    /// persisted install identity; never a fabricated constant).
    pub(crate) attestation_key: Option<crate::anticheat::AttestationKeyPair>,
}

impl GuestAnticheatState {
    pub(crate) fn new(guest_pid: u32) -> Self {
        Self {
            debug: crate::anticheat::AntiDebugSurface::new(guest_pid),
            clock: std::sync::Arc::new(crate::anticheat::MonotonicClock::new()),
            attestation: crate::anticheat::AttestationRegistry::new(),
            attestation_key: None,
        }
    }
}
