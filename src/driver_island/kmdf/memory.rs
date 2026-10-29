//! KMDF object model.

use super::*;

impl IslandState {
    /// `WdfMemoryCreate`/`WdfMemoryCreatePreallocated`: allocate a framework
    /// memory object over real guest bytes.
    pub(crate) fn wdf_memory_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        preallocated: bool,
    ) -> AppResult<()> {
        let pointer = self.arch.pointer_bytes() as u64;
        let (attributes, pool_type, supplied_buffer, size, memory_out, buffer_out) = if preallocated
        {
            (
                guest_arg(state, memory, 0)?,
                0,
                guest_arg(state, memory, 1)?,
                guest_arg(state, memory, 2)? as usize,
                guest_arg(state, memory, 3)?,
                0,
            )
        } else {
            (
                guest_arg(state, memory, 0)?,
                guest_arg(state, memory, 1)? as u32,
                u64::MAX,
                guest_arg(state, memory, 3)? as usize,
                guest_arg(state, memory, 4)?,
                guest_arg(state, memory, 5)?,
            )
        };
        let out_valid = memory_out != 0
            && crate::host_thunks::validate_guest_pointer(memory, memory_out, pointer as usize)
                .is_ok();
        let buffer_out_valid = preallocated
            || (buffer_out != 0
                && crate::host_thunks::validate_guest_pointer(
                    memory,
                    buffer_out,
                    pointer as usize,
                )
                .is_ok());
        if !out_valid || !buffer_out_valid {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if (!preallocated && pool_type > 1) || size > 0x10_0000 {
            set_status(
                state,
                if pool_type > 1 && !preallocated {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_INSUFFICIENT_RESOURCES
                },
            );
            return Ok(());
        }
        let buffer = if preallocated {
            if size > 0
                && (supplied_buffer == 0
                    || crate::host_thunks::validate_guest_pointer(memory, supplied_buffer, size)
                        .is_err())
            {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
            supplied_buffer
        } else {
            let buffer = self.arena.alloc(memory, size.max(1), 8)?;
            memory.map_bytes(buffer, &vec![0_u8; size.max(1)]);
            buffer
        };
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Memory, attributes)?;
        self.kmdf.memories.insert(
            handle,
            KmdfMemory {
                buffer,
                size,
                preallocated,
            },
        );
        write_guest_pointer(memory, memory_out, handle, self.arch)?;
        if !preallocated {
            write_guest_pointer(memory, buffer_out, buffer, self.arch)?;
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfMemoryGetBuffer`.
    pub(crate) fn wdf_memory_get_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let size_out = guest_arg(state, memory, 1)?;
        let Some(record) = self.kmdf.memories.get(&handle).cloned() else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if size_out != 0
            && crate::host_thunks::validate_guest_pointer(
                memory,
                size_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if size_out != 0 {
            write_guest_pointer(memory, size_out, record.size as u64, self.arch)?;
        }
        state.set(Register::Rax, record.buffer);
        Ok(())
    }

    /// `WdfStringCreate`: copy a caller `UNICODE_STRING` into a WDFSTRING.
    pub(crate) fn wdf_string_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let source = guest_arg(state, memory, 0)?;
        let attributes = guest_arg(state, memory, 1)?;
        let string_out = guest_arg(state, memory, 2)?;
        if string_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                string_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(text) = self.read_valid_unicode_string(memory, source) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let length = (text.encode_utf16().count() * 2) as u16;
        let bytes = length as usize;
        let buffer = self.arena.alloc(memory, bytes.max(2), 2)?;
        memory.map_bytes(buffer, &vec![0_u8; bytes.max(2)]);
        for (index, unit) in text.encode_utf16().enumerate() {
            memory.write_u16(buffer + index as u64 * 2, unit);
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::String, attributes)?;
        self.kmdf.strings.insert(
            handle,
            KmdfString {
                buffer,
                length,
                maximum: length.saturating_add(2),
            },
        );
        write_guest_pointer(memory, string_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfStringGetUnicodeString`.
    pub(crate) fn wdf_string_get_unicode_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let destination = guest_arg(state, memory, 1)?;
        if destination == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                destination,
                unicode_string_size(self.arch),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let Some(record) = self.kmdf.strings.get(&handle).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        write_unicode_string_header(
            memory,
            destination,
            record.length,
            record.maximum,
            record.buffer,
            self.arch,
        )?; // coverage: unreachable — write_unicode_string_header only performs infallible MemoryImage writes
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// Validate and read a `UNICODE_STRING` without converting a malformed
    /// descriptor into an internal guest-memory error.
    pub(crate) fn read_valid_unicode_string(
        &self,
        memory: &MemoryImage,
        address: u64,
    ) -> Option<String> {
        if address == 0 {
            return Some(String::new());
        }
        if crate::host_thunks::validate_guest_pointer(
            memory,
            address,
            unicode_string_size(self.arch),
        )
        .is_err()
        {
            return None;
        }
        let length = memory.read_u16(address).ok()? as usize;
        let maximum = memory.read_u16(address + 2).ok()? as usize;
        if length % 2 != 0 || length > maximum || length > 0x800 {
            return None;
        }
        let buffer = read_guest_pointer(
            memory,
            address + unicode_string_buffer_offset(self.arch),
            self.arch,
        )
        .ok()?;
        if length > 0
            && (buffer == 0
                || crate::host_thunks::validate_guest_pointer(memory, buffer, length).is_err())
        {
            return None;
        }
        read_unicode_string(memory, address, self.arch)
            .ok()
            .map(|(text, _, _)| text)
    }

    /// `WdfLookasideListCreate`.
    pub(crate) fn wdf_lookaside_list_create(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let attributes = guest_arg(state, memory, 0)?;
        let pool_type = guest_arg(state, memory, 1)? as u32;
        let buffer_size = guest_arg(state, memory, 2)? as usize;
        let _tag = guest_arg(state, memory, 3)? as u32;
        let lookaside_out = guest_arg(state, memory, 4)?;
        if lookaside_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                lookaside_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
            || buffer_size == 0
            || buffer_size > 0x1_0000
            || pool_type > 1
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::LookasideList, attributes)?;
        self.attach_kmdf_parent(handle, self.kmdf.driver_handle);
        self.kmdf.lookasides.insert(
            handle,
            KmdfLookaside {
                block_size: buffer_size,
                max_depth: 32,
                free: Vec::new(),
                in_use: 0,
                hits: 0,
                misses: 0,
            },
        );
        write_guest_pointer(memory, lookaside_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfMemoryCreateFromLookaside`: allocates a fixed-size block from the
    /// lookaside, reusing the most recently freed block by pointer identity.
    pub(crate) fn wdf_memory_create_from_lookaside(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let lookaside = guest_arg(state, memory, 0)?;
        let memory_out = guest_arg(state, memory, 1)?;
        if memory_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                memory_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if let Err(status) = self.kmdf_expect_kind(lookaside, KmdfObjectKind::LookasideList) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .lookasides
            .get(&lookaside)
            .cloned()
            .expect("lookaside was validated");
        let buffer = match record.free.last().copied() {
            Some(block) => {
                let lookaside_state = self
                    .kmdf
                    .lookasides
                    .get_mut(&lookaside)
                    .expect("lookaside was validated");
                lookaside_state.free.pop();
                lookaside_state.hits += 1;
                block
            }
            None => {
                let block = self.arena.alloc(memory, record.block_size, 8)?;
                memory.map_bytes(block, &vec![0_u8; record.block_size]);
                self.kmdf
                    .lookasides
                    .get_mut(&lookaside)
                    .expect("lookaside was validated")
                    .misses += 1;
                block
            }
        };
        self.kmdf
            .lookasides
            .get_mut(&lookaside)
            .expect("lookaside was validated")
            .in_use += 1;
        let handle = self.create_kmdf_object(memory, KmdfObjectKind::Memory, 0)?;
        self.attach_kmdf_parent(handle, lookaside);
        self.kmdf.memories.insert(
            handle,
            KmdfMemory {
                buffer,
                size: record.block_size,
                preallocated: false,
            },
        );
        self.kmdf.lookaside_blocks.insert(
            handle,
            KmdfLookasideBlock {
                lookaside,
                block: buffer,
            },
        );
        self.kmdf.lookaside_allocations += 1;
        write_guest_pointer(memory, memory_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfMemoryCopy`: overlapping source/target ranges are rejected with
    /// `STATUS_INVALID_PARAMETER`; sizes beyond either buffer fail with
    /// `STATUS_BUFFER_TOO_SMALL`.
    pub(crate) fn wdf_memory_copy(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let source = guest_arg(state, memory, 0)?;
        let target = guest_arg(state, memory, 1)?;
        let size = guest_arg(state, memory, 2)? as usize;
        if let Err(status) = self.kmdf_expect_kind(source, KmdfObjectKind::Memory) {
            set_status(state, status);
            return Ok(());
        }
        if let Err(status) = self.kmdf_expect_kind(target, KmdfObjectKind::Memory) {
            set_status(state, status);
            return Ok(());
        }
        let source_record = self
            .kmdf
            .memories
            .get(&source)
            .copied()
            .expect("source memory was validated");
        let target_record = self
            .kmdf
            .memories
            .get(&target)
            .copied()
            .expect("target memory was validated");
        if size > source_record.size || size > target_record.size {
            set_status(state, STATUS_BUFFER_TOO_SMALL);
            return Ok(());
        }
        let source_end = source_record.buffer.saturating_add(size as u64);
        let target_end = target_record.buffer.saturating_add(size as u64);
        let overlaps =
            size > 0 && source_record.buffer < target_end && target_record.buffer < source_end;
        if overlaps {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        if size > 0 {
            let bytes = (0..size as u64)
                .map(|offset| memory.read_u8(source_record.buffer + offset))
                .collect::<AppResult<Vec<_>>>()?;
            for (offset, byte) in bytes.into_iter().enumerate() {
                memory.write_u8(target_record.buffer + offset as u64, byte);
            }
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfMemoryAssign`: rebinds a preallocated memory object to a new
    /// caller buffer; framework-owned memory cannot be reassigned.
    pub(crate) fn wdf_memory_assign(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        let buffer = guest_arg(state, memory, 1)?;
        let size = guest_arg(state, memory, 2)? as usize;
        if let Err(status) = self.kmdf_expect_kind(handle, KmdfObjectKind::Memory) {
            set_status(state, status);
            return Ok(());
        }
        let record = self
            .kmdf
            .memories
            .get(&handle)
            .copied()
            .expect("memory was validated");
        if !record.preallocated || size > 0x10_0000 {
            set_status(state, STATUS_INVALID_DEVICE_STATE);
            return Ok(());
        }
        if size > 0
            && (buffer == 0
                || crate::host_thunks::validate_guest_pointer(memory, buffer, size).is_err())
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let record = self
            .kmdf
            .memories
            .get_mut(&handle)
            .expect("memory was validated");
        record.buffer = buffer;
        record.size = size;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}
