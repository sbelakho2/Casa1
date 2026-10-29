//! Guest memory allocation helpers (runtime methods).

use super::*;

impl PeHostRuntime {
    pub(crate) fn alloc_zeroed(
        &mut self,
        memory: &mut MemoryImage,
        size: usize,
        align: u64,
    ) -> AppResult<u64> {
        let address = align_up_u64(self.next_data_address, align);
        self.next_data_address = address.checked_add(size as u64).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                "PE runtime data allocation overflow",
            )
        })?;
        memory.map_bytes(address, &vec![0; size]);
        // Canonical VM: the CRT data area (globals, PEB/TEB, TLS blocks,
        // module handles) is a growing region the guest reads and writes.
        let data_base = data_base_for_arch(self.guest_arch);
        self.win32.address_space_mut().register(
            data_base,
            self.next_data_address.saturating_sub(data_base),
            crate::vm::VmRegionKind::Private,
        );
        self.win32.address_space_mut().commit(
            address,
            size as u64,
            crate::vm::VmProtection::READ_WRITE,
            false,
        );
        Ok(address)
    }

    pub(crate) fn alloc_c_string(
        &mut self,
        memory: &mut MemoryImage,
        value: &str,
    ) -> AppResult<u64> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        let address = self.alloc_zeroed(memory, bytes.len(), 1)?;
        memory.map_bytes(address, &bytes);
        Ok(address)
    }

    /// Mint a MIB change-notification registration handle
    /// (NotifyAddrChange / NotifyRouteChange).  The guest network is
    /// static, so the registration never completes; CancelMibChangeNotify2
    /// consumes the handle.
    pub(crate) fn mint_mib_change_notification(&mut self) -> u64 {
        let handle = self.next_mib_change_notify_handle;
        self.next_mib_change_notify_handle = self.next_mib_change_notify_handle.wrapping_add(1);
        self.mib_change_notifications.insert(handle, 0);
        handle
    }

    /// Allocate a guest `SecPkgInfoW` for a package name (used by
    /// QueryContextAttributesW(SECPKG_ATTR_PACKAGE_INFO)).
    pub(crate) fn alloc_sec_pkg_info(
        &mut self,
        memory: &mut MemoryImage,
        package: &str,
    ) -> AppResult<u64> {
        let comment = match package {
            "Negotiate" => "Microsoft Negotiate SSP",
            _ => "Microsoft NTLM SSP",
        };
        let stride = if self.guest_arch == GuestArch::X86 {
            20
        } else {
            32
        };
        let entry = self.alloc_heap(memory, stride, true)?;
        write_u32(memory, entry, 0x7); // SECPKG_FLAG_INTEGRITY|PRIVACY|TOKEN_ONLY
        memory.map_bytes(entry + 4, &0_u16.to_le_bytes()); // wVersion
        memory.map_bytes(
            entry + 6,
            &(if package == "Negotiate" {
                9_u16
            } else {
                10_u16
            })
            .to_le_bytes(),
        ); // wRpcid
        write_u32(memory, entry + 8, crate::sspi::SSPI_CB_MAX_TOKEN);
        let name_addr = self.alloc_utf16_string(memory, package)?;
        let comment_addr = self.alloc_utf16_string(memory, comment)?;
        if self.guest_arch == GuestArch::X86 {
            write_guest_pointer(memory, entry + 12, name_addr, self.guest_arch)?;
            write_guest_pointer(memory, entry + 16, comment_addr, self.guest_arch)?;
        } else {
            write_guest_pointer(memory, entry + 16, name_addr, self.guest_arch)?;
            write_guest_pointer(memory, entry + 24, comment_addr, self.guest_arch)?;
        }
        Ok(entry)
    }

    pub(crate) fn alloc_pointer_array(
        &mut self,
        memory: &mut MemoryImage,
        values: &[u64],
    ) -> AppResult<u64> {
        let pointer_bytes = self.guest_arch.pointer_bytes();
        let address =
            self.alloc_zeroed(memory, values.len() * pointer_bytes, pointer_bytes as u64)?;
        for (index, value) in values.iter().enumerate() {
            write_guest_pointer(
                memory,
                address + (index as u64 * pointer_bytes as u64),
                *value,
                self.guest_arch,
            )?;
        }
        Ok(address)
    }

    pub(crate) fn alloc_pointer(&mut self, memory: &mut MemoryImage, value: u64) -> AppResult<u64> {
        let pointer_bytes = self.guest_arch.pointer_bytes();
        let address = self.alloc_zeroed(memory, pointer_bytes, pointer_bytes as u64)?;
        write_guest_pointer(memory, address, value, self.guest_arch)?;
        Ok(address)
    }

    pub(crate) fn alloc_u32(&mut self, memory: &mut MemoryImage, value: u32) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 4, 4)?;
        write_u32(memory, address, value);
        Ok(address)
    }

    pub(crate) fn alloc_heap(
        &mut self,
        memory: &mut MemoryImage,
        size: usize,
        zeroed: bool,
    ) -> AppResult<u64> {
        // Test-only failure injection: one-shot ENOMEM for the next heap
        // allocation (see `crt_alloc_fail_next`).
        if self.crt_alloc_fail_next {
            self.crt_alloc_fail_next = false;
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                "injected heap allocation failure (ENOMEM)",
            ));
        }
        let requested_size = size.max(1);
        let mapped_size = align_up_u64(requested_size as u64 + 15, 16) as usize;
        let mut address = align_up_u64(self.next_heap_address, 16);
        // For x86 guests, the heap bump pointer must stay within the 32-bit
        // addressable range (0x0000_0000..=0xFFFF_FFFF). If the next heap address
        // (address + aligned_size) exceeds 4 GB, switch to a secondary heap region
        // instead of wrapping back to X86_CRT_HEAP_BASE—wrapping reuses still-mapped
        // pages causing data corruption.
        self.next_heap_address = address.checked_add(mapped_size as u64).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                "PE runtime heap allocation overflow",
            )
        })?;
        if self.guest_arch == GuestArch::X86 && self.next_heap_address > 0xFFFF_FFFF {
            self.x86_heap_region += 1;
            address = match self.x86_heap_region {
                1 => X86_CRT_HEAP_BASE_2,
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        "x86 heap exhausted all available regions",
                    ));
                }
            };
            self.next_heap_address = address.checked_add(mapped_size as u64).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    "PE runtime heap allocation overflow",
                )
            })?;
        }
        let bytes = if zeroed {
            vec![0; mapped_size]
        } else {
            // Zero-initialize: the buffer is mapped into guest memory and may be
            // read before every byte is written, so uninitialized contents would
            // be observable.
            vec![0u8; mapped_size]
        };
        memory.map_bytes(address, &bytes);
        // Canonical VM: the heap is a growing Heap region (the bump
        // allocator shares pages between consecutive allocations, so the
        // region covers the whole active heap area and only the allocated
        // ranges are committed).
        let heap_base = match self.guest_arch {
            GuestArch::X86 if self.x86_heap_region == 1 => X86_CRT_HEAP_BASE_2,
            GuestArch::X86 => X86_CRT_HEAP_BASE,
            GuestArch::X64 => CRT_HEAP_BASE,
        };
        self.win32.address_space_mut().register(
            heap_base,
            self.next_heap_address.saturating_sub(heap_base),
            crate::vm::VmRegionKind::Heap,
        );
        self.win32.address_space_mut().commit(
            address,
            mapped_size as u64,
            crate::vm::VmProtection::READ_WRITE,
            false,
        );
        self.heap_allocations.insert(address, requested_size);
        Ok(address)
    }

    pub(crate) fn alloc_private_pages(
        &mut self,
        memory: &mut MemoryImage,
        requested_address: u64,
        size: usize,
        protection: crate::vm::VmProtection,
    ) -> AppResult<u64> {
        let size = align_up_u64(size.max(1) as u64, 0x1000) as usize;
        let address = if requested_address == 0 {
            // The canonical VM's cursor picks the address (and advances).
            self.win32.address_space_mut().reserve(None, size as u64)
        } else {
            let candidate = requested_address & !0xfff;
            let base = self
                .win32
                .address_space_mut()
                .reserve(Some(candidate), size as u64);
            if base == 0 {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "VirtualAlloc at {candidate:#x} size {size:#x} overlaps an existing allocation"
                    ),
                ));
            }
            base
        };
        if address == 0 {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                "PE runtime virtual allocation overflow",
            ));
        }
        memory.map_bytes(address, &vec![0; size]);
        self.win32
            .address_space_mut()
            .commit(address, size as u64, protection, false);
        Ok(address)
    }
}
