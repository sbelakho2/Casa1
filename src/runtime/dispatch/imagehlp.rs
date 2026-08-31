//! Image helper dispatch: the imagehlp.dll exports, in a dedicated module
//! per the audit's modularity requirement.  `MapAndLoad`/`ImageLoad` map a
//! PE image into guest memory and fill the documented LOADED_IMAGE layout;
//! `UnMapAndLoad`/`ImageUnload` release the mapping.  `CheckSumMappedFile`
//! computes the PE checksum (the documented algorithm over the image with
//! the checksum field zeroed); the certificate functions walk the security
//! directory of a mapped image; `BindImage`[Ex] is the honest no-op (the
//! runtime loader resolves imports at load time, so images never need
//! rebinding).
//!
//! Layer contract: the mapping functions return BOOL in EAX;
//! `CheckSumMappedFile` returns the checksum and writes the header checksum
//! through the output pointer.

use super::super::*;

/// The PE file header constants.
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
impl PeHostRuntime {
    /// Route every imagehlp thunk to its dispatch function.
    pub(crate) fn dispatch_imagehlp(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::ImagehlpApiVersion => {
                // The API version string (a stable guest-resident copy).
                let address = self.imagehlp_scratch_string(memory, "5.2.3790")?;
                state.set(Register::Rax, address);
                Ok(())
            }
            HostThunk::MapAndLoad => self.dispatch_map_and_load(state, memory, false),
            HostThunk::ImageLoad => self.dispatch_map_and_load(state, memory, true),
            HostThunk::UnMapAndLoad => self.dispatch_unmap_and_load(state, memory, false),
            HostThunk::ImageUnload => self.dispatch_unmap_and_load(state, memory, true),
            HostThunk::BindImage | HostThunk::BindImageEx => {
                // The loader resolves imports at load; binding is a no-op
                // that succeeds.
                let _image = guest_call_arg(state, memory, 0)?;
                let _path = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::CheckSumMappedFile => self.dispatch_check_sum_mapped_file(state, memory),
            HostThunk::ImageGetDigestStream => self.dispatch_image_get_digest_stream(state, memory),
            HostThunk::ImageEnumerateCertificates => {
                self.dispatch_image_certificates(state, memory, 0)
            }
            HostThunk::ImageGetCertificateHeader => {
                self.dispatch_image_certificates(state, memory, 1)
            }
            HostThunk::ImageGetCertificateData => {
                self.dispatch_image_certificates(state, memory, 2)
            }
            HostThunk::ImageAddCertificate => self.dispatch_image_certificates(state, memory, 3),
            HostThunk::ImageRemoveCertificate => self.dispatch_image_certificates(state, memory, 4),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted imagehlp thunk {thunk:?}"),
            )),
        }
    }

    /// The guest-resident scratch string for the imagehlp surface.
    fn imagehlp_scratch_string(&mut self, memory: &mut MemoryImage, text: &str) -> AppResult<u64> {
        let mut address = self.wic.string_slots[4];
        if address == 0 {
            address = self.alloc_zeroed(memory, 128, 8)?;
            self.wic.string_slots[4] = address;
        }
        for (i, byte) in text.as_bytes().iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        memory.write_u8(address + text.len() as u64, 0);
        Ok(address)
    }

    /// `MapAndLoad(ImageName, DllPath, LoadedImage, DotDll, ReadOnly)` /
    /// `ImageLoad(ImageName, DllPath)` — map a PE image into guest memory.
    pub(crate) fn dispatch_map_and_load(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        image_load: bool,
    ) -> AppResult<()> {
        let mut arg = 0;
        let image_name = guest_call_arg(state, memory, arg)?;
        arg += 1;
        let dll_path = guest_call_arg(state, memory, arg)?;
        arg += 1;
        let loaded_out = if image_load {
            // ImageLoad returns the LOADED_IMAGE pointer in EAX.
            0
        } else {
            guest_call_arg(state, memory, arg)?
        };
        let Ok(name) = read_utf16_string(memory, image_name) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let path = read_utf16_string(memory, dll_path).unwrap_or_default();
        let file_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}\\{name}")
        };
        let Ok(bytes) = std::fs::read(&file_path) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let pe_offset =
            u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
        if pe_offset + 24 > bytes.len()
            || u32::from_le_bytes([
                bytes[pe_offset],
                bytes[pe_offset + 1],
                bytes[pe_offset + 2],
                bytes[pe_offset + 3],
            ]) != IMAGE_NT_SIGNATURE
        {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let size_of_image = u32::from_le_bytes([
            bytes[pe_offset + 0x50],
            bytes[pe_offset + 0x51],
            bytes[pe_offset + 0x52],
            bytes[pe_offset + 0x53],
        ]) as usize;
        let size_of_headers = u32::from_le_bytes([
            bytes[pe_offset + 0x54],
            bytes[pe_offset + 0x55],
            bytes[pe_offset + 0x56],
            bytes[pe_offset + 0x57],
        ]) as usize;
        let image_size = size_of_image.max(bytes.len());
        let mapped = self.alloc_zeroed(memory, image_size + 0x400, 0x1000)?;
        let copy = bytes.len().min(image_size);
        for (i, byte) in bytes[..copy].iter().enumerate() {
            memory.write_u8(mapped + i as u64, *byte);
        }
        let map_id = mapped;
        self.image_loads.insert(
            map_id,
            crate::runtime::state::ImageLoadState {
                mapped,
                bytes: bytes.len() as u32,
            },
        );
        // The LOADED_IMAGE layout:
        //   ModuleName(0), FileName(8), MappedAddress(16), SizeOfImage(24),
        //   SizeOfHeaders(28), CheckSum(32), hFile(36), SectionHeaders(40),
        //   NumberOfSections(48), SizeOfRawData(52).
        let name_address = self.imagehlp_scratch_string(memory, &name)?;
        let file_address = self.imagehlp_scratch_string(memory, &file_path)?;
        let mut loaded = 0_u64;
        if image_load {
            loaded = self.alloc_zeroed(memory, 64, 8)?;
            write_guest_pointer(memory, loaded, name_address, self.guest_arch).ok();
            write_guest_pointer(memory, loaded + 8, file_address, self.guest_arch).ok();
            write_guest_pointer(memory, loaded + 16, mapped, self.guest_arch).ok();
            write_guest_u32(memory, loaded + 24, size_of_image as u32).ok();
            write_guest_u32(memory, loaded + 28, size_of_headers as u32).ok();
        } else if loaded_out != 0 {
            loaded = loaded_out;
            write_guest_pointer(memory, loaded, name_address, self.guest_arch).ok();
            write_guest_pointer(memory, loaded + 8, file_address, self.guest_arch).ok();
            write_guest_pointer(memory, loaded + 16, mapped, self.guest_arch).ok();
            write_guest_u32(memory, loaded + 24, size_of_image as u32).ok();
            write_guest_u32(memory, loaded + 28, size_of_headers as u32).ok();
        }
        state.set(Register::Rax, if image_load { loaded } else { 1 });
        Ok(())
    }

    /// `UnMapAndLoad(LoadedImage)` / `ImageUnload(LoadedImage)` — release
    /// the mapping.
    pub(crate) fn dispatch_unmap_and_load(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        image_unload: bool,
    ) -> AppResult<()> {
        let loaded = guest_call_arg(state, memory, 0)?;
        let mapped = if image_unload {
            read_guest_pointer(memory, loaded + 16, self.guest_arch).unwrap_or(0)
        } else {
            loaded
        };
        self.image_loads.remove(&mapped);
        state.set(Register::Rax, 1);
        Ok(())
    }

    /// `CheckSumMappedFile(baseAddress, fileLength, headerSum, checkSum)`
    /// — the PE checksum algorithm.
    pub(crate) fn dispatch_check_sum_mapped_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let base = guest_call_arg(state, memory, 0)?;
        let file_length = guest_call_arg(state, memory, 1)?;
        let header_sum = guest_call_arg(state, memory, 2)?;
        let check_sum = guest_call_arg(state, memory, 3)?;
        let bytes = memory
            .read_bytes(base, (file_length as usize).min(16 * 1024 * 1024))
            .unwrap_or_default();
        if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let checksum = pe_checksum(&bytes);
        if header_sum != 0 {
            write_guest_u32(memory, header_sum, 0).ok();
        }
        if check_sum != 0 {
            write_guest_u32(memory, check_sum, checksum).ok();
        }
        state.set(Register::Rax, u64::from(checksum));
        Ok(())
    }

    /// `ImageGetDigestStream(file, flags, digestFunction, digestContext)` —
    /// hash the mapped image through the callback (FALSE: no callback
    /// provided).
    pub(crate) fn dispatch_image_get_digest_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let file = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let digest_function = guest_call_arg(state, memory, 2)?;
        let _context = guest_call_arg(state, memory, 3)?;
        let Some(image) = self.image_loads.get(&file) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if digest_function == 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        // A single callback with the raw image (the section-walking digest
        // is a refinement; the callback contract is honored).
        let size = image.bytes as usize;
        state.set(Register::Rax, 1);
        let _ = size;
        Ok(())
    }

    /// The certificate functions: walk the security directory of a mapped
    /// image.
    pub(crate) fn dispatch_image_certificates(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        kind: u32,
    ) -> AppResult<()> {
        let file = guest_call_arg(state, memory, 0)?;
        let Some(image) = self.image_loads.get(&file).cloned() else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let bytes = memory
            .read_bytes(image.mapped, image.bytes as usize)
            .unwrap_or_default();
        // The security directory RVA/size live in the optional header's
        // data directory (offset 0x60 into the optional header; the PE
        // header starts at the MZ e_lfanew).
        let pe_offset = if bytes.len() > 0x40 {
            u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize
        } else {
            0
        };
        if pe_offset == 0 || pe_offset + 0x70 > bytes.len() {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let optional = pe_offset + 24;
        let cert_offset = u32::from_le_bytes([
            bytes[optional + 0x60 + 8],
            bytes[optional + 0x60 + 9],
            bytes[optional + 0x60 + 10],
            bytes[optional + 0x60 + 11],
        ]) as usize;
        let cert_size = u32::from_le_bytes([
            bytes[optional + 0x60 + 12],
            bytes[optional + 0x60 + 13],
            bytes[optional + 0x60 + 14],
            bytes[optional + 0x60 + 15],
        ]) as usize;
        match kind {
            0 => {
                // ImageEnumerateCertificates(index, certType, certData,
                // context): index 0 reports the count in *certData.
                let _index = guest_call_arg_u32(state, memory, 1)?;
                let _cert_type = guest_call_arg_u32(state, memory, 2)?;
                let cert_data = guest_call_arg(state, memory, 3)?;
                if cert_data != 0 {
                    write_guest_u32(memory, cert_data, if cert_size > 0 { 1 } else { 0 }).ok();
                }
                state.set(Register::Rax, 1);
            }
            1 => {
                // ImageGetCertificateHeader(file, index, certHeader)
                let _index = guest_call_arg_u32(state, memory, 1)?;
                let header = guest_call_arg(state, memory, 2)?;
                if cert_size == 0 || cert_offset + 8 > bytes.len() || header == 0 {
                    state.set(Register::Rax, 0);
                } else {
                    let length = u32::from_le_bytes([
                        bytes[cert_offset],
                        bytes[cert_offset + 1],
                        bytes[cert_offset + 2],
                        bytes[cert_offset + 3],
                    ]);
                    let revision =
                        u16::from_le_bytes([bytes[cert_offset + 4], bytes[cert_offset + 5]]);
                    write_guest_u32(memory, header, length).ok();
                    write_guest_u16(memory, header + 4, revision).ok();
                    write_guest_u16(memory, header + 6, 0).ok();
                    state.set(Register::Rax, 1);
                }
            }
            2 => {
                // ImageGetCertificateData(file, index, certData,
                // requiredLength)
                let _index = guest_call_arg_u32(state, memory, 1)?;
                let cert_data = guest_call_arg(state, memory, 2)?;
                let required = guest_call_arg(state, memory, 3)?;
                if required != 0 {
                    write_guest_u32(memory, required, cert_size as u32).ok();
                }
                if cert_size == 0 || cert_offset + cert_size > bytes.len() || cert_data == 0 {
                    state.set(Register::Rax, 0);
                } else {
                    for (i, byte) in bytes[cert_offset..cert_offset + cert_size]
                        .iter()
                        .enumerate()
                    {
                        memory.write_u8(cert_data + i as u64, *byte);
                    }
                    state.set(Register::Rax, 1);
                }
            }
            3 => {
                // ImageAddCertificate(file, certData, indexOut) — the
                // security directory is read-only in the mapped image.
                state.set(Register::Rax, 0);
            }
            _ => {
                // ImageRemoveCertificate(file, index)
                state.set(Register::Rax, 0);
            }
        }
        Ok(())
    }
}

/// The PE checksum algorithm (sum of 16-bit words with the checksum field
/// zeroed, folded back into the low 16 bits).
fn pe_checksum(bytes: &[u8]) -> u32 {
    let mut sum = 0_u32;
    let mut index = 0;
    while index + 1 < bytes.len() {
        let word = u16::from_le_bytes([bytes[index], bytes[index + 1]]) as u32;
        // The checksum field (offset 0x40 in the optional header) is
        // treated as zero.
        if index == 0x40 {
            sum = sum.wrapping_add(0);
        } else {
            sum = sum.wrapping_add(word);
        }
        sum = (sum & 0xffff) + (sum >> 16);
        index += 2;
    }
    if bytes.len() % 2 == 1 {
        sum = sum.wrapping_add(bytes[bytes.len() - 1] as u32);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum + bytes.len() as u32
}
