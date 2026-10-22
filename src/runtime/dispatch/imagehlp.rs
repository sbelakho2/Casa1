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
    /// walk the mapped image (headers plus every section's raw data, with
    /// the requested data directories added for the selective levels) and
    /// invoke the guest digest callback for each byte range.
    pub(crate) fn dispatch_image_get_digest_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let file = guest_call_arg(state, memory, 0)?;
        let flags = guest_call_arg_u32(state, memory, 1)?;
        let digest_function = guest_call_arg(state, memory, 2)?;
        let context = guest_call_arg(state, memory, 3)?;
        let Some(image) = self.image_loads.get(&file).cloned() else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        if digest_function == 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let bytes = memory
            .read_bytes(image.mapped, image.bytes as usize)
            .unwrap_or_default();
        let Some(ranges) = pe_digest_ranges(&bytes, flags) else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let mut ok = true;
        for (start, length) in ranges {
            if length == 0 {
                continue;
            }
            let result = self.execute_guest_callback(
                state,
                memory,
                digest_function,
                &[context, image.mapped + start as u64, length as u64],
                "ImageGetDigestStream::DigestFunction",
            );
            if result.unwrap_or(0) == 0 {
                ok = false;
                break;
            }
        }
        state.set(Register::Rax, u64::from(ok));
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

/// The `CERT_PE_IMAGE_DIGEST_*` levels.
const CERT_PE_IMAGE_DIGEST_DEBUG_INFO: u32 = 1;
const CERT_PE_IMAGE_DIGEST_RESOURCES: u32 = 2;
const CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO: u32 = 4;
const CERT_PE_IMAGE_DIGEST_NON_PE_INFO: u32 = 8;

/// The byte ranges the image digest covers: the headers, every section's
/// raw data, the data directories the selective levels ask for, and the
/// non-PE overlay for CERT_PE_IMAGE_DIGEST_NON_PE_INFO.
fn pe_digest_ranges(bytes: &[u8], flags: u32) -> Option<Vec<(usize, usize)>> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return None;
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
        return None;
    }
    let number_of_sections =
        u16::from_le_bytes([bytes[pe_offset + 6], bytes[pe_offset + 7]]) as usize;
    let optional_size = u16::from_le_bytes([bytes[pe_offset + 20], bytes[pe_offset + 21]]) as usize;
    let optional = pe_offset + 24;
    if optional + 2 > bytes.len() {
        return None;
    }
    let size_of_headers = u32::from_le_bytes([
        bytes[optional + 0x3c],
        bytes[optional + 0x3d],
        bytes[optional + 0x3e],
        bytes[optional + 0x3f],
    ]) as usize;
    let mut ranges = Vec::new();
    ranges.push((0, size_of_headers.min(bytes.len())));
    // The section table: (VirtualAddress, VirtualSize, PointerToRawData,
    // SizeOfRawData) per entry.
    let section_table = optional + optional_size;
    let mut sections: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut max_raw_end = size_of_headers.min(bytes.len());
    for index in 0..number_of_sections {
        let entry = section_table + index * 40;
        if entry + 40 > bytes.len() {
            break;
        }
        let virtual_size = u32::from_le_bytes([
            bytes[entry + 8],
            bytes[entry + 9],
            bytes[entry + 10],
            bytes[entry + 11],
        ]) as usize;
        let virtual_address = u32::from_le_bytes([
            bytes[entry + 12],
            bytes[entry + 13],
            bytes[entry + 14],
            bytes[entry + 15],
        ]) as usize;
        let raw_size = u32::from_le_bytes([
            bytes[entry + 16],
            bytes[entry + 17],
            bytes[entry + 18],
            bytes[entry + 19],
        ]) as usize;
        let raw_pointer = u32::from_le_bytes([
            bytes[entry + 20],
            bytes[entry + 21],
            bytes[entry + 22],
            bytes[entry + 23],
        ]) as usize;
        sections.push((
            virtual_address,
            virtual_size.max(raw_size),
            raw_pointer,
            raw_size,
        ));
        if raw_size != 0 && raw_pointer < bytes.len() {
            let end = raw_pointer.saturating_add(raw_size).min(bytes.len());
            ranges.push((raw_pointer, end - raw_pointer));
            max_raw_end = max_raw_end.max(end);
        }
    }
    let rva_to_offset = |rva: usize| -> Option<usize> {
        if rva < size_of_headers {
            return Some(rva);
        }
        for (virtual_address, virtual_size, raw_pointer, _) in &sections {
            if rva >= *virtual_address && rva < virtual_address + virtual_size.max(&1) {
                return Some(raw_pointer + (rva - virtual_address));
            }
        }
        None
    };
    let magic = u16::from_le_bytes([bytes[optional], bytes[optional + 1]]);
    let directory_offset = if magic == 0x20b {
        optional + 112
    } else {
        optional + 96
    };
    let mark_directory = |index: usize, ranges: &mut Vec<(usize, usize)>| {
        let entry = directory_offset + index * 8;
        if entry + 8 > bytes.len() {
            return;
        }
        let rva = u32::from_le_bytes([
            bytes[entry],
            bytes[entry + 1],
            bytes[entry + 2],
            bytes[entry + 3],
        ]) as usize;
        let size = u32::from_le_bytes([
            bytes[entry + 4],
            bytes[entry + 5],
            bytes[entry + 6],
            bytes[entry + 7],
        ]) as usize;
        if rva == 0 || size == 0 {
            return;
        }
        if let Some(offset) = rva_to_offset(rva) {
            let end = offset.saturating_add(size).min(bytes.len());
            if end > offset {
                ranges.push((offset, end - offset));
            }
        }
    };
    if flags & CERT_PE_IMAGE_DIGEST_DEBUG_INFO != 0 {
        mark_directory(6, &mut ranges);
    }
    if flags & CERT_PE_IMAGE_DIGEST_RESOURCES != 0 {
        mark_directory(2, &mut ranges);
    }
    if flags & CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO != 0 {
        for index in [1, 11, 12, 13] {
            mark_directory(index, &mut ranges);
        }
    }
    if flags & CERT_PE_IMAGE_DIGEST_NON_PE_INFO != 0 && max_raw_end < bytes.len() {
        ranges.push((max_raw_end, bytes.len() - max_raw_end));
    }
    Some(ranges)
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

#[cfg(test)]
mod tests {
    use super::super::test_support::{dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const NAME: u64 = 0x42_000;
    const LOADED: u64 = 0x43_000;
    const STUB: u64 = 0x44_000;
    const COUNTERS: u64 = 0x45_000;

    fn build_pe() -> Vec<u8> {
        let mut pe = vec![0_u8; 0x204];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        let pe_offset = 0x40;
        pe[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        pe[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x14c_u16.to_le_bytes());
        pe[pe_offset + 6..pe_offset + 8].copy_from_slice(&1_u16.to_le_bytes());
        pe[pe_offset + 20..pe_offset + 22].copy_from_slice(&0xe0_u16.to_le_bytes());
        let optional = pe_offset + 24;
        pe[optional..optional + 2].copy_from_slice(&0x10b_u16.to_le_bytes());
        pe[optional + 0x38..optional + 0x3c].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[optional + 0x3c..optional + 0x40].copy_from_slice(&0x200_u32.to_le_bytes());
        let section = optional + 0xe0;
        pe[section..section + 5].copy_from_slice(b".text");
        pe[section + 8..section + 12].copy_from_slice(&4_u32.to_le_bytes());
        pe[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[section + 16..section + 20].copy_from_slice(&4_u32.to_le_bytes());
        pe[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[0x200..0x204].copy_from_slice(b"DATA");
        pe
    }

    fn digest_stub() -> Vec<u8> {
        vec![
            0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+12]
            0x01, 0x05, 0x00, 0x50, 0x04, 0x00, // add [0x45000], eax
            0x83, 0x05, 0x04, 0x50, 0x04, 0x00, 0x01, // add dword [0x45004], 1
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3, // ret
        ]
    }

    fn map_fixture_pe(fixture: &mut super::super::test_support::Fixture) -> u64 {
        let path = fixture._temp.path().join("digest.dll");
        std::fs::write(&path, build_pe()).unwrap();
        let mut name_bytes = Vec::new();
        for unit in path.to_string_lossy().encode_utf16().chain([0]) {
            name_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fixture.memory.map_bytes(NAME, &name_bytes);
        fixture.memory.map_bytes(LOADED, &[0_u8; 64]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::MapAndLoad,
                &[NAME as u32, 0, LOADED as u32, 0, 0]
            ),
            1
        );
        let mapped = read_guest_pointer(&fixture.memory, LOADED + 16, GuestArch::X86).unwrap();
        assert_ne!(mapped, 0);
        mapped
    }
}
