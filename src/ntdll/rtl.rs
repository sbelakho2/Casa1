//! Stage-4 NTDLL — the Rtl surface (string primitives, version reporting,
//! status conversion, context capture).
//!
//! The heap primitives (`RtlAllocateHeap` / `RtlFreeHeap` / `RtlSizeHeap`)
//! are pure adapters onto the runtime's heap implementation (the same
//! bump-allocator the Win32 HeapAlloc/HeapFree thunks drive); they live in
//! the dispatch wiring together with the runtime-side `RtlRaiseException` /
//! `RtlLookupFunctionEntry` (they need the SEH subsystem).  This module owns
//! the guest-format helpers: UNICODE_STRING / ANSI_STRING construction and
//! comparison, the version structure, and the status conversion boundary.

use crate::cpu::{GuestArch, MemoryImage};
use crate::ntdll::{NtStatus, nt_status_to_dos_error};

/// Read a guest `UNICODE_STRING` header (Length u16, MaximumLength u16,
/// Buffer ptr at +4 on x86 / +8 on x64) and the wide characters it names.
/// The length is in BYTES per the NT contract; a zero `Buffer` reads empty.
pub fn read_unicode_string(
    memory: &MemoryImage,
    string_ptr: u64,
    arch: GuestArch,
) -> Result<String, NtStatus> {
    if string_ptr == 0 {
        return Ok(String::new());
    }
    let length = memory
        .read_u16(string_ptr)
        .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?;
    let buffer_ptr = read_unicode_buffer_ptr(memory, string_ptr, arch)?;
    if buffer_ptr == 0 || length == 0 {
        return Ok(String::new());
    }
    let byte_len = length as usize;
    let mut bytes = vec![0_u8; byte_len];
    memory
        .read_into(buffer_ptr, &mut bytes)
        .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?;
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Ok(String::from_utf16_lossy(&units))
}

fn read_unicode_buffer_ptr(
    memory: &MemoryImage,
    string_ptr: u64,
    arch: GuestArch,
) -> Result<u64, NtStatus> {
    match arch {
        GuestArch::X64 => memory
            .read_u64(string_ptr + 8)
            .map_err(|_| STATUS_ACCESS_VIOLATION_RTL),
        GuestArch::X86 => memory
            .read_u32(string_ptr + 4)
            .map(u64::from)
            .map_err(|_| STATUS_ACCESS_VIOLATION_RTL),
    }
}

/// Write a guest `UNICODE_STRING` header (Length + MaximumLength in bytes,
/// Buffer at +4 on x86 / +8 on x64).
pub fn write_unicode_string_header(
    memory: &mut MemoryImage,
    string_ptr: u64,
    buffer_ptr: u64,
    length_bytes: u16,
    maximum_length_bytes: u16,
    arch: GuestArch,
) -> Result<(), NtStatus> {
    memory.write_u16(string_ptr, length_bytes);
    memory.write_u16(string_ptr + 2, maximum_length_bytes);
    match arch {
        GuestArch::X64 => {
            memory.write_u64(string_ptr + 8, buffer_ptr);
        }
        GuestArch::X86 => {
            memory.write_u32(string_ptr + 4, buffer_ptr as u32);
        }
    }
    Ok(())
}

/// Read a NUL-terminated wide string (the Rtl* string sources).
pub fn read_wide_string(memory: &MemoryImage, ptr: u64) -> Result<String, NtStatus> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mut units = Vec::new();
    let mut offset = 0_u64;
    loop {
        let unit = memory
            .read_u16(ptr + offset)
            .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?;
        if unit == 0 {
            break;
        }
        units.push(unit);
        offset += 2;
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Read a NUL-terminated ANSI string.
pub fn read_ansi_string(memory: &MemoryImage, ptr: u64) -> Result<String, NtStatus> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mut bytes = Vec::new();
    let mut offset = 0_u64;
    loop {
        let byte = memory
            .read_u8(ptr + offset)
            .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        offset += 1;
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read an ANSI_STRING structure (`{ Length: u16 @0, MaximumLength: u16 @2,
/// Buffer: uptr @8 (x64) / @4 (x86) }`).  Length is in BYTES for ANSI
/// strings; the buffer bytes are decoded lossily like
/// [`read_ansi_string`].
pub fn read_ansi_string_struct(
    memory: &MemoryImage,
    string_ptr: u64,
    arch: GuestArch,
) -> Result<String, NtStatus> {
    if string_ptr == 0 {
        return Ok(String::new());
    }
    let length = memory
        .read_u16(string_ptr)
        .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?;
    let buffer_ptr = match arch {
        GuestArch::X64 => memory
            .read_u64(string_ptr + 8)
            .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?,
        GuestArch::X86 => u64::from(
            memory
                .read_u32(string_ptr + 4)
                .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?,
        ),
    };
    if buffer_ptr == 0 || length == 0 {
        return Ok(String::new());
    }
    let mut bytes = vec![0_u8; length as usize];
    memory
        .read_into(buffer_ptr, &mut bytes)
        .map_err(|_| STATUS_ACCESS_VIOLATION_RTL)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `RtlInitUnicodeString` — initialize the destination header from a
/// NUL-terminated wide source (Buffer aliases the source; Length excludes
/// the terminator, MaximumLength includes it).
pub fn rtl_init_unicode_string(
    memory: &mut MemoryImage,
    destination_ptr: u64,
    source_ptr: u64,
    arch: GuestArch,
) -> Result<(), NtStatus> {
    let value = read_wide_string(memory, source_ptr)?;
    let bytes = value.encode_utf16().count() as u32 * 2;
    write_unicode_string_header(
        memory,
        destination_ptr,
        source_ptr,
        bytes as u16,
        (bytes + 2) as u16,
        arch,
    )
}

/// `RtlInitAnsiString` — ANSI variant (Length in bytes, MaximumLength
/// includes the NUL).
pub fn rtl_init_ansi_string(
    memory: &mut MemoryImage,
    destination_ptr: u64,
    source_ptr: u64,
    arch: GuestArch,
) -> Result<(), NtStatus> {
    let value = read_ansi_string(memory, source_ptr)?;
    let bytes = value.len() as u16;
    match arch {
        GuestArch::X64 => {
            memory.write_u16(destination_ptr, bytes);
            memory.write_u16(destination_ptr + 2, bytes.saturating_add(1));
            memory.write_u64(destination_ptr + 8, source_ptr);
        }
        GuestArch::X86 => {
            memory.write_u16(destination_ptr, bytes);
            memory.write_u16(destination_ptr + 2, bytes.saturating_add(1));
            memory.write_u32(destination_ptr + 4, source_ptr as u32);
        }
    }
    Ok(())
}

/// `RtlFreeUnicodeString` / `RtlFreeAnsiString` — zero the header.  The
/// buffer itself is NOT freed: the runtime cannot free arbitrary guest
/// allocations (documented divergence — the header contract is preserved so
/// double-init/free of stack strings behaves like Windows).
pub fn rtl_free_string_header(memory: &mut MemoryImage, string_ptr: u64) -> Result<(), NtStatus> {
    memory.write_u16(string_ptr, 0);
    memory.write_u16(string_ptr + 2, 0);
    Ok(())
}

/// `RtlCompareUnicodeString` — returns <0 / 0 / >0.  Case-insensitive mode
/// compares the lowercased units.
pub fn rtl_compare_unicode_string(
    memory: &MemoryImage,
    first_ptr: u64,
    second_ptr: u64,
    case_insensitive: bool,
    arch: GuestArch,
) -> Result<i32, NtStatus> {
    let first = read_unicode_string(memory, first_ptr, arch)?;
    let second = read_unicode_string(memory, second_ptr, arch)?;
    let comparison = if case_insensitive {
        first.to_lowercase().cmp(&second.to_lowercase())
    } else {
        first.cmp(&second)
    };
    Ok(match comparison {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}

/// `RtlEqualUnicodeString` — equality (case-sensitive or not).
pub fn rtl_equal_unicode_string(
    memory: &MemoryImage,
    first_ptr: u64,
    second_ptr: u64,
    case_insensitive: bool,
    arch: GuestArch,
) -> Result<bool, NtStatus> {
    let first = read_unicode_string(memory, first_ptr, arch)?;
    let second = read_unicode_string(memory, second_ptr, arch)?;
    Ok(if case_insensitive {
        first.eq_ignore_ascii_case(&second)
    } else {
        first == second
    })
}

/// `RtlNtStatusToDosError` — the canonical NTSTATUS → Win32 conversion
/// (the Win32 wrapper boundary).
pub fn rtl_nt_status_to_dos_error(status: NtStatus) -> u32 {
    nt_status_to_dos_error(status)
}

/// The configured guest version, mirroring the fields the Win32
/// GetVersionExW / VerifyVersionInfoW thunks report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtOsVersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
}

/// `OSVERSIONINFOEXW` (x64, 284 bytes): the structure `RtlGetVersion` writes
/// (the same layout GetVersionExW uses in this runtime).
pub const OSVERSIONINFOEXW_SIZE: usize = 0x11C;

impl NtOsVersionInfo {
    /// Serialize the OSVERSIONINFOEXW layout:
    /// `dwOSVersionInfoSize(4) dwMajorVersion(4) dwMinorVersion(4)
    ///  dwBuildNumber(4) dwPlatformId(4) szCSDVersion[128] wServicePackMajor(2)
    ///  wServicePackMinor(2) wSuiteMask(2) wProductType(1) wReserved(1)`.
    pub fn serialize_ex_x64(&self, csd: &str) -> [u8; 0x11C] {
        let mut bytes = [0_u8; 0x11C];
        bytes[0..4].copy_from_slice(&(OSVERSIONINFOEXW_SIZE as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&self.major.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.minor.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.build.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.platform_id.to_le_bytes());
        // szCSDVersion at 0x14 (128 bytes of UTF-16, NUL-terminated).
        let mut written = 0;
        for (index, unit) in csd.encode_utf16().take(127).enumerate() {
            let offset = 0x14 + index * 2;
            bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
            written = index + 1;
        }
        let _ = written;
        bytes[0x114..0x116].copy_from_slice(&self.service_pack_major.to_le_bytes());
        bytes[0x116..0x118].copy_from_slice(&self.service_pack_minor.to_le_bytes());
        bytes[0x118..0x11A].copy_from_slice(&self.suite_mask.to_le_bytes());
        bytes[0x11A] = self.product_type;
        bytes
    }
}

/// `STATUS_ACCESS_VIOLATION` used by the string readers.
const STATUS_ACCESS_VIOLATION_RTL: NtStatus = crate::ntdll::STATUS_ACCESS_VIOLATION;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::VirtualMemory;

    fn memory_with(vm: &mut VirtualMemory) -> MemoryImage {
        // Register the test address ranges in the canonical VM so the raw
        // accessors (which consult the VM first) validate.
        vm.register(0x4000_0000, 0x4000_0000, crate::vm::VmRegionKind::Private);
        vm.commit(
            0x4000_0000,
            0x4000_0000,
            crate::vm::VmProtection::READ_WRITE,
            false,
        );
        let mut memory = MemoryImage::default();
        memory.set_vm(vm);
        memory
    }

    fn mapped(memory: &mut MemoryImage, bytes: &[u8]) -> u64 {
        let address = 0x4000_0000;
        memory.map_bytes(address, bytes);
        address
    }

    fn mapped_at(memory: &mut MemoryImage, address: u64, bytes: &[u8]) {
        memory.map_bytes(address, bytes);
    }

    #[test]
    fn unicode_string_round_trips_through_guest_memory() {
        let mut vm = VirtualMemory::new(0x7fff_0000_0000);
        let mut memory = memory_with(&mut vm);
        // Source wide string "abc".
        let mut wide = "abc"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        wide.extend_from_slice(&0u16.to_le_bytes());
        let source = mapped(&mut memory, &wide);
        let header = 0x4100_0000;
        mapped_at(&mut memory, header, &[0_u8; 16]);
        rtl_init_unicode_string(&mut memory, header, source, GuestArch::X64).expect("init");
        assert_eq!(memory.read_u16(header).unwrap(), 6, "Length in bytes");
        assert_eq!(memory.read_u16(header + 2).unwrap(), 8, "MaximumLength");
        assert_eq!(
            memory.read_u64(header + 8).unwrap(),
            source,
            "Buffer aliases"
        );
        assert_eq!(
            read_unicode_string(&memory, header, GuestArch::X64).as_deref(),
            Ok("abc")
        );
        // The x86 header is laid out differently.
        let header32 = 0x4200_0000;
        mapped_at(&mut memory, header32, &[0_u8; 8]);
        rtl_init_unicode_string(&mut memory, header32, source, GuestArch::X86).expect("init");
        assert_eq!(memory.read_u32(header32 + 4).unwrap(), source as u32);
        assert_eq!(
            read_unicode_string(&memory, header32, GuestArch::X86).as_deref(),
            Ok("abc")
        );
    }

    #[test]
    fn compare_and_equal_implement_the_nt_contract() {
        let mut vm = VirtualMemory::new(0x7fff_0000_0000);
        let mut memory = memory_with(&mut vm);
        let a_buf = mapped(
            &mut memory,
            &"Alpha"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect::<Vec<_>>(),
        );
        let b_buf = 0x4100_0000;
        mapped_at(
            &mut memory,
            b_buf,
            &"alpha"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect::<Vec<_>>(),
        );
        let c_buf = 0x4200_0000;
        mapped_at(
            &mut memory,
            c_buf,
            &"Beta"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect::<Vec<_>>(),
        );
        // The Rtl* comparison entry points take UNICODE_STRING headers.
        let a = 0x4300_0000;
        let b = 0x4300_0010;
        let c = 0x4300_0020;
        for (header, buffer, text) in [(a, a_buf, "Alpha"), (b, b_buf, "alpha"), (c, c_buf, "Beta")]
        {
            mapped_at(&mut memory, header, &[0_u8; 16]);
            rtl_init_unicode_string(&mut memory, header, buffer, GuestArch::X64).expect("init");
            assert_eq!(
                read_unicode_string(&memory, header, GuestArch::X64).as_deref(),
                Ok(text)
            );
        }
        // Case-sensitive: "Alpha" < "alpha" ('A' < 'a').
        assert_eq!(
            rtl_compare_unicode_string(&memory, a, b, false, GuestArch::X64),
            Ok(-1)
        );
        assert_eq!(
            rtl_compare_unicode_string(&memory, a, b, true, GuestArch::X64),
            Ok(0)
        );
        assert_eq!(
            rtl_compare_unicode_string(&memory, a, c, false, GuestArch::X64),
            Ok(-1)
        );
        assert_eq!(
            rtl_equal_unicode_string(&memory, a, b, false, GuestArch::X64),
            Ok(false)
        );
        assert_eq!(
            rtl_equal_unicode_string(&memory, a, b, true, GuestArch::X64),
            Ok(true)
        );
    }

    #[test]
    fn os_version_info_serializes_the_configured_version() {
        let info = NtOsVersionInfo {
            major: 10,
            minor: 0,
            build: 22631,
            platform_id: 2,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0x100,
            product_type: 1,
        };
        let bytes = info.serialize_ex_x64("");
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0x11C);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 22631);
        assert_eq!(
            u16::from_le_bytes(bytes[0x118..0x11A].try_into().unwrap()),
            0x100
        );
        assert_eq!(bytes[0x11A], 1);
        assert_eq!(bytes.len(), OSVERSIONINFOEXW_SIZE);
    }

    #[test]
    fn status_conversion_boundary_agrees_with_the_canonical_map() {
        assert_eq!(
            rtl_nt_status_to_dos_error(crate::ntdll::STATUS_INVALID_HANDLE),
            crate::error::ntstatus_to_dos_error(0xC000_0008)
        );
    }
}
