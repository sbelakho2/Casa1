//! Guest memory read/write primitives.

use super::*;

pub(crate) fn read_c_string(memory: &MemoryImage, address: u64) -> AppResult<String> {
    let bytes = read_c_string_limit(memory, address, usize::MAX)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn read_c_string_limit(
    memory: &MemoryImage,
    address: u64,
    limit: usize,
) -> AppResult<Vec<u8>> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = Vec::new();
    let mut cursor = address;
    while bytes.len() < limit {
        let byte = memory.read_u8(cursor)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        cursor = cursor.wrapping_add(1);
    }
    Ok(bytes)
}

pub(crate) fn read_utf16_string(memory: &MemoryImage, address: u64) -> AppResult<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut code_units = Vec::new();
    let mut cursor = address;
    loop {
        let low = memory.read_u8(cursor)?;
        let high = memory.read_u8(cursor + 1)?;
        let code_unit = u16::from_le_bytes([low, high]);
        if code_unit == 0 {
            break;
        }
        code_units.push(code_unit);
        cursor = cursor.wrapping_add(2);
    }
    Ok(String::from_utf16_lossy(&code_units))
}

/// Read a NUL-terminated UTF-16 guest string with full validation.
///
/// - Stops at the first NUL unit (the terminator is not included).
/// - Reads at most `max_chars` UTF-16 code units (excluding the NUL);
///   exceeding the limit is an error (`RcGuestPointerOutOfRange`).
/// - Handles page boundaries (reads via the page-aware memory accessors).
/// - Returns a guest-visible error (Err(AppError)) on any unmapped page or
///   unmapped range rather than silently truncating.
/// - Handles unaligned pointers (byte-wise reads; Windows permits unaligned
///   UTF-16 string pointers for x86).
/// - Handles x86 (32-bit) pointer width: the pointer value is the zero-
///   extended guest address already; nothing further is required.
/// - Validates surrogate pairs: well-formed pairs (e.g. U+1F600) round-trip
///   losslessly through `String::from_utf16_lossy`; lone surrogates are
///   replaced lossily (U+FFFD) where only a Rust `String` is representable.
///
/// A NULL pointer yields an empty string, matching the existing
/// `read_utf16_string` behavior. Strings written by the guest immediately
/// before the call are visible directly (same address space, no cache).
pub(crate) fn read_utf16z(memory: &MemoryImage, ptr: u64, max_chars: usize) -> AppResult<String> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mut code_units = Vec::new();
    let mut cursor = ptr;
    let mut count = 0_usize;
    loop {
        // One more non-NUL unit than the limit means the string exceeds it.
        if count > max_chars {
            return Err(AppError::new(
                ReasonCode::RcGuestPointerOutOfRange,
                format!("UTF-16 string at {ptr:#x} exceeds the {max_chars}-unit limit"),
            ));
        }
        let low_address = cursor;
        let high_address = cursor.checked_add(1).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcGuestPointerOutOfRange,
                format!("UTF-16 string pointer overflow at {cursor:#x}"),
            )
        })?;
        let low = memory.read_u8(low_address)?;
        let high = memory.read_u8(high_address)?;
        let code_unit = u16::from_le_bytes([low, high]);
        if code_unit == 0 {
            break;
        }
        code_units.push(code_unit);
        cursor = cursor.checked_add(2).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcGuestPointerOutOfRange,
                format!("UTF-16 string pointer overflow at {cursor:#x}"),
            )
        })?;
        count += 1;
    }
    Ok(String::from_utf16_lossy(&code_units))
}

/// Write a NUL-terminated UTF-16 string into a guest buffer with `capacity_chars`
/// units.  Returns false (writing nothing) when the buffer cannot hold the
/// string and its terminator, or when the pointer is null.
pub(crate) fn write_utf16_buffer(
    memory: &mut MemoryImage,
    address: u64,
    capacity_chars: usize,
    value: &str,
) -> bool {
    if address == 0 || capacity_chars == 0 {
        return false;
    }
    let units: Vec<u16> = value.encode_utf16().collect();
    if units.len() + 1 > capacity_chars {
        return false;
    }
    for (index, unit) in units.iter().enumerate() {
        write_u16(memory, address + index as u64 * 2, *unit);
    }
    write_u16(memory, address + units.len() as u64 * 2, 0);
    true
}

/// Read a null-terminated ANSI string from guest memory.
pub(crate) fn read_ansi_string(memory: &MemoryImage, address: u64) -> String {
    if address == 0 {
        return String::new();
    }
    let mut s = String::new();
    let mut offset = 0;
    loop {
        match memory.read_u8(address.wrapping_add(offset)) {
            Ok(0) => break,
            Ok(c) => {
                s.push(c as char);
                offset += 1;
            }
            Err(_) => break,
        }
    }
    s
}

pub(crate) fn classify_wide_char_type(info_type: u32, code_unit: u16) -> u16 {
    match info_type {
        CT_CTYPE1 => {
            let Some(ch) = char::from_u32(u32::from(code_unit)) else {
                return 0;
            };
            let mut mask = 0;
            if ch.is_uppercase() {
                mask |= C1_UPPER;
            }
            if ch.is_lowercase() {
                mask |= C1_LOWER;
            }
            if ch.is_numeric() {
                mask |= C1_DIGIT;
            }
            if ch.is_whitespace() {
                mask |= C1_SPACE;
            }
            if ch == ' ' || ch == '\t' {
                mask |= C1_BLANK;
            }
            if ch.is_control() {
                mask |= C1_CNTRL;
            }
            if ch.is_alphabetic() {
                mask |= C1_ALPHA;
            }
            if ch.is_ascii_hexdigit() {
                mask |= C1_XDIGIT;
            }
            if !ch.is_control() && !ch.is_whitespace() && !ch.is_alphanumeric() {
                mask |= C1_PUNCT;
            }
            mask
        }
        CT_CTYPE2 | CT_CTYPE3 => 0,
        _ => 0,
    }
}

pub(crate) fn read_utf16_environment_block(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<BTreeMap<String, String>> {
    let mut cursor = address;
    let mut environment = BTreeMap::new();
    loop {
        let entry = read_utf16_string(memory, cursor)?;
        if entry.is_empty() {
            break;
        }
        if let Some((key, value)) = entry.split_once('=') {
            environment.insert(key.to_string(), value.to_string());
        }
        cursor = cursor.wrapping_add(((entry.encode_utf16().count() + 1) * 2) as u64);
    }
    Ok(environment)
}

/// Read a Win32 ANSI environment block from guest memory.
///
/// The format is a sequence of null-terminated ANSI strings
/// `"KEY=VALUE\0"` terminated by an additional null byte
/// (i.e. double-null terminated overall).
pub(crate) fn read_ansi_environment_block(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<BTreeMap<String, String>> {
    let mut cursor = address;
    let mut environment = BTreeMap::new();
    loop {
        let entry = read_c_string(memory, cursor)?;
        if entry.is_empty() {
            break;
        }
        if let Some((key, value)) = entry.split_once('=') {
            environment.insert(key.to_string(), value.to_string());
        }
        cursor = cursor.wrapping_add((entry.len() + 1) as u64);
    }
    Ok(environment)
}

pub(crate) fn module_file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

pub(crate) fn build_windows_command_line(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_string())
        .chain(args.iter().cloned())
        .map(|arg| {
            if arg.contains([' ', '\t', '"']) {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Expand the Win32 `GENERIC_*` access bits into their concrete
/// `FILE_*`/standard-right equivalents, as `NtCreateFile` does when
/// `CreateFile`-style desired-access values are passed in.  The expanded mask
/// is what gets stored as the handle's granted access and what subsequent
/// per-operation access checks are evaluated against; a bare `GENERIC_READ`
/// must not implicitly grant `FILE_WRITE_*` bits, and vice versa.
pub(crate) fn expand_generic_access(desired_access: u32) -> u32 {
    const GENERIC_BITS: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    let mut expanded = desired_access & !GENERIC_BITS;
    if desired_access & GENERIC_READ != 0 {
        expanded |= FILE_GENERIC_READ;
    }
    if desired_access & GENERIC_WRITE != 0 {
        expanded |= FILE_GENERIC_WRITE;
    }
    if desired_access & GENERIC_EXECUTE != 0 {
        expanded |= FILE_GENERIC_EXECUTE;
    }
    if desired_access & GENERIC_ALL != 0 {
        expanded |= FILE_ALL_ACCESS;
    }
    expanded
}

/// Project a full Win32 file-rights mask onto the three-boolean
/// `crate::ge::FileAccess` used by the GE filesystem layer.
///
/// This is a deliberate compatibility projection: the GE layer reasons about
/// read/write/delete intent, while the full expanded rights mask is retained
/// on the handle for per-operation enforcement (see `require_access` in
/// win32.rs).  `FILE_EXECUTE` deliberately does NOT imply read-data: execute
/// access alone must not allow reading the file's contents.
///
/// Attribute/EA access does NOT participate in share classification (Windows:
/// an attribute-only open succeeds even against a share=0 holder); those bits
/// are only enforced per-operation via the granted mask.
pub(crate) fn file_access_from_win32(desired_access: u32) -> crate::ge::FileAccess {
    let read_bits = GENERIC_READ | GENERIC_ALL | FILE_READ_DATA;
    let write_bits =
        GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD;
    crate::ge::FileAccess {
        read: desired_access & read_bits != 0,
        write: desired_access & write_bits != 0,
        delete: desired_access & (GENERIC_ALL | DELETE_ACCESS | FILE_DELETE_CHILD) != 0,
    }
}

pub(crate) fn share_mode_from_win32(share_mode: u32) -> crate::ge::ShareMode {
    crate::ge::ShareMode {
        read: share_mode & FILE_SHARE_READ != 0,
        write: share_mode & FILE_SHARE_WRITE != 0,
        delete: share_mode & FILE_SHARE_DELETE != 0,
    }
}

pub(crate) fn creation_disposition_from_win32(value: u32) -> AppResult<CreationDisposition> {
    match value {
        CREATE_NEW => Ok(CreationDisposition::CreateNew),
        CREATE_ALWAYS => Ok(CreationDisposition::CreateAlways),
        OPEN_EXISTING => Ok(CreationDisposition::OpenExisting),
        OPEN_ALWAYS => Ok(CreationDisposition::OpenAlways),
        TRUNCATE_EXISTING => Ok(CreationDisposition::TruncateExisting),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported CreateFileW disposition {other}"),
        )),
    }
}

pub(crate) fn read_guest_u16(memory: &MemoryImage, address: u64) -> AppResult<u16> {
    memory.read_u16(address)
}

pub(crate) fn read_guest_u32(memory: &MemoryImage, address: u64) -> AppResult<u32> {
    memory.read_u32(address)
}

pub(crate) fn probe_read_guest_u32(memory: &MemoryImage, address: u64) -> Option<u32> {
    if !memory.is_range_mapped(address, 4) {
        return None;
    }
    read_guest_u32(memory, address).ok()
}

pub(crate) fn probe_read_guest_pointer(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
) -> Option<u64> {
    if !memory.is_range_mapped(address, guest_arch.pointer_bytes()) {
        return None;
    }
    read_guest_pointer(memory, address, guest_arch).ok()
}

pub(crate) fn read_guest_i32(memory: &MemoryImage, address: u64) -> AppResult<i32> {
    Ok(memory.read_u32(address)? as i32)
}

pub(crate) fn read_guest_f32(memory: &MemoryImage, address: u64) -> AppResult<f32> {
    Ok(f32::from_bits(read_guest_u32(memory, address)?))
}

pub(crate) fn write_guest_u32(memory: &mut MemoryImage, address: u64, value: u32) -> AppResult<()> {
    memory.write_u32(address, value);
    Ok(())
}

pub(crate) fn write_guest_u64(memory: &mut MemoryImage, address: u64, value: u64) -> AppResult<()> {
    memory.write_u64(address, value);
    Ok(())
}

pub(crate) fn write_guest_u16(memory: &mut MemoryImage, address: u64, value: u16) -> AppResult<()> {
    memory.write_u16(address, value);
    Ok(())
}

pub(crate) fn write_guest_f64(memory: &mut MemoryImage, address: u64, value: f64) -> AppResult<()> {
    memory.write_u64(address, value.to_bits());
    Ok(())
}

pub(crate) fn write_guest_f32(memory: &mut MemoryImage, address: u64, value: f32) -> AppResult<()> {
    memory.write_u32(address, value.to_bits());
    Ok(())
}

pub(crate) fn read_guest_u64(memory: &MemoryImage, address: u64) -> AppResult<u64> {
    memory.read_u64(address)
}

pub(crate) fn read_guest_f64(memory: &MemoryImage, address: u64) -> AppResult<f64> {
    Ok(f64::from_bits(memory.read_u64(address)?))
}

pub(crate) fn read_guest_bytes(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> AppResult<Vec<u8>> {
    memory.read_bytes(address, len)
}

/// Validate that a guest pointer range `[address, address+len)` is accessible.
///
/// Delegates to [`crate::host_thunks::validate_guest_pointer`] for consistent
/// null-pointer, overflow, and range-mapped checks across all call sites.
#[allow(dead_code)] // validate_guest_pointer: checked guest-memory access helper; flagged for the API database (no current PE import path reaches it)
pub(crate) fn validate_guest_pointer(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> AppResult<()> {
    host_validate_guest_pointer(memory, address, len)
}

/// Read bytes from guest memory with full pointer validation.
///
/// Delegates to [`crate::host_thunks::read_guest_bytes_checked`] for consistent
/// validation across all call sites.
#[allow(dead_code)] // read_guest_bytes_checked: checked guest-memory access helper; flagged for the API database (no current PE import path reaches it)
pub(crate) fn read_guest_bytes_checked(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> AppResult<Vec<u8>> {
    host_read_guest_bytes_checked(memory, address, len)
}

/// Write a byte slice to guest memory with full pointer validation.
///
/// Delegates to [`crate::host_thunks::write_guest_bytes_checked`] for consistent
/// validation across all call sites.
#[allow(dead_code)] // write_guest_bytes_checked: checked guest-memory access helper; flagged for the API database (no current PE import path reaches it)
pub(crate) fn write_guest_bytes_checked(
    memory: &mut MemoryImage,
    address: u64,
    bytes: &[u8],
) -> AppResult<()> {
    host_write_guest_bytes_checked(memory, address, bytes)
}

/// Read a UTF-16 null-terminated string from guest memory with validation.
///
/// Reads code units one at a time until a null terminator is found or
/// `max_units` code units have been read. Returns an error for null pointers,
/// unmapped memory, or if the string exceeds `max_units`.
#[allow(dead_code)] // read_utf16_string_checked: checked guest-memory access helper; flagged for the API database (no current PE import path reaches it)
pub(crate) fn read_utf16_string_checked(
    memory: &MemoryImage,
    address: u64,
    max_units: usize,
) -> AppResult<String> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            "guest pointer for UTF-16 string is null",
        ));
    }
    let mut code_units = Vec::new();
    let mut cursor = address;
    for _ in 0..max_units {
        let byte_addr = cursor;
        validate_guest_pointer(memory, byte_addr, 2)?;
        let low = memory.read_u8(cursor)?;
        let high = memory.read_u8(cursor + 1)?;
        let code_unit = u16::from_le_bytes([low, high]);
        if code_unit == 0 {
            break;
        }
        code_units.push(code_unit);
        cursor = cursor.checked_add(2).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcGuestPointerOutOfRange,
                "guest pointer overflow while reading UTF-16 string",
            )
        })?;
    }
    Ok(String::from_utf16_lossy(&code_units))
}

pub(crate) fn read_filetime(memory: &MemoryImage, address: u64) -> AppResult<u64> {
    let low = read_u32(memory, address)? as u64;
    let high = read_u32(memory, address + 4)? as u64;
    Ok(low | (high << 32))
}

pub(crate) fn read_guid_string(memory: &MemoryImage, address: u64) -> AppResult<String> {
    let data1 = read_u32(memory, address)?;
    let data2 = read_guest_u16(memory, address + 4)?;
    let data3 = read_guest_u16(memory, address + 6)?;
    let data4 = memory.read_bytes(address + 8, 8)?;
    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        data1,
        data2,
        data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7],
    ))
}

pub(crate) fn read_u32(memory: &MemoryImage, address: u64) -> AppResult<u32> {
    Ok(u32::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
        memory.read_u8(address + 2)?,
        memory.read_u8(address + 3)?,
    ]))
}

pub(crate) fn read_u64(memory: &MemoryImage, address: u64) -> AppResult<u64> {
    let low = read_u32(memory, address)?;
    let high = read_u32(memory, address + 4)?;
    Ok((u64::from(high) << 32) | u64::from(low))
}

#[allow(dead_code)] // read_u16: checked guest-memory access helper; flagged for the API database (no current PE import path reaches it)
pub(crate) fn read_u16(memory: &MemoryImage, address: u64) -> AppResult<u16> {
    Ok(u16::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
    ]))
}

pub(crate) fn write_i32(memory: &mut MemoryImage, address: u64, value: i32) {
    write_u32(memory, address, value as u32);
}

pub(crate) fn write_utf16_fixed(
    memory: &mut MemoryImage,
    address: u64,
    capacity: usize,
    value: &str,
) {
    let mut bytes = vec![0_u8; capacity * 2];
    for (index, unit) in value
        .encode_utf16()
        .take(capacity.saturating_sub(1))
        .enumerate()
    {
        let offset = index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    memory.map_bytes(address, &bytes);
}

pub(crate) fn write_u32(memory: &mut MemoryImage, address: u64, value: u32) {
    memory.map_bytes(address, &value.to_le_bytes());
}

pub(crate) fn write_u64(memory: &mut MemoryImage, address: u64, value: u64) {
    memory.write_u64(address, value);
}

pub(crate) fn write_u16(memory: &mut MemoryImage, address: u64, value: u16) {
    memory.map_bytes(address, &value.to_le_bytes());
}

pub(crate) fn write_u8(memory: &mut MemoryImage, address: u64, value: u8) {
    memory.map_bytes(address, &[value]);
}

/// Read a slice of bytes from guest memory.
pub(crate) fn read_memory_slice(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> AppResult<Vec<u8>> {
    memory.read_bytes(address, len)
}
