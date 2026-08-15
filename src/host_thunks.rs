//! Centralized host thunk metadata, guest pointer helpers, and subsystem
//! organization for the PE runtime dispatch layer.
//!
//! This module provides:
//! - [`ThunkMetadata`] — centralized metadata for each host thunk (name,
//!   subsystem, argument count, last-error behavior).
//! - [`Subsystem`] — enumeration of host thunk subsystems for modular
//!   organization.
//! - [`LastErrorBehavior`] — describes how a thunk affects `GetLastError`.
//! - Guest pointer read/write helpers with bounds checking, overflow
//!   protection, and partial-write detection.
//!
//! # Design Goals
//!
//! 1. **Single source of truth** for thunk metadata so argument counts, names,
//!    and last-error behavior stay consistent across dispatch, testing, and
//!    diagnostics.
//! 2. **Safe guest memory access** through validated pointer helpers that
//!    replace ad-hoc `memory.read_u32(...)` calls with bounds-checked
//!    alternatives.
//! 3. **Subsystem-level organization** enabling future modular splitting of
//!    `pe_runtime.rs` by grouping thunks into logical categories.

use crate::cpu::MemoryImage;
use crate::error::AppError;
use crate::reason::ReasonCode;

// ---------------------------------------------------------------------------
// Subsystem enumeration
// ---------------------------------------------------------------------------

/// Subsystem categories for host thunks.
///
/// Each thunk belongs to exactly one subsystem, which determines its
/// logical grouping for modular dispatch, testing, and documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subsystem {
    /// Core Win32 kernel APIs (kernel32.dll, kernelbase.dll, ntdll.dll).
    Kernel,
    /// User32 window management and GDI (user32.dll, gdi32.dll).
    User32,
    /// Network APIs (ws2_32.dll, winhttp.dll, wininet.dll).
    Network,
    /// Graphics APIs (d3d11.dll, d3d12.dll, dxgi.dll, d3d9.dll).
    Graphics,
    /// Audio APIs (xaudio2_*.dll, dsound.dll).
    Audio,
    /// COM / OLE automation (ole32.dll, oleaut32.dll).
    Com,
    /// Shell and filesystem (shell32.dll, shlwapi.dll, advapi32.dll).
    Shell,
    /// Steam API (steam_api64.dll, steam_api.dll).
    Steam,
    /// Direct2D / DirectWrite (d2d1.dll, dwrite.dll).
    D2D,
    /// WebView2 (webview2.dll).
    WebView2,
    /// WMI (wbem*.dll).
    Wmi,
    /// Security and cryptography (bcrypt.dll, crypt32.dll).
    Security,
    /// C runtime (msvcrt.dll, ucrtbase.dll, vcruntime*.dll).
    Crt,
    /// Diagnostics and telemetry.
    Diagnostics,
    /// Internal runtime helpers (guest object management, delay-load).
    Runtime,
}

// ---------------------------------------------------------------------------
// Last-error behavior
// ---------------------------------------------------------------------------

/// Describes how a host thunk affects the Win32 last-error value.
///
/// Windows API functions fall into several categories regarding
/// `GetLastError` / `SetLastError`:
///
/// - **SetsOnFailure**: The thunk calls `SetLastError` with a specific code
///   when it fails. On success, last-error may or may not be modified.
/// - **SetsAlways**: The thunk always sets last-error (even on success).
/// - **Preserves**: The thunk never modifies last-error.
/// - **Unknown**: Not yet audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastErrorBehavior {
    /// Sets last-error on failure; may or may not modify on success.
    SetsOnFailure,
    /// Always sets last-error regardless of outcome.
    SetsAlways,
    /// Never modifies last-error.
    Preserves,
    /// Not yet audited — assume it may modify last-error.
    Unknown,
}

// ---------------------------------------------------------------------------
// Thunk metadata
// ---------------------------------------------------------------------------

/// Static metadata for a single host thunk.
///
/// This struct centralizes information that was previously scattered across
/// the `HostThunk::x86_arg_bytes()` match arms and dispatch code.
#[derive(Debug, Clone)]
pub struct ThunkMetadata {
    /// Human-readable API name (e.g., `"CreateFileW"`).
    pub name: &'static str,
    /// Subsystem this thunk belongs to.
    pub subsystem: Subsystem,
    /// Total size of all arguments in bytes for x86 (32-bit) calling convention.
    /// For x64, arguments are passed in registers (RCX, RDX, R8, R9) and then
    /// stack, so this is primarily used for x86 stack cleanup.
    pub x86_arg_bytes: u32,
    /// How this thunk affects `GetLastError`.
    pub last_error: LastErrorBehavior,
}

// ---------------------------------------------------------------------------
// Guest pointer helpers
// ---------------------------------------------------------------------------

/// Validate that a guest pointer range `[address, address+len)` is accessible.
///
/// Checks:
/// - `address` is non-zero (null pointer check)
/// - `address + len` does not overflow `u64`
/// - The range falls within mapped guest memory
///
/// Returns `Ok(())` if the range is valid, or an `AppError` with
/// [`ReasonCode::RcGuestPointerOutOfRange`] otherwise.
pub fn validate_guest_pointer(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> Result<(), AppError> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            "guest pointer is null",
        ));
    }
    if len == 0 {
        return Ok(());
    }
    let end = address.checked_add(len as u64).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            format!("guest pointer range overflow: {address:#x}+{len:#x}"),
        )
    })?;
    if !memory.is_range_mapped(address, len) {
        return Err(AppError::new(
            ReasonCode::RcGuestPointerOutOfRange,
            format!("guest pointer range [{address:#x}, {end:#x}) is not mapped"),
        ));
    }
    Ok(())
}

/// Read bytes from guest memory with full pointer validation.
///
/// Performs null-pointer check, overflow check, and range-mapped check before
/// reading. Returns [`ReasonCode::RcGuestPointerOutOfRange`] for invalid addresses.
pub fn read_guest_bytes_checked(
    memory: &MemoryImage,
    address: u64,
    len: usize,
) -> Result<Vec<u8>, AppError> {
    validate_guest_pointer(memory, address, len)?;
    memory.read_bytes(address, len)
}

/// Write a byte slice to guest memory with full pointer validation.
///
/// Performs null-pointer check (if `bytes` is non-empty), overflow check, and
/// range-mapped check before writing. Returns [`ReasonCode::RcGuestPointerOutOfRange`]
/// for invalid addresses.
pub fn write_guest_bytes_checked(
    memory: &mut MemoryImage,
    address: u64,
    bytes: &[u8],
) -> Result<(), AppError> {
    if bytes.is_empty() {
        return Ok(());
    }
    validate_guest_pointer(memory, address, bytes.len())?;
    memory.map_bytes(address, bytes);
    Ok(())
}

/// Read a `u16` from guest memory with pointer validation.
pub fn read_guest_u16_checked(memory: &MemoryImage, address: u64) -> Result<u16, AppError> {
    validate_guest_pointer(memory, address, 2)?;
    memory.read_u16(address)
}

/// Read a `u32` from guest memory with pointer validation.
pub fn read_guest_u32_checked(memory: &MemoryImage, address: u64) -> Result<u32, AppError> {
    validate_guest_pointer(memory, address, 4)?;
    memory.read_u32(address)
}

/// Read a `u64` from guest memory with pointer validation.
pub fn read_guest_u64_checked(memory: &MemoryImage, address: u64) -> Result<u64, AppError> {
    validate_guest_pointer(memory, address, 8)?;
    memory.read_u64(address)
}

/// Write a `u16` to guest memory with pointer validation.
pub fn write_guest_u16_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: u16,
) -> Result<(), AppError> {
    validate_guest_pointer(memory, address, 2)?;
    memory.write_u16(address, value);
    Ok(())
}

/// Write a `u32` to guest memory with pointer validation.
pub fn write_guest_u32_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: u32,
) -> Result<(), AppError> {
    validate_guest_pointer(memory, address, 4)?;
    memory.write_u32(address, value);
    Ok(())
}

/// Write a `u64` to guest memory with pointer validation.
pub fn write_guest_u64_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
) -> Result<(), AppError> {
    validate_guest_pointer(memory, address, 8)?;
    memory.write_u64(address, value);
    Ok(())
}

/// Read a UTF-16 string from guest memory with full validation.
///
/// Handles:
/// - Null pointer (returns empty string)
/// - Explicit length (reads exactly `length` code units, no null terminator required)
/// - Null-terminated (reads until null when `length < 0`)
/// - Invalid surrogate pairs (replaced with U+FFFD via `String::from_utf16_lossy`)
/// - Truncated strings (if the string crosses a page boundary, unmapped pages
///   result in an error)
///
/// # Arguments
/// * `memory` - Guest memory image
/// * `ptr` - Guest address of the UTF-16 string
/// * `length` - If >= 0, exact number of code units to read. If < 0, read until null.
/// * `max_units` - Safety cap on the number of code units to read (prevents
///   runaway reads on corrupt guest data).
pub fn read_guest_utf16_string_checked(
    memory: &MemoryImage,
    ptr: u64,
    length: i32,
    max_units: usize,
) -> Result<String, AppError> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mut units = Vec::new();
    if length >= 0 {
        let count = (length as usize).min(max_units);
        // Validate the entire range upfront
        validate_guest_pointer(memory, ptr, count * 2)?;
        for i in 0..count {
            let cu = memory.read_u16(ptr + (i as u64 * 2)).unwrap_or(0);
            units.push(cu);
        }
    } else {
        // Read until null terminator, with safety cap
        loop {
            if units.len() >= max_units {
                break;
            }
            let offset = ptr + (units.len() as u64 * 2);
            // Validate each pair before reading
            if offset.checked_add(2).is_none() {
                break;
            }
            if !memory.is_range_mapped(offset, 2) {
                return Err(AppError::new(
                    ReasonCode::RcGuestPointerOutOfRange,
                    format!(
                        "UTF-16 string read at {offset:#x} exceeds mapped memory (read {} units)",
                        units.len()
                    ),
                ));
            }
            let cu = memory.read_u16(offset).unwrap_or(0);
            if cu == 0 {
                break;
            }
            units.push(cu);
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Read a null-terminated UTF-16 string from guest memory.
///
/// Returns an empty string for null pointers. Replaces invalid surrogate
/// pairs with the replacement character. Reads up to `max_units` code units
/// as a safety cap.
pub fn read_guest_utf16_string_null_terminated(
    memory: &MemoryImage,
    ptr: u64,
    max_units: usize,
) -> Result<String, AppError> {
    read_guest_utf16_string_checked(memory, ptr, -1, max_units)
}

/// Read a sized UTF-16 buffer from guest memory.
///
/// Reads exactly `length` code units (no null terminator required).
/// Replaces invalid surrogate pairs with the replacement character.
pub fn read_guest_utf16_string_sized(
    memory: &MemoryImage,
    ptr: u64,
    length: i32,
    max_units: usize,
) -> Result<String, AppError> {
    read_guest_utf16_string_checked(memory, ptr, length, max_units)
}

/// Write a UTF-16 string to guest memory with null terminator.
///
/// Validates the target range before writing. Returns an error if the
/// target buffer is too small or unmapped.
pub fn write_guest_utf16_string_checked(
    memory: &mut MemoryImage,
    address: u64,
    value: &str,
    capacity_including_null: usize,
) -> Result<(), AppError> {
    let total_bytes = capacity_including_null * 2;
    validate_guest_pointer(memory, address, total_bytes)?;

    let mut bytes = vec![0u8; total_bytes];
    for (index, unit) in value
        .encode_utf16()
        .take(capacity_including_null.saturating_sub(1))
        .enumerate()
    {
        let offset = index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    memory.map_bytes(address, &bytes);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::MemoryImage;

    /// Helper: create a MemoryImage with a mapped region at the given address.
    fn make_memory_with_region(base: u64, size: usize) -> MemoryImage {
        let mut mem = MemoryImage::default();
        mem.map_bytes(base, &vec![0xAAu8; size]);
        mem
    }

    // ---- validate_guest_pointer tests ----

    #[test]
    fn test_validate_null_pointer_rejected() {
        let mem = MemoryImage::default();
        let err = validate_guest_pointer(&mem, 0, 4).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
        assert!(err.message.contains("null"));
    }

    #[test]
    fn test_validate_zero_length_null_rejected() {
        let mem = MemoryImage::default();
        // Null pointer is rejected even for zero-length reads (our policy is strict)
        let result = validate_guest_pointer(&mem, 0, 0);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    }

    #[test]
    fn test_validate_unmapped_pointer_rejected() {
        let mem = MemoryImage::default();
        let err = validate_guest_pointer(&mem, 0x1000, 4).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
        assert!(err.message.contains("not mapped"));
    }

    #[test]
    fn test_validate_mapped_pointer_ok() {
        let mem = make_memory_with_region(0x1000, 64);
        validate_guest_pointer(&mem, 0x1000, 4).unwrap();
        validate_guest_pointer(&mem, 0x1000, 64).unwrap();
    }

    #[test]
    fn test_validate_overflow_rejected() {
        let mem = make_memory_with_region(0x1000, 64);
        let err = validate_guest_pointer(&mem, u64::MAX, 4).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
        assert!(err.message.contains("overflow"));
    }

    #[test]
    fn test_validate_partial_unmapped_rejected() {
        let mem = make_memory_with_region(0x1000, 16);
        // Start is mapped but end extends past
        let err = validate_guest_pointer(&mem, 0x1000, 32).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    }

    // ---- read_guest_u16_checked tests ----

    #[test]
    fn test_read_u16_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x1000, &0x1234_u16.to_le_bytes());
        let val = read_guest_u16_checked(&mem, 0x1000).unwrap();
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn test_read_u16_checked_null_rejected() {
        let mem = MemoryImage::default();
        let err = read_guest_u16_checked(&mem, 0).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    }

    #[test]
    fn test_read_u16_checked_unmapped_rejected() {
        let mem = MemoryImage::default();
        let err = read_guest_u16_checked(&mem, 0xDEAD_0000).unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    }

    // ---- read_guest_u32_checked tests ----

    #[test]
    fn test_read_u32_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x2000, &0xDEADBEEF_u32.to_le_bytes());
        let val = read_guest_u32_checked(&mem, 0x2000).unwrap();
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn test_read_u32_checked_null_rejected() {
        let mem = MemoryImage::default();
        assert!(read_guest_u32_checked(&mem, 0).is_err());
    }

    // ---- read_guest_u64_checked tests ----

    #[test]
    fn test_read_u64_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x3000, &0xCAFEBABE_DEADC0DE_u64.to_le_bytes());
        let val = read_guest_u64_checked(&mem, 0x3000).unwrap();
        assert_eq!(val, 0xCAFEBABE_DEADC0DE);
    }

    #[test]
    fn test_read_u64_checked_null_rejected() {
        let mem = MemoryImage::default();
        assert!(read_guest_u64_checked(&mem, 0).is_err());
    }

    // ---- write_guest_u32_checked tests ----

    #[test]
    fn test_write_u32_checked_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x4000, &[0u8; 8]);
        write_guest_u32_checked(&mut mem, 0x4000, 0x12345678).unwrap();
        let val = read_guest_u32_checked(&mem, 0x4000).unwrap();
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_write_u32_checked_null_rejected() {
        let mut mem = MemoryImage::default();
        assert!(write_guest_u32_checked(&mut mem, 0, 42).is_err());
    }

    // ---- write_guest_u64_checked tests ----

    #[test]
    fn test_write_u64_checked_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x5000, &[0u8; 16]);
        write_guest_u64_checked(&mut mem, 0x5000, 0xAABBCCDDEEFF0011).unwrap();
        let val = read_guest_u64_checked(&mem, 0x5000).unwrap();
        assert_eq!(val, 0xAABBCCDDEEFF0011);
    }

    // ---- read/write bytes checked tests ----

    #[test]
    fn test_read_bytes_checked_null_rejected() {
        let mem = MemoryImage::default();
        assert!(read_guest_bytes_checked(&mem, 0, 4).is_err());
    }

    #[test]
    fn test_read_bytes_checked_mapped() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x1000, &[1, 2, 3, 4]);
        let bytes = read_guest_bytes_checked(&mem, 0x1000, 4).unwrap();
        assert_eq!(bytes, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_write_bytes_checked_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x6000, &[0u8; 8]);
        write_guest_bytes_checked(&mut mem, 0x6000, &[0xAA, 0xBB, 0xCC]).unwrap();
        let bytes = read_guest_bytes_checked(&mem, 0x6000, 3).unwrap();
        assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_write_bytes_checked_null_rejected() {
        let mut mem = MemoryImage::default();
        assert!(write_guest_bytes_checked(&mut mem, 0, &[1, 2, 3]).is_err());
    }

    #[test]
    fn test_write_bytes_checked_empty_ok() {
        let mut mem = MemoryImage::default();
        write_guest_bytes_checked(&mut mem, 0, &[]).unwrap();
    }

    // ---- UTF-16 string tests ----

    #[test]
    fn test_utf16_null_pointer_returns_empty() {
        let mem = MemoryImage::default();
        let s = read_guest_utf16_string_null_terminated(&mem, 0, 256).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn test_utf16_read_null_terminated() {
        let mut mem = MemoryImage::default();
        // "Hi\0" in UTF-16LE
        let data: Vec<u8> = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00]
            .iter()
            .copied()
            .collect();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_null_terminated(&mem, 0x1000, 256).unwrap();
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_utf16_read_sized() {
        let mut mem = MemoryImage::default();
        // "ABCD" in UTF-16LE (no null terminator)
        let data: Vec<u8> = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00]
            .iter()
            .copied()
            .collect();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_sized(&mem, 0x1000, 4, 256).unwrap();
        assert_eq!(s, "ABCD");
    }

    #[test]
    fn test_utf16_truncated_surrogate_pair() {
        let mut mem = MemoryImage::default();
        // High surrogate without low surrogate (U+D800)
        let data: Vec<u8> = [0x00, 0xD8, 0x00, 0x00].iter().copied().collect();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_sized(&mem, 0x1000, 2, 256).unwrap();
        // U+D800 is an unpaired surrogate → replacement character
        assert!(
            s.contains('\u{FFFD}'),
            "expected replacement char, got: {s:?}"
        );
    }

    #[test]
    fn test_utf16_invalid_surrogate_pair() {
        let mut mem = MemoryImage::default();
        // High surrogate followed by another high surrogate (invalid)
        let data: Vec<u8> = [0x00, 0xD8, 0x01, 0xD8, 0x00, 0x00]
            .iter()
            .copied()
            .collect();
        mem.map_bytes(0x1000, &data);
        let s = read_guest_utf16_string_null_terminated(&mem, 0x1000, 256).unwrap();
        // Both should be replaced
        assert!(
            s.contains('\u{FFFD}'),
            "expected replacement char for invalid surrogate pair, got: {s:?}"
        );
    }

    #[test]
    fn test_utf16_max_units_cap() {
        let mut mem = MemoryImage::default();
        // "ABCDE" in UTF-16LE with no null terminator
        let data: Vec<u8> = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00, 0x45, 0x00]
            .iter()
            .copied()
            .collect();
        mem.map_bytes(0x1000, &data);
        // Cap at 3 units even though 5 are available
        let s = read_guest_utf16_string_null_terminated(&mem, 0x1000, 3).unwrap();
        assert_eq!(s, "ABC");
    }

    #[test]
    fn test_utf16_unmapped_memory_rejected() {
        let mem = MemoryImage::default();
        let result = read_guest_utf16_string_null_terminated(&mem, 0xFFFF_0000, 256);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    }

    #[test]
    fn test_utf16_write_and_read_roundtrip() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x7000, &[0u8; 32]);
        write_guest_utf16_string_checked(&mut mem, 0x7000, "Hello", 16).unwrap();
        let s = read_guest_utf16_string_null_terminated(&mem, 0x7000, 256).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_utf16_write_truncates_to_capacity() {
        let mut mem = MemoryImage::default();
        mem.map_bytes(0x8000, &[0u8; 16]);
        // Write "Hello" into a buffer of capacity 4 (including null) → only "Hel" + null
        write_guest_utf16_string_checked(&mut mem, 0x8000, "Hello", 4).unwrap();
        let s = read_guest_utf16_string_null_terminated(&mem, 0x8000, 256).unwrap();
        assert_eq!(s, "Hel");
    }

    #[test]
    fn test_utf16_write_unmapped_rejected() {
        let mut mem = MemoryImage::default();
        let result = write_guest_utf16_string_checked(&mut mem, 0xDEAD_0000, "test", 8);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    }

    #[test]
    fn test_utf16_non_terminated_string() {
        let mut mem = MemoryImage::default();
        // Write "AB" without null terminator, followed by garbage
        let data: Vec<u8> = [0x41, 0x00, 0x42, 0x00, 0xFF, 0xFF]
            .iter()
            .copied()
            .collect();
        mem.map_bytes(0x1000, &data);
        // Read exactly 2 code units (no null terminator expected)
        let s = read_guest_utf16_string_sized(&mem, 0x1000, 2, 256).unwrap();
        assert_eq!(s, "AB");
    }

    // ---- Subsystem and metadata tests ----

    #[test]
    fn test_subsystem_equality() {
        assert_eq!(Subsystem::Kernel, Subsystem::Kernel);
        assert_ne!(Subsystem::Kernel, Subsystem::Network);
    }

    #[test]
    fn test_last_error_behavior_variants() {
        assert_ne!(
            LastErrorBehavior::SetsOnFailure,
            LastErrorBehavior::Preserves
        );
        assert_ne!(LastErrorBehavior::SetsAlways, LastErrorBehavior::Unknown);
    }

    #[test]
    fn test_thunk_metadata_fields() {
        let meta = ThunkMetadata {
            name: "TestThunk",
            subsystem: Subsystem::Kernel,
            x86_arg_bytes: 12,
            last_error: LastErrorBehavior::SetsOnFailure,
        };
        assert_eq!(meta.name, "TestThunk");
        assert_eq!(meta.subsystem, Subsystem::Kernel);
        assert_eq!(meta.x86_arg_bytes, 12);
        assert_eq!(meta.last_error, LastErrorBehavior::SetsOnFailure);
    }
}
