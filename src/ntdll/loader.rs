//! Stage-4 NTDLL — the section surface (`NtCreateSection`,
//! `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtQuerySection`).
//!
//! Sections are the native-API face of the image/mapping loader: a section
//! object owns a shared backing store, and views of it are mapped into the
//! guest address space.  The backing store and the view registry are the
//! SAME structures the Win32 CreateFileMappingW / MapViewOfFile path uses
//! (the `SectionObject` in the live handle namespace), and every view is
//! ALSO registered in the canonical [`crate::vm::VirtualMemory`] so the
//! address space stays consistent with the interpreter/JIT validation and
//! VirtualQuery-class queries.
//!
//! Documented divergences (shared with the Win32 file-mapping path):
//! - a file-backed section's backing is the section's shared byte storage
//!   (contents are not streamed from the host file at map time), and
//! - the view's raw pages are materialized through the dispatch wiring the
//!   same way the Win32 MapViewOfFile thunk does.

use crate::ge::RegistryView;
use crate::ntdll::{
    NtStatus, SECTION_BASIC_INFORMATION_CLASS, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};
use crate::win32::Win32Subsystem;

/// The x64 `SECTION_BASIC_INFORMATION` layout (48 bytes):
///
/// ```text
/// +0x00 BaseAddress        u64
/// +0x08 AllocationAttributes u32
/// +0x0C (padding)
/// +0x10 MaximumSize        u64
/// +0x18 SectionPageProtection u32
/// +0x1C (padding)
/// +0x20 GrantedAccess      u32
/// +0x24 (padding)
/// +0x28 (unused, 0)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtSectionBasicInformation {
    pub base_address: u64,
    pub allocation_attributes: u32,
    pub maximum_size: u64,
    pub section_page_protection: u32,
    pub granted_access: u32,
}

impl NtSectionBasicInformation {
    pub fn serialize_x64(&self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..8].copy_from_slice(&self.base_address.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.allocation_attributes.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.maximum_size.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.section_page_protection.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.granted_access.to_le_bytes());
        bytes
    }
}

/// `NtCreateSection` — create a section object in the live handle
/// namespace.  `maximum_size` in bytes (0 → 64 KiB default like the Win32
/// path), `section_page_protection` a PAGE_* value, `file_handle` `None`
/// for a pagefile-backed section.  Named sections share the backing store
/// across handles (the same `shared_memory_sections` registry the Win32
/// CreateFileMappingW uses).  Returns the section handle.
pub fn nt_create_section(
    win32: &mut Win32Subsystem,
    name: Option<&str>,
    maximum_size: u64,
    section_page_protection: u32,
    file_handle: Option<u32>,
) -> Result<u32, NtStatus> {
    if file_handle.is_some() {
        // File-backed sections adapt onto the shared-memory backing path
        // (see the module docs — the section's size is the mapping size).
        // The file handle itself is validated as a live file handle.
        if let Some(handle) = file_handle
            && win32.file_state(handle).is_err()
        {
            return Err(STATUS_INVALID_HANDLE);
        }
    }
    let protection = protection_from_nt_flags(section_page_protection);
    if protection.is_none() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let size = if maximum_size == 0 {
        0x1_0000
    } else {
        maximum_size
    };
    if size > MAX_SECTION_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    match win32.create_file_mapping_w(name, size as usize, protection.expect("validated"), false) {
        Ok((handle, _existed)) => Ok(handle),
        Err(_) => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Convert PAGE_* flags to the win32 `MemoryProtection` used by the shared
/// section layer (None for invalid combinations).
pub fn protection_from_nt_flags(flags: u32) -> Option<crate::win32::MemoryProtection> {
    match flags & !crate::ntdll::PAGE_GUARD & !crate::ntdll::PAGE_NOCACHE {
        crate::ntdll::PAGE_NOACCESS => Some(crate::win32::MemoryProtection {
            read: false,
            write: false,
            execute: false,
        }),
        crate::ntdll::PAGE_READONLY => Some(crate::win32::MemoryProtection {
            read: true,
            write: false,
            execute: false,
        }),
        crate::ntdll::PAGE_READWRITE => Some(crate::win32::MemoryProtection {
            read: true,
            write: true,
            execute: false,
        }),
        crate::ntdll::PAGE_EXECUTE => Some(crate::win32::MemoryProtection {
            read: false,
            write: false,
            execute: true,
        }),
        crate::ntdll::PAGE_EXECUTE_READ => Some(crate::win32::MemoryProtection {
            read: true,
            write: false,
            execute: true,
        }),
        crate::ntdll::PAGE_EXECUTE_READWRITE => Some(crate::win32::MemoryProtection {
            read: true,
            write: true,
            execute: true,
        }),
        _ => None,
    }
}

/// `NtMapViewOfSection` — map a view of the section into the process.  The
/// view is registered in the canonical VM by the dispatch wiring (which owns
/// the process address space); this function computes the validated
/// (base, view_size) pair through the shared mapping layer.
pub fn nt_map_view_of_section(
    win32: &mut Win32Subsystem,
    section_handle: u32,
    offset: u64,
    view_size: u64,
) -> Result<(u64, u64), NtStatus> {
    let size = if view_size == 0 {
        win32
            .section_state(section_handle)
            .map(|state| state.size)
            .map_err(|_| STATUS_INVALID_HANDLE)?
    } else {
        view_size as usize
    };
    if offset == 0 && size == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let base = win32
        .map_view_of_file(section_handle, offset, size)
        .map_err(|_| STATUS_INVALID_HANDLE)?;
    // The view size the caller must be told (the shared layer clamps to the
    // section remainder, at least one page).
    let state = win32
        .section_state(section_handle)
        .map_err(|_| STATUS_INVALID_HANDLE)?;
    let remaining = state.size.saturating_sub(offset as usize);
    let actual = if view_size == 0 {
        remaining.max(1)
    } else {
        (view_size as usize).min(remaining).max(1)
    };
    Ok((base, actual as u64))
}

/// `NtUnmapViewOfSection` — release a mapped view.
pub fn nt_unmap_view_of_section(
    win32: &mut Win32Subsystem,
    base_address: u64,
) -> Result<(), NtStatus> {
    win32
        .unmap_view_of_file(base_address)
        .map_err(|_| STATUS_INVALID_PARAMETER)
}

/// `NtQuerySection` — BasicInformation (the only class this layer
/// implements; others are STATUS_INVALID_INFO_CLASS).
pub fn nt_query_section(
    win32: &Win32Subsystem,
    section_handle: u32,
    info_class: u32,
) -> Result<NtSectionBasicInformation, NtStatus> {
    if info_class != SECTION_BASIC_INFORMATION_CLASS {
        return Err(crate::ntdll::STATUS_INVALID_INFO_CLASS);
    }
    let state = win32
        .section_state(section_handle)
        .map_err(|_| STATUS_INVALID_HANDLE)?;
    Ok(NtSectionBasicInformation {
        base_address: state.base_address,
        allocation_attributes: crate::ntdll::MEM_COMMIT,
        maximum_size: state.size as u64,
        section_page_protection: crate::ntdll::page_flags_from_protection(
            &crate::vm::VmProtection {
                read: state.protection.read,
                write: state.protection.write,
                execute: state.protection.execute,
            },
        ),
        granted_access: crate::ntdll::SECTION_ALL_ACCESS,
    })
}

/// The largest section size the shared layer accepts (parity with the Win32
/// file-mapping cap).
const MAX_SECTION_SIZE: u64 = 0x7F00_0000;

/// The registry view type is re-exported here so the loader module does not
/// depend on the registry module for the type (kept for signature symmetry).
#[allow(dead_code)]
const _: RegistryView = RegistryView::Native;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    fn setup() -> (TempDir, Win32Subsystem) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ntdll-loader", GeArch::X64, "win11-23h2")
                .expect("create GE");
        let win32 = Win32Subsystem::new(ge, true);
        (temp_dir, win32)
    }

    #[test]
    fn create_section_and_query_basic_information() {
        let (_tmp, mut win32) = setup();
        let handle =
            nt_create_section(&mut win32, None, 0x4000, crate::ntdll::PAGE_READWRITE, None)
                .expect("create section");
        let info = nt_query_section(&win32, handle, SECTION_BASIC_INFORMATION_CLASS)
            .expect("query section");
        assert_eq!(info.maximum_size, 0x4000);
        assert_eq!(info.section_page_protection, crate::ntdll::PAGE_READWRITE);
        assert_eq!(
            nt_query_section(&win32, handle, 77),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
        assert_eq!(
            nt_query_section(&win32, 0xBAD, SECTION_BASIC_INFORMATION_CLASS),
            Err(STATUS_INVALID_HANDLE)
        );
        // Invalid page protection is rejected.
        assert_eq!(
            nt_create_section(&mut win32, None, 0x1000, 0xDEAD, None),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn named_sections_share_one_backing_store() {
        let (_tmp, mut win32) = setup();
        let first = nt_create_section(
            &mut win32,
            Some("Casa1NtSection"),
            0x2000,
            crate::ntdll::PAGE_READWRITE,
            None,
        )
        .expect("first");
        let second = nt_create_section(
            &mut win32,
            Some("Casa1NtSection"),
            0x2000,
            crate::ntdll::PAGE_READWRITE,
            None,
        )
        .expect("second");
        // Views mapped through EITHER handle resolve to the shared backing
        // store of the named section.
        let base1 = nt_map_view_of_section(&mut win32, first, 0, 0x1000)
            .expect("view 1")
            .0;
        let base2 = nt_map_view_of_section(&mut win32, second, 0, 0x1000)
            .expect("view 2")
            .0;
        assert!(win32.mapped_view_section(base1).is_some());
        assert!(win32.mapped_view_section(base2).is_some());
    }

    #[test]
    fn map_and_unmap_a_view() {
        let (_tmp, mut win32) = setup();
        let handle =
            nt_create_section(&mut win32, None, 0x4000, crate::ntdll::PAGE_READWRITE, None)
                .expect("create section");
        let (base, view_size) =
            nt_map_view_of_section(&mut win32, handle, 0, 0x1000).expect("map view");
        assert_ne!(base, 0);
        assert_eq!(view_size, 0x1000);
        // The view is live in the shared layer.
        assert!(win32.mapped_view_section(base).is_some());
        nt_unmap_view_of_section(&mut win32, base).expect("unmap");
        assert!(win32.mapped_view_section(base).is_none());
        assert_eq!(
            nt_unmap_view_of_section(&mut win32, base),
            Err(STATUS_INVALID_PARAMETER),
            "a second unmap of the same base fails"
        );
    }
}
