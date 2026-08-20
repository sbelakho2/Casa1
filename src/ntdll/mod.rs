//! Stage-4 NTDLL foundation — the native Windows API layer.
//!
//! ONE canonical NTSTATUS type for the whole crate: every `Nt*` API in this
//! module tree returns [`NtStatus`], and the Win32 wrapper boundary is the
//! ONLY place an NTSTATUS is converted to a DOS/Win32 error
//! ([`nt_status_to_dos_error`] / [`dos_error_to_nt_status`]).
//!
//! The constants below are the canonical Windows NTSTATUS values
//! (`ntstatus.h`); they are used by the Nt* thunks dispatched from
//! `crate::runtime::dispatch::ntdll`.
//!
//! Layer contract:
//! - The `Nt*` implementations build on the canonical layers — the single
//!   [`crate::vm::VirtualMemory`], the guest-process identity model
//!   ([`crate::runtime::process`]), and the ONE live handle namespace owned
//!   by the [`crate::win32::Win32Subsystem`] (whose object manager / handle
//!   table semantics are the Stage-3 canonical surface the subsystem is
//!   being migrated onto; the Nt layer adapts onto that live table rather
//!   than minting a second handle namespace).
//! - Guest memory is accessed ONLY through the checked accessors
//!   (`guest_read_checked` / `guest_write_checked`) that never create pages.
//! - Waits route through the guest scheduler's wait-descriptor machinery
//!   (`GuestWait` / `park_for_wait`) — never host blocking.

use std::fmt;

/// The Nt* file surface (NtCreateFile).
pub mod file;
/// The Nt* section / mapping surface.
pub mod loader;
/// The Nt* virtual-memory surface.
pub mod memory;
/// The Nt* object surface (NtClose, NtDuplicateObject, NtQueryObject).
pub mod object;
/// The Nt* process-information surface.
pub mod process;
/// The Nt* registry surface.
pub mod registry;
/// The Rtl* surface.
pub mod rtl;
/// The Nt* synchronization surface.
pub mod sync;
/// The Nt* system/time surface.
pub mod system;
/// The Nt* thread surface.
pub mod thread;

/// A canonical NTSTATUS value.
///
/// NTSTATUS is a signed 32-bit value; the failure bit is bit 31
/// (`0x8000_0000`), so every failure status is negative as an `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NtStatus(pub i32);

impl NtStatus {
    /// The status code as a 32-bit unsigned value (the guest-visible form).
    pub const fn raw(self) -> u32 {
        self.0 as u32
    }

    /// True for success / informational / warning codes (bit 31 clear).
    pub const fn is_success(self) -> bool {
        self.raw() & 0x8000_0000 == 0
    }

    /// True for failure codes (bit 31 set).
    pub const fn is_error(self) -> bool {
        !self.is_success()
    }

    /// The severity code (0 = success, 1 = informational, 2 = warning,
    /// 3 = error).
    pub const fn severity(self) -> u8 {
        ((self.raw() >> 30) & 0x3) as u8
    }

    /// Convenience constructor from a raw `u32` status code.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw as i32)
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.raw())
    }
}

// ── Canonical NTSTATUS constants (values from the Windows ntstatus.h) ──────

/// STATUS_SUCCESS — 0x0000_0000.
pub const STATUS_SUCCESS: NtStatus = NtStatus(0x0000_0000u32 as i32);
/// STATUS_WAIT_0 — 0x0000_0000 (the first object satisfied a wait).
pub const STATUS_WAIT_0: NtStatus = NtStatus(0x0000_0000u32 as i32);
/// STATUS_ABANDONED_WAIT_0 — 0x0000_0080.
pub const STATUS_ABANDONED_WAIT_0: NtStatus = NtStatus(0x0000_0080u32 as i32);
/// STATUS_USER_APC — 0x0000_00C0 (an alertable wait completed via APC).
pub const STATUS_USER_APC: NtStatus = NtStatus(0x0000_00C0u32 as i32);
/// STATUS_ALREADY_COMPLETE — 0x0000_00FF.
pub const STATUS_ALREADY_COMPLETE: NtStatus = NtStatus(0x0000_00FFu32 as i32);
/// STATUS_TIMEOUT — 0x0000_0102.
pub const STATUS_TIMEOUT: NtStatus = NtStatus(0x0000_0102u32 as i32);
/// STATUS_PENDING — 0x0000_0103 (an operation is pending / thread still active).
pub const STATUS_PENDING: NtStatus = NtStatus(0x0000_0103u32 as i32);
/// STATUS_BUFFER_OVERFLOW — 0x8000_0005 (informational: the output was
/// truncated; the required size is reported in the length output).
pub const STATUS_BUFFER_OVERFLOW: NtStatus = NtStatus(0x8000_0005u32 as i32);
/// STATUS_NO_MORE_ENTRIES — 0x8000_001A.
pub const STATUS_NO_MORE_ENTRIES: NtStatus = NtStatus(0x8000_001Au32 as i32);
/// STATUS_IMAGE_ALREADY_LOADED — 0x4000_0003.
pub const STATUS_IMAGE_ALREADY_LOADED: NtStatus = NtStatus(0x4000_0003u32 as i32);
/// STATUS_INFO_LENGTH_MISMATCH — 0xC000_0004.
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = NtStatus(0xC000_0004u32 as i32);
/// STATUS_ACCESS_VIOLATION — 0xC000_0005.
pub const STATUS_ACCESS_VIOLATION: NtStatus = NtStatus(0xC000_0005u32 as i32);
/// STATUS_INVALID_HANDLE — 0xC000_0008.
pub const STATUS_INVALID_HANDLE: NtStatus = NtStatus(0xC000_0008u32 as i32);
/// STATUS_INVALID_PARAMETER — 0xC000_000D.
pub const STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xC000_000Du32 as i32);
/// STATUS_NO_SUCH_FILE — 0xC000_000F.
pub const STATUS_NO_SUCH_FILE: NtStatus = NtStatus(0xC000_000Fu32 as i32);
/// STATUS_INVALID_DEVICE_REQUEST — 0xC000_0010.
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = NtStatus(0xC000_0010u32 as i32);
/// STATUS_NO_MEMORY — 0xC000_0017.
pub const STATUS_NO_MEMORY: NtStatus = NtStatus(0xC000_0017u32 as i32);
/// STATUS_CONFLICTING_ADDRESSES — 0xC000_0018 (the requested range overlaps
/// an existing reservation).
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = NtStatus(0xC000_0018u32 as i32);
/// STATUS_ACCESS_DENIED — 0xC000_0022.
pub const STATUS_ACCESS_DENIED: NtStatus = NtStatus(0xC000_0022u32 as i32);
/// STATUS_BUFFER_TOO_SMALL — 0xC000_0023.
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = NtStatus(0xC000_0023u32 as i32);
/// STATUS_OBJECT_TYPE_MISMATCH — 0xC000_0030.
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = NtStatus(0xC000_0030u32 as i32);
/// STATUS_OBJECT_NAME_INVALID — 0xC000_0033.
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = NtStatus(0xC000_0033u32 as i32);
/// STATUS_OBJECT_NAME_NOT_FOUND — 0xC000_0034.
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xC000_0034u32 as i32);
/// STATUS_OBJECT_NAME_COLLISION — 0xC000_0035.
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xC000_0035u32 as i32);
/// STATUS_OBJECT_PATH_NOT_FOUND — 0xC000_003A.
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xC000_003Au32 as i32);
/// STATUS_SHARING_VIOLATION — 0xC000_0043.
pub const STATUS_SHARING_VIOLATION: NtStatus = NtStatus(0xC000_0043u32 as i32);
/// STATUS_LOCK_NOT_SUPPORTED — 0xC000_0049.
pub const STATUS_LOCK_NOT_SUPPORTED: NtStatus = NtStatus(0xC000_0049u32 as i32);
/// STATUS_THREAD_IS_TERMINATING — 0xC000_004A.
pub const STATUS_THREAD_IS_TERMINATING: NtStatus = NtStatus(0xC000_004Au32 as i32);
/// STATUS_LOCK_VIOLATION — 0xC000_004B.
pub const STATUS_LOCK_VIOLATION: NtStatus = NtStatus(0xC000_004Bu32 as i32);
/// STATUS_DELETE_PENDING — 0xC000_0056.
pub const STATUS_DELETE_PENDING: NtStatus = NtStatus(0xC000_0056u32 as i32);
/// STATUS_PRIVILEGE_NOT_HELD — 0xC000_0061.
pub const STATUS_PRIVILEGE_NOT_HELD: NtStatus = NtStatus(0xC000_0061u32 as i32);
/// STATUS_INVALID_IMAGE_FORMAT — 0xC000_007B.
pub const STATUS_INVALID_IMAGE_FORMAT: NtStatus = NtStatus(0xC000_007Bu32 as i32);
/// STATUS_PROCESS_IS_TERMINATING — 0xC000_010A.
pub const STATUS_PROCESS_IS_TERMINATING: NtStatus = NtStatus(0xC000_010Au32 as i32);
/// STATUS_CANNOT_DELETE — 0xC000_0121.
pub const STATUS_CANNOT_DELETE: NtStatus = NtStatus(0xC000_0121u32 as i32);
/// STATUS_DLL_NOT_FOUND — 0xC000_0135.
pub const STATUS_DLL_NOT_FOUND: NtStatus = NtStatus(0xC000_0135u32 as i32);
/// STATUS_ENTRYPOINT_NOT_FOUND — 0xC000_0139.
pub const STATUS_ENTRYPOINT_NOT_FOUND: NtStatus = NtStatus(0xC000_0139u32 as i32);
/// STATUS_NOT_SUPPORTED — 0xC000_00BB.
pub const STATUS_NOT_SUPPORTED: NtStatus = NtStatus(0xC000_00BBu32 as i32);
/// STATUS_INVALID_INFO_CLASS — 0xC000_0003.
pub const STATUS_INVALID_INFO_CLASS: NtStatus = NtStatus(0xC000_0003u32 as i32);

/// Convert an NTSTATUS to the Win32 DOS error code, using the canonical
/// mapping in [`crate::error::ntstatus_to_dos_error`].  This is the ONLY
/// place an NTSTATUS crosses into the Win32 error domain; the Nt* layer
/// itself returns [`NtStatus`] exclusively.
pub fn nt_status_to_dos_error(status: NtStatus) -> u32 {
    crate::error::ntstatus_to_dos_error(status.raw())
}

/// Convert a Win32 DOS error code to the canonical NTSTATUS.  The subset
/// covers the errors the Nt* layer and its Win32 wrappers actually produce;
/// unknown codes map to STATUS_UNSUCCESSFUL (0xC0000001).
pub fn dos_error_to_nt_status(error: u32) -> NtStatus {
    match error {
        0 => STATUS_SUCCESS,                  // ERROR_SUCCESS
        2 => STATUS_OBJECT_NAME_NOT_FOUND,    // ERROR_FILE_NOT_FOUND
        3 => STATUS_OBJECT_PATH_NOT_FOUND,    // ERROR_PATH_NOT_FOUND
        5 => STATUS_ACCESS_DENIED,            // ERROR_ACCESS_DENIED
        6 => STATUS_INVALID_HANDLE,           // ERROR_INVALID_HANDLE
        8 | 14 => STATUS_NO_MEMORY,           // ERROR_NOT_ENOUGH_MEMORY / ERROR_OUTOFMEMORY
        32 => STATUS_SHARING_VIOLATION,       // ERROR_SHARING_VIOLATION
        33 => STATUS_LOCK_VIOLATION,          // ERROR_LOCK_VIOLATION
        50 => STATUS_NOT_SUPPORTED,           // ERROR_NOT_SUPPORTED
        87 => STATUS_INVALID_PARAMETER,       // ERROR_INVALID_PARAMETER
        122 => STATUS_BUFFER_TOO_SMALL,       // ERROR_INSUFFICIENT_BUFFER
        123 => STATUS_OBJECT_NAME_INVALID,    // ERROR_INVALID_NAME
        126 => STATUS_DLL_NOT_FOUND,          // ERROR_MOD_NOT_FOUND
        127 => STATUS_ENTRYPOINT_NOT_FOUND,   // ERROR_PROC_NOT_FOUND
        183 => STATUS_OBJECT_NAME_COLLISION,  // ERROR_ALREADY_EXISTS
        234 => STATUS_BUFFER_OVERFLOW,        // ERROR_MORE_DATA
        259 => STATUS_NO_MORE_ENTRIES,        // ERROR_NO_MORE_ITEMS
        998 => STATUS_ACCESS_VIOLATION,       // ERROR_NOACCESS
        1460 => STATUS_TIMEOUT,               // ERROR_TIMEOUT
        _ => NtStatus(0xC000_0001u32 as i32), // STATUS_UNSUCCESSFUL
    }
}

// ── Shared NT constants used by the Nt* modules ─────────────────────────────

// Memory allocation types (ntddk.h / winnt.h).
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_DECOMMIT: u32 = 0x4000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_TOP_DOWN: u32 = 0x100000;
pub const MEM_WRITE_WATCH: u32 = 0x200000;

// Page protections (winnt.h PAGE_*).
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;

/// Convert PAGE_* flags to the canonical [`crate::vm::VmProtection`]
/// (guard pages are reported through the VM's guard flag).
pub fn protection_from_page_flags(flags: u32) -> crate::vm::VmProtection {
    match flags & !PAGE_GUARD & !PAGE_NOCACHE {
        PAGE_NOACCESS => crate::vm::VmProtection::NONE,
        PAGE_READONLY => crate::vm::VmProtection::READ,
        PAGE_READWRITE | PAGE_WRITECOPY => crate::vm::VmProtection::READ_WRITE,
        PAGE_EXECUTE => crate::vm::VmProtection {
            read: false,
            write: false,
            execute: true,
        },
        PAGE_EXECUTE_READ => crate::vm::VmProtection::READ_EXECUTE,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => {
            crate::vm::VmProtection::READ_WRITE_EXECUTE
        }
        _ => crate::vm::VmProtection::NONE,
    }
}

/// Convert a canonical [`crate::vm::VmProtection`] back to PAGE_* flags.
pub fn page_flags_from_protection(protection: &crate::vm::VmProtection) -> u32 {
    match (protection.read, protection.write, protection.execute) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (true, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (false, true, false) => PAGE_READWRITE,
        (false, true, true) => PAGE_EXECUTE_READWRITE,
    }
}

// Memory state (MEMORY_BASIC_INFORMATION.State).
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_RESERVE_STATE: u32 = 0x2000;
pub const MEM_COMMIT_STATE: u32 = 0x1000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_IMAGE: u32 = 0x1000000;
pub const MEM_MAPPED: u32 = 0x40000;

// Wait-status values shared by the Nt wait APIs and the scheduler resume.
pub const WAIT_OBJECT_0: u32 = 0x0000_0000;
pub const WAIT_ABANDONED: u32 = 0x0000_0080;
pub const WAIT_IO_COMPLETION: u32 = 0x0000_00C0;
pub const WAIT_TIMEOUT: u32 = 0x0000_0102;

// EVENT_INFORMATION_CLASS (NtQueryEvent) — not used yet; EVENT_TYPE values:
pub const EVENT_TYPE_NOTIFICATION: u32 = 0;
pub const EVENT_TYPE_SYNCHRONIZATION: u32 = 1;

// Object attributes flags (ntdef.h OBJ_*).
pub const OBJ_INHERIT: u32 = 0x0000_0002;
pub const OBJ_PERMANENT: u32 = 0x0000_0010;
pub const OBJ_EXCLUSIVE: u32 = 0x0000_0020;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
pub const OBJ_OPENIF: u32 = 0x0000_0080;
pub const OBJ_OPENLINK: u32 = 0x0000_0100;
pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

// NtDuplicateObject options.
pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
pub const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

// NtCreateFile disposition (FILE_* from ntddk.h).
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

// NtCreateFile create options.
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
pub const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_CREATE_TREE_CONNECTION: u32 = 0x0000_0080;
pub const FILE_COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
pub const FILE_NO_EA_KNOWLEDGE: u32 = 0x0000_0200;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
pub const FILE_OPEN_BY_FILE_ID: u32 = 0x0000_2000;
pub const FILE_RANDOM_ACCESS: u32 = 0x0000_0800;
pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;

// Generic access rights (ntdef.h GENERIC_*).
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;

// Registry access rights (KEY_*).
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_NOTIFY: u32 = 0x0010;
pub const KEY_CREATE_LINK: u32 = 0x0020;
pub const KEY_WOW64_64KEY: u32 = 0x0100;
pub const KEY_WOW64_32KEY: u32 = 0x0200;
pub const KEY_READ: u32 = 0x0002_0019;
pub const KEY_WRITE: u32 = 0x0002_0006;
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;

// REG_* value types (winnt.h).
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_LITTLE_ENDIAN: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;
pub const REG_QWORD_LITTLE_ENDIAN: u32 = 11;

// KEY_INFORMATION_CLASS (NtQueryKey).
pub const KEY_BASIC_INFORMATION_CLASS: u32 = 0;
pub const KEY_NODE_INFORMATION_CLASS: u32 = 1;
pub const KEY_FULL_INFORMATION_CLASS: u32 = 2;
pub const KEY_NAME_INFORMATION_CLASS: u32 = 3;
pub const KEY_CACHED_INFORMATION_CLASS: u32 = 4;
pub const KEY_FLAGS_INFORMATION_CLASS: u32 = 5;

// KEY_VALUE_INFORMATION_CLASS (NtQueryValueKey).
pub const KEY_VALUE_BASIC_INFORMATION_CLASS: u32 = 0;
pub const KEY_VALUE_FULL_INFORMATION_CLASS: u32 = 1;
pub const KEY_VALUE_PARTIAL_INFORMATION_CLASS: u32 = 2;
pub const KEY_VALUE_PARTIAL_INFORMATION_ALIGN64_CLASS: u32 = 3;

// SECTION_INHERIT (NtMapViewOfSection).
pub const SECTION_INHERIT_VIEW_SHARE: u32 = 1;
pub const SECTION_INHERIT_VIEWS_ALWAYS: u32 = 2;

// SECTION_INFORMATION_CLASS (NtQuerySection).
pub const SECTION_BASIC_INFORMATION_CLASS: u32 = 0;
pub const SECTION_IMAGE_INFORMATION_CLASS: u32 = 1;
pub const SECTION_RELOCATION_INFORMATION_CLASS: u32 = 2;
pub const SECTION_ORIGINAL_BASE_INFORMATION_CLASS: u32 = 3;

// SECTION_* access rights.
pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_EXTEND_SIZE: u32 = 0x0010;
pub const SECTION_ALL_ACCESS: u32 = 0x000F_001F;

// PROCESSINFOCLASS (NtQueryInformationProcess).
pub const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
pub const PROCESS_DEBUG_PORT_CLASS: u32 = 7;
pub const PROCESS_IMAGE_FILE_NAME_CLASS: u32 = 30;
pub const PROCESS_PROCESS_TIMES_CLASS: u32 = 4;
pub const PROCESS_PROTECTION_INFORMATION_CLASS: u32 = 38;
pub const PROCESS_MITIGATION_POLICY_CLASS: u32 = 52;

// THREADINFOCLASS (NtQueryInformationThread / NtSetInformationThread).
pub const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;
pub const THREAD_TIMES_CLASS: u32 = 1;
pub const THREAD_AFFINITY_MASK_CLASS: u32 = 3;
pub const THREAD_PRIORITY_CLASS: u32 = 16;
pub const THREAD_BASE_PRIORITY_CLASS: u32 = 17;

// SYSTEM_INFORMATION_CLASS (NtQuerySystemInformation).
pub const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
pub const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_CLASS: u32 = 8;
pub const SYSTEM_TIME_OF_DAY_INFORMATION_CLASS: u32 = 3;
pub const SYSTEM_PERFORMANCE_INFORMATION_CLASS: u32 = 2;

// OBJECT_INFORMATION_CLASS (NtQueryObject).
pub const OBJECT_BASIC_INFORMATION_CLASS: u32 = 0;
pub const OBJECT_NAME_INFORMATION_CLASS: u32 = 1;
pub const OBJECT_TYPE_INFORMATION_CLASS: u32 = 2;

// PROCESS_INFORMATION_CLASS helpers are consumed by the runtime dispatch
// layer; the x64 structure layouts live in the module that serializes them.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_status_values_match_ntstatus_dot_h() {
        // The values the task layer depends on, pinned against the real
        // Windows ntstatus.h constants.
        assert_eq!(STATUS_SUCCESS.raw(), 0x0000_0000);
        assert_eq!(STATUS_PENDING.raw(), 0x0000_0103);
        assert_eq!(STATUS_TIMEOUT.raw(), 0x0000_0102);
        assert_eq!(STATUS_ALREADY_COMPLETE.raw(), 0x0000_00FF);
        assert_eq!(STATUS_INFO_LENGTH_MISMATCH.raw(), 0xC000_0004);
        assert_eq!(STATUS_ACCESS_VIOLATION.raw(), 0xC000_0005);
        assert_eq!(STATUS_INVALID_HANDLE.raw(), 0xC000_0008);
        assert_eq!(STATUS_INVALID_PARAMETER.raw(), 0xC000_000D);
        assert_eq!(STATUS_INVALID_DEVICE_REQUEST.raw(), 0xC000_0010);
        assert_eq!(STATUS_ACCESS_DENIED.raw(), 0xC000_0022);
        assert_eq!(STATUS_BUFFER_TOO_SMALL.raw(), 0xC000_0023);
        assert_eq!(STATUS_OBJECT_NAME_NOT_FOUND.raw(), 0xC000_0034);
        assert_eq!(STATUS_OBJECT_NAME_COLLISION.raw(), 0xC000_0035);
        assert_eq!(STATUS_OBJECT_PATH_NOT_FOUND.raw(), 0xC000_003A);
        assert_eq!(STATUS_SHARING_VIOLATION.raw(), 0xC000_0043);
        assert_eq!(STATUS_LOCK_NOT_SUPPORTED.raw(), 0xC000_0049);
        assert_eq!(STATUS_THREAD_IS_TERMINATING.raw(), 0xC000_004A);
        assert_eq!(STATUS_LOCK_VIOLATION.raw(), 0xC000_004B);
        assert_eq!(STATUS_DELETE_PENDING.raw(), 0xC000_0056);
        assert_eq!(STATUS_PRIVILEGE_NOT_HELD.raw(), 0xC000_0061);
        assert_eq!(STATUS_INVALID_IMAGE_FORMAT.raw(), 0xC000_007B);
        assert_eq!(STATUS_PROCESS_IS_TERMINATING.raw(), 0xC000_010A);
        assert_eq!(STATUS_CANNOT_DELETE.raw(), 0xC000_0121);
        assert_eq!(STATUS_DLL_NOT_FOUND.raw(), 0xC000_0135);
        assert_eq!(STATUS_ENTRYPOINT_NOT_FOUND.raw(), 0xC000_0139);
        assert_eq!(STATUS_IMAGE_ALREADY_LOADED.raw(), 0x4000_0003);
    }

    #[test]
    fn status_helpers_classify_severity() {
        assert!(STATUS_SUCCESS.is_success());
        assert!(STATUS_PENDING.is_success());
        assert!(STATUS_ACCESS_VIOLATION.is_error());
        assert_eq!(STATUS_ACCESS_VIOLATION.severity(), 3);
        assert_eq!(STATUS_IMAGE_ALREADY_LOADED.severity(), 1);
        assert_eq!(STATUS_SUCCESS.raw(), STATUS_SUCCESS.0 as u32);
        assert_eq!(NtStatus::from_raw(0xC000_000D), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn nt_status_to_dos_error_maps_known_values() {
        assert_eq!(nt_status_to_dos_error(STATUS_SUCCESS), 0);
        assert_eq!(nt_status_to_dos_error(STATUS_INVALID_HANDLE), 6);
        assert_eq!(nt_status_to_dos_error(STATUS_ACCESS_DENIED), 5);
        assert_eq!(nt_status_to_dos_error(STATUS_INVALID_PARAMETER), 87);
        assert_eq!(nt_status_to_dos_error(STATUS_ACCESS_VIOLATION), 998);
        assert_eq!(nt_status_to_dos_error(STATUS_OBJECT_NAME_NOT_FOUND), 2);
        assert_eq!(nt_status_to_dos_error(STATUS_SHARING_VIOLATION), 32);
    }

    #[test]
    fn dos_error_to_nt_status_round_trips_known_values() {
        assert_eq!(dos_error_to_nt_status(0), STATUS_SUCCESS);
        assert_eq!(dos_error_to_nt_status(6), STATUS_INVALID_HANDLE);
        assert_eq!(dos_error_to_nt_status(5), STATUS_ACCESS_DENIED);
        assert_eq!(dos_error_to_nt_status(87), STATUS_INVALID_PARAMETER);
        assert_eq!(dos_error_to_nt_status(122), STATUS_BUFFER_TOO_SMALL);
        assert_eq!(dos_error_to_nt_status(1460), STATUS_TIMEOUT);
        // The canonical round trip through error.rs agrees on both legs.
        assert_eq!(
            nt_status_to_dos_error(dos_error_to_nt_status(32)),
            32,
            "STATUS_SHARING_VIOLATION must map back to ERROR_SHARING_VIOLATION"
        );
        // Unknown Win32 errors fall back to STATUS_UNSUCCESSFUL.
        assert_eq!(dos_error_to_nt_status(0xDEAD).0 as u32, 0xC000_0001);
    }

    #[test]
    fn page_flags_round_trip_through_canonical_protection() {
        for flags in [
            PAGE_NOACCESS,
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
        ] {
            let protection = protection_from_page_flags(flags);
            assert_eq!(
                page_flags_from_protection(&protection),
                flags,
                "page flags 0x{flags:x} must round trip"
            );
        }
        // Guard / nocache bits are stripped before conversion.
        assert_eq!(
            protection_from_page_flags(PAGE_READWRITE | PAGE_GUARD),
            crate::vm::VmProtection::READ_WRITE
        );
    }
}
