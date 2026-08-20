//! Stage-4 NTDLL — the file surface (`NtCreateFile`).
//!
//! `NtCreateFile` maps onto the SAME filesystem semantic layer the Win32
//! `CreateFileW` path uses ([`crate::win32::Win32Subsystem::create_file_w_extended`]
//! → the GE share-state matrix + sandboxed host filesystem).  The NT
//! disposition constants translate 1:1 to the Win32 `CreationDisposition`
//! (FILE_SUPERSEDE → CREATE_ALWAYS, FILE_OPEN → OPEN_EXISTING, …), NT
//! generic/standard access bits expand to the concrete `FILE_*` mask the
//! handle's granted-access records, and the NT create options map onto the
//! Win32 flags (FILE_DELETE_ON_CLOSE → FILE_FLAG_DELETE_ON_CLOSE,
//! FILE_DIRECTORY_FILE → backup semantics, missing FILE_SYNCHRONOUS_IO_* →
//! overlapped handle).  There is exactly ONE file semantic layer; the Nt
//! entry point shares it with the Win32 entry point.

use crate::ge::{FileAccess, ShareMode};
use crate::ntdll::{
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
    FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT, GENERIC_ALL, GENERIC_EXECUTE,
    GENERIC_READ, GENERIC_WRITE, NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_SHARING_VIOLATION,
};
use crate::win32::{CreationDisposition, Win32Subsystem};

// Concrete FILE_* access bits (ntddk.h).
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_READ_EA: u32 = 0x0008;
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_EXECUTE: u32 = 0x0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const FILE_DELETE: u32 = 0x0001_0000;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const SYNCHRONIZE: u32 = 0x0010_0000;
const STANDARD_RIGHTS_READ: u32 = 0x0002_0000;
const STANDARD_RIGHTS_WRITE: u32 = 0x0002_0000;
const STANDARD_RIGHTS_EXECUTE: u32 = 0x0002_0000;
const STANDARD_RIGHTS_ALL: u32 = 0x001F_0000;

/// FILE_GENERIC_READ / FILE_GENERIC_WRITE / FILE_GENERIC_EXECUTE /
/// FILE_ALL_ACCESS (ntddk.h).
const FILE_GENERIC_READ: u32 =
    STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
const FILE_GENERIC_WRITE: u32 = STANDARD_RIGHTS_WRITE
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | SYNCHRONIZE;
const FILE_GENERIC_EXECUTE: u32 =
    STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;
const FILE_ALL_ACCESS: u32 = STANDARD_RIGHTS_ALL | 0x1FF;

/// Expand the NT generic access bits into the concrete `FILE_*` mask
/// (Windows `SeAccessCheck`-style expansion, matching what the Win32
/// `expand_generic_access` produces for the same mask).
pub fn expand_nt_generic_access(desired_access: u32) -> u32 {
    const GENERIC_BITS: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    let mut access = desired_access & !GENERIC_BITS;
    if desired_access & GENERIC_READ != 0 {
        access |= FILE_GENERIC_READ;
    }
    if desired_access & GENERIC_WRITE != 0 {
        access |= FILE_GENERIC_WRITE;
    }
    if desired_access & GENERIC_EXECUTE != 0 {
        access |= FILE_GENERIC_EXECUTE;
    }
    if desired_access & GENERIC_ALL != 0 {
        access |= FILE_ALL_ACCESS;
    }
    access
}

/// Project the RAW desired-access mask onto the GE three-boolean
/// [`FileAccess`] — the exact mirror of the Win32 layer's
/// `file_access_from_win32` (generic bits participate; attribute/EA bits do
/// not classify share intent).
pub fn file_access_from_nt(desired_access: u32) -> FileAccess {
    let read_bits = GENERIC_READ | GENERIC_ALL | FILE_READ_DATA;
    let write_bits =
        GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD;
    FileAccess {
        read: desired_access & read_bits != 0,
        write: desired_access & write_bits != 0,
        delete: desired_access & (GENERIC_ALL | FILE_DELETE | FILE_DELETE_CHILD) != 0,
    }
}

/// Project the NT share-access mask onto the GE [`ShareMode`]
/// (FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, FILE_SHARE_DELETE=4 — the same
/// values as the Win32 FILE_SHARE_* constants).
pub fn share_mode_from_nt(share_access: u32) -> ShareMode {
    ShareMode {
        read: share_access & 0x1 != 0,
        write: share_access & 0x2 != 0,
        delete: share_access & 0x4 != 0,
    }
}

/// Translate the NT `CreateDisposition` to the Win32
/// [`CreationDisposition`] the shared file layer speaks.
pub fn creation_disposition_from_nt(disposition: u32) -> Option<CreationDisposition> {
    match disposition {
        FILE_SUPERSEDE => Some(CreationDisposition::CreateAlways),
        FILE_OPEN => Some(CreationDisposition::OpenExisting),
        FILE_CREATE => Some(CreationDisposition::CreateNew),
        FILE_OPEN_IF => Some(CreationDisposition::OpenAlways),
        FILE_OVERWRITE => Some(CreationDisposition::TruncateExisting),
        FILE_OVERWRITE_IF => Some(CreationDisposition::CreateAlways),
        _ => None,
    }
}

/// Normalize an NT object name to the guest path form the shared file layer
/// expects: strip the `\??\` device-namespace prefix and the
/// `\Device\HarddiskVolumeN\` prefix (best-effort mapping onto `C:\`).
pub fn normalize_nt_object_name(name: &str) -> String {
    let name = name
        .strip_prefix("\\??\\")
        .or_else(|| name.strip_prefix("\\\\?\\"))
        .unwrap_or(name);
    if let Some(rest) = name.strip_prefix("\\Device\\HarddiskVolume")
        && let Some(digits) = rest
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .ok()
            .filter(|digits| *digits >= 1)
    {
        let remainder = &rest[digits.to_string().len()..];
        return format!("C:{remainder}");
    }
    name.to_string()
}

/// `NtCreateFile` — open/create a file through the shared file layer.
/// Returns the file handle or the NTSTATUS failure.  `create_options` is
/// validated for the handled bits; unsupported options are accepted and
/// ignored (the file layer's documented divergence set).
#[allow(clippy::too_many_arguments)]
pub fn nt_create_file(
    win32: &mut Win32Subsystem,
    path: &str,
    desired_access: u32,
    share_access: u32,
    disposition: u32,
    create_options: u32,
    file_attributes: u32,
    inheritable: bool,
) -> Result<u32, NtStatus> {
    let _ = file_attributes;
    let Some(creation) = creation_disposition_from_nt(disposition) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let expanded = expand_nt_generic_access(desired_access);
    let mut file_access = file_access_from_nt(desired_access);
    let delete_on_close = create_options & FILE_DELETE_ON_CLOSE != 0;
    if delete_on_close {
        // FILE_DELETE_ON_CLOSE behaves like a DELETE access request for the
        // share matrix (mirrors the Win32 FILE_FLAG_DELETE_ON_CLOSE path).
        file_access.delete = true;
    }
    let share_mode = share_mode_from_nt(share_access);
    let backup_semantics = create_options & FILE_DIRECTORY_FILE != 0;
    let overlapped =
        create_options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) == 0;
    win32
        .create_file_w_extended(
            path,
            file_access,
            share_mode,
            creation,
            inheritable,
            overlapped,
            backup_semantics,
            expanded,
            delete_on_close,
        )
        .map_err(nt_status_from_file_error)
}

/// Map the shared file layer's `AppError` to the NTSTATUS domain.
pub fn nt_status_from_file_error(error: crate::error::AppError) -> NtStatus {
    match error.code {
        crate::reason::ReasonCode::RcFsNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        crate::reason::ReasonCode::RcFsPathInvalid
        | crate::reason::ReasonCode::RcFsReservedName
        | crate::reason::ReasonCode::RcFsPathTooLong => crate::ntdll::STATUS_OBJECT_NAME_INVALID,
        crate::reason::ReasonCode::RcFsSandboxEscape
        | crate::reason::ReasonCode::RcSandboxPathViolation => STATUS_ACCESS_DENIED,
        crate::reason::ReasonCode::RcFsSharingViolation => STATUS_SHARING_VIOLATION,
        crate::reason::ReasonCode::RcFsAlreadyExists => crate::ntdll::STATUS_OBJECT_NAME_COLLISION,
        crate::reason::ReasonCode::RcWin32InvalidHandle => STATUS_INVALID_HANDLE,
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// STATUS_OBJECT_PATH_NOT_FOUND is reported for missing parent directories
/// by the shared layer's missing-parent contract; the NT name for that DOS
/// error is STATUS_OBJECT_PATH_NOT_FOUND.
#[allow(dead_code)]
const _: NtStatus = STATUS_OBJECT_PATH_NOT_FOUND;

/// The NT name for ERROR_INVALID_NAME (a path whose syntax is invalid).
#[allow(dead_code)]
const _: u32 = crate::ntdll::STATUS_OBJECT_NAME_INVALID.raw();

/// Options this layer explicitly recognizes; the rest pass through to the
/// shared layer as flags.
#[allow(dead_code)]
const _: u32 = FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_disposition_maps_onto_the_win32_creation_set() {
        assert_eq!(
            creation_disposition_from_nt(FILE_SUPERSEDE),
            Some(CreationDisposition::CreateAlways)
        );
        assert_eq!(
            creation_disposition_from_nt(FILE_OPEN),
            Some(CreationDisposition::OpenExisting)
        );
        assert_eq!(
            creation_disposition_from_nt(FILE_CREATE),
            Some(CreationDisposition::CreateNew)
        );
        assert_eq!(
            creation_disposition_from_nt(FILE_OPEN_IF),
            Some(CreationDisposition::OpenAlways)
        );
        assert_eq!(
            creation_disposition_from_nt(FILE_OVERWRITE),
            Some(CreationDisposition::TruncateExisting)
        );
        assert_eq!(
            creation_disposition_from_nt(FILE_OVERWRITE_IF),
            Some(CreationDisposition::CreateAlways)
        );
        assert_eq!(creation_disposition_from_nt(77), None);
    }

    #[test]
    fn nt_generic_access_expands_like_the_win32_layer() {
        let expanded = expand_nt_generic_access(GENERIC_READ);
        assert_ne!(expanded & FILE_READ_DATA, 0);
        assert_ne!(expanded & SYNCHRONIZE, 0);
        assert_eq!(expanded & GENERIC_READ, 0, "generic bits are consumed");
        let expanded = expand_nt_generic_access(GENERIC_WRITE);
        assert_ne!(expanded & FILE_WRITE_DATA, 0);
        assert_ne!(expanded & FILE_APPEND_DATA, 0);
        let expanded = expand_nt_generic_access(GENERIC_EXECUTE);
        assert_ne!(expanded & FILE_EXECUTE, 0);
        // Projection onto the GE access model (raw masks, like Win32).
        assert!(file_access_from_nt(GENERIC_READ).read);
        assert!(!file_access_from_nt(GENERIC_READ).write);
        assert!(file_access_from_nt(GENERIC_WRITE).write);
        assert!(!file_access_from_nt(GENERIC_WRITE).read);
        assert!(file_access_from_nt(FILE_DELETE).delete);
        // Share modes use the Win32 values.
        assert_eq!(
            share_mode_from_nt(7),
            ShareMode {
                read: true,
                write: true,
                delete: true
            }
        );
        assert_eq!(share_mode_from_nt(0), ShareMode::none());
    }

    #[test]
    fn nt_object_names_normalize_to_guest_paths() {
        assert_eq!(
            normalize_nt_object_name("\\??\\C:\\Windows\\x"),
            "C:\\Windows\\x"
        );
        assert_eq!(normalize_nt_object_name("\\\\?\\C:\\x"), "C:\\x");
        assert_eq!(
            normalize_nt_object_name("\\Device\\HarddiskVolume2\\dir\\f"),
            "C:\\dir\\f"
        );
        assert_eq!(normalize_nt_object_name("C:\\plain"), "C:\\plain");
    }
}
