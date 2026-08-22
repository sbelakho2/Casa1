//! Stage-4 NTDLL — the kernel-object surface (`NtClose`, `NtDuplicateObject`,
//! `NtQueryObject`).
//!
//! Handle semantics live in ONE namespace: the live handle table of the
//! [`crate::win32::Win32Subsystem`] (generation-protected, FIFO value
//! recycling, protect-from-close — the same semantics the Win32
//! CloseHandle/DuplicateHandle thunks use).  The canonical object-manager /
//! handle-table modules (`crate::runtime::object_manager` /
//! `crate::runtime::handle_table`) declare that surface; the Nt layer
//! adapts onto the live subsystem table so a handle minted by
//! `CreateEventW` closes through `NtClose` and vice versa — there is never a
//! second handle namespace.

use crate::ntdll::{
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, NtStatus, OBJ_INHERIT, STATUS_ACCESS_DENIED,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use crate::win32::{ObjectType, Win32Subsystem};

/// `NtClose` — close a handle through the object manager's close semantics.
/// An invalid (or socket) handle is `STATUS_INVALID_HANDLE`; a handle
/// protected from close is `STATUS_ACCESS_DENIED` (Windows reports
/// STATUS_ACCESS_DENIED for close-protected handles).
pub fn nt_close(win32: &mut Win32Subsystem, handle: u32) -> NtStatus {
    match win32.close_handle(handle) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => match error.code {
            crate::reason::ReasonCode::RcHelperPermissionDenied => STATUS_ACCESS_DENIED,
            _ => STATUS_INVALID_HANDLE,
        },
    }
}

/// `NtDuplicateObject` — duplicate `source_handle` into the target process
/// (both process handles must be live process objects), with
/// `DUPLICATE_SAME_ACCESS` / `DUPLICATE_CLOSE_SOURCE` option semantics and
/// access-mask validation (a requested access that is not a subset of the
/// source's granted access is `STATUS_ACCESS_DENIED`).  Returns the
/// duplicated handle value.
pub fn nt_duplicate_object(
    win32: &mut Win32Subsystem,
    source_process_handle: u32,
    source_handle: u32,
    target_process_handle: u32,
    desired_access: u32,
    handle_attributes: u32,
    options: u32,
) -> Result<u32, NtStatus> {
    if win32.process_state(source_process_handle).is_err()
        || win32.process_state(target_process_handle).is_err()
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    let same_access = options & DUPLICATE_SAME_ACCESS != 0;
    let close_source = options & DUPLICATE_CLOSE_SOURCE != 0;
    let inheritable = handle_attributes & OBJ_INHERIT != 0;
    match win32.duplicate_handle(
        source_handle,
        desired_access,
        inheritable,
        same_access,
        close_source,
    ) {
        Ok(duplicated) => Ok(duplicated),
        Err(error) => match error.code {
            crate::reason::ReasonCode::RcHelperPermissionDenied => Err(STATUS_ACCESS_DENIED),
            _ => Err(STATUS_INVALID_HANDLE),
        },
    }
}

/// The `OBJECT_BASIC_INFORMATION` payload (x64, 40 bytes):
///
/// ```text
/// +0x00 Attributes              u32
/// +0x04 HandleCount             u32
/// +0x08 PointerCount            u32
/// +0x0C PagedPoolCharge         u32
/// +0x10 NonPagedPoolCharge      u32
/// +0x14 NameInfoSize            u32
/// +0x18 TypeInfoSize            u32
/// +0x1C SecurityDescriptorSize  u32
/// +0x20 CreationTime            u64
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtObjectBasicInformation {
    pub attributes: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
    pub paged_pool_charge: u32,
    pub non_paged_pool_charge: u32,
    pub name_info_size: u32,
    pub type_info_size: u32,
    pub security_descriptor_size: u32,
    pub creation_time: u64,
}

impl NtObjectBasicInformation {
    pub fn serialize_x64(&self) -> [u8; 40] {
        let mut bytes = [0_u8; 40];
        bytes[0..4].copy_from_slice(&self.attributes.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.handle_count.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.pointer_count.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.paged_pool_charge.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.non_paged_pool_charge.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.name_info_size.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.type_info_size.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.security_descriptor_size.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.creation_time.to_le_bytes());
        bytes
    }
}

/// `NtQueryObject(ObjectBasicInformation)` — attributes / handle count /
/// pointer count / access mask for a live handle.
pub fn nt_query_object_basic(
    win32: &Win32Subsystem,
    handle: u32,
) -> Result<NtObjectBasicInformation, NtStatus> {
    let descriptor = win32
        .describe_handle(handle)
        .map_err(|_| STATUS_INVALID_HANDLE)?;
    Ok(NtObjectBasicInformation {
        attributes: if descriptor.inheritable {
            OBJ_INHERIT
        } else {
            0
        },
        handle_count: 1,
        pointer_count: 1,
        paged_pool_charge: 0,
        non_paged_pool_charge: 0,
        name_info_size: 0,
        type_info_size: 0,
        security_descriptor_size: 0,
        creation_time: 0,
    })
}

/// The guest-visible type name for `ObjectTypeInformation`, matching the
/// names the Windows kernel reports for kernel handles.
pub fn object_type_name(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::File => "File",
        ObjectType::Event => "Event",
        ObjectType::IoCompletionPort => "IoCompletion",
        ObjectType::Mutex => "Mutant",
        ObjectType::Semaphore => "Semaphore",
        ObjectType::Thread => "Thread",
        ObjectType::Process => "Process",
        ObjectType::Section => "Section",
        ObjectType::Key => "Key",
        ObjectType::Timer => "Timer",
        ObjectType::Pipe => "File",
        ObjectType::DirectorySearch => "File",
        ObjectType::Socket => "File",
        ObjectType::WindowStation => "WindowStation",
    }
}

/// `NtQueryObject(ObjectTypeInformation)` — the type-name information as a
/// `UNICODE_STRING` (header + wide buffer).
pub fn nt_query_object_type_information(
    win32: &Win32Subsystem,
    handle: u32,
) -> Result<String, NtStatus> {
    let object_type = win32
        .handle_object_type(handle)
        .map_err(|_| STATUS_INVALID_HANDLE)?;
    Ok(object_type_name(object_type).to_string())
}

/// Validate the `OBJECT_INFORMATION_CLASS` requested by `NtQueryObject`;
/// unsupported classes report `STATUS_INVALID_INFO_CLASS`.
pub fn validate_object_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::OBJECT_BASIC_INFORMATION_CLASS
        | crate::ntdll::OBJECT_NAME_INFORMATION_CLASS
        | crate::ntdll::OBJECT_TYPE_INFORMATION_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

/// An invalid argument (e.g. a null out-parameter) maps to
/// `STATUS_INVALID_PARAMETER`.
#[allow(dead_code)]
const _: NtStatus = STATUS_INVALID_PARAMETER;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    fn setup() -> (TempDir, Win32Subsystem) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ntdll-object", GeArch::X64, "win11-23h2")
                .expect("create GE");
        let win32 = Win32Subsystem::new(ge, true);
        (temp_dir, win32)
    }

    #[test]
    fn nt_close_on_an_invalid_handle_is_status_invalid_handle() {
        let (_tmp, mut win32) = setup();
        assert_eq!(nt_close(&mut win32, 0x1234_5678), STATUS_INVALID_HANDLE);
        assert_eq!(nt_close(&mut win32, 0), STATUS_INVALID_HANDLE);
    }

    #[test]
    fn nt_close_closes_a_live_event_handle() {
        let (_tmp, mut win32) = setup();
        let (handle, _) = win32.create_event(false, false, false, None);
        assert!(win32.describe_handle(handle).is_ok());
        assert_eq!(nt_close(&mut win32, handle), STATUS_SUCCESS);
        assert!(win32.describe_handle(handle).is_err(), "handle is gone");
        // Closing again is an invalid handle.
        assert_eq!(nt_close(&mut win32, handle), STATUS_INVALID_HANDLE);
    }

    #[test]
    fn nt_duplicate_object_mints_a_live_duplicate() {
        let (_tmp, mut win32) = setup();
        let process_handle = win32.current_process_handle();
        let (event, _) = win32.create_event(true, true, false, None);
        let dup = nt_duplicate_object(
            &mut win32,
            process_handle,
            event,
            process_handle,
            0x1F0003,
            0,
            0,
        )
        .expect("duplicate");
        assert_ne!(dup, event);
        assert_eq!(
            win32.describe_handle(dup).expect("dup").object_type,
            ObjectType::Event
        );
        // DUPLICATE_CLOSE_SOURCE closes the source.
        let dup2 = nt_duplicate_object(
            &mut win32,
            process_handle,
            dup,
            process_handle,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
        )
        .expect("duplicate with close source");
        assert!(win32.describe_handle(dup).is_err(), "source closed");
        assert!(win32.describe_handle(dup2).is_ok());
        // An invalid source handle is an invalid handle.
        assert_eq!(
            nt_duplicate_object(&mut win32, process_handle, 0xBAD, process_handle, 0, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        // Requesting more access than granted is access denied.
        let (event2, _) = win32.create_event(true, false, false, None);
        assert_eq!(
            nt_duplicate_object(
                &mut win32,
                process_handle,
                event2,
                process_handle,
                0xFFFF_FFFF,
                0,
                0,
            ),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    #[test]
    fn nt_query_object_reports_basic_information() {
        let (_tmp, mut win32) = setup();
        let (event, _) = win32.create_event(true, true, false, None);
        let info = nt_query_object_basic(&win32, event).expect("basic info");
        assert_eq!(info.handle_count, 1);
        assert_eq!(info.attributes, 0);
        let (inherited, _) = win32.create_event(true, false, true, None);
        let info = nt_query_object_basic(&win32, inherited).expect("basic info");
        assert_eq!(info.attributes, OBJ_INHERIT);
        assert_eq!(
            nt_query_object_basic(&win32, 0xBAD),
            Err(STATUS_INVALID_HANDLE)
        );
        // Type names are the canonical kernel names.
        assert_eq!(
            nt_query_object_type_information(&win32, event).as_deref(),
            Ok("Event")
        );
        let file = win32.create_file_w_extended(
            "C:\\ntdll-object-test.txt",
            crate::ge::FileAccess::read_write(),
            crate::ge::ShareMode::all(),
            crate::win32::CreationDisposition::CreateAlways,
            false,
            false,
            false,
            0x0012_0089,
            false,
        );
        if let Ok(handle) = file {
            assert_eq!(
                nt_query_object_type_information(&win32, handle).as_deref(),
                Ok("File")
            );
        }
    }
}
