//! Stage-4 NTDLL — the process-information surface
//! (`NtQueryInformationProcess`).
//!
//! The information classes serialize the canonical guest-process identity:
//! the GUEST pid from the canonical guest-PID namespace
//! ([`crate::runtime::process::allocate_guest_pid`]) — never the host's
//! POSIX pid — the guest PEB base, the configured affinity and the process
//! exit status (STATUS_PENDING while running).  The dispatch wiring owns
//! the live values; this module owns the x64/x86 structure layouts and the
//! class contract.

use crate::ntdll::NtStatus;

/// `PROCESS_BASIC_INFORMATION` (x64, 48 bytes):
///
/// ```text
/// +0x00 ExitStatus                i32 (NTSTATUS)
/// +0x04 (padding)
/// +0x08 PebBaseAddress            ptr
/// +0x10 AffinityMask              ptr
/// +0x18 BasePriority              i32
/// +0x1C (padding)
/// +0x20 UniqueProcessId           ptr
/// +0x28 InheritedFromUniqueProcessId ptr
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtProcessBasicInformation {
    pub exit_status: u32,
    pub peb_base_address: u64,
    pub affinity_mask: u64,
    pub base_priority: i32,
    pub unique_process_id: u64,
    pub inherited_from_unique_process_id: u64,
}

pub const PROCESS_BASIC_INFORMATION64_SIZE: u64 = 48;
pub const PROCESS_BASIC_INFORMATION32_SIZE: u64 = 24;

impl NtProcessBasicInformation {
    pub fn serialize_x64(&self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..4].copy_from_slice(&self.exit_status.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.peb_base_address.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.affinity_mask.to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.base_priority as u32).to_le_bytes());
        bytes[32..40].copy_from_slice(&self.unique_process_id.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.inherited_from_unique_process_id.to_le_bytes());
        bytes
    }

    /// x86 `PROCESS_BASIC_INFORMATION` (24 bytes): every field 4 bytes.
    pub fn serialize_x86(&self) -> [u8; 24] {
        let mut bytes = [0_u8; 24];
        bytes[0..4].copy_from_slice(&self.exit_status.to_le_bytes());
        bytes[4..8].copy_from_slice(&(self.peb_base_address as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(self.affinity_mask as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(self.base_priority as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&(self.unique_process_id as u32).to_le_bytes());
        bytes[20..24]
            .copy_from_slice(&(self.inherited_from_unique_process_id as u32).to_le_bytes());
        bytes
    }

    /// The structure size for a guest arch.
    pub fn size_for(is_x64: bool) -> u64 {
        if is_x64 {
            PROCESS_BASIC_INFORMATION64_SIZE
        } else {
            PROCESS_BASIC_INFORMATION32_SIZE
        }
    }
}

/// `ProcessDebugObjectHandle` — the debug object handle a debugger attached
/// through `DebugActiveProcess` owns (`NtQueryInformationProcess`, class 30).
pub const PROCESS_DEBUG_OBJECT_HANDLE_CLASS: u32 = 30;
/// `ProcessDebugFlags` — `!BeingDebugged` (`NtQueryInformationProcess`,
/// class 31): non-zero while NO debugger is attached.
pub const PROCESS_DEBUG_FLAGS_CLASS: u32 = 31;
/// `ProcessImageFileName` — the current process image path as a
/// `UNICODE_STRING` (the canonical current-Windows value is 27; the debug
/// classes above occupy 30/31).
pub const PROCESS_IMAGE_FILE_NAME_CLASS: u32 = 27;

/// The info classes `NtQueryInformationProcess` implements.
pub fn validate_process_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::PROCESS_BASIC_INFORMATION_CLASS
        | crate::ntdll::PROCESS_DEBUG_PORT_CLASS
        | PROCESS_DEBUG_OBJECT_HANDLE_CLASS
        | PROCESS_DEBUG_FLAGS_CLASS
        | PROCESS_IMAGE_FILE_NAME_CLASS
        | crate::ntdll::PROCESS_PROTECTION_INFORMATION_CLASS
        | crate::ntdll::PROCESS_MITIGATION_POLICY_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_info_classes_validate() {
        assert!(validate_process_information_class(0).is_ok());
        assert!(validate_process_information_class(7).is_ok());
        assert!(validate_process_information_class(27).is_ok());
        assert!(validate_process_information_class(30).is_ok());
        assert!(validate_process_information_class(31).is_ok());
        assert_eq!(
            validate_process_information_class(99),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
        // The debug classes are the verified current-Windows numbering.
        assert_eq!(PROCESS_DEBUG_OBJECT_HANDLE_CLASS, 30);
        assert_eq!(PROCESS_DEBUG_FLAGS_CLASS, 31);
        assert_eq!(PROCESS_IMAGE_FILE_NAME_CLASS, 27);
    }
}
