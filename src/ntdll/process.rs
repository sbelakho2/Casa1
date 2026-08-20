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

/// The info classes `NtQueryInformationProcess` implements.
pub fn validate_process_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::PROCESS_BASIC_INFORMATION_CLASS
        | crate::ntdll::PROCESS_DEBUG_PORT_CLASS
        | crate::ntdll::PROCESS_IMAGE_FILE_NAME_CLASS
        | crate::ntdll::PROCESS_PROTECTION_INFORMATION_CLASS
        | crate::ntdll::PROCESS_MITIGATION_POLICY_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_basic_information_layouts_are_canonical() {
        let info = NtProcessBasicInformation {
            exit_status: 0x103,
            peb_base_address: 0x7FFF_0000_0000,
            affinity_mask: 0xFF,
            base_priority: 8,
            unique_process_id: 4,
            inherited_from_unique_process_id: 0,
        };
        let x64 = info.serialize_x64();
        assert_eq!(x64.len(), 48);
        assert_eq!(u32::from_le_bytes(x64[0..4].try_into().unwrap()), 0x103);
        assert_eq!(
            u64::from_le_bytes(x64[8..16].try_into().unwrap()),
            0x7FFF_0000_0000
        );
        assert_eq!(u64::from_le_bytes(x64[16..24].try_into().unwrap()), 0xFF);
        assert_eq!(u32::from_le_bytes(x64[24..28].try_into().unwrap()), 8);
        assert_eq!(u64::from_le_bytes(x64[32..40].try_into().unwrap()), 4);

        let x86 = info.serialize_x86();
        assert_eq!(x86.len(), 24);
        assert_eq!(u32::from_le_bytes(x86[0..4].try_into().unwrap()), 0x103);
        assert_eq!(
            u32::from_le_bytes(x86[4..8].try_into().unwrap()),
            0x0000_0000
        );
        assert_eq!(u32::from_le_bytes(x86[16..20].try_into().unwrap()), 4);
        assert_eq!(NtProcessBasicInformation::size_for(true), 48);
        assert_eq!(NtProcessBasicInformation::size_for(false), 24);
    }

    #[test]
    fn process_info_classes_validate() {
        assert!(validate_process_information_class(0).is_ok());
        assert!(validate_process_information_class(7).is_ok());
        assert!(validate_process_information_class(30).is_ok());
        assert_eq!(
            validate_process_information_class(99),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
    }
}
