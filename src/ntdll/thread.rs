//! Stage-4 NTDLL — the thread surface (`NtQueryInformationThread`,
//! `NtSetInformationThread`, `NtGetContextThread`, `NtSetContextThread`,
//! suspend/resume, termination).
//!
//! Thread identity comes from the guest thread model: the guest thread id,
//! the TEB base of the scheduler's pending-thread record, the guest process
//! id and the scheduler suspend count (a suspended thread is not runnable —
//! the pump skips records with `suspended > 0`).  The CONTEXT serialization
//! covers the architecture-appropriate integer/control register subset at
//! the canonical Windows offsets.

use crate::ntdll::NtStatus;

/// `THREAD_BASIC_INFORMATION` (x64, 48 bytes):
///
/// ```text
/// +0x00 ExitStatus                i32 (NTSTATUS)
/// +0x04 (padding)
/// +0x08 TebBaseAddress            ptr
/// +0x10 UniqueProcessId           ptr
/// +0x18 UniqueThreadId            ptr
/// +0x20 AffinityMask              ptr
/// +0x28 Priority                  i32
/// +0x2C BasePriority              i32
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtThreadBasicInformation {
    pub exit_status: u32,
    pub teb_base_address: u64,
    pub unique_process_id: u64,
    pub unique_thread_id: u64,
    pub affinity_mask: u64,
    pub priority: i32,
    pub base_priority: i32,
}

pub const THREAD_BASIC_INFORMATION64_SIZE: u64 = 48;
pub const THREAD_BASIC_INFORMATION32_SIZE: u64 = 28;

impl NtThreadBasicInformation {
    pub fn serialize_x64(&self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..4].copy_from_slice(&self.exit_status.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.teb_base_address.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.unique_process_id.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.unique_thread_id.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.affinity_mask.to_le_bytes());
        bytes[40..44].copy_from_slice(&(self.priority as u32).to_le_bytes());
        bytes[44..48].copy_from_slice(&(self.base_priority as u32).to_le_bytes());
        bytes
    }

    /// x86 `THREAD_BASIC_INFORMATION` (28 bytes): every field 4 bytes.
    pub fn serialize_x86(&self) -> [u8; 28] {
        let mut bytes = [0_u8; 28];
        bytes[0..4].copy_from_slice(&self.exit_status.to_le_bytes());
        bytes[4..8].copy_from_slice(&(self.teb_base_address as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(self.unique_process_id as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(self.unique_thread_id as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&(self.affinity_mask as u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&(self.priority as u32).to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.base_priority as u32).to_le_bytes());
        bytes
    }

    pub fn size_for(is_x64: bool) -> u64 {
        if is_x64 {
            THREAD_BASIC_INFORMATION64_SIZE
        } else {
            THREAD_BASIC_INFORMATION32_SIZE
        }
    }
}

/// The info classes `NtQueryInformationThread` implements.
pub fn validate_thread_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::THREAD_BASIC_INFORMATION_CLASS
        | crate::ntdll::THREAD_TIMES_CLASS
        | crate::ntdll::THREAD_AFFINITY_MASK_CLASS
        | crate::ntdll::THREAD_PRIORITY_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

// ── x64 CONTEXT (winnt.h _CONTEXT, AMD64) ──────────────────────────────────
//
// Only the integer / control subset is modelled; the canonical offsets are:
// P1Home..P4Home 0x00, Rax 0x20 .. R15 0x98, Rip 0xA0, EFlags 0xA8,
// SegCs..SegSs 0xB0, MxCsr 0xBC, ContextFlags 0x3B8.

/// CONTEXT_AMD64 base mask and the standard flag subsets.
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

pub const X64_CONTEXT_FLAGS_OFFSET: u64 = 0x3B8;
pub const X64_CONTEXT_RAX_OFFSET: u64 = 0x20;
pub const X64_CONTEXT_RIP_OFFSET: u64 = 0xA0;
pub const X64_CONTEXT_RSP_OFFSET: u64 = 0x40;
pub const X64_CONTEXT_EFLAGS_OFFSET: u64 = 0xA8;

/// The x64 CONTEXT integer-register offsets in the order the CpuState GPR
/// array stores them (rax..r15 → gpr[0..15]).
pub const X64_CONTEXT_GPR_OFFSETS: [u64; 16] = [
    0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98,
];

/// The i386 CONTEXT integer-register offsets (winnt.h _CONTEXT, i386).
pub const X86_CONTEXT_FLAGS_OFFSET: u64 = 0x00;
pub const X86_CONTEXT_EDI_OFFSET: u64 = 0xA0;
pub const X86_CONTEXT_ESI_OFFSET: u64 = 0xA4;
pub const X86_CONTEXT_EBX_OFFSET: u64 = 0xA8;
pub const X86_CONTEXT_EDX_OFFSET: u64 = 0xAC;
pub const X86_CONTEXT_ECX_OFFSET: u64 = 0xB0;
pub const X86_CONTEXT_EAX_OFFSET: u64 = 0xB4;
pub const X86_CONTEXT_EBP_OFFSET: u64 = 0xB8;
pub const X86_CONTEXT_EIP_OFFSET: u64 = 0xBC;
pub const X86_CONTEXT_EFLAGS_OFFSET: u64 = 0xC4;
pub const X86_CONTEXT_ESP_OFFSET: u64 = 0xC8;

/// The thread info classes `NtSetInformationThread` accepts (priority and
/// affinity mask).
pub fn validate_set_thread_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::THREAD_PRIORITY_CLASS | crate::ntdll::THREAD_AFFINITY_MASK_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_basic_information_layouts_are_canonical() {
        let info = NtThreadBasicInformation {
            exit_status: 0x103,
            teb_base_address: 0x7FFF_0000_1000,
            unique_process_id: 4,
            unique_thread_id: 2,
            affinity_mask: 0xFF,
            priority: 0,
            base_priority: 0,
        };
        let x64 = info.serialize_x64();
        assert_eq!(x64.len(), 48);
        assert_eq!(
            u64::from_le_bytes(x64[8..16].try_into().unwrap()),
            0x7FFF_0000_1000
        );
        assert_eq!(u64::from_le_bytes(x64[16..24].try_into().unwrap()), 4);
        assert_eq!(u64::from_le_bytes(x64[24..32].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(x64[32..40].try_into().unwrap()), 0xFF);
        let x86 = info.serialize_x86();
        assert_eq!(x86.len(), 28);
        assert_eq!(u32::from_le_bytes(x86[12..16].try_into().unwrap()), 2);
        assert_eq!(NtThreadBasicInformation::size_for(true), 48);
        assert_eq!(NtThreadBasicInformation::size_for(false), 28);
    }

    #[test]
    fn context_offsets_follow_the_canonical_windows_layouts() {
        // Register order rax..r15, and the canonical GPR offsets.
        assert_eq!(X64_CONTEXT_GPR_OFFSETS[0], 0x20); // Rax
        assert_eq!(X64_CONTEXT_GPR_OFFSETS[4], 0x40); // Rsp
        assert_eq!(X64_CONTEXT_GPR_OFFSETS[15], 0x98); // R15
        assert_eq!(X64_CONTEXT_RIP_OFFSET, 0xA0);
        assert_eq!(X64_CONTEXT_EFLAGS_OFFSET, 0xA8);
        assert_eq!(X64_CONTEXT_FLAGS_OFFSET, 0x3B8);
        assert_eq!(X86_CONTEXT_EAX_OFFSET, 0xB4);
        assert_eq!(X86_CONTEXT_ESP_OFFSET, 0xC8);
        assert_eq!(
            CONTEXT_FULL,
            CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
        );
    }

    #[test]
    fn thread_info_classes_validate() {
        assert!(validate_thread_information_class(0).is_ok());
        assert_eq!(
            validate_thread_information_class(99),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
        assert!(validate_set_thread_information_class(16).is_ok());
        assert!(validate_set_thread_information_class(3).is_ok());
        assert_eq!(
            validate_set_thread_information_class(0),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
    }
}
