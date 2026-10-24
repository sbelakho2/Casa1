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
///
/// Class numbers are the verified current-Windows `THREADINFOCLASS` values
/// (see the constants in `crate::ntdll` — wine/mingw-w64/phnt all agree).
pub fn validate_thread_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::THREAD_BASIC_INFORMATION_CLASS
        | crate::ntdll::THREAD_TIMES_CLASS
        | crate::ntdll::THREAD_IS_TERMINATED_CLASS
        | crate::ntdll::THREAD_PRIORITY_CLASS
        | crate::ntdll::THREAD_BASE_PRIORITY_CLASS
        | crate::ntdll::THREAD_AFFINITY_MASK_CLASS
        | crate::ntdll::THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS
        | crate::ntdll::THREAD_AM_I_LAST_THREAD_CLASS
        | crate::ntdll::THREAD_PRIORITY_BOOST_CLASS
        | crate::ntdll::THREAD_HIDE_FROM_DEBUGGER_CLASS
        | crate::ntdll::THREAD_SUSPEND_COUNT_CLASS => Ok(()),
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

/// The x64 CONTEXT debug-register offsets (winnt.h `_CONTEXT`, AMD64):
/// `Dr0`-`Dr3`, `Dr6` and `Dr7` live immediately after the four home slots.
pub const X64_CONTEXT_DR0_OFFSET: u64 = 0x48;
pub const X64_CONTEXT_DR1_OFFSET: u64 = 0x50;
pub const X64_CONTEXT_DR2_OFFSET: u64 = 0x58;
pub const X64_CONTEXT_DR3_OFFSET: u64 = 0x60;
pub const X64_CONTEXT_DR6_OFFSET: u64 = 0x68;
pub const X64_CONTEXT_DR7_OFFSET: u64 = 0x70;

/// The six x64 debug registers in `Dr0..Dr3, Dr6, Dr7` order, paired with
/// their canonical CONTEXT offsets.
pub const X64_CONTEXT_DEBUG_OFFSETS: [u64; 6] = [
    X64_CONTEXT_DR0_OFFSET,
    X64_CONTEXT_DR1_OFFSET,
    X64_CONTEXT_DR2_OFFSET,
    X64_CONTEXT_DR3_OFFSET,
    X64_CONTEXT_DR6_OFFSET,
    X64_CONTEXT_DR7_OFFSET,
];

/// The i386 CONTEXT debug-register offsets (winnt.h `_CONTEXT`, i386):
/// `ContextFlags` is at 0x00 and `Dr0`-`Dr7` follow it.
pub const X86_CONTEXT_DR0_OFFSET: u64 = 0x04;
pub const X86_CONTEXT_DR1_OFFSET: u64 = 0x08;
pub const X86_CONTEXT_DR2_OFFSET: u64 = 0x0C;
pub const X86_CONTEXT_DR3_OFFSET: u64 = 0x10;
pub const X86_CONTEXT_DR6_OFFSET: u64 = 0x14;
pub const X86_CONTEXT_DR7_OFFSET: u64 = 0x18;

/// The six i386 debug registers in `Dr0..Dr3, Dr6, Dr7` order, paired with
/// their canonical CONTEXT offsets.
pub const X86_CONTEXT_DEBUG_OFFSETS: [u64; 6] = [
    X86_CONTEXT_DR0_OFFSET,
    X86_CONTEXT_DR1_OFFSET,
    X86_CONTEXT_DR2_OFFSET,
    X86_CONTEXT_DR3_OFFSET,
    X86_CONTEXT_DR6_OFFSET,
    X86_CONTEXT_DR7_OFFSET,
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

/// The thread info classes `NtSetInformationThread` accepts (priority,
/// affinity mask, and the null-buffer `ThreadHideFromDebugger`).
///
/// `ThreadHideFromDebugger` (17) is the class the anti-debug surface models:
/// Windows accepts it only with a zero-length buffer, and it is the only way
/// a thread asks not to be seen by an attached debugger.
pub fn validate_set_thread_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::THREAD_PRIORITY_CLASS
        | crate::ntdll::THREAD_AFFINITY_MASK_CLASS
        | crate::ntdll::THREAD_HIDE_FROM_DEBUGGER_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_info_classes_validate() {
        // Every supported query class validates; unsupported classes are
        // rejected with STATUS_INVALID_INFO_CLASS.
        for supported in [
            crate::ntdll::THREAD_BASIC_INFORMATION_CLASS,
            crate::ntdll::THREAD_TIMES_CLASS,
            crate::ntdll::THREAD_IS_TERMINATED_CLASS,
            crate::ntdll::THREAD_PRIORITY_CLASS,
            crate::ntdll::THREAD_BASE_PRIORITY_CLASS,
            crate::ntdll::THREAD_AFFINITY_MASK_CLASS,
            crate::ntdll::THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS,
            crate::ntdll::THREAD_AM_I_LAST_THREAD_CLASS,
            crate::ntdll::THREAD_PRIORITY_BOOST_CLASS,
            crate::ntdll::THREAD_HIDE_FROM_DEBUGGER_CLASS,
            crate::ntdll::THREAD_SUSPEND_COUNT_CLASS,
        ] {
            assert!(validate_thread_information_class(supported).is_ok());
        }
        assert_eq!(
            validate_thread_information_class(99),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
        // The verified current-Windows numbering.
        assert_eq!(crate::ntdll::THREAD_PRIORITY_CLASS, 2);
        assert_eq!(crate::ntdll::THREAD_BASE_PRIORITY_CLASS, 3);
        assert_eq!(crate::ntdll::THREAD_AFFINITY_MASK_CLASS, 4);
        assert_eq!(crate::ntdll::THREAD_IS_TERMINATED_CLASS, 20);
        assert_eq!(crate::ntdll::THREAD_SUSPEND_COUNT_CLASS, 35);
        // The set surface: ThreadPriority + ThreadAffinityMask + the
        // null-buffer ThreadHideFromDebugger.
        assert!(validate_set_thread_information_class(2).is_ok());
        assert!(validate_set_thread_information_class(4).is_ok());
        assert!(validate_set_thread_information_class(17).is_ok());
        assert_eq!(X64_CONTEXT_DR0_OFFSET, 0x48);
        assert_eq!(X64_CONTEXT_DR7_OFFSET, 0x70);
        assert_eq!(X86_CONTEXT_DR0_OFFSET, 0x04);
        assert_eq!(X86_CONTEXT_DR7_OFFSET, 0x18);
        assert_eq!(
            validate_set_thread_information_class(0),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
    }
}
