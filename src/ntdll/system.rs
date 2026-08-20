//! Stage-4 NTDLL — the system/time surface (`NtQuerySystemInformation`,
//! `NtQueryPerformanceCounter`, `NtQueryTimerResolution`,
//! `NtSetTimerResolution`, `NtQuerySystemTime`).
//!
//! INTERNAL CONSISTENCY CONTRACT: every number this layer reports comes from
//! the SAME configured guest topology the Win32 GetSystemInfo /
//! GetNativeSystemInfo thunks report (8 processors, mask 0xFF, 4 KiB pages,
//! 0x10000 allocation granularity) and the SAME guest clock the Win32
//! GetSystemTimeAsFileTime / QueryPerformanceCounter thunks read.  The
//! serialization helpers are pure; the dispatch wiring feeds the live
//! values.

use crate::ntdll::NtStatus;

/// `SYSTEM_BASIC_INFORMATION` (100 bytes, the ntoskrnl layout):
///
/// ```text
/// +0x00 Reserved1[2]          u32 × 2
/// +0x08 NumberOfProcessors    u32
/// +0x0C Reserved2[3]          u32 × 3
/// +0x18 NumberOfProcessors2   u32
/// +0x1C Reserved3[8]          u32 × 8
/// +0x3C NumberOfProcessors3   u32
/// +0x40 Reserved4[8]          u32 × 8
/// +0x60 NumberOfProcessors4   u32
/// ```
pub const SYSTEM_BASIC_INFORMATION_SIZE: usize = 100;

pub fn serialize_system_basic_information_x64(number_of_processors: u32) -> [u8; 100] {
    let mut bytes = [0_u8; 100];
    bytes[8..12].copy_from_slice(&number_of_processors.to_le_bytes());
    bytes[24..28].copy_from_slice(&number_of_processors.to_le_bytes());
    bytes[60..64].copy_from_slice(&number_of_processors.to_le_bytes());
    bytes[96..100].copy_from_slice(&number_of_processors.to_le_bytes());
    bytes
}

/// `SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION` (48 bytes per processor):
///
/// ```text
/// +0x00 IdleTime       i64
/// +0x08 KernelTime     i64
/// +0x10 UserTime       i64
/// +0x18 DpcTime        i64
/// +0x20 InterruptTime  i64
/// +0x28 InterruptCount u32
/// ```
pub const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_SIZE: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtProcessorPerformanceInformation {
    pub idle_time: i64,
    pub kernel_time: i64,
    pub user_time: i64,
    pub dpc_time: i64,
    pub interrupt_time: i64,
    pub interrupt_count: u32,
}

impl NtProcessorPerformanceInformation {
    pub fn serialize_x64(&self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..8].copy_from_slice(&self.idle_time.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.kernel_time.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.user_time.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.dpc_time.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.interrupt_time.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.interrupt_count.to_le_bytes());
        bytes
    }
}

/// `SYSTEM_TIME_OF_DAY_INFORMATION` (48 bytes):
///
/// ```text
/// +0x00 BootTime           i64 (FILETIME)
/// +0x08 CurrentTime        i64 (FILETIME)
/// +0x10 TimeZoneBias       i64
/// +0x18 TimeZoneId         u32
/// +0x1C Reserved           u32
/// +0x20 BootTimeBias       u64
/// +0x28 SleepTimeBias      u64
/// ```
pub const SYSTEM_TIME_OF_DAY_INFORMATION_SIZE: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtSystemTimeOfDayInformation {
    pub boot_time: i64,
    pub current_time: i64,
    pub time_zone_bias: i64,
    pub time_zone_id: u32,
}

impl NtSystemTimeOfDayInformation {
    pub fn serialize_x64(&self) -> [u8; 48] {
        let mut bytes = [0_u8; 48];
        bytes[0..8].copy_from_slice(&self.boot_time.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.current_time.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.time_zone_bias.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.time_zone_id.to_le_bytes());
        bytes
    }
}

/// The system info classes `NtQuerySystemInformation` implements.
pub fn validate_system_information_class(info_class: u32) -> Result<(), NtStatus> {
    match info_class {
        crate::ntdll::SYSTEM_BASIC_INFORMATION_CLASS
        | crate::ntdll::SYSTEM_TIME_OF_DAY_INFORMATION_CLASS
        | crate::ntdll::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_CLASS => Ok(()),
        _ => Err(crate::ntdll::STATUS_INVALID_INFO_CLASS),
    }
}

/// The guest timer resolution range (100 ns units).  The values mirror what
/// the Win32 time layer exposes: a 1 ms minimum, the historical 15.6 ms
/// default and current resolution.
pub const TIMER_MINIMUM_RESOLUTION_100NS: u32 = 10_000; // 1 ms
pub const TIMER_MAXIMUM_RESOLUTION_100NS: u32 = 156_250; // 15.6 ms

/// `NtQueryPerformanceCounter` — the (counter, frequency) pair, straight
/// from the guest clock the Win32 QueryPerformanceCounter thunk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtPerformanceCounter {
    pub counter: u64,
    pub frequency: u64,
}

impl NtPerformanceCounter {
    pub fn serialize_x64(&self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[0..8].copy_from_slice(&self.counter.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.frequency.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_basic_information_matches_the_get_system_info_topology() {
        // GetSystemInfo reports 8 processors — the Nt layer must agree.
        let bytes = serialize_system_basic_information_x64(8);
        assert_eq!(bytes.len(), 100);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(bytes[60..64].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(bytes[96..100].try_into().unwrap()), 8);
    }

    #[test]
    fn processor_performance_serializes_the_clock_domain() {
        let info = NtProcessorPerformanceInformation {
            idle_time: 1,
            kernel_time: 2,
            user_time: 3,
            dpc_time: 4,
            interrupt_time: 5,
            interrupt_count: 6,
        };
        let bytes = info.serialize_x64();
        assert_eq!(i64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1);
        assert_eq!(i64::from_le_bytes(bytes[16..24].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(bytes[40..44].try_into().unwrap()), 6);
    }

    #[test]
    fn time_of_day_serializes_the_guest_filetime_domain() {
        let info = NtSystemTimeOfDayInformation {
            boot_time: 0x1000,
            current_time: 0x2000,
            time_zone_bias: 0,
            time_zone_id: 1,
        };
        let bytes = info.serialize_x64();
        assert_eq!(i64::from_le_bytes(bytes[0..8].try_into().unwrap()), 0x1000);
        assert_eq!(i64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x2000);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 1);
    }

    #[test]
    fn system_info_classes_validate_and_counter_layout_is_canonical() {
        assert!(validate_system_information_class(0).is_ok());
        assert!(validate_system_information_class(3).is_ok());
        assert!(validate_system_information_class(8).is_ok());
        assert_eq!(
            validate_system_information_class(99),
            Err(crate::ntdll::STATUS_INVALID_INFO_CLASS)
        );
        let counter = NtPerformanceCounter {
            counter: 12345,
            frequency: 10_000_000,
        };
        let bytes = counter.serialize_x64();
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 12345);
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            10_000_000
        );
    }
}
