//! Guest time, timezone, and security-cookie helpers.

use super::*;

/// Read a SEC_WINNT_AUTH_IDENTITY (guest credentials structure).
pub(crate) fn read_guest_auth_identity(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
) -> AppResult<crate::sspi::SspiIdentity> {
    use crate::sspi::SspiIdentity;
    let pointer_bytes = guest_arch.pointer_bytes() as u64;
    let read_field = |index: usize| -> AppResult<String> {
        let ptr = read_guest_pointer(memory, address + index as u64 * pointer_bytes, guest_arch)?;
        let len = read_guest_u32(memory, address + 3 * pointer_bytes + index as u64 * 4)?;
        if ptr == 0 || len == 0 {
            return Ok(String::new());
        }
        let units = read_guest_bytes(memory, ptr, len as usize)?;
        let mut code_units = Vec::with_capacity(units.len() / 2);
        for chunk in units.as_chunks::<2>().0 {
            code_units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(String::from_utf16_lossy(&code_units))
    };
    let flags = read_guest_u32(memory, address + 3 * pointer_bytes + 3 * 4)?;
    let (user, domain, password) = if flags == 0x2 {
        // SEC_WINNT_AUTH_IDENTITY_UNICODE
        (read_field(0)?, read_field(1)?, read_field(2)?)
    } else {
        (String::new(), String::new(), String::new())
    };
    Ok(SspiIdentity {
        user,
        domain,
        password,
    })
}

pub(crate) fn write_shell_link_clsid(memory: &mut MemoryImage, address: u64) {
    write_u32(memory, address, 0x0002_1401);
    memory.map_bytes(address + 4, &0_u16.to_le_bytes());
    memory.map_bytes(address + 6, &0_u16.to_le_bytes());
    memory.map_bytes(
        address + 8,
        &[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );
}

pub(crate) fn is_shell_link_interface_iid(iid: &str) -> bool {
    iid.eq_ignore_ascii_case(IID_IUNKNOWN)
        || iid.eq_ignore_ascii_case(IID_ISHELLLINKW)
        || iid.eq_ignore_ascii_case(IID_IPERSIST)
        || iid.eq_ignore_ascii_case(IID_IPERSISTFILE)
}

pub(crate) fn current_guest_filetime_ticks(dtm: bool) -> u64 {
    if dtm { 0 } else { current_host_ticks_100ns() }
}

/// THE ONE guest system-time derivation (FILETIME 100 ns since 1601),
/// shared by the Win32 clock thunks (GetSystemTimeAsFileTime /
/// GetSystemTimePreciseAsFileTime) and the Nt clock dispatch
/// (NtQuerySystemTime / NtQuerySystemInformation(SystemTimeOfDay)).
///
/// Live runs report the host wall clock.  Deterministic runs derive from
/// the canonical guest clock (`TimeState::ticks_ms` — the same clock
/// GetTickCount64 / GetTickCount read), so the system time advances in
/// lockstep with the tick counter after every guest sleep and the two
/// surfaces can never disagree.
pub(crate) fn guest_filetime_ticks(win32: &crate::win32::Win32Subsystem) -> u64 {
    if win32.is_dtm() {
        WINDOWS_EPOCH_OFFSET_100NS.saturating_add(win32.get_tick_count64().saturating_mul(10_000))
    } else {
        current_host_ticks_100ns()
    }
}

/// The four guest-clock FILETIME values (creation, exit, kernel, user)
/// reported by GetThreadTimes and the ThreadTimes information class.
///
/// BOTH APIs derive from the SAME guest-clock domain through this helper so
/// they always agree (the process has no modelled creation/exit timestamps,
/// so those report 0; kernel and user time report the clock delta — 0 in
/// deterministic mode).
pub(crate) fn guest_thread_times_filetimes(dtm: bool) -> [u64; 4] {
    let ticks = current_guest_filetime_ticks(dtm);
    [0, 0, ticks, ticks]
}

pub(crate) struct HostTimeZoneInformation {
    pub(crate) bias_minutes: i32,
    pub(crate) standard_name: String,
    pub(crate) daylight_name: String,
    pub(crate) result: u32,
}

pub(crate) fn current_host_time_zone_information(dtm: bool) -> HostTimeZoneInformation {
    if dtm {
        return HostTimeZoneInformation {
            bias_minutes: 0,
            standard_name: "UTC".to_string(),
            daylight_name: "UTC".to_string(),
            result: TIME_ZONE_ID_UNKNOWN,
        };
    }

    // SAFETY: guest memory access and FFI for PE runtime emulation
    unsafe {
        let mut now: libc::time_t = 0;
        if libc::time(&mut now as *mut _) == -1 {
            return HostTimeZoneInformation {
                bias_minutes: 0,
                standard_name: String::new(),
                daylight_name: String::new(),
                result: TIME_ZONE_ID_UNKNOWN,
            };
        }

        let mut local_tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut local_tm as *mut _).is_null() {
            return HostTimeZoneInformation {
                bias_minutes: 0,
                standard_name: String::new(),
                daylight_name: String::new(),
                result: TIME_ZONE_ID_UNKNOWN,
            };
        }

        let local_as_utc = libc::timegm(&mut local_tm as *mut _);
        let bias_minutes = if local_as_utc == -1 {
            0
        } else {
            (now as i64 - local_as_utc as i64).div_euclid(60) as i32
        };
        let zone_name = format_time_zone_name(&local_tm);
        let result = if local_tm.tm_isdst > 0 {
            TIME_ZONE_ID_DAYLIGHT
        } else if local_tm.tm_isdst == 0 {
            TIME_ZONE_ID_STANDARD
        } else {
            TIME_ZONE_ID_UNKNOWN
        };
        HostTimeZoneInformation {
            bias_minutes,
            standard_name: zone_name.clone(),
            daylight_name: zone_name,
            result,
        }
    }
}

pub(crate) fn format_time_zone_name(local_tm: &libc::tm) -> String {
    let mut buffer = [0_i8; 64];
    // SAFETY: strftime is called with a valid buffer pointer, buffer length,
    // a null-terminated format string, and a valid tm pointer.
    let written = unsafe {
        libc::strftime(
            buffer.as_mut_ptr(),
            buffer.len(),
            c"%Z".as_ptr().cast(),
            local_tm as *const _,
        )
    };
    if written == 0 {
        String::new()
    } else {
        // SAFETY: CString creation for FFI — string contents are valid and null-terminated
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }
}

pub(crate) fn write_time_zone_information(
    memory: &mut MemoryImage,
    address: u64,
    info: &HostTimeZoneInformation,
) {
    memory.map_bytes(address, &[0; TIME_ZONE_INFORMATION_SIZE]);
    write_i32(memory, address, info.bias_minutes);
    write_utf16_fixed(
        memory,
        address + 4,
        TIME_ZONE_NAME_CAPACITY,
        &info.standard_name,
    );
    write_i32(memory, address + 84, 0);
    write_utf16_fixed(
        memory,
        address + 88,
        TIME_ZONE_NAME_CAPACITY,
        &info.daylight_name,
    );
    write_i32(memory, address + 168, 0);
}

pub(crate) fn default_security_cookie(guest_arch: GuestArch) -> u64 {
    match guest_arch {
        GuestArch::X86 => DEFAULT_SECURITY_COOKIE_X86,
        GuestArch::X64 => DEFAULT_SECURITY_COOKIE_X64,
    }
}

pub(crate) fn sanitize_security_cookie(guest_arch: GuestArch, mut cookie: u64) -> u64 {
    match guest_arch {
        GuestArch::X86 => {
            cookie &= u64::from(u32::MAX);
            if cookie == 0 || cookie == DEFAULT_SECURITY_COOKIE_X86 {
                cookie = DEFAULT_SECURITY_COOKIE_X86 + 1;
            } else if cookie & 0xffff_0000 == 0 {
                cookie |= (cookie | 0x4711) << 16;
                cookie &= u64::from(u32::MAX);
            }
            cookie
        }
        GuestArch::X64 => {
            cookie &= 0x0000_ffff_ffff_ffff;
            if cookie == 0 || cookie == DEFAULT_SECURITY_COOKIE_X64 {
                cookie = DEFAULT_SECURITY_COOKIE_X64 + 1;
            }
            cookie
        }
    }
}

pub(crate) fn encode_pointer_value(value: u64, cookie: u64, guest_arch: GuestArch) -> u64 {
    match guest_arch {
        GuestArch::X86 => {
            let cookie32 = cookie as u32;
            u64::from((value as u32).rotate_left(cookie32 & 31) ^ cookie32)
        }
        GuestArch::X64 => value.rotate_left((cookie & 63) as u32) ^ cookie,
    }
}

pub(crate) fn decode_pointer_value(value: u64, cookie: u64, guest_arch: GuestArch) -> u64 {
    match guest_arch {
        GuestArch::X86 => {
            let cookie32 = cookie as u32;
            u64::from(((value as u32) ^ cookie32).rotate_right(cookie32 & 31))
        }
        GuestArch::X64 => (value ^ cookie).rotate_right((cookie & 63) as u32),
    }
}

pub(crate) fn initial_guest_security_cookie(
    dtm: bool,
    guest_arch: GuestArch,
    mapped_image_base: u64,
    peb_base: u64,
    teb_base: u64,
) -> u64 {
    let entropy = if dtm {
        mapped_image_base.rotate_left(17)
            ^ peb_base.rotate_left(7)
            ^ teb_base.rotate_left(29)
            ^ 0x4711_5eed
    } else {
        current_guest_filetime_ticks(false)
            ^ current_host_ticks_100ns().rotate_left(13)
            ^ u64::from(std::process::id())
            ^ 1
            ^ mapped_image_base.rotate_left(17)
            ^ peb_base.rotate_left(7)
            ^ teb_base.rotate_left(29)
    };
    sanitize_security_cookie(guest_arch, entropy)
}

pub(crate) fn current_host_ticks_100ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| {
            WINDOWS_EPOCH_OFFSET_100NS.saturating_add(duration.as_nanos().div_euclid(100) as u64)
        })
        .unwrap_or(WINDOWS_EPOCH_OFFSET_100NS)
}

/// Convert a SYSTEMTIME (year, month, day, hour, minute, second, millis) to FILETIME ticks
/// (100-ns intervals since 1601-01-01 00:00:00 UTC).
pub(crate) fn systemtime_to_filetime_ticks(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
    millis: i32,
) -> u64 {
    // Days from 1601-01-01 to 1970-01-01
    const DAYS_1601_TO_1970: u64 = 134774;
    // Compute days from 1970-01-01 to year-01-01
    let y = year as u64;
    let m = month as u64;
    let d = day as u64;
    // Days from epoch using the civil calendar algorithm
    let days_from_epoch = if m > 2 {
        y * 365 + y.div_ceil(4) - y.div_ceil(100) + y.div_ceil(400) + (m * 153 + 2) / 5 + d - 719468
    } else {
        let yn = y - 1;
        yn * 365 + yn.div_ceil(4) - yn.div_ceil(100)
            + yn.div_ceil(400)
            + ((m + 9) * 153 + 2) / 5
            + d
            - 719468
    };
    let total_days = DAYS_1601_TO_1970 + days_from_epoch;

    total_days * 864_000_000_000  // days to 100ns
        + hour as u64 * 3_600_000_000
        + minute as u64 * 60_000_000
        + second as u64 * 10_000_000
        + millis as u64 * 10_000
}

/// Convert FILETIME ticks (100-ns intervals since 1601-01-01) to SYSTEMTIME components.
/// Returns (year, month, day_of_week, day, hour, minute, second, millis).
pub(crate) fn filetime_ticks_to_systemtime(ticks: u64) -> (u16, u16, u16, u16, u16, u16, u16, u16) {
    // Convert to days since 1601-01-01 and time-of-day in 100ns units
    let days_since_1601 = ticks / 864_000_000_000;
    let time_of_day = ticks % 864_000_000_000;
    let hour = (time_of_day / 3_600_000_000) as u16;
    let minute = ((time_of_day % 3_600_000_000) / 60_000_000) as u16;
    let second = ((time_of_day % 60_000_000) / 10_000_000) as u16;
    let millis = ((time_of_day % 10_000_000) / 10_000) as u16;
    // Convert days since 1601-01-01 to year/month/day
    // First convert to days since 1970-01-01
    let days_since_epoch = days_since_1601 as i64 - 134774;
    // Use the civil calendar algorithm to convert to year/month/day
    let z = days_since_epoch + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    // Day of week: 1601-01-01 was a Monday (day_of_week=1)
    let day_of_week = ((days_since_1601 + 1) % 7) as u16;
    (
        year as u16,
        m as u16,
        day_of_week,
        d as u16,
        hour,
        minute,
        second,
        millis,
    )
}

/// Get the local timezone bias in minutes (positive = west of UTC, e.g. UTC-5 returns +300).
///
/// Uses `libc::localtime_r` to query the system timezone offset. Falls back
/// to 0 (UTC) if the system call fails.
pub(crate) fn local_timezone_bias_minutes() -> i32 {
    #[cfg(target_os = "macos")]
    {
        use std::mem::MaybeUninit;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut tm: MaybeUninit<libc::tm> = MaybeUninit::uninit();
        let time_val: libc::time_t = now_secs;
        // SAFETY: localtime_r is thread-safe and writes to a caller-owned buffer.
        // The time_t is a valid Unix timestamp. The function returns a pointer
        // to the same buffer we provided on success, or null on failure.
        let result = unsafe { libc::localtime_r(&time_val, tm.as_mut_ptr()) };
        if result.is_null() {
            // Fallback: return 0 (UTC) if localtime_r fails
            return 0;
        }
        // SAFETY: localtime_r succeeded (result non-null), so tm is initialized.
        let tm = unsafe { tm.assume_init() };
        // tm_gmtoff is the UTC offset in seconds (positive = east of UTC).
        // Windows TIME_ZONE_ID. Bias is positive = west of UTC.
        // So Bias = -tm_gmtoff / 60.
        let offset_seconds = tm.tm_gmtoff;
        -(offset_seconds / 60) as i32
    }
    #[cfg(not(target_os = "macos"))]
    {
        // On non-macOS platforms, return 0 (UTC) as a safe default.
        let _ = std::time::SystemTime::now();
        0
    }
}

pub(crate) fn is_processor_feature_present(feature: u32) -> bool {
    match feature {
        0 => false,
        1 => false,
        2 => true,
        3 => true,
        6 => true,
        7 => false,
        8 => true,
        9 => true,
        10 => true,
        11 => true,
        12 => true,
        13 => true,
        14 => true,
        15 => true,
        17 => true,
        _ => false,
    }
}

pub(crate) fn read_optional_filetime(memory: &MemoryImage, address: u64) -> AppResult<Option<u64>> {
    if address == 0 {
        Ok(None)
    } else {
        Ok(Some(read_filetime(memory, address)?))
    }
}

pub(crate) fn write_filetime(memory: &mut MemoryImage, address: u64, ticks: u64) {
    write_u64(memory, address, ticks);
}
