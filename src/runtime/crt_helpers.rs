//! CRT string/number formatting helpers.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrtLengthModifier {
    None,
    H,
    Hh,
    L,
    Ll,
}

/// Cursor over an x86-cdecl vararg list (the UCRT `va_list` for x86 guests is
/// a pointer into the caller's stack).  32-bit values advance 4 bytes; 64-bit
/// values (ll/I64 integers and doubles) advance 8 bytes across two slots.
pub(crate) struct CrtVaReader {
    pub(crate) cursor: u64,
    pub(crate) arch: GuestArch,
}

impl CrtVaReader {
    pub(crate) fn new(cursor: u64, arch: GuestArch) -> Self {
        Self { cursor, arch }
    }

    pub(crate) fn read_u32(&mut self, memory: &MemoryImage) -> AppResult<u32> {
        let value = read_u32(memory, self.cursor)?;
        self.cursor = self.cursor.wrapping_add(4);
        Ok(value)
    }

    pub(crate) fn read_u64(&mut self, memory: &MemoryImage) -> AppResult<u64> {
        let value = match self.arch {
            GuestArch::X86 => {
                let low = read_u32(memory, self.cursor)? as u64;
                let high = read_u32(memory, self.cursor.wrapping_add(4))? as u64;
                low | (high << 32)
            }
            GuestArch::X64 => memory.read_u64(self.cursor)?,
        };
        self.cursor = self.cursor.wrapping_add(8);
        Ok(value)
    }

    pub(crate) fn read_pointer(&mut self, memory: &MemoryImage) -> AppResult<u64> {
        match self.arch {
            GuestArch::X86 => {
                let value = read_u32(memory, self.cursor)? as u64;
                self.cursor = self.cursor.wrapping_add(4);
                Ok(value)
            }
            GuestArch::X64 => {
                let value = memory.read_u64(self.cursor)?;
                self.cursor = self.cursor.wrapping_add(8);
                Ok(value)
            }
        }
    }

    pub(crate) fn read_f64(&mut self, memory: &MemoryImage) -> AppResult<f64> {
        let bits = self.read_u64(memory)?;
        Ok(f64::from_bits(bits))
    }
}

/// MSVC strerror message table (mirrors UCRT's strerror.c strings).
pub(crate) fn crt_errno_message(errnum: i32) -> &'static str {
    match errnum {
        0 => "No error",
        1 => "Operation not permitted",
        2 => "No such file or directory",
        3 => "No such process",
        4 => "Interrupted function call",
        5 => "Input/output error",
        6 => "No such device or address",
        7 => "Arg list too long",
        8 => "Exec format error",
        9 => "Bad file descriptor",
        10 => "No child processes",
        11 => "Resource temporarily unavailable",
        12 => "Not enough space",
        13 => "Permission denied",
        14 => "Bad address",
        15 => "Unknown error",
        16 => "Resource device",
        17 => "File exists",
        18 => "Improper link",
        19 => "No such device",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        23 => "Too many open files in system",
        24 => "Too many open files",
        25 => "Inappropriate I/O control operation",
        26 => "Text file busy",
        27 => "File too large",
        28 => "No space left on device",
        29 => "Illegal seek",
        30 => "Cannot create a file when that file already exists",
        31 => "Directory not empty",
        32 => "Broken pipe",
        33 => "Math argument",
        34 => "Result too large",
        35 => "File already exists",
        36 => "Too many links",
        37 => "Unknown error",
        38 => "Filename too long",
        39 => "No locks available",
        40 => "Function not implemented",
        41 => "Directory not empty",
        _ => "Unknown error",
    }
}

/// Stat data collected for `_stat`/`_fstat` (FILETIME ticks, Unix-converted on
/// write).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CrtStatInfo {
    pub(crate) is_directory: bool,
    pub(crate) read_only: bool,
    pub(crate) size: u64,
    pub(crate) creation_time_ticks: u64,
    pub(crate) last_access_time_ticks: u64,
    pub(crate) last_write_time_ticks: u64,
}

/// Collect stat info for a resolved guest path (GE metadata + host size).
pub(crate) fn crt_stat_info(runtime: &mut PeHostRuntime, path: &str) -> AppResult<CrtStatInfo> {
    let metadata = runtime.win32.ge().get_file_metadata(path)?;
    let host_path = runtime.win32.guest_path_to_host_path(path)?;
    let host_metadata = std::fs::metadata(&host_path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to stat {}", host_path.display()),
            &error,
        )
    })?;
    Ok(CrtStatInfo {
        is_directory: metadata.kind == crate::ge::FsEntryKind::Directory,
        read_only: metadata.attributes.iter().any(|a| a == "readonly"),
        size: if metadata.kind == crate::ge::FsEntryKind::Directory {
            0
        } else {
            host_metadata.len()
        },
        creation_time_ticks: metadata.creation_time_ticks,
        last_access_time_ticks: metadata.last_access_time_ticks,
        last_write_time_ticks: metadata.last_write_time_ticks,
    })
}

/// Convert FILETIME ticks (100 ns since 1601) to Unix seconds.
pub(crate) fn crt_ticks_to_unix(ticks: u64) -> i64 {
    if ticks == 0 {
        return 0;
    }
    const WINDOWS_TO_UNIX_OFFSET: u64 = 11_644_473_600;
    let seconds = ticks / 10_000_000;
    (seconds.saturating_sub(WINDOWS_TO_UNIX_OFFSET)) as i64
}

/// Write a `struct _stat` (x86: st_dev u32@0, st_ino u16@4, st_mode u16@6,
/// st_nlink u16@8, st_uid u16@10, st_gid u16@12, st_rdev u32@14, st_size u32@18,
/// st_atime u32@22, st_mtime u32@26, st_ctime u32@30 — 34 bytes) or
/// `struct _stat64` (st_size/st_atime/st_mtime/st_ctime as i64 at 16/24/32/40 —
/// 48 bytes) into guest memory.
pub(crate) fn crt_write_stat(
    memory: &mut MemoryImage,
    stat_ptr: u64,
    info: &CrtStatInfo,
    wide64: bool,
) {
    let mode = if info.is_directory { S_IFDIR } else { S_IFREG }
        | if info.read_only {
            S_IREAD
        } else {
            S_IREAD | S_IWRITE
        };
    let mtime = crt_ticks_to_unix(info.last_write_time_ticks);
    let atime = crt_ticks_to_unix(info.last_access_time_ticks);
    let ctime = crt_ticks_to_unix(info.creation_time_ticks);
    if wide64 {
        // _stat64: st_dev u32 @0, st_ino u16 @4, st_mode u16 @6,
        // st_nlink u16 @8, st_uid u16 @10, st_gid u16 @12, st_rdev u32 @14,
        // st_size i64 @16, st_atime i64 @24, st_mtime i64 @32, st_ctime i64 @40.
        write_u32(memory, stat_ptr, 0);
        write_u16(memory, stat_ptr + 4, 0);
        write_u16(memory, stat_ptr + 6, mode as u16);
        write_u16(memory, stat_ptr + 8, 1);
        write_u16(memory, stat_ptr + 10, 0);
        write_u16(memory, stat_ptr + 12, 0);
        write_u32(memory, stat_ptr + 14, 0);
        write_u64(memory, stat_ptr + 16, info.size);
        write_u64(memory, stat_ptr + 24, atime as u64);
        write_u64(memory, stat_ptr + 32, mtime as u64);
        write_u64(memory, stat_ptr + 40, ctime as u64);
    } else {
        // _stat: st_dev u32 @0, st_ino u16 @4, st_mode u16 @6, st_nlink u16
        // @8, st_uid u16 @10, st_gid u16 @12, st_rdev u32 @14, st_size u32
        // @18, st_atime u32 @22, st_mtime u32 @26, st_ctime u32 @30.
        write_u32(memory, stat_ptr, 0);
        write_u16(memory, stat_ptr + 4, 0);
        write_u16(memory, stat_ptr + 6, mode as u16);
        write_u16(memory, stat_ptr + 8, 1);
        write_u16(memory, stat_ptr + 10, 0);
        write_u16(memory, stat_ptr + 12, 0);
        write_u32(memory, stat_ptr + 14, 0);
        write_u32(memory, stat_ptr + 18, info.size.min(u32::MAX as u64) as u32);
        write_u32(memory, stat_ptr + 22, atime as u32);
        write_u32(memory, stat_ptr + 26, mtime as u32);
        write_u32(memory, stat_ptr + 30, ctime as u32);
    }
}

/// Write a NUL-terminated narrow string into guest memory (used by
/// _splitpath-family thunks).
pub(crate) fn write_guest_c_str(memory: &mut MemoryImage, buffer: u64, value: &str) {
    if buffer == 0 {
        return;
    }
    memory.map_bytes(buffer, value.as_bytes());
    memory.write_u8(buffer + value.len() as u64, 0);
}

/// Write a NUL-terminated wide string into guest memory.
pub(crate) fn write_guest_wide_str(memory: &mut MemoryImage, buffer: u64, value: &str) {
    if buffer == 0 {
        return;
    }
    let bytes = value
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    memory.map_bytes(buffer, &bytes);
}

/// Windows `_splitpath` decomposition: drive ("C:"), directory (including
/// separators), filename, extension (including the leading '.').
pub(crate) fn crt_split_path(path: &str) -> (String, String, String, String) {
    let (drive, rest) = match windows_drive_prefix(path) {
        Some(prefix) => {
            let rest = &path[prefix.len()..];
            (prefix.to_string(), rest)
        }
        None => (String::new(), path),
    };
    // Locate the last separator after the drive.
    let separator = rest.rfind(['\\', '/']).map(|index| index + 1);
    let (dir, name_ext) = match separator {
        Some(index) => (rest[..index].to_string(), &rest[index..]),
        None => (String::new(), rest),
    };
    if name_ext == "." || name_ext == ".." {
        return (drive, dir, name_ext.to_string(), String::new());
    }
    let ext_start = name_ext.rfind('.');
    match ext_start {
        Some(index) => (
            drive,
            dir,
            name_ext[..index].to_string(),
            name_ext[index..].to_string(),
        ),
        None => (drive, dir, name_ext.to_string(), String::new()),
    }
}

/// Windows `_makepath` assembly: drive (adding ':' if absent), dir (adding a
/// trailing separator if non-empty and missing one), name, ext.  A bare
/// extension (without a leading '.') gets a '.' prepended: _makepath(buf,
/// "c", "dir", "file", "txt") → "c:dir\file.txt".
pub(crate) fn crt_make_path(drive: &str, dir: &str, name: &str, ext: &str) -> String {
    let mut out = String::new();
    if !drive.is_empty() {
        out.push_str(drive);
        if !out.ends_with(':') {
            out.push(':');
        }
    }
    if !dir.is_empty() {
        out.push_str(dir);
        if !out.ends_with(['\\', '/']) {
            out.push('\\');
        }
    }
    out.push_str(name);
    if !ext.is_empty() {
        if !ext.starts_with('.') {
            out.push('.');
        }
        out.push_str(ext);
    }
    out
}

/// strtol core (32-bit `long` on Windows): parses with base 0/2..=36, returns
/// (value, consumed_bytes, overflow).
pub(crate) fn crt_parse_strtol_full(bytes: &str, base: i32) -> (i64, usize, bool) {
    let bytes = bytes.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() && (bytes[index] as char).is_ascii_whitespace() {
        index += 1;
    }
    let mut negative = false;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        negative = bytes[index] == b'-';
        index += 1;
    }
    let mut base = base;
    let mut digits_start = index;
    if base == 0 {
        if index + 1 < bytes.len()
            && bytes[index] == b'0'
            && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X')
        {
            base = 16;
            index += 2;
            digits_start = index;
        } else if index < bytes.len() && bytes[index] == b'0' {
            base = 8;
        } else {
            base = 10;
        }
    } else if base == 16
        && index + 1 < bytes.len()
        && bytes[index] == b'0'
        && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X')
    {
        index += 2;
        digits_start = index;
    }
    let mut value: i64 = 0;
    let mut overflow = false;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'a'..=b'z' => bytes[index] - b'a' + 10,
            b'A'..=b'Z' => bytes[index] - b'A' + 10,
            _ => break,
        } as i64;
        if digit >= i64::from(base.max(2)) {
            break;
        }
        let next = value.saturating_mul(base as i64).saturating_add(digit);
        if next < value || next > i32::MAX as i64 {
            overflow = true;
        }
        value = next;
        index += 1;
    }
    if index == digits_start {
        // No conversion: consumed == 0 so callers write *endptr = nptr.
        return (0, 0, false);
    }
    (
        if negative {
            value.wrapping_neg()
        } else {
            value
        },
        index,
        overflow,
    )
}

/// _strtoi64 core: same parsing with 64-bit range clamping.
pub(crate) fn crt_parse_strtoll_full(bytes: &str, base: i32) -> (i64, usize, bool) {
    let bytes = bytes.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() && (bytes[index] as char).is_ascii_whitespace() {
        index += 1;
    }
    let mut negative = false;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        negative = bytes[index] == b'-';
        index += 1;
    }
    let mut base = base;
    let mut digits_start = index;
    if base == 0 {
        if index + 1 < bytes.len()
            && bytes[index] == b'0'
            && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X')
        {
            base = 16;
            index += 2;
            digits_start = index;
        } else if index < bytes.len() && bytes[index] == b'0' {
            base = 8;
        } else {
            base = 10;
        }
    } else if base == 16
        && index + 1 < bytes.len()
        && bytes[index] == b'0'
        && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X')
    {
        index += 2;
        digits_start = index;
    }
    let mut value: i64 = 0;
    let mut overflow = false;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'a'..=b'z' => bytes[index] - b'a' + 10,
            b'A'..=b'Z' => bytes[index] - b'A' + 10,
            _ => break,
        } as i64;
        if digit >= i64::from(base.max(2)) {
            break;
        }
        let (next, overflowing) = value.overflowing_mul(base as i64);
        let (next, overflowing_add) = next.overflowing_add(digit);
        if overflowing || overflowing_add {
            overflow = true;
            value = if negative { i64::MIN } else { i64::MAX };
            // Consume the remaining digits so endptr lands after them.
            index += 1;
            while index < bytes.len() {
                let digit = match bytes[index] {
                    b'0'..=b'9' => bytes[index] - b'0',
                    b'a'..=b'z' => bytes[index] - b'a' + 10,
                    b'A'..=b'Z' => bytes[index] - b'A' + 10,
                    _ => break,
                } as i64;
                if digit >= i64::from(base.max(2)) {
                    break;
                }
                index += 1;
            }
            break;
        }
        value = next;
        index += 1;
    }
    if index == digits_start {
        return (0, 0, false);
    }
    (
        if negative {
            value.wrapping_neg()
        } else {
            value
        },
        index,
        overflow,
    )
}

/// Simple strtol: parse with a fixed base, clamp at i32 range (strtol on
/// Windows is 32-bit), used by atoi/atol.
pub(crate) fn crt_parse_strtol(bytes: &str, base: i32, _end: Option<&mut usize>) -> i64 {
    let (value, _, overflow) = crt_parse_strtol_full(bytes, base);
    if overflow {
        if value < 0 {
            i32::MIN as i64
        } else {
            i32::MAX as i64
        }
    } else {
        value
    }
}

/// Minimal strtod (C locale): optional whitespace, sign, digits, '.',
/// exponent.  Also recognizes inf/infinity/nan and C99 hex floats
/// ("0x1p4" → 16.0).
pub(crate) fn crt_parse_strtod(bytes: &str) -> f64 {
    let bytes = bytes.trim_start();
    if bytes.is_empty() {
        return 0.0;
    }
    // inf / infinity / nan (with an optional leading sign), case-insensitive.
    let lower = bytes.to_ascii_lowercase();
    let magnitude = lower.trim_start_matches(['+', '-']);
    let negative = bytes.starts_with('-');
    if magnitude.starts_with("inf") {
        return if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    if magnitude.starts_with("nan") {
        return if negative { -f64::NAN } else { f64::NAN };
    }
    // C99 hex float ("0x1p4" → 16.0): parse manually since Rust's f64
    // parser has no hex-float support.  Falls through to the decimal path
    // when the string is not a well-formed hex float.
    if magnitude.starts_with("0x")
        && let Ok(value) = crt_parse_hex_float(bytes)
    {
        return value;
    }
    let mut index = 0_usize;
    if index < bytes.len() && (bytes.as_bytes()[index] == b'+' || bytes.as_bytes()[index] == b'-') {
        index += 1;
    }
    let start = index;
    while index < bytes.len() && bytes.as_bytes()[index].is_ascii_digit() {
        index += 1;
    }
    let mut has_dot = false;
    if index < bytes.len() && bytes.as_bytes()[index] == b'.' {
        has_dot = true;
        index += 1;
        while index < bytes.len() && bytes.as_bytes()[index].is_ascii_digit() {
            index += 1;
        }
    }
    let mut mantissa_end = index;
    let mut exponent = String::new();
    if index < bytes.len() && (bytes.as_bytes()[index] == b'e' || bytes.as_bytes()[index] == b'E') {
        // `index` points AT the 'e': the mantissa ends here, and the exponent
        // ('e' + optional sign + digits) is appended exactly once below.
        mantissa_end = index;
        let mut exp_index = index + 1;
        if exp_index < bytes.len()
            && (bytes.as_bytes()[exp_index] == b'+' || bytes.as_bytes()[exp_index] == b'-')
        {
            exp_index += 1;
        }
        if exp_index < bytes.len() && bytes.as_bytes()[exp_index].is_ascii_digit() {
            exponent = bytes[index..exp_index].to_string();
            index = exp_index;
            while index < bytes.len() && bytes.as_bytes()[index].is_ascii_digit() {
                index += 1;
            }
            exponent.push_str(&bytes[exp_index..index]);
        }
    }
    if mantissa_end == start && !has_dot {
        return 0.0;
    }
    let token = format!("{}{}", &bytes[..mantissa_end], exponent);
    token.parse::<f64>().unwrap_or(0.0)
}

/// Number of bytes a scanf float conversion consumes (C locale): optional
/// whitespace, sign, digits, '.', digits, exponent, the "inf"/"nan"
/// spellings and C99 hex floats ("0x1p4").  Returns 0 when the slice does
/// not start with a convertible float item.
pub(crate) fn crt_scan_float_consumed(bytes: &[u8]) -> usize {
    let mut index = 0_usize;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        index += 1;
    }
    let tail = &bytes[index..];
    let lower = tail
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    for word in ["infinity", "inf", "nan"] {
        if lower.starts_with(word.as_bytes()) {
            return index + word.len();
        }
    }
    // C99 hex float: "0x" + hex digits ['.' hex digits] ['p' sign digits].
    if bytes.get(index) == Some(&b'0') && matches!(bytes.get(index + 1), Some(b'x') | Some(b'X')) {
        let mut h = index + 2;
        let mut hex_digits = 0_usize;
        while h < bytes.len() && bytes[h].is_ascii_hexdigit() {
            h += 1;
            hex_digits += 1;
        }
        if h < bytes.len() && bytes[h] == b'.' {
            h += 1;
            while h < bytes.len() && bytes[h].is_ascii_hexdigit() {
                h += 1;
                hex_digits += 1;
            }
        }
        if hex_digits == 0 {
            return 0;
        }
        if h < bytes.len() && (bytes[h] == b'p' || bytes[h] == b'P') {
            let mut p = h + 1;
            if p < bytes.len() && (bytes[p] == b'+' || bytes[p] == b'-') {
                p += 1;
            }
            let mut exp_digits = 0_usize;
            while p < bytes.len() && bytes[p].is_ascii_digit() {
                p += 1;
                exp_digits += 1;
            }
            if exp_digits > 0 {
                h = p;
            }
        }
        return h;
    }
    // Decimal: digits ['.' digits] [('e'|'E') sign digits].
    let start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    let mut has_dot = false;
    if index < bytes.len() && bytes[index] == b'.' {
        has_dot = true;
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
    }
    if index == start && !has_dot {
        return 0;
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        let mut exp = index + 1;
        if exp < bytes.len() && (bytes[exp] == b'+' || bytes[exp] == b'-') {
            exp += 1;
        }
        if exp < bytes.len() && bytes[exp].is_ascii_digit() {
            index = exp;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
    }
    index
}

/// Parse a C99 hex float ("0x1p4" → 16.0, "0x1.8p-3" → 0.1875).  Returns
/// `Ok(value)` only for a well-formed hex float (leading "0x"/"0X" with a
/// mandatory 'p' exponent); anything else yields `Err` so the caller falls
/// back to decimal parsing.
pub(crate) fn crt_parse_hex_float(bytes: &str) -> Result<f64, ()> {
    let bytes = bytes.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() && (bytes[index] as char).is_ascii_whitespace() {
        index += 1;
    }
    let mut negative = false;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        negative = bytes[index] == b'-';
        index += 1;
    }
    if index + 1 >= bytes.len()
        || bytes[index] != b'0'
        || (bytes[index + 1] != b'x' && bytes[index + 1] != b'X')
    {
        return Err(());
    }
    index += 2;
    let hex_digit = |ch: u8| -> Option<u32> {
        match ch {
            b'0'..=b'9' => Some(u32::from(ch - b'0')),
            b'a'..=b'f' => Some(u32::from(ch - b'a' + 10)),
            b'A'..=b'F' => Some(u32::from(ch - b'A' + 10)),
            _ => None,
        }
    };
    let mut value = 0_u64;
    let mut frac_value = 0_u64;
    let mut frac_digits = 0_u32;
    let mut any_digit = false;
    while index < bytes.len()
        && let Some(digit) = hex_digit(bytes[index])
    {
        value = value.wrapping_mul(16).wrapping_add(u64::from(digit));
        any_digit = true;
        index += 1;
    }
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        while index < bytes.len()
            && let Some(digit) = hex_digit(bytes[index])
        {
            frac_value = frac_value.wrapping_mul(16).wrapping_add(u64::from(digit));
            frac_digits = frac_digits.saturating_add(1);
            any_digit = true;
            index += 1;
        }
    }
    if !any_digit || index >= bytes.len() || (bytes[index] != b'p' && bytes[index] != b'P') {
        return Err(());
    }
    index += 1;
    let mut exp_negative = false;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        exp_negative = bytes[index] == b'-';
        index += 1;
    }
    let mut exponent: i32 = 0;
    let mut exp_digits = false;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        exponent = exponent
            .saturating_mul(10)
            .saturating_add(i32::from(bytes[index] - b'0'));
        exp_digits = true;
        index += 1;
    }
    if !exp_digits {
        return Err(());
    }
    if exp_negative {
        exponent = -exponent;
    }
    let mut result = value as f64;
    if frac_digits > 0 {
        result += (frac_value as f64) / 16f64.powi(frac_digits as i32);
    }
    result *= 2f64.powi(exponent);
    Ok(if negative { -result } else { result })
}

pub(crate) fn crt_format_fixed(value: f64, precision: i32) -> Vec<u8> {
    if !value.is_finite() {
        return if value.is_nan() {
            b"nan".to_vec()
        } else {
            b"inf".to_vec()
        };
    }
    format!("{:.*}", precision.max(0) as usize, value).into_bytes()
}

pub(crate) fn crt_format_exponential(value: f64, precision: i32, uppercase: bool) -> Vec<u8> {
    if !value.is_finite() {
        return if value.is_nan() {
            b"nan".to_vec()
        } else {
            b"inf".to_vec()
        };
    }
    if value == 0.0 {
        let mut out = format!("0.{:0width$}", "", width = precision.max(0) as usize).into_bytes();
        out.push(if uppercase { b'E' } else { b'e' });
        out.extend_from_slice(b"+00");
        return out;
    }
    // Normalise to d.ddd… × 10^exp
    let mut exponent = value.log10().floor() as i32;
    let mut mantissa = value / 10f64.powi(exponent);
    let precision = precision.max(0) as usize;
    // Rounding can push the ROUNDED mantissa past 10 (e.g. 9.9999995 with
    // precision 2 → "10.00"): renormalise so the output is "1.00e+01",
    // never "10.00e+00".
    let rounded = format!("{:.*}", precision, mantissa)
        .parse::<f64>()
        .unwrap_or(0.0);
    if mantissa >= 10.0 || rounded >= 10.0 {
        mantissa /= 10.0;
        exponent += 1;
    }
    let mut out = format!("{:.*}", precision, mantissa).into_bytes();
    out.push(if uppercase { b'E' } else { b'e' });
    if exponent < 0 {
        out.push(b'-');
        exponent = exponent.saturating_abs();
    } else {
        out.push(b'+');
    }
    out.extend_from_slice(format!("{exponent:02}").as_bytes());
    out
}

pub(crate) fn crt_format_general(
    value: f64,
    precision: i32,
    uppercase: bool,
    hash: bool,
) -> Vec<u8> {
    if !value.is_finite() {
        return if value.is_nan() {
            b"nan".to_vec()
        } else {
            b"inf".to_vec()
        };
    }
    let precision = precision.max(1) as usize;
    if value == 0.0 {
        return vec![b'0'];
    }
    let exponent = value.abs().log10().floor() as i32;
    if exponent < -4 || exponent >= precision as i32 {
        // %e with precision-1.  With the '#' flag trailing zeros in the
        // mantissa are retained; otherwise they are stripped.
        let mut out =
            crt_format_exponential(value, (precision.saturating_sub(1)) as i32, uppercase);
        if let Some(e_pos) = out.iter().position(|byte| *byte == b'e' || *byte == b'E') {
            let mut mantissa = out[..e_pos].to_vec();
            if !hash {
                while mantissa.len() > 2 && mantissa.last() == Some(&b'0') {
                    mantissa.pop();
                }
            }
            let mut rest = out[e_pos..].to_vec();
            mantissa.append(&mut rest);
            out = mantissa;
        }
        out
    } else {
        // Fixed format.  With the '#' flag trailing zeros are retained:
        // "%#g" of 1.0 → "1.00000".
        let mut out = crt_format_fixed(value, (precision as i32 - exponent - 1).max(0));
        if !hash {
            while out.last() == Some(&b'0') {
                out.pop();
            }
            if out.last() == Some(&b'.') {
                out.pop();
            }
        }
        out
    }
}
