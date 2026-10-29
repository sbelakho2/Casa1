//! Guest path normalization helpers.

use super::*;

pub(crate) fn resolve_full_guest_path(current_directory: &str, path: &str) -> String {
    normalize_windows_path(&resolve_guest_path(current_directory, path))
}

pub(crate) fn resolve_guest_path(current_directory: &str, path: &str) -> String {
    if path.is_empty() {
        return current_directory.to_string();
    }
    if path.starts_with("\\\\") {
        return path.to_string();
    }
    if let Some(drive_prefix) = windows_drive_prefix(path) {
        let remainder = &path[2..];
        if remainder.is_empty() {
            // Drive-only path ("C:"): Windows resolves it to the per-drive
            // current directory (the CWD when the CWD is on that drive,
            // the drive root otherwise) — never unconditionally to the root.
            return drive_relative_base(current_directory, drive_prefix);
        }
        if remainder.starts_with(['\\', '/']) {
            let trimmed = remainder.trim_start_matches(['\\', '/']);
            return if trimmed.is_empty() {
                format!("{drive_prefix}\\")
            } else {
                format!("{drive_prefix}\\{trimmed}")
            };
        }
        let base = drive_relative_base(current_directory, drive_prefix);
        return format!("{}\\{}", base.trim_end_matches(['\\', '/']), remainder);
    }
    if path.starts_with(['\\', '/']) {
        let drive_prefix = windows_drive_prefix(current_directory).unwrap_or("C:");
        let trimmed = path.trim_start_matches(['\\', '/']);
        return if trimmed.is_empty() {
            format!("{drive_prefix}\\")
        } else {
            format!("{drive_prefix}\\{trimmed}")
        };
    }
    let base = current_directory.trim_end_matches(['\\', '/']);
    if base.is_empty() {
        format!("C:\\{}", path.trim_start_matches(['\\', '/']))
    } else {
        format!("{}\\{}", base, path.trim_start_matches(['\\', '/']))
    }
}

pub(crate) fn normalize_windows_path(path: &str) -> String {
    let normalized = path.replace('/', "\\");
    if normalized.starts_with("\\\\") {
        return normalize_unc_windows_path(&normalized);
    }
    if let Some(drive_prefix) = windows_drive_prefix(&normalized) {
        let mut segments = Vec::new();
        for segment in normalized[2..].split('\\') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                _ => segments.push(segment),
            }
        }
        return if segments.is_empty() {
            format!("{drive_prefix}\\")
        } else {
            format!("{drive_prefix}\\{}", segments.join("\\"))
        };
    }
    normalized
}

pub(crate) fn normalize_unc_windows_path(path: &str) -> String {
    let mut parts = path
        .trim_start_matches(['\\', '/'])
        .split(['\\', '/'])
        .filter(|part| !part.is_empty());
    let Some(server) = parts.next() else {
        return "\\\\".to_string();
    };
    let Some(share) = parts.next() else {
        return format!("\\\\{server}");
    };
    let mut segments = Vec::new();
    for segment in parts {
        match segment {
            "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    if segments.is_empty() {
        format!("\\\\{server}\\{share}")
    } else {
        format!("\\\\{server}\\{share}\\{}", segments.join("\\"))
    }
}

pub(crate) fn runtime_guest_path(ge: &GameEnvironment, host_path: &Path) -> String {
    for mapping in ge.active_drive_mappings() {
        let Ok(drive_root) = ge.host_path_for_windows_path(&format!("{}:\\", mapping.drive)) else {
            continue;
        };
        if let Ok(relative) = host_path.strip_prefix(&drive_root) {
            return runtime_windows_path_for_drive(&mapping.drive, relative);
        }
    }
    ge.normalize_host_path(host_path)
}

pub(crate) fn runtime_windows_path_for_drive(prefix: &str, relative: &Path) -> String {
    let mut pieces = Vec::new();
    for component in relative.components() {
        if let std::path::Component::Normal(value) = component {
            pieces.push(value.to_string_lossy().to_string());
        }
    }
    if pieces.is_empty() {
        format!("{prefix}:\\")
    } else {
        format!("{prefix}:\\{}", pieces.join("\\"))
    }
}

pub(crate) fn initial_guest_current_directory(
    ge: &GameEnvironment,
    host_cwd: &Path,
    guest_program_path: &str,
) -> String {
    let candidate = runtime_guest_path(ge, host_cwd);
    if is_windows_absolute_path(&candidate)
        && let Some(drive_prefix) = windows_drive_prefix(&candidate)
    {
        let drive = &drive_prefix[..1];
        if ge
            .active_drive_mappings()
            .iter()
            .any(|mapping| mapping.drive.eq_ignore_ascii_case(drive))
        {
            return candidate;
        }
    }
    windows_parent_path(guest_program_path).unwrap_or_else(|| "C:\\".to_string())
}

pub(crate) fn drive_relative_base(current_directory: &str, drive_prefix: &str) -> String {
    if let Some(current_drive) = windows_drive_prefix(current_directory)
        && current_drive.eq_ignore_ascii_case(drive_prefix)
    {
        let trimmed = current_directory.trim_end_matches(['\\', '/']);
        return if trimmed.len() <= 2 {
            format!("{drive_prefix}\\")
        } else {
            trimmed.to_string()
        };
    }
    format!("{drive_prefix}\\")
}

pub(crate) fn windows_parent_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if let Some(drive_prefix) = windows_drive_prefix(trimmed) {
        let remainder = &trimmed[2..];
        if remainder.is_empty() || remainder == "\\" {
            return Some(format!("{drive_prefix}\\"));
        }
    }
    let separator = trimmed.rfind(['\\', '/'])?;
    if separator == 2 && windows_drive_prefix(trimmed).is_some() {
        Some(trimmed[..=separator].to_string())
    } else {
        Some(trimmed[..separator].to_string())
    }
}

pub(crate) fn windows_file_part_offset(path: &str) -> Option<u64> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return None;
    }
    let component_start = match trimmed.rfind(['\\', '/']) {
        Some(index) => index + 1,
        None if windows_drive_prefix(trimmed).is_some() => return None,
        None => 0,
    };
    Some((path[..component_start].encode_utf16().count() * 2) as u64)
}

pub(crate) fn windows_drive_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(&path[..2])
    } else {
        None
    }
}

pub(crate) fn normalize_module_name(module_name: &str) -> String {
    let module_name = module_name.replace('\\', "/");
    let file_name = Path::new(&module_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(module_name.as_str())
        .trim();
    let normalized = file_name.to_ascii_lowercase();
    if normalized.is_empty() {
        String::new()
    } else if normalized.contains('.') {
        normalized
    } else {
        format!("{normalized}.dll")
    }
}

/// Read the TimeDateStamp from a PE file's IMAGE_FILE_HEADER (at file offset 0x08)
/// and compare it against the expected bound import timestamp.
///
/// Bound imports embed the expected DLL timestamp at link time. If the on-disk
/// DLL still has the same timestamp, the bound IAT values are still valid.
pub(crate) fn check_dll_timestamp(host_path: &Path, expected_timestamp: u32) -> bool {
    use std::fs;
    let bytes = match fs::read(host_path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() < 0x40 {
        return false;
    }
    // Read e_lfanew at offset 0x3C
    let pe_offset = match bytes.get(0x3C..0x40) {
        Some(slice) => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize,
        None => return false,
    };
    if pe_offset + 8 >= bytes.len() {
        return false;
    }
    // PE signature is at pe_offset, machine at +4, numberOfSections at +6
    // TimeDateStamp is at pe_offset + 8 (4 bytes)
    let timestamp_bytes = match bytes.get(pe_offset + 8..pe_offset + 12) {
        Some(slice) => slice,
        None => return false,
    };
    let actual_timestamp = u32::from_le_bytes([
        timestamp_bytes[0],
        timestamp_bytes[1],
        timestamp_bytes[2],
        timestamp_bytes[3],
    ]);
    actual_timestamp == expected_timestamp
}

pub(crate) fn locale_name_to_lcid(locale_name: &str) -> Option<u32> {
    let normalized = locale_name.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "en" | "en-us" | "english" | "!x-user-default-locale" | "!x-sys-default-locale" => {
            Some(LOCALE_EN_US)
        }
        _ if normalized.starts_with("en-") => Some(LOCALE_EN_US),
        _ => None,
    }
}

/// Delegates to the canonical implementation in [`crate::error::ntstatus_to_dos_error`].
pub(crate) fn ntstatus_to_dos_error(status: u32) -> u32 {
    crate::error::ntstatus_to_dos_error(status)
}

pub(crate) fn is_windows_absolute_path(path: &str) -> bool {
    path.starts_with("\\\\")
        || matches!(path.as_bytes(), [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
}

pub(crate) fn shell_special_folder_path(
    user_name: &str,
    raw_csidl: i32,
    guest_arch: GuestArch,
) -> Option<String> {
    let csidl = raw_csidl & 0x00ff;
    let user_root = format!("C:\\users\\{user_name}");
    let roaming = format!("{user_root}\\AppData\\Roaming");
    let local = format!("{user_root}\\AppData\\Local");
    let program_files = if guest_arch == GuestArch::X86 {
        "C:\\Program Files (x86)"
    } else {
        "C:\\Program Files"
    };
    let path = match csidl {
        CSIDL_DESKTOP | CSIDL_DESKTOPDIRECTORY => format!("{user_root}\\Desktop"),
        CSIDL_PROGRAMS => format!("{roaming}\\Microsoft\\Windows\\Start Menu\\Programs"),
        CSIDL_PERSONAL => format!("{user_root}\\Documents"),
        CSIDL_FAVORITES => format!("{user_root}\\Favorites"),
        CSIDL_STARTUP => format!("{roaming}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        CSIDL_RECENT => format!("{user_root}\\Recent"),
        CSIDL_SENDTO => format!("{user_root}\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"),
        CSIDL_STARTMENU => format!("{roaming}\\Microsoft\\Windows\\Start Menu"),
        CSIDL_NETHOOD => format!("{roaming}\\Microsoft\\Windows\\Network Shortcuts"),
        CSIDL_FONTS => "C:\\Windows\\Fonts".to_string(),
        CSIDL_TEMPLATES => format!("{roaming}\\Microsoft\\Windows\\Templates"),
        CSIDL_APPDATA => roaming,
        CSIDL_LOCAL_APPDATA => local,
        CSIDL_INTERNET_CACHE => format!("{local}\\Microsoft\\Windows\\INetCache"),
        CSIDL_COOKIES => format!("{local}\\Microsoft\\Windows\\INetCookies"),
        CSIDL_HISTORY => format!("{local}\\Microsoft\\Windows\\History"),
        CSIDL_COMMON_APPDATA => "C:\\ProgramData".to_string(),
        CSIDL_WINDOWS => "C:\\Windows".to_string(),
        CSIDL_SYSTEM | CSIDL_SYSTEMX86 => "C:\\Windows\\System32".to_string(),
        CSIDL_PROGRAM_FILES => program_files.to_string(),
        CSIDL_MYPICTURES => format!("{user_root}\\Pictures"),
        CSIDL_PROFILE => user_root,
        CSIDL_PROGRAM_FILESX86 => "C:\\Program Files (x86)".to_string(),
        CSIDL_COMMON_TEMPLATES => "C:\\ProgramData\\Microsoft\\Windows\\Templates".to_string(),
        CSIDL_COMMON_DOCUMENTS => "C:\\Users\\Public\\Documents".to_string(),
        CSIDL_COMMON_ADMINTOOLS => {
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"
                .to_string()
        }
        CSIDL_ADMINTOOLS => {
            format!("{roaming}\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools")
        }
        _ => return None,
    };
    Some(path)
}
