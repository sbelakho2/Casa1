//! The Windows shell-link (.lnk) binary format.
//!
//! This module is the single writer AND reader for the shortcut files the
//! runtime persists: the `IPersistFile::Save` surface of the IShellLink COM
//! objects and the `SHCreateLinks` export both encode through
//! [`encode`], and [`parse`] reads a link back (tests round-trip the
//! exact bytes the runtime writes).
//!
//! Layout (MS-SHLLINK, [MS-SHLLINK] 2.3 "ShellLinkHeader" and friends):
//!
//! ```text
//! 0x00  u32    HeaderSize           = 0x0000004C
//! 0x04  GUID   LinkCLSID            = {00021401-0000-0000-C000-000000000046}
//! 0x14  u32    LinkFlags            (see below)
//! 0x18  u32    FileAttributes       (FILE_ATTRIBUTE_* mask of the target)
//! 0x1C  i64    CreationTime         (FILETIME 100 ns since 1601; 0 when unknown)
//! 0x24  i64    AccessTime           (ditto)
//! 0x2C  i64    WriteTime            (the target's last write time)
//! 0x34  u32    FileSize             (target byte size; 0 for directories)
//! 0x38  i32    IconIndex
//! 0x3C  u32    ShowCommand          (SW_SHOWNORMAL etc.)
//! 0x40  u16    HotKey
//! 0x42  u16    Reserved1            (0)
//! 0x44  u32    Reserved2            (0)
//! 0x48  u32    Reserved3            (0)     — header ends at 0x4C
//!
//! [optional]  LinkTargetIDList      — only when LinkFlags & HasLinkTargetIDList
//! [optional]  LinkInfo              — only when LinkFlags & HasLinkInfo
//! [optional]  StringData            — the flag-gated Unicode strings:
//!             NAME_STRING (HasName), RELATIVE_PATH (HasRelativePath),
//!             WORKING_DIR (HasWorkingDir), COMMAND_LINE_ARGUMENTS
//!             (HasArguments), ICON_LOCATION (HasIconLocation), each a
//!             u16 character count followed by that many UTF-16 code units
//!             (not null-terminated; real Windows pads an odd unit count to
//!             a 4-byte boundary — the parser accepts the padding).
//! ```
//!
//! The writer models a link that carries its target path inside `LinkInfo`
//! (header + volume ID + the ANSI/Unicode local base path and common path
//! suffix pairs), which is the form Windows itself writes for local
//! targets.  LinkFlags written: `HasLinkInfo | IsUnicode` plus the
//! per-member flags for every string the caller supplies.
//!
//! Known model bounds (documented rather than hidden): the "ANSI" local
//! base path is written as the UTF-8 bytes of the guest path (the runtime
//! has no ANSI code page; ASCII guest paths — the Windows filesystem
//! convention — are byte-identical either way), the creation/access
//! FILETIMEs are not tracked by the runtime (0), and the volume serial is
//! not known (0).  [`parse`] reads the ANSI strings back lossily so the
//! runtime's own files round-trip exactly.

/// The header-size field value of a shell link.
const SHELL_LINK_HEADER_SIZE: u32 = 0x0000_004C;
/// The LinkCLSID of every shell link: {00021401-0000-0000-C000-000000000046}.
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// LinkFlags: a LinkTargetIDList follows the header.
#[cfg(test)]
const LINK_FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
/// LinkFlags: a LinkInfo structure follows the (optional) ID list.
const LINK_FLAG_HAS_LINK_INFO: u32 = 0x0000_0002;
/// LinkFlags: StringData begins with a NAME_STRING.
const LINK_FLAG_HAS_NAME: u32 = 0x0000_0004;
/// LinkFlags: StringData contains a RELATIVE_PATH string.
#[cfg(test)]
const LINK_FLAG_HAS_RELATIVE_PATH: u32 = 0x0000_0008;
/// LinkFlags: StringData contains a WORKING_DIR string.
const LINK_FLAG_HAS_WORKING_DIR: u32 = 0x0000_0010;
/// LinkFlags: StringData contains COMMAND_LINE_ARGUMENTS.
const LINK_FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;
/// LinkFlags: StringData contains an ICON_LOCATION string.
const LINK_FLAG_HAS_ICON_LOCATION: u32 = 0x0000_0040;
/// LinkFlags: the StringData strings are UTF-16 (Unicode).
const LINK_FLAG_IS_UNICODE: u32 = 0x0000_0080;

/// The LinkInfo header size this writer emits.
const LINK_INFO_HEADER_SIZE: u32 = 0x24;
/// LinkInfo flags: the structure carries a volume ID and a local base path.
const LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x0000_0001;
/// The drive type written into the volume ID: DRIVE_FIXED.
const DRIVE_FIXED: u32 = 3;
/// FILE_ATTRIBUTE_NORMAL (used when the caller reports no attributes).
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// SW_SHOWNORMAL (the show command written for a link whose caller did not
/// pick one).
const SW_SHOWNORMAL: i32 = 1;

/// The full set of string payloads one link can carry.
#[derive(Debug, Clone, Default)]
pub(crate) struct ShellLinkData {
    /// The Windows path of the link target (used for the LinkInfo volume +
    /// local base/common suffix pair; written into the header metadata
    /// resolution is done by the caller).
    pub target_path: String,
    /// NAME_STRING (the shortcut's description / display name).
    pub description: String,
    /// WORKING_DIR string.
    pub working_directory: String,
    /// COMMAND_LINE_ARGUMENTS string.
    pub arguments: String,
    /// ICON_LOCATION string.
    pub icon_location: String,
    /// ICON_LOCATION index.
    pub icon_index: i32,
    /// The show command (SW_SHOWNORMAL/SW_SHOWMINIMIZED/...); 0 is
    /// normalized to SW_SHOWNORMAL exactly like the Windows shell does.
    pub show_cmd: i32,
    /// FILE_ATTRIBUTE_* mask of the target.
    pub file_attributes: u32,
    /// The target file size in bytes (0 when the target is a directory or
    /// its size is unknown).
    pub file_size: u32,
    /// The target's last write time in FILETIME ticks (100 ns since
    /// 1601-01-01); 0 when unknown.
    pub write_time_ticks: u64,
}

/// The result of parsing a shell-link byte stream.
///
/// The parser is test-facing (`cfg(test)`): the runtime never reads .lnk
/// files back — `parse` exists to verify the links `encode`/`SHCreateLinks`
/// persist, in the module's round-trip tests and the runtime dispatch
/// tests.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedShellLink {
    /// The LinkFlags from the header.
    pub link_flags: u32,
    /// The FILE_ATTRIBUTE_* mask of the target.
    pub file_attributes: u32,
    /// The target's last write time in FILETIME ticks.
    pub write_time_ticks: u64,
    /// The target file size in bytes.
    pub file_size: u32,
    /// The icon index.
    pub icon_index: i32,
    /// The show command.
    pub show_cmd: i32,
    /// The hotkey.
    pub hotkey: u16,
    /// NAME_STRING (present when HasName).
    pub description: Option<String>,
    /// RELATIVE_PATH string (present when HasRelativePath).
    pub relative_path: Option<String>,
    /// WORKING_DIR string (present when HasWorkingDir).
    pub working_directory: Option<String>,
    /// COMMAND_LINE_ARGUMENTS (present when HasArguments).
    pub arguments: Option<String>,
    /// ICON_LOCATION (present when HasIconLocation).
    pub icon_location: Option<String>,
    /// The reconstructed target path (present when the link carries a
    /// LinkInfo with a local base path).
    pub target_path: Option<String>,
}

/// Encode a shell-link byte stream (see the module documentation for the
/// layout).  String members are flag-gated; empty strings are omitted.
pub(crate) fn encode(data: &ShellLinkData) -> Vec<u8> {
    let mut link_flags = LINK_FLAG_HAS_LINK_INFO | LINK_FLAG_IS_UNICODE;
    if !data.description.is_empty() {
        link_flags |= LINK_FLAG_HAS_NAME;
    }
    if !data.working_directory.is_empty() {
        link_flags |= LINK_FLAG_HAS_WORKING_DIR;
    }
    if !data.arguments.is_empty() {
        link_flags |= LINK_FLAG_HAS_ARGUMENTS;
    }
    if !data.icon_location.is_empty() {
        link_flags |= LINK_FLAG_HAS_ICON_LOCATION;
    }

    let file_attributes = if data.file_attributes == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        data.file_attributes
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SHELL_LINK_HEADER_SIZE.to_le_bytes());
    bytes.extend_from_slice(&LINK_CLSID);
    bytes.extend_from_slice(&link_flags.to_le_bytes());
    bytes.extend_from_slice(&file_attributes.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes()); // CreationTime
    bytes.extend_from_slice(&0_u64.to_le_bytes()); // AccessTime
    bytes.extend_from_slice(&data.write_time_ticks.to_le_bytes());
    bytes.extend_from_slice(&data.file_size.to_le_bytes());
    bytes.extend_from_slice(&data.icon_index.to_le_bytes());
    let show_cmd = if data.show_cmd == 0 {
        SW_SHOWNORMAL
    } else {
        data.show_cmd
    };
    bytes.extend_from_slice(&show_cmd.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes()); // HotKey
    bytes.extend_from_slice(&0_u16.to_le_bytes()); // Reserved1
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // Reserved2
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // Reserved3
    bytes.extend_from_slice(&encode_link_info(&data.target_path));
    if !data.description.is_empty() {
        append_string_data(&mut bytes, &data.description);
    }
    if !data.working_directory.is_empty() {
        append_string_data(&mut bytes, &data.working_directory);
    }
    if !data.arguments.is_empty() {
        append_string_data(&mut bytes, &data.arguments);
    }
    if !data.icon_location.is_empty() {
        append_string_data(&mut bytes, &data.icon_location);
    }
    bytes
}

/// Parse a shell-link byte stream back into its fields.  Returns `None`
/// when the stream is not a structurally valid shell link (wrong header
/// size, wrong CLSID, truncated members, corrupt offsets).
#[cfg(test)]
pub(crate) fn parse(bytes: &[u8]) -> Option<ParsedShellLink> {
    if bytes.len() < 76 {
        return None;
    }
    if u32::from_le_bytes(bytes[0..4].try_into().ok()?) != SHELL_LINK_HEADER_SIZE {
        return None;
    }
    if bytes[4..20] != LINK_CLSID {
        return None;
    }
    let link_flags = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let file_attributes = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
    let write_time_ticks = u64::from_le_bytes(bytes[44..52].try_into().ok()?);
    let file_size = u32::from_le_bytes(bytes[52..56].try_into().ok()?);
    let icon_index = i32::from_le_bytes(bytes[56..60].try_into().ok()?);
    let show_cmd = u32::from_le_bytes(bytes[60..64].try_into().ok()?) as i32;
    let hotkey = u16::from_le_bytes(bytes[64..66].try_into().ok()?);

    let mut cursor = 76usize;
    let mut link_info: Option<(usize, usize)> = None; // (start, end) of LinkInfo

    if link_flags & LINK_FLAG_HAS_LINK_TARGET_ID_LIST != 0 {
        // u16 cbIDList followed by the ID list (byte-aligned).
        if cursor + 2 > bytes.len() {
            return None;
        }
        let id_list_size = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().ok()?) as usize;
        cursor = cursor.checked_add(2)?.checked_add(id_list_size)?;
        if cursor > bytes.len() {
            return None;
        }
    }
    if link_flags & LINK_FLAG_HAS_LINK_INFO != 0 {
        if cursor + 4 > bytes.len() {
            return None;
        }
        let link_info_size =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().ok()?) as usize;
        let info_start = cursor;
        let info_end = cursor.checked_add(link_info_size)?;
        if info_end > bytes.len() {
            return None;
        }
        cursor = info_end;
        link_info = Some((info_start, info_end));
    }

    // StringData.
    let mut description = None;
    let mut relative_path = None;
    let mut working_directory = None;
    let mut arguments = None;
    let mut icon_location = None;
    if link_flags & LINK_FLAG_IS_UNICODE != 0 {
        if link_flags & LINK_FLAG_HAS_NAME != 0 {
            let (value, next) = read_string_data(bytes, cursor)?;
            description = Some(value);
            cursor = next;
        }
        if link_flags & LINK_FLAG_HAS_RELATIVE_PATH != 0 {
            let (value, next) = read_string_data(bytes, cursor)?;
            relative_path = Some(value);
            cursor = next;
        }
        if link_flags & LINK_FLAG_HAS_WORKING_DIR != 0 {
            let (value, next) = read_string_data(bytes, cursor)?;
            working_directory = Some(value);
            cursor = next;
        }
        if link_flags & LINK_FLAG_HAS_ARGUMENTS != 0 {
            let (value, next) = read_string_data(bytes, cursor)?;
            arguments = Some(value);
            cursor = next;
        }
        if link_flags & LINK_FLAG_HAS_ICON_LOCATION != 0 {
            let (value, _next) = read_string_data(bytes, cursor)?;
            icon_location = Some(value);
        }
    }

    // The target path lives in the LinkInfo local-base/common-suffix pair.
    let target_path = link_info.and_then(|(start, end)| parse_link_info_target(bytes, start, end));

    Some(ParsedShellLink {
        link_flags,
        file_attributes,
        write_time_ticks,
        file_size,
        icon_index,
        show_cmd,
        hotkey,
        description,
        relative_path,
        working_directory,
        arguments,
        icon_location,
        target_path,
    })
}

/// Reconstruct the link target from the LinkInfo local-base/common-suffix
/// path pair.
#[cfg(test)]
fn parse_link_info_target(bytes: &[u8], start: usize, end: usize) -> Option<String> {
    if end < start + 0x24 {
        return None;
    }
    let info = &bytes[start..end];
    let header_size = u32::from_le_bytes(info[4..8].try_into().ok()?) as usize;
    if header_size > info.len() {
        return None;
    }
    let local_base_ansi_offset = u32::from_le_bytes(info[16..20].try_into().ok()?) as usize;
    let common_suffix_ansi_offset = u32::from_le_bytes(info[24..28].try_into().ok()?) as usize;
    let local_base_unicode_offset = u32::from_le_bytes(info[28..32].try_into().ok()?) as usize;
    let common_suffix_unicode_offset = u32::from_le_bytes(info[32..36].try_into().ok()?) as usize;
    let base = if local_base_unicode_offset != 0 {
        read_link_info_utf16(info, local_base_unicode_offset)?
    } else if local_base_ansi_offset != 0 {
        read_link_info_ansi(info, local_base_ansi_offset)?
    } else {
        return None;
    };
    let suffix = if common_suffix_unicode_offset != 0 {
        read_link_info_utf16(info, common_suffix_unicode_offset)
    } else if common_suffix_ansi_offset != 0 {
        read_link_info_ansi(info, common_suffix_ansi_offset)
    } else {
        None
    };
    match suffix {
        Some(suffix) => {
            let separator = if base.ends_with('\\') { "" } else { "\\" };
            Some(format!("{base}{separator}{suffix}"))
        }
        None => Some(base),
    }
}

/// Read a null-terminated ANSI (byte) string out of a LinkInfo, bounded by
/// the LinkInfo size.  The runtime's writer stores the UTF-8 bytes of the
/// guest path in this slot (there is no ANSI code page); Windows-native
/// files are decoded lossily.
#[cfg(test)]
fn read_link_info_ansi(info: &[u8], offset: usize) -> Option<String> {
    if offset >= info.len() {
        return None;
    }
    let mut end = offset;
    while end < info.len() && info[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&info[offset..end]).into_owned())
}

/// Read a null-terminated UTF-16 string out of a LinkInfo.
#[cfg(test)]
fn read_link_info_utf16(info: &[u8], offset: usize) -> Option<String> {
    let mut end = offset;
    loop {
        if end + 2 > info.len() {
            return None;
        }
        let unit = u16::from_le_bytes([info[end], info[end + 1]]);
        if unit == 0 {
            break;
        }
        end += 2;
    }
    let mut units = Vec::with_capacity((end - offset) / 2);
    for chunk in info[offset..end].as_chunks::<2>().0 {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Some(String::from_utf16_lossy(&units))
}

/// Read one StringData member (u16 character count + UTF-16 units) and the
/// cursor position after it (consuming the 4-byte-alignment padding real
/// Windows appends after an odd unit count, when present).
#[cfg(test)]
fn read_string_data(bytes: &[u8], cursor: usize) -> Option<(String, usize)> {
    if cursor + 2 > bytes.len() {
        return None;
    }
    let count = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().ok()?) as usize;
    let mut next = cursor.checked_add(2)?.checked_add(count.checked_mul(2)?)?;
    if next > bytes.len() {
        return None;
    }
    let mut units = Vec::with_capacity(count);
    for chunk in bytes[cursor + 2..next].as_chunks::<2>().0 {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let value = String::from_utf16_lossy(&units);
    if count % 2 == 1 && bytes.len() >= next + 2 && bytes[next] == 0 && bytes[next + 1] == 0 {
        // Windows pads the string to a 4-byte boundary; the runtime's own
        // writer omits the padding, so only consume genuine zero padding.
        let peek = u16::from_le_bytes([bytes[next], bytes[next + 1]]);
        if peek == 0 {
            next += 2;
        }
    }
    Some((value, next))
}

/// The LinkInfo body: header, volume ID, and the local base/common suffix
/// strings the LinkInfo layout defines.
fn encode_link_info(target_path: &str) -> Vec<u8> {
    let normalized = normalize_windows_path(target_path);
    let (local_base_path, common_path_suffix) =
        if let Some((parent, leaf)) = normalized.rsplit_once('\\') {
            let base = format!("{parent}\\");
            (base, leaf.to_string())
        } else {
            (normalized.clone(), String::new())
        };
    let local_base_path_ansi = local_base_path.as_bytes().to_vec();
    let common_path_suffix_ansi = common_path_suffix.as_bytes().to_vec();
    let local_base_path_unicode = encode_utf16_terminated(&local_base_path);
    let common_path_suffix_unicode = encode_utf16_terminated(&common_path_suffix);
    let volume_id = encode_volume_id(&normalized);

    let volume_id_offset = 0x24_u32;
    let local_base_path_offset = volume_id_offset + volume_id.len() as u32;
    let common_path_suffix_offset = local_base_path_offset + local_base_path_ansi.len() as u32 + 1;
    let local_base_path_offset_unicode =
        common_path_suffix_offset + common_path_suffix_ansi.len() as u32 + 1;
    let common_path_suffix_offset_unicode =
        local_base_path_offset_unicode + local_base_path_unicode.len() as u32;
    let link_info_size =
        common_path_suffix_offset_unicode + common_path_suffix_unicode.len() as u32;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&link_info_size.to_le_bytes());
    bytes.extend_from_slice(&LINK_INFO_HEADER_SIZE.to_le_bytes());
    bytes.extend_from_slice(&LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH.to_le_bytes());
    bytes.extend_from_slice(&volume_id_offset.to_le_bytes());
    bytes.extend_from_slice(&local_base_path_offset.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&common_path_suffix_offset.to_le_bytes());
    bytes.extend_from_slice(&local_base_path_offset_unicode.to_le_bytes());
    bytes.extend_from_slice(&common_path_suffix_offset_unicode.to_le_bytes());
    bytes.extend_from_slice(&volume_id);
    bytes.extend_from_slice(&local_base_path_ansi);
    bytes.push(0);
    bytes.extend_from_slice(&common_path_suffix_ansi);
    bytes.push(0);
    bytes.extend_from_slice(&local_base_path_unicode);
    bytes.extend_from_slice(&common_path_suffix_unicode);
    bytes
}

/// The volume ID of the LinkInfo: size, drive type, serial (unknown: 0),
/// label offset, and the drive-letter label.
fn encode_volume_id(path: &str) -> Vec<u8> {
    let volume_label = windows_drive_prefix(path)
        .map(|prefix| prefix.trim_end_matches(':').as_bytes().to_vec())
        .unwrap_or_else(|| b"C".to_vec());
    let volume_id_size = 0x10_u32 + volume_label.len() as u32 + 1;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&volume_id_size.to_le_bytes());
    bytes.extend_from_slice(&DRIVE_FIXED.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0x10_u32.to_le_bytes());
    bytes.extend_from_slice(&volume_label);
    bytes.push(0);
    bytes
}

/// One StringData member: u16 character count + the UTF-16 code units.
fn append_string_data(bytes: &mut Vec<u8>, value: &str) {
    let code_units = value.encode_utf16().collect::<Vec<_>>();
    bytes.extend_from_slice(&(code_units.len() as u16).to_le_bytes());
    for code_unit in code_units {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
}

/// UTF-16 bytes with a null terminator (LinkInfo string form).
fn encode_utf16_terminated(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

/// Collapse a guest Windows path: forward slashes become backslashes,
/// drive-relative and UNC paths are normalized (`.` and `..` segments
/// resolved), trailing separators removed.
fn normalize_windows_path(path: &str) -> String {
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

fn normalize_unc_windows_path(path: &str) -> String {
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

/// The drive designator (`C:`) at the front of an absolute Windows path.
fn windows_drive_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(&path[..2])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> ShellLinkData {
        ShellLinkData {
            target_path: "C:\\Program Files (x86)\\Steam\\Steam.exe".to_string(),
            description: "Steam".to_string(),
            working_directory: "C:\\Program Files (x86)\\Steam".to_string(),
            arguments: "-silent".to_string(),
            icon_location: "C:\\Program Files (x86)\\Steam\\Steam.exe".to_string(),
            icon_index: 0,
            show_cmd: SW_SHOWNORMAL,
            file_attributes: FILE_ATTRIBUTE_NORMAL,
            file_size: 0x1_2345,
            write_time_ticks: 0x01D4_0000_0000_0000,
        }
    }

    #[test]
    fn header_and_flags_layout() {
        let data = ShellLinkData {
            target_path: "C:\\Games\\game.exe".to_string(),
            description: "Game".to_string(),
            ..ShellLinkData::default()
        };
        let bytes = encode(&data);
        // Header size + shell-link CLSID.
        assert_eq!(&bytes[0..4], &0x4C_u32.to_le_bytes());
        assert_eq!(&bytes[4..20], &LINK_CLSID);
        // HasLinkInfo | IsUnicode | HasName.
        assert_eq!(
            &bytes[20..24],
            &(LINK_FLAG_HAS_LINK_INFO | LINK_FLAG_IS_UNICODE | LINK_FLAG_HAS_NAME).to_le_bytes()
        );
        // FILE_ATTRIBUTE_NORMAL, zero times, write time, file size.
        assert_eq!(&bytes[24..28], &FILE_ATTRIBUTE_NORMAL.to_le_bytes());
        assert_eq!(&bytes[44..52], &0_u64.to_le_bytes());
        assert_eq!(&bytes[52..56], &0_u32.to_le_bytes());
        // Show command 1, zero hotkey/reserved fields → header is 76 bytes.
        assert_eq!(&bytes[60..64], &1_u32.to_le_bytes());
        // LinkInfo begins at 76: its own header carries size 0x24 and the
        // VolumeIDAndLocalBasePath flag.
        assert_ne!(&bytes[76..80], &0_u32.to_le_bytes(), "LinkInfo has a size");
        assert_eq!(
            &bytes[80..84],
            &0x24_u32.to_le_bytes(),
            "LinkInfo header size"
        );
        assert_eq!(
            &bytes[84..88],
            &LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH.to_le_bytes()
        );
    }

    #[test]
    fn round_trip_full_data() {
        let data = sample_data();
        let bytes = encode(&data);
        let parsed = parse(&bytes).expect("parse the encoded link");
        assert_eq!(
            parsed.link_flags & LINK_FLAG_HAS_LINK_INFO,
            LINK_FLAG_HAS_LINK_INFO
        );
        assert_eq!(
            parsed.link_flags & LINK_FLAG_IS_UNICODE,
            LINK_FLAG_IS_UNICODE
        );
        assert_eq!(parsed.file_attributes, FILE_ATTRIBUTE_NORMAL);
        assert_eq!(parsed.write_time_ticks, data.write_time_ticks);
        assert_eq!(parsed.file_size, 0x1_2345);
        assert_eq!(parsed.show_cmd, SW_SHOWNORMAL);
        assert_eq!(parsed.description.as_deref(), Some("Steam"));
        assert_eq!(
            parsed.working_directory.as_deref(),
            Some("C:\\Program Files (x86)\\Steam")
        );
        assert_eq!(parsed.arguments.as_deref(), Some("-silent"));
        assert_eq!(
            parsed.icon_location.as_deref(),
            Some("C:\\Program Files (x86)\\Steam\\Steam.exe")
        );
        assert_eq!(
            parsed.target_path.as_deref(),
            Some("C:\\Program Files (x86)\\Steam\\Steam.exe")
        );
    }

    #[test]
    fn link_only_with_target_round_trips() {
        let data = ShellLinkData {
            target_path: "C:\\Games\\game.exe".to_string(),
            file_attributes: 0x20, // archive
            file_size: 4096,
            write_time_ticks: 77,
            ..ShellLinkData::default()
        };
        let bytes = encode(&data);
        let parsed = parse(&bytes).expect("parse");
        assert_eq!(parsed.target_path.as_deref(), Some("C:\\Games\\game.exe"));
        assert_eq!(parsed.file_attributes, 0x20);
        assert_eq!(parsed.file_size, 4096);
        assert_eq!(parsed.write_time_ticks, 77);
        assert!(parsed.description.is_none());
        assert!(parsed.working_directory.is_none());
        assert!(parsed.arguments.is_none());
        assert!(parsed.icon_location.is_none());
    }

    #[test]
    fn directory_target_round_trips() {
        let data = ShellLinkData {
            target_path: "C:\\Users\\casa1\\Desktop".to_string(),
            ..ShellLinkData::default()
        };
        let parsed = parse(&encode(&data)).expect("parse");
        assert_eq!(
            parsed.target_path.as_deref(),
            Some("C:\\Users\\casa1\\Desktop")
        );
    }

    #[test]
    fn odd_length_strings_round_trip_with_and_without_padding() {
        // "a" (1 unit — odd) followed by more StringData.
        let mut data = ShellLinkData {
            target_path: "C:\\x\\y.exe".to_string(),
            description: "a".to_string(),
            working_directory: "b".to_string(),
            ..ShellLinkData::default()
        };
        let bytes = encode(&data);
        let parsed = parse(&bytes).expect("parse the unpadded stream");
        assert_eq!(parsed.description.as_deref(), Some("a"));
        assert_eq!(parsed.working_directory.as_deref(), Some("b"));

        // A Windows writer pads each odd-count string to a 4-byte
        // boundary; the parser must accept that form too.  Rebuild the
        // byte stream with the padding inserted after each odd string.
        data.description = "Steam".to_string();
        data.working_directory = "C:\\x".to_string();
        let bytes = encode(&data);
        let mut padded = Vec::new();
        let mut cursor = 76usize;
        let info_size = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        padded.extend_from_slice(&bytes[..cursor + info_size]);
        cursor += info_size;
        for chunk in [&data.description[..], &data.working_directory[..]] {
            let units = chunk.encode_utf16().count();
            padded.extend_from_slice(&(units as u16).to_le_bytes());
            for unit in chunk.encode_utf16() {
                padded.extend_from_slice(&unit.to_le_bytes());
            }
            if units % 2 == 1 {
                padded.extend_from_slice(&[0, 0]);
            }
        }
        let parsed = parse(&padded).expect("parse the padded stream");
        assert_eq!(parsed.description.as_deref(), Some("Steam"));
        assert_eq!(parsed.working_directory.as_deref(), Some("C:\\x"));
    }

    #[test]
    fn unicode_strings_and_odd_targets() {
        let data = ShellLinkData {
            target_path: "C:\\Users\\casa1\\Documents\\über.pdf".to_string(),
            description: "café".to_string(),
            icon_location: "C:\\icons\\app.ico".to_string(),
            icon_index: -3,
            show_cmd: 7,
            ..ShellLinkData::default()
        };
        let parsed = parse(&encode(&data)).expect("parse");
        assert_eq!(parsed.description.as_deref(), Some("café"));
        assert_eq!(parsed.icon_index, -3);
        assert_eq!(parsed.show_cmd, 7);
        assert_eq!(
            parsed.target_path.as_deref(),
            Some("C:\\Users\\casa1\\Documents\\über.pdf")
        );
        assert_eq!(parsed.icon_location.as_deref(), Some("C:\\icons\\app.ico"));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0; 76]).is_none(), "wrong header size");
        let mut wrong_clsid = vec![0u8; 76];
        wrong_clsid[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        assert!(parse(&wrong_clsid).is_none(), "wrong CLSID");
        let mut truncated = encode(&sample_data());
        truncated.truncate(truncated.len() - 3);
        assert!(parse(&truncated).is_none(), "truncated stream");
    }

    #[test]
    fn normalize_collapses_dot_segments() {
        let data = ShellLinkData {
            target_path: "C:\\a\\.\\b\\..\\game.exe".to_string(),
            ..ShellLinkData::default()
        };
        let parsed = parse(&encode(&data)).expect("parse");
        assert_eq!(parsed.target_path.as_deref(), Some("C:\\a\\game.exe"));
    }

    #[test]
    fn show_cmd_zero_normalizes_to_shownormal() {
        let data = ShellLinkData {
            target_path: "C:\\x\\y.exe".to_string(),
            show_cmd: 0,
            ..ShellLinkData::default()
        };
        let bytes = encode(&data);
        assert_eq!(&bytes[60..64], &1_u32.to_le_bytes());
        assert_eq!(parse(&bytes).expect("parse").show_cmd, 1);
    }
}
