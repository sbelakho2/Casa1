//! INI document helpers.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IniSection {
    pub(crate) name: String,
    pub(crate) entries: Vec<(String, String)>,
}

pub(crate) fn read_ini_document(host_path: &Path) -> AppResult<(Vec<IniSection>, bool)> {
    match fs::read(host_path) {
        Ok(bytes) => Ok(parse_ini_document(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), false)),
        Err(error) => Err(AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", host_path.display()),
            &error,
        )),
    }
}

pub(crate) fn parse_ini_document(bytes: &[u8]) -> (Vec<IniSection>, bool) {
    let (text, prefer_utf16) = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        (String::from_utf16_lossy(&units), true)
    } else {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    };
    let mut sections = Vec::<IniSection>::new();
    let mut current_section: Option<usize> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let name = trimmed[1..trimmed.len() - 1].trim().to_string();
            let index = ini_section_index(&sections, &name).unwrap_or_else(|| {
                sections.push(IniSection {
                    name: name.clone(),
                    entries: Vec::new(),
                });
                sections.len() - 1
            });
            current_section = Some(index);
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let Some(section_index) = current_section else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.to_string();
        if key.is_empty() {
            continue;
        }
        let entries = &mut sections[section_index].entries;
        if let Some(entry_index) = ini_entry_index(entries, key) {
            entries[entry_index].1 = value;
        } else {
            entries.push((key.to_string(), value));
        }
    }
    (sections, prefer_utf16)
}

pub(crate) fn serialize_ini_document(sections: &[IniSection], prefer_utf16: bool) -> Vec<u8> {
    let mut text = String::new();
    for (section_index, section) in sections.iter().enumerate() {
        if section_index != 0 {
            text.push('\n');
        }
        text.push('[');
        text.push_str(&section.name);
        text.push_str("]\n");
        for (key, value) in &section.entries {
            text.push_str(key);
            text.push('=');
            text.push_str(value);
            text.push('\n');
        }
    }
    if prefer_utf16 {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    } else {
        text.into_bytes()
    }
}

pub(crate) fn update_ini_document(
    sections: &mut Vec<IniSection>,
    section: &str,
    key: Option<&str>,
    value: Option<&str>,
) {
    let Some(section_index) = ini_section_index(sections, section) else {
        if key.is_none() || value.is_none() {
            return;
        }
        sections.push(IniSection {
            name: section.to_string(),
            entries: vec![(key.unwrap().to_string(), value.unwrap().to_string())],
        });
        return;
    };
    if key.is_none() {
        sections.remove(section_index);
        return;
    }
    let entries = &mut sections[section_index].entries;
    let key = key.unwrap();
    if value.is_none() {
        if let Some(entry_index) = ini_entry_index(entries, key) {
            entries.remove(entry_index);
        }
        if entries.is_empty() {
            sections.remove(section_index);
        }
        return;
    }
    if let Some(entry_index) = ini_entry_index(entries, key) {
        entries[entry_index].1 = value.unwrap().to_string();
    } else {
        entries.push((key.to_string(), value.unwrap().to_string()));
    }
}

pub(crate) fn ini_section_index(sections: &[IniSection], section: &str) -> Option<usize> {
    sections
        .iter()
        .position(|candidate| candidate.name.eq_ignore_ascii_case(section))
}

pub(crate) fn ini_entry_index(entries: &[(String, String)], key: &str) -> Option<usize> {
    entries
        .iter()
        .position(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
}

/// Expand `%VARNAME%` references in a string against the guest process
/// environment (the same `process_environment` table SetEnvironmentVariableW
/// maintains).  Lookups are case-insensitive; undefined variables are copied
/// through literally, matching ExpandEnvironmentStringsW.
pub(crate) fn expand_environment_strings(
    environment: &BTreeMap<String, String>,
    source: &str,
) -> String {
    let mut expanded = String::with_capacity(source.len());
    let mut remainder = source;
    while let Some(start) = remainder.find('%') {
        expanded.push_str(&remainder[..start]);
        let after_start = &remainder[start + 1..];
        if let Some(end) = after_start.find('%') {
            let name = &after_start[..end];
            let value = environment
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str());
            if let Some(value) = value {
                expanded.push_str(value);
            } else {
                expanded.push('%');
                expanded.push_str(name);
                expanded.push('%');
            }
            remainder = &after_start[end + 1..];
        } else {
            expanded.push('%');
            remainder = after_start;
            break;
        }
    }
    expanded.push_str(remainder);
    expanded
}

/// The section names of an INI document as a multi-string (NUL-separated,
/// double-NUL terminated) for the GetPrivateProfileStringW section listing.
pub(crate) fn list_ini_section_names(sections: &[IniSection]) -> String {
    let mut listing = String::new();
    for section in sections {
        listing.push_str(&section.name);
        listing.push('\0');
    }
    listing
}

/// The key names of an INI section as a multi-string (NUL-separated,
/// double-NUL terminated) for the GetPrivateProfileStringW key listing.
pub(crate) fn list_ini_keys(section: &IniSection) -> String {
    let mut listing = String::new();
    for (key, _) in &section.entries {
        listing.push_str(key);
        listing.push('\0');
    }
    listing
}

/// Write a GetPrivateProfileStringW result into a guest buffer with the
/// documented size contract: at most `buffer_len - 1` characters are copied
/// plus a NUL terminator; the return value is the number of characters
/// copied EXCLUDING the final NUL (for multi-string listings the interior
/// NUL separators count).  A truncated write returns `buffer_len - 1`.
pub(crate) fn write_ini_query_string(
    memory: &mut MemoryImage,
    buffer: u64,
    buffer_len: usize,
    value: &str,
) -> u32 {
    if buffer == 0 || buffer_len == 0 {
        return 0;
    }
    let units = value.encode_utf16().collect::<Vec<_>>();
    let copy_units = units.len().min(buffer_len.saturating_sub(1));
    let mut bytes = Vec::with_capacity((copy_units + 1) * 2);
    for unit in units.iter().take(copy_units) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    memory.map_bytes(buffer, &bytes);
    if copy_units < units.len() {
        (buffer_len - 1) as u32
    } else {
        copy_units as u32
    }
}
