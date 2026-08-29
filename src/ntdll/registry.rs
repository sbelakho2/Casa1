//! Stage-4 NTDLL — the registry surface (`NtCreateKey`, `NtOpenKey`,
//! `NtQueryValueKey`, `NtSetValueKey`, `NtDeleteKey`, `NtDeleteValueKey`,
//! `NtEnumerateKey`, `NtEnumerateValueKey`, `NtQueryKey`).
//!
//! Every operation adapts onto the SAME registry backing store the Win32
//! Reg* APIs use — the GE registry database
//! ([`crate::ge::GameEnvironment::registry_set_value`] and friends) reached
//! through the key handles in the live handle namespace.  There is exactly
//! one registry store; the Nt entry points share it with the Win32 entry
//! points (a value written via `RegSetValueExW` reads back through
//! `NtQueryValueKey` and vice versa).
//!
//! The x64 structures serialized here match the kernel's
//! `KEY_VALUE_BASIC_INFORMATION` / `KEY_VALUE_FULL_INFORMATION` /
//! `KEY_BASIC_INFORMATION` layouts.

use crate::ge::{RegistryView, StoredRegistryValue};
use crate::ntdll::{
    KEY_BASIC_INFORMATION_CLASS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS,
    KEY_FULL_INFORMATION_CLASS, KEY_NAME_INFORMATION_CLASS, KEY_QUERY_VALUE, KEY_SET_VALUE,
    KEY_VALUE_BASIC_INFORMATION_CLASS, KEY_VALUE_FULL_INFORMATION_CLASS,
    KEY_VALUE_PARTIAL_INFORMATION_ALIGN64_CLASS, KEY_VALUE_PARTIAL_INFORMATION_CLASS,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, NtStatus, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NO_MORE_ENTRIES,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use crate::reason::ReasonCode;
use crate::win32::Win32Subsystem;

/// Predefined root-key handles (winnt.h HKEY_*).
pub const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
pub const HKEY_CURRENT_USER: u32 = 0x8000_0001;
pub const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
pub const HKEY_USERS: u32 = 0x8000_0003;
pub const HKEY_CURRENT_CONFIG: u32 = 0x8000_0005;

/// Registry disposition results (winnt.h).
pub const REG_CREATED_NEW_KEY: u32 = 1;
pub const REG_OPENED_EXISTING_KEY: u32 = 2;

/// `KEY_BASIC_INFORMATION` (x64, 24 bytes + name):
/// `{ LastWriteTime: u64, TitleIndex: u32, NameLength: u32, Name: wchar[] }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtKeyBasicInformation {
    pub last_write_time: u64,
    pub title_index: u32,
    pub name: String,
}

impl NtKeyBasicInformation {
    /// Serialize into the x64 structure; `name_bytes` is the caller-owned
    /// wide-name buffer laid out immediately after the 16-byte header.
    pub fn serialize_header_x64(&self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[0..8].copy_from_slice(&self.last_write_time.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.title_index.to_le_bytes());
        bytes[12..16].copy_from_slice(&(self.name.encode_utf16().count() as u32 * 2).to_le_bytes());
        bytes
    }
}

/// `KEY_VALUE_BASIC_INFORMATION` (x64, 24 bytes + name):
/// `{ TitleIndex: u32, Type: u32, NameLength: u32, Name: wchar[] }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtKeyValueBasicInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub name: String,
}

impl NtKeyValueBasicInformation {
    pub fn serialize_header_x64(&self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[0..4].copy_from_slice(&self.title_index.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.value_type.to_le_bytes());
        bytes[8..12].copy_from_slice(&(self.name.encode_utf16().count() as u32 * 2).to_le_bytes());
        bytes
    }
}

/// `KEY_VALUE_FULL_INFORMATION` (x64, 24 bytes + name + data):
/// `{ TitleIndex: u32, Type: u32, DataOffset: u32, DataLength: u32,
///    NameLength: u32, Name: wchar[], Data: byte[] }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtKeyValueFullInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub name: String,
    pub data: Vec<u8>,
}

impl NtKeyValueFullInformation {
    /// Total serialized size (header + aligned name + data).
    pub fn total_size(&self) -> u64 {
        let name_bytes = self.name.encode_utf16().count() * 2;
        24 + name_bytes as u64 + self.data.len() as u64
    }
}

/// Resolve a root-key handle to the GE hive name + base key, mirroring the
/// Win32 Reg* layer's `resolve_registry_root_key` exactly (the two layers
/// must agree on hive names or the shared store would split).
pub fn resolve_registry_root_key(
    win32: &Win32Subsystem,
    hkey: u32,
    requested_view: RegistryView,
) -> Result<(String, String, RegistryView), NtStatus> {
    match hkey {
        HKEY_CLASSES_ROOT => Ok(("HKCR".to_string(), String::new(), requested_view)),
        HKEY_CURRENT_USER => Ok(("HKCU".to_string(), String::new(), requested_view)),
        HKEY_LOCAL_MACHINE => Ok(("HKLM".to_string(), String::new(), requested_view)),
        HKEY_USERS => Ok(("HKCU".to_string(), String::new(), requested_view)),
        HKEY_CURRENT_CONFIG => Ok((
            "HKLM".to_string(),
            "System\\CurrentControlSet\\Hardware Profiles\\Current".to_string(),
            requested_view,
        )),
        _ => {
            let key = win32.key_state(hkey).map_err(|_| STATUS_INVALID_HANDLE)?;
            Ok((key.hive, key.key, key.view))
        }
    }
}

/// Registry view selection from the KEY_WOW64_* access bits (mirror of the
/// Win32 layer's `registry_view_from_sam_desired`).
pub fn registry_view_from_sam_desired(sam_desired: u32, is_x64_guest: bool) -> RegistryView {
    if sam_desired & KEY_WOW64_64KEY != 0 {
        RegistryView::Native64
    } else if sam_desired & KEY_WOW64_32KEY != 0 || !is_x64_guest {
        RegistryView::Wow6432
    } else {
        RegistryView::Native
    }
}

/// Join a subkey onto a base key path (mirror of `join_registry_subkey`).
pub fn join_registry_subkey(base: &str, suffix: &str) -> String {
    if base.is_empty() {
        suffix.trim_matches('\\').to_string()
    } else if suffix.is_empty() {
        base.trim_matches('\\').to_string()
    } else {
        format!("{}\\{}", base.trim_matches('\\'), suffix.trim_matches('\\'))
    }
}

/// Normalize a full key path for the GE store (mirror of
/// `normalize_registry_runtime_key`).
pub fn normalize_registry_runtime_key(hive: &str, key: &str) -> String {
    if hive == "HKCU" {
        key.strip_prefix(".DEFAULT\\")
            .or_else(|| key.strip_prefix(".Default\\"))
            .unwrap_or(key)
            .trim_matches('\\')
            .to_string()
    } else {
        key.trim_matches('\\').to_string()
    }
}

/// The full (hive, normalized-key, view) triple of a live key handle.
pub fn key_handle_target(
    win32: &Win32Subsystem,
    hkey: u32,
    is_x64_guest: bool,
) -> Result<(String, String, RegistryView), NtStatus> {
    let view = registry_view_from_sam_desired(0, is_x64_guest);
    let (hive, base_key, key_view) = resolve_registry_root_key(win32, hkey, view)?;
    let normalized = normalize_registry_runtime_key(&hive, &base_key);
    Ok((hive, normalized, key_view))
}

/// `NtOpenKey` — open an existing key; `STATUS_OBJECT_NAME_NOT_FOUND` when
/// the key does not exist.  Returns the key handle.
pub fn nt_open_key(
    win32: &mut Win32Subsystem,
    root_handle: u32,
    subkey: &str,
    desired_access: u32,
    is_x64_guest: bool,
) -> Result<u32, NtStatus> {
    let _ = desired_access;
    let view = registry_view_from_sam_desired(desired_access, is_x64_guest);
    let (hive, base_key, key_view) = resolve_registry_root_key(win32, root_handle, view)?;
    let full_key = normalize_registry_runtime_key(&hive, &join_registry_subkey(&base_key, subkey));
    let exists = full_key.is_empty()
        || win32
            .registry_key_exists(&hive, &full_key, key_view)
            .map_err(nt_status_from_registry_error)?;
    if !exists {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    Ok(win32.open_registry_key(&hive, &full_key, key_view, false))
}

/// `NtCreateKey` — create (or open) a key; reports the disposition through
/// the `created` flag (REG_CREATED_NEW_KEY / REG_OPENED_EXISTING_KEY).
pub fn nt_create_key(
    win32: &mut Win32Subsystem,
    root_handle: u32,
    subkey: &str,
    desired_access: u32,
    is_x64_guest: bool,
) -> Result<(u32, u32), NtStatus> {
    let view = registry_view_from_sam_desired(desired_access, is_x64_guest);
    let (hive, base_key, key_view) = resolve_registry_root_key(win32, root_handle, view)?;
    let full_key = normalize_registry_runtime_key(&hive, &join_registry_subkey(&base_key, subkey));
    let created = if full_key.is_empty() {
        false
    } else {
        win32
            .create_registry_key(&hive, &full_key, key_view)
            .map_err(nt_status_from_registry_error)?
    };
    let handle = win32.open_registry_key(&hive, &full_key, key_view, false);
    let disposition = if created {
        REG_CREATED_NEW_KEY
    } else {
        REG_OPENED_EXISTING_KEY
    };
    Ok((handle, disposition))
}

/// `NtSetValueKey` — write a value (type + data bytes) into the shared
/// registry store.  The data bytes are decoded per the REG_* type exactly
/// like the Win32 RegSetValueExW path decodes them.
pub fn nt_set_value_key(
    win32: &Win32Subsystem,
    key_handle: u32,
    value_name: &str,
    value_type: u32,
    data: &[u8],
) -> NtStatus {
    let (hive, key_path, key_view) = match key_handle_target(win32, key_handle, true) {
        Ok(target) => target,
        Err(status) => return status,
    };
    match decode_registry_value_data(data, value_type) {
        Ok((kind, value)) => match win32
            .ge()
            .registry_set_value(&hive, &key_path, value_name, &kind, value, key_view)
        {
            Ok(()) => STATUS_SUCCESS,
            Err(error) => nt_status_from_registry_error(error),
        },
        Err(status) => status,
    }
}

/// `NtQueryValueKey` — read a value from the shared store.  `info_class`
/// selects the structure; the name + data are returned so the dispatch
/// wiring can serialize the requested layout.  A too-small caller buffer is
/// reported through the `buffer_too_small` flag (the required size is
/// returned in the length output either way).
pub fn nt_query_value_key(
    win32: &Win32Subsystem,
    key_handle: u32,
    value_name: &str,
    info_class: u32,
    buffer_capacity: u64,
) -> Result<(Vec<u8>, u64, bool), NtStatus> {
    let (hive, key_path, key_view) = key_handle_target(win32, key_handle, true)?;
    let Some(stored) = win32
        .registry_get_value(&hive, &key_path, value_name, key_view)
        .map_err(nt_status_from_registry_error)?
    else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let value_type = registry_value_type_to_win32(&stored.value_type);
    let data = encode_registry_value_data(&stored)?;
    let name_units = value_name.encode_utf16().count() as u32;
    let name_bytes = name_units * 2;
    let (body, required) = match info_class {
        KEY_VALUE_BASIC_INFORMATION_CLASS => {
            // TitleIndex(4) + Type(4) + NameLength(4) + Name
            let required = 12 + name_bytes as u64;
            let mut body = Vec::new();
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&value_type.to_le_bytes());
            body.extend_from_slice(&name_bytes.to_le_bytes());
            body.extend(value_name.encode_utf16().flat_map(|u| u.to_le_bytes()));
            (body, required)
        }
        KEY_VALUE_FULL_INFORMATION_CLASS => {
            // TitleIndex(4) + Type(4) + DataOffset(4) + DataLength(4) +
            // NameLength(4) + Name + Data (data 8-aligned after name)
            let data_offset = (20 + name_bytes as u64).wrapping_add(7) & !7;
            let required = data_offset + data.len() as u64;
            let mut body = Vec::new();
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&value_type.to_le_bytes());
            body.extend_from_slice(&(data_offset as u32).to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&name_bytes.to_le_bytes());
            body.extend(value_name.encode_utf16().flat_map(|u| u.to_le_bytes()));
            while !(body.len() as u64).is_multiple_of(8) {
                body.push(0);
            }
            body.extend_from_slice(&data);
            (body, required)
        }
        KEY_VALUE_PARTIAL_INFORMATION_CLASS | KEY_VALUE_PARTIAL_INFORMATION_ALIGN64_CLASS => {
            // TitleIndex(4) + Type(4) + DataLength(4) + Data
            let required = 12 + data.len() as u64;
            let mut body = Vec::new();
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&value_type.to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&data);
            (body, required)
        }
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    Ok((body, required, buffer_capacity < required))
}

/// `NtDeleteValueKey` — remove a value from the shared store.
pub fn nt_delete_value_key(win32: &Win32Subsystem, key_handle: u32, value_name: &str) -> NtStatus {
    let (hive, key_path, key_view) = match key_handle_target(win32, key_handle, true) {
        Ok(target) => target,
        Err(status) => return status,
    };
    match win32
        .ge()
        .registry_delete_value(&hive, &key_path, value_name, key_view)
    {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => nt_status_from_registry_error(error),
    }
}

/// `NtDeleteKey` — remove a key (with its subkeys) from the shared store.
pub fn nt_delete_key(win32: &Win32Subsystem, key_handle: u32) -> NtStatus {
    let (hive, key_path, key_view) = match key_handle_target(win32, key_handle, true) {
        Ok(target) => target,
        Err(status) => return status,
    };
    match win32.ge().registry_delete_key(&hive, &key_path, key_view) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => nt_status_from_registry_error(error),
    }
}

/// `NtEnumerateKey` — list the subkeys of a key; `STATUS_NO_MORE_ENTRIES`
/// past the end.
pub fn nt_enumerate_key(
    win32: &Win32Subsystem,
    key_handle: u32,
    index: u32,
) -> Result<String, NtStatus> {
    let (hive, key_path, key_view) = key_handle_target(win32, key_handle, true)?;
    let keys = win32
        .ge()
        .registry_enum_keys(&hive, &key_path, key_view)
        .map_err(nt_status_from_registry_error)?;
    keys.get(index as usize)
        .cloned()
        .ok_or(STATUS_NO_MORE_ENTRIES)
}

/// `NtEnumerateValueKey` — list the value names of a key;
/// `STATUS_NO_MORE_ENTRIES` past the end.
pub fn nt_enumerate_value_key(
    win32: &Win32Subsystem,
    key_handle: u32,
    index: u32,
) -> Result<String, NtStatus> {
    let (hive, key_path, key_view) = key_handle_target(win32, key_handle, true)?;
    let values = win32
        .ge()
        .registry_enum_values(&hive, &key_path, key_view)
        .map_err(nt_status_from_registry_error)?;
    values
        .get(index as usize)
        .cloned()
        .ok_or(STATUS_NO_MORE_ENTRIES)
}

/// `NtQueryKey` (KeyNameInformation) — the full key path of a key handle.
pub fn nt_query_key_name(win32: &Win32Subsystem, key_handle: u32) -> Result<String, NtStatus> {
    let (hive, key_path, _) = key_handle_target(win32, key_handle, true)?;
    if key_path.is_empty() {
        return Ok(hive);
    }
    Ok(format!("{hive}\\{key_path}"))
}

/// Decode REG_* data bytes into the GE store's `(type-name, Value)` form
/// (the exact mirror of the Win32 `decode_registry_value_data`).
fn decode_registry_value_data(
    bytes: &[u8],
    value_type: u32,
) -> Result<(String, serde_json::Value), NtStatus> {
    match value_type {
        REG_SZ | REG_EXPAND_SZ => {
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            let trimmed = units
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            Ok((
                if value_type == REG_SZ {
                    "REG_SZ".to_string()
                } else {
                    "REG_EXPAND_SZ".to_string()
                },
                serde_json::json!(String::from_utf16_lossy(&trimmed)),
            ))
        }
        REG_DWORD => {
            if bytes.len() < 4 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            Ok((
                "REG_DWORD".to_string(),
                serde_json::json!(u32::from_le_bytes(bytes[..4].try_into().expect("dword"))),
            ))
        }
        REG_QWORD => {
            if bytes.len() < 8 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            Ok((
                "REG_QWORD".to_string(),
                serde_json::json!(u64::from_le_bytes(bytes[..8].try_into().expect("qword"))),
            ))
        }
        REG_BINARY => Ok((
            "REG_BINARY".to_string(),
            serde_json::json!(
                bytes
                    .iter()
                    .map(|byte| u64::from(*byte))
                    .collect::<Vec<_>>()
            ),
        )),
        REG_MULTI_SZ => {
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            let mut items = Vec::new();
            let mut current = Vec::new();
            for unit in units {
                if unit == 0 {
                    if current.is_empty() {
                        break;
                    }
                    items.push(String::from_utf16_lossy(&current));
                    current.clear();
                } else {
                    current.push(unit);
                }
            }
            Ok(("REG_MULTI_SZ".to_string(), serde_json::json!(items)))
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Encode a stored value back to the REG_* data bytes (the mirror of the
/// Win32 `encode_registry_value_data`).
pub fn encode_registry_value_data(value: &StoredRegistryValue) -> Result<Vec<u8>, NtStatus> {
    match value.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => {
            let text = value.data.as_str().ok_or(STATUS_INVALID_PARAMETER)?;
            Ok(text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|unit| unit.to_le_bytes())
                .collect())
        }
        "REG_DWORD" => {
            let number = value.data.as_u64().ok_or(STATUS_INVALID_PARAMETER)?;
            Ok((number as u32).to_le_bytes().to_vec())
        }
        "REG_QWORD" => {
            let number = value.data.as_u64().ok_or(STATUS_INVALID_PARAMETER)?;
            Ok(number.to_le_bytes().to_vec())
        }
        "REG_BINARY" => {
            let items = value.data.as_array().ok_or(STATUS_INVALID_PARAMETER)?;
            items
                .iter()
                .map(|item| {
                    item.as_u64()
                        .map(|byte| byte as u8)
                        .ok_or(STATUS_INVALID_PARAMETER)
                })
                .collect()
        }
        "REG_MULTI_SZ" => {
            let items = value.data.as_array().ok_or(STATUS_INVALID_PARAMETER)?;
            let mut encoded = Vec::new();
            for item in items {
                let text = item.as_str().ok_or(STATUS_INVALID_PARAMETER)?;
                encoded.extend(text.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
                encoded.extend_from_slice(&0u16.to_le_bytes());
            }
            encoded.extend_from_slice(&0u16.to_le_bytes());
            Ok(encoded)
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Stored type-name → REG_* code (mirror of `registry_value_type_to_win32`).
pub fn registry_value_type_to_win32(value_type: &str) -> u32 {
    match value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" => REG_SZ,
        "REG_EXPAND_SZ" => REG_EXPAND_SZ,
        "REG_BINARY" => REG_BINARY,
        "REG_DWORD" => REG_DWORD,
        "REG_MULTI_SZ" => REG_MULTI_SZ,
        "REG_QWORD" => REG_QWORD,
        _ => 0,
    }
}

/// Map the GE registry layer's `AppError` to the NTSTATUS domain.
pub fn nt_status_from_registry_error(error: crate::error::AppError) -> NtStatus {
    match error.code {
        ReasonCode::RcRegistryNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        ReasonCode::RcHelperPermissionDenied => STATUS_ACCESS_DENIED,
        ReasonCode::RcWin32InvalidHandle => STATUS_INVALID_HANDLE,
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// The key/value classes this layer implements (the dispatch validates
/// `info_class` against these before calling).
#[allow(dead_code)]
const _: u32 = KEY_BASIC_INFORMATION_CLASS
    | KEY_FULL_INFORMATION_CLASS
    | KEY_NAME_INFORMATION_CLASS
    | KEY_CREATE_SUB_KEY
    | KEY_ENUMERATE_SUB_KEYS
    | KEY_QUERY_VALUE
    | KEY_SET_VALUE;

/// `STATUS_BUFFER_TOO_SMALL` is the query-value overflow status.
#[allow(dead_code)]
const _: NtStatus = STATUS_BUFFER_TOO_SMALL;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    fn setup() -> (TempDir, Win32Subsystem) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "ntdll-registry",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create GE");
        let win32 = Win32Subsystem::new(ge, true);
        (temp_dir, win32)
    }

    #[test]
    fn set_and_query_value_key_round_trip_through_the_shared_store() {
        let (_tmp, mut win32) = setup();
        let (handle, disposition) = nt_create_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtTest",
            0x20019,
            true,
        )
        .expect("create key");
        assert_eq!(disposition, REG_CREATED_NEW_KEY);

        // REG_SZ round trip.
        let mut data = "hello"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        data.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            nt_set_value_key(&win32, handle, "Greeting", REG_SZ, &data),
            STATUS_SUCCESS
        );
        let (body, required, too_small) = nt_query_value_key(
            &win32,
            handle,
            "Greeting",
            KEY_VALUE_FULL_INFORMATION_CLASS,
            4096,
        )
        .expect("query value");
        assert!(!too_small);
        assert!(required > 0);
        // The full information layout: TitleIndex(4) Type(4) DataOffset(4)
        // DataLength(4) NameLength(4) = 20 bytes header.
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), REG_SZ);
        let data_offset = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
        assert_eq!(data_offset, 40, "data sits 8-aligned after the name");
        // REG_SZ encodes as UTF-16 + a NUL terminator (12 bytes).
        assert_eq!(
            &body[data_offset..data_offset + data_len],
            b"h\0e\0l\0l\0o\0\0\0"
        );

        // The value is visible through the Win32 store API too (one store).
        let (hive, key_path, view) = key_handle_target(&win32, handle, true).expect("target");
        let stored = win32
            .registry_get_value(&hive, &key_path, "Greeting", view)
            .expect("get value")
            .expect("value exists");
        assert_eq!(stored.value_type, "REG_SZ");
        assert_eq!(stored.data.as_str(), Some("hello"));

        // Deleting the value: the shared store prunes a key whose last
        // value is removed, so the value query reports not-found after.
        assert_eq!(
            nt_delete_value_key(&win32, handle, "Greeting"),
            STATUS_SUCCESS
        );
        assert_eq!(
            nt_query_value_key(
                &win32,
                handle,
                "Greeting",
                KEY_VALUE_FULL_INFORMATION_CLASS,
                4096
            ),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        // Re-create the key, then delete the whole key.
        let (handle, _) = nt_create_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtTest",
            0x20019,
            true,
        )
        .expect("recreate key");
        assert_eq!(nt_delete_key(&win32, handle), STATUS_SUCCESS);
        assert_eq!(
            nt_open_key(
                &mut win32,
                HKEY_CURRENT_USER,
                "Software\\Casa1NtTest",
                0,
                true
            ),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn open_key_and_enumerate() {
        let (_tmp, mut win32) = setup();
        let (_handle_a, _) = nt_create_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtEnum\\A",
            0x20019,
            true,
        )
        .expect("create A");
        let _ = nt_create_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtEnum\\B",
            0x20019,
            true,
        )
        .expect("create B");
        let opened = nt_open_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtEnum",
            0x20019,
            true,
        )
        .expect("open parent");
        let mut found = Vec::new();
        for index in 0..8 {
            match nt_enumerate_key(&win32, opened, index) {
                Ok(name) => found.push(name),
                Err(STATUS_NO_MORE_ENTRIES) => break,
                Err(other) => panic!("enumerate failed: {other}"),
            }
        }
        assert_eq!(found, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(
            nt_enumerate_key(&win32, opened, 99),
            Err(STATUS_NO_MORE_ENTRIES)
        );
        assert!(
            nt_query_key_name(&win32, opened)
                .expect("key name")
                .ends_with("Casa1NtEnum")
        );
    }

    #[test]
    fn registry_ops_validate_handles() {
        let (_tmp, mut win32) = setup();
        assert_eq!(
            nt_set_value_key(&win32, 0xBAD, "x", REG_SZ, b"x\0\0"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            nt_open_key(&mut win32, 0xBAD, "a", 0, true),
            Err(STATUS_INVALID_HANDLE)
        );
        // Querying a missing value name is object-name-not-found.
        let (handle, _) = nt_create_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtMissing",
            0x20019,
            true,
        )
        .expect("create");
        let _ = handle;
        assert_eq!(
            nt_query_value_key(
                &win32,
                handle,
                "Absent",
                KEY_VALUE_BASIC_INFORMATION_CLASS,
                4096
            ),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn evidence_core_nt_enumerate_value_key_lists_values_in_order() {
        let (_tmp, mut win32) = setup();
        let (handle, _) = nt_create_key(
            &mut win32,
            HKEY_CURRENT_USER,
            "Software\\Casa1NtEnumVals",
            0x20019,
            true,
        )
        .expect("create key");
        let mut data = "v"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        data.extend_from_slice(&0u16.to_le_bytes());
        nt_set_value_key(&win32, handle, "zeta", REG_SZ, &data);
        nt_set_value_key(&win32, handle, "alpha", REG_SZ, &data);
        nt_set_value_key(&win32, handle, "mid", REG_SZ, &data);

        let mut found = Vec::new();
        for index in 0..8 {
            match nt_enumerate_value_key(&win32, handle, index) {
                Ok(name) => found.push(name),
                Err(STATUS_NO_MORE_ENTRIES) => break,
                Err(other) => panic!("enumerate value failed: {other}"),
            }
        }
        assert_eq!(
            found,
            vec!["alpha".to_string(), "mid".to_string(), "zeta".to_string()],
            "the values enumerate in the store's sorted order"
        );
        assert_eq!(
            nt_enumerate_value_key(&win32, handle, 99),
            Err(STATUS_NO_MORE_ENTRIES)
        );
        assert_eq!(
            nt_enumerate_value_key(&win32, 0xBAD, 0),
            Err(STATUS_INVALID_HANDLE)
        );
    }
}
