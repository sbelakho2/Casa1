//! Registry value/decoding helpers.

use super::*;

pub(crate) fn registry_view_from_sam_desired(
    sam_desired: u32,
    guest_arch: GuestArch,
) -> RegistryView {
    if sam_desired & KEY_WOW64_64KEY != 0 {
        RegistryView::Native64
    } else if sam_desired & KEY_WOW64_32KEY != 0 || guest_arch == GuestArch::X86 {
        RegistryView::Wow6432
    } else {
        RegistryView::Native
    }
}

pub(crate) fn resolve_registry_root_key(
    win32: &Win32Subsystem,
    hkey: u32,
    requested_view: RegistryView,
) -> AppResult<(String, String, RegistryView)> {
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
            let key = win32.key_state(hkey)?;
            Ok((key.hive, key.key, key.view))
        }
    }
}

pub(crate) fn join_registry_subkey(base: &str, suffix: &str) -> String {
    if base.is_empty() {
        suffix.trim_matches('\\').to_string()
    } else if suffix.is_empty() {
        base.trim_matches('\\').to_string()
    } else {
        format!("{}\\{}", base.trim_matches('\\'), suffix.trim_matches('\\'))
    }
}

pub(crate) fn normalize_registry_runtime_key(hive: &str, key: &str) -> String {
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

pub(crate) fn registry_value_type_to_win32(value_type: &str) -> AppResult<u32> {
    match value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" => Ok(REG_SZ),
        "REG_EXPAND_SZ" => Ok(REG_EXPAND_SZ),
        "REG_BINARY" => Ok(REG_BINARY),
        "REG_DWORD" => Ok(REG_DWORD),
        "REG_MULTI_SZ" => Ok(REG_MULTI_SZ),
        "REG_QWORD" => Ok(REG_QWORD),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type {other}"),
        )),
    }
}

pub(crate) fn decode_registry_value_data(
    memory: &MemoryImage,
    data_ptr: u64,
    data_len: u32,
    value_type: u32,
) -> AppResult<(String, Value)> {
    let bytes = if data_ptr == 0 || data_len == 0 {
        Vec::new()
    } else {
        memory.read_bytes(data_ptr, data_len as usize)?
    };
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
                json!(String::from_utf16_lossy(&trimmed)),
            ))
        }
        REG_DWORD => {
            if bytes.len() < 4 {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "REG_DWORD data is shorter than 4 bytes",
                ));
            }
            Ok((
                "REG_DWORD".to_string(),
                json!(u32::from_le_bytes(bytes[..4].try_into().expect("dword"))),
            ))
        }
        REG_QWORD => {
            if bytes.len() < 8 {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "REG_QWORD data is shorter than 8 bytes",
                ));
            }
            Ok((
                "REG_QWORD".to_string(),
                json!(u64::from_le_bytes(bytes[..8].try_into().expect("qword"))),
            ))
        }
        REG_BINARY => Ok((
            "REG_BINARY".to_string(),
            json!(bytes.into_iter().map(u64::from).collect::<Vec<_>>()),
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
            Ok(("REG_MULTI_SZ".to_string(), json!(items)))
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type code {other}"),
        )),
    }
}

pub(crate) fn encode_registry_value_data(
    value: &crate::ge::StoredRegistryValue,
) -> AppResult<Vec<u8>> {
    match value.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => {
            let text = value.data.as_str().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "registry string value has non-string data: {:?}",
                        value.data
                    ),
                )
            })?;
            Ok(text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|unit| unit.to_le_bytes())
                .collect())
        }
        "REG_DWORD" => {
            let number = value.data.as_u64().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "registry dword value has non-numeric data: {:?}",
                        value.data
                    ),
                )
            })?;
            Ok((number as u32).to_le_bytes().to_vec())
        }
        "REG_QWORD" => {
            let number = value.data.as_u64().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "registry qword value has non-numeric data: {:?}",
                        value.data
                    ),
                )
            })?;
            Ok(number.to_le_bytes().to_vec())
        }
        "REG_BINARY" => {
            let bytes = value.data.as_array().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("registry binary value has non-array data: {:?}", value.data),
                )
            })?;
            bytes
                .iter()
                .map(|item| {
                    item.as_u64().map(|byte| byte as u8).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcCliInvalid,
                            format!("registry binary value contains non-byte data: {item:?}"),
                        )
                    })
                })
                .collect()
        }
        "REG_MULTI_SZ" => {
            let items = value.data.as_array().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "registry multi-string value has non-array data: {:?}",
                        value.data
                    ),
                )
            })?;
            let mut encoded = Vec::new();
            for item in items {
                let text = item.as_str().ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("registry multi-string value contains non-string data: {item:?}"),
                    )
                })?;
                encoded.extend(text.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
                encoded.extend_from_slice(&0u16.to_le_bytes());
            }
            encoded.extend_from_slice(&0u16.to_le_bytes());
            Ok(encoded)
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type code {other}"),
        )),
    }
}

/// Write a documented SERVICE_STATUS structure (28 bytes, all DWORDs).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_service_status(
    memory: &mut MemoryImage,
    status_ptr: u64,
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
) {
    write_u32(memory, status_ptr, service_type);
    write_u32(memory, status_ptr + 4, current_state);
    write_u32(memory, status_ptr + 8, controls_accepted);
    write_u32(memory, status_ptr + 12, win32_exit_code);
    write_u32(memory, status_ptr + 16, service_specific_exit_code);
    write_u32(memory, status_ptr + 20, checkpoint);
    write_u32(memory, status_ptr + 24, wait_hint);
}

pub(crate) fn decode_registry_value_data_ansi(
    memory: &MemoryImage,
    data_ptr: u64,
    data_len: u32,
    value_type: u32,
) -> AppResult<(String, Value)> {
    let bytes = if data_ptr == 0 || data_len == 0 {
        Vec::new()
    } else {
        memory.read_bytes(data_ptr, data_len as usize)?
    };
    match value_type {
        REG_SZ | REG_EXPAND_SZ => {
            let trimmed = bytes
                .iter()
                .copied()
                .take_while(|byte| *byte != 0)
                .map(char::from)
                .collect::<String>();
            Ok((
                if value_type == REG_SZ {
                    "REG_SZ".to_string()
                } else {
                    "REG_EXPAND_SZ".to_string()
                },
                json!(trimmed),
            ))
        }
        REG_DWORD | REG_QWORD | REG_BINARY => {
            decode_registry_value_data(memory, data_ptr, data_len, value_type)
        }
        REG_MULTI_SZ => {
            let mut items = Vec::new();
            let mut current = Vec::new();
            for byte in bytes {
                if byte == 0 {
                    if current.is_empty() {
                        break;
                    }
                    items.push(current.iter().copied().map(char::from).collect::<String>());
                    current.clear();
                } else {
                    current.push(byte);
                }
            }
            Ok(("REG_MULTI_SZ".to_string(), json!(items)))
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type code {other}"),
        )),
    }
}

pub(crate) fn encode_registry_value_data_ansi(
    value: &crate::ge::StoredRegistryValue,
) -> AppResult<Vec<u8>> {
    match value.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => {
            let text = value.data.as_str().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "registry string value has non-string data: {:?}",
                        value.data
                    ),
                )
            })?;
            let mut encoded = text
                .chars()
                .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' })
                .collect::<Vec<_>>();
            encoded.push(0);
            Ok(encoded)
        }
        "REG_DWORD" | "REG_QWORD" | "REG_BINARY" => encode_registry_value_data(value),
        "REG_MULTI_SZ" => {
            let items = value.data.as_array().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!(
                        "registry multi-string value has non-array data: {:?}",
                        value.data
                    ),
                )
            })?;
            let mut encoded = Vec::new();
            for item in items {
                let text = item.as_str().ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("registry multi-string value contains non-string data: {item:?}"),
                    )
                })?;
                encoded.extend(
                    text.chars()
                        .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' }),
                );
                encoded.push(0);
            }
            encoded.push(0);
            Ok(encoded)
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type {other}"),
        )),
    }
}
