//! Registry services (`Zw*Key`, kernel path resolution).

use super::*;

impl IslandState {
    pub(crate) fn zw_open_key(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle_out = guest_arg(state, memory, 0)?;
        let desired_access = guest_arg(state, memory, 1)? as u32;
        let object_attributes = guest_arg(state, memory, 2)?;
        if handle_out == 0 || object_attributes == 0 {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // The island implements read-only key access.  Any mutating or
        // administrative right is refused exactly rather than silently
        // downgraded.
        const MUTATING_ACCESS: u32 = 0x0000_0002 // KEY_SET_VALUE
            | 0x0000_0004 // KEY_CREATE_SUB_KEY
            | 0x0000_0020 // KEY_CREATE_LINK
            | 0x0001_0000 // DELETE
            | 0x0004_0000 // WRITE_DAC
            | 0x0008_0000; // WRITE_OWNER
        if desired_access & MUTATING_ACCESS != 0 {
            set_status(state, STATUS_ACCESS_DENIED);
            return Ok(());
        }
        let (root_directory, name_pointer) =
            read_object_attributes(memory, object_attributes, self.arch)?;
        let (name, _, _) = read_unicode_string(memory, name_pointer, self.arch)?;
        if name.is_empty() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let path = match resolve_kernel_registry_path(
            runtime,
            &self.kernel.registry_keys,
            root_directory,
            &name,
        ) {
            Ok(path) => path,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        let handle = self.kernel.next_key_handle + KEY_HANDLE_BASE;
        self.kernel.next_key_handle += 1;
        self.kernel.registry_keys.insert(handle, path);
        write_guest_pointer(memory, handle_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    pub(crate) fn zw_query_value_key(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_arg(state, memory, 0)?;
        let value_name_pointer = guest_arg(state, memory, 1)?;
        let class = guest_arg(state, memory, 2)? as u32;
        let buffer = guest_arg(state, memory, 3)?;
        let length = guest_arg(state, memory, 4)? as usize;
        let result_length_out = guest_arg(state, memory, 5)?;
        let Some(path) = self.kernel.registry_keys.get(&key).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        if class != KEY_VALUE_FULL_INFORMATION && class != KEY_VALUE_PARTIAL_INFORMATION {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let (value_name, _, _) = read_unicode_string(memory, value_name_pointer, self.arch)?;
        let names = runtime
            .win32
            .ge()
            .registry_enum_values("HKLM", &path, RegistryView::Native)
            .unwrap_or_default();
        let Some(actual_name) = names
            .iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(&value_name))
        else {
            set_status(state, STATUS_OBJECT_NAME_NOT_FOUND);
            return Ok(());
        };
        let Some(stored) = runtime
            .win32
            .ge()
            .registry_get_value("HKLM", &path, actual_name, RegistryView::Native)
            .ok()
            .flatten()
        else {
            // coverage: unreachable — enumeration and lookup share one locked
            // GE store, so a value enumerated above cannot disappear here.
            set_status(state, STATUS_OBJECT_NAME_NOT_FOUND); // coverage: unreachable
            return Ok(()); // coverage: unreachable
        };
        let (value_type, data) = match registry_value_bytes(&stored) {
            Some(converted) => converted,
            None => {
                // coverage: unreachable — GE validates REG_* types on write and
                // imported stores are parsed through the same validator.
                set_status(state, STATUS_INVALID_PARAMETER); // coverage: unreachable
                return Ok(()); // coverage: unreachable
            }
        };
        let name_bytes = actual_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let (header_size, data_offset) = if class == KEY_VALUE_FULL_INFORMATION {
            let offset = align_up_usize(20 + name_bytes.len(), 4);
            (20, offset)
        } else {
            (12, 12)
        };
        let required = data_offset.saturating_add(data.len());
        if result_length_out != 0 {
            write_guest_pointer(memory, result_length_out, required as u64, self.arch)?;
        }
        if length < header_size {
            set_status(state, STATUS_BUFFER_TOO_SMALL);
            return Ok(());
        }
        let available = length.saturating_sub(data_offset).min(data.len());
        if class == KEY_VALUE_FULL_INFORMATION {
            memory.write_u32(buffer, 0);
            memory.write_u32(buffer + 4, value_type);
            memory.write_u32(buffer + 8, data_offset as u32);
            memory.write_u32(buffer + 12, data.len() as u32);
            memory.write_u32(buffer + 16, name_bytes.len() as u32);
            for (index, byte) in name_bytes.iter().enumerate() {
                memory.write_u8(buffer + 20 + index as u64, *byte);
            }
        } else {
            memory.write_u32(buffer, 0);
            memory.write_u32(buffer + 4, value_type);
            memory.write_u32(buffer + 8, data.len() as u32);
        }
        for (index, byte) in data.iter().take(available).enumerate() {
            memory.write_u8(buffer + data_offset as u64 + index as u64, *byte);
        }
        if length < required {
            set_status(state, STATUS_BUFFER_OVERFLOW);
        } else {
            set_status(state, STATUS_SUCCESS);
        }
        Ok(())
    }

    pub(crate) fn zw_close(&mut self, state: &mut CpuState, memory: &MemoryImage) -> AppResult<()> {
        let handle = guest_arg(state, memory, 0)?;
        if self.kernel.registry_keys.remove(&handle).is_none() {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}

/// Read `OBJECT_ATTRIBUTES` and return `(RootDirectory, ObjectName)`.
pub(crate) fn read_object_attributes(
    memory: &MemoryImage,
    attributes: u64,
    arch: GuestArch,
) -> AppResult<(u64, u64)> {
    let (root_offset, name_offset) = match arch {
        GuestArch::X86 => (4, 8),
        GuestArch::X64 => (8, 16),
    };
    let root = read_guest_pointer(memory, attributes + root_offset, arch)?;
    let name = read_guest_pointer(memory, attributes + name_offset, arch)?;
    Ok((root, name))
}

/// Resolve a registry open to a canonical `HKLM`-relative key path that exists
/// in the GE registry store.
pub(crate) fn resolve_kernel_registry_path(
    runtime: &PeHostRuntime,
    open_keys: &BTreeMap<u64, String>,
    root: u64,
    name: &str,
) -> Result<String, i32> {
    let lower = name.to_ascii_lowercase();
    let relative = if lower.starts_with("\\registry\\machine\\") {
        name["\\registry\\machine\\".len()..].to_string()
    } else if lower.starts_with("\\registry\\user\\")
        || lower.starts_with("\\registry\\")
        || name.starts_with("\\\\")
    {
        return Err(STATUS_OBJECT_PATH_INVALID);
    } else if let Some(parent) = open_keys.get(&root) {
        format!("{parent}\\{name}")
    } else {
        return Err(STATUS_OBJECT_PATH_INVALID);
    };
    let trimmed = relative.trim_matches('\\');
    if trimmed.is_empty() {
        return Err(STATUS_OBJECT_PATH_INVALID);
    }
    let segments = trimmed.split('\\').collect::<Vec<_>>();
    let mut actual = String::new();
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return Err(STATUS_OBJECT_PATH_INVALID);
        }
        let children = runtime
            .win32
            .ge()
            .registry_enum_keys("HKLM", &actual, RegistryView::Native)
            .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        if index + 1 == segments.len() {
            let Some(found) = children
                .iter()
                .find(|child| child.eq_ignore_ascii_case(segment))
            else {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            };
            actual = if actual.is_empty() {
                found.clone()
            } else {
                format!("{actual}\\{found}")
            };
        } else {
            let Some(found) = children
                .iter()
                .find(|child| child.eq_ignore_ascii_case(segment))
            else {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            };
            actual = if actual.is_empty() {
                found.clone()
            } else {
                format!("{actual}\\{found}")
            };
        }
    }
    Ok(actual)
}

/// Convert a stored GE registry value into `(REG_* type, raw bytes)` using the
/// native registry value encoding.
pub(crate) fn registry_value_bytes(value: &StoredRegistryValue) -> Option<(u32, Vec<u8>)> {
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;
    const REG_DWORD_BIG_ENDIAN: u32 = 5;
    const REG_MULTI_SZ: u32 = 7;
    const REG_QWORD: u32 = 11;
    let encode_utf16 = |text: &str, terminate: bool| {
        let mut bytes = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        if terminate {
            bytes.extend_from_slice(&0_u16.to_le_bytes());
        }
        bytes
    };
    match value.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" => Some((REG_SZ, encode_utf16(value.data.as_str()?, true))),
        "REG_EXPAND_SZ" => Some((REG_EXPAND_SZ, encode_utf16(value.data.as_str()?, true))),
        "REG_MULTI_SZ" => {
            let entries = value.data.as_array()?;
            let mut bytes = Vec::new();
            for entry in entries {
                bytes.extend(encode_utf16(entry.as_str()?, true));
            }
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            Some((REG_MULTI_SZ, bytes))
        }
        "REG_DWORD" => Some((
            REG_DWORD,
            (value.data.as_u64()? as u32).to_le_bytes().to_vec(),
        )),
        "REG_DWORD_BIG_ENDIAN" => Some((
            REG_DWORD_BIG_ENDIAN,
            (value.data.as_u64()? as u32).to_be_bytes().to_vec(),
        )),
        "REG_QWORD" => Some((REG_QWORD, value.data.as_u64()?.to_le_bytes().to_vec())),
        "REG_BINARY" => {
            let bytes = value
                .data
                .as_array()?
                .iter()
                .map(|byte| byte.as_u64().map(|value| value as u8))
                .collect::<Option<Vec<_>>>()?;
            Some((REG_BINARY, bytes))
        }
        _ => None,
    }
}
