//! KMDF object model.

use super::*;

impl IslandState {
    /// `WdfRegistryOpenKey`: opens an existing key in the GE registry store.
    /// A null parent requires an absolute `\Registry\Machine\...` name; a
    /// parent handle resolves relative names beneath it.
    /// Resolve a `WdfRegistry*` key path to the exact stored case by
    /// walking the GE store segment by segment.  Absolute names must live
    /// under `\Registry\Machine\`; relative names join beneath `parent`.
    pub(crate) fn resolve_kmdf_registry_path(
        &self,
        runtime: &PeHostRuntime,
        parent: u64,
        name: &str,
    ) -> Result<String, i32> {
        let lower = name.to_ascii_lowercase();
        let relative = if lower.starts_with("\\registry\\machine\\") {
            name["\\registry\\machine\\".len()..].to_string()
        } else if lower.starts_with("\\registry\\") || name.starts_with("\\\\") {
            return Err(STATUS_OBJECT_PATH_INVALID);
        } else if parent != 0 {
            let Some(record) = self.kmdf.registry_keys.get(&parent) else {
                return Err(STATUS_INVALID_HANDLE);
            };
            format!("{}\\{name}", record.path)
        } else {
            return Err(STATUS_OBJECT_PATH_INVALID);
        };
        let trimmed = relative.trim_matches('\\');
        if trimmed.is_empty() {
            return Err(STATUS_OBJECT_PATH_INVALID);
        }
        let segments = trimmed.split('\\').collect::<Vec<_>>();
        let mut actual = String::new();
        for segment in &segments {
            if segment.is_empty() {
                return Err(STATUS_OBJECT_PATH_INVALID);
            }
            let children = runtime
                .win32
                .ge()
                .registry_enum_keys("HKLM", &actual, RegistryView::Native)
                .expect("HKLM registry store loads");
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
        Ok(actual)
    }

    pub(crate) fn wdf_registry_open_key(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let parent = guest_arg(state, memory, 0)?;
        let name = guest_arg(state, memory, 1)?;
        let desired_access = guest_arg(state, memory, 2)? as u32;
        let key_out = guest_arg(state, memory, 3)?;
        if key_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                key_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let (text, _, _) = read_unicode_string(memory, name, self.arch)?;
        if text.is_empty() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let path = match self.resolve_kmdf_registry_path(runtime, parent, &text) {
            Ok(path) => path,
            Err(status) => {
                set_status(state, status);
                return Ok(());
            }
        };
        // The exact-case segment walk above already failed with
        // STATUS_OBJECT_NAME_NOT_FOUND for a missing key, so `path` exists.
        self.kmdf.next_registry_key += 1;
        let handle = self.kmdf.next_registry_key + 0x7F00_0000;
        self.kmdf.registry_keys.insert(
            handle,
            KmdfRegistryKey {
                path,
                access: desired_access,
            },
        );
        write_guest_pointer(memory, key_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRegistryCreateKey`: creates (if needed) and opens a key.
    pub(crate) fn wdf_registry_create_key(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let parent = guest_arg(state, memory, 0)?;
        let name = guest_arg(state, memory, 1)?;
        let desired_access = guest_arg(state, memory, 2)? as u32;
        let key_out = guest_arg(state, memory, 3)?;
        if key_out == 0
            || crate::host_thunks::validate_guest_pointer(
                memory,
                key_out,
                self.arch.pointer_bytes(),
            )
            .is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let (text, _, _) = read_unicode_string(memory, name, self.arch)?;
        if text.is_empty() {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        // `WdfRegistryCreateKey` may create the final segment, so only the
        // parent prefix must already exist (case-insensitively).
        let lower = text.to_ascii_lowercase();
        let relative = if lower.starts_with("\\registry\\machine\\") {
            text["\\registry\\machine\\".len()..].to_string()
        } else if lower.starts_with("\\registry\\") || text.starts_with("\\\\") {
            set_status(state, STATUS_OBJECT_PATH_INVALID);
            return Ok(());
        } else if parent != 0 {
            let Some(record) = self.kmdf.registry_keys.get(&parent) else {
                set_status(state, STATUS_INVALID_HANDLE);
                return Ok(());
            };
            format!("{}\\{text}", record.path)
        } else {
            set_status(state, STATUS_OBJECT_PATH_INVALID);
            return Ok(());
        };
        let trimmed = relative.trim_matches('\\');
        let segments = trimmed.split('\\').collect::<Vec<_>>();
        if segments.iter().any(|segment| segment.is_empty()) {
            set_status(state, STATUS_OBJECT_PATH_INVALID);
            return Ok(());
        }
        let (leaf, parents) = segments.split_last().expect("non-empty path");
        let mut actual = String::new();
        for segment in parents {
            let children = runtime
                .win32
                .ge()
                .registry_enum_keys("HKLM", &actual, RegistryView::Native)
                .expect("HKLM registry store loads");
            let Some(found) = children
                .iter()
                .find(|child| child.eq_ignore_ascii_case(segment))
            else {
                set_status(state, STATUS_OBJECT_PATH_INVALID);
                return Ok(());
            };
            actual = if actual.is_empty() {
                found.clone()
            } else {
                format!("{actual}\\{found}")
            };
        }
        let path = if actual.is_empty() {
            (*leaf).to_string()
        } else {
            format!("{actual}\\{leaf}")
        };
        runtime
            .win32
            .ge()
            .registry_create_key("HKLM", &path, RegistryView::Native)
            .expect("HKLM registry create");
        self.kmdf.next_registry_key += 1;
        let handle = self.kmdf.next_registry_key + 0x7F00_0000;
        self.kmdf.registry_keys.insert(
            handle,
            KmdfRegistryKey {
                path,
                access: desired_access,
            },
        );
        write_guest_pointer(memory, key_out, handle, self.arch)?;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRegistryClose`; a double close fails with `STATUS_INVALID_HANDLE`.
    pub(crate) fn wdf_registry_close(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let key = guest_arg(state, memory, 0)?;
        if self.kmdf.registry_keys.remove(&key).is_none() {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRegistryQueryValue`.
    pub(crate) fn wdf_registry_query_value(
        &self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_arg(state, memory, 0)?;
        let value_name = guest_arg(state, memory, 1)?;
        let buffer = guest_arg(state, memory, 2)?;
        let buffer_length = guest_arg(state, memory, 3)? as usize;
        let value_length_out = guest_arg(state, memory, 4)?;
        let type_out = guest_arg(state, memory, 5)?;
        let Some(record) = self.kmdf.registry_keys.get(&key) else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        let path = record.path.clone();
        let (text, _, _) = read_unicode_string(memory, value_name, self.arch)?;
        let Some(stored) = runtime
            .win32
            .ge()
            .registry_get_value("HKLM", &path, &text, RegistryView::Native)
            .ok()
            .flatten()
        else {
            set_status(state, STATUS_OBJECT_NAME_NOT_FOUND);
            return Ok(());
        };
        let Some((value_type, data)) = registry_value_bytes(&stored) else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        if value_length_out != 0 {
            write_guest_pointer(memory, value_length_out, data.len() as u64, self.arch)?;
        }
        if type_out != 0 {
            memory.write_u32(type_out, value_type);
        }
        if buffer_length < data.len() {
            set_status(state, STATUS_BUFFER_TOO_SMALL);
            return Ok(());
        }
        if buffer == 0
            || crate::host_thunks::validate_guest_pointer(memory, buffer, data.len()).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        for (offset, byte) in data.iter().enumerate() {
            memory.write_u8(buffer + offset as u64, *byte);
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRegistryAssignValue` (`WdfRegistrySetValue`): writes a typed
    /// value; the data length must match the registry type's width exactly.
    pub(crate) fn wdf_registry_assign_value(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_arg(state, memory, 0)?;
        let value_name = guest_arg(state, memory, 1)?;
        let value_type = guest_arg(state, memory, 2)? as u32;
        let data = guest_arg(state, memory, 3)?;
        let data_length = guest_arg(state, memory, 4)? as usize;
        let Some(record) = self.kmdf.registry_keys.get(&key).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        const KEY_SET_VALUE: u32 = 0x0000_0002;
        if record.access & KEY_SET_VALUE == 0 {
            set_status(state, STATUS_ACCESS_DENIED);
            return Ok(());
        }
        const REG_DWORD: u32 = 4;
        const REG_QWORD: u32 = 11;
        match value_type {
            REG_DWORD | REG_QWORD => {
                let expected = if value_type == REG_DWORD { 4 } else { 8 };
                if data_length != expected {
                    set_status(state, STATUS_INVALID_PARAMETER);
                    return Ok(());
                }
            }
            _ => {
                set_status(state, STATUS_INVALID_PARAMETER);
                return Ok(());
            }
        }
        if data_length == 0
            || data == 0
            || crate::host_thunks::validate_guest_pointer(memory, data, data_length).is_err()
        {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        }
        let value = match value_type {
            REG_DWORD => serde_json::Value::from(u64::from(memory.read_u32(data)?)),
            _ => serde_json::Value::from(memory.read_u64(data)?),
        };
        let (text, _, _) = read_unicode_string(memory, value_name, self.arch)?;
        let type_name = if value_type == REG_DWORD {
            "REG_DWORD"
        } else {
            "REG_QWORD"
        };
        runtime
            .win32
            .ge()
            .registry_set_value(
                "HKLM",
                &record.path,
                &text,
                type_name,
                value,
                RegistryView::Native,
            )
            .expect("validated value writes to the open key");
        self.kmdf.registry_value_writes += 1;
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }

    /// `WdfRegistryDeleteValue`.
    pub(crate) fn wdf_registry_delete_value(
        &mut self,
        runtime: &PeHostRuntime,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_arg(state, memory, 0)?;
        let value_name = guest_arg(state, memory, 1)?;
        let Some(record) = self.kmdf.registry_keys.get(&key).cloned() else {
            set_status(state, STATUS_INVALID_HANDLE);
            return Ok(());
        };
        const KEY_SET_VALUE: u32 = 0x0000_0002;
        if record.access & KEY_SET_VALUE == 0 {
            set_status(state, STATUS_ACCESS_DENIED);
            return Ok(());
        }
        let (text, _, _) = read_unicode_string(memory, value_name, self.arch)?;
        if runtime
            .win32
            .ge()
            .registry_delete_value("HKLM", &record.path, &text, RegistryView::Native)
            .is_err()
        {
            set_status(state, STATUS_OBJECT_NAME_NOT_FOUND);
            return Ok(());
        }
        set_status(state, STATUS_SUCCESS);
        Ok(())
    }
}
