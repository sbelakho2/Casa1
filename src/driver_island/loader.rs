//! PE image mapping, import/relocation patching and service loading.

use super::*;

pub(crate) struct ActiveIsland {
    pub(crate) previous: Option<Rc<RefCell<IslandState>>>,
}

impl ActiveIsland {
    pub(crate) fn install(island: Rc<RefCell<IslandState>>) -> Self {
        let previous = ACTIVE_ISLAND.with(|slot| slot.replace(Some(island)));
        Self { previous }
    }
}

impl Drop for ActiveIsland {
    fn drop(&mut self) {
        let previous = self.previous.take();
        ACTIVE_ISLAND.with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Block-boundary preemption tick for the active island.
///
/// The callback executor calls this after every translated block when it is
/// running an island system thread.  It lets a pure guest loop (no host shim
/// calls) observe its quantum deadline, a pending termination, or a pending
/// virtual interrupt, and yield exactly like a shim boundary would.
pub(crate) fn tick_active_island_preemption(runtime: &mut PeHostRuntime) {
    let inner = ACTIVE_ISLAND.with(|slot| slot.borrow().clone());
    let Some(inner) = inner else {
        return;
    };
    if let Ok(mut state) = inner.try_borrow_mut() {
        state.maybe_preempt(runtime);
    }
}

pub(crate) fn allocate_shim(runtime: &mut PeHostRuntime, function: DriverShim) -> u64 {
    let address = runtime.next_thunk_address;
    runtime.next_thunk_address += 0x10;
    runtime
        .host_thunks
        .insert(address, HostThunk::DriverIslandShim { function });
    address
}

pub(crate) fn patch_imports(
    driver: &mut LoadedDriver,
    runtime: &mut PeHostRuntime,
    arch: GuestArch,
) -> (ImportReport, Vec<(String, String, KernelApiSet)>) {
    let mut report = ImportReport {
        resolved: Vec::new(),
        unresolved: Vec::new(),
    };
    let pointer_bytes = arch.pointer_bytes();
    let imports = driver.imports.clone();
    for module in imports {
        for (index, symbol) in module.symbols.iter().enumerate() {
            let target = (module.dll.clone(), symbol.display(), module.set);
            let address = match symbol {
                ImportRef::Name(name) => {
                    DriverShim::for_import(name).map(|function| allocate_shim(runtime, function))
                }
                ImportRef::Ordinal(_) => None,
            };
            let offset = module.first_thunk_rva as usize + index * pointer_bytes;
            match address {
                Some(address) if offset + pointer_bytes <= driver.image.len() => {
                    write_image_pointer(&mut driver.image, offset, address, arch);
                    report.resolved.push(target);
                }
                _ => report.unresolved.push(target),
            }
        }
    }
    // Delay imports are resolved eagerly at load time (lazy resolution is
    // not required by the island contract): every name is mapped through the
    // same kernel shim table and the delay IAT is written before entry runs.
    let delay_imports = driver.delay_imports.clone();
    for module in delay_imports {
        let set = KernelApiSet::classify(&module.dll);
        for (index, symbol) in module.symbols.iter().enumerate() {
            let target = (module.dll.clone(), symbol.display(), set);
            let address = match symbol {
                ImportRef::Name(name) => {
                    DriverShim::for_import(name).map(|function| allocate_shim(runtime, function))
                }
                ImportRef::Ordinal(_) => None,
            };
            let offset = module.iat_rva as usize + index * pointer_bytes;
            match address {
                Some(address) if offset + pointer_bytes <= driver.image.len() => {
                    write_image_pointer(&mut driver.image, offset, address, arch);
                    // Keep the delay INT consistent with the patched IAT so a
                    // runtime helper that re-reads it sees the same targets.
                    let int_offset = module.int_rva as usize + index * pointer_bytes;
                    if int_offset + pointer_bytes <= driver.image.len() {
                        write_image_pointer(&mut driver.image, int_offset, address, arch);
                    }
                    report.resolved.push(target);
                }
                _ => report.unresolved.push(target),
            }
        }
    }
    let unresolved = report.unresolved.clone();
    (report, unresolved)
}

pub(crate) fn runtime_identity(runtime: &PeHostRuntime) -> usize {
    runtime as *const PeHostRuntime as usize
}

pub(crate) fn loaded_driver_key(runtime: &PeHostRuntime, service_name: &str) -> (usize, String) {
    (runtime_identity(runtime), service_name.to_ascii_lowercase())
}

/// Read a `PUNICODE_STRING` argument, rejecting null, unmapped, and
/// structurally invalid descriptors.
pub(crate) fn read_service_unicode_string(
    memory: &MemoryImage,
    address: u64,
    arch: GuestArch,
) -> Result<String, i32> {
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let length = memory
        .read_u16(address)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let _maximum = memory
        .read_u16(address + 2)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let buffer = read_guest_pointer(memory, address + unicode_string_buffer_offset(arch), arch)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    if length == 0 || length % 2 != 0 || buffer == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut bytes = vec![0_u8; length as usize];
    memory
        .read_into(buffer, &mut bytes)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| STATUS_INVALID_PARAMETER)
}

/// Extract the service name from a `\Registry\Machine\System\
/// CurrentControlSet\Services\<name>` path.  The prefix comparison is
/// case-insensitive, matching the object manager's path semantics.
pub(crate) fn parse_service_name(raw: &str) -> Result<String, i32> {
    let path = raw.trim_matches(|ch| ch == '\0' || ch == ' ');
    let lower = path.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix(MACHINE_REGISTRY_PREFIX)
        .map(|_| &path[MACHINE_REGISTRY_PREFIX.len()..])
    else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    if !rest
        .to_ascii_lowercase()
        .starts_with(SERVICE_REGISTRY_PREFIX)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let service = rest[SERVICE_REGISTRY_PREFIX.len()..].trim_matches('\\');
    let service = service.split('\\').next().unwrap_or("");
    if service.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(service.to_string())
}

/// Resolve `SYSTEM\CurrentControlSet\Services\<name>` case-insensitively
/// through the real registry store (the same GE registry the Win32 Reg*
/// layer and `NtOpenKey` use).
pub(crate) fn resolve_service_key(runtime: &PeHostRuntime, service_name: &str) -> Option<String> {
    let mut actual = String::new();
    for segment in ["SYSTEM", "CurrentControlSet", "Services", service_name] {
        let children = runtime
            .win32
            .ge()
            .registry_enum_keys("HKLM", &actual, RegistryView::Native)
            .ok()?;
        let found = children
            .iter()
            .find(|child| child.eq_ignore_ascii_case(segment))?;
        actual = if actual.is_empty() {
            found.clone()
        } else {
            format!("{actual}\\{found}")
        };
    }
    Some(actual)
}

/// Read `ImagePath` from the resolved service key and expand it against the
/// GE file system.  Only `REG_SZ`/`REG_EXPAND_SZ` values carry an image path.
pub(crate) fn read_service_image_path(
    runtime: &PeHostRuntime,
    registry_key: &str,
) -> Result<String, i32> {
    let value_names = runtime
        .win32
        .ge()
        .registry_enum_values("HKLM", registry_key, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let value_name = value_names
        .iter()
        .find(|name| name.eq_ignore_ascii_case("ImagePath"))
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let stored = runtime
        .win32
        .registry_get_value("HKLM", registry_key, value_name, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    match stored.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => {}
        _ => return Err(crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32),
    }
    let image_path = stored
        .data
        .as_str()
        .ok_or(crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32)?;
    Ok(expand_driver_image_path(
        image_path,
        &runtime.process_environment,
    ))
}

/// Read the service `StartType` (`SERVICE_BOOT_START`..`SERVICE_DISABLED`).
/// A missing value is accepted (no start-type constraint).
pub(crate) fn service_start_type(
    runtime: &PeHostRuntime,
    registry_key: &str,
) -> Result<Option<u32>, i32> {
    let value_names = runtime
        .win32
        .ge()
        .registry_enum_values("HKLM", registry_key, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let Some(value_name) = value_names
        .iter()
        .find(|name| name.eq_ignore_ascii_case("StartType"))
    else {
        return Ok(None);
    };
    let stored = runtime
        .win32
        .registry_get_value("HKLM", registry_key, value_name, RegistryView::Native)
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let raw = stored
        .data
        .as_u64()
        .or_else(|| stored.data.as_str().and_then(|text| text.parse().ok()))
        .ok_or(STATUS_INVALID_PARAMETER)?;
    Ok(Some(raw as u32))
}

/// Expand a driver `ImagePath`: strip quotes, expand every `%VAR%` against
/// the GE process environment, map `\SystemRoot` / `%SystemRoot%` to
/// `C:\Windows`, unwrap `\??\` / `\DosDevices\`, and root relative paths at
/// the Windows directory.
pub(crate) fn expand_driver_image_path(
    raw: &str,
    environment: &BTreeMap<String, String>,
) -> String {
    const WINDOWS: &str = "C:\\Windows";
    let mut path = raw.trim().to_string();
    if let Some(quoted) = path.strip_prefix('"') {
        if let Some(end) = quoted.find('"') {
            path = quoted[..end].to_string();
        }
    }
    path = expand_environment_percent(&path, environment);
    path = replace_ascii_case_insensitive(&path, "%systemroot%", WINDOWS);
    path = replace_ascii_case_insensitive(&path, "\\systemroot", WINDOWS);
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("\\??\\") {
        path = path[4..].to_string();
    } else if lower.starts_with("\\dosdevices\\") {
        path = path[12..].to_string();
    }
    if !path.contains(':') {
        path = if path.starts_with('\\') {
            format!("{WINDOWS}{path}")
        } else {
            format!("{WINDOWS}\\{path}")
        };
    }
    path.replace('/', "\\")
}

pub(crate) fn replace_ascii_case_insensitive(
    input: &str,
    needle: &str,
    replacement: &str,
) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut start = 0;
    while let Some(offset) = lower[start..].find(needle) {
        let position = start + offset;
        output.push_str(&input[start..position]);
        output.push_str(replacement);
        start = position + needle.len();
    }
    output.push_str(&input[start..]);
    output
}

/// Open the image through the runtime's real file tables and read its bytes.
pub(crate) fn read_service_image(
    runtime: &mut PeHostRuntime,
    image_path: &str,
) -> Result<Vec<u8>, i32> {
    let handle = runtime
        .win32
        .create_file_w(
            image_path,
            FileAccess::read_only(),
            ShareMode::all(),
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let bytes = runtime
        .win32
        .read_file(handle, usize::MAX)
        .map_err(|_| crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32);
    let _ = runtime.win32.close_handle(handle);
    bytes
}

/// Expand `%NAME%` references against the GE process environment,
/// case-insensitively.  An undefined variable is copied through literally,
/// matching `ExpandEnvironmentStringsW`.
pub(crate) fn expand_environment_percent(
    source: &str,
    environment: &BTreeMap<String, String>,
) -> String {
    let mut expanded = String::with_capacity(source.len());
    let mut remainder = source;
    while let Some(start) = remainder.find('%') {
        expanded.push_str(&remainder[..start]);
        let after_start = &remainder[start + 1..];
        if let Some(end) = after_start.find('%') {
            let name = &after_start[..end];
            if let Some((_, value)) = environment
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
            {
                expanded.push_str(value);
                remainder = &after_start[end + 1..];
                continue;
            }
        }
        expanded.push('%');
        remainder = after_start;
    }
    expanded.push_str(remainder);
    expanded
}

/// Record one driver load/unload trace event on the runtime.
pub(crate) fn record_driver_event(
    runtime: &mut PeHostRuntime,
    call_id: &str,
    service_name: &str,
    status: i32,
    image_path: Option<&str>,
) {
    let index = runtime.next_trace_index;
    let mut parameters = BTreeMap::from([
        ("service".to_string(), json!(service_name)),
        ("status".to_string(), json!(format!("{status:#010x}"))),
    ]);
    if let Some(path) = image_path {
        parameters.insert("image_path".to_string(), json!(path));
    }
    runtime.trace_events.push(TraceEvent {
        event_index: index,
        category: "driver".to_string(),
        call_id: call_id.to_string(),
        parameters,
        return_value: json!(status),
        get_last_error: None,
        side_effect_hashes: Vec::new(),
    });
    runtime.next_trace_index += 1;
}

pub(crate) fn nt_load_error_status(error: &AppError) -> i32 {
    match error.code {
        ReasonCode::RcFsNotFound | ReasonCode::RcRegistryNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        _ => crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32,
    }
}

#[cfg(test)]
pub(crate) fn with_loaded_driver<R>(
    runtime: &PeHostRuntime,
    service_name: &str,
    inspect: impl FnOnce(&DriverIsland) -> R,
) -> Option<R> {
    let key = loaded_driver_key(runtime, service_name);
    lock_registry()
        .services
        .get(&key.0)
        .and_then(|services| services.get(&key.1))
        .map(|island| inspect(&island.0))
}

/// Drop every island registration and handle owned by `runtime`.  Called by
/// the runtime's `Drop` so a reused host address never observes a stale
/// service namespace.
pub(crate) fn forget_runtime(runtime: &PeHostRuntime) {
    let runtime_id = runtime_identity(runtime);
    let mut registry = lock_registry();
    registry.services.remove(&runtime_id);
    registry.device_handles.remove(&runtime_id);
    registry.next_device_handle.remove(&runtime_id);
    registry.directory_handles.remove(&runtime_id);
    registry.next_directory_handle.remove(&runtime_id);
}

#[cfg(test)]
pub(crate) fn reset_runtime_registry(runtime: &PeHostRuntime) {
    forget_runtime(runtime);
}

#[cfg(test)]
pub(crate) fn take_last_unloaded_driver() -> Option<DriverIsland> {
    LAST_UNLOADED_DRIVER.with(|slot| slot.borrow_mut().take())
}

pub(crate) fn driver_image_error(status: u32) -> AppError {
    AppError::new(
        ReasonCode::RcPeParseInvalid,
        format!("driver image rejected with NTSTATUS {status:#010x}"),
    )
}

pub(crate) fn nt_error(operation: &str, status: i32) -> AppError {
    AppError::new(
        ReasonCode::RcIo,
        format!("{operation} failed with NTSTATUS {status:#010x}"),
    )
}

/// The guest architecture of a PE image, rejecting a machine/optional-header
/// magic mismatch (the only images the island refuses for bitness reasons).
pub(crate) fn pe_image_arch(bytes: &[u8]) -> Result<GuestArch, String> {
    if bytes.len() < 0x40 || read_u16(bytes, 0) != Some(0x5A4D) {
        return Err("driver island requires a PE image".to_string());
    }
    let pe = read_u32(bytes, 0x3C).ok_or("truncated DOS header")? as usize;
    if read_u32(bytes, pe) != Some(0x0000_4550) {
        return Err("driver island requires a PE image".to_string());
    }
    let machine = read_u16(bytes, pe + 4).ok_or("truncated COFF header")?;
    let magic = read_u16(bytes, pe + 24).ok_or("truncated optional header")?;
    match (machine, magic) {
        (0x8664, 0x020B) => Ok(GuestArch::X64),
        (0x014C, 0x010B) => Ok(GuestArch::X86),
        (0x8664, 0x010B) => Err("PE32 optional header on an x64 machine".to_string()),
        (0x014C, 0x020B) => Err("PE32+ optional header on an x86 machine".to_string()),
        (other, _) => Err(format!("driver island rejects machine {other:#x}")),
    }
}

/// Returns `(preferred image base, SizeOfImage)` from the PE headers when the
/// basic DOS/PE/optional-header shape is present.
pub(crate) fn pe_layout_hint(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < 0x40 || read_u16(bytes, 0) != Some(0x5A4D) {
        return None;
    }
    let pe = read_u32(bytes, 0x3C)? as usize;
    if read_u32(bytes, pe) != Some(0x0000_4550) {
        return None;
    }
    let coff = pe + 4;
    let optional = coff + 20;
    let magic = read_u16(bytes, optional)?;
    let (base, size_offset) = match magic {
        0x020B => (read_u64(bytes, optional + 24)?, optional + 56),
        0x010B => (read_u32(bytes, optional + 28)? as u64, optional + 56),
        _ => return None,
    };
    let size = read_u32(bytes, size_offset)? as u64;
    Some((base, size.max(0x1000)))
}

pub(crate) fn choose_placement(
    runtime: &PeHostRuntime,
    preferred: u64,
    size_hint: u64,
    arch: GuestArch,
) -> AppResult<(u64, u64)> {
    let fallback = if arch == GuestArch::X86 {
        DEFAULT_IMAGE_BASE_X86
    } else {
        DEFAULT_IMAGE_BASE
    };
    let preferred_valid = preferred >= 0x1_0000
        && preferred & 0xFFFF == 0
        && (arch != GuestArch::X86 || preferred < X86_ADDRESS_LIMIT);
    let start = if preferred_valid { preferred } else { fallback };
    let size = size_hint.max(0x1000);
    for index in 0..256_u64 {
        let base = start.wrapping_add(index * 0x40_0000);
        let arena = align_up(base.saturating_add(size), 0x1_0000);
        if arch == GuestArch::X86
            && (base.saturating_add(size) > X86_ADDRESS_LIMIT
                || arena.saturating_add(ARENA_SIZE) > X86_ADDRESS_LIMIT)
        {
            break;
        }
        let stack_end = STACK_BASE + STACK_SIZE;
        if base < stack_end && base.saturating_add(size) > STACK_BASE {
            continue;
        }
        if arena < stack_end && arena.saturating_add(ARENA_SIZE) > STACK_BASE {
            continue; // coverage: unreachable — arena >= align_up(STACK_BASE + 0x1000, 0x10000) = 0x20000 > stack_end 0x12000
        }
        if range_is_free(runtime, base, size) && range_is_free(runtime, arena, ARENA_SIZE) {
            return Ok((base, arena));
        }
    }
    Err(AppError::new(
        ReasonCode::RcIo,
        format!("no free guest address range for a {size:#x}-byte driver image"),
    ))
}

pub(crate) fn range_is_free(runtime: &PeHostRuntime, base: u64, size: u64) -> bool {
    let vm = runtime.win32.address_space();
    let start = base & !0xFFF;
    let end = base.saturating_add(size);
    let mut address = start;
    while address < end {
        if vm.query(address).state != VmState::Free {
            return false;
        }
        address = address.saturating_add(0x1000);
    }
    true
}
