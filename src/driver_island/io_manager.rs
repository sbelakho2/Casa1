//! I/O manager glue: device namespace, handle table, IRP construction.

use super::*;

impl IslandState {
    pub(crate) fn io_allocate_irp(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _stack_size = guest_arg(state, memory, 0)? as u8;
        let _charge_quota = guest_arg(state, memory, 1)? != 0;
        let target = self
            .devices
            .iter()
            .rev()
            .find(|device| !device.deleted)
            .and_then(|device| self.device_ids.get(&device.guest_pointer).copied());
        let Some(target) = target else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let irp = match self.io.allocate_irp(
            target,
            IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 0),
        ) {
            Ok(irp) => irp,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let guest = match self.arena.alloc(memory, 0x100, 8) {
            Ok(guest) => guest,
            Err(_) => {
                let _ = self.io.complete_irp(irp, STATUS_CANCELLED, 0);
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        memory.write_u16(guest, IRP_TYPE);
        memory.write_u16(guest + 0x02, 0x100);
        self.irp_ids.insert(guest, irp);
        self.irp_guests.insert(irp, guest);
        state.set(Register::Rax, guest);
        Ok(())
    }

    pub(crate) fn io_free_irp(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        if let Some(irp) = self.irp_ids.remove(&guest) {
            let _ = self.io.complete_irp(irp, STATUS_CANCELLED, 0);
            self.irp_guests.remove(&irp);
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    pub(crate) fn io_complete_request(
        &mut self,
        state: &mut CpuState,
        memory: &MemoryImage,
    ) -> AppResult<()> {
        let guest = guest_arg(state, memory, 0)?;
        let Some(irp) = self.irp_ids.get(&guest).copied() else {
            set_status(state, STATUS_INVALID_PARAMETER);
            return Ok(());
        };
        let status = self
            .io
            .complete_irp(irp, STATUS_SUCCESS, 0)
            .unwrap_or(STATUS_INVALID_PARAMETER);
        set_status(state, status);
        Ok(())
    }
}

/// True when `handle` was minted by an island device-namespace open.
pub(crate) fn is_island_device_handle(runtime: &PeHostRuntime, handle: u32) -> bool {
    let runtime_id = runtime_identity(runtime);
    lock_registry()
        .device_handles
        .get(&runtime_id)
        .is_some_and(|handles| handles.contains_key(&handle))
}

/// The live island namespace for `runtime`: loaded drivers, their live device
/// objects and their symbolic links.  This is the crate-visible accessor the
/// NT directory-object surface enumerates.
pub(crate) fn island_namespace(runtime: &PeHostRuntime) -> IslandNamespace {
    let runtime_id = runtime_identity(runtime);
    let registry = lock_registry();
    let mut namespace = IslandNamespace::default();
    for island in registry
        .services
        .get(&runtime_id)
        .into_iter()
        .flat_map(|services| services.values())
    {
        let state = island.0.inner.borrow();
        namespace.drivers.push(state.driver_name.clone());
        for device in &state.devices {
            if !device.deleted && !device.name.is_empty() {
                namespace.devices.push(device.name.clone());
                namespace
                    .device_drivers
                    .push((device.name.clone(), state.driver_name.clone()));
            }
        }
        namespace
            .symbolic_links
            .extend(state.symbolic_links.iter().cloned());
    }
    namespace.drivers.sort();
    namespace.drivers.dedup();
    namespace.devices.sort();
    namespace.devices.dedup();
    namespace.device_drivers.sort();
    namespace.device_drivers.dedup();
    namespace.symbolic_links.sort();
    namespace.symbolic_links.dedup();
    namespace
}

/// Normalize an object-directory path: `/` to `\`, trailing separators
/// removed.  The root object directory stays a single `\`.
pub(crate) fn normalize_directory_path(raw: &str) -> String {
    let mut path = raw.trim_matches('\0').trim().replace('/', "\\");
    if path.len() > 1 {
        while path.ends_with('\\') {
            path.pop();
        }
    }
    path
}

/// Case-insensitive object-path prefix strip.
pub(crate) fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

/// Canonicalize a directory-object path against the live island namespace.
///
/// The root object directory `\`, the four top-level directories and the
/// per-device / per-driver subtrees are all resolved from real state:
///
/// - `\` enumerates the top-level directories;
/// - `\Device` enumerates live device objects;
/// - `\Device\<name>` matches a live device object exactly, or an existing
///   parent of a deeper live device path (a real subtree);
/// - `\Driver` enumerates loaded drivers;
/// - `\Driver\<name>` matches a loaded driver case-insensitively.
///
/// A miss returns `None`; the caller decides between
/// `STATUS_OBJECT_NAME_NOT_FOUND` (parent exists) and
/// `STATUS_OBJECT_PATH_NOT_FOUND` (parent does not).
pub(crate) fn canonical_directory_name(namespace: &IslandNamespace, raw: &str) -> Option<String> {
    let path = normalize_directory_path(raw);
    if path == "\\" {
        return Some(path);
    }
    let upper = path.to_ascii_uppercase();
    match upper.as_str() {
        "\\DEVICE" => return Some("\\Device".to_string()),
        "\\DRIVER" => return Some("\\Driver".to_string()),
        "\\GLOBAL??" => return Some("\\GLOBAL??".to_string()),
        "\\??" => return Some("\\??".to_string()),
        _ => {}
    }
    if let Some(rest) = strip_prefix_ci(&path, "\\Device\\") {
        let prefix = format!("\\Device\\{rest}");
        // An exact live device object is the canonical spelling the island
        // registered.
        if let Some(device) = namespace
            .devices
            .iter()
            .find(|device| device.eq_ignore_ascii_case(&prefix))
        {
            return Some(device.clone());
        }
        // An intermediate segment of a deeper live device path is a real
        // subtree even when no device object is registered at that path.
        let child_prefix = format!("{prefix}\\");
        if namespace
            .devices
            .iter()
            .any(|device| strip_prefix_ci(device, &child_prefix).is_some())
        {
            return Some(prefix);
        }
        return None;
    }
    if let Some(rest) = strip_prefix_ci(&path, "\\Driver\\") {
        return namespace
            .drivers
            .iter()
            .find(|driver| driver.eq_ignore_ascii_case(rest))
            .map(|driver| format!("\\Driver\\{driver}"));
    }
    None
}

/// The direct child name of `parent` in the full object path `full`, or
/// `None` when `full` is not strictly under `parent`.
pub(crate) fn direct_child_name(parent: &str, full: &str) -> Option<String> {
    let rest = strip_prefix_ci(full, parent)?;
    let rest = rest.strip_prefix('\\')?;
    if rest.is_empty() {
        return None;
    }
    Some(match rest.split_once('\\') {
        Some((first, _)) => first.to_string(),
        None => rest.to_string(),
    })
}

/// The entries of one canonical directory object, as `(name, type_name)`
/// pairs built from the live island registry.
pub(crate) fn directory_entries(
    namespace: &IslandNamespace,
    directory: &str,
) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    if directory == "\\" {
        entries.push(("Device".to_string(), "Directory".to_string()));
        entries.push(("Driver".to_string(), "Directory".to_string()));
        entries.push(("GLOBAL??".to_string(), "Directory".to_string()));
        entries.push(("??".to_string(), "SymbolicLink".to_string()));
    } else if directory == "\\Device" {
        for device in &namespace.devices {
            if let Some(name) = direct_child_name("\\Device", device) {
                entries.push((name, "Device".to_string()));
            }
        }
    } else if directory == "\\Driver" {
        for driver in &namespace.drivers {
            entries.push((driver.clone(), "Driver".to_string()));
        }
    } else if strip_prefix_ci(directory, "\\Device\\").is_some() {
        // Per-device subtree: real child device objects (deeper registered
        // device paths) appear as the next path segment.
        for device in &namespace.devices {
            if device.eq_ignore_ascii_case(directory) {
                continue;
            }
            if let Some(name) = direct_child_name(directory, device) {
                entries.push((name, "Device".to_string()));
            }
        }
    } else if let Some(driver_name) = strip_prefix_ci(directory, "\\Driver\\") {
        // Per-driver subtree: the live device objects the driver created.
        for (device, driver) in &namespace.device_drivers {
            if !driver.eq_ignore_ascii_case(driver_name) {
                continue;
            }
            if let Some(name) = direct_child_name("\\Device", device) {
                entries.push((name, "Device".to_string()));
            }
        }
    } else {
        for (link, _) in &namespace.symbolic_links {
            let name = strip_prefix_ci(link, "\\??\\")
                .or_else(|| strip_prefix_ci(link, "\\DosDevices\\"))
                .or_else(|| strip_prefix_ci(link, "\\GLOBAL??\\"));
            if let Some(name) = name
                && !name.is_empty()
            {
                entries.push((name.to_string(), "SymbolicLink".to_string()));
            }
        }
    }
    let mut seen = BTreeSet::new();
    entries.retain(|(name, ty)| seen.insert((name.to_ascii_lowercase(), ty.clone())));
    entries.sort();
    entries
}

/// Mint a directory-object handle for an already-canonical directory name.
pub(crate) fn open_directory_object(runtime: &PeHostRuntime, path: &str) -> u32 {
    let runtime_id = runtime_identity(runtime);
    let mut registry = lock_registry();
    let counter = registry
        .next_directory_handle
        .entry(runtime_id)
        .or_insert(0);
    let handle = DIRECTORY_HANDLE_BASE.wrapping_add(*counter);
    *counter = counter.wrapping_add(1);
    registry
        .directory_handles
        .entry(runtime_id)
        .or_default()
        .insert(
            handle,
            IslandDirectoryHandle {
                path: path.to_string(),
            },
        );
    handle
}

/// The canonical directory path behind a live directory-object handle.
pub(crate) fn directory_object_path(runtime: &PeHostRuntime, handle: u32) -> Option<String> {
    let runtime_id = runtime_identity(runtime);
    lock_registry()
        .directory_handles
        .get(&runtime_id)
        .and_then(|handles| handles.get(&handle))
        .map(|directory| directory.path.clone())
}

/// Close a directory-object handle.  Returns `true` only for a live handle
/// owned by the island namespace (a second close reports `false`).
pub(crate) fn close_directory_object(runtime: &PeHostRuntime, handle: u32) -> bool {
    let runtime_id = runtime_identity(runtime);
    lock_registry()
        .directory_handles
        .get_mut(&runtime_id)
        .and_then(|handles| handles.remove(&handle))
        .is_some()
}

/// Close an island device-namespace handle.  Returns `true` when the handle
/// belonged to the island namespace and was released by this call (a second
/// close therefore reports `false` and falls through to the invalid-handle
/// path).
pub(crate) fn close_island_device_handle(runtime: &PeHostRuntime, handle: u32) -> bool {
    let runtime_id = runtime_identity(runtime);
    lock_registry()
        .device_handles
        .get_mut(&runtime_id)
        .and_then(|handles| handles.remove(&handle))
        .is_some()
}

/// `NtCreateFile` island hook: when `raw_path` names a loaded island device
/// (directly or through a symbolic link), mint a device handle and write it
/// to `handle_ptr`.  Returns `None` when the path is not in the island
/// namespace, `Some(status)` otherwise.
pub(crate) fn nt_open_island_device(
    runtime: &PeHostRuntime,
    memory: &mut MemoryImage,
    raw_path: &str,
    handle_ptr: u64,
) -> Option<i32> {
    let device = resolve_island_device(runtime, raw_path)?;
    if handle_ptr == 0 || crate::host_thunks::validate_guest_pointer(memory, handle_ptr, 4).is_err()
    {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let runtime_id = runtime_identity(runtime);
    let mut registry = lock_registry();
    let counter = registry.next_device_handle.entry(runtime_id).or_insert(0);
    let handle = DEVICE_HANDLE_BASE.wrapping_add(*counter);
    *counter = counter.wrapping_add(1);
    registry
        .device_handles
        .entry(runtime_id)
        .or_default()
        .insert(handle, device);
    drop(registry);
    memory.write_u32(handle_ptr, handle);
    Some(STATUS_SUCCESS)
}

/// Dispatch an island device handle's I/O through the real driver
/// `MajorFunction`.  Returns `None` for handles outside the island namespace.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_island_device_io(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    handle: u32,
    major: IrpMajorFunction,
    io_control_code: u32,
    input_ptr: u64,
    input_len: u32,
    output_ptr: u64,
    output_len: u32,
    byte_offset: u64,
) -> AppResult<Option<(i32, usize)>> {
    let runtime_id = runtime_identity(runtime);
    let (device, inner) = {
        let registry = lock_registry();
        let Some(device) = registry
            .device_handles
            .get(&runtime_id)
            .and_then(|handles| handles.get(&handle))
            .cloned()
        else {
            return Ok(None);
        };
        let service_key = device.service_name.to_ascii_lowercase();
        let Some(shared) = registry
            .services
            .get(&runtime_id)
            .and_then(|services| services.get(&service_key))
        else {
            return Ok(Some((STATUS_INVALID_HANDLE, 0)));
        };
        (device, shared.0.inner.clone())
    };
    // A handle opened to a device that has since been deleted is stale.
    let live = inner
        .borrow()
        .device_ids
        .get(&device.device_guest)
        .is_some_and(|id| *id == device.device_id);
    if !live {
        return Ok(Some((STATUS_INVALID_HANDLE, 0)));
    }
    let result = DriverIsland { inner }.dispatch_irp(
        runtime,
        memory,
        device.device_guest,
        major,
        io_control_code,
        input_ptr,
        input_len,
        output_ptr,
        output_len,
        byte_offset,
    )?;
    Ok(Some(result))
}

pub(crate) fn normalize_device_path(raw: &str) -> String {
    let mut path = raw
        .trim_matches(|ch| ch == '\0' || ch == ' ')
        .replace('/', "\\");
    if let Some(rest) = path.strip_prefix("\\\\.\\") {
        path = format!("\\??\\{rest}");
    }
    if path.len() > 1 {
        while path.ends_with('\\') {
            path.pop();
        }
    }
    path
}

pub(crate) fn resolve_island_device(
    runtime: &PeHostRuntime,
    raw_path: &str,
) -> Option<IslandDeviceHandle> {
    let path = normalize_device_path(raw_path);
    if path.is_empty() {
        return None;
    }
    let runtime_id = runtime_identity(runtime);
    let registry = lock_registry();
    for island in registry
        .services
        .get(&runtime_id)
        .into_iter()
        .flat_map(|services| services.values())
    {
        let state = island.0.inner.borrow();
        let direct = state
            .devices
            .iter()
            .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(&path));
        let link_target = state
            .symbolic_links
            .iter()
            .find_map(|(link, target)| link.eq_ignore_ascii_case(&path).then_some(target.as_str()));
        let linked = link_target.and_then(|target| {
            state
                .devices
                .iter()
                .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(target))
        });
        // `\??\Name` is also accepted for a device without an explicit
        // symbolic link (the NT object-manager DOS-device prefix).
        let dos_prefixed = {
            let rest = path
                .strip_prefix("\\??\\")
                .or_else(|| path.strip_prefix("\\DosDevices\\"));
            rest.and_then(|rest| {
                let target = format!("\\Device\\{rest}");
                state
                    .devices
                    .iter()
                    .find(|device| !device.deleted && device.name.eq_ignore_ascii_case(&target))
            })
        };
        let Some(device) = direct.or(linked).or(dos_prefixed) else {
            continue;
        };
        let device_id = state
            .device_ids
            .get(&device.guest_pointer)
            .copied()
            .expect("live device object always has an island id");
        return Some(IslandDeviceHandle {
            service_name: state.driver_name.clone(),
            device_guest: device.guest_pointer,
            device_id,
        });
    }
    None
}
