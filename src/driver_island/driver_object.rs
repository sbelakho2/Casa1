//! `DriverEntry`/`DriverUnload`, driver object lifecycle and introspection.

use super::*;

impl DriverIsland {
    /// Loads `bytes` as a PE64 driver, maps it into `memory`, resolves its
    /// imports against the kernel shim table, builds a real guest
    /// `DRIVER_OBJECT`, and executes `DriverEntry(DriverObject, RegistryPath)`
    /// through `runtime`'s guest callback entry.
    ///
    /// A negative `DriverEntry` status is returned as an island state (the
    /// call itself succeeded); malformed images and unresolved imports are
    /// errors.
    #[cfg(test)]
    pub(crate) fn load_and_start(
        bytes: &[u8],
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> AppResult<Self> {
        Self::load_and_start_named(bytes, "CasaDriver", runtime, memory)
    }

    /// Like [`Self::load_and_start`] with an explicit driver/service name.
    pub(crate) fn load_and_start_named(
        bytes: &[u8],
        driver_name: &str,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> AppResult<Self> {
        let image_arch = pe_image_arch(bytes)
            .map_err(|message| AppError::new(ReasonCode::RcPeParseInvalid, message))?;
        if runtime.guest_arch != image_arch {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "driver island requires a {} guest runtime for this image",
                    match image_arch {
                        GuestArch::X86 => "x86",
                        GuestArch::X64 => "x64",
                    }
                ),
            ));
        }
        let default_base = if image_arch == GuestArch::X86 {
            DEFAULT_IMAGE_BASE_X86
        } else {
            DEFAULT_IMAGE_BASE
        };
        let (preferred, size_hint) = pe_layout_hint(bytes).unwrap_or((default_base, 0x10000));
        let (image_base, arena_base) = choose_placement(runtime, preferred, size_hint, image_arch)?;
        let mut driver =
            load_driver_image(bytes, image_base).map_err(|status| driver_image_error(status))?;
        if driver.machine
            != if image_arch == GuestArch::X86 {
                0x014C
            } else {
                0x8664
            }
        {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!(
                    "driver image optional header does not match machine {:#x}",
                    driver.machine
                ),
            ));
        }

        // Resolve the regular imports and the delay-import table at load
        // time; both IATs are patched before DriverEntry executes.
        let (imports, unresolved) = patch_imports(&mut driver, runtime, image_arch);
        if !unresolved.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcImportMissing,
                format!(
                    "unsupported or unresolved driver imports: {}",
                    unresolved
                        .iter()
                        .map(|(dll, symbol, set)| format!("{set:?}:{dll}!{symbol}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }

        memory.set_vm(runtime.win32.address_space_mut());
        {
            let vm = runtime.win32.address_space_mut();
            let image_size = driver.size_of_image as u64;
            vm.register(image_base, image_size, VmRegionKind::Image);
            vm.commit(
                image_base,
                image_size,
                VmProtection::READ_WRITE_EXECUTE,
                false,
            );
            vm.register(STACK_BASE, STACK_SIZE, VmRegionKind::Stack);
            vm.commit(STACK_BASE, STACK_SIZE, VmProtection::READ_WRITE, false);
            vm.register(arena_base, ARENA_SIZE, VmRegionKind::Private);
            vm.commit(arena_base, ARENA_SIZE, VmProtection::READ_WRITE, false);
        }
        memory.map_bytes(image_base, &driver.image);
        memory.map_bytes(STACK_BASE, &vec![0_u8; STACK_SIZE as usize]);

        let mut io = IoManager::new();
        let casak_driver = io
            .create_driver(driver_name, DeviceExtension::new())
            .map_err(|status| nt_error("IoCreateDriver", status))?;
        let default_dispatch = allocate_shim(runtime, DriverShim::IrpDispatch);
        let current_process = ProcessId(runtime.win32.current_process_id());
        let current_thread = ThreadId(runtime.win32.current_thread_id());
        let mut process = ProcessManager::new();
        process
            .ensure_process(current_process, driver_name, None)
            .map_err(|status| nt_error("PsGetCurrentProcessId", status))?;
        process
            .ensure_thread(current_process, current_thread, 0)
            .map_err(|status| nt_error("PsGetCurrentThreadId", status))?;
        let mut system_threads = SystemThreadManager::new();
        system_threads
            .adopt_thread(current_process, current_thread)
            .map_err(|status| nt_error("PsGetCurrentThreadId", status))?;

        let registry_path =
            format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{driver_name}");
        let mut state = IslandState {
            arch: image_arch,
            image_base,
            image_size: driver.size_of_image,
            driver_name: driver_name.to_string(),
            registry_path: registry_path.clone(),
            driver_object_guest: 0,
            registry_path_guest: 0,
            default_dispatch,
            entry_rva: driver.entry_rva,
            entry_guest: driver.address_of(driver.entry_rva),
            unload_rva: driver.unload_rva,
            unload_guest: driver.unload_rva.map(|rva| driver.address_of(rva)),
            status: STATUS_SUCCESS,
            loaded: false,
            unloaded: false,
            io,
            casak_driver,
            devices: Vec::new(),
            device_ids: BTreeMap::new(),
            debug_log: Vec::new(),
            imports,
            pool: TaggedPool::new(4 * 1024 * 1024),
            pool_blocks: BTreeMap::new(),
            irp_ids: BTreeMap::new(),
            irp_guests: BTreeMap::new(),
            symbolic_links: Vec::new(),
            kmdf: KmdfState::default(),
            kernel: KernelState::default(),
            process,
            current_process,
            current_thread,
            diagnostics: DiagnosticsManager::new(),
            alpc: AlpcManager::new(),
            alpc_handles: BTreeMap::new(),
            next_alpc_handle: 1,
            executive: Executive::new(),
            system_threads,
            interrupts: InterruptManager::new(),
            thread_cpus: BTreeMap::new(),
            thread_quantum: Duration::from_millis(4),
            slice_deadline: None,
            current_system_thread: None,
            pending_interrupts: VecDeque::new(),
            notification_waits: 0,
            removed_device_objects: BTreeSet::new(),
            arena: IslandArena {
                cursor: arena_base,
                end: arena_base + ARENA_SIZE,
            },
        };

        let driver_name_guest = allocate_unicode_string(&mut state, memory, driver_name)?;
        let registry_guest = allocate_unicode_string(&mut state, memory, &registry_path)?;
        let driver_object =
            state
                .arena
                .alloc(memory, driver_object_size(image_arch) as usize, 16)?;
        let extension = state.arena.alloc(memory, 0x28, 16)?;
        state.driver_object_guest = driver_object;
        state.registry_path_guest = registry_guest;
        build_driver_object(
            &state,
            memory,
            driver_object,
            extension,
            driver_name_guest,
            registry_guest,
            default_dispatch,
        )?;

        let inner = Rc::new(RefCell::new(state));
        let status = {
            let _active = ActiveIsland::install(inner.clone());
            let mut cpu = CpuState::new(image_arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
            let entry = inner.borrow().entry_guest;
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                entry,
                &[driver_object, registry_guest],
                "DriverEntry",
            )?;
            result as u32 as i32
        };
        {
            let mut state = inner.borrow_mut();
            state.status = status;
            state.loaded = status_is_success(status);
        }
        Ok(Self { inner })
    }

    /// Executes the exported `DriverUnload` (when present), then deletes any
    /// devices the driver left behind.  Returns the unload status, or `None`
    /// when the island was already unloaded or had no unload routine.
    pub(crate) fn unload(
        &mut self,
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<i32>> {
        let inner = self.inner.clone();
        let (unloaded, unload_guest, driver_object) = {
            let state = inner.borrow();
            (
                state.unloaded,
                state.unload_guest,
                state.driver_object_guest,
            )
        };
        if unloaded {
            return Ok(None);
        }
        if self.has_open_device_handles(runtime) {
            return Ok(Some(STATUS_DEVICE_BUSY));
        }
        let arch = inner.borrow().arch;
        let status = if let Some(entry) = unload_guest {
            let _active = ActiveIsland::install(inner.clone());
            let mut cpu = CpuState::new(arch);
            cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
            let result = runtime.execute_guest_callback(
                &mut cpu,
                memory,
                entry,
                &[driver_object],
                "DriverUnload",
            )?;
            Some(result as u32 as i32)
        } else {
            None
        };

        let mut callbacks = Vec::new();
        {
            let mut state = inner.borrow_mut();
            let driver_handle = state.kmdf.driver_handle;
            if driver_handle != 0 {
                state.collect_delete_callbacks(driver_handle, &mut callbacks);
            }
        }
        if !callbacks.is_empty() {
            let _active = ActiveIsland::install(inner.clone());
            for call in callbacks {
                let mut cpu = CpuState::new(arch);
                cpu.set(Register::Rsp, STACK_BASE + STACK_SIZE - 0x100);
                runtime
                    .execute_guest_callback(&mut cpu, memory, call.entry, &call.args, call.label)?;
            }
        }
        let mut state = inner.borrow_mut();
        state.purge_deleted_objects();
        state.kmdf.driver_handle = 0;
        let live = state
            .io
            .driver_devices(state.casak_driver)
            .unwrap_or_default();
        let mut deleted_guests = Vec::new();
        for id in live {
            if state.io.delete_device(id).is_ok() {
                deleted_guests.extend(
                    state
                        .device_ids
                        .iter()
                        .filter_map(|(guest, mapped)| (*mapped == id).then_some(*guest)),
                );
            }
        }
        for device in state.devices.iter_mut() {
            if deleted_guests.contains(&device.guest_pointer) {
                device.deleted = true;
            }
        }
        state.device_ids.clear();
        // Symbolic links are island-owned objects: unloading the service
        // tears them down with the devices that exposed them.
        state.symbolic_links.clear();
        if driver_object != 0 {
            let head_offset = match arch {
                GuestArch::X86 => 0x04,
                GuestArch::X64 => 0x08,
            };
            write_guest_pointer(memory, driver_object + head_offset, 0, arch)?;
        }
        state.loaded = false;
        state.unloaded = true;
        Ok(status)
    }

    /// The real `NtLoadDriver` surface: open the service's registry key,
    /// read and expand `ImagePath`, read the image through the runtime file
    /// tables, and load it as a real island (executing `DriverEntry`).
    ///
    /// Statuses follow the kernel contract: a duplicate service is
    /// `STATUS_IMAGE_ALREADY_LOADED`; a missing key/value/image is
    /// `STATUS_OBJECT_NAME_NOT_FOUND`; a malformed or wrong-bitness image is
    /// `STATUS_INVALID_IMAGE_FORMAT`; a bad `UNICODE_STRING` is
    /// `STATUS_INVALID_PARAMETER`.  A failing `DriverEntry` returns its own
    /// NTSTATUS and leaves no registration behind.
    pub(crate) fn nt_load_driver(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        service_path: u64,
    ) -> i32 {
        let raw_path = match read_service_unicode_string(memory, service_path, runtime.guest_arch) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let service_name = match parse_service_name(&raw_path) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let key = loaded_driver_key(runtime, &service_name);
        if lock_registry()
            .services
            .get(&key.0)
            .is_some_and(|services| services.contains_key(&key.1))
        {
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        let Some(registry_key) = resolve_service_key(runtime, &service_name) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        match service_start_type(runtime, &registry_key) {
            Ok(
                Some(SERVICE_BOOT_START)
                | Some(SERVICE_SYSTEM_START)
                | Some(SERVICE_AUTO_START)
                | Some(SERVICE_DEMAND_START)
                | None,
            ) => {}
            Ok(Some(SERVICE_DISABLED)) => return STATUS_OBJECT_NAME_NOT_FOUND,
            Ok(Some(_)) => return STATUS_OBJECT_NAME_NOT_FOUND,
            Err(status) => return status,
        }
        let image_path = match read_service_image_path(runtime, &registry_key) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let bytes = match read_service_image(runtime, &image_path) {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let island =
            match DriverIsland::load_and_start_named(&bytes, &service_name, runtime, memory) {
                Ok(island) => island,
                Err(error) => return nt_load_error_status(&error),
            };
        if island.status() < 0 {
            return island.status();
        }
        lock_registry()
            .services
            .entry(key.0)
            .or_default()
            .insert(key.1, SharedIsland(Box::new(island)));
        record_driver_event(
            runtime,
            "NtLoadDriver",
            &service_name,
            STATUS_SUCCESS,
            Some(&image_path),
        );
        STATUS_SUCCESS
    }

    /// The real `NtUnloadDriver` surface: look up the loaded island by
    /// service name, execute `DriverUnload` (when exported), destroy the
    /// CasaK devices/links, and forget the registration.  An unloaded or
    /// unknown service is `STATUS_OBJECT_NAME_NOT_FOUND`.
    pub(crate) fn nt_unload_driver(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        service_path: u64,
    ) -> i32 {
        let raw_path = match read_service_unicode_string(memory, service_path, runtime.guest_arch) {
            Ok(path) => path,
            Err(status) => return status,
        };
        let service_name = match parse_service_name(&raw_path) {
            Ok(name) => name,
            Err(status) => return status,
        };
        let key = loaded_driver_key(runtime, &service_name);
        let removed = lock_registry()
            .services
            .get_mut(&key.0)
            .and_then(|services| services.remove(&key.1));
        let Some(SharedIsland(boxed)) = removed else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let mut island = *boxed;
        if island.has_open_device_handles(runtime) {
            lock_registry()
                .services
                .entry(key.0)
                .or_default()
                .insert(key.1, SharedIsland(Box::new(island)));
            record_driver_event(
                runtime,
                "NtUnloadDriver",
                &service_name,
                STATUS_DEVICE_BUSY,
                None,
            );
            return STATUS_DEVICE_BUSY;
        }
        match island.unload(runtime, memory) {
            Ok(status) => {
                let status = status.unwrap_or(STATUS_SUCCESS);
                record_driver_event(runtime, "NtUnloadDriver", &service_name, status, None);
                #[cfg(test)]
                LAST_UNLOADED_DRIVER.with(|slot| *slot.borrow_mut() = Some(island));
                #[cfg(not(test))]
                drop(island);
                status
            }
            Err(_) => {
                lock_registry()
                    .services
                    .entry(key.0)
                    .or_default()
                    .insert(key.1, SharedIsland(Box::new(island)));
                record_driver_event(
                    runtime,
                    "NtUnloadDriver",
                    &service_name,
                    STATUS_INVALID_PARAMETER,
                    None,
                );
                STATUS_INVALID_PARAMETER
            }
        }
    }

    /// The driver/service name used for `\Driver\<name>` and the registry
    /// service path.
    pub fn driver_name(&self) -> String {
        self.inner.borrow().driver_name.clone()
    }

    /// The real guest `UNICODE_STRING` path handed to `DriverEntry`.
    pub fn registry_path(&self) -> String {
        self.inner.borrow().registry_path.clone()
    }

    /// The guest base the driver image is mapped at.
    pub fn image_base(&self) -> u64 {
        self.inner.borrow().image_base
    }

    /// `SizeOfImage`.
    pub fn image_size(&self) -> u32 {
        self.inner.borrow().image_size
    }

    /// The guest `PDRIVER_OBJECT` passed to `DriverEntry`.
    pub fn driver_object_pointer(&self) -> u64 {
        self.inner.borrow().driver_object_guest
    }

    /// `AddressOfEntryPoint` of the loaded image.
    pub fn entry_rva(&self) -> u32 {
        self.inner.borrow().entry_rva
    }

    /// The exported `DriverUnload` RVA, when the image exports one.
    pub fn unload_rva(&self) -> Option<u32> {
        self.inner.borrow().unload_rva
    }

    /// The guest `DriverUnload` entry address, when exported.
    pub fn unload_pointer(&self) -> Option<u64> {
        self.inner.borrow().unload_guest
    }

    /// The real `DriverEntry` NTSTATUS.
    pub fn status(&self) -> i32 {
        self.inner.borrow().status
    }

    /// Whether `DriverEntry` returned success and the island is still loaded.
    pub fn is_loaded(&self) -> bool {
        self.inner.borrow().loaded
    }

    /// Whether any guest handle is still open onto this island's device
    /// namespace (an unload is refused while one is).
    pub(crate) fn has_open_device_handles(&self, runtime: &PeHostRuntime) -> bool {
        let state = self.inner.borrow();
        let runtime_id = runtime_identity(runtime);
        let registry = lock_registry();
        registry
            .device_handles
            .get(&runtime_id)
            .into_iter()
            .flat_map(|handles| handles.values())
            .any(|handle| {
                handle.service_name == state.driver_name
                    && state.device_ids.values().any(|id| *id == handle.device_id)
            })
    }

    /// The number of devices currently owned by the CasaK driver object.
    pub fn device_count(&self) -> usize {
        let state = self.inner.borrow();
        state
            .io
            .driver_device_count(state.casak_driver)
            .unwrap_or(0)
    }

    /// The device chain as observed in CasaK (most recently created first).
    pub fn casak_device_names(&self) -> Vec<String> {
        let state = self.inner.borrow();
        state
            .io
            .driver_devices(state.casak_driver)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| {
                state
                    .io
                    .device(id)
                    .ok()
                    .and_then(|device| device.name.clone())
            })
            .collect()
    }

    /// Devices the driver created through `IoCreateDevice`, including deleted
    /// ones.
    pub fn created_devices(&self) -> Vec<IslandDevice> {
        self.inner.borrow().devices.clone()
    }

    /// Every formatted `DbgPrint` message, in call order.
    pub fn dbg_print_log(&self) -> Vec<String> {
        self.inner.borrow().debug_log.clone()
    }

    /// The import resolution report produced while patching the IAT.
    pub fn imports(&self) -> ImportReport {
        self.inner.borrow().imports.clone()
    }

    /// Symbolic links created by the driver (`link -> target`).
    pub fn symbolic_links(&self) -> Vec<(String, String)> {
        self.inner.borrow().symbolic_links.clone()
    }

    /// Live tagged pool bytes currently owned through
    /// `ExAllocatePoolWithTag`.
    pub fn pool_used_bytes(&self) -> usize {
        self.inner.borrow().pool.used_bytes()
    }

    /// Tagged pool allocations performed by the driver.
    pub fn pool_allocation_count(&self) -> usize {
        self.inner.borrow().pool.allocation_count()
    }

    /// Tagged pool frees performed by the driver.
    pub fn pool_free_count(&self) -> usize {
        self.inner.borrow().pool.free_count()
    }

    /// IRPs the driver completed through `IoCompleteRequest`.
    pub fn completed_irp_count(&self) -> u64 {
        self.inner.borrow().io.completed_irp_count()
    }
}

pub(crate) fn build_driver_object(
    state: &IslandState,
    memory: &mut MemoryImage,
    driver_object: u64,
    extension: u64,
    driver_name: u64,
    registry_path: u64,
    default_dispatch: u64,
) -> AppResult<()> {
    let arch = state.arch;
    match arch {
        GuestArch::X64 => {
            memory.write_u16(driver_object, DRIVER_OBJECT_TYPE);
            memory.write_u16(driver_object + 0x02, DRIVER_OBJECT_SIZE as u16);
            memory.write_u64(driver_object + 0x08, 0);
            memory.write_u32(driver_object + 0x10, 0);
            memory.write_u64(driver_object + 0x18, state.image_base);
            memory.write_u32(driver_object + 0x20, state.image_size);
            memory.write_u64(driver_object + 0x28, 0);
            memory.write_u64(driver_object + 0x30, extension);
            copy_unicode_string(memory, driver_name, driver_object + 0x38, arch)?;
            memory.write_u64(driver_object + 0x48, 0);
            memory.write_u64(driver_object + 0x50, 0);
            memory.write_u64(driver_object + 0x58, state.entry_guest);
            memory.write_u64(driver_object + 0x60, 0);
            memory.write_u64(driver_object + 0x68, state.unload_guest.unwrap_or(0));
        }
        GuestArch::X86 => {
            memory.write_u16(driver_object, DRIVER_OBJECT_TYPE);
            memory.write_u16(driver_object + 0x02, DRIVER_OBJECT_SIZE_X86 as u16);
            write_guest_pointer(memory, driver_object + 0x04, 0, arch)?;
            memory.write_u32(driver_object + 0x08, 0);
            memory.write_u32(driver_object + 0x0C, state.image_base as u32);
            memory.write_u32(driver_object + 0x10, state.image_size);
            write_guest_pointer(memory, driver_object + 0x14, 0, arch)?;
            write_guest_pointer(memory, driver_object + 0x18, extension, arch)?;
            copy_unicode_string(memory, driver_name, driver_object + 0x1C, arch)?;
            write_guest_pointer(memory, driver_object + 0x24, 0, arch)?;
            write_guest_pointer(memory, driver_object + 0x28, 0, arch)?;
            write_guest_pointer(memory, driver_object + 0x2C, state.entry_guest, arch)?;
            write_guest_pointer(memory, driver_object + 0x30, 0, arch)?;
            write_guest_pointer(
                memory,
                driver_object + 0x34,
                state.unload_guest.unwrap_or(0),
                arch,
            )?; // coverage: unreachable — write_guest_pointer is infallible for a MemoryImage
        }
    }
    let major_offset = major_function_offset(arch);
    for index in 0..MAJOR_FUNCTION_COUNT {
        write_guest_pointer(
            memory,
            driver_object + major_offset + index as u64 * arch.pointer_bytes() as u64,
            default_dispatch,
            arch,
        )?; // coverage: unreachable — write_guest_pointer is infallible for a MemoryImage
    }

    write_guest_pointer(memory, extension, driver_object, arch)?;
    write_guest_pointer(memory, extension + 0x08, 0, arch)?;
    memory.write_u32(extension + 0x10, 0);
    copy_unicode_string(memory, registry_path, extension + 0x18, arch)?;
    Ok(())
}

pub(crate) fn major_function_offset(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => 0x38,
        GuestArch::X64 => 0x70,
    }
}

pub(crate) fn driver_object_size(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => DRIVER_OBJECT_SIZE_X86,
        GuestArch::X64 => DRIVER_OBJECT_SIZE,
    }
}
