//! PE loading: module list, image mapping, DLL entry points, TLS
//! callbacks, and process-state seeding.
use super::*;

impl PeHostRuntime {
    pub(crate) fn stage_main_module(&mut self, source_program: &Path) -> AppResult<String> {
        let source_program = if source_program.is_absolute() {
            source_program.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    AppError::from_io(
                        ReasonCode::RcIo,
                        format!(
                            "failed to resolve working directory for {}",
                            source_program.display()
                        ),
                        &error,
                    )
                })?
                .join(source_program)
        };
        let normalized_source = runtime_guest_path(self.win32.ge(), &source_program);
        if is_windows_absolute_path(&normalized_source)
            && let Some(drive_prefix) = windows_drive_prefix(&normalized_source)
        {
            let drive = &drive_prefix[..1];
            if self
                .win32
                .ge()
                .active_drive_mappings()
                .iter()
                .any(|mapping| mapping.drive.eq_ignore_ascii_case(drive))
            {
                return Ok(normalized_source);
            }
        }
        let file_name = source_program
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("program.exe");
        let guest_program_path = format!("{}\\{}", self.win32.get_temp_path_w()?, file_name);
        self.win32
            .stage_host_file_w(&source_program, &guest_program_path)?;
        Ok(guest_program_path)
    }

    pub(crate) fn set_main_module(
        &mut self,
        guest_program_path: &str,
        mapped_image_base: u64,
        exports: &[ExportSymbol],
        tls_callbacks_rva: &[u64],
    ) {
        let main_module_name = normalize_module_name(module_file_name(guest_program_path));
        self.main_module_name = main_module_name.clone();
        self.main_module_path = guest_program_path.to_string();
        self.main_module_exports = exports.to_vec();
        if !main_module_name.is_empty() {
            self.module_handles
                .insert(main_module_name.clone(), mapped_image_base);
            self.module_names_by_handle
                .insert(mapped_image_base, main_module_name.clone());
            self.module_paths_by_handle
                .insert(mapped_image_base, guest_program_path.to_string());
            // Register DllInfo for the main module (the .exe).
            self.dll_info_table.insert(
                mapped_image_base,
                DllInfo {
                    handle: mapped_image_base,
                    image_size: self.mapped_image_size,
                    entry_point_rva: 0, // Main module entry point is not a DllMain
                    load_count: 1,
                    module_name: main_module_name,
                    host_path: guest_program_path.to_string(),
                    tls_callbacks: tls_callbacks_rva.to_vec(),
                },
            );
        }
    }

    pub(crate) fn get_or_create_module_handle(&mut self, module_name: &str) -> u64 {
        let normalized = normalize_module_name(module_name);
        if normalized.is_empty() || normalized.ends_with(".exe") {
            return self.mapped_image_base;
        }
        // Already created?  Increment the load count.
        if let Some(&handle) = self.module_handles.get(&normalized) {
            if let Some(info) = self.dll_info_table.get_mut(&handle) {
                info.load_count = info.load_count.saturating_add(1);
            }
            return handle;
        }
        let handle = align_up_u64(self.next_data_address, 0x1000);
        self.next_data_address = handle + 0x1000;
        self.module_names_by_handle
            .insert(handle, normalized.clone());
        self.module_paths_by_handle.insert(
            handle,
            resolve_full_guest_path(&self.current_directory, module_name),
        );
        self.module_handles.insert(normalized.clone(), handle);
        self.synthetic_module_handles.insert(handle);

        // Register DllInfo for this synthetic module.
        self.dll_info_table.insert(
            handle,
            DllInfo {
                handle,
                image_size: 0x1000, // Minimal synthetic image size
                entry_point_rva: 0,
                load_count: 1,
                module_name: normalized.clone(),
                host_path: String::new(),
                tls_callbacks: Vec::new(), // Synthetic modules have no TLS callbacks
            },
        );

        // Fire synthetic DLL init callbacks (DLL_PROCESS_ATTACH).
        for cb in &mut self.synthetic_dll_init_callbacks {
            cb(handle, DLL_PROCESS_ATTACH);
        }

        handle
    }

    pub(crate) fn ensure_synthetic_module_image(
        &mut self,
        memory: &mut MemoryImage,
        module_handle: u64,
    ) {
        if module_handle == 0
            || module_handle == self.mapped_image_base
            || !self.synthetic_module_handles.contains(&module_handle)
            || !self.materialized_synthetic_modules.insert(module_handle)
        {
            return;
        }
        let bytes = minimal_synthetic_module_image(module_handle, self.guest_arch);
        memory.map_bytes(module_handle, &bytes);
        // Canonical VM: synthetic module images are guest-accessible Image
        // regions (nested inside the growing CRT data area).
        self.win32.address_space_mut().register(
            module_handle,
            bytes.len() as u64,
            crate::vm::VmRegionKind::Image,
        );
        self.win32.address_space_mut().commit(
            module_handle,
            bytes.len() as u64,
            crate::vm::VmProtection::READ_WRITE_EXECUTE,
            false,
        );
    }

    pub(crate) fn lookup_module_handle(&self, module_name: &str) -> Option<u64> {
        let normalized = normalize_module_name(module_name);
        if normalized.is_empty() || normalized.ends_with(".exe") {
            return Some(self.mapped_image_base);
        }
        self.module_handles.get(&normalized).copied()
    }

    pub(crate) fn can_synthesize_module(&self, module_name: &str) -> bool {
        let normalized = normalize_module_name(module_name);
        !normalized.is_empty()
            && (normalized.starts_with("api-ms-")
                || normalized.starts_with("ext-ms-")
                || export_tables().contains_key(&normalized))
    }

    pub(crate) fn resolve_load_library_handle(&mut self, module_name: &str) -> (u64, u32) {
        if module_name.trim().is_empty() {
            return (0, 0);
        }
        let normalized = normalize_module_name(module_name);

        // 1. Already loaded as a real DLL?  Increment BOTH refcount tracks
        // (RealDllState::refcount AND DllInfo::load_count) — the Win32
        // FreeLibrary and LdrRemoveRefDll paths decrement both, so repeat
        // loads must have bumped both.
        if let Some(state) = self.loaded_real_dlls.get_mut(&normalized) {
            state.refcount += 1;
            if let Some(info) = self.dll_info_table.get_mut(&state.handle) {
                info.load_count = info.load_count.saturating_add(1);
            }
            let handle = state.handle;
            return (handle, 0);
        }

        // 2. Already loaded as a synthetic module?  Route through
        // get_or_create_module_handle so the load count increments exactly
        // like the first load did (refcount symmetry with the Win32
        // FreeLibrary / LdrRemoveRefDll decrement paths).
        if self.lookup_module_handle(module_name).is_some() {
            return (self.get_or_create_module_handle(module_name), 0);
        }

        // 3. Can synthesize a module from built-in export tables?
        if self.can_synthesize_module(module_name) {
            return (self.get_or_create_module_handle(module_name), 0);
        }

        // 4. Search for the DLL on disk using the standard DLL search order.
        let found_path = self
            .search_dll_paths(module_name)
            .into_iter()
            .find(|p| p.exists());

        if let Some(host_path) = found_path {
            // Try to load it as a real DLL (parse PE, read exports, create thunks)
            return self.load_real_dll(module_name, &host_path);
        }

        // 5. Fallback: try the original guest-to-host path resolution
        let guest_path = resolve_full_guest_path(&self.current_directory, module_name);
        if let Ok(host_path) = self.win32.guest_path_to_host_path(&guest_path)
            && host_path.exists()
        {
            return self.load_real_dll(module_name, &host_path);
        }

        (0, ERROR_MOD_NOT_FOUND)
    }

    pub(crate) fn resolve_main_module_export(&self, symbol: &ImportSymbol) -> u64 {
        let export = match symbol {
            ImportSymbol::ByName { name, .. } => self
                .main_module_exports
                .iter()
                .find(|export| export.name.as_deref() == Some(name.as_str())),
            ImportSymbol::ByOrdinal { ordinal } => self
                .main_module_exports
                .iter()
                .find(|export| export.ordinal == u32::from(*ordinal)),
        };
        match export.map(|export| &export.target) {
            Some(ExportTarget::Rva(rva)) => self.mapped_image_base + u64::from(*rva),
            _ => 0,
        }
    }

    pub(crate) fn resolve_proc_address(&mut self, module_handle: u64, symbol: ImportSymbol) -> u64 {
        if module_handle == self.mapped_image_base {
            return self.resolve_main_module_export(&symbol);
        }
        let Some(module_name) = self.module_names_by_handle.get(&module_handle).cloned() else {
            return 0;
        };
        let normalized = normalize_module_name(&module_name);

        // Check if this is a real (loaded) DLL with registered exports
        if let Some(dll_state) = self.loaded_real_dlls.get(&normalized) {
            let export_addr = match &symbol {
                ImportSymbol::ByName { name, .. } => dll_state.exports.get(name).copied(),
                ImportSymbol::ByOrdinal { .. } => {
                    // Ordinal-only exports aren't indexed by name; skip for now
                    None
                }
            };
            if let Some(addr) = export_addr
                && addr != 0
            {
                return addr;
            }
        }

        // Check if this is a synthetic module with an export table that contains
        // a forwarder.  If so, follow the forwarder chain recursively.
        if let Some(export_table) = export_tables().get(&normalized) {
            let export = match &symbol {
                ImportSymbol::ByName { name, .. } => export_table
                    .iter()
                    .find(|exp| exp.name.as_deref() == Some(name.as_str())),
                ImportSymbol::ByOrdinal { ordinal } => export_table
                    .iter()
                    .find(|exp| exp.ordinal == u32::from(*ordinal)),
            };
            if let Some(ExportTarget::Forwarder(fwd_str)) = export.map(|exp| &exp.target) {
                let mut visited = std::collections::HashSet::new();
                if let Some(addr) = self.resolve_forwarder_export(fwd_str, &mut visited) {
                    return addr;
                }
                // Forwarder unresolvable — return 0 (caller sets ERROR_PROC_NOT_FOUND).
                return 0;
            }
            // RVA export found — nothing special to do; fall through to HostThunk
            // creation below.  (Synthetic module RVA exports are handled by the
            // HostThunk dispatch mechanism.)
        }

        let thunk = HostThunk::from_import(&ResolvedImport {
            requested_module: module_name.clone(),
            resolved_module: module_name,
            symbol: symbol.clone(),
            iat_rva: 0,
            export: synthetic_export_symbol(&symbol),
        });
        if matches!(thunk, HostThunk::Unsupported { .. }) {
            return 0;
        }
        let thunk_address = self.next_thunk_address;
        self.next_thunk_address += 0x10;
        self.host_thunks.insert(thunk_address, thunk);
        thunk_address
    }

    /// Maximum forwarder chain depth to prevent stack overflow on deeply
    /// nested or malicious forwarder chains.
    const MAX_FORWARDER_DEPTH: usize = 8;

    /// Resolve a forwarder export string like `"kernel32.LocalAlloc"` by
    /// chaining to the target module's export table.
    ///
    /// Results are cached in `forwarder_export_cache` to avoid re-resolving
    /// the same forwarder on subsequent lookups.  Unresolvable forwarders
    /// are cached as `None` to avoid re-attempting.
    pub(crate) fn resolve_forwarder_export(
        &mut self,
        forwarder: &str,
        visited: &mut std::collections::HashSet<String>,
    ) -> Option<u64> {
        // Check cache first.
        if let Some(cached) = self.forwarder_export_cache.get(forwarder) {
            return *cached;
        }

        // Guard against circular forwarding.
        if !visited.insert(forwarder.to_string()) {
            eprintln!("[pe_runtime] circular forwarder detected: {forwarder}");
            self.forwarder_export_cache
                .insert(forwarder.to_string(), None);
            return None;
        }

        // Guard against excessive forwarder depth.
        if visited.len() > Self::MAX_FORWARDER_DEPTH {
            eprintln!(
                "[pe_runtime] forwarder chain too deep (>{}) at: {forwarder}",
                Self::MAX_FORWARDER_DEPTH,
            );
            self.forwarder_export_cache
                .insert(forwarder.to_string(), None);
            return None;
        }

        // Forwarder format: "DLL_NAME.SymbolName" or "DLL_NAME.#ORDINAL"
        let (dll_part, symbol_part) = forwarder.split_once('.')?;
        let dll_name = normalize_module_name(dll_part);
        // normalize_module_name() always appends .dll if no extension is present,
        // so dll_name is guaranteed to end with ".dll" here.

        let (target_handle, _) = self.resolve_load_library_handle(&dll_name);
        if target_handle == 0 {
            self.forwarder_export_cache
                .insert(forwarder.to_string(), None);
            return None;
        }

        let import_sym = if let Some(ord_str) = symbol_part.strip_prefix('#') {
            let ord = ord_str.parse::<u16>().ok()?;
            ImportSymbol::ByOrdinal { ordinal: ord }
        } else {
            ImportSymbol::ByName {
                hint: 0,
                name: symbol_part.to_string(),
            }
        };

        // Dynamic-import instrumentation: following a forwarded export is a
        // runtime resolution into the forwarding target module — record the
        // (DLL, name) pair so import coverage sees the resolution.
        record_dynamic_import(&dll_name, symbol_part);

        let result = Some(self.resolve_proc_address(target_handle, import_sym));

        // Cache the result (address or None if address is 0).
        if let Some(addr) = result
            && addr != 0
        {
            self.forwarder_export_cache
                .insert(forwarder.to_string(), Some(addr));
            return Some(addr);
        }
        self.forwarder_export_cache
            .insert(forwarder.to_string(), None);
        None
    }

    /// DLL search order: app directory → C:\Windows\System32 → C:\Windows → PATH
    ///
    /// Returns the list of candidate host paths for the given module name.
    pub(crate) fn search_dll_paths(&self, module_name: &str) -> Vec<PathBuf> {
        let mut candidates: Vec<PathBuf> = Vec::new();

        // 1. App (current) directory — use the guest current directory mapped to host
        let app_guest_dir = &self.current_directory;
        let app_path = resolve_full_guest_path(app_guest_dir, module_name);
        if let Ok(host_path) = self.win32.guest_path_to_host_path(&app_path) {
            candidates.push(host_path);
        }

        // 2. C:\Windows\System32 → mapped to ges/.../drive_c/windows/system32
        let sys32_guest = format!(r"C:\Windows\System32\{}", module_name);
        if let Ok(host_path) = self.win32.guest_path_to_host_path(&sys32_guest) {
            candidates.push(host_path);
        }

        // 3. C:\Windows
        let win_guest = format!(r"C:\Windows\{}", module_name);
        if let Ok(host_path) = self.win32.guest_path_to_host_path(&win_guest) {
            candidates.push(host_path);
        }

        // 4. PATH environment variable entries (as guest paths, then mapped)
        if let Some(path_val) = self.process_environment.get("PATH") {
            for dir in path_val.split(';') {
                let candidate = format!(r"{}\{}", dir.trim_end_matches('\\'), module_name);
                if let Ok(host_path) = self.win32.guest_path_to_host_path(&candidate) {
                    candidates.push(host_path);
                }
            }
        }

        // Deduplicate while preserving order
        let mut seen = std::collections::HashSet::new();
        candidates.retain(|p| seen.insert(p.clone()));

        candidates
    }

    /// Returns whether a comctl32 version 6 (Common Controls v6) activation
    /// context is active. When true, the guest expects modern common control
    /// styles and visual themes.
    #[allow(dead_code)] // comctl32 v6 state query; flagged for the API database
    pub fn is_comctl32_v6_active(&self) -> bool {
        self.comctl32_v6_active
    }

    /// Check whether a `.local` file exists next to the given executable path.
    /// If present, Windows redirects all DLL loads to search the application
    /// directory first (activation context isolation via ".local" file).
    pub fn check_local_redirection(&mut self, program_path: &Path) -> bool {
        // .local file path: <program_exe>.local
        let mut local_path = program_path.to_path_buf();
        let mut exe_name = program_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        exe_name.push_str(".local");
        local_path.set_file_name(&exe_name);

        let exists = local_path.exists();
        self.local_redirect_active = exists;
        if exists {
            eprintln!(
                "[pe_runtime] .local redirection active: {}",
                local_path.display()
            );
        }
        exists
    }

    /// Try to load a native macOS dylib shim for a known Windows DLL.
    ///
    /// Returns `Some(library)` if a native .dylib equivalent was found and loaded,
    /// or `None` if no shim exists (the DLL is handled entirely by built-in thunks).
    pub(crate) fn load_native_shim(dll_name: &str) -> Option<libloading::Library> {
        let normalized = normalize_module_name(dll_name);
        // Map of known Windows DLLs to macOS dylib paths
        let shim_paths: &[(&str, &[&str])] = &[
            // Core system libraries — use the built-in HostThunk dispatch instead
            ("kernel32.dll", &[]),
            ("kernelbase.dll", &[]),
            ("user32.dll", &[]),
            ("gdi32.dll", &[]),
            ("advapi32.dll", &[]),
            ("ole32.dll", &[]),
            ("oleaut32.dll", &[]),
            ("ws2_32.dll", &[]),
            ("winmm.dll", &[]),
            ("comctl32.dll", &[]),
            ("comdlg32.dll", &[]),
            ("shell32.dll", &[]),
            ("shlwapi.dll", &[]),
            ("shcore.dll", &[]),
            ("crypt32.dll", &[]),
            ("bcrypt.dll", &[]),
            ("ncrypt.dll", &[]),
            ("winhttp.dll", &[]),
            ("wininet.dll", &[]),
            ("psapi.dll", &[]),
            ("d3d11.dll", &[]),
            ("d3d12.dll", &[]),
            ("dxgi.dll", &[]),
            ("xaudio2_9.dll", &[]),
            ("xinput1_3.dll", &[]),
            ("xinput1_4.dll", &[]),
            ("ucrtbase.dll", &[]),
            ("vcruntime140.dll", &[]),
            ("msvcp140.dll", &[]),
            ("ntdll.dll", &[]),
            ("userenv.dll", &[]),
            ("version.dll", &[]),
            ("iphlpapi.dll", &[]),
            ("dnsapi.dll", &[]),
            ("secur32.dll", &[]),
            ("sspicli.dll", &[]),
            ("wtsapi32.dll", &[]),
            // Crypto library — may have a native equivalent
            (
                "libcrypto.dll",
                &[
                    "/usr/lib/libcrypto.dylib",
                    "/opt/homebrew/lib/libcrypto.dylib",
                ],
            ),
            (
                "libssl.dll",
                &["/usr/lib/libssl.dylib", "/opt/homebrew/lib/libssl.dylib"],
            ),
        ];

        for (name, paths) in shim_paths {
            if normalize_module_name(name) == normalized {
                if paths.is_empty() {
                    // Built-in — no native shim needed, signal as None (caller will use synthetic thunks)
                    return None;
                }
                // Try each candidate path
                for candidate in *paths {
                    let p = Path::new(candidate);
                    if p.exists() {
                        // Safety: libloading::Library::new is unsafe because loading a library
                        // with unknown constructors could be dangerous. We accept this risk
                        // for known system libraries.
                        match unsafe { libloading::Library::new(candidate) } {
                            Ok(lib) => return Some(lib),
                            Err(e) => {
                                eprintln!(
                                    "[pe_runtime] failed to load native shim {candidate}: {e:?}"
                                );
                            }
                        }
                    }
                }
                return None;
            }
        }
        None
    }

    /// Load a real on-disk DLL: parse its PE header, read exports, and register
    /// synthetic HostThunks for each exported function.
    ///
    /// Returns the guest module handle and a status code (0 = success).
    pub(crate) fn load_real_dll(&mut self, module_name: &str, host_path: &Path) -> (u64, u32) {
        let normalized = normalize_module_name(module_name);

        // Invalidate forwarder export cache entries that reference this DLL,
        // since loading a new version may change its exports.
        let dll_prefix = normalized.trim_end_matches(".dll").to_uppercase();
        self.forwarder_export_cache.retain(|key, _| {
            // Keep entries whose key does not start with "<DLL_NAME>."
            !key.starts_with(&format!("{dll_prefix}."))
        });

        // Already loaded?
        if let Some(state) = self.loaded_real_dlls.get_mut(&normalized) {
            state.refcount += 1;
            // Keep the DllInfo load-count track in step with the
            // RealDllState refcount track (FreeLibrary / LdrRemoveRefDll
            // decrement BOTH; a second LoadLibrary must have bumped both).
            if let Some(info) = self.dll_info_table.get_mut(&state.handle) {
                info.load_count = info.load_count.saturating_add(1);
            }
            return (state.handle, 0);
        }

        // Read the PE file bytes (needed for both parsing and Authenticode verification)
        let pe_bytes = match std::fs::read(host_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[pe_runtime] failed to read PE for {normalized}: {e:?}");
                return (0, ERROR_MOD_NOT_FOUND);
            }
        };

        // Parse the PE file
        let parsed = match crate::pe::parse(&pe_bytes) {
            Ok(mut pe) => {
                pe.external_manifest = match crate::pe::parse_external_manifest(host_path) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!(
                            "[pe_runtime] failed to read external manifest for {normalized}: {e:?}"
                        );
                        None
                    }
                };
                pe
            }
            Err(e) => {
                eprintln!("[pe_runtime] failed to parse PE for {normalized}: {e:?}");
                return (0, ERROR_MOD_NOT_FOUND);
            }
        };

        // -- Phase M7: .NET assembly detection ------------------------------------------------
        if parsed.is_dotnet {
            eprintln!(
                "[pe_runtime] warning: {normalized} is a .NET assembly — CLR is not available, native parts will load"
            );
        }

        // -- Phase O3: Code integrity enforcement -------------------------------------------
        // Verify the embedded Authenticode signature before allowing the DLL to load.
        // Drivers (IMAGE_SUBSYSTEM_NATIVE) require a valid signature; other DLLs may load
        // without one but a warning is emitted. Tampered or corrupted signatures are rejected.
        const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
        match crate::security::verify_pe_authenticode(&pe_bytes) {
            crate::security::AuthenticodeVerdict::Valid => {
                // Signature verified successfully.
            }
            crate::security::AuthenticodeVerdict::NoSignature => {
                if parsed.subsystem == IMAGE_SUBSYSTEM_NATIVE {
                    eprintln!("[pe_runtime] rejecting unsigned native (driver) image {normalized}");
                    return (0, ERROR_MOD_NOT_FOUND);
                }
                // Non-driver DLL without a signature: log a warning but allow loading.
                eprintln!("[pe_runtime] warning: loading unsigned DLL {normalized}");
            }
            crate::security::AuthenticodeVerdict::Invalid(ref reason) => {
                eprintln!(
                    "[pe_runtime] rejecting PE {normalized} with invalid Authenticode signature: {reason}"
                );
                return (0, ERROR_MOD_NOT_FOUND);
            }
        }

        // Allocate a module handle in guest space
        let handle = align_up_u64(self.next_data_address, 0x1000);
        self.next_data_address = handle + 0x1000;

        // Try to load a native shim (macOS dylib equivalent)
        let native_library = Self::load_native_shim(&normalized);

        // Map export names → thunk addresses
        let mut export_thunks: HashMap<String, u64> = HashMap::new();

        for export in &parsed.exports {
            let export_name = match &export.name {
                Some(n) => n.clone(),
                None => continue, // Skip ordinal-only exports for now
            };

            let thunk_addr = match &export.target {
                ExportTarget::Rva(_rva) => {
                    if let Some(ref lib) = native_library {
                        // Try to look up the symbol in the native dylib
                        let symbol_name = export_name.as_bytes();
                        // libloading::Library::get returns a Symbol, which we can
                        // use to get a function pointer.
                        // SAFETY: lib is a valid Library handle; symbol_name is a valid
                        // null-terminated byte string for the lookup.
                        let func_ptr: Option<*mut std::ffi::c_void> = unsafe {
                            lib.get::<*mut std::ffi::c_void>(symbol_name)
                                .ok()
                                .map(|s| s.into_raw().into_raw())
                        };

                        if func_ptr.is_some() {
                            // Create a RealDllExport thunk that will dispatch to native code
                            let thunk = HostThunk::RealDllExport {
                                dll_name: normalized.clone(),
                                export_name: export_name.clone(),
                            };
                            let addr = self.next_thunk_address;
                            self.next_thunk_address += 0x10;
                            self.host_thunks.insert(addr, thunk);
                            addr
                        } else {
                            // Native symbol not found; create unsupported thunk
                            let thunk = HostThunk::Unsupported {
                                dll: normalized.clone(),
                                symbol: export_name.clone(),
                            };
                            let addr = self.next_thunk_address;
                            self.next_thunk_address += 0x10;
                            self.host_thunks.insert(addr, thunk);
                            addr
                        }
                    } else {
                        // No native dylib — create a synthetic export thunk via
                        // the standard resolve_proc_address mechanism.
                        // We create a host thunk that will be dispatched.
                        let thunk = HostThunk::Unsupported {
                            dll: normalized.clone(),
                            symbol: export_name.clone(),
                        };
                        let addr = self.next_thunk_address;
                        self.next_thunk_address += 0x10;
                        self.host_thunks.insert(addr, thunk);
                        addr
                    }
                }
                ExportTarget::Forwarder(fwd_str) => {
                    // Forwarder export: resolve through the chain.
                    // Use a fresh visited set per DLL; cross-DLL circular chains
                    // are handled by the already-loaded guard at the top of this
                    // function and by the insert check in resolve_forwarder_export.
                    let mut visited = HashSet::new();
                    match self.resolve_forwarder_export(fwd_str, &mut visited) {
                        Some(addr) => addr,
                        None => {
                            let thunk = HostThunk::Unsupported {
                                dll: normalized.clone(),
                                symbol: export_name.clone(),
                            };
                            let addr = self.next_thunk_address;
                            self.next_thunk_address += 0x10;
                            self.host_thunks.insert(addr, thunk);
                            addr
                        }
                    }
                }
            };
            export_thunks.insert(export_name.clone(), thunk_addr);
        }

        let entry_point = if parsed.address_of_entry_point != 0 {
            Some(parsed.address_of_entry_point)
        } else {
            None
        };

        let state = RealDllState {
            path: host_path.to_path_buf(),
            dll_name: normalized.clone(),
            exports: export_thunks,
            entry_point,
            image_base: parsed.image_base,
            refcount: 1,
            handle,
            native_library,
        };

        // Queue DllMain(DLL_PROCESS_ATTACH) for execution after the host thunk
        // returns to the main execution loop.  We cannot run guest code from
        // within a host thunk, so we defer the call.
        if let Some(ep_rva) = entry_point {
            self.pending_dll_main_calls
                .push_back((handle, ep_rva, DLL_PROCESS_ATTACH));
        }

        self.loaded_real_dlls.insert(normalized.clone(), state);

        // Register the module handle
        self.module_names_by_handle
            .insert(handle, normalized.clone());
        self.module_paths_by_handle.insert(
            handle,
            resolve_full_guest_path(&self.current_directory, module_name),
        );
        self.module_handles.insert(normalized.clone(), handle);

        // Extract TLS callback RVAs (relative to original image base) for this DLL.
        let tls_callbacks_rva: Vec<u64> = parsed
            .tls_directory
            .as_ref()
            .map(|tls| {
                tls.callbacks
                    .iter()
                    .map(|&va| va.wrapping_sub(parsed.image_base))
                    .collect()
            })
            .unwrap_or_default();

        // Register DllInfo for this real PE DLL.
        self.dll_info_table.insert(
            handle,
            DllInfo {
                handle,
                image_size: parsed.size_of_image as u64,
                entry_point_rva: parsed.address_of_entry_point,
                load_count: 1,
                module_name: normalized.clone(),
                host_path: host_path.to_string_lossy().to_string(),
                tls_callbacks: tls_callbacks_rva,
            },
        );

        // Live session trace for important DLL loads
        if self.live_session.is_some() {
            let lower = normalized.to_ascii_lowercase();
            if lower.contains("d3d11")
                || lower.contains("d3d12")
                || lower.contains("dxgi")
                || lower.contains("cef")
                || lower.contains("chrome_elf")
                || lower.contains("libcef")
                || lower.contains("user32")
                || lower.contains("gdi32")
                || lower.contains("opengl32")
            {
                crate::live::live_trace(&format!(
                    "[pe] dll_loaded {} handle={:#x}",
                    normalized, handle
                ));
            }
        }

        (handle, 0)
    }

    /// Call a loaded DLL's entry point (DllMain) with the given reason code.
    ///
    /// `entry_point_rva` is the RVA from the PE header.
    /// `reason` is one of `DLL_PROCESS_ATTACH`, `DLL_THREAD_ATTACH`,
    /// `DLL_THREAD_DETACH`, or `DLL_PROCESS_DETACH`.
    /// Execute all queued DllMain calls after the current host thunk returns.
    ///
    /// DllMain calls are queued by [`load_real_dll`] when a real PE DLL with a
    /// non-zero entry point is loaded.  We drain the queue here, executing each
    /// entry point as a guest callback with the standard DllMain arguments:
    ///
    ///   BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    ///
    /// TLS callbacks are fired BEFORE DllMain for process-attach and thread-attach,
    /// and AFTER DllMain for process-detach and thread-detach, matching Windows
    /// behavior.
    ///
    /// This MUST be called from the main execution loop (or from a context where
    /// guest code can be safely executed), NOT from within a host thunk dispatch.
    pub(crate) fn drain_pending_dll_main_calls(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        while let Some((image_base, entry_point_rva, reason)) =
            self.pending_dll_main_calls.pop_front()
        {
            // Fire TLS callbacks BEFORE DllMain for attach reasons.
            if reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH {
                self.execute_tls_callbacks_for_module(state, memory, image_base, reason)?;
            }

            let entry_point = image_base + entry_point_rva as u64;
            eprintln!(
                "[pe_runtime] DllMain({:#x}, {}, NULL) at {:#x}",
                image_base, reason, entry_point
            );
            self.execute_guest_callback(
                state,
                memory,
                entry_point,
                &[image_base, reason as u64, 0],
                &format!("DllMain({:#x}, reason={})", image_base, reason),
            )?;

            // Fire TLS callbacks AFTER DllMain for detach reasons.
            if reason == DLL_PROCESS_DETACH || reason == DLL_THREAD_DETACH {
                self.execute_tls_callbacks_for_module(state, memory, image_base, reason)?;
            }
        }
        Ok(())
    }

    /// Legacy stub — kept for any leftover callers.  Delegates to the queue-based
    /// mechanism via [`drain_pending_dll_main_calls`] (which is a no-op when the
    /// queue is empty).
    #[allow(dead_code)] // legacy DllMain stub kept for leftover callers; flagged for the API database
    pub(crate) fn call_dll_entry_point(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        entry_point_rva: u32,
        image_base: u64,
        reason: u32,
    ) -> AppResult<()> {
        // Queue a pending DllMain call so it is executed after the current host
        // thunk returns to the main execution loop.
        self.pending_dll_main_calls
            .push_back((image_base, entry_point_rva, reason));
        // Immediately drain in case the caller expects synchronous execution
        // from a context where guest code can be safely run.
        self.drain_pending_dll_main_calls(state, memory)
    }

    /// Iterate all loaded DLLs from the `dll_info_table` and queue their entry
    /// points to be called with the given `reason`.
    ///
    /// Only DLLs with a non-zero `entry_point_rva` (i.e. those that actually
    /// export a DllMain) are notified.  Synthetic/managed modules that have no
    /// PE entry point are skipped.
    ///
    /// The calls are deferred via [`pending_dll_main_calls`] and must be drained
    /// later (e.g. via [`drain_pending_dll_main_calls`]) from a context where
    /// guest code can safely execute.
    #[allow(dead_code)] // DllMain notification API; used by tests
    pub fn call_dll_entry_points(&mut self, dll_handles: &[u64], reason: DllReason) {
        let raw_reason = reason.to_raw();
        for &handle in dll_handles {
            if let Some(info) = self.dll_info_table.get(&handle)
                && info.entry_point_rva != 0
            {
                self.pending_dll_main_calls
                    .push_back((handle, info.entry_point_rva, raw_reason));
            }
        }
    }

    /// Dispatch a RealDllExport thunk by looking up the native function pointer
    /// from the loaded library and calling it with the guest's register state.
    pub(crate) fn dispatch_real_dll_export(
        &self,
        _state: &mut CpuState,
        _memory: &MemoryImage,
        dll_name: &str,
        export_name: &str,
    ) {
        // Find the loaded DLL state
        let Some(dll_state) = self.loaded_real_dlls.get(dll_name) else {
            eprintln!("[pe_runtime] RealDllExport: DLL {dll_name} not loaded");
            return;
        };
        let Some(ref lib) = dll_state.native_library else {
            eprintln!("[pe_runtime] RealDllExport: DLL {dll_name} has no native library");
            return;
        };

        // Look up the symbol in the native library
        // SAFETY: lib is a valid Library handle; export_name is a valid byte string.
        let func: libloading::Symbol<unsafe extern "C" fn()> = unsafe {
            match lib.get(export_name.as_bytes()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[pe_runtime] RealDllExport: symbol {export_name} not found in {dll_name}: {e}"
                    );
                    return;
                }
            }
        };

        // Call the native function.
        // NOTE: This is inherently unsafe and the function signature is unknown.
        // We assume a __cdecl or stdcall function with no arguments for the
        // call itself — the actual arguments were set up in guest registers
        // by the caller. This is a best-effort native dispatch.
        //
        // Real-world emulators handle this with dynamic code generation or
        // per-function thunk tables. For now, we call the native function and
        // let the guest registers pass through.
        // SAFETY: guest memory access and FFI for PE runtime emulation
        unsafe {
            func();
        }

        eprintln!("[pe_runtime] RealDllExport: called native {export_name} from {dll_name}");
    }

    pub(crate) fn current_process_module_handles(&self) -> Vec<u64> {
        let mut handles = self.module_handles.values().copied().collect::<Vec<_>>();
        handles.sort_unstable();
        handles.dedup();
        handles.retain(|handle| *handle != 0 && *handle != self.mapped_image_base);
        handles.insert(0, self.mapped_image_base);
        handles
    }

    pub(crate) fn module_handle_from_address(&self, address: u64) -> Option<u64> {
        if address >= self.mapped_image_base
            && address < self.mapped_image_base + self.mapped_image_size
        {
            return Some(self.mapped_image_base);
        }
        self.current_process_module_handles()
            .into_iter()
            .find(|handle| {
                *handle != self.mapped_image_base
                    && address >= *handle
                    && address < *handle + 0x1000
            })
    }

    pub(crate) fn winsock_extension_function(&mut self, guid: &str) -> Option<u64> {
        match guid.to_ascii_uppercase().as_str() {
            "{25A207B9-DDF3-4660-8EE9-76E58C74063E}" => {
                Some(self.alloc_host_thunk(HostThunk::ConnectEx))
            }
            "{7FDA2E11-8630-436F-A031-F536A6EEC157}" => {
                Some(self.alloc_host_thunk(HostThunk::DisconnectEx))
            }
            _ => None,
        }
    }

    pub(crate) fn current_instruction_budget(&self) -> AppResult<u64> {
        pe_runtime_instruction_budget(&self.process_environment, self.live_session.is_some())
    }

    pub(crate) fn module_base_name(&self, module_handle: u64) -> String {
        if module_handle == 0 || module_handle == self.mapped_image_base {
            return module_file_name(&self.main_module_path).to_string();
        }
        self.module_paths_by_handle
            .get(&module_handle)
            .map(|path| module_file_name(path).to_string())
            .or_else(|| self.module_names_by_handle.get(&module_handle).cloned())
            .unwrap_or_default()
    }

    /// Registers a callback that will be invoked when a synthetic/managed DLL receives
    /// a DllMain notification (e.g. `DLL_PROCESS_ATTACH`).
    ///
    /// The callback receives the module handle (HMODULE) and the notification reason
    /// (e.g. `DLL_PROCESS_ATTACH = 1`). Callbacks fire from
    /// [`get_or_create_module_handle`] when a synthetic module is first created.
    #[allow(dead_code)] // synthetic-DLL init callback registration; used by tests
    pub fn register_synthetic_dll_init_callback(&mut self, cb: Box<dyn FnMut(u64, u32)>) {
        self.synthetic_dll_init_callbacks.push(cb);
    }
}

impl PeHostRuntime {
    pub(crate) fn seed_process_state(
        &mut self,
        memory: &mut MemoryImage,
        guest_program_path: &str,
        args: &[String],
        mapped_image_base: u64,
        mapped_image_size: u64,
    ) -> AppResult<()> {
        self.mapped_image_base = mapped_image_base;
        self.mapped_image_size = mapped_image_size;
        self.win32.ensure_default_locale_registry()?;
        self.command_line = build_windows_command_line(guest_program_path, args);
        self.command_line_ansi_ptr = 0;
        self.command_line_wide_ptr = 0;
        self.process_parameters_ptr = 0;

        let mut argv_values = Vec::with_capacity(args.len() + 2);
        argv_values.push(self.alloc_c_string(memory, guest_program_path)?);
        for arg in args {
            argv_values.push(self.alloc_c_string(memory, arg)?);
        }
        argv_values.push(0);
        let argv_array = self.alloc_pointer_array(memory, &argv_values)?;
        let argv_ptr_ptr = self.alloc_pointer(memory, argv_array)?;
        let argc_ptr = self.alloc_u32(memory, (args.len() + 1) as u32)?;
        let environ_array = self.alloc_pointer_array(memory, &[0])?;
        let environ_ptr_ptr = self.alloc_pointer(memory, environ_array)?;
        let commode_ptr = self.alloc_u32(memory, 0)?;
        let fmode_ptr = self.alloc_u32(memory, 0)?;
        let peb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        let teb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        // Main-thread stack bounds — same region the loader maps for the main
        // thread (see the main-run path: stack_base_for_arch + STACK_SIZE).
        let stack_bottom = stack_base_for_arch(self.guest_arch);
        let stack_top = stack_bottom + STACK_SIZE as u64;
        if self.guest_arch == GuestArch::X86 {
            write_u32(memory, teb_base, X86_EXCEPTION_CHAIN_END as u32);
            write_u32(memory, teb_base + 0x04, stack_top as u32);
            write_u32(memory, teb_base + 0x08, stack_bottom as u32);
            write_guest_pointer(memory, teb_base + 0x30, peb_base, self.guest_arch)?;
            write_guest_pointer(memory, teb_base + 0x18, teb_base, self.guest_arch)?;
            write_guest_pointer(memory, peb_base + 0x08, mapped_image_base, self.guest_arch)?;
            // Minimal PEB_LDR_DATA (x86 layout): Length@0, Initialized@4,
            // SsHandle@8, InLoadOrderModuleList@0x0c, InMemoryOrderModuleList@0x14,
            // InInitializationOrderModuleList@0x1c.  Each list head is
            // self-referential so Ldr walks terminate on empty-but-valid lists
            // instead of a NULL pointer.
            let peb_ldr_base = self.alloc_zeroed(memory, 0x40, 16)?;
            write_u32(memory, peb_ldr_base, 0x24);
            memory.write_u8(peb_ldr_base + 0x04, 1);
            write_u32(memory, peb_ldr_base + 0x08, 0);
            for list_offset in [0x0c_u64, 0x14, 0x1c] {
                let list_head = peb_ldr_base + list_offset;
                write_guest_pointer(memory, list_head, list_head, self.guest_arch)?;
                write_guest_pointer(memory, list_head + 4, list_head, self.guest_arch)?;
            }
            write_guest_pointer(memory, peb_base + 0x0c, peb_ldr_base, self.guest_arch)?;
            write_guest_pointer(
                memory,
                peb_base + 0x18,
                PROCESS_HEAP_HANDLE,
                self.guest_arch,
            )?;
            let tls_vector_ptr =
                self.alloc_zeroed(memory, 4096 * self.guest_arch.pointer_bytes(), 16)?;
            let static_tls_block = self.alloc_zeroed(memory, 0x2000, 16)?;
            write_guest_pointer(memory, teb_base + 0x2c, tls_vector_ptr, self.guest_arch)?;
            write_guest_pointer(memory, tls_vector_ptr, static_tls_block, self.guest_arch)?;
            self.tls_slots.insert(0, static_tls_block);
            self.tls_vector_ptr = tls_vector_ptr;
        } else {
            write_guest_pointer(memory, teb_base + 0x30, teb_base, self.guest_arch)?;
            write_guest_pointer(memory, teb_base + 0x60, peb_base, self.guest_arch)?;
            // x64 TEB: StackBase at +0x08, StackLimit at +0x10.
            write_guest_pointer(memory, teb_base + 0x08, stack_top, self.guest_arch)?;
            write_guest_pointer(memory, teb_base + 0x10, stack_bottom, self.guest_arch)?;
            write_guest_pointer(memory, peb_base + 0x10, mapped_image_base, self.guest_arch)?;
            write_guest_pointer(
                memory,
                peb_base + 0x30,
                PROCESS_HEAP_HANDLE,
                self.guest_arch,
            )?;
            self.tls_vector_ptr = 0;
        }

        let mut iob_streams = [0_u64; 3];
        for stream in &mut iob_streams {
            *stream = self.alloc_zeroed(memory, 0x80, 16)?;
        }

        self.teb_base = teb_base;
        self.peb_base = peb_base;
        self.sync_process_parameters(memory, guest_program_path)?;

        self.globals = CrtGlobals {
            argc_ptr,
            argv_ptr_ptr,
            environ_ptr_ptr,
            commode_ptr,
            fmode_ptr,
            iob_streams,
        };
        Ok(())
    }

    /// Execute TLS callbacks for a specific module with the given reason code.
    ///
    /// `handle` is the mapped image base (HMODULE) for the module.
    /// `reason` is one of `DLL_PROCESS_ATTACH`, `DLL_PROCESS_DETACH`,
    /// `DLL_THREAD_ATTACH`, or `DLL_THREAD_DETACH`.
    ///
    /// Callback addresses are stored as RVAs in DllInfo and are converted to
    /// runtime addresses by adding `handle`.
    pub(crate) fn execute_tls_callbacks_for_module(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        handle: u64,
        reason: u32,
    ) -> AppResult<()> {
        let callbacks = self
            .dll_info_table
            .get(&handle)
            .map(|info| info.tls_callbacks.clone())
            .unwrap_or_default();
        for (index, &callback_rva) in callbacks.iter().enumerate() {
            if callback_rva == 0 {
                continue;
            }
            let callback_address = handle.wrapping_add(callback_rva);
            let _result = self.execute_guest_callback(
                state,
                memory,
                callback_address,
                &[callback_address, reason as u64, 0, 0],
                &format!("TLS callback {} for module {:#x}", index, handle),
            )?;
        }
        Ok(())
    }

    /// Fire TLS callbacks with the given reason for all registered modules.
    pub(crate) fn fire_tls_callbacks_for_all_modules(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        reason: u32,
    ) -> AppResult<()> {
        let handles: Vec<u64> = self.dll_info_table.keys().copied().collect();
        for handle in handles {
            self.execute_tls_callbacks_for_module(state, memory, handle, reason)?;
        }
        Ok(())
    }

    /// Register `.pdata` exception tables for a loaded image with the SEH subsystem.
    pub fn register_seh_exception_data(
        &mut self,
        image_base: u64,
        pdata_bytes: &[u8],
        unwind_bytes: &[u8],
    ) {
        self.seh.register_pdata(image_base, pdata_bytes);
        self.seh
            .register_unwind_data(image_base, unwind_bytes.to_vec());
    }

    pub(crate) fn initialize_main_thread_tls(
        &mut self,
        memory: &mut MemoryImage,
        image: &pe::ParsedPe,
        mapped_image_base: u64,
    ) -> AppResult<()> {
        if self.guest_arch != GuestArch::X86 || self.tls_vector_ptr == 0 {
            return Ok(());
        }
        let Some(tls_directory) = image.tls_directory.as_ref() else {
            return Ok(());
        };

        let raw_data_size = tls_directory
            .raw_data_end
            .saturating_sub(tls_directory.raw_data_start) as usize;
        let raw_data = if raw_data_size == 0 {
            Vec::new()
        } else {
            let raw_data_base = mapped_image_base.wrapping_add(
                tls_directory
                    .raw_data_start
                    .saturating_sub(image.image_base),
            );
            read_window(memory, raw_data_base, raw_data_size)?
        };

        let slot_zero_block = self.alloc_zeroed(memory, raw_data.len().max(0x2000), 16)?;
        if !raw_data.is_empty() {
            memory.map_bytes(slot_zero_block, &raw_data);
        }
        self.tls_slots.insert(0, slot_zero_block);
        self.sync_guest_tls_slot(memory, 0, slot_zero_block)?;

        let index_address = mapped_image_base.wrapping_add(
            tls_directory
                .address_of_index
                .saturating_sub(image.image_base),
        );
        write_u32(memory, index_address, 0);
        Ok(())
    }

    pub(crate) fn execute_main_image_tls_process_attach_callbacks(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        image: &pe::ParsedPe,
        mapped_image_base: u64,
    ) -> AppResult<()> {
        let Some(tls_directory) = image.tls_directory.as_ref() else {
            return Ok(());
        };
        if tls_directory.callbacks.is_empty() {
            return Ok(());
        }

        let _callbacks_array_base = mapped_image_base.wrapping_add(
            tls_directory
                .address_of_callbacks
                .saturating_sub(image.image_base),
        );

        for (index, callback_rva) in tls_directory.callbacks.iter().enumerate() {
            if *callback_rva == 0 {
                continue;
            }
            let callback_address =
                mapped_image_base.wrapping_add(callback_rva.saturating_sub(image.image_base));
            let _result = self.execute_guest_callback(
                state,
                memory,
                callback_address,
                &[callback_address, DLL_PROCESS_ATTACH as u64, 0, 0],
                &format!("TLS callback {}", index),
            )?;
        }

        Ok(())
    }

    pub(crate) fn initialize_security_cookie(
        &mut self,
        memory: &mut MemoryImage,
        image: &pe::ParsedPe,
        mapped_image_base: u64,
    ) -> AppResult<()> {
        let Some(load_config) = image.load_config.as_ref() else {
            return Ok(());
        };
        if load_config.security_cookie == 0 {
            return Ok(());
        }

        let cookie_size = self.guest_arch.pointer_bytes() as u64;
        let image_end = image.image_base.saturating_add(image.size_of_image as u64);
        if load_config.security_cookie < image.image_base
            || load_config.security_cookie.saturating_add(cookie_size) > image_end
        {
            return Ok(());
        }

        let cookie_address = mapped_image_base + (load_config.security_cookie - image.image_base);
        let existing_cookie = read_guest_pointer(memory, cookie_address, self.guest_arch)?;
        let default_cookie = default_security_cookie(self.guest_arch);
        self.main_module_security_cookie_address = Some(cookie_address);
        if existing_cookie != 0 && existing_cookie != default_cookie {
            self.process_pointer_cookie = existing_cookie;
            return Ok(());
        }

        let cookie = initial_guest_security_cookie(
            self.dtm,
            self.guest_arch,
            mapped_image_base,
            self.peb_base,
            self.teb_base,
        );
        write_guest_pointer(memory, cookie_address, cookie, self.guest_arch)?;
        self.process_pointer_cookie = cookie;
        self.push_trace(
            "process",
            "InitializeSecurityCookie",
            BTreeMap::from([
                ("address".to_string(), json!(format!("{cookie_address:#x}"))),
                (
                    "existing".to_string(),
                    json!(format!("{existing_cookie:#x}")),
                ),
                ("value".to_string(), json!(format!("{cookie:#x}"))),
            ]),
            json!(format!("{cookie:#x}")),
        );
        Ok(())
    }

    pub(crate) fn pointer_encoding_cookie(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        if let Some(address) = self.main_module_security_cookie_address {
            let cookie = read_guest_pointer(memory, address, self.guest_arch)?;
            if cookie != 0 {
                self.process_pointer_cookie = cookie;
                return Ok(cookie);
            }
        }
        if self.process_pointer_cookie == 0 {
            self.process_pointer_cookie = initial_guest_security_cookie(
                self.dtm,
                self.guest_arch,
                self.mapped_image_base,
                self.peb_base,
                self.teb_base,
            );
        }
        Ok(self.process_pointer_cookie)
    }

    pub(crate) fn bind_imports(
        &mut self,
        selected_base: u64,
        memory: &mut MemoryImage,
        resolved_imports: &[ResolvedImport],
    ) -> AppResult<()> {
        let mut registered_modules = BTreeSet::new();
        for import in resolved_imports {
            if registered_modules.insert(import.resolved_module.clone()) {
                let handle = self.get_or_create_module_handle(&import.resolved_module);
                self.ensure_synthetic_module_image(memory, handle);
            }
        }
        for import in resolved_imports {
            let slot_va = selected_base + import.iat_rva as u64;
            let thunk_address = self.next_thunk_address;
            self.next_thunk_address += 0x10;
            self.host_thunks
                .insert(thunk_address, HostThunk::from_import(import));
            // Register a fast-thunk for this import so that JIT-compiled
            // blocks can call the host function directly.
            self.register_fast_thunk(thunk_address);
            write_guest_pointer(memory, slot_va, thunk_address, self.guest_arch)?;
            // Generic runtime event (no behavior change): the import was
            // resolved to an export.
            let (name, ordinal) = match &import.symbol {
                pe::ImportSymbol::ByName { name, .. } => (name.clone(), None),
                pe::ImportSymbol::ByOrdinal { ordinal } => (
                    ordinal_import_name(&import.resolved_module, *ordinal)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("ordinal#{ordinal}")),
                    Some(*ordinal),
                ),
            };
            self.emit_event(crate::runtime_events::RuntimeEvent::ExportResolved {
                module: import.resolved_module.clone(),
                name,
                ordinal,
            });
        }
        Ok(())
    }

    /// Attempt to use bound import descriptors to resolve imports.
    ///
    /// Bound imports are a PE linker optimization: the linker pre-computes the
    /// correct IAT addresses at link time, storing the expected timestamps of
    /// each imported DLL. If the timestamps still match (i.e. the DLLs haven't
    /// been updated since the executable was built), the IAT values from the
    /// bound import directory can be used directly, skipping normal resolution.
    ///
    /// In our emulator we check timestamps against the real DLL file metadata
    /// (when available). If validation passes, we write the pre-computed IAT
    /// values directly into guest memory. Otherwise we fall back to normal
    /// import resolution.
    pub(crate) fn try_use_bound_imports(
        &mut self,
        image: &pe::ParsedPe,
        _selected_base: u64,
        memory: &mut MemoryImage,
    ) -> AppResult<bool> {
        if image.bound_imports.is_empty() {
            return Ok(false);
        }

        // Validate all bound import timestamps against the real DLLs.
        // A bound import's time_date_stamp should match the DLL's
        // IMAGE_FILE_HEADER.TimeDateStamp (seconds since 1970-01-01).
        let mut all_valid = true;
        for bound in &image.bound_imports {
            if !self.validate_bound_timestamp(&bound.module_name, bound.time_date_stamp) {
                all_valid = false;
                break;
            }
            // Also validate forwarder chain entries
            for fwd in &bound.forwarder_chain {
                if !self.validate_bound_timestamp(&fwd.module_name, fwd.time_date_stamp) {
                    all_valid = false;
                    break;
                }
            }
            if !all_valid {
                break;
            }
        }

        if !all_valid {
            self.push_trace(
                "pe",
                "BoundImportFallback",
                BTreeMap::from([("bound_count".to_string(), json!(image.bound_imports.len()))]),
                json!("falling back to normal import resolution"),
            );
            return Ok(false);
        }

        // All timestamps are valid — write the bound IAT values directly.
        // Bound imports don't store per-slot IAT values; instead the linker
        // has already written the correct addresses into the IAT. We only
        // need to ensure the modules are registered (synthetic images exist).
        for bound in &image.bound_imports {
            let handle = self.get_or_create_module_handle(&bound.module_name);
            self.ensure_synthetic_module_image(memory, handle);
        }

        self.push_trace(
            "pe",
            "BoundImportSuccess",
            BTreeMap::from([("bound_count".to_string(), json!(image.bound_imports.len()))]),
            json!("bound imports validated and accepted"),
        );
        Ok(true)
    }

    /// Validate that a bound import timestamp matches the actual DLL timestamp.
    ///
    /// Checks the DLL's PE header TimeDateStamp (at file offset 0x08 in the
    /// PE file) against the expected timestamp from the bound import descriptor.
    /// Returns `true` if the timestamp matches or if the DLL cannot be found
    /// (conservative fallback — allowing normal resolution to proceed would be
    /// correct even if slower).
    pub(crate) fn validate_bound_timestamp(
        &self,
        module_name: &str,
        expected_timestamp: u32,
    ) -> bool {
        // Look up the module handle to find its host path
        let handle = self.lookup_module_handle(module_name);
        let handle = match handle {
            Some(h) => h,
            None => {
                // Module not loaded yet — try to resolve its path
                let paths = self.search_dll_paths(module_name);
                if paths.is_empty() {
                    // Can't find the DLL — conservatively return false so
                    // normal resolution is attempted
                    return false;
                }
                // Try the first path
                let path = &paths[0];
                return check_dll_timestamp(path, expected_timestamp);
            }
        };

        // Find the module info for this handle
        let dll_info = self.dll_info_table.get(&handle);
        match dll_info {
            Some(info)
                // We have the DLL info with a host path — check its timestamp.
                // host_path is a String; empty means synthetic module.
                if !info.host_path.is_empty() => {
                    check_dll_timestamp(Path::new(&info.host_path), expected_timestamp)
                }
            Some(_) => false,
            None => false,
        }
    }
}
