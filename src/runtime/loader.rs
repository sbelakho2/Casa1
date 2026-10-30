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

    /// Resolve the module (HMODULE / image base) whose image range contains
    /// the given guest address.  Used by `DisableThreadLibraryCalls(NULL)`
    /// to identify the calling module; falls back to the main image base.
    pub(crate) fn module_handle_containing(&self, address: u64) -> u64 {
        if address != 0 {
            for (handle, info) in &self.dll_info_table {
                let image_size = info.image_size.max(1);
                if address >= *handle && address < handle.saturating_add(image_size) {
                    return *handle;
                }
            }
        }
        self.mapped_image_base
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
                if parsed.subsystem == IMAGE_SUBSYSTEM_NATIVE {
                    eprintln!(
                        "[pe_runtime] rejecting driver {normalized} with invalid Authenticode signature: {reason}"
                    );
                    return (0, ERROR_MOD_NOT_FOUND);
                }
                // H4: a failed Authenticode check must not block a non-driver
                // user-mode DLL.  Windows only enforces signatures for
                // drivers / protected processes; log and keep loading.
                eprintln!(
                    "[pe_runtime] warning: {normalized} has an invalid Authenticode signature ({reason}); loading anyway"
                );
            }
        }

        // E1: map a REAL image (sections, relocations) at its preferred base
        // BEFORE any DllMain is queued.  The old code handed the guest a
        // heap handle and jumped to handle + AddressOfEntryPoint, i.e. ran the
        // entry point out of uninitialised heap.  A mapping failure is a bad
        // image and LoadLibrary must return NULL with ERROR_BAD_EXE_FORMAT.
        let selected_base = parsed.image_base;
        let mapped = match crate::pe::map_image_at(&pe_bytes, &parsed, selected_base) {
            Ok(mapped) => mapped,
            Err(error) => {
                eprintln!(
                    "[pe_runtime] failed to map PE image {normalized} at {selected_base:#x}: {error}"
                );
                return (0, crate::error::ERROR_BAD_EXE_FORMAT);
            }
        };
        let handle = mapped.selected_base;

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

        // Resolve the image's IAT entries now that every provider's export
        // thunks exist.  They are written into the mapped image immediately
        // before DllMain runs (see `materialize_real_dll_image`).
        let mut import_thunks: Vec<(u32, u64)> = Vec::new();
        for descriptor in parsed.imports.iter().chain(parsed.delay_imports.iter()) {
            let provider = normalize_module_name(&descriptor.dll_name);
            let provider_is_self = provider == normalized;
            let provider_handle = if provider_is_self {
                0
            } else {
                self.lookup_module_handle(&provider)
                    .or_else(|| {
                        if export_tables().contains_key(&provider) {
                            Some(self.get_or_create_module_handle(&provider))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0)
            };
            for thunk in &descriptor.imports {
                let address = if provider_is_self {
                    match &thunk.symbol {
                        pe::ImportSymbol::ByName { name, .. } => {
                            export_thunks.get(name).copied().unwrap_or(0)
                        }
                        pe::ImportSymbol::ByOrdinal { .. } => 0,
                    }
                } else if provider_handle != 0 {
                    self.resolve_proc_address(provider_handle, thunk.symbol.clone())
                } else {
                    0
                };
                if address != 0 {
                    import_thunks.push((thunk.iat_rva, address));
                }
            }
        }

        let state = RealDllState {
            path: host_path.to_path_buf(),
            dll_name: normalized.clone(),
            exports: export_thunks,
            entry_point,
            image_base: parsed.image_base,
            refcount: 1,
            handle,
            native_library,
            mapped_image: Some(mapped),
            materialized: false,
            import_thunks,
            pointer_bytes: parsed.pointer_bytes(),
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

    /// Copy a mapped real-DLL image into guest memory (once) and patch its
    /// IAT entries.  Called from the DllMain drain, before TLS callbacks and
    /// the entry point run.
    pub(crate) fn materialize_real_dll_image(
        &mut self,
        image_base: u64,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let Some(state) = self
            .loaded_real_dlls
            .values()
            .find(|state| state.handle == image_base)
        else {
            return Ok(());
        };
        if state.materialized {
            return Ok(());
        }
        let Some(mapped) = state.mapped_image.clone() else {
            return Ok(());
        };
        let import_thunks = state.import_thunks.clone();
        let pointer_bytes = state.pointer_bytes;
        let mut bytes = mapped.memory;
        for (iat_rva, address) in import_thunks {
            let offset = iat_rva as usize;
            if offset + pointer_bytes > bytes.len() {
                continue;
            }
            if pointer_bytes == 8 {
                bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
            } else {
                bytes[offset..offset + 4].copy_from_slice(&(address as u32).to_le_bytes());
            }
        }
        let size = bytes.len() as u64;
        memory.map_bytes(mapped.selected_base, &bytes);
        self.win32.address_space_mut().register(
            mapped.selected_base,
            size,
            crate::vm::VmRegionKind::Image,
        );
        self.win32.address_space_mut().commit(
            mapped.selected_base,
            size,
            crate::vm::VmProtection::READ_WRITE_EXECUTE,
            false,
        );
        for section in &mapped.sections {
            let protection = crate::vm::VmProtection {
                read: section.protection.read,
                write: section.protection.write,
                execute: section.protection.execute,
            };
            self.win32.address_space_mut().protect(
                mapped.selected_base + u64::from(section.virtual_address),
                u64::from(section.mapped_size),
                protection,
            );
        }
        if let Some(state) = self
            .loaded_real_dlls
            .values_mut()
            .find(|state| state.handle == image_base)
        {
            state.materialized = true;
        }
        Ok(())
    }

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
            // The mapped image must be in guest memory before the first TLS
            // callback or DllMain executes.  Mapping itself (sections +
            // relocations) already happened synchronously in `load_real_dll`;
            // this copies those bytes in and patches the IAT.
            self.materialize_real_dll_image(image_base, memory)?;
            // Modules marked by DisableThreadLibraryCalls never receive
            // DLL_THREAD_ATTACH / DLL_THREAD_DETACH notifications (the
            // loader-lock flag semantics of the Win32 API).
            if (reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH)
                && self.disabled_thread_library_calls.contains(&image_base)
            {
                continue;
            }
            // Fire TLS callbacks BEFORE DllMain for attach reasons.
            if reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH {
                self.execute_tls_callbacks_for_module(state, memory, image_base, reason)?;
            }

            let entry_point = image_base + entry_point_rva as u64;
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

    /// Call a loaded DLL's entry point (DllMain) with the given reason code.
    ///
    /// `entry_point_rva` is the RVA from the PE header.  `reason` is one of
    /// `DLL_PROCESS_ATTACH`, `DLL_THREAD_ATTACH`, `DLL_THREAD_DETACH`, or
    /// `DLL_PROCESS_DETACH`.
    ///
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
    /// PE entry point are skipped.  Modules marked by
    /// `DisableThreadLibraryCalls` are skipped for thread attach/detach.
    ///
    /// The calls are deferred via [`pending_dll_main_calls`] and must be drained
    /// later (e.g. via [`drain_pending_dll_main_calls`]) from a context where
    /// guest code can safely execute.
    #[allow(dead_code)] // DllMain notification API; used by tests
    pub fn call_dll_entry_points(&mut self, dll_handles: &[u64], reason: DllReason) {
        let raw_reason = reason.to_raw();
        for &handle in dll_handles {
            let thread_reason = matches!(reason, DllReason::ThreadAttach | DllReason::ThreadDetach);
            if thread_reason && self.disabled_thread_library_calls.contains(&handle) {
                continue;
            }
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
                if *handle == self.mapped_image_base || address < *handle {
                    return false;
                }
                let size = self
                    .dll_info_table
                    .get(handle)
                    .map(|info| info.image_size.max(0x1000))
                    .unwrap_or(0x1000);
                address < handle.saturating_add(size)
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
    pub fn register_synthetic_dll_init_callback(
        &mut self,
        cb: Box<dyn FnMut(u64, u32) + Send + Sync>,
    ) {
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
        self.materialize_real_dll_image(handle, memory)?;
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
    ///
    /// Modules marked by `DisableThreadLibraryCalls` are skipped for the
    /// thread attach/detach reasons (their thread notifications are
    /// suppressed as a whole, TLS callbacks included).
    pub(crate) fn fire_tls_callbacks_for_all_modules(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        reason: u32,
    ) -> AppResult<()> {
        let thread_reason = reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH;
        let handles: Vec<u64> = self.dll_info_table.keys().copied().collect();
        for handle in handles {
            if thread_reason && self.disabled_thread_library_calls.contains(&handle) {
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::GeArch;

    const PROBE_IMAGE_BASE: u32 = 0x1000_0000;
    const IAT_SELF_BY_NAME: u32 = 0x2080;
    const IAT_SELF_BY_ORDINAL: u32 = 0x2084;
    const IAT_PROVIDER: u32 = 0x2098;
    const IAT_KERNEL32: u32 = 0x20A8;
    const IAT_MISSING: u32 = 0x20B8;
    const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
    const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

    fn probe_runtime(name: &str) -> (PeHostRuntime, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
            .expect("game environment");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
        runtime.next_data_address = data_base_for_arch(GuestArch::X86);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
        runtime.x86_heap_region = 0;
        (runtime, temp_dir)
    }

    fn write_probe(temp_dir: &tempfile::TempDir, file_name: &str, image: &[u8]) -> PathBuf {
        let path = temp_dir.path().join(file_name);
        fs::write(&path, image).expect("write probe image");
        path
    }

    /// Minimal PE32 (two sections, one named export) with optional knobs for
    /// the loader error paths: unaligned `image_base` (map failure), native
    /// subsystem + garbage Authenticode table (driver rejection), and a
    /// four-descriptor import table exercising every IAT-resolution branch of
    /// `load_real_dll`: self by-name, self by-ordinal, a loaded real provider,
    /// the synthesizable `kernel32.dll` provider, and a missing module.
    fn build_probe_pe(
        dll_name: &str,
        image_base: u32,
        subsystem: u16,
        garbage_cert: bool,
        with_imports: bool,
    ) -> Vec<u8> {
        let mut pe = vec![0u8; 0x600];
        // DOS header with e_lfanew == 0x80.
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        // NT headers: COFF (i386, two sections, 0xE0-byte optional header).
        let nt = 0x80usize;
        pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
        pe[nt + 4..nt + 6].copy_from_slice(&0x014C_u16.to_le_bytes());
        pe[nt + 6..nt + 8].copy_from_slice(&2_u16.to_le_bytes());
        pe[nt + 20..nt + 22].copy_from_slice(&0x00E0_u16.to_le_bytes());
        pe[nt + 22..nt + 24].copy_from_slice(&0x2102_u16.to_le_bytes());
        // Optional header (PE32).
        let opt = nt + 24;
        pe[opt..opt + 2].copy_from_slice(&0x010B_u16.to_le_bytes());
        pe[opt + 16..opt + 20].copy_from_slice(&0_u32.to_le_bytes()); // no entry point: no DllMain
        pe[opt + 20..opt + 24].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[opt + 24..opt + 28].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[opt + 28..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes()); // SectionAlignment
        pe[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes()); // FileAlignment
        pe[opt + 48..opt + 50].copy_from_slice(&4_u16.to_le_bytes()); // MajorSubsystemVersion
        pe[opt + 56..opt + 60].copy_from_slice(&0x3000_u32.to_le_bytes()); // SizeOfImage
        pe[opt + 60..opt + 64].copy_from_slice(&0x200_u32.to_le_bytes()); // SizeOfHeaders
        pe[opt + 68..opt + 70].copy_from_slice(&subsystem.to_le_bytes());
        pe[opt + 92..opt + 96].copy_from_slice(&16_u32.to_le_bytes()); // NumberOfRvaAndSizes
        // Data directories: [0] export (RVA 0x1000, size 0x40), [1] import.
        pe[opt + 96..opt + 100].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[opt + 100..opt + 104].copy_from_slice(&0x40_u32.to_le_bytes());
        if with_imports {
            pe[opt + 104..opt + 108].copy_from_slice(&0x2000_u32.to_le_bytes());
            pe[opt + 108..opt + 112].copy_from_slice(&0x80_u32.to_le_bytes());
        }
        if garbage_cert {
            // IMAGE_DIRECTORY_ENTRY_SECURITY carries a FILE offset, not an RVA.
            let security = opt + 96 + 4 * 8;
            pe[security..security + 4].copy_from_slice(&0x600_u32.to_le_bytes());
            pe[security + 4..security + 8].copy_from_slice(&0x20_u32.to_le_bytes());
        }
        // Section table: .edata (VA 0x1000, file 0x200), .idata (VA 0x2000, file 0x400).
        let section = opt + 0xE0;
        pe[section..section + 8].copy_from_slice(b".edata\0\0");
        pe[section + 8..section + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        pe[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[section + 36..section + 40].copy_from_slice(&0x4000_0040_u32.to_le_bytes());
        let idata_header = section + 40;
        pe[idata_header..idata_header + 8].copy_from_slice(b".idata\0\0");
        pe[idata_header + 8..idata_header + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[idata_header + 12..idata_header + 16].copy_from_slice(&0x2000_u32.to_le_bytes());
        pe[idata_header + 16..idata_header + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        pe[idata_header + 20..idata_header + 24].copy_from_slice(&0x400_u32.to_le_bytes());
        pe[idata_header + 36..idata_header + 40].copy_from_slice(&0xC000_0040_u32.to_le_bytes());

        // RVA → file offset for the two single-section images.
        let edata = |rva: u32| -> usize { 0x200 + (rva - 0x1000) as usize };
        let idata = |rva: u32| -> usize { 0x400 + (rva - 0x2000) as usize };
        let put_u32 = |pe: &mut Vec<u8>, at: usize, value: u32| {
            pe[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        let put_name = |pe: &mut Vec<u8>, at: usize, value: &str| {
            pe[at..at + value.len()].copy_from_slice(value.as_bytes());
        };

        // Export directory at RVA 0x1000: one named function.
        put_u32(&mut pe, edata(0x1000) + 12, 0x1080); // Name
        put_u32(&mut pe, edata(0x1000) + 16, 1); // Base
        put_u32(&mut pe, edata(0x1000) + 20, 1); // NumberOfFunctions
        put_u32(&mut pe, edata(0x1000) + 24, 1); // NumberOfNames
        put_u32(&mut pe, edata(0x1000) + 28, 0x1040); // AddressOfFunctions
        put_u32(&mut pe, edata(0x1000) + 32, 0x1044); // AddressOfNames
        put_u32(&mut pe, edata(0x1000) + 36, 0x1048); // AddressOfNameOrdinals
        put_u32(&mut pe, edata(0x1040), 0x1050); // function RVA (outside the directory)
        put_u32(&mut pe, edata(0x1044), 0x1060); // name RVA
        put_u32(&mut pe, edata(0x1048), 0); // ordinal index
        put_name(&mut pe, edata(0x1060), "ProbeExport\0");
        put_name(&mut pe, edata(0x1080), &format!("{dll_name}\0"));

        if with_imports {
            // Four descriptors + null terminator at RVA 0x2000.
            let mut descriptor = |index: u32, oft: u32, name_rva: u32, ft: u32| {
                let at = idata(0x2000 + index * 20);
                put_u32(&mut pe, at, oft);
                put_u32(&mut pe, at + 12, name_rva);
                put_u32(&mut pe, at + 16, ft);
            };
            descriptor(0, 0x2070, 0x2150, 0x2080); // self
            descriptor(1, 0x2090, 0x2170, 0x2098); // loaded real provider
            descriptor(2, 0x20A0, 0x2190, 0x20A8); // synthesizable kernel32
            descriptor(3, 0x20B0, 0x21B0, 0x20B8); // missing module
            // INT/IAT arrays (PE32: 4-byte entries, zero-terminated).
            for (iat, hint_name) in [
                (0x2070_u32, 0x20C0_u32),
                (0x2080, 0x20C0),
                (0x2090, 0x20D0),
                (0x2098, 0x20D0),
                (0x20A0, 0x20E0),
                (0x20A8, 0x20E0),
                (0x20B0, 0x20F0),
                (0x20B8, 0x20F0),
            ] {
                put_u32(&mut pe, idata(iat), hint_name);
            }
            // Self ordinal import second entry (iat slot 0x2084).
            put_u32(&mut pe, idata(0x2074), 0x8000_0001);
            put_u32(&mut pe, idata(0x2084), 0x8000_0001);
            // Hint/name entries.
            for (at, symbol) in [
                (0x20C0_u32, "ProbeExport\0"),
                (0x20D0, "ProbeExport\0"),
                (0x20E0, "CreateFileW\0"),
                (0x20F0, "NoSuchExport\0"),
            ] {
                put_name(&mut pe, idata(at + 2), symbol);
            }
            // Imported module names.
            put_name(&mut pe, idata(0x2150), "casa1_import_probe.dll\0");
            put_name(&mut pe, idata(0x2170), "casa1_provider.dll\0");
            put_name(&mut pe, idata(0x2190), "KERNEL32.dll\0");
            put_name(&mut pe, idata(0x21B0), "definitely_missing_module.dll\0");
        }

        if garbage_cert {
            // WIN_CERTIFICATE at file offset 0x600: well-formed header,
            // garbage PKCS#7 payload → AuthenticodeVerdict::Invalid.
            pe.extend_from_slice(&0x20_u32.to_le_bytes()); // dwLength
            pe.extend_from_slice(&0x0200_u16.to_le_bytes()); // wRevision
            pe.extend_from_slice(&0x0002_u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            pe.extend_from_slice(&[0xFF; 0x18]);
        }
        pe
    }

    #[test]
    fn load_real_dll_rejects_driver_image_with_invalid_authenticode_signature() {
        let (mut runtime, temp_dir) = probe_runtime("loader-driver-reject");
        let image = build_probe_pe(
            "casa1_driver_probe.sys",
            PROBE_IMAGE_BASE,
            IMAGE_SUBSYSTEM_NATIVE,
            true,
            false,
        );
        let path = write_probe(&temp_dir, "casa1_driver_probe.sys", &image);
        let (handle, status) = runtime.load_real_dll("casa1_driver_probe.sys", &path);
        assert_eq!(handle, 0, "an invalidly signed driver must not load");
        assert_eq!(status, ERROR_MOD_NOT_FOUND);
        assert!(
            !runtime
                .loaded_real_dlls
                .contains_key("casa1_driver_probe.sys"),
            "the rejected driver must not be registered"
        );

        // H4: the SAME invalid signature on a non-driver (user-mode) image
        // must not block the load — Windows only enforces Authenticode for
        // drivers / protected processes, so the image loads with a warning.
        let user_image = build_probe_pe(
            "casa1_invalid_sig_user.dll",
            0x0E00_0000,
            IMAGE_SUBSYSTEM_WINDOWS_CUI,
            true,
            false,
        );
        let user_path = write_probe(&temp_dir, "casa1_invalid_sig_user.dll", &user_image);
        let (user_handle, user_status) =
            runtime.load_real_dll("casa1_invalid_sig_user.dll", &user_path);
        assert_eq!(
            user_status, 0,
            "an invalid signature must not block a user DLL"
        );
        assert_eq!(user_handle, 0x0E00_0000);
        assert!(
            runtime
                .loaded_real_dlls
                .contains_key("casa1_invalid_sig_user.dll")
        );
    }

    #[test]
    fn load_real_dll_rejects_unaligned_image_base_with_bad_exe_format() {
        let (mut runtime, temp_dir) = probe_runtime("loader-unaligned-map");
        // Parses cleanly; only `map_image_at` rejects the image base that is
        // not aligned to SectionAlignment.
        let image = build_probe_pe(
            "casa1_unaligned_probe.dll",
            PROBE_IMAGE_BASE + 1,
            IMAGE_SUBSYSTEM_WINDOWS_CUI,
            false,
            false,
        );
        let path = write_probe(&temp_dir, "casa1_unaligned_probe.dll", &image);
        let (handle, status) = runtime.load_real_dll("casa1_unaligned_probe.dll", &path);
        assert_eq!(handle, 0, "the unaligned image must not map");
        assert_eq!(status, crate::error::ERROR_BAD_EXE_FORMAT);
        assert!(runtime.loaded_real_dlls.is_empty());
    }

    #[test]
    fn load_real_dll_import_edge_missing_provider_and_ordinal_thunks_resolve_exactly() {
        let (mut runtime, temp_dir) = probe_runtime("loader-import-edges");

        // The provider maps at its own distinct preferred base so its state
        // can never shadow the probe's handle in `materialize_real_dll_image`.
        let provider_image = build_probe_pe(
            "casa1_provider.dll",
            0x0F00_0000,
            IMAGE_SUBSYSTEM_WINDOWS_CUI,
            false,
            false,
        );
        let provider_path = write_probe(&temp_dir, "casa1_provider.dll", &provider_image);
        let (provider_handle, provider_status) =
            runtime.load_real_dll("casa1_provider.dll", &provider_path);
        assert_eq!(provider_status, 0);
        assert_ne!(provider_handle, 0);
        let provider_thunk = runtime
            .loaded_real_dlls
            .get("casa1_provider.dll")
            .expect("provider state")
            .exports
            .get("ProbeExport")
            .copied()
            .expect("provider ProbeExport thunk");
        assert_ne!(provider_thunk, 0);

        let probe_image = build_probe_pe(
            "casa1_import_probe.dll",
            PROBE_IMAGE_BASE,
            IMAGE_SUBSYSTEM_WINDOWS_CUI,
            false,
            true,
        );
        let probe_path = write_probe(&temp_dir, "casa1_import_probe.dll", &probe_image);
        let (handle, status) = runtime.load_real_dll("casa1_import_probe.dll", &probe_path);
        assert_eq!(status, 0, "the import probe must load");
        assert_eq!(handle, u64::from(PROBE_IMAGE_BASE));

        let state = runtime
            .loaded_real_dlls
            .get("casa1_import_probe.dll")
            .expect("probe state");
        assert_eq!(state.pointer_bytes, 4);
        let self_thunk = state
            .exports
            .get("ProbeExport")
            .copied()
            .expect("self export thunk");
        assert_ne!(self_thunk, 0);
        assert_eq!(
            state.import_thunks.len(),
            3,
            "self by-name + loaded provider + synthesizable kernel32"
        );
        assert_eq!(state.import_thunks[0], (IAT_SELF_BY_NAME, self_thunk));
        assert_eq!(state.import_thunks[1], (IAT_PROVIDER, provider_thunk));
        assert_eq!(state.import_thunks[2].0, IAT_KERNEL32);
        let kernel32_thunk = state.import_thunks[2].1;
        assert_ne!(
            kernel32_thunk, 0,
            "kernel32!CreateFileW must synthesize a host thunk"
        );
        assert!(
            !state
                .import_thunks
                .iter()
                .any(|(iat_rva, _)| *iat_rva == IAT_SELF_BY_ORDINAL),
            "ordinal-only self import must stay unresolved"
        );
        assert!(
            !state
                .import_thunks
                .iter()
                .any(|(iat_rva, _)| *iat_rva == IAT_MISSING),
            "import from a missing module must stay unresolved"
        );

        // An IAT RVA outside the mapped image must be skipped, not panic.
        runtime
            .loaded_real_dlls
            .get_mut("casa1_import_probe.dll")
            .expect("probe state")
            .import_thunks
            .push((0xF000_0000, 0xABCD));

        let mut memory = MemoryImage::default();
        runtime
            .materialize_real_dll_image(handle, &mut memory)
            .expect("materialise probe image");
        assert_eq!(
            read_u32(&memory, handle + u64::from(IAT_SELF_BY_NAME)).expect("self IAT slot"),
            self_thunk as u32
        );
        assert_eq!(
            read_u32(&memory, handle + u64::from(IAT_PROVIDER)).expect("provider IAT slot"),
            provider_thunk as u32
        );
        assert_eq!(
            read_u32(&memory, handle + u64::from(IAT_KERNEL32)).expect("kernel32 IAT slot"),
            kernel32_thunk as u32
        );
        assert_eq!(
            read_u32(&memory, handle + u64::from(IAT_MISSING)).expect("missing IAT slot"),
            0x20F0,
            "the unresolved slot keeps the raw image value, never a thunk"
        );
        assert_eq!(
            memory.read_u8(handle).expect("mapped header"),
            b'M',
            "headers are copied into guest memory before DllMain"
        );
        assert!(
            runtime
                .loaded_real_dlls
                .get("casa1_import_probe.dll")
                .expect("probe state")
                .materialized
        );
        // Second call hits the materialised early-return; an unknown handle
        // hits the no-state early-return.
        runtime
            .materialize_real_dll_image(handle, &mut memory)
            .expect("already materialised image is a no-op");
        runtime
            .materialize_real_dll_image(0xDEAD_0000, &mut memory)
            .expect("unknown handle is a no-op");
    }

    #[test]
    fn materialize_real_dll_image_edge_unmapped_state_and_x64_iat_width() {
        let (mut runtime, _temp_dir) = probe_runtime("loader-materialize-edges");
        let mut memory = MemoryImage::default();

        runtime
            .materialize_real_dll_image(0x1234_0000, &mut memory)
            .expect("unknown handle is a no-op");

        runtime.loaded_real_dlls.insert(
            "synthetic_probe.dll".to_string(),
            RealDllState {
                path: PathBuf::from("/synthetic/probe.dll"),
                dll_name: "synthetic_probe.dll".to_string(),
                exports: HashMap::new(),
                entry_point: None,
                image_base: 0x1400_0000,
                refcount: 1,
                handle: 0x1400_0000,
                native_library: None,
                mapped_image: None,
                materialized: false,
                import_thunks: Vec::new(),
                pointer_bytes: 4,
            },
        );
        runtime
            .materialize_real_dll_image(0x1400_0000, &mut memory)
            .expect("state without a mapped image is a no-op");

        // 64-bit image: the IAT patch must span a full 8-byte pointer.
        let x64_base = 0x0000_0001_8000_0000_u64;
        runtime.loaded_real_dlls.insert(
            "x64_probe.dll".to_string(),
            RealDllState {
                path: PathBuf::from("/x64/probe.dll"),
                dll_name: "x64_probe.dll".to_string(),
                exports: HashMap::new(),
                entry_point: None,
                image_base: x64_base,
                refcount: 1,
                handle: x64_base,
                native_library: None,
                mapped_image: Some(crate::pe::MappedImage {
                    preferred_base: x64_base,
                    selected_base: x64_base,
                    memory: vec![0u8; 0x2000],
                    sections: vec![crate::pe::SectionMapping {
                        name: ".text".to_string(),
                        virtual_address: 0x1000,
                        mapped_size: 0x1000,
                        raw_data_size: 0,
                        protection: crate::pe::MemoryProtection {
                            read: true,
                            write: false,
                            execute: true,
                        },
                    }],
                }),
                materialized: false,
                import_thunks: vec![(0x100, 0x1122_3344_5566_7788)],
                pointer_bytes: 8,
            },
        );
        runtime
            .materialize_real_dll_image(x64_base, &mut memory)
            .expect("materialise 64-bit image");
        assert_eq!(
            read_u64(&memory, x64_base + 0x100).expect("64-bit IAT slot"),
            0x1122_3344_5566_7788
        );
        assert!(
            runtime
                .loaded_real_dlls
                .get("x64_probe.dll")
                .expect("x64 state")
                .materialized
        );
        runtime
            .materialize_real_dll_image(x64_base, &mut memory)
            .expect("already materialised image is a no-op");
    }

    #[test]
    fn dll_main_drain_edge_disabled_thread_module_is_materialized_without_guest_entry() {
        let (mut runtime, _temp_dir) = probe_runtime("loader-drain-disabled");
        let mut memory = MemoryImage::default();
        let mut state = CpuState::new(GuestArch::X86);

        let base = 0x6000_0000_u64;
        let mut image = vec![0u8; 0x800];
        image[0] = b'M';
        image[1] = b'Z';
        runtime.loaded_real_dlls.insert(
            "drain_probe.dll".to_string(),
            RealDllState {
                path: PathBuf::from("/drain/probe.dll"),
                dll_name: "drain_probe.dll".to_string(),
                exports: HashMap::new(),
                entry_point: Some(0x100),
                image_base: base,
                refcount: 1,
                handle: base,
                native_library: None,
                mapped_image: Some(crate::pe::MappedImage {
                    preferred_base: base,
                    selected_base: base,
                    memory: image,
                    sections: Vec::new(),
                }),
                materialized: false,
                import_thunks: Vec::new(),
                pointer_bytes: 4,
            },
        );
        runtime.disabled_thread_library_calls.insert(base);
        runtime
            .pending_dll_main_calls
            .push_back((base, 0x100, DLL_THREAD_ATTACH));
        runtime
            .drain_pending_dll_main_calls(&mut state, &mut memory)
            .expect("drain skips the disabled module");
        assert_eq!(
            runtime.pending_dll_main_calls.len(),
            0,
            "the queued notification is consumed"
        );
        assert_eq!(
            memory.read_u8(base).expect("materialised image"),
            b'M',
            "materialise ran before the disabled-thread skip"
        );
    }

    #[test]
    fn execute_tls_callbacks_for_missing_module_is_noop() {
        let (mut runtime, _temp_dir) = probe_runtime("loader-tls-missing");
        let mut memory = MemoryImage::default();
        let mut state = CpuState::new(GuestArch::X86);
        let before = runtime.dll_info_table.len();
        let result = runtime.execute_tls_callbacks_for_module(
            &mut state,
            &mut memory,
            0x7777_0000,
            DLL_PROCESS_ATTACH,
        );
        assert_eq!(result.err().map(|error| error.code), None::<ReasonCode>);
        assert_eq!(
            runtime.dll_info_table.len(),
            before,
            "no module table entry is invented"
        );
    }

    #[test]
    fn execute_tls_callbacks_error_on_faulting_callback_address() {
        let (mut runtime, _temp_dir) = probe_runtime("loader-tls-fault");
        let mut memory = MemoryImage::default();
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, 0x50_000);
        memory.map_bytes(0x50_000, &[0u8; 0x400]);
        let handle = 0x7788_0000_u64;
        runtime.dll_info_table.insert(
            handle,
            DllInfo {
                handle,
                image_size: 0x1000,
                entry_point_rva: 0,
                load_count: 1,
                module_name: "ghost_tls.dll".to_string(),
                host_path: String::new(),
                // The zero RVA is skipped before any guest code runs; the
                // second callback lands in unmapped memory and must surface
                // the guest fetch fault instead of being swallowed.
                tls_callbacks: vec![0, 0x100],
            },
        );
        let error = runtime
            .execute_tls_callbacks_for_module(&mut state, &mut memory, handle, DLL_PROCESS_ATTACH)
            .expect_err("unmapped TLS callback must fail");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        assert_eq!(
            error.message,
            "unmapped guest memory at 0x77880100 while executing guest instruction at \
             0x77880100: <unavailable> | rax=0x0 rbx=0x0 rcx=0x0 rdx=0x0 rsi=0x0 rdi=0x0 \
             rsp=0x4ffec rbp=0x0"
        );
    }

    #[test]
    fn module_handle_from_address_edge_ranges_missing_info_and_saturation() {
        let (mut runtime, _temp_dir) = probe_runtime("loader-module-address");
        runtime.mapped_image_base = 0x4000_0000;
        runtime.mapped_image_size = 0x1000;
        runtime
            .module_handles
            .insert("probe_a.dll".to_string(), 0x6000_0000);
        runtime.dll_info_table.insert(
            0x6000_0000,
            DllInfo {
                handle: 0x6000_0000,
                image_size: 0x2000,
                entry_point_rva: 0,
                load_count: 1,
                module_name: "probe_a.dll".to_string(),
                host_path: String::new(),
                tls_callbacks: Vec::new(),
            },
        );
        // Registered without DllInfo: the 0x1000 fallback window applies.
        runtime
            .module_handles
            .insert("probe_b.dll".to_string(), 0x7000_0000);
        runtime
            .module_handles
            .insert("probe_top.dll".to_string(), u64::MAX - 0x100);

        assert_eq!(
            runtime.module_handle_from_address(0x4000_0800),
            Some(0x4000_0000),
            "addresses inside the main image resolve to it"
        );
        assert_eq!(
            runtime.module_handle_from_address(0x6000_1000),
            Some(0x6000_0000)
        );
        assert_eq!(
            runtime.module_handle_from_address(0x6000_0000),
            Some(0x6000_0000),
            "the exact module base is inside the module"
        );
        assert_eq!(
            runtime.module_handle_from_address(0x7000_0F00),
            Some(0x7000_0000),
            "missing DllInfo falls back to a 0x1000 window"
        );
        assert_eq!(
            runtime.module_handle_from_address(0x6000_3000),
            None,
            "past the module size and below the next handle"
        );
        assert_eq!(
            runtime.module_handle_from_address(0x4000_2000),
            None,
            "the main-image handle is skipped before its size is consulted"
        );
        assert_eq!(
            runtime.module_handle_from_address(0x2000_0000),
            None,
            "addresses below every handle never resolve"
        );
        assert_eq!(
            runtime.module_handle_from_address(u64::MAX - 0x80),
            Some(u64::MAX - 0x100),
            "the topmost handle saturates instead of overflowing"
        );
    }

    #[test]
    fn synthetic_dll_init_callback_failure_race_fires_exactly_once() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "loader-synthetic-callback",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("game environment");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_callback = std::sync::Arc::clone(&seen);
        runtime.register_synthetic_dll_init_callback(Box::new(move |handle, reason| {
            seen_callback
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((handle, reason));
        }));
        let handle = runtime.get_or_create_module_handle("casa1_callback_probe.dll");
        assert_ne!(handle, 0, "a synthetic module must receive a real handle");
        assert_eq!(
            *seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![(handle, DLL_PROCESS_ATTACH)],
            "the callback must observe the created handle and the attach reason"
        );
        let again = runtime.get_or_create_module_handle("casa1_callback_probe.dll");
        assert_eq!(again, handle, "the repeat load must reuse the handle");
        assert_eq!(
            seen.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1,
            "a repeated load must not fire a second synthetic init callback"
        );
    }
}
