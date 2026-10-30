//! Process lifecycle, precompilation, and shell glue (runtime methods).

use super::*;

impl PeHostRuntime {
    /// Precompile the whole mapped image at `entry` when enabled.
    pub(crate) fn precompile_image(
        &mut self,
        memory: &MemoryImage,
        entry: u64,
    ) -> AppResult<Option<crate::precompile::PrecompileReport>> {
        if !self.aot_precompile || self.mapped_image_size == 0 {
            return Ok(None);
        }
        let image_end = self
            .mapped_image_base
            .saturating_add(self.mapped_image_size);
        self.precompile_code_range(memory, entry, image_end, 20_000)
    }

    /// Discover and precompile every control-flow-reachable block of the
    /// mapped image before guest entry, persisting each translation in the
    /// AOT cache.  Returns `None` when the JIT is disabled.
    pub(crate) fn precompile_code_range(
        &mut self,
        memory: &MemoryImage,
        start: u64,
        end: u64,
        max_blocks: usize,
    ) -> AppResult<Option<crate::precompile::PrecompileReport>> {
        let arch = self.guest_arch;
        let Some(jit) = self.jit_runtime.as_mut() else {
            return Ok(None);
        };
        let report = crate::precompile::precompile_blocks(
            memory,
            arch,
            start,
            end,
            max_blocks,
            |ir, address| {
                jit.get_or_compile_slice_block(ir, address, arch)
                    .map(|_| ())
            },
        )?;
        Ok(Some(report))
    }

    /// Attach a generic runtime-event observer.  The runtime works perfectly
    /// with no observer attached — this is purely opt-in workload wiring.
    pub fn add_observer(&mut self, observer: Box<dyn crate::runtime_events::RuntimeObserver>) {
        if let Ok(mut guard) = self.observers.lock() {
            guard.push(observer);
        }
    }

    /// Dispatch one generic runtime event to every attached observer.
    pub(crate) fn emit_event(&mut self, event: crate::runtime_events::RuntimeEvent) {
        crate::runtime_events::dispatch(&self.observers, &event);
    }

    /// True when at least one observer is attached (hot paths use this to
    /// skip constructing events nobody will receive).
    pub(crate) fn has_observers(&self) -> bool {
        crate::runtime_events::observer_count(&self.observers) > 0
    }

    pub(crate) fn set_guest_arch(&mut self, guest_arch: GuestArch) {
        self.guest_arch = guest_arch;
        self.next_thunk_address = thunk_base_for_arch(guest_arch);
        self.next_data_address = data_base_for_arch(guest_arch);
        self.next_heap_address = heap_base_for_arch(guest_arch);
        self.win32
            .reset_address_space(private_pages_base_for_arch(guest_arch));
        self.x86_heap_region = 0;
        // JIT enablement is part of the runner protocol (RunnerJob.jit_mode):
        //   - Disabled: never construct the JIT runtime.
        //   - Auto: construct the JIT runtime only when the runtime capability
        //     probe actually executed its ARM64 stub AND the run is not
        //     deterministic.  On an incapable host (e.g. macOS without the
        //     allow-jit entitlement, or a non-ARM64 build) Auto stays
        //     interpreter-only, exactly like Disabled.
        //   - Enabled: explicit caller override — construct the JIT runtime
        //     even when the probe is unavailable (the run reports the honest
        //     execution failure) and even for deterministic runs.
        // The exact rule is centralised in `jit_construction_selected` and
        // covered by `jit_construction_gate_rule`.
        let capability_available = crate::jit::jit_execution_available();
        if jit_construction_selected(&self.jit_mode, self.dtm, capability_available) {
            let mut jit_runtime = crate::jit::JitRuntime::new(guest_arch);
            jit_runtime.unwind_table.register_with_seh(&mut self.seh);
            self.jit_runtime = Some(jit_runtime);
            self.tiered_compiler = crate::jit::TieredCompiler::new();
            eprintln!(
                "[pe_runtime] JIT runtime constructed (mode={}, capability={}, deterministic={})",
                self.jit_mode.as_str(),
                capability_available,
                self.dtm
            );
        }
    }

    pub(crate) fn launch_guest_child_process(
        &mut self,
        application: &str,
        command_line: &str,
        environment: &BTreeMap<String, String>,
        cwd: &str,
        inherit_handles: bool,
    ) -> AppResult<crate::win32::CreateProcessResult> {
        let result = self.win32.create_process_w(
            application,
            command_line,
            environment,
            cwd,
            inherit_handles,
        )?;
        let host_program = self.win32.guest_path_to_host_path(application)?;
        if !host_program.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("child executable not found: {}", host_program.display()),
            ));
        }

        let host_cwd = self
            .win32
            .guest_path_to_host_path(cwd)
            .ok()
            .or_else(|| host_program.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));

        // Install the exit-sync condvar pair so that WaitForSingleObject
        // can block on this child process handle until it finishes.
        let sync = Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        self.win32
            .install_process_exit_sync(result.process_handle, sync.clone())?;

        if is_pe_image(&host_program)? {
            // For PE images, spawn casa1-runner as a child subprocess.
            // The casa1-runner binary handles PE execution in a separate
            // process, providing real process isolation.
            let runner_path = find_casa1_runner_binary()?;
            let argv: Vec<String> = result.argv.iter().skip(1).cloned().collect();
            // Child run identity (instrumentation): the child runner inherits
            // the parent's CASA1_RUN_ID so its bootstrap artifact belongs to
            // the same run and the parent can merge child evidence, plus the
            // parent's guest-visible pid.  The injection mirrors real Windows
            // environment inheritance even when the guest passed its own
            // environment block.
            let mut env = (*environment).clone();
            if let Some(run_id) = self.process_environment.get("CASA1_RUN_ID").cloned() {
                env.insert("CASA1_RUN_ID".to_string(), run_id);
            }
            env.insert(
                "CASA1_PARENT_PID".to_string(),
                self.win32.current_process_id().to_string(),
            );
            let ge = self.win32.ge().clone();
            let dtm = self.dtm;
            let child_test_base = env
                .get("CASA1_TEST_ID")
                .map(String::as_str)
                .filter(|id| !id.is_empty())
                .unwrap_or("nested-pe-child")
                .to_string();
            // Every child gets a distinct test id (the guest-visible child
            // process id) so concurrent children never collide on artifact
            // filenames or trace paths.
            let child_test_id = format!("{child_test_base}-child-{}", result.process_id);

            // Build a RunnerJob for the child PE.
            let job = crate::runner::RunnerJob {
                ge_name: ge.config.name.clone(),
                ge_root: ge.root.clone(),
                program: host_program.clone(),
                args: argv,
                cwd: host_cwd.clone(),
                env,
                dtm,
                intent: crate::runner::RunIntent::Run,
                trace_categories: Vec::new(),
                test_id: child_test_id,
                jit_mode: crate::runner::JitMode::Auto,
                steam_ipc: false,
                window_width: None,
                window_height: None,
                // CreateProcessW children run their image from the entry
                // point; only an NtCreateThreadEx first thread injects a
                // start routine.
                thread_start: None,
            };

            // Serialise the job to a temporary JSON file.
            let job_json = serde_json::to_string(&job).map_err(|e| {
                AppError::new(
                    ReasonCode::RcRunnerProtocolInvalid,
                    format!("failed to serialise runner job: {e}"),
                )
            })?;
            let job_dir = std::env::temp_dir().join("casa1-createprocess");
            std::fs::create_dir_all(&job_dir).map_err(|e| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to create job dir {}", job_dir.display()),
                    &e,
                )
            })?;
            let job_path = job_dir.join(format!("child-{}.json", result.process_id));
            std::fs::write(&job_path, &job_json).map_err(|e| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to write runner job to {}", job_path.display()),
                    &e,
                )
            })?;

            // Spawn the background monitor thread that starts the runner
            // subprocess and captures its exit code.
            let sync = Some(sync);
            let job_path_clone = job_path.clone();
            std::thread::spawn(move || {
                let exit_code = Self::spawn_runner_and_wait(&runner_path, &job_path_clone);
                // Clean up the temporary job file.
                let _ = std::fs::remove_file(&job_path_clone);
                if let Some(ref sync) = sync {
                    let (lock, cvar) = &**sync;
                    let mut guard = lock.lock().unwrap();
                    *guard = Some(exit_code);
                    cvar.notify_all();
                }
            });
        } else {
            // Guest processes may only run PE images.  A host binary (script,
            // Mach-O, ELF) must never be exec'd from inside the sandbox: that
            // would be an arbitrary native-execution escape.
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!(
                    "child image {} is not a PE image; native execution is forbidden",
                    host_program.display()
                ),
            ));
        }

        Ok(result)
    }

    /// Spawn casa1-runner as a child process for a serialized job, WITHOUT
    /// waiting: the caller owns the returned `Child` (the native-child
    /// launch path tracks its pid for `NtTerminateProcess`).
    pub(crate) fn spawn_runner_process(
        runner_path: &Path,
        job_path: &Path,
    ) -> AppResult<std::process::Child> {
        std::process::Command::new(runner_path)
            .arg("--job")
            .arg(job_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcRunnerSpawnFailed,
                    format!("failed to spawn casa1-runner: {error}"),
                    &error,
                )
            })
    }

    /// Wait for a spawned casa1-runner child and return its guest exit code
    /// (extracted from the runner's JSON outcome on stdout; `u32::MAX` when
    /// the wait fails or the child died without a parseable outcome).
    pub(crate) fn finish_runner_child(child: std::process::Child) -> u32 {
        match child.wait_with_output() {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Try to extract the actual child PE exit code from the JSON output.
                if let Ok(outcome) =
                    serde_json::from_str::<crate::runner::RunnerOutcome>(&output_str)
                {
                    outcome.canonical_output.exit_code as u32
                } else {
                    // Fallback: use the process exit code.
                    output.status.code().map(|c| c as u32).unwrap_or(u32::MAX)
                }
            }
            Err(e) => {
                eprintln!("[pe_runtime] failed to wait for casa1-runner: {e:?}");
                u32::MAX
            }
        }
    }

    /// Spawn casa1-runner with a job file and wait for it to complete.
    /// Returns the exit code (u32::MAX on failure).
    pub(crate) fn spawn_runner_and_wait(runner_path: &Path, job_path: &Path) -> u32 {
        match Self::spawn_runner_process(runner_path, job_path) {
            Ok(child) => Self::finish_runner_child(child),
            Err(error) => {
                eprintln!("[pe_runtime] failed to spawn casa1-runner: {error:?}");
                u32::MAX
            }
        }
    }

    pub(crate) fn alloc_utf16_string(
        &mut self,
        memory: &mut MemoryImage,
        value: &str,
    ) -> AppResult<u64> {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        let address = self.alloc_zeroed(memory, bytes.len(), 2)?;
        memory.map_bytes(address, &bytes);
        Ok(address)
    }

    pub(crate) fn shell_special_folder_path(
        &mut self,
        raw_csidl: i32,
    ) -> AppResult<Option<String>> {
        // SHGetFolderPath-style APIs return the canonical path without
        // creating anything: Windows never manufactures special-folder
        // directories here, so neither does the runtime.
        Ok(shell_special_folder_path(
            &self.win32.ge().config.user_name,
            raw_csidl,
            self.guest_arch,
        ))
    }

    /// Extract the largest icon resource of a guest module path (the
    /// ExtractIconW contract): `None` when the file cannot be read or
    /// carries no icon resource — the documented zero-handle path.
    pub(crate) fn extract_guest_icon(&self, guest_path: &str) -> Option<crate::icon::IconImage> {
        let host_path = self.win32.guest_path_to_host_path(guest_path).ok()?;
        let bytes = fs::read(&host_path).ok()?;
        crate::pe::extract_icon_from_pe(&bytes)
            .ok()?
            .into_iter()
            .next()
    }

    /// Extract all icon resources of a guest module path (the
    /// ExtractIconExW contract): an empty vector when the file cannot be
    /// read or carries no icon resources.
    pub(crate) fn extract_all_guest_icons(&self, guest_path: &str) -> Vec<crate::icon::IconImage> {
        let Ok(host_path) = self.win32.guest_path_to_host_path(guest_path) else {
            return Vec::new();
        };
        let Ok(bytes) = fs::read(&host_path) else {
            return Vec::new();
        };
        crate::pe::extract_all_icons_from_pe(&bytes).unwrap_or_default()
    }

    /// PathMakeUniqueName: the template itself when it does not exist;
    /// otherwise the template with " (n)" inserted before the extension,
    /// choosing the first non-conflicting name through the guest
    /// filesystem layer.
    pub(crate) fn make_unique_guest_path(&self, template: &str) -> String {
        let exists = |path: &str| -> bool {
            self.win32
                .guest_path_to_host_path(path)
                .map(|host_path| host_path.exists())
                .unwrap_or(false)
        };
        if !exists(template) {
            return template.to_string();
        }
        let (stem, extension) = match template.rfind('.') {
            Some(dot) if dot > template.rfind('\\').unwrap_or(0) => {
                (&template[..dot], &template[dot..])
            }
            _ => (template, ""),
        };
        for counter in 1..1024 {
            let candidate = format!("{stem} ({counter}){extension}");
            if !exists(&candidate) {
                return candidate;
            }
        }
        template.to_string()
    }

    /// SHFileOperationW over the guest filesystem: FO_MOVE (1), FO_COPY
    /// (2), FO_DELETE (3), FO_RENAME (4) with the documented return
    /// codes.
    pub(crate) fn shell_file_operation(&self, function: u32, from: &str, to: &str) -> u32 {
        let result = (|| -> AppResult<()> {
            let from_host = self.win32.guest_path_to_host_path(from)?;
            let io_error = |operation: &str, error: &std::io::Error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("SHFileOperationW {operation} failed for {from}"),
                    error,
                )
            };
            match function {
                // FO_DELETE
                3 => {
                    if from_host.is_dir() {
                        fs::remove_dir_all(&from_host)
                            .map_err(|error| io_error("delete", &error))?;
                    } else if from_host.is_file() {
                        fs::remove_file(&from_host).map_err(|error| io_error("delete", &error))?;
                    } else {
                        return Err(AppError::new(
                            ReasonCode::RcFsNotFound,
                            format!("delete target missing: {from}"),
                        ));
                    }
                    Ok(())
                }
                // FO_MOVE
                1 => {
                    let to_host = self.win32.guest_path_to_host_path(to)?;
                    fs::rename(&from_host, &to_host).map_err(|error| io_error("move", &error))?;
                    Ok(())
                }
                // FO_COPY
                2 => {
                    let to_host = self.win32.guest_path_to_host_path(to)?;
                    fs::copy(&from_host, &to_host).map_err(|error| io_error("copy", &error))?;
                    Ok(())
                }
                // FO_RENAME
                4 => {
                    let to_host = self.win32.guest_path_to_host_path(to)?;
                    fs::rename(&from_host, &to_host).map_err(|error| io_error("rename", &error))?;
                    Ok(())
                }
                _ => Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("unsupported SHFileOperation function {function}"),
                )),
            }
        })();
        match result {
            Ok(()) => crate::advapi32::ERROR_SUCCESS,
            Err(error) => last_error_from_app_error(&error),
        }
    }

    pub(crate) fn alloc_utf16_environment_block(
        &mut self,
        memory: &mut MemoryImage,
        environment: &BTreeMap<String, String>,
    ) -> AppResult<u64> {
        let mut bytes = Vec::new();
        // Real Windows prepends hidden per-drive current-directory entries such
        // as `=C:=C:\Steam`; the first one names the process's current drive.
        let drive = self
            .current_directory
            .get(..2)
            .filter(|prefix| prefix.ends_with(':'))
            .unwrap_or("C:");
        for unit in format!("={drive}={}", self.current_directory).encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        for (key, value) in environment {
            for unit in format!("{key}={value}").encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&0_u16.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());

        let address = self.alloc_heap(memory, bytes.len().max(2), false)?;
        memory.map_bytes(address, &bytes);
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};

    #[test]
    fn non_pe_child_image_is_rejected_with_pe_parse_invalid_and_no_spawn() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "c3-launch", GeArch::X86, "win11-23h2")
                .expect("create game environment");
        std::fs::write(ge.drive_c().join("native.sh"), b"#!/bin/sh\nexit 0\n")
            .expect("write non-PE child");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);

        let environment = std::collections::BTreeMap::new();
        let error = runtime
            .launch_guest_child_process(
                "C:\\native.sh",
                "C:\\native.sh",
                &environment,
                "C:\\",
                false,
            )
            .expect_err("a non-PE child image must never be spawned");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(
            error.last_error(),
            crate::error::ERROR_BAD_EXE_FORMAT,
            "CreateProcess failure must surface ERROR_BAD_EXE_FORMAT (193)"
        );
    }
}
