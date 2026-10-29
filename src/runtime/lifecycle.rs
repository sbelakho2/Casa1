//! Process lifecycle, image loading, and top-level execution entry points.

use super::*;

pub fn synthetic_pid(dtm: bool) -> u32 {
    if dtm {
        SYNTHETIC_PID_DTM
    } else {
        std::process::id().saturating_add(10_000)
    }
}

pub fn is_pe_image(path: &Path) -> AppResult<bool> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    Ok(bytes.starts_with(b"MZ"))
}

/// Locate the `casa1-runner` binary on disk.
///
/// Search order:
/// 1. Same directory as the current executable (for installed / `cargo run`).
/// 2. Cargo target directory (for `cargo test` / `cargo build`).
/// 3. `PATH` environment variable.
pub fn find_casa1_runner_binary() -> AppResult<PathBuf> {
    // 1. Next to current executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        let candidate = exe_dir.join("casa1-runner");
        if candidate.exists() {
            return Ok(candidate);
        }
        // Also check for casa1-runner with .exe suffix (cross-compile scenarios)
        let candidate_exe = exe_dir.join("casa1-runner.exe");
        if candidate_exe.exists() {
            return Ok(candidate_exe);
        }
    }

    // 2. Cargo target directory (dev/test), honoring CARGO_TARGET_DIR.
    let target_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_MANIFEST_DIR").map(|dir| PathBuf::from(dir).join("target"))
        });
    if let Some(target_root) = target_root {
        for &profile in &["debug", "release"] {
            let candidate = target_root.join(profile).join("casa1-runner");
            if candidate.exists() {
                return Ok(candidate);
            }
            let candidate_exe = target_root.join(profile).join("casa1-runner.exe");
            if candidate_exe.exists() {
                return Ok(candidate_exe);
            }
        }
    }

    // 3. PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("casa1-runner");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(AppError::new(
        ReasonCode::RcRunnerSpawnFailed,
        "casa1-runner binary not found — ensure the project is built (cargo build)",
    ))
}

thread_local! {
    static ARM64_IMPORT_ERROR: std::cell::RefCell<Option<AppError>> =
        const { std::cell::RefCell::new(None) };
    static ARM64_GUEST_EXIT: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

impl PeHostRuntime {
    /// Run an ARM64EC image whose entry point is x64 code.  The x64 machine is
    /// started at `entry` and every branch into a natively-classified EC
    /// function is routed through the entry-thunk conversion.
    pub(crate) fn run_ec_x64_entry(
        &mut self,
        runner: &mut crate::arm64::Arm64NativeRunner,
        checker: &crate::arm64::EcCallChecker,
        memory: &mut MemoryImage,
        entry: u64,
    ) -> AppResult<i32> {
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            &self.win32.ge().config.winver,
            env!("CARGO_PKG_VERSION"),
            None,
        )?;
        let mut engine = CpuExecutionEngine::new(config);
        let mut state = CpuState::new(GuestArch::X64);
        let stack_size = 0x10000usize;
        let stack_base = self.alloc_zeroed(memory, stack_size, 0x1000)?;
        let stack_top = stack_base + stack_size as u64;
        // Leave room above rsp for the x64 shadow-home area and stack
        // arguments; an entry thunk must not place rsp at the end of the
        // allocation.
        let rsp = ((stack_top.saturating_sub(0x400)) & !0xF) | 0x8;
        state.set(Register::Rsp, rsp);
        state.segment_bases.gs = self.teb_base;
        state.rip = entry;
        write_u64(memory, rsp, 0);
        self.run_ec_x64_machine(
            runner as *mut crate::arm64::Arm64NativeRunner,
            memory,
            &mut state,
            &mut engine,
            checker,
            "arm64ec-x64-entry",
        )?;
        Ok(state.get(Register::Rax) as u32 as i32)
    }

    /// Execute one x64 call reached from an ARM64EC exit thunk.  The x64
    /// return address is the synthetic zero at `[rsp]`, so `ret` terminates
    /// the nested machine exactly at the transition boundary.
    pub(crate) fn run_ec_x64_transition(
        &mut self,
        runner_ptr: *mut crate::arm64::Arm64NativeRunner,
        memory: &mut MemoryImage,
        request: &crate::arm64::EcExitRequest,
        checker: &crate::arm64::EcCallChecker,
    ) -> AppResult<crate::arm64::EcExitResponse> {
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            &self.win32.ge().config.winver,
            env!("CARGO_PKG_VERSION"),
            None,
        )?;
        let mut engine = CpuExecutionEngine::new(config);
        let mut state = CpuState::new(GuestArch::X64);
        state.gpr = request.args.gpr;
        for (index, value) in request.args.vec.iter().copied().enumerate() {
            state.xmm[index] = crate::cpu::XmmValue {
                low: value as u64,
                high: (value >> 64) as u64,
            };
        }
        for (x64_index, _) in crate::arm64::EC_NONVOLATILE_GPR_PAIRS {
            state.gpr[x64_index] = request.nonvolatile.gpr[x64_index];
        }
        for index in crate::arm64::EC_NONVOLATILE_VECTOR_INDICES {
            state.xmm[index] = crate::cpu::XmmValue {
                low: request.nonvolatile.xmm[index] as u64,
                high: (request.nonvolatile.xmm[index] >> 64) as u64,
            };
        }
        state.segment_bases.gs = if request.teb != 0 {
            request.teb
        } else {
            self.teb_base
        };
        let stack_size = 0x1000usize + request.args.stack.len() * 8;
        let stack_base = self.alloc_zeroed(memory, stack_size, 0x1000)?;
        let stack_top = stack_base + stack_size as u64;
        let headroom = 0x400 + request.args.stack.len() as u64 * 8;
        let rsp = ((stack_top.saturating_sub(headroom)) & !0xF) | 0x8;
        state.set(Register::Rsp, rsp);
        write_u64(memory, rsp, 0);
        for (index, value) in request.args.stack.iter().copied().enumerate() {
            write_u64(memory, rsp + 0x28 + index as u64 * 8, value);
        }
        state.rip = request.target;
        self.run_ec_x64_machine(
            runner_ptr,
            memory,
            &mut state,
            &mut engine,
            checker,
            "arm64ec-x64-exit",
        )?;
        Ok(crate::arm64::EcExitResponse {
            rax: state.get(Register::Rax),
            rdx: state.get(Register::Rdx),
            xmm0: u128::from(state.xmm[0].low) | (u128::from(state.xmm[0].high) << 64),
            xmm1: u128::from(state.xmm[1].low) | (u128::from(state.xmm[1].high) << 64),
        })
    }

    pub(crate) fn run_ec_x64_machine(
        &mut self,
        runner_ptr: *mut crate::arm64::Arm64NativeRunner,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        engine: &mut CpuExecutionEngine,
        checker: &crate::arm64::EcCallChecker,
        label: &str,
    ) -> AppResult<()> {
        let mut steps = 0u64;
        let instruction_budget = self.current_instruction_budget()?;
        loop {
            if state.rip == 0 {
                return Ok(());
            }
            if RUN_DEADLINE_EXPIRED.load(std::sync::atomic::Ordering::Acquire) {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "ARM64EC hybrid x64 run exceeded the wall-clock deadline at {:#x}",
                        state.rip
                    ),
                ));
            }
            if let Some(result) = self.dispatch_import_if_present(state.rip, state, memory)? {
                if let Some(code) = result {
                    ARM64_GUEST_EXIT.with(|slot| slot.set(Some(code)));
                    state.rip = 0;
                }
                continue;
            }
            if let Some(kind) = checker.classify(state.rip)
                && kind.is_native()
            {
                let rva = (state.rip - checker.image_base) as u32;
                let x64 = crate::arm64::X64AbiState::from_cpu_state(state);
                let outcome = crate::arm64::enter_ec_from_x64_native(
                    // SAFETY: synchronous nested execution from the same
                    // thread; the runner outlives the generated thunk call.
                    unsafe { &mut *runner_ptr },
                    &crate::arm64::EcSignature::class_parallel(),
                    &x64,
                    memory,
                    rva,
                )?;
                let mut next = x64;
                next.gpr[Register::Rax.index()] = outcome.result.rax;
                next.gpr[Register::Rdx.index()] = outcome.result.rdx;
                next.gpr[Register::Rsp.index()] = x64.gpr[Register::Rsp.index()] + 8;
                next.xmm[0] = outcome.result.xmm0;
                next.rip = outcome.return_address;
                crate::arm64::copy_ec_nonvolatile_to_x64(&outcome.state, &mut next);
                next.write_to_cpu_state(state);
                continue;
            }
            let mut instructions = Vec::new();
            let mut window = [0u8; 15];
            let mut available = 0usize;
            for offset in 0..window.len() {
                match memory.read_u8(state.rip + offset as u64) {
                    Ok(byte) => {
                        window[offset] = byte;
                        available = offset + 1;
                    }
                    Err(_) => break,
                }
            }
            if available == 0 {
                return Err(MemoryImage::unmapped_memory_error(state.rip));
            }
            let decoded = engine.decode_block(&window[..available], state.rip)?;
            for instruction in decoded {
                let control = instruction_controls_rip(instruction.opcode)
                    || instruction.opcode == DecodedOpcode::Ret;
                instructions.push(instruction);
                if control {
                    break;
                }
            }
            let executed = instructions.len() as u64;
            let ir = crate::cpu::lower_to_ir(&instructions)?;
            self.execute_ir_with_guest_exception_delivery(engine, state, memory, &ir, label)?;
            advance_runtime_steps(
                self,
                &mut steps,
                instruction_budget,
                executed,
                memory,
                state,
                label,
            )?;
        }
    }
}

pub(crate) fn arm64_dispatch_runtime_import(
    runtime_ptr: *mut PeHostRuntime,
    memory_ptr: *mut MemoryImage,
    scratch: u64,
    thunk: u64,
    call: &crate::arm64::EcImportCall,
) -> crate::arm64::EcImportResult {
    // SAFETY: the native ARM64 image is fully synchronous; the runtime and
    // memory outlive the call and no other borrow is active while the guest
    // thread executes.
    eprintln!(
        "[arm64-dispatch] enter thunk={thunk:#x} abi={:?} gpr={:?} vec={:?}",
        call.abi, call.registers.gpr, call.registers.vec
    );
    let runtime = unsafe { &mut *runtime_ptr };
    let memory = unsafe { &mut *memory_ptr };
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, scratch);
    state.rip = 0;
    write_u64(memory, scratch, 0);
    let mut stack_arguments = Vec::new();
    match call.abi {
        crate::arm64::EcImportAbi::ClassParallel => {
            for (destination, source) in [
                (Register::Rcx, 0usize),
                (Register::Rdx, 1),
                (Register::R8, 2),
                (Register::R9, 3),
            ] {
                state.set(destination, call.registers.gpr[source]);
            }
            for (index, value) in call.registers.vec.iter().copied().take(4).enumerate() {
                state.xmm[index] = crate::cpu::XmmValue {
                    low: value as u64,
                    high: (value >> 64) as u64,
                };
            }
            stack_arguments.extend(call.registers.gpr[4..8].iter().copied());
            for value in call.registers.vec[4..8].iter().copied() {
                if value != 0 {
                    stack_arguments.push(value as u64);
                }
            }
        }
        crate::arm64::EcImportAbi::Variadic => {
            // ARM64EC variadic passes every register argument in x0-x3.
            // x64 variadic duplicates floating-point values into the
            // corresponding XMM register, so publish both classes.
            for (destination, source) in [
                (Register::Rcx, 0usize),
                (Register::Rdx, 1),
                (Register::R8, 2),
                (Register::R9, 3),
            ] {
                state.set(destination, call.registers.gpr[source]);
                state.xmm[source] = crate::cpu::XmmValue {
                    low: call.registers.gpr[source],
                    high: 0,
                };
            }
            stack_arguments.extend(call.variadic_stack.iter().copied());
        }
    }
    for (index, value) in stack_arguments.iter().copied().enumerate() {
        write_u64(memory, scratch + 0x28 + (index as u64 * 8), value);
    }
    let dispatched = runtime.dispatch_import(thunk, &mut state, memory);
    eprintln!(
        "[arm64-dispatch] dispatched={:?} rax={:#x}",
        dispatched.as_ref().map(|v| *v),
        state.get(Register::Rax)
    );
    match dispatched {
        Ok(Some(code)) => {
            ARM64_GUEST_EXIT.with(|slot| slot.set(Some(code)));
        }
        Ok(None) => {}
        Err(error) => {
            ARM64_IMPORT_ERROR.with(|slot| {
                *slot.borrow_mut() = Some(error);
            });
            return crate::arm64::EcImportResult {
                rax: u64::MAX,
                ..crate::arm64::EcImportResult::default()
            };
        }
    }
    crate::arm64::EcImportResult {
        rax: state.get(Register::Rax),
        rdx: state.get(Register::Rdx),
        xmm0: u128::from(state.xmm[0].low) | (u128::from(state.xmm[0].high) << 64),
        xmm1: u128::from(state.xmm[1].low) | (u128::from(state.xmm[1].high) << 64),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_native_arm64_image(
    program: &Path,
    args: &[String],
    ge: &GameEnvironment,
    image: &pe::ParsedPe,
    bytes: &[u8],
    env: &BTreeMap<String, String>,
    dtm: bool,
    _test_id: &str,
    options: PeExecutionOptions,
) -> AppResult<PeExecutionResult> {
    if !crate::arm64::native_arm64_available() {
        return Err(AppError::new(
            ReasonCode::RcUnsupportedPlatform,
            "native ARM64 image execution requires an aarch64 host",
        ));
    }
    ARM64_IMPORT_ERROR.with(|slot| *slot.borrow_mut() = None);
    ARM64_GUEST_EXIT.with(|slot| slot.set(None));
    let mut runner = crate::arm64::Arm64NativeRunner::load(bytes, image)?;
    let checker = crate::arm64::EcCallChecker::for_loaded_image(image, runner.image.base)?;
    let selected_base = runner.image.base;
    let mut runtime = PeHostRuntime::new(
        ge.clone(),
        dtm,
        load_keyboard_replay(env)?,
        options.live_session,
        load_trace_categories(env),
    );
    runtime.set_guest_arch(GuestArch::X64);
    runtime.process_environment = env.clone();
    for observer in options.observers {
        runtime.add_observer(observer);
    }
    let mut memory = MemoryImage::default();
    memory.set_vm(runtime.win32.address_space_mut());
    memory.map_bytes(selected_base, &runner.image.mapped.memory);
    runtime.win32.address_space_mut().register(
        selected_base,
        image.size_of_image as u64,
        crate::vm::VmRegionKind::Image,
    );
    runtime.win32.address_space_mut().commit(
        selected_base,
        image.size_of_image as u64,
        crate::vm::VmProtection::READ_WRITE_EXECUTE,
        false,
    );
    let guest_path = program.to_string_lossy().to_string();
    let tls_rvas: Vec<u64> = image
        .tls_directory
        .as_ref()
        .map(|tls| {
            tls.callbacks
                .iter()
                .map(|&va| va.wrapping_sub(image.image_base))
                .collect()
        })
        .unwrap_or_default();
    runtime.set_main_module(&guest_path, selected_base, &image.exports, &tls_rvas);
    runtime.seed_process_state(
        &mut memory,
        &guest_path,
        args,
        selected_base,
        image.size_of_image as u64,
    )?;
    let resolver = ApiSetResolver::new();
    let imports = resolve_imports_for_runtime(image, &resolver);
    let scratch = runtime.alloc_zeroed(&mut memory, 0x100, 16)?;
    let runtime_ptr = &mut runtime as *mut PeHostRuntime;
    let memory_ptr = &mut memory as *mut MemoryImage;
    // Native ARM64EC call checkers and exit thunks are generated once and
    // installed into the image's import slots / CHPE helper pointers.
    let check_thunk = runner
        .image
        .alloc_thunk(&crate::arm64::build_ec_check_thunk())?;
    let exit_dispatch_thunk = runner
        .image
        .alloc_thunk(&crate::arm64::build_ec_exit_thunk(None, 0))?;
    crate::arm64::set_call_checker(checker.clone());
    let runner_ptr = &mut runner as *mut crate::arm64::Arm64NativeRunner;
    let hook_checker = checker.clone();
    crate::arm64::set_exit_hook(move |request| {
        // SAFETY: native ARM64EC execution is synchronous; the runtime,
        // memory and runner outlive the exit thunk call and no other borrow
        // of them is active while the hook runs.
        let runtime = unsafe { &mut *runtime_ptr };
        let memory = unsafe { &mut *memory_ptr };
        runtime.run_ec_x64_transition(runner_ptr, memory, request, &hook_checker)
    });
    for (import_index, import) in imports.iter().enumerate() {
        let thunk = HostThunk::from_import(import);
        let thunk_address = runtime.alloc_host_thunk(thunk);
        let key = match &import.symbol {
            ImportSymbol::ByName { name, .. } => {
                format!("{}.{}", import.requested_module, name)
            }
            ImportSymbol::ByOrdinal { ordinal } => {
                format!(
                    "{}.{}",
                    import.requested_module,
                    ordinal_import_name(&import.resolved_module, *ordinal).unwrap_or("")
                )
            }
        };
        let import_abi = crate::arm64::EcImportAbi::for_import_name(&key);
        let arm64_thunk = runner
            .imports
            .register_abi(key.clone(), import_abi, move |call| {
                arm64_dispatch_runtime_import(runtime_ptr, memory_ptr, scratch, thunk_address, call)
            })?;
        let lowered_key = key.to_ascii_lowercase();
        let slot_thunk = if lowered_key.contains("__os_arm64x_check_icall") {
            check_thunk
        } else if lowered_key.contains("__os_arm64x_dispatch_call")
            || lowered_key.contains("__os_arm64x_dispatch_icall")
            || lowered_key.contains("__os_arm64x_x64_jump")
            || lowered_key.contains("__os_arm64x_dispatch_ret")
        {
            exit_dispatch_thunk
        } else {
            arm64_thunk
        };
        runner.image.write_slot(import.iat_rva, slot_thunk)?;
        if let Some(chpe) = image.chpe_metadata() {
            for auxiliary in [
                chpe.auxiliary_iat_rva,
                chpe.auxiliary_iat_copy_rva,
                chpe.auxiliary_delayload_iat_rva,
                chpe.auxiliary_delayload_iat_copy_rva,
            ] {
                if auxiliary != 0 {
                    let slot = auxiliary
                        .checked_add((import_index as u32).checked_mul(8).ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcPeParseInvalid,
                                "ARM64EC auxiliary IAT offset overflow",
                            )
                        })?)
                        .ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcPeParseInvalid,
                                "ARM64EC auxiliary IAT RVA overflow",
                            )
                        })?;
                    runner.image.write_slot(slot, slot_thunk)?;
                }
            }
        }
    }
    let direct_patches = runner.image.patch_cross_isa_direct_calls(image, &checker)?;
    if direct_patches != 0 {
        crate::live::live_trace(&format!(
            "[arm64-runtime] patched {direct_patches} direct x64 call(s) to exit thunks"
        ));
    }
    runner.image.protect()?;
    for callback in &tls_rvas {
        let callback_rva = u32::try_from(*callback).map_err(|_| {
            AppError::new(
                ReasonCode::RcPeParseInvalid,
                "ARM64 TLS callback RVA does not fit in 32 bits",
            )
        })?;
        runner.call_rva(callback_rva, &[selected_base, 1, 0])?;
        if let Some(error) = ARM64_IMPORT_ERROR.with(|slot| slot.borrow_mut().take()) {
            return Err(error);
        }
    }
    eprintln!(
        "[arm64-runtime] iat={:02x?}",
        &runner.image.bytes()[0x2060..0x2068]
    );
    let entry_rva = crate::arm64x::route_entry_point(image, crate::arm64x::HybridView::Native)?;
    let start_time = std::time::Instant::now();
    eprintln!(
        "[arm64-runtime] entry={entry_rva:#x} code={:02x?}",
        &runner.image.bytes()[0x1000..0x1020]
    );
    let entry_address = selected_base + u64::from(entry_rva);
    let mut exit_code = match checker.classify(entry_address) {
        Some(kind) if kind.is_x64() => {
            runtime.run_ec_x64_entry(&mut runner, &checker, &mut memory, entry_address)?
        }
        _ => {
            let result = runner.call_entry(image, &[])?;
            result.return_value() as u32 as i32
        }
    };
    if let Some(error) = crate::arm64::take_exit_error() {
        return Err(error.to_app_error());
    }
    if let Some(error) = crate::arm64::take_call_checker_error() {
        return Err(error.to_app_error());
    }
    if let Some(error) = crate::arm64::take_vector_import_error() {
        return Err(error.to_app_error());
    }
    if let Some(error) = ARM64_IMPORT_ERROR.with(|slot| slot.borrow_mut().take()) {
        return Err(error);
    }
    if let Some(code) = ARM64_GUEST_EXIT.with(|slot| slot.take()) {
        exit_code = code;
    }
    let image_hash = util::sha256_bytes(bytes);
    finalize_execution(
        runtime,
        &mut memory,
        image,
        &runner.image.mapped,
        env,
        dtm,
        image_hash,
        0,
        0,
        start_time,
        exit_code,
        ExecutionTermination::GuestExit { code: exit_code },
        None,
    )
}

pub fn execute(
    program: &Path,
    args: &[String],
    ge: &GameEnvironment,
    _cwd: &Path,
    env: &BTreeMap<String, String>,
    dtm: bool,
    test_id: &str,
) -> AppResult<PeExecutionResult> {
    execute_with_options(
        program,
        args,
        ge,
        _cwd,
        env,
        dtm,
        test_id,
        PeExecutionOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_with_options(
    program: &Path,
    args: &[String],
    ge: &GameEnvironment,
    _cwd: &Path,
    env: &BTreeMap<String, String>,
    dtm: bool,
    test_id: &str,
    options: PeExecutionOptions,
) -> AppResult<PeExecutionResult> {
    // ── Entry trace ─────────────────────────────────────────────────────────
    crate::live::live_trace("[pe] execute_with_options ENTERED");
    // Steam run instrumentation (no behavior change): every run starts from a
    // clean milestone slate — the shared static, the last-thunk recorder, the
    // run-start marker and the per-run counters — so evidence from a previous
    // run in this process can never leak into the new run's artifact.
    crate::steam_milestones::reset_milestones();
    crate::steam_milestones::mark_run_start();
    // The deadline flag is a process-wide static: it MUST be reset per run,
    // or a previous run's expired deadline instantly ends the next one
    // (observed: a stale deadline ended a fresh run at iteration 0).
    RUN_DEADLINE_EXPIRED.store(false, std::sync::atomic::Ordering::Release);
    // ── Diagnostic markers (DISABLED: file I/O was too slow) ─────────────────
    // Was writing to /tmp/casa1_diag.txt but file open/write/flush/close on
    // every call throttled execution to ~10 iterations/second.  All diag()
    // calls now compile away to nothing.  Use eprintln!/stderr for lightweight
    // progress tracking below.
    let diag = |_: &str| {};
    // ── OOM alloc error hook ─────────────────────────────────────────────────
    // Install a custom panic hook that captures OOM panics with allocation size.
    // This ensures out-of-memory conditions during guest execution are surfaced
    // as descriptive panics rather than aborting the process silently.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-str panic>".to_string());
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("[OOM/panic] {msg} at {location}");
        // Call the previous hook so the default abort/stderr behavior is preserved.
        prev_hook(info);
    }));

    let bytes = fs::read(program).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", program.display()),
            &error,
        )
    })?;
    let image = pe::parse_from_file(program)?;
    let guest_arch = match image.machine {
        0x8664 => GuestArch::X64,
        0x014c => GuestArch::X86,
        crate::pe::IMAGE_FILE_MACHINE_ARM64
        | crate::pe::IMAGE_FILE_MACHINE_ARM64EC
        | crate::pe::IMAGE_FILE_MACHINE_ARM64X => {
            return execute_native_arm64_image(
                program, args, ge, &image, &bytes, env, dtm, test_id, options,
            );
        }
        _ => {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!("unsupported PE machine 0x{:04x}", image.machine),
            )
            .with_hint("supported machines are x86, x86_64, ARM64, ARM64EC and ARM64X"));
        }
    };

    // A managed (.NET) image carries a CLI header (data directory 14).  Run
    // it on the real CoreCLR host installed on this machine instead of
    // executing IL bytes as native code.
    if image
        .data_directories
        .get(14)
        .is_some_and(|directory| directory.virtual_address != 0 && directory.size != 0)
    {
        return execute_managed_image(program, args, env, dtm);
    }

    let mut runtime = PeHostRuntime::new(
        ge.clone(),
        dtm,
        load_keyboard_replay(env)?,
        options.live_session,
        load_trace_categories(env),
    );
    runtime.jit_mode = options.jit_mode.unwrap_or(crate::runner::JitMode::Auto);
    if let Some(workers) = options.scheduler_workers
        && !runtime.set_scheduler_mode(SchedulerMode::Production {
            workers: workers.max(1),
        })
    {
        return Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            "cannot select the concurrent scheduler while guest waits are parked",
        ));
    }
    runtime.set_guest_arch(guest_arch);
    runtime.process_environment = env.clone();
    for observer in options.observers {
        runtime.add_observer(observer);
    }
    // Generic named-pipe compat listeners requested by the workload (e.g.
    // the Steam workload pre-creates the `steam_service` pipe so a guest
    // Steam client finds a live listener without SteamService.exe running).
    // The Steam-specific part of that wiring lives in the workload module;
    // the runtime only honors the generic request.
    for pipe_name in &options.compat_named_pipes {
        runtime
            .win32
            .named_pipe_service()
            .create_compat_listener(pipe_name)?;
    }
    let staged_program_path = runtime.stage_main_module(program)?;
    runtime.current_directory =
        initial_guest_current_directory(runtime.win32.ge(), _cwd, &staged_program_path);

    let resolver = ApiSetResolver::new();
    let resolved_imports = resolve_imports_for_runtime(&image, &resolver);
    let image_hash = util::sha256_bytes(&bytes);
    let mapped = pe::map_image(&bytes, &image, &image_hash, dtm)?;
    let mut memory = MemoryImage::default();
    // Attach the canonical VM: every guest access is now validated by the
    // VM layer FIRST (the raw page map only supplies the bytes), so the
    // interpreter, the JIT helpers and the VirtualAlloc-family thunks share
    // ONE authoritative view of reservations / commits / protection.
    memory.set_vm(runtime.win32.address_space_mut());
    memory.map_bytes(mapped.selected_base, &mapped.memory);
    // Canonical VM: the loader-mapped main image is an Image region.
    runtime.win32.address_space_mut().register(
        mapped.selected_base,
        image.size_of_image as u64,
        crate::vm::VmRegionKind::Image,
    );
    runtime.win32.address_space_mut().commit(
        mapped.selected_base,
        image.size_of_image as u64,
        crate::vm::VmProtection::READ_WRITE_EXECUTE,
        false,
    );
    // Extract main image TLS callback RVAs for storage in DllInfo.
    let main_tls_callbacks_rva: Vec<u64> = image
        .tls_directory
        .as_ref()
        .map(|tls| {
            tls.callbacks
                .iter()
                .map(|&va| va.wrapping_sub(image.image_base))
                .collect()
        })
        .unwrap_or_default();
    runtime.set_main_module(
        &staged_program_path,
        mapped.selected_base,
        &image.exports,
        &main_tls_callbacks_rva,
    );
    // Generic runtime event (no behavior change): the main image is mapped.
    runtime.emit_event(crate::runtime_events::RuntimeEvent::ImageLoaded {
        module: module_file_name(&staged_program_path).to_string(),
        base: mapped.selected_base,
        size: image.size_of_image as usize,
    });
    let start_time = std::time::Instant::now();
    runtime.seed_process_state(
        &mut memory,
        &staged_program_path,
        args,
        mapped.selected_base,
        image.size_of_image as u64,
    )?;
    runtime.initialize_security_cookie(&mut memory, &image, mapped.selected_base)?;
    runtime.initialize_main_thread_tls(&mut memory, &image, mapped.selected_base)?;
    diag("2:imports bound");

    // ── Phase M1: Attempt bound import resolution ──────────────────────────
    // Bound imports are a PE optimization where the linker pre-computes IAT
    // addresses. Our emulator always falls back to normal resolution since we
    // use synthesized host thunks, but we attempt it for structural correctness.
    let bound_ok = runtime.try_use_bound_imports(&image, mapped.selected_base, &mut memory)?;
    if !bound_ok {
        runtime.bind_imports(mapped.selected_base, &mut memory, &resolved_imports)?;
    }
    runtime.record_iat_bindings(mapped.selected_base, &mut memory, &resolved_imports);
    let _ = std::fs::write("/tmp/casa1_diag.txt", "2:imports bound\n");

    // ── Phase M2: Bind delay-load import thunks for lazy resolution ──────────
    // Each delay-load import slot gets a `DelayLoadResolve` thunk that patches
    // the IAT on first call and forwards to the resolved address.
    let delay_thunks = resolve_delay_imports_for_runtime(&image, &resolver, mapped.selected_base);
    for thunk in &delay_thunks {
        if let HostThunk::DelayLoadResolve {
            iat_rva,
            selected_base,
            ..
        } = thunk
        {
            let thunk_address = runtime.alloc_host_thunk(thunk.clone());
            let slot_va = selected_base + u64::from(*iat_rva);
            write_guest_pointer(&mut memory, slot_va, thunk_address, guest_arch)?;
        }
    }

    // ── Register .pdata exception tables with the SEH subsystem ──────────────
    if guest_arch == GuestArch::X64 {
        // Extract .pdata section bytes (runtime function entries)
        let mut pdata_bytes: &[u8] = &[];
        if let Some(pdata_section) = image.sections.iter().find(|s| {
            let name = s.name.trim_end_matches('\u{0000}');
            name == ".pdata"
        }) {
            let start = pdata_section.virtual_address as usize;
            let end = (pdata_section.virtual_address + pdata_section.virtual_size) as usize;
            if end <= mapped.memory.len() {
                pdata_bytes = &mapped.memory[start..end];
            }
        }
        // Register the full mapped image as unwind data so that any
        // UNWIND_INFO structure (typically in .rdata or .xdata) can be found
        // by RVA during lazy parsing.
        if !pdata_bytes.is_empty() {
            runtime.register_seh_exception_data(mapped.selected_base, pdata_bytes, &mapped.memory);
        }
    }

    // ── Phase M4: Side-by-side Assembly (SxS) Isolation ────────────────────
    // Check for .local DLL redirection (a `<module>.local` file next to the
    // executable forces all DLL loads to search the application directory first).
    runtime.check_local_redirection(program);

    // Detect comctl32 version 6 (Common Controls v6) activation request from
    // the main module's manifest. If the manifest requests
    // `Microsoft.Windows.Common-Controls` version 6.0.0.0, we set up an
    // activation context so that the guest sees the modern common controls.
    if let Some(ref manifest) = image.embedded_manifest {
        for asm in &manifest.assemblies {
            if asm.name == "Microsoft.Windows.Common-Controls"
                && asm.version.as_deref() == Some("6.0.0.0")
            {
                runtime.comctl32_v6_active = true;
                // Also register an initial activation context for the main module
                let handle = runtime.next_activation_context_handle;
                runtime.next_activation_context_handle =
                    runtime.next_activation_context_handle.wrapping_add(1);
                let ctx = crate::pe::ActivationContext {
                    handle,
                    cookie: 0,
                    source: staged_program_path.clone(),
                    assembly_directory: None,
                    manifest_info: Some(manifest.clone()),
                };
                runtime.activation_contexts.insert(handle, ctx);
                eprintln!(
                    "[pe_runtime] SxS: comctl32 v6 active via embedded manifest (ctx handle={handle:#x})"
                );
                break;
            }
        }
    }
    // Also check the external manifest for comctl32 v6
    if !runtime.comctl32_v6_active
        && let Some(ref external_manifest) = image.external_manifest
    {
        for asm in &external_manifest.assemblies {
            if asm.name == "Microsoft.Windows.Common-Controls"
                && asm.version.as_deref() == Some("6.0.0.0")
            {
                runtime.comctl32_v6_active = true;
                let handle = runtime.next_activation_context_handle;
                runtime.next_activation_context_handle =
                    runtime.next_activation_context_handle.wrapping_add(1);
                let ctx = crate::pe::ActivationContext {
                    handle,
                    cookie: 0,
                    source: staged_program_path.clone(),
                    assembly_directory: None,
                    manifest_info: Some(external_manifest.clone()),
                };
                runtime.activation_contexts.insert(handle, ctx);
                eprintln!(
                    "[pe_runtime] SxS: comctl32 v6 active via external manifest (ctx handle={handle:#x})"
                );
                break;
            }
        }
    }

    // Parse Steam command-line flags if running Steam.exe.
    if staged_program_path.contains("Steam.exe") || staged_program_path.contains("steam.exe") {
        let steam_flags = process_steam_command_line(args);
        if steam_flags.has_launch_command() {
            emit_live_ui_debug(format!(
                "SteamCliFlags: -applaunch {} args={:?}",
                steam_flags.launch_app_id().unwrap_or(0),
                steam_flags.applaunch_args,
            ));
        }
        if steam_flags.silent {
            emit_live_ui_debug("SteamCliFlags: -silent (minimized to tray)".to_string());
        }
        if steam_flags.no_browser {
            emit_live_ui_debug("SteamCliFlags: -no-browser".to_string());
        }
        if steam_flags.offline {
            emit_live_ui_debug("SteamCliFlags: -offline".to_string());
        }
        if steam_flags.dev {
            emit_live_ui_debug("SteamCliFlags: -dev (developer mode)".to_string());
        }
        if steam_flags.console {
            emit_live_ui_debug("SteamCliFlags: -console".to_string());
        }
        if steam_flags.big_picture {
            emit_live_ui_debug("SteamCliFlags: -bigpicture".to_string());
        }
        runtime.push_trace(
            "process",
            "SteamCliFlags",
            BTreeMap::from([
                ("applaunch".to_string(), json!(steam_flags.applaunch)),
                (
                    "applaunch_args".to_string(),
                    json!(steam_flags.applaunch_args),
                ),
                ("silent".to_string(), json!(steam_flags.silent)),
                ("no_browser".to_string(), json!(steam_flags.no_browser)),
                ("offline".to_string(), json!(steam_flags.offline)),
                ("dev".to_string(), json!(steam_flags.dev)),
                ("console".to_string(), json!(steam_flags.console)),
                ("big_picture".to_string(), json!(steam_flags.big_picture)),
            ]),
            json!(steam_flags.applaunch),
        );

        // Check for steam:// protocol URLs in the arguments.
        if has_steam_protocol_url(args) {
            let urls: Vec<String> = extract_steam_protocol_urls(args);
            for url in &urls {
                emit_live_ui_debug(format!("SteamProtocolURL: {url}"));
            }
            runtime.push_trace(
                "process",
                "SteamProtocolURLs",
                BTreeMap::from([("urls".to_string(), json!(urls))]),
                json!(urls.len()),
            );
        }
    }

    // Probe Steam.exe startup globals before execution begins.
    // These four globals control the main startup state machine:
    //   0x45715c — startup state (0 = not initialised)
    //   0x457620 — termination flag
    //   0x457624 — global array element count
    //   0x457628 — global array base pointer
    // A zero `startup_state` or `array_count` after imports are bound indicates
    // that a prior initialisation API (registry, file I/O, …) returned an
    // unexpected value and the record table at 0x42a270 will be empty, causing
    // the crash at RVA 0x401389.
    if guest_arch == GuestArch::X86 && staged_program_path.ends_with("Steam.exe") {
        let startup_state = probe_read_guest_u32(&memory, mapped.selected_base + 0x0045_715c);
        let term_flag = probe_read_guest_u32(&memory, mapped.selected_base + 0x0045_7620);
        let array_count = probe_read_guest_u32(&memory, mapped.selected_base + 0x0045_7624);
        let array_ptr = probe_read_guest_u32(&memory, mapped.selected_base + 0x0045_7628);
        runtime.push_trace(
            "process",
            "SteamInitialGlobals",
            BTreeMap::from([
                (
                    "startup_state".to_string(),
                    json!(startup_state.map(|v| format!("{v:#x}"))),
                ),
                (
                    "term_flag".to_string(),
                    json!(term_flag.map(|v| format!("{v:#x}"))),
                ),
                (
                    "array_count".to_string(),
                    json!(array_count.map(|v| format!("{v:#x}"))),
                ),
                (
                    "array_ptr".to_string(),
                    json!(array_ptr.map(|v| format!("{v:#x}"))),
                ),
            ]),
            json!(array_count.unwrap_or(0)),
        );
    }

    let config = CpuEngineConfig::from_profile(
        guest_arch,
        &ge.config.winver,
        env!("CARGO_PKG_VERSION"),
        None,
    )?;
    let mut engine = CpuExecutionEngine::new(config);
    let instruction_budget = runtime.current_instruction_budget()?;
    let run_deadline = std::env::var(PE_RUNTIME_DEADLINE_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(|secs| std::time::Instant::now() + std::time::Duration::from_secs(secs));
    // Deadline watchdog: independent of the main loop, so a run stuck
    // inside nested thunk/callback execution still terminates.
    if let Some(deadline) = run_deadline {
        std::thread::spawn(move || {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            std::thread::sleep(remaining);
            expire_run_deadline();
        });
    }
    let mut state = CpuState::new(guest_arch);
    let guest_pointer_bytes = guest_arch.pointer_bytes() as u64;
    let stack_bottom = stack_base_for_arch(guest_arch);
    memory.map_bytes(stack_bottom, &vec![0_u8; STACK_SIZE]);
    // Canonical VM: the main-thread stack is a Stack region, fully
    // committed.  The pages below the base belong to no region, so a stack
    // overflow faults through the canonical layer exactly as before (the
    // region boundary is the stack guard).
    runtime.win32.address_space_mut().register(
        stack_bottom,
        STACK_SIZE as u64,
        crate::vm::VmRegionKind::Stack,
    );
    runtime.win32.address_space_mut().commit(
        stack_bottom,
        STACK_SIZE as u64,
        crate::vm::VmProtection::READ_WRITE,
        false,
    );
    let stack_top = stack_bottom + STACK_SIZE as u64;
    let rsp = stack_top - guest_pointer_bytes;
    write_guest_pointer(&mut memory, rsp, 0, guest_arch)?;
    state.set(Register::Rsp, rsp);
    if guest_arch == GuestArch::X64 {
        state.segment_bases.gs = runtime.teb_base;
    } else {
        state.segment_bases.fs = runtime.teb_base;
    }
    runtime.execute_main_image_tls_process_attach_callbacks(
        &mut state,
        &mut memory,
        &image,
        mapped.selected_base,
    )?;
    state.rip = mapped.selected_base + image.address_of_entry_point as u64;
    match runtime.precompile_image(&memory, state.rip) {
        Ok(Some(report)) => crate::live::live_trace(&format!(
            "[aot] precompiled {}/{} reachable blocks (skipped {}, out-of-range {})",
            report.compiled, report.blocks, report.skipped, report.out_of_range
        )),
        Ok(None) => {}
        Err(error) => crate::live::live_trace(&format!("[aot] precompile failed: {error}")),
    }
    // NtCreateThreadEx on a native child passes the FIRST thread's start
    // routine/parameter: the child's first thread genuinely begins at that
    // address, not at the image entry point.  The address is a guest VA in
    // the image's PREFERRED mapping (the caller never saw this process's
    // chosen base), so rebase it into this mapping; the thread parameter is
    // delivered through the thread-start ABI (x86: `[esp+4]`; x64: `rcx`).
    if let Some((start_address, start_parameter)) = options.thread_start {
        let preferred_image_end = image.image_base + image.size_of_image as u64;
        if !(image.image_base..preferred_image_end).contains(&start_address) {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "NtCreateThreadEx start routine {start_address:#x} is outside the child image \
                     ({:#x}..{preferred_image_end:#x})",
                    image.image_base
                ),
            ));
        }
        state.rip = mapped.selected_base + (start_address - image.image_base);
        if guest_arch == GuestArch::X64 {
            // x64 thread entry: the parameter arrives in RCX.  Leave the
            // shadow space and a zero return address under it so a routine
            // that returns ends at RIP=0 (the main-loop exit) like the
            // image entry point does.
            let rsp = stack_top - guest_pointer_bytes - 0x20;
            write_guest_pointer(&mut memory, rsp, 0, guest_arch)?;
            state.set(Register::Rsp, rsp);
            state.set(Register::Rcx, start_parameter);
        } else {
            // x86 stdcall thread entry: the parameter is at `[esp+4]` above
            // the synthetic return address.
            let rsp = stack_top - 2 * guest_pointer_bytes;
            write_guest_pointer(&mut memory, rsp, 0, guest_arch)?;
            write_guest_pointer(
                &mut memory,
                rsp + guest_pointer_bytes,
                start_parameter,
                guest_arch,
            )?;
            state.set(Register::Rsp, rsp);
        }
    }
    crate::live::live_trace(&format!(
        "[pe] before main loop — entry_rip={:#x} live_session={}",
        state.rip,
        runtime.live_session.is_some(),
    ));
    diag("3:before main loop");

    // The run body is a closure so every `?` error (instruction budget,
    // wall-clock deadline, unsupported instruction, guest fault, host
    // error) is CAUGHT here and finalized into a PeExecutionResult with a
    // structured ExecutionTermination — the runner never reconstructs a
    // synthetic result and never has to sniff error-message strings.
    let run_body = |runtime: &mut PeHostRuntime,
                    memory: &mut MemoryImage,
                    state: &mut CpuState,
                    engine: &mut CpuExecutionEngine,
                    instruction_budget: u64|
     -> AppResult<(i32, u64, u64)> {
        let mut exit_code = 0_i32;
        let mut steps = 0_u64;
        let mut block_count: u64 = 0;
        let mut thunk_count: u64 = 0;
        let mut last_progress_log = std::time::Instant::now();
        let mut last_safepoint = std::time::Instant::now();
        let mut last_rip_for_loop_detect = 0u64;
        let mut same_rip_consecutive_count = 0u32;
        // RIP seen two iterations ago, for detecting tight A↔B cycles.
        let mut two_rip_prev_rip: u64 = 0;
        // Count of consecutive A↔B alternations (resets on any other RIP).
        let mut two_rip_cycle_count: u32 = 0;
        crate::live::live_trace("[pe] entering main execution loop");

        // Register the JIT runtime so the live-session watchdog can
        // forcibly break JIT block chains across threads.
        if let Some(jit) = runtime.jit_runtime.as_mut() {
            crate::jit::register_jit_runtime(jit);
        }

        loop {
            block_count += 1;
            // Steam run instrumentation (no behavior change): the first block
            // dispatch marks bootstrap as started, with the guest context in
            // which the run's first block executed.
            crate::steam_milestones::note_bootstrap_started(runtime.milestone_evidence(
                state,
                "block dispatch",
                None,
                "first block dispatch of the PE main loop",
            ));
            // Generic runtime event (no behavior change): the first block
            // dispatch of ANY PE image is the process-first-instruction
            // marker.  The Steam workload observer derives
            // `process_first_instruction` from it, and a steamwebhelper
            // child PE derives its process-started evidence IMMEDIATELY at
            // FIRST block dispatch (never at child completion) — an
            // in-process child's start is already visible to the parent's
            // snapshot, and an out-of-process child runner's artifact
            // carries the evidence from the first dispatched block onward.
            // Guarded to the first dispatch: the marker must not repeat per
            // iteration.
            if block_count == 1 {
                runtime.emit_event(
                    crate::runtime_events::RuntimeEvent::ProcessFirstInstruction {
                        pid: runtime.win32.current_process_id(),
                        image: module_file_name(&runtime.main_module_path).to_string(),
                    },
                );
            }
            // ── Host-side block-dispatch safepoint ───────────────────────────
            // Every SAFEPOINT_INTERVAL_MS (2 ms) of wall-clock time, service the
            // guest scheduler between dispatched blocks: pump a pending guest
            // thread, drain timer callbacks, deliver APCs to the main thread,
            // poll due SetTimer timers, and advance the guest clock by the
            // measured wall elapsed.  The GUI scheduler requires this — an
            // order of magnitude faster than Steam's own 250 ms polls — so a
            // guest spin loop (which never reaches a wait site) cannot freeze
            // the clock or starve pending threads, timers, APCs and the live
            // frame pipeline.
            //
            // The safepoint must NOT run while a pumped guest thread is active
            // (nested execution): the pump services scheduling for the pumped
            // thread's own lifetime, and running the safepoint inside it would
            // recurse into another pump.
            //
            // The live watchdog's `JIT_CHAIN_BREAK_REQUESTED` path remains
            // intact as a fallback for when JIT block chains are re-enabled;
            // the old 50 ms main-loop chain-break timer is replaced by this
            // safepoint.
            if RUN_DEADLINE_EXPIRED.load(std::sync::atomic::Ordering::Acquire) {
                // Wall-clock run deadline (instrumentation): end the run with
                // exit code -2 so artifacts are produced even though Steam's
                // main loop never exits on its own.
                exit_code = -2;
                crate::live::live_trace("[pe] run deadline reached — ending run with exit -2");
                break;
            }

            if runtime.active_pumped_guest_thread.is_none()
                && last_safepoint.elapsed().as_millis() as u64 >= SAFEPOINT_INTERVAL_MS
            {
                // Measure the wall elapsed since the previous safepoint BEFORE
                // running the body so a pumped thread's execution time lands in
                // the NEXT interval (the pump advances the clock itself via the
                // guest's own wait/sleep APIs).
                let elapsed_ms = last_safepoint.elapsed().as_millis() as u64;
                last_safepoint = std::time::Instant::now();
                if let Some(code) =
                    runtime.run_block_dispatch_safepoint(state, memory, elapsed_ms)?
                {
                    // A pumped thread or timer callback requested process exit.
                    exit_code = code;
                    break;
                }
            }

            // Infinite loop detection: track consecutive same-RIP iterations.
            // Also catch tight 2-RIP cycles (A↔B) by treating the previous RIP as
            // part of the same spin window — many real busy-loops alternate
            // between exactly two addresses, which the strict same-RIP check
            // alone would never flag.
            let prev_rip_for_detect = last_rip_for_loop_detect;
            if state.rip == last_rip_for_loop_detect
                || (two_rip_cycle_count < u32::MAX && state.rip == two_rip_prev_rip)
            {
                same_rip_consecutive_count += 1;
                if state.rip == two_rip_prev_rip && state.rip != last_rip_for_loop_detect {
                    two_rip_cycle_count += 1;
                }
            } else {
                // Log transition when leaving a previously-same-RIP pattern
                if same_rip_consecutive_count >= 10 {
                    diag(&format!(
                        "LOOP_EXIT after {} same-rip iterations, new rip={:#x}",
                        same_rip_consecutive_count, state.rip
                    ));
                }
                two_rip_prev_rip = prev_rip_for_detect;
                last_rip_for_loop_detect = state.rip;
                same_rip_consecutive_count = 1;
                two_rip_cycle_count = 0;
                // Log first encounter of the infinite loop address
                if last_rip_for_loop_detect == runtime.mapped_image_base + 0x1714ea {
                    diag(&format!(
                        "ENTERED_INFINITE_LOOP_RIP iter={} rip={:#x} eax={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x}",
                        block_count,
                        state.rip,
                        state.get(Register::Rax),
                        state.get(Register::Rcx),
                        state.get(Register::Rdx),
                        state.get(Register::Rsi),
                        state.get(Register::Rdi)
                    ));
                }
            }
            if same_rip_consecutive_count >= 10 && same_rip_consecutive_count.is_multiple_of(5) {
                diag(&format!(
                    "SAME_RIP_WARN rip={:#x} consecutive={} eax={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x}",
                    state.rip,
                    same_rip_consecutive_count,
                    state.get(Register::Rax),
                    state.get(Register::Rcx),
                    state.get(Register::Rdx),
                    state.get(Register::Rsi),
                    state.get(Register::Rdi)
                ));
            }
            // Yield CPU when stuck in a tight spin loop (same RIP for 1000+
            // consecutive iterations).  This prevents 99% CPU usage when the
            // guest is polling a memory flag or waiting in a non-message API.
            // Use sleep(1ms) instead of yield_now() because on macOS
            // yield_now() is effectively a no-op — the thread immediately
            // resumes and CPU stays at 99%.
            // No per-iteration sleep.  The time-based yield (every 1s) handles
            // CPU backpressure.  Per-iteration sleeps of 1ms on tight loops
            // (memset, memcpy, heap init during CRT startup) would accumulate
            // to hundreds of milliseconds, making the emulator unusably slow.
            if same_rip_consecutive_count == 25 {
                let rva = if state.rip >= runtime.mapped_image_base
                    && state.rip < runtime.mapped_image_base + runtime.mapped_image_size
                {
                    format!("{:#x}", state.rip.saturating_sub(runtime.mapped_image_base))
                } else {
                    format!("<outside:{:#x}>", state.rip)
                };
                diag(&format!(
                    "INFINITE_LOOP_DETECTED rip={:#x} rva={} consecutive={} eax={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x} esp={:#x} ebp={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x}",
                    state.rip,
                    rva,
                    same_rip_consecutive_count,
                    state.get(Register::Rax),
                    state.get(Register::Rcx),
                    state.get(Register::Rdx),
                    state.get(Register::Rsi),
                    state.get(Register::Rdi),
                    state.get(Register::Rsp),
                    state.get(Register::Rbp),
                    state.get(Register::R8),
                    state.get(Register::R9),
                    state.get(Register::R10),
                    state.get(Register::R11)
                ));
                // Decode and log the block to understand the loop
                if let Ok(window) = read_window(memory, state.rip, 32) {
                    let hex: String = window
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    diag(&format!(
                        "INFINITE_LOOP_BYTES at rip={:#x}: {}",
                        state.rip, hex
                    ));
                }
            }
            // Progress via stderr — every 5 seconds
            if runtime.live_session.is_some() && last_progress_log.elapsed().as_secs() >= 5 {
                last_progress_log = std::time::Instant::now();
                let msg = format!(
                    "[pe] live blocks={} steps={} thunks={} elapsed_ms={}",
                    block_count,
                    steps,
                    thunk_count,
                    start_time.elapsed().as_millis()
                );
                let _ = std::fs::write("/tmp/casa1_progress.txt", &msg);
            }

            if let Some(result) = runtime.dispatch_import_if_present(state.rip, state, memory)? {
                thunk_count += 1;
                advance_runtime_steps(
                    runtime,
                    &mut steps,
                    instruction_budget,
                    1,
                    memory,
                    state,
                    test_id,
                )?;
                if let Some(code) = result {
                    exit_code = code;
                    break;
                }
                if runtime.main_thread_parked {
                    // A wait thunk parked the main thread in the scheduler wait
                    // queue: switch to pump-driven execution until the run ends.
                    // The parked thread resumes (and runs) inside the pump, so
                    // `state` here is stale and must not be used again.
                    exit_code = runtime.run_pump_driven(memory, &mut steps, instruction_budget)?;
                    break;
                }
                runtime.drain_pending_dll_main_calls(state, memory)?;
                continue;
            }

            let opcode = memory
                .read_u8(state.rip)
                .map_err(|error| annotate_guest_fault(error, memory, state))?;
            if opcode == 0xFF {
                match memory.read_u8(state.rip + 1)? {
                    0x15 | 0x25 => {
                        advance_runtime_steps(
                            runtime,
                            &mut steps,
                            instruction_budget,
                            1,
                            memory,
                            state,
                            test_id,
                        )?;
                        let next_rip = state.rip + 6;
                        let slot_address = if guest_arch == GuestArch::X64 {
                            let displacement = read_i32_from_memory(memory, state.rip + 2)?;
                            (next_rip as i128 + displacement as i128) as u64
                        } else {
                            read_u32(memory, state.rip + 2)? as u64
                        };
                        let target = read_guest_pointer(memory, slot_address, guest_arch)?;
                        let is_call = memory.read_u8(state.rip + 1)? == 0x15;

                        if is_call {
                            let call_rsp =
                                state.get(Register::Rsp).wrapping_sub(guest_pointer_bytes);
                            write_guest_pointer(memory, call_rsp, next_rip, guest_arch)?;
                            state.set(Register::Rsp, call_rsp);
                        }

                        if let Some(result) =
                            runtime.dispatch_import_if_present(target, state, memory)?
                        {
                            thunk_count += 1;
                            if let Some(code) = result {
                                exit_code = code;
                                break;
                            }
                            // Host thunk was dispatched successfully. For a CALL, advance
                            // RIP past the call instruction so the subsequent block decode
                            // (line 4807) starts from the instruction AFTER the call.
                            // Without this, the decoded block will contain the same call
                            // instruction, causing a second dispatch through the IR
                            // interpreter — a double-dispatch bug.
                            if is_call {
                                state.rip = next_rip;
                            }
                            // For a JMP (ModRM 0x25), the thunk handles control flow
                            // internally.  Just continue the loop — dispatch_import
                            // will have updated state.rip as needed.
                        } else {
                            state.rip = target;
                        }
                    }

                    _ => {}
                }
            }

            let cached_block = decode_basic_block_cached(
                engine,
                memory,
                &mut runtime.instruction_cache,
                &mut runtime.instruction_cache_lru,
                &mut runtime.instruction_cache_generation,
                INSTRUCTION_CACHE_LIMIT,
                &mut runtime.basic_block_cache,
                &mut runtime.basic_block_cache_lru,
                &mut runtime.basic_block_cache_generation,
                BASIC_BLOCK_CACHE_LIMIT,
                state.rip,
            )
            .map_err(|error| annotate_guest_fault(error, memory, state))?;
            if block_count <= 10 {
                let start_rip = state.rip;
                let rva = if start_rip >= runtime.mapped_image_base
                    && start_rip < runtime.mapped_image_base + runtime.mapped_image_size
                {
                    format!("{:#x}", start_rip.saturating_sub(runtime.mapped_image_base))
                } else {
                    format!("<outside:{:#x}>", start_rip)
                };
                diag(&format!(
                    "iter:{} decoded block at rva={}, {} insns",
                    block_count,
                    rva,
                    cached_block.translated.decoded.len()
                ));
            }
            let block_start_rip = state.rip;
            let block_rva = if block_start_rip >= runtime.mapped_image_base
                && block_start_rip < runtime.mapped_image_base + runtime.mapped_image_size
            {
                let block_rva = block_start_rip.saturating_sub(runtime.mapped_image_base) as u32;
                // Steam diagnostic tracking of block RVAs (only when tracing is active).
                if runtime.enable_steam_tracing {
                    if runtime.recent_main_block_rvas.len() == 32
                        && runtime.recent_main_block_rvas.pop_front() == Some(0x000c_c400)
                    {
                        runtime.recent_main_cc400_count =
                            runtime.recent_main_cc400_count.saturating_sub(1);
                    }
                    runtime.recent_main_block_rvas.push_back(block_rva);
                    if block_rva == 0x000c_c400 {
                        runtime.recent_main_cc400_count += 1;
                    }
                }
                Some(block_rva)
            } else {
                if runtime.enable_steam_tracing && !runtime.steam_reported_image_exit {
                    runtime.steam_reported_image_exit = true;
                    let last_rvas: Vec<String> = runtime
                        .recent_main_block_rvas
                        .iter()
                        .map(|rva| format!("{rva:#x}"))
                        .collect();
                    let last_rvas_str = last_rvas.join(" ");
                    emit_live_ui_debug(format!(
                        "ImageExit: rip={:#x} mapped_base={:#x} mapped_size={:#x} last_32_block_rvas=[{}]",
                        state.rip,
                        runtime.mapped_image_base,
                        runtime.mapped_image_size,
                        last_rvas_str,
                    ));
                    runtime.push_trace(
                        "process",
                        "ImageExit",
                        BTreeMap::from([
                            ("rip".to_string(), json!(format!("{:#x}", state.rip))),
                            (
                                "mapped_base".to_string(),
                                json!(format!("{:#x}", runtime.mapped_image_base)),
                            ),
                            (
                                "mapped_size".to_string(),
                                json!(format!("{:#x}", runtime.mapped_image_size)),
                            ),
                            ("last_32_block_rvas".to_string(), json!(last_rvas_str)),
                        ]),
                        json!(null),
                    );
                }
                None
            };
            if runtime.enable_steam_tracing
                && let Some(block_rva) = block_rva
            {
                if guest_arch == GuestArch::X86 {
                    let cookie_watch_site = match block_rva {
                        0x0017_5f4e => Some("after_get_module_file_name_w"),
                        0x0017_5f94 => Some("after_175f8f_call"),
                        0x0017_5faf => Some("after_175faa_call"),
                        0x0017_5fb8 => Some("before_security_check"),
                        _ => None,
                    };
                    if let Some(site) = cookie_watch_site {
                        let ebp = state.get(Register::Rbp) as u32;
                        let frame_cookie_addr = ebp.wrapping_sub(4) as u64;
                        let frame_cookie = match read_guest_u32(memory, frame_cookie_addr) {
                            Ok(value) => Some(value),
                            Err(error) => {
                                eprintln!(
                                    "[pe_runtime] SteamCookieWatch: failed to read frame cookie at {:#x}: {}",
                                    frame_cookie_addr, error
                                );
                                None
                            }
                        };
                        let global_cookie_addr = runtime.mapped_image_base + 0x003c_bfd4;
                        let global_cookie = match read_guest_u32(memory, global_cookie_addr) {
                            Ok(value) => Some(value),
                            Err(error) => {
                                eprintln!(
                                    "[pe_runtime] SteamCookieWatch: failed to read global cookie at {:#x}: {}",
                                    global_cookie_addr, error
                                );
                                None
                            }
                        };
                        let decoded_cookie = frame_cookie.map(|value| value ^ ebp);
                        runtime.push_trace(
                            "process",
                            "SteamCookieWatch",
                            BTreeMap::from([
                                ("site".to_string(), json!(site)),
                                ("ebp".to_string(), json!(format!("{ebp:#x}"))),
                                (
                                    "esp".to_string(),
                                    json!(format!("{:#x}", state.get(Register::Rsp))),
                                ),
                                (
                                    "frame_cookie_addr".to_string(),
                                    json!(format!("{frame_cookie_addr:#x}")),
                                ),
                                (
                                    "frame_cookie".to_string(),
                                    json!(
                                        frame_cookie
                                            .map(|value| format!("{value:#x}"))
                                            .unwrap_or_else(|| "<unavailable>".to_string())
                                    ),
                                ),
                                (
                                    "decoded_cookie".to_string(),
                                    json!(
                                        decoded_cookie
                                            .map(|value| format!("{value:#x}"))
                                            .unwrap_or_else(|| "<unavailable>".to_string())
                                    ),
                                ),
                                (
                                    "global_cookie".to_string(),
                                    json!(
                                        global_cookie
                                            .map(|value| format!("{value:#x}"))
                                            .unwrap_or_else(|| "<unavailable>".to_string())
                                    ),
                                ),
                            ]),
                            json!(site),
                        );
                    }
                }
                let in_final_assert_window = (0x0013_6400..=0x0013_6f00).contains(&block_rva)
                    || (0x0013_d180..=0x0013_d1b0).contains(&block_rva)
                    || (0x0013_ea00..=0x0013_f800).contains(&block_rva)
                    || (0x0014_ca80..=0x0014_cd50).contains(&block_rva);
                let in_pre_report_window = (0x0014_dee0..=0x0014_df40).contains(&block_rva)
                    || (0x0015_e6d0..=0x0015_e720).contains(&block_rva)
                    || (0x0016_c040..=0x0016_c0c0).contains(&block_rva)
                    || (0x0016_ddf0..=0x0016_e120).contains(&block_rva);
                runtime.trace_steam_pre_report_pointer_state(memory, state, block_rva);
                if in_final_assert_window || in_pre_report_window {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let return_addr = read_guest_u32(memory, state.get(Register::Rsp))
                        .ok()
                        .map(u64::from)
                        .map(|value| {
                            format!("{:#x}", value.saturating_sub(runtime.mapped_image_base))
                        })
                        .unwrap_or_else(|| "<unavailable>".to_string());
                    let final_assert_tls_state = if guest_arch == GuestArch::X86
                        && block_rva == 0x0013_ea80
                    {
                        let format_opt = |value: Option<u64>| {
                            value
                                .map(|value| format!("{value:#x}"))
                                .unwrap_or_else(|| "<unavailable>".to_string())
                        };
                        let tls_index_address = runtime.mapped_image_base + 0x0045_71a8;
                        let compare_left_address = runtime.mapped_image_base + 0x0042_6400;
                        let tls_vector = match read_guest_pointer(
                            memory,
                            runtime.teb_base + 0x2c,
                            guest_arch,
                        ) {
                            Ok(value) => Some(value),
                            Err(error) => {
                                eprintln!(
                                    "[pe_runtime] SteamTLSWatch: failed to read TLS vector at {:#x}: {}",
                                    runtime.teb_base + 0x2c,
                                    error
                                );
                                None
                            }
                        };
                        let tls_index = read_guest_u32(memory, tls_index_address)
                            .ok()
                            .map(u64::from);
                        let tls_slot = match (tls_vector, tls_index) {
                            (Some(vector), Some(index)) if vector != 0 => read_guest_pointer(
                                memory,
                                vector + index * guest_arch.pointer_bytes() as u64,
                                guest_arch,
                            )
                            .ok(),
                            _ => None,
                        };
                        let compare_left = read_guest_u32(memory, compare_left_address)
                            .ok()
                            .map(u64::from);
                        let compare_right = match tls_slot {
                            Some(slot) if slot != 0 => {
                                read_guest_u32(memory, slot + 0x480).ok().map(u64::from)
                            }
                            _ => None,
                        };
                        format!(
                            " tls_index={} tls_vector={} tls_slot={} compare_lhs={} compare_rhs={}",
                            format_opt(tls_index),
                            format_opt(tls_vector),
                            format_opt(tls_slot),
                            format_opt(compare_left),
                            format_opt(compare_right),
                        )
                    } else {
                        String::new()
                    };
                    let block_summary = format!(
                        "block_start={block_rva:#x} ret_rva={return_addr} eax={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x} esp={:#x} ebp={:#x}{final_assert_tls_state} decoded=[{decoded_instructions}]",
                        state.get(Register::Rax),
                        state.get(Register::Rcx),
                        state.get(Register::Rdx),
                        state.get(Register::Rsi),
                        state.get(Register::Rdi),
                        state.get(Register::Rsp),
                        state.get(Register::Rbp),
                    );
                    if in_final_assert_window {
                        if runtime.steam_final_assert_recent_blocks.len() == 32 {
                            runtime.steam_final_assert_recent_blocks.pop_front();
                        }
                        runtime
                            .steam_final_assert_recent_blocks
                            .push_back(block_summary.clone());
                        if (0x0013_eaf0..=0x0013_eb10).contains(&block_rva)
                            || (0x0014_ca80..=0x0014_cd80).contains(&block_rva)
                        {
                            if runtime.steam_final_status_writer_blocks.len() == 40 {
                                runtime.steam_final_status_writer_blocks.pop_front();
                            }
                            runtime
                                .steam_final_status_writer_blocks
                                .push_back(block_summary.clone());
                        } else if (0x0013_c3d0..=0x0013_c410).contains(&block_rva)
                            || (0x0013_d190..=0x0013_d197).contains(&block_rva)
                            || (0x0013_f0a0..=0x0013_f0d0).contains(&block_rva)
                            || (0x0013_f560..=0x0013_f790).contains(&block_rva)
                        {
                            if runtime.steam_final_lock_blocks.len() == 64 {
                                runtime.steam_final_lock_blocks.pop_front();
                            }
                            runtime
                                .steam_final_lock_blocks
                                .push_back(block_summary.clone());
                        }
                    }
                    if in_pre_report_window {
                        if runtime.steam_pre_report_blocks.len() == 64 {
                            runtime.steam_pre_report_blocks.pop_front();
                        }
                        runtime.steam_pre_report_blocks.push_back(block_summary);
                    }
                }
            }
            // --- Steam tracing pre-execution state captures ---
            // These variable declarations capture guest state before block execution so
            // that tracing emission blocks (C, D, E below) can compare before/after values.
            // They are always computed (guards are cheap) but must remain in scope for the
            // later tracing emission blocks after execute_ir_with_guest_exception_delivery.
            let esi_before = state.get(Register::Rsi) as u32;
            let steam_565af0_range_start = runtime.mapped_image_base + 0x0016_5ab5;
            let steam_565af0_range_end = runtime.mapped_image_base + 0x0016_5d10;
            let steam_565ac1 = runtime.mapped_image_base + 0x0016_5ac1;
            let steam_565af0 = runtime.mapped_image_base + 0x0016_5af0;
            let steam_565c46 = runtime.mapped_image_base + 0x0016_5c46;
            let trace_steam_final_assert_globals = guest_arch == GuestArch::X86
                && matches!(
                    block_rva,
                    Some(rva)
                        if (0x0013_6400..=0x0013_6f00).contains(&rva)
                            || (0x0013_d180..=0x0013_d1b0).contains(&rva)
                            || (0x0013_ea00..=0x0013_f800).contains(&rva)
                            || (0x0014_ca80..=0x0014_cd50).contains(&rva)
                            || (0x0014_dee0..=0x0014_df40).contains(&rva)
                            || (0x0015_e6d0..=0x0015_e720).contains(&rva)
                            || (0x0016_c040..=0x0016_c0c0).contains(&rva)
                            || (0x0016_ddf0..=0x0016_e120).contains(&rva)
                );
            let final_assert_globals_before = if trace_steam_final_assert_globals {
                Some([
                    (
                        runtime.mapped_image_base + 0x003c_bfc4,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_bfc4),
                    ),
                    (
                        runtime.mapped_image_base + 0x003c_bfd4,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_bfd4),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_3a34,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3a34),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_3a38,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3a38),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_3fbc,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3fbc),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_6130,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_6130),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_63e8,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_63e8),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_6400,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_6400),
                    ),
                    (
                        runtime.mapped_image_base + 0x0042_6404,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_6404),
                    ),
                ])
            } else {
                None
            };
            let steam_trace = runtime.enable_steam_tracing && guest_arch == GuestArch::X86;
            let trace_steam_136b50_entry = steam_trace && block_rva == Some(0x0013_6b50);
            let steam_136b50_esp_before =
                trace_steam_136b50_entry.then_some(state.get(Register::Rsp));
            let steam_136b50_arg0_before = steam_136b50_esp_before
                .and_then(|esp| probe_read_guest_u32(memory, esp + 4).map(u64::from));
            let steam_136b50_arg1_before = steam_136b50_esp_before
                .and_then(|esp| probe_read_guest_u32(memory, esp + 8).map(u64::from));
            let steam_136b50_global_423fbc_before = trace_steam_136b50_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3fbc)
                        .map(u64::from)
                })
                .flatten();
            let steam_136b50_global_423fb8_before = trace_steam_136b50_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3fb8)
                        .map(u64::from)
                })
                .flatten();
            let steam_136b50_global_423a30_before = trace_steam_136b50_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3a30)
                        .map(u64::from)
                })
                .flatten();
            let steam_136b50_global_423a38_before = trace_steam_136b50_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3a38)
                        .map(u64::from)
                })
                .flatten();
            let trace_steam_136e80_entry = steam_trace && block_rva == Some(0x0013_6e80);
            let steam_136e80_esp_before =
                trace_steam_136e80_entry.then_some(state.get(Register::Rsp));
            let steam_136e80_args_before = steam_136e80_esp_before.map(|esp| {
                [
                    probe_read_guest_u32(memory, esp + 4).map(u64::from),
                    probe_read_guest_u32(memory, esp + 8).map(u64::from),
                    probe_read_guest_u32(memory, esp + 12).map(u64::from),
                    probe_read_guest_u32(memory, esp + 16).map(u64::from),
                    probe_read_guest_u32(memory, esp + 20).map(u64::from),
                ]
            });
            let steam_136e80_global_423e4c_before = trace_steam_136e80_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3e4c)
                        .map(u64::from)
                })
                .flatten();
            let steam_136e80_global_423e6c_before = trace_steam_136e80_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0042_3e6c)
                        .map(u64::from)
                })
                .flatten();
            let steam_136e80_tls_index_before = trace_steam_136e80_entry
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_71a8)
                        .map(u64::from)
                })
                .flatten();
            let steam_136e80_tls_vector_before = trace_steam_136e80_entry
                .then(|| probe_read_guest_pointer(memory, runtime.teb_base + 0x2c, guest_arch))
                .flatten();
            let steam_136e80_tls_slot_before = match (
                steam_136e80_tls_vector_before,
                steam_136e80_tls_index_before,
            ) {
                (Some(vector), Some(index)) if vector != 0 => probe_read_guest_pointer(
                    memory,
                    vector + index * guest_arch.pointer_bytes() as u64,
                    guest_arch,
                ),
                _ => None,
            };
            let steam_136e80_tls_slot_480_before = steam_136e80_tls_slot_before
                .and_then(|slot| {
                    (slot != 0).then(|| probe_read_guest_u32(memory, slot + 0x480).map(u64::from))
                })
                .flatten();
            let trace_steam_memstd_oom_entry = steam_trace && block_rva == Some(0x0013_4bd0);
            let steam_memstd_oom_esp_before =
                trace_steam_memstd_oom_entry.then_some(state.get(Register::Rsp));
            let steam_memstd_oom_size_before = steam_memstd_oom_esp_before
                .and_then(|esp| probe_read_guest_u32(memory, esp + 4).map(u64::from));
            let steam_memstd_oom_return_rva_before = steam_memstd_oom_esp_before
                .and_then(|esp| probe_read_guest_u32(memory, esp).map(u64::from))
                .map(|value| value.saturating_sub(runtime.mapped_image_base));
            let steam_memstd_oom_this_before =
                trace_steam_memstd_oom_entry.then_some(state.get(Register::Rcx));
            let trace_steam_memstd_oom_caller = steam_trace && block_rva == Some(0x0013_4b56);
            let steam_memstd_caller_this_before =
                trace_steam_memstd_oom_caller.then_some(state.get(Register::Rdi));
            let steam_memstd_caller_old_address_before =
                trace_steam_memstd_oom_caller.then_some(state.get(Register::Rsi));
            let steam_memstd_caller_requested_size_before =
                trace_steam_memstd_oom_caller.then_some(state.get(Register::Rbx));
            let steam_memstd_caller_mode_before =
                steam_memstd_caller_this_before.and_then(|this_ptr| {
                    probe_read_guest_u32(memory, this_ptr + 0x5918).map(u64::from)
                });
            let steam_memstd_caller_range1_table_before =
                steam_memstd_caller_this_before.and_then(|this_ptr| {
                    probe_read_guest_u32(memory, this_ptr + 0x0c58).map(u64::from)
                });
            let steam_memstd_caller_range2_table_before =
                steam_memstd_caller_this_before.and_then(|this_ptr| {
                    probe_read_guest_u32(memory, this_ptr + 0x5910).map(u64::from)
                });
            let steam_global_array_watch = steam_trace
                && matches!(
                    block_rva,
                    Some(
                        0x0015_e9b1
                            | 0x0015_e9c5
                            | 0x0015_e9d0
                            | 0x0015_e9f0
                            | 0x0015_ea1b
                            | 0x0015_ea89
                            | 0x0015_ea98
                            | 0x0015_eac0
                            | 0x0017_21d1
                            | 0x0017_21f0
                    )
                );
            let steam_global_array_count_before = steam_global_array_watch
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7624)
                        .map(u64::from)
                })
                .flatten();
            let steam_global_array_ptr_before = steam_global_array_watch
                .then(|| {
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7628)
                        .map(u64::from)
                })
                .flatten();
            let steam_global_array_return_before = steam_global_array_watch
                .then(|| probe_read_guest_u32(memory, state.get(Register::Rsp)).map(u64::from))
                .flatten()
                .map(|value| value.saturating_sub(runtime.mapped_image_base));
            let steam_early_termination_watch = steam_trace
                && matches!(block_rva, Some(rva) if (0x0015_e740..=0x0015_e7a5).contains(&rva));
            let steam_early_termination_return_before = steam_early_termination_watch
                .then(|| probe_read_guest_u32(memory, state.get(Register::Rsp)).map(u64::from))
                .flatten()
                .map(|value| value.saturating_sub(runtime.mapped_image_base));
            let steam_global_state_watch = steam_trace && block_rva.is_some();
            let steam_global_state_before = steam_global_state_watch.then(|| {
                [
                    (
                        runtime.mapped_image_base + 0x0045_715c,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_715c),
                    ),
                    (
                        runtime.mapped_image_base + 0x0045_7624,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7624),
                    ),
                    (
                        runtime.mapped_image_base + 0x0045_7628,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7628),
                    ),
                    (
                        runtime.mapped_image_base + 0x003c_873c,
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_873c),
                    ),
                ]
            });
            let steam_initterm_e_watch = steam_trace
                && matches!(block_rva, Some(rva) if (0x0016_e34b..=0x0016_e371).contains(&rva));
            let steam_initterm_e_start_before = steam_initterm_e_watch
                .then(|| probe_read_guest_u32(memory, state.get(Register::Rsp) + 4).map(u64::from))
                .flatten();
            let steam_initterm_e_end_before = steam_initterm_e_watch
                .then(|| probe_read_guest_u32(memory, state.get(Register::Rsp) + 8).map(u64::from))
                .flatten();
            let steam_startup_init_watch = steam_trace
                && matches!(block_rva, Some(rva) if (0x0014_d105..=0x0014_d17b).contains(&rva));
            let steam_startup_failure_watch = steam_trace
                && matches!(block_rva, Some(rva) if (0x0014_d257..=0x0014_d264).contains(&rva));
            let steam_callback_walk_watch = steam_trace && block_rva == Some(0x0017_7827);
            let steam_callback_walk_entry_before = steam_callback_walk_watch.then(|| {
                let entry = state.get(Register::Rsi);
                (
                    entry,
                    probe_read_guest_u32(memory, entry).map(u64::from),
                    probe_read_guest_u32(memory, entry + 4).map(u64::from),
                )
            });
            let steam_post_577113_watch =
                steam_trace && matches!(block_rva, Some(0x0017_6f61 | 0x0017_6f84));
            let steam_post_56ee10_watch = steam_trace && block_rva == Some(0x0017_6f3c);
            let steam_post_576ca8_watch = steam_trace && block_rva == Some(0x0017_7133);
            let steam_post_576d7e_watch = steam_trace && block_rva == Some(0x0017_71a9);
            let steam_577113_epilogue_watch = steam_trace && block_rva == Some(0x0017_72f4);
            let steam_577113_epilogue_before = steam_577113_epilogue_watch.then(|| {
                let rsp = state.get(Register::Rsp);
                (
                    rsp,
                    probe_read_guest_u32(memory, rsp).map(u64::from),
                    probe_read_guest_u32(memory, rsp + 4).map(u64::from),
                    probe_read_guest_u32(memory, rsp + 8).map(u64::from),
                    probe_read_guest_u32(memory, rsp + 12).map(u64::from),
                    state.get(Register::Rdi),
                    state.get(Register::Rsi),
                )
            });
            let steam_saved_edi_slot_watch = steam_trace
                && matches!(block_rva, Some(rva) if (0x0001_6ca8..=0x0001_7304).contains(&rva));
            let steam_saved_edi_slot_before = steam_saved_edi_slot_watch
                .then(|| probe_read_guest_u32(memory, 0x7000_ff1c).map(u64::from))
                .flatten();
            let trace_steam_convar_create = steam_trace && block_rva == Some(0x000c_c542);
            let trace_steam_convar_create_start = steam_trace && block_rva == Some(0x000c_c400);
            let steam_convar_trace_active =
                trace_steam_convar_create || trace_steam_convar_create_start;
            let steam_convar_this_before = if trace_steam_convar_create_start {
                Some(state.get(Register::Rcx))
            } else if trace_steam_convar_create {
                Some(state.get(Register::Rsi))
            } else {
                None
            };
            let steam_convar_frame_before =
                steam_convar_trace_active.then_some(state.get(Register::Rbp));
            let steam_convar_name_ptr_before = steam_convar_frame_before
                .and_then(|frame| probe_read_guest_u32(memory, frame + 0x08).map(u64::from));
            let steam_convar_flags_before = steam_convar_frame_before
                .and_then(|frame| probe_read_guest_u32(memory, frame + 0x10).map(u64::from));
            let steam_convar_help_ptr_before = steam_convar_frame_before
                .and_then(|frame| probe_read_guest_u32(memory, frame + 0x14).map(u64::from));
            let steam_convar_parent_ptr_before = steam_convar_frame_before
                .and_then(|frame| probe_read_guest_u32(memory, frame + 0x18).map(u64::from));
            let steam_convar_callback_ptr_before = steam_convar_frame_before
                .and_then(|frame| probe_read_guest_u32(memory, frame + 0x2c).map(u64::from));
            let steam_convar_vector_ptr_before =
                steam_convar_this_before.and_then(|this_ptr| this_ptr.checked_add(0x84));
            let steam_convar_vector_bytes_before = steam_convar_vector_ptr_before
                .and_then(|vector_ptr| probe_read_window(memory, vector_ptr, 0x14));
            let recent_main_has_cc400 = steam_trace && runtime.recent_main_cc400_count != 0;
            let steam_convar_helper_watch = if recent_main_has_cc400 {
                match block_rva {
                    Some(0x0014_c88e) => Some("0x14c88e"),
                    Some(0x0014_e980) => Some("0x14e980"),
                    Some(0x0014_6200) => Some("0x146200"),
                    Some(0x0016_00aa) => Some("0x1600aa"),
                    Some(0x0016_0033) => Some("0x160033"),
                    Some(0x0014_6570) => Some("0x146570"),
                    Some(0x0016_6127) => Some("0x166127"),
                    _ => None,
                }
            } else {
                None
            };
            let steam_convar_helper_this_before = if steam_convar_helper_watch.is_some() {
                Some(state.get(Register::Rsi))
            } else {
                None
            };
            let steam_convar_helper_vector_ptr_before =
                steam_convar_helper_this_before.and_then(|this_ptr| this_ptr.checked_add(0x84));
            let steam_convar_helper_vector_bytes_before = steam_convar_helper_vector_ptr_before
                .and_then(|vector_ptr| probe_read_window(memory, vector_ptr, 0x14));
            let steam_convar_helper_arg0_before = steam_convar_helper_watch.and_then(|_| {
                probe_read_guest_u32(memory, state.get(Register::Rsp) + 4).map(u64::from)
            });
            let steam_convar_helper_arg1_before = steam_convar_helper_watch.and_then(|_| {
                probe_read_guest_u32(memory, state.get(Register::Rsp) + 8).map(u64::from)
            });
            let steam_convar_helper_arg2_before = steam_convar_helper_watch.and_then(|_| {
                probe_read_guest_u32(memory, state.get(Register::Rsp) + 12).map(u64::from)
            });
            let steam_convar_helper_return_before = steam_convar_helper_watch
                .and_then(|_| probe_read_guest_u32(memory, state.get(Register::Rsp)).map(u64::from))
                .map(|value| value.saturating_sub(runtime.mapped_image_base));
            if matches!(steam_convar_helper_watch, Some("0x14e980")) {
                runtime.steam_convar_memcpy_watch_this = steam_convar_helper_this_before;
            }
            let steam_convar_memcpy_byte_watch = if recent_main_has_cc400 {
                match block_rva {
                    Some(0x0014_ee9d) => Some("0x14ee9d"),
                    Some(0x0014_eea6) => Some("0x14eea6"),
                    _ => None,
                }
            } else {
                None
            };
            let steam_convar_memcpy_byte_this_before =
                steam_convar_memcpy_byte_watch.and(runtime.steam_convar_memcpy_watch_this);
            let steam_convar_memcpy_byte_vector_ptr_before = steam_convar_memcpy_byte_this_before
                .and_then(|this_ptr| this_ptr.checked_add(0x84));
            let steam_convar_memcpy_byte_vector_bytes_before =
                steam_convar_memcpy_byte_vector_ptr_before
                    .and_then(|vector_ptr| probe_read_window(memory, vector_ptr, 0x14));
            let steam_convar_memcpy_return_watch = if recent_main_has_cc400 {
                match block_rva {
                    Some(0x0014_eeb0) => Some("0x14eeb0"),
                    Some(0x000c_c474) => Some("0xcc474"),
                    _ => None,
                }
            } else {
                None
            };
            let steam_convar_memcpy_return_this_before =
                steam_convar_memcpy_return_watch.and(runtime.steam_convar_memcpy_watch_this);
            let steam_convar_memcpy_return_vector_ptr_before =
                steam_convar_memcpy_return_this_before
                    .and_then(|this_ptr| this_ptr.checked_add(0x84));
            let steam_convar_memcpy_return_vector_bytes_before =
                steam_convar_memcpy_return_vector_ptr_before
                    .and_then(|vector_ptr| probe_read_window(memory, vector_ptr, 0x14));
            let trace_steam_vector_grow_request = steam_trace && block_rva == Some(0x0009_968b);
            let steam_vector_this_before =
                trace_steam_vector_grow_request.then_some(state.get(Register::Rdi));
            let steam_vector_element_size_before = steam_vector_this_before
                .and_then(|vector_ptr| probe_read_guest_u32(memory, vector_ptr).map(u64::from));
            let steam_vector_old_address_before = steam_vector_this_before.and_then(|vector_ptr| {
                probe_read_guest_u32(memory, vector_ptr + 0x4).map(u64::from)
            });
            let steam_vector_capacity_before = steam_vector_this_before.and_then(|vector_ptr| {
                probe_read_guest_u32(memory, vector_ptr + 0x8).map(u64::from)
            });
            let steam_vector_grow_size_before = steam_vector_this_before.and_then(|vector_ptr| {
                probe_read_guest_u32(memory, vector_ptr + 0x0c).map(u64::from)
            });
            let steam_vector_count_before = steam_vector_this_before.and_then(|vector_ptr| {
                probe_read_guest_u32(memory, vector_ptr + 0x10).map(u64::from)
            });
            let decode_steam_convar_vector_fields = |bytes: &[u8]| -> BTreeMap<String, Value> {
                let read_u32_at = |offset: usize| -> u64 {
                    u64::from(u32::from_le_bytes(
                        bytes[offset..offset + 4].try_into().unwrap(),
                    ))
                };
                BTreeMap::from([
                    (
                        "element_size".to_string(),
                        json!(format!("{:#x}", read_u32_at(0))),
                    ),
                    (
                        "memory_ptr".to_string(),
                        json!(format!("{:#x}", read_u32_at(4))),
                    ),
                    (
                        "allocation_count".to_string(),
                        json!(format!("{:#x}", read_u32_at(8))),
                    ),
                    (
                        "grow_size".to_string(),
                        json!(format!("{:#x}", read_u32_at(12))),
                    ),
                    (
                        "count".to_string(),
                        json!(format!("{:#x}", read_u32_at(16))),
                    ),
                ])
            };
            let steam_convar_precise_watch = if steam_trace {
                match block_rva {
                    Some(0x000c_c400) => Some("0xcc400"),
                    Some(0x000c_c447) => Some("0xcc447"),
                    Some(0x000c_c457) => Some("0xcc457"),
                    Some(0x000c_c465) => Some("0xcc465"),
                    Some(0x000c_c474) => Some("0xcc474"),
                    Some(0x000c_c4ac) => Some("0xcc4ac"),
                    Some(0x000c_c514) => Some("0xcc514"),
                    Some(0x000c_c542) => Some("0xcc542"),
                    _ => None,
                }
            } else {
                None
            };
            let steam_convar_precise_this_before = steam_convar_precise_watch.and_then(|_| {
                let this_ptr = if block_rva == Some(0x000c_c400) {
                    state.get(Register::Rcx)
                } else {
                    state.get(Register::Rsi)
                };
                (this_ptr != 0).then_some(this_ptr)
            });
            let steam_convar_precise_vector_before = steam_convar_precise_this_before
                .and_then(|this_ptr| this_ptr.checked_add(0x84))
                .and_then(|vector_ptr| read_window(memory, vector_ptr, 0x14).ok())
                .map(|bytes| decode_steam_convar_vector_fields(&bytes));
            let steam_convar_precise_field_94_before = steam_convar_precise_this_before
                .and_then(|this_ptr| read_guest_u32(memory, this_ptr + 0x94).ok().map(u64::from));
            let contains_steam_4013c0 = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == 0x4013c0);
            let contains_steam_4013ba = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == 0x4013ba);
            let contains_steam_4013a3 = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == 0x4013a3);
            let contains_steam_402a57 = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == 0x402a57);
            let touches_steam_565af0_helper = steam_trace
                && cached_block.translated.decoded.iter().any(|instruction| {
                    (steam_565af0_range_start..=steam_565af0_range_end)
                        .contains(&instruction.address)
                });
            let contains_steam_565ac1 = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == steam_565ac1);
            let contains_steam_565af0 = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == steam_565af0);
            let contains_steam_565c46 = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| instruction.address == steam_565c46);
            let watch_steam_adf60_edi_preservation = steam_trace
                && matches!(block_rva, Some(rva) if (0x000a_df67..=0x000a_e239).contains(&rva));
            let enter_steam_4dea00 = steam_trace && block_rva == Some(0x000a_ea00);
            let watch_steam_4dea00_edi_preservation = steam_trace
                && matches!(block_rva, Some(rva) if (0x000a_ea09..=0x000a_ec80).contains(&rva));
            let steam_hash_insert_probe_before = (steam_trace
                && runtime.steam_4ae970_probe_count < 16
                && cached_block.translated.decoded.iter().any(|instruction| {
                    let instruction_rva = instruction
                        .address
                        .saturating_sub(runtime.mapped_image_base);
                    (0x000a_e970..=0x000a_ea10).contains(&instruction_rva)
                }))
            .then(|| {
                (
                    probe_read_guest_u32(memory, state.get(Register::Rsp)).map(u64::from),
                    probe_read_guest_u32(memory, state.get(Register::Rbp) + 8).map(u64::from),
                    state.get(Register::Rbx),
                    state.get(Register::Rdi),
                    state.get(Register::Rbp),
                    state.get(Register::Rsp),
                    block_rva,
                )
            });
            let steam_owner_allocator_probe_before = (steam_trace
                && runtime.steam_owner_allocator_probe_count < 16
                && cached_block.translated.decoded.iter().any(|instruction| {
                    let instruction_rva = instruction
                        .address
                        .saturating_sub(runtime.mapped_image_base);
                    (0x000a_bfd7..=0x000a_c04b).contains(&instruction_rva)
                }))
            .then(|| {
                (
                    block_rva,
                    probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_873c),
                    state.get(Register::Rsp),
                    state.get(Register::Rax),
                    state.get(Register::Rcx),
                )
            });
            let steam_install_dir_set_edi = steam_trace
                && cached_block.translated.decoded.iter().any(|instruction| {
                    instruction.address == runtime.mapped_image_base + 0x0005_47c4
                });
            let watch_steam_install_dir_edi_preservation = steam_trace
                && cached_block.translated.decoded.iter().any(|instruction| {
                    let instruction_rva = instruction
                        .address
                        .saturating_sub(runtime.mapped_image_base);
                    (0x0005_47c6..=0x0005_4a33).contains(&instruction_rva)
                });
            let watched_esi_slot_before =
                runtime
                    .steam_401389_saved_esi_slot_addr
                    .and_then(|address| {
                        read_guest_u32(memory, address)
                            .ok()
                            .map(|value| (address, value))
                    });
            let touches_steam_401389_helper = steam_trace
                && cached_block
                    .translated
                    .decoded
                    .iter()
                    .any(|instruction| (0x401389..=0x4013fc).contains(&instruction.address));
            if runtime.enable_steam_tracing {
                if guest_arch == GuestArch::X86 && contains_steam_565af0 {
                    runtime.steam_565af0_recent_blocks.clear();
                }
                if enter_steam_4dea00 {
                    runtime.steam_4dea00_expected_edi = Some(state.get(Register::Rdi));
                } else if guest_arch == GuestArch::X86 && !watch_steam_4dea00_edi_preservation {
                    runtime.steam_4dea00_expected_edi = None;
                }
                if watch_steam_4dea00_edi_preservation
                    && let Some(expected_edi) = runtime.steam_4dea00_expected_edi
                {
                    let actual_edi = state.get(Register::Rdi);
                    if actual_edi != expected_edi {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "steam 0x4dea00 callee lost edi inside block={block_start_rip:#x}: expected {expected_edi:#x}, actual {actual_edi:#x}, ebp={:#x}",
                                state.get(Register::Rbp),
                            ),
                        )
                        .with_hint(format!(
                            "steam-0x4dea00 esp={:#x} return={} eax={:#x} ecx={:#x} edx={:#x}",
                            state.get(Register::Rsp),
                            read_guest_u32(memory, state.get(Register::Rsp))
                                .ok()
                                .map(|value| format!("{:#x}", u64::from(value)))
                                .unwrap_or_else(|| "<unavailable>".to_string()),
                            state.get(Register::Rax),
                            state.get(Register::Rcx),
                            state.get(Register::Rdx),
                        )));
                    }
                }
                if watch_steam_install_dir_edi_preservation
                    && let Some(expected_edi) = runtime.steam_install_dir_expected_edi
                {
                    let actual_edi = state.get(Register::Rdi);
                    if actual_edi != expected_edi {
                        let decoded_addresses = cached_block
                            .translated
                            .decoded
                            .iter()
                            .map(|instruction| format!("{:#x}", instruction.address))
                            .collect::<Vec<_>>()
                            .join(",");
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "steam install-dir callee lost edi before block {block_start_rip:#x}: expected {expected_edi:#x}, actual {actual_edi:#x}"
                            ),
                        )
                        .with_hint(format!(
                            "steam-install-dir block_addrs=[{decoded_addresses}] recent_main_block_rvas=[{}] ebp={:#x} esp={:#x}",
                            runtime
                                .recent_main_block_rvas
                                .iter()
                                .map(|value| format!("{value:#x}"))
                                .collect::<Vec<_>>()
                                .join(","),
                            state.get(Register::Rbp),
                            state.get(Register::Rsp),
                        )));
                    }
                }
                if watch_steam_adf60_edi_preservation {
                    let expected_edi =
                        read_guest_u32(memory, state.get(Register::Rbp).wrapping_add(12))
                            .ok()
                            .map(u64::from)
                            .unwrap_or(0);
                    let actual_edi = state.get(Register::Rdi);
                    if expected_edi != 0 && actual_edi != expected_edi {
                        return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 0xadf60 wrapper lost edi before call block={block_start_rip:#x}: expected {expected_edi:#x}, actual {actual_edi:#x}, ebp={:#x}",
                            state.get(Register::Rbp),
                        ),
                    )
                    .with_hint(format!(
                        "steam-0xadf60 frame return={} arg0={} arg1={} arg2={} ecx={:#x} esi={:#x}",
                        read_guest_u32(memory, state.get(Register::Rbp).wrapping_add(4))
                            .ok()
                            .map(|value| format!("{:#x}", u64::from(value)))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        read_guest_u32(memory, state.get(Register::Rbp).wrapping_add(8))
                            .ok()
                            .map(|value| format!("{:#x}", u64::from(value)))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        read_guest_u32(memory, state.get(Register::Rbp).wrapping_add(12))
                            .ok()
                            .map(|value| format!("{:#x}", u64::from(value)))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        read_guest_u32(memory, state.get(Register::Rbp).wrapping_add(16))
                            .ok()
                            .map(|value| format!("{:#x}", u64::from(value)))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        state.get(Register::Rcx),
                        state.get(Register::Rsi),
                    )));
                    }
                }
                if touches_steam_565af0_helper {
                    let decoded_addresses = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| format!("{:#x}", instruction.address))
                        .collect::<Vec<_>>()
                        .join(",");
                    let esp = state.get(Register::Rsp);
                    let ebp = state.get(Register::Rbp);
                    let return_addr = read_guest_u32(memory, esp).ok().map(u64::from);
                    let arg_from_esp = read_guest_u32(memory, esp + 4).ok().map(u64::from);
                    let arg_from_ebp = read_guest_u32(memory, ebp.wrapping_add(8))
                        .ok()
                        .map(u64::from);
                    let preview_ascii = |pointer: Option<u64>| -> String {
                        let Some(pointer) = pointer else {
                            return "<unavailable>".to_string();
                        };
                        if pointer == 0 {
                            return "<null>".to_string();
                        }
                        let mut bytes = Vec::new();
                        for offset in 0..32_u64 {
                            match memory.read_u8(pointer + offset) {
                                Ok(0) => break,
                                Ok(byte) => bytes.push(byte),
                                Err(_) if bytes.is_empty() => return "<unreadable>".to_string(),
                                Err(_) => break,
                            }
                        }
                        bytes
                            .iter()
                            .map(|byte| {
                                if byte.is_ascii_graphic() || *byte == b' ' {
                                    char::from(*byte)
                                } else {
                                    '.'
                                }
                            })
                            .collect::<String>()
                    };
                    let eax_ascii = preview_ascii(Some(state.get(Register::Rax)));
                    let esp_arg0_ascii = preview_ascii(arg_from_esp);
                    let esi_deref_ascii = preview_ascii(
                        read_guest_u32(memory, state.get(Register::Rsi))
                            .ok()
                            .map(u64::from),
                    );
                    let block_summary = format!(
                        "block_start={block_start_rip:#x} addrs=[{decoded_addresses}] esp={esp:#x} ebp={ebp:#x} eax={:#x} eax_ascii={} ecx={:#x} edx={:#x} esi_deref_ascii={} return_addr={} esp_arg0={} esp_arg0_ascii={} ebp_arg0={} pre_call_eax={}",
                        state.get(Register::Rax),
                        eax_ascii,
                        state.get(Register::Rcx),
                        state.get(Register::Rdx),
                        esi_deref_ascii,
                        return_addr
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        arg_from_esp
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        esp_arg0_ascii,
                        arg_from_ebp
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        if contains_steam_565ac1 {
                            format!("{:#x}", state.get(Register::Rax))
                        } else {
                            "<n/a>".to_string()
                        },
                    );
                    if runtime.steam_565af0_recent_blocks.len() == 20 {
                        runtime.steam_565af0_recent_blocks.pop_front();
                    }
                    runtime.steam_565af0_recent_blocks.push_back(block_summary);
                }
                if guest_arch == GuestArch::X86 && contains_steam_565c46 {
                    let frame_ebp = state.get(Register::Rbp);
                    let frame_arg0 = read_guest_u32(memory, frame_ebp.wrapping_add(8))
                        .ok()
                        .map(u64::from)
                        .unwrap_or(0);
                    if frame_arg0 == 0 || read_guest_u32(memory, frame_arg0).is_err() {
                        let recent_blocks = runtime
                            .steam_565af0_recent_blocks
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" || ");
                        return Err(
                        AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "steam 565c46 entered with invalid arg0 {frame_arg0:#x} (ebp={frame_ebp:#x}, esp={:#x})",
                                state.get(Register::Rsp),
                            ),
                        )
                        .with_hint(format!("steam-565af0 recent-blocks {recent_blocks}")),
                    );
                    }
                }
                if guest_arch == GuestArch::X86
                    && contains_steam_402a57
                    && let Some(expected_esi) = runtime.steam_401389_expected_esi_after_401434
                {
                    let saved_esi =
                        read_guest_u32(memory, state.get(Register::Rbp).wrapping_sub(0x2b8))
                            .unwrap_or(0);
                    if saved_esi != expected_esi {
                        return Err(AppError::new(
                            ReasonCode::RcUnimplInsn,
                            format!(
                                "steam 401434 corrupted its saved ESI slot before epilogue: expected {expected_esi:#x}, saved slot holds {saved_esi:#x}"
                            ),
                        ));
                    }
                }
            }
            if state.rip <= 0x19026bf1 && cached_block.end_rip > 0x19026bf1 {
                let this_ptr = state.get(Register::Rcx) & state.arch.register_mask();
                let first = read_guest_pointer(memory, this_ptr, guest_arch).unwrap_or(0);
                let second = read_guest_pointer(memory, first, guest_arch).unwrap_or(0);
                if second != 0 {
                    let field_4c = read_u32(memory, second + 0x4c).unwrap_or(0) as u64;
                    if read_u32(memory, second + 0x48).unwrap_or(0) as u64
                        == u64::from(DEFAULT_ANSI_CODE_PAGE)
                        && field_4c >= 0x1_0000
                    {
                        write_u32(memory, second + 0x48, field_4c as u32);
                    }
                }
            }
            if runtime.enable_steam_tracing {
                // Trace hash-table insertion probes (capped at 16 emissions).
                if let Some((
                    return_addr,
                    key_arg,
                    map_this,
                    edi_before,
                    ebp_before,
                    rsp_before,
                    block_rva_before,
                )) = steam_hash_insert_probe_before
                {
                    runtime.push_trace(
                        "process",
                        "SteamHashInsert",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva_before
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            (
                                "return_rva".to_string(),
                                json!(
                                    return_addr
                                        .map(|v| format!(
                                            "{:#x}",
                                            v.saturating_sub(runtime.mapped_image_base)
                                        ))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "frame_key".to_string(),
                                json!(
                                    key_arg
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            ("map_this".to_string(), json!(format!("{map_this:#x}"))),
                            ("edi_before".to_string(), json!(format!("{edi_before:#x}"))),
                            ("ebp_before".to_string(), json!(format!("{ebp_before:#x}"))),
                            ("esp_before".to_string(), json!(format!("{rsp_before:#x}"))),
                        ]),
                        json!(format!("{map_this:#x}")),
                    );
                    runtime.steam_4ae970_probe_count += 1;
                }
            }
            // All per-block diagnostic writes removed for performance.
            let consumed_instructions = cached_block.translated.decoded.len().max(1) as u64;
            advance_runtime_steps(
                runtime,
                &mut steps,
                instruction_budget,
                consumed_instructions,
                memory,
                state,
                test_id,
            )?;
            let _rip_before = state.rip;
            let block_start_rip = cached_block.start_rip;
            let _block_end_rip = cached_block.end_rip;
            let continue_after_execute = match runtime.execute_ir_with_guest_exception_delivery(
                // Note: execute already timed via t2/t3 below
                engine,
                state,
                memory,
                &cached_block.translated.ir,
                test_id,
            ) {
                Ok(should_continue) => should_continue,
                Err(error) => {
                    let mut wrapped = annotate_guest_fault(error, memory, state);
                    let current_block_detail = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    wrapped = wrapped.with_hint(format!(
                    "guest-crash-context mapped_base={:#x} rip={:#x} block_start_rva={:#x} block_end_rva={:#x} decoded {}",
                    runtime.mapped_image_base,
                    state.rip,
                    cached_block.start_rip.saturating_sub(runtime.mapped_image_base),
                    cached_block.end_rip.saturating_sub(runtime.mapped_image_base),
                    current_block_detail,
                ));
                    if !runtime.steam_401389_recent_blocks.is_empty() {
                        wrapped = wrapped.with_hint(format!(
                            "steam-401389 recent-blocks {}",
                            runtime
                                .steam_401389_recent_blocks
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" || ")
                        ));
                    }
                    if let Some(block) = runtime.steam_401389_first_over_0x1000.as_deref() {
                        wrapped =
                            wrapped.with_hint(format!("steam-401389 first-over-0x1000 {block}"));
                    }
                    if let Some(mode) = runtime.configured_narrow_argv_mode {
                        wrapped =
                            wrapped.with_hint(format!("crt-configure-narrow-argv mode={mode:#x}"));
                    }
                    if !runtime.module_paths_by_handle.is_empty() {
                        wrapped = wrapped.with_hint(format!(
                            "loaded-modules {}",
                            runtime
                                .module_paths_by_handle
                                .iter()
                                .map(|(handle, path)| format!("{handle:#x}={path}"))
                                .collect::<Vec<_>>()
                                .join(" || ")
                        ));
                    }
                    if !runtime.steam_565af0_recent_blocks.is_empty() {
                        wrapped = wrapped.with_hint(format!(
                            "steam-565af0 recent-blocks {}",
                            runtime
                                .steam_565af0_recent_blocks
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" || ")
                        ));
                    }
                    return Err(wrapped);
                }
            };

            // --- Adaptive tiered compilation ---
            // Hot blocks (>= 50 dispatches) are compiled to MAP_JIT native
            // code and executed through execute_with_jit.  The tiered
            // compiler only promotes when the JIT runtime exists (jit_mode
            // Enabled, or Auto on a capable, non-deterministic run); otherwise
            // this stays a cheap counter.  A promotion carries the target
            // tier so the block is recompiled with the real optimizer
            // (constant folding at Tier1, loop unrolling at Tier2) instead of
            // returning identical Tier0 code.
            let promotion_start = cached_block.start_rip;
            let promotion = runtime.tiered_compiler.record_execution(promotion_start);
            let function_blocks = if promotion == Some(crate::jit::CompilationTier::Tier2) {
                collect_tier2_function_blocks(&runtime.basic_block_cache, promotion_start)
            } else {
                None
            };
            if let Some(jit) = runtime.jit_runtime.as_mut() {
                let mut promoted_function = false;
                if let Some(blocks) = function_blocks.as_ref() {
                    if let Ok(Some(_)) =
                        jit.get_or_compile_function_tier2(blocks, engine.config.arch)
                    {
                        promoted_function = true;
                    }
                }
                if let Some(tier) = promotion {
                    if !promoted_function {
                        let ir = &cached_block.translated.ir;
                        let _ = jit.get_or_compile_at_tier(
                            ir,
                            promotion_start,
                            engine.config.arch,
                            tier,
                            None,
                        );
                    }
                    // Sync updated unwind info to the SEH subsystem so that
                    // RtlVirtualUnwind can find newly compiled JIT blocks.
                    if jit.is_unwind_dirty() {
                        jit.unwind_table.register_with_seh(&mut runtime.seh);
                    }
                }
            }

            if runtime.enable_steam_tracing {
                if let Some(block_label) = steam_convar_precise_watch {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let steam_convar_precise_vector_after = steam_convar_precise_this_before
                        .and_then(|this_ptr| this_ptr.checked_add(0x84))
                        .and_then(|vector_ptr| read_window(memory, vector_ptr, 0x14).ok())
                        .map(|bytes| decode_steam_convar_vector_fields(&bytes));
                    let steam_convar_precise_field_94_after = steam_convar_precise_this_before
                        .and_then(|this_ptr| {
                            read_guest_u32(memory, this_ptr + 0x94).ok().map(u64::from)
                        });
                    runtime.push_trace(
                        "process",
                        "SteamConVarVectorState",
                        BTreeMap::from([
                            ("block_rva".to_string(), json!(block_label)),
                            (
                                "this_ptr".to_string(),
                                json!(
                                    steam_convar_precise_this_before
                                        .map(|value| format!("{value:#x}"))
                                ),
                            ),
                            (
                                "field_0x94_before".to_string(),
                                json!(
                                    steam_convar_precise_field_94_before
                                        .map(|value| format!("{value:#x}"))
                                ),
                            ),
                            (
                                "field_0x94_after".to_string(),
                                json!(
                                    steam_convar_precise_field_94_after
                                        .map(|value| format!("{value:#x}"))
                                ),
                            ),
                            (
                                "vector_before".to_string(),
                                json!(steam_convar_precise_vector_before),
                            ),
                            (
                                "vector_after".to_string(),
                                json!(steam_convar_precise_vector_after),
                            ),
                            (
                                "recent_main_block_rvas".to_string(),
                                json!(
                                    runtime
                                        .recent_main_block_rvas
                                        .iter()
                                        .map(|value| format!("{value:#x}"))
                                        .collect::<Vec<_>>()
                                ),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                // Track writes to Steam's global state variables (0x45715c, 0x457620,
                // 0x457624, 0x457628, 0x42a270).  Emit a trace event when a value changes.
                if let Some(steam_global_state_before) = steam_global_state_before {
                    for (address, before_value) in steam_global_state_before {
                        let after_value = probe_read_guest_u32(memory, address);
                        if after_value != before_value {
                            runtime.push_trace(
                                "process",
                                "SteamGlobalWrite",
                                BTreeMap::from([
                                    (
                                        "block_rva".to_string(),
                                        json!(
                                            block_rva
                                                .map(|v| format!("{v:#x}"))
                                                .unwrap_or_else(|| "<non-main>".to_string())
                                        ),
                                    ),
                                    (
                                        "address_rva".to_string(),
                                        json!(format!(
                                            "{:#x}",
                                            address.saturating_sub(runtime.mapped_image_base)
                                        )),
                                    ),
                                    (
                                        "before".to_string(),
                                        json!(
                                            before_value
                                                .map(|v| format!("{v:#x}"))
                                                .unwrap_or_else(|| "<unmapped>".to_string())
                                        ),
                                    ),
                                    (
                                        "after".to_string(),
                                        json!(
                                            after_value
                                                .map(|v| format!("{v:#x}"))
                                                .unwrap_or_else(|| "<unmapped>".to_string())
                                        ),
                                    ),
                                    (
                                        "rip_after_rva".to_string(),
                                        json!(format!(
                                            "{:#x}",
                                            state.rip.saturating_sub(runtime.mapped_image_base)
                                        )),
                                    ),
                                ]),
                                json!(after_value.unwrap_or(0)),
                            );
                        }
                    }
                }
            }
            if continue_after_execute {
                continue;
            }
            if runtime.enable_steam_tracing {
                if let Some(final_assert_globals_before) = final_assert_globals_before {
                    for (address, before_value) in final_assert_globals_before {
                        let after_value = probe_read_guest_u32(memory, address);
                        if after_value != before_value {
                            let stack_return_addr =
                                probe_read_guest_u32(memory, state.get(Register::Rsp))
                                    .map(u64::from);
                            let decoded_instructions = cached_block
                                .translated
                                .decoded
                                .iter()
                                .map(|instruction| {
                                    format!(
                                        "{:#x}:{:?} {:?}",
                                        instruction
                                            .address
                                            .saturating_sub(runtime.mapped_image_base),
                                        instruction.opcode,
                                        instruction.operands
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(" | ");
                            let history_entry = format!(
                                "addr={:#x} block_rva={} return_rva={} before={} after={} decoded=[{}]",
                                address.saturating_sub(runtime.mapped_image_base),
                                block_rva
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<non-main>".to_string()),
                                stack_return_addr
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string()),
                                before_value
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unmapped>".to_string()),
                                after_value
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unmapped>".to_string()),
                                decoded_instructions,
                            );
                            if runtime.steam_final_assert_global_history.len() == 20 {
                                runtime.steam_final_assert_global_history.pop_front();
                            }
                            runtime
                                .steam_final_assert_global_history
                                .push_back(history_entry);
                            runtime.push_trace(
                                "process",
                                "SteamFinalAssertGlobalWrite",
                                BTreeMap::from([
                                    (
                                        "address".to_string(),
                                        json!(format!(
                                            "{:#x}",
                                            address.saturating_sub(runtime.mapped_image_base)
                                        )),
                                    ),
                                    (
                                        "block_rva".to_string(),
                                        json!(
                                            block_rva
                                                .map(|value| format!("{value:#x}"))
                                                .unwrap_or_else(|| "<non-main>".to_string())
                                        ),
                                    ),
                                    ("return_rva".to_string(), json!(stack_return_addr)),
                                    (
                                        "before".to_string(),
                                        json!(
                                            before_value
                                                .map(|value| format!("{value:#x}"))
                                                .unwrap_or_else(|| "<unmapped>".to_string())
                                        ),
                                    ),
                                    (
                                        "after".to_string(),
                                        json!(
                                            after_value
                                                .map(|value| format!("{value:#x}"))
                                                .unwrap_or_else(|| "<unmapped>".to_string())
                                        ),
                                    ),
                                    (
                                        "recent_main_block_rvas".to_string(),
                                        json!(
                                            runtime
                                                .recent_main_block_rvas
                                                .iter()
                                                .map(|value| format!("{value:#x}"))
                                                .collect::<Vec<_>>()
                                        ),
                                    ),
                                ]),
                                json!(decoded_instructions),
                            );
                            if after_value == Some(0x8000_000d) {
                                runtime.push_trace(
                                    "process",
                                    "SteamFinalStatusCode",
                                    BTreeMap::from([
                                        (
                                            "address".to_string(),
                                            json!(format!(
                                                "{:#x}",
                                                address.saturating_sub(runtime.mapped_image_base)
                                            )),
                                        ),
                                        (
                                            "block_rva".to_string(),
                                            json!(
                                                block_rva
                                                    .map(|value| format!("{value:#x}"))
                                                    .unwrap_or_else(|| "<non-main>".to_string())
                                            ),
                                        ),
                                        ("return_rva".to_string(), json!(stack_return_addr)),
                                        (
                                            "before".to_string(),
                                            json!(
                                                before_value
                                                    .map(|value| format!("{value:#x}"))
                                                    .unwrap_or_else(|| "<unmapped>".to_string())
                                            ),
                                        ),
                                        (
                                            "after".to_string(),
                                            json!(
                                                after_value
                                                    .map(|value| format!("{value:#x}"))
                                                    .unwrap_or_else(|| "<unmapped>".to_string())
                                            ),
                                        ),
                                        (
                                            "recent_main_block_rvas".to_string(),
                                            json!(
                                                runtime
                                                    .recent_main_block_rvas
                                                    .iter()
                                                    .map(|value| format!("{value:#x}"))
                                                    .collect::<Vec<_>>()
                                            ),
                                        ),
                                    ]),
                                    json!(decoded_instructions),
                                );
                            }
                        }
                    }
                }
                if trace_steam_136b50_entry {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    runtime.push_trace(
                        "process",
                        "SteamLateGate136b50Entry",
                        BTreeMap::from([
                            ("block_rva".to_string(), json!("0x136b50")),
                            (
                                "arg0".to_string(),
                                json!(format_opt(steam_136b50_arg0_before)),
                            ),
                            (
                                "arg1".to_string(),
                                json!(format_opt(steam_136b50_arg1_before)),
                            ),
                            (
                                "global_0x423fbc_before".to_string(),
                                json!(format_opt(steam_136b50_global_423fbc_before)),
                            ),
                            (
                                "global_0x423fb8_before".to_string(),
                                json!(format_opt(steam_136b50_global_423fb8_before)),
                            ),
                            (
                                "global_0x423a30_before".to_string(),
                                json!(format_opt(steam_136b50_global_423a30_before)),
                            ),
                            (
                                "global_0x423a38_before".to_string(),
                                json!(format_opt(steam_136b50_global_423a38_before)),
                            ),
                            (
                                "eax_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "rip_after".to_string(),
                                json!(format!(
                                    "{:#x}",
                                    state.rip.saturating_sub(runtime.mapped_image_base)
                                )),
                            ),
                            (
                                "recent_main_block_rvas".to_string(),
                                json!(
                                    runtime
                                        .recent_main_block_rvas
                                        .iter()
                                        .map(|value| format!("{value:#x}"))
                                        .collect::<Vec<_>>()
                                ),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                if trace_steam_136e80_entry {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let args_before =
                        steam_136e80_args_before.unwrap_or([None, None, None, None, None]);
                    runtime.push_trace(
                        "process",
                        "SteamLateGate136e80Entry",
                        BTreeMap::from([
                            ("block_rva".to_string(), json!("0x136e80")),
                            ("arg0".to_string(), json!(format_opt(args_before[0]))),
                            ("arg1".to_string(), json!(format_opt(args_before[1]))),
                            ("arg2".to_string(), json!(format_opt(args_before[2]))),
                            ("arg3".to_string(), json!(format_opt(args_before[3]))),
                            ("arg4".to_string(), json!(format_opt(args_before[4]))),
                            (
                                "global_0x423e4c_before".to_string(),
                                json!(format_opt(steam_136e80_global_423e4c_before)),
                            ),
                            (
                                "global_0x423e6c_before".to_string(),
                                json!(format_opt(steam_136e80_global_423e6c_before)),
                            ),
                            (
                                "tls_index_before".to_string(),
                                json!(format_opt(steam_136e80_tls_index_before)),
                            ),
                            (
                                "tls_vector_before".to_string(),
                                json!(format_opt(steam_136e80_tls_vector_before)),
                            ),
                            (
                                "tls_slot_before".to_string(),
                                json!(format_opt(steam_136e80_tls_slot_before)),
                            ),
                            (
                                "tls_slot_plus_0x480_before".to_string(),
                                json!(format_opt(steam_136e80_tls_slot_480_before)),
                            ),
                            (
                                "eax_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "rip_after".to_string(),
                                json!(format!(
                                    "{:#x}",
                                    state.rip.saturating_sub(runtime.mapped_image_base)
                                )),
                            ),
                            (
                                "recent_main_block_rvas".to_string(),
                                json!(
                                    runtime
                                        .recent_main_block_rvas
                                        .iter()
                                        .map(|value| format!("{value:#x}"))
                                        .collect::<Vec<_>>()
                                ),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                if trace_steam_memstd_oom_entry {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    runtime.push_trace(
                        "process",
                        "SteamMemstdOomEntry",
                        BTreeMap::from([
                            ("block_rva".to_string(), json!("0x134bd0")),
                            (
                                "caller_rva".to_string(),
                                json!(
                                    steam_memstd_oom_return_rva_before
                                        .map(|value| format!("{value:#x}"))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "requested_size".to_string(),
                                json!(format_opt(steam_memstd_oom_size_before)),
                            ),
                            (
                                "this_ptr".to_string(),
                                json!(format_opt(steam_memstd_oom_this_before)),
                            ),
                            (
                                "eax_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "rip_after".to_string(),
                                json!(format!(
                                    "{:#x}",
                                    state.rip.saturating_sub(runtime.mapped_image_base)
                                )),
                            ),
                            (
                                "recent_main_block_rvas".to_string(),
                                json!(
                                    runtime
                                        .recent_main_block_rvas
                                        .iter()
                                        .map(|value| format!("{value:#x}"))
                                        .collect::<Vec<_>>()
                                ),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                if trace_steam_memstd_oom_caller {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    runtime.push_trace(
                        "process",
                        "SteamMemstdOomCaller",
                        BTreeMap::from([
                            ("block_rva".to_string(), json!("0x134b56")),
                            (
                                "this_ptr".to_string(),
                                json!(format_opt(steam_memstd_caller_this_before)),
                            ),
                            (
                                "old_address".to_string(),
                                json!(format_opt(steam_memstd_caller_old_address_before)),
                            ),
                            (
                                "requested_size".to_string(),
                                json!(format_opt(steam_memstd_caller_requested_size_before)),
                            ),
                            (
                                "mode".to_string(),
                                json!(format_opt(steam_memstd_caller_mode_before)),
                            ),
                            (
                                "range1_table".to_string(),
                                json!(format_opt(steam_memstd_caller_range1_table_before)),
                            ),
                            (
                                "range2_table".to_string(),
                                json!(format_opt(steam_memstd_caller_range2_table_before)),
                            ),
                            (
                                "recent_main_block_rvas".to_string(),
                                json!(
                                    runtime
                                        .recent_main_block_rvas
                                        .iter()
                                        .map(|value| format!("{value:#x}"))
                                        .collect::<Vec<_>>()
                                ),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                if steam_global_array_watch {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let steam_global_array_count_after =
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7624)
                            .map(u64::from);
                    let steam_global_array_ptr_after =
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7628)
                            .map(u64::from);
                    // The push_trace below already captures the full lifecycle data.
                    runtime.push_trace(
                        "process",
                        "SteamGlobalArrayLifecycle",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva
                                        .map(|value| format!("{value:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            (
                                "return_rva".to_string(),
                                json!(
                                    steam_global_array_return_before
                                        .map(|value| format!("{value:#x}"))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "count_before".to_string(),
                                json!(format_opt(steam_global_array_count_before)),
                            ),
                            (
                                "ptr_before".to_string(),
                                json!(format_opt(steam_global_array_ptr_before)),
                            ),
                            (
                                "count_after".to_string(),
                                json!(format_opt(steam_global_array_count_after)),
                            ),
                            (
                                "ptr_after".to_string(),
                                json!(format_opt(steam_global_array_ptr_after)),
                            ),
                            (
                                "eax_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "esi_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsi))),
                            ),
                            (
                                "edi_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rdi))),
                            ),
                            (
                                "esp_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsp))),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                if steam_early_termination_watch {
                    runtime.push_trace(
                        "process",
                        "SteamEarlyTermination",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            (
                                "return_rva".to_string(),
                                json!(
                                    steam_early_termination_return_before
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "eax".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "ebx".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rbx))),
                            ),
                            (
                                "esi".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsi))),
                            ),
                            (
                                "edi".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rdi))),
                            ),
                            (
                                "esp".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsp))),
                            ),
                        ]),
                        json!(state.get(Register::Rax)),
                    );
                }
                if steam_initterm_e_watch {
                    runtime.push_trace(
                        "process",
                        "SteamInittermE",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            (
                                "start".to_string(),
                                json!(
                                    steam_initterm_e_start_before
                                        .map(|v| format!(
                                            "{:#x}",
                                            v.saturating_sub(runtime.mapped_image_base)
                                        ))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "end".to_string(),
                                json!(
                                    steam_initterm_e_end_before
                                        .map(|v| format!(
                                            "{:#x}",
                                            v.saturating_sub(runtime.mapped_image_base)
                                        ))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "esi".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsi))),
                            ),
                            (
                                "edi".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rdi))),
                            ),
                            (
                                "eax".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                        ]),
                        json!(state.get(Register::Rax)),
                    );
                }
                if steam_startup_init_watch {
                    runtime.push_trace(
                        "process",
                        "SteamStartupInit",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            (
                                "eax".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "ecx".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rcx))),
                            ),
                            (
                                "state_0x45715c".to_string(),
                                json!(
                                    probe_read_guest_u32(
                                        memory,
                                        runtime.mapped_image_base + 0x0045_715c
                                    )
                                    .map(|v| format!("{v:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "esp".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsp))),
                            ),
                        ]),
                        json!(state.get(Register::Rax)),
                    );
                }
                if steam_startup_failure_watch {
                    runtime.push_trace(
                        "process",
                        "SteamStartupFailure",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            (
                                "eax".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            (
                                "esi".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsi))),
                            ),
                            (
                                "state_0x45715c".to_string(),
                                json!(
                                    probe_read_guest_u32(
                                        memory,
                                        runtime.mapped_image_base + 0x0045_715c
                                    )
                                    .map(|v| format!("{v:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "esp".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsp))),
                            ),
                        ]),
                        json!(state.get(Register::Rax)),
                    );
                }
                if let Some((
                    block_rva_before,
                    counter_before,
                    rsp_before,
                    eax_before,
                    ecx_before,
                )) = steam_owner_allocator_probe_before
                {
                    let counter_before_str = counter_before
                        .map(|value| format!("{value:#x}"))
                        .unwrap_or_else(|| "<unavailable>".to_string());
                    let counter_after_str =
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x003c_873c)
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string());
                    runtime.push_trace(
                        "process",
                        "SteamOwnerAllocator",
                        BTreeMap::from([
                            (
                                "block_rva".to_string(),
                                json!(
                                    block_rva_before
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<non-main>".to_string())
                                ),
                            ),
                            ("counter_before".to_string(), json!(counter_before_str)),
                            ("counter_after".to_string(), json!(counter_after_str)),
                            ("eax_before".to_string(), json!(format!("{eax_before:#x}"))),
                            (
                                "eax_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax))),
                            ),
                            ("ecx_before".to_string(), json!(format!("{ecx_before:#x}"))),
                            (
                                "ecx_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rcx))),
                            ),
                            ("esp_before".to_string(), json!(format!("{rsp_before:#x}"))),
                            (
                                "esp_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rsp))),
                            ),
                        ]),
                        json!(state.get(Register::Rax)),
                    );
                    runtime.steam_owner_allocator_probe_count += 1;
                }
                if let Some((entry, callback, unwind)) = steam_callback_walk_entry_before {
                    let get_process_heap_slot = runtime.mapped_image_base + 0x002e_230c;
                    let get_process_heap_target = if callback
                        == Some(runtime.mapped_image_base + 0x0016_b18c)
                    {
                        read_guest_pointer(memory, get_process_heap_slot, runtime.guest_arch).ok()
                    } else {
                        None
                    };
                    let get_process_heap_binding = get_process_heap_target.and_then(|target| {
                        runtime
                            .host_thunks
                            .get(&target)
                            .map(|thunk| format!("{thunk:?}"))
                    });
                    runtime.push_trace(
                        "process",
                        "SteamCallbackWalk",
                        BTreeMap::from([
                            ("entry".to_string(), json!(format!("{entry:#x}"))),
                            (
                                "callback".to_string(),
                                json!(
                                    callback
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "unwind".to_string(),
                                json!(
                                    unwind
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<unavailable>".to_string())
                                ),
                            ),
                            (
                                "al_after".to_string(),
                                json!(format!("{:#x}", state.get(Register::Rax) & 0xff)),
                            ),
                            (
                                "next_rva".to_string(),
                                json!(format!(
                                    "{:#x}",
                                    state.rip.saturating_sub(runtime.mapped_image_base)
                                )),
                            ),
                            (
                                "get_process_heap_target".to_string(),
                                json!(
                                    get_process_heap_target
                                        .map(|v| format!("{v:#x}"))
                                        .unwrap_or_else(|| "<n/a>".to_string())
                                ),
                            ),
                            (
                                "get_process_heap_binding".to_string(),
                                json!(
                                    get_process_heap_binding.unwrap_or_else(|| "<n/a>".to_string())
                                ),
                            ),
                        ]),
                        json!(state.get(Register::Rax) & 0xff),
                    );
                }
                if steam_post_577113_watch {
                    let decoded_detail: Vec<String> = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|inst| {
                            let rva = inst.address.saturating_sub(runtime.mapped_image_base);
                            format!("{rva:#x}:{:?} {:?}", inst.opcode, inst.operands)
                        })
                        .collect();
                    emit_live_ui_debug(format!(
                        "steam-post-577113 block_rva={} eax={:#x} esi={:#x} edi={:#x} arg_obj={} heap_handle={} rsp={:#x} decoded=[{}]",
                        block_rva
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<non-main>".to_string()),
                        state.get(Register::Rax),
                        state.get(Register::Rsi),
                        state.get(Register::Rdi),
                        probe_read_guest_u32(memory, state.get(Register::Rsp) + 4)
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7664)
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        state.get(Register::Rsp),
                        decoded_detail.join(" | "),
                    ));
                }
                if steam_post_56ee10_watch {
                    let decoded_detail: Vec<String> = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|inst| {
                            let rva = inst.address.saturating_sub(runtime.mapped_image_base);
                            format!("{rva:#x}:{:?} {:?}", inst.opcode, inst.operands)
                        })
                        .collect();
                    emit_live_ui_debug(format!(
                        "steam-post-56ee10 eax={:#x} edi={:#x} esi={:#x} ebx={:#x} heap_handle={} rsp={:#x} decoded=[{}]",
                        state.get(Register::Rax),
                        state.get(Register::Rdi),
                        state.get(Register::Rsi),
                        state.get(Register::Rbx),
                        probe_read_guest_u32(memory, runtime.mapped_image_base + 0x0045_7664)
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        state.get(Register::Rsp),
                        decoded_detail.join(" | "),
                    ));
                }
                if steam_post_576ca8_watch || steam_post_576d7e_watch {
                    let decoded_detail: Vec<String> = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|inst| {
                            let rva = inst.address.saturating_sub(runtime.mapped_image_base);
                            format!("{rva:#x}:{:?} {:?}", inst.opcode, inst.operands)
                        })
                        .collect();
                    emit_live_ui_debug(format!(
                        "steam-post-helper block_rva={} rsp={:#x} stack0={} stack1={} stack2={} edi={:#x} esi={:#x} ebx={:#x} decoded=[{}]",
                        block_rva
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<non-main>".to_string()),
                        state.get(Register::Rsp),
                        probe_read_guest_u32(memory, state.get(Register::Rsp))
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        probe_read_guest_u32(memory, state.get(Register::Rsp) + 4)
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        probe_read_guest_u32(memory, state.get(Register::Rsp) + 8)
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        state.get(Register::Rdi),
                        state.get(Register::Rsi),
                        state.get(Register::Rbx),
                        decoded_detail.join(" | "),
                    ));
                }
                if let Some((rsp_before, stack0, stack1, stack2, stack3, edi_before, esi_before)) =
                    steam_577113_epilogue_before
                {
                    emit_live_ui_debug(format!(
                        "steam-577113-epilogue rsp_before={:#x} stack0={} stack1={} stack2={} stack3={} edi_before={:#x} esi_before={:#x} rsp_after={:#x} edi_after={:#x} esi_after={:#x}",
                        rsp_before,
                        stack0
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        stack1
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        stack2
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        stack3
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string()),
                        edi_before,
                        esi_before,
                        state.get(Register::Rsp),
                        state.get(Register::Rdi),
                        state.get(Register::Rsi),
                    ));
                }
                if let Some(saved_edi_before) = steam_saved_edi_slot_before {
                    let saved_edi_after = probe_read_guest_u32(memory, 0x7000_ff1c).map(u64::from);
                    if saved_edi_after != Some(saved_edi_before) {
                        runtime.push_trace(
                            "process",
                            "SteamSavedEdiSlotWrite",
                            BTreeMap::from([
                                (
                                    "block_rva".to_string(),
                                    json!(
                                        block_rva
                                            .map(|v| format!("{v:#x}"))
                                            .unwrap_or_else(|| "<non-main>".to_string())
                                    ),
                                ),
                                (
                                    "before".to_string(),
                                    json!(format!("{saved_edi_before:#x}")),
                                ),
                                (
                                    "after".to_string(),
                                    json!(
                                        saved_edi_after
                                            .map(|v| format!("{v:#x}"))
                                            .unwrap_or_else(|| "<unavailable>".to_string())
                                    ),
                                ),
                                (
                                    "rsp".to_string(),
                                    json!(format!("{:#x}", state.get(Register::Rsp))),
                                ),
                                (
                                    "rbp".to_string(),
                                    json!(format!("{:#x}", state.get(Register::Rbp))),
                                ),
                            ]),
                            json!(saved_edi_before),
                        );
                    }
                }
                if trace_steam_convar_create || trace_steam_convar_create_start {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let read_c_string_opt = |ptr: Option<u64>| {
                        ptr.and_then(|ptr| {
                            if ptr == 0 {
                                Some(String::new())
                            } else {
                                read_c_string(memory, ptr).ok()
                            }
                        })
                        .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let vector_fields = steam_convar_vector_bytes_before.map(|bytes| {
                        let read_u32_at = |offset: usize| -> u64 {
                            u64::from(u32::from_le_bytes(
                                bytes[offset..offset + 4].try_into().unwrap(),
                            ))
                        };
                        BTreeMap::from([
                            (
                                "element_size".to_string(),
                                json!(format!("{:#x}", read_u32_at(0))),
                            ),
                            (
                                "memory_ptr".to_string(),
                                json!(format!("{:#x}", read_u32_at(4))),
                            ),
                            (
                                "allocation_count".to_string(),
                                json!(format!("{:#x}", read_u32_at(8))),
                            ),
                            (
                                "grow_size".to_string(),
                                json!(format!("{:#x}", read_u32_at(12))),
                            ),
                            (
                                "count".to_string(),
                                json!(format!("{:#x}", read_u32_at(16))),
                            ),
                        ])
                    });
                    let mut parameters = BTreeMap::from([
                        (
                            "block_rva".to_string(),
                            json!(if trace_steam_convar_create_start {
                                "0xcc400"
                            } else {
                                "0xcc542"
                            }),
                        ),
                        (
                            "this_ptr".to_string(),
                            json!(format_opt(steam_convar_this_before)),
                        ),
                        (
                            "frame_ptr".to_string(),
                            json!(format_opt(steam_convar_frame_before)),
                        ),
                        (
                            "name_ptr".to_string(),
                            json!(format_opt(steam_convar_name_ptr_before)),
                        ),
                        (
                            "name".to_string(),
                            json!(read_c_string_opt(steam_convar_name_ptr_before)),
                        ),
                        (
                            "flags".to_string(),
                            json!(format_opt(steam_convar_flags_before)),
                        ),
                        (
                            "help_ptr".to_string(),
                            json!(format_opt(steam_convar_help_ptr_before)),
                        ),
                        (
                            "help".to_string(),
                            json!(read_c_string_opt(steam_convar_help_ptr_before)),
                        ),
                        (
                            "parent_ptr".to_string(),
                            json!(format_opt(steam_convar_parent_ptr_before)),
                        ),
                        (
                            "callback_ptr".to_string(),
                            json!(format_opt(steam_convar_callback_ptr_before)),
                        ),
                        (
                            "vector_ptr".to_string(),
                            json!(format_opt(steam_convar_vector_ptr_before)),
                        ),
                        (
                            "recent_main_block_rvas".to_string(),
                            json!(
                                runtime
                                    .recent_main_block_rvas
                                    .iter()
                                    .map(|value| format!("{value:#x}"))
                                    .collect::<Vec<_>>()
                            ),
                        ),
                    ]);
                    if let Some(vector_fields) = vector_fields {
                        parameters.insert("vector_fields".to_string(), json!(vector_fields));
                    }
                    runtime.push_trace(
                        "process",
                        if trace_steam_convar_create_start {
                            "SteamConVarCreateStart"
                        } else {
                            "SteamConVarCreateEntry"
                        },
                        parameters,
                        json!(decoded_instructions),
                    );
                }
                if let Some(helper_rva) = steam_convar_helper_watch {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let vector_fields = steam_convar_helper_vector_bytes_before.map(|bytes| {
                        let read_u32_at = |offset: usize| -> u64 {
                            u64::from(u32::from_le_bytes(
                                bytes[offset..offset + 4].try_into().unwrap(),
                            ))
                        };
                        BTreeMap::from([
                            (
                                "element_size".to_string(),
                                json!(format!("{:#x}", read_u32_at(0))),
                            ),
                            (
                                "memory_ptr".to_string(),
                                json!(format!("{:#x}", read_u32_at(4))),
                            ),
                            (
                                "allocation_count".to_string(),
                                json!(format!("{:#x}", read_u32_at(8))),
                            ),
                            (
                                "grow_size".to_string(),
                                json!(format!("{:#x}", read_u32_at(12))),
                            ),
                            (
                                "count".to_string(),
                                json!(format!("{:#x}", read_u32_at(16))),
                            ),
                        ])
                    });
                    let mut parameters = BTreeMap::from([
                        ("helper_rva".to_string(), json!(helper_rva)),
                        (
                            "this_ptr".to_string(),
                            json!(format_opt(steam_convar_helper_this_before)),
                        ),
                        (
                            "vector_ptr".to_string(),
                            json!(format_opt(steam_convar_helper_vector_ptr_before)),
                        ),
                        (
                            "arg0".to_string(),
                            json!(format_opt(steam_convar_helper_arg0_before)),
                        ),
                        (
                            "arg1".to_string(),
                            json!(format_opt(steam_convar_helper_arg1_before)),
                        ),
                        (
                            "arg2".to_string(),
                            json!(format_opt(steam_convar_helper_arg2_before)),
                        ),
                        (
                            "return_rva".to_string(),
                            json!(
                                steam_convar_helper_return_before
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            ),
                        ),
                        (
                            "recent_main_block_rvas".to_string(),
                            json!(
                                runtime
                                    .recent_main_block_rvas
                                    .iter()
                                    .map(|value| format!("{value:#x}"))
                                    .collect::<Vec<_>>()
                            ),
                        ),
                    ]);
                    if let Some(vector_fields) = vector_fields {
                        parameters.insert("vector_fields".to_string(), json!(vector_fields));
                    }
                    runtime.push_trace(
                        "process",
                        "SteamConVarHelperEntry",
                        parameters,
                        json!(decoded_instructions),
                    );
                }
                if let Some(block_label) = steam_convar_memcpy_byte_watch {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let vector_fields = steam_convar_memcpy_byte_vector_bytes_before.map(|bytes| {
                        let read_u32_at = |offset: usize| -> u64 {
                            u64::from(u32::from_le_bytes(
                                bytes[offset..offset + 4].try_into().unwrap(),
                            ))
                        };
                        BTreeMap::from([
                            (
                                "element_size".to_string(),
                                json!(format!("{:#x}", read_u32_at(0))),
                            ),
                            (
                                "memory_ptr".to_string(),
                                json!(format!("{:#x}", read_u32_at(4))),
                            ),
                            (
                                "allocation_count".to_string(),
                                json!(format!("{:#x}", read_u32_at(8))),
                            ),
                            (
                                "grow_size".to_string(),
                                json!(format!("{:#x}", read_u32_at(12))),
                            ),
                            (
                                "count".to_string(),
                                json!(format!("{:#x}", read_u32_at(16))),
                            ),
                        ])
                    });
                    let mut parameters = BTreeMap::from([
                        ("block_rva".to_string(), json!(block_label)),
                        (
                            "this_ptr".to_string(),
                            json!(format_opt(steam_convar_memcpy_byte_this_before)),
                        ),
                        (
                            "vector_ptr".to_string(),
                            json!(format_opt(steam_convar_memcpy_byte_vector_ptr_before)),
                        ),
                        (
                            "eax".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rax))),
                        ),
                        (
                            "ecx".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rcx))),
                        ),
                        (
                            "edx".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rdx))),
                        ),
                        (
                            "edi".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rdi))),
                        ),
                        (
                            "recent_main_block_rvas".to_string(),
                            json!(
                                runtime
                                    .recent_main_block_rvas
                                    .iter()
                                    .map(|value| format!("{value:#x}"))
                                    .collect::<Vec<_>>()
                            ),
                        ),
                    ]);
                    if let Some(vector_fields) = vector_fields {
                        parameters.insert("vector_fields".to_string(), json!(vector_fields));
                    }
                    runtime.push_trace(
                        "process",
                        "SteamConVarMemcpyByteBlock",
                        parameters,
                        json!(decoded_instructions),
                    );
                }
                if let Some(block_label) = steam_convar_memcpy_return_watch {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let vector_fields =
                        steam_convar_memcpy_return_vector_bytes_before.map(|bytes| {
                            let read_u32_at = |offset: usize| -> u64 {
                                u64::from(u32::from_le_bytes(
                                    bytes[offset..offset + 4].try_into().unwrap(),
                                ))
                            };
                            BTreeMap::from([
                                (
                                    "element_size".to_string(),
                                    json!(format!("{:#x}", read_u32_at(0))),
                                ),
                                (
                                    "memory_ptr".to_string(),
                                    json!(format!("{:#x}", read_u32_at(4))),
                                ),
                                (
                                    "allocation_count".to_string(),
                                    json!(format!("{:#x}", read_u32_at(8))),
                                ),
                                (
                                    "grow_size".to_string(),
                                    json!(format!("{:#x}", read_u32_at(12))),
                                ),
                                (
                                    "count".to_string(),
                                    json!(format!("{:#x}", read_u32_at(16))),
                                ),
                            ])
                        });
                    let mut parameters = BTreeMap::from([
                        ("block_rva".to_string(), json!(block_label)),
                        (
                            "this_ptr".to_string(),
                            json!(format_opt(steam_convar_memcpy_return_this_before)),
                        ),
                        (
                            "vector_ptr".to_string(),
                            json!(format_opt(steam_convar_memcpy_return_vector_ptr_before)),
                        ),
                        (
                            "eax".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rax))),
                        ),
                        (
                            "ecx".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rcx))),
                        ),
                        (
                            "edx".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rdx))),
                        ),
                        (
                            "esi".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rsi))),
                        ),
                        (
                            "edi".to_string(),
                            json!(format!("{:#x}", state.get(Register::Rdi))),
                        ),
                        (
                            "recent_main_block_rvas".to_string(),
                            json!(
                                runtime
                                    .recent_main_block_rvas
                                    .iter()
                                    .map(|value| format!("{value:#x}"))
                                    .collect::<Vec<_>>()
                            ),
                        ),
                    ]);
                    if let Some(vector_fields) = vector_fields {
                        parameters.insert("vector_fields".to_string(), json!(vector_fields));
                    }
                    runtime.push_trace(
                        "process",
                        "SteamConVarMemcpyReturnBlock",
                        parameters,
                        json!(decoded_instructions),
                    );
                }
                if trace_steam_vector_grow_request {
                    let decoded_instructions = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| {
                            format!(
                                "{:#x}:{:?} {:?}",
                                instruction
                                    .address
                                    .saturating_sub(runtime.mapped_image_base),
                                instruction.opcode,
                                instruction.operands
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let format_opt = |value: Option<u64>| {
                        value
                            .map(|value| format!("{value:#x}"))
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let requested_bytes = match (
                        steam_vector_element_size_before,
                        steam_vector_capacity_before,
                    ) {
                        (Some(element_size), Some(capacity)) => element_size.checked_mul(capacity),
                        _ => None,
                    };
                    let owner_ptr_candidate = steam_vector_this_before
                        .and_then(|vector_ptr| vector_ptr.checked_sub(0x84));
                    runtime.push_trace(
                        "process",
                        "SteamVectorGrowRequest",
                        BTreeMap::from([
                            ("block_rva".to_string(), json!("0x9968b")),
                            (
                                "vector_ptr".to_string(),
                                json!(format_opt(steam_vector_this_before)),
                            ),
                            (
                                "owner_ptr_candidate".to_string(),
                                json!(format_opt(owner_ptr_candidate)),
                            ),
                            (
                                "old_address".to_string(),
                                json!(format_opt(steam_vector_old_address_before)),
                            ),
                            (
                                "element_size".to_string(),
                                json!(format_opt(steam_vector_element_size_before)),
                            ),
                            (
                                "capacity".to_string(),
                                json!(format_opt(steam_vector_capacity_before)),
                            ),
                            (
                                "grow_size".to_string(),
                                json!(format_opt(steam_vector_grow_size_before)),
                            ),
                            (
                                "count".to_string(),
                                json!(format_opt(steam_vector_count_before)),
                            ),
                            (
                                "requested_bytes".to_string(),
                                json!(format_opt(requested_bytes)),
                            ),
                            (
                                "recent_main_block_rvas".to_string(),
                                json!(
                                    runtime
                                        .recent_main_block_rvas
                                        .iter()
                                        .map(|value| format!("{value:#x}"))
                                        .collect::<Vec<_>>()
                                ),
                            ),
                        ]),
                        json!(decoded_instructions),
                    );
                }
                if guest_arch == GuestArch::X86
                    && runtime.steam_401389_expected_esi_after_401434.is_some()
                    && runtime.steam_401389_saved_esi_slot_addr.is_none()
                    && let Some(expected_esi) = runtime.steam_401389_expected_esi_after_401434
                {
                    let candidate = state.get(Register::Rbp).wrapping_sub(0x2b8);
                    if read_guest_u32(memory, candidate).ok() == Some(expected_esi) {
                        runtime.steam_401389_saved_esi_slot_addr = Some(candidate);
                    }
                }
                if let Some((watched_address, before_value)) = watched_esi_slot_before
                    && let Ok(after_value) = read_guest_u32(memory, watched_address)
                    && after_value != before_value
                {
                    let decoded_addresses = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| format!("{:#x}", instruction.address))
                        .collect::<Vec<_>>()
                        .join(",");
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401434 overwrote saved ESI slot at {watched_address:#x} from {before_value:#x} to {after_value:#x} while executing block {block_start_rip:#x} addrs=[{decoded_addresses}]"
                        ),
                    ));
                }
                if steam_install_dir_set_edi {
                    let expected_edi = runtime.mapped_image_base + 0x003d_6168;
                    let actual_edi = state.get(Register::Rdi);
                    runtime.steam_install_dir_expected_edi = Some(expected_edi);
                    if actual_edi != expected_edi {
                        let decoded_addresses = cached_block
                            .translated
                            .decoded
                            .iter()
                            .map(|instruction| format!("{:#x}", instruction.address))
                            .collect::<Vec<_>>()
                            .join(",");
                        return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam install-dir setup block failed to leave edi on the relocated install-dir buffer: expected {expected_edi:#x}, actual {actual_edi:#x}"
                        ),
                    )
                    .with_hint(format!(
                        "steam-install-dir set-block={block_start_rip:#x} addrs=[{decoded_addresses}]"
                    )));
                    }
                }
                if touches_steam_401389_helper {
                    let record_base = read_guest_u32(memory, 0x42a270).ok().map(u64::from);
                    let summarize_record = |index: u32| {
                        record_base
                            .map(|base| {
                                let record_address = base + u64::from(index) * 0x1c;
                                let fields = (0..7)
                                    .map(|slot| {
                                        let value =
                                            read_guest_u32(memory, record_address + slot * 4)
                                                .ok()
                                                .map(u64::from)
                                                .unwrap_or(0);
                                        format!("{slot}:{value:#x}")
                                    })
                                    .collect::<Vec<_>>()
                                    .join(",");
                                format!("addr={record_address:#x} fields=[{fields}]")
                            })
                            .unwrap_or_else(|| "<unavailable>".to_string())
                    };
                    let decoded_addresses = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| format!("{:#x}", instruction.address))
                        .collect::<Vec<_>>()
                        .join(",");
                    let esi_after = state.get(Register::Rsi) as u32;
                    let helper_arg = read_guest_u32(memory, state.get(Register::Rsp) + 8)
                        .ok()
                        .map(u64::from)
                        .map(|value| format!("{value:#x}"))
                        .unwrap_or_else(|| "<unavailable>".to_string());
                    let block_summary = format!(
                        "block_start={block_start_rip:#x} addrs=[{decoded_addresses}] esi_before={esi_before:#x} esi_after={esi_after:#x} eax_after={:#x} helper_arg={} before_record={} after_record={}",
                        state.get(Register::Rax),
                        helper_arg,
                        summarize_record(esi_before),
                        summarize_record(esi_after),
                    );
                    if runtime.steam_401389_first_over_0x1000.is_none() && esi_after >= 0x1000 {
                        runtime.steam_401389_first_over_0x1000 = Some(block_summary.clone());
                    }
                    if runtime.steam_401389_recent_blocks.len() == 4 {
                        runtime.steam_401389_recent_blocks.pop_front();
                    }
                    runtime.steam_401389_recent_blocks.push_back(block_summary);
                }
                if guest_arch == GuestArch::X86 && contains_steam_4013a3 {
                    runtime.steam_401389_expected_esi_after_401434 = Some(esi_before);
                }
                if guest_arch == GuestArch::X86 && contains_steam_4013c0 {
                    let esi_after = state.get(Register::Rsi) as u32;
                    if esi_before < 0x1000 && esi_after >= 0x1000 {
                        let record_base = read_guest_u32(memory, 0x42a270).unwrap_or(0) as u64;
                        let previous_record = if record_base != 0 {
                            let record_address = record_base + u64::from(esi_before) * 0x1c;
                            let fields = (0..7)
                                .map(|slot| {
                                    let value = read_guest_u32(memory, record_address + slot * 4)
                                        .unwrap_or(0)
                                        as u64;
                                    format!("{slot}:{value:#x}")
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("addr={record_address:#x} fields=[{fields}]")
                        } else {
                            "<unavailable>".to_string()
                        };
                        let current_record = if record_base != 0 {
                            let record_address = record_base + u64::from(esi_after) * 0x1c;
                            let fields = (0..7)
                                .map(|slot| {
                                    let value = read_guest_u32(memory, record_address + slot * 4)
                                        .unwrap_or(0)
                                        as u64;
                                    format!("{slot}:{value:#x}")
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("addr={record_address:#x} fields=[{fields}]")
                        } else {
                            "<unavailable>".to_string()
                        };
                        return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401389 transition block {block_start_rip:#x} jumped across 0x1000 from {esi_before:#x} to {esi_after:#x}"
                        ),
                    )
                    .with_hint(format!(
                        "steam-401389 threshold-jump record_base={record_base:#x} previous_record={previous_record} current_record={current_record}"
                    )));
                    }
                    if esi_after > 0x10000 {
                        let record_base = read_guest_u32(memory, 0x42a270).unwrap_or(0) as u64;
                        let previous_record = if record_base != 0 {
                            let record_address = record_base + u64::from(esi_before) * 0x1c;
                            let fields = (0..7)
                                .map(|slot| {
                                    let value = read_guest_u32(memory, record_address + slot * 4)
                                        .unwrap_or(0)
                                        as u64;
                                    format!("{slot}:{value:#x}")
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("addr={record_address:#x} fields=[{fields}]")
                        } else {
                            "<unavailable>".to_string()
                        };
                        return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401389 transition block {block_start_rip:#x} jumped from {esi_before:#x} to large index {esi_after:#x}"
                        ),
                    )
                    .with_hint(format!(
                        "steam-401389 transition record_base={record_base:#x} previous_record={previous_record}"
                    )));
                    }
                }
                if guest_arch == GuestArch::X86 && contains_steam_4013ba {
                    let esi_after = state.get(Register::Rsi) as u32;
                    if esi_before < 0x1000 && esi_after >= 0x1000 {
                        let record_base = read_guest_u32(memory, 0x42a270).unwrap_or(0) as u64;
                        let current_record = if record_base != 0 {
                            let record_address = record_base + u64::from(esi_after) * 0x1c;
                            let fields = (0..7)
                                .map(|slot| {
                                    let value = read_guest_u32(memory, record_address + slot * 4)
                                        .unwrap_or(0)
                                        as u64;
                                    format!("{slot}:{value:#x}")
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("addr={record_address:#x} fields=[{fields}]")
                        } else {
                            "<unavailable>".to_string()
                        };
                        let previous_record = if record_base != 0 {
                            let record_address = record_base + u64::from(esi_before) * 0x1c;
                            let fields = (0..7)
                                .map(|slot| {
                                    let value = read_guest_u32(memory, record_address + slot * 4)
                                        .unwrap_or(0)
                                        as u64;
                                    format!("{slot}:{value:#x}")
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("addr={record_address:#x} fields=[{fields}]")
                        } else {
                            "<unavailable>".to_string()
                        };
                        return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401389 linear scan crossed 0x1000 via inc esi from {esi_before:#x} to {esi_after:#x}"
                        ),
                    )
                    .with_hint(format!(
                        "steam-401389 inc-esi record_base={record_base:#x} previous_record={previous_record} current_record={current_record}"
                    )));
                    }
                }
            }
            let last_instruction = cached_block.translated.decoded.last().ok_or_else(|| {
                AppError::new(ReasonCode::RcUnimplInsn, "translated basic block was empty")
            })?;
            if last_instruction.opcode == DecodedOpcode::Ret {
                if state.rip == 0 {
                    break;
                }
            } else if !instruction_controls_rip(last_instruction.opcode) {
                state.rip = cached_block.end_rip;
            }
        }

        // ── Thread-drain phase after a main-thread exit ─────────────────────
        // `ExitThread`/`_endthreadex`/`_endthread` on the main thread ends only
        // the MAIN thread; Windows ends the process when its LAST thread exits.
        // If guest workers are still pending, keep pumping them to completion
        // (unless a process-exit API was called, which abandons every thread).
        if runtime.main_thread_exit_code.is_some() && !runtime.pending_guest_threads.is_empty() {
            exit_code = runtime.drain_pending_guest_threads_after_main_exit(memory)?;
        }

        // JIT runtime is no longer needed — unregister so the live-session
        // watchdog no longer holds a reference to it.
        crate::jit::unregister_jit_runtime();

        eprintln!(
            "CASA1_LOOP_EXIT: iter={} exit_code={} elapsed_ms={}",
            block_count,
            exit_code,
            start_time.elapsed().as_millis()
        );

        Ok((exit_code, steps, block_count))
    };

    // Run the body; every error is classified into an authoritative
    // ExecutionTermination and finalized — nothing is lost.
    let (exit_code, steps, block_count) = match run_body(
        &mut runtime,
        &mut memory,
        &mut state,
        &mut engine,
        instruction_budget,
    ) {
        Ok((code, steps, block_count)) => (code, steps, block_count),
        Err(error) => {
            let termination = if runtime.unhandled_guest_exception.is_some() {
                // The root cause was an unhandled guest exception; the fault
                // that surfaced afterwards is secondary.
                ExecutionTermination::GuestException
            } else {
                classify_execution_error(&error)
            };
            let detail = Some(error.to_string());
            let exit_code = legacy_exit_code(termination);
            // The error path has no completed step accounting (the budget /
            // deadline errors carry the step count in their message); the
            // rest of the diagnostic state is preserved by the finalizer.
            return finalize_execution(
                runtime,
                &mut memory,
                &image,
                &mapped,
                env,
                dtm,
                image_hash,
                0,
                0,
                start_time,
                exit_code,
                termination,
                detail,
            );
        }
    };
    let termination = if runtime.unhandled_guest_exception.is_some() {
        // An unhandled guest exception (RaiseException with no handler, or
        // an unhandled fault) terminated the process — the structured
        // termination is GuestException, not a normal guest exit.
        ExecutionTermination::GuestException
    } else if RUN_DEADLINE_EXPIRED.load(std::sync::atomic::Ordering::Acquire) && exit_code == -2 {
        ExecutionTermination::HarnessDeadline
    } else {
        ExecutionTermination::GuestExit { code: exit_code }
    };
    let termination_detail = None;

    finalize_execution(
        runtime,
        &mut memory,
        &image,
        &mapped,
        env,
        dtm,
        image_hash,
        steps,
        block_count,
        start_time,
        exit_code,
        termination,
        termination_detail,
    )
}

/// Build the final PeExecutionResult, preserving EVERY piece of diagnostic
/// state: stdout/stderr, guest exceptions, trace events, graphics frames,
/// perf counters, milestones, provenance and the authoritative termination.
/// Every exit path (guest exit, harness deadline, instruction budget,
/// unsupported instruction, guest exception, host error) funnels through
/// here — the runner never reconstructs a synthetic result.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_execution(
    mut runtime: PeHostRuntime,
    _memory: &mut MemoryImage,
    image: &pe::ParsedPe,
    mapped: &pe::MappedImage,
    env: &std::collections::BTreeMap<String, String>,
    dtm: bool,
    image_hash: String,
    steps: u64,
    block_count: u64,
    start_time: std::time::Instant,
    exit_code: i32,
    termination: ExecutionTermination,
    termination_detail: Option<String>,
) -> AppResult<PeExecutionResult> {
    eprintln!(
        "CASA1_LOOP_EXIT: iter={} exit_code={} elapsed_ms={}",
        block_count,
        exit_code,
        start_time.elapsed().as_millis()
    );

    let perf = vec![PerfMetric {
        metric_id: "pe_runtime_steps".to_string(),
        value: steps as f64,
        unit: "instructions".to_string(),
    }];
    runtime.export_final_frame_if_requested(env)?;

    let mut trace_events = vec![trace_event(
        1,
        "process",
        "NtContinue",
        BTreeMap::from([
            ("mode".to_string(), Value::String("pe-runtime".to_string())),
            (
                "entrypoint".to_string(),
                json!(format!(
                    "{:#x}",
                    mapped.selected_base + image.address_of_entry_point as u64
                )),
            ),
        ]),
        json!(exit_code),
        vec![image_hash],
    )];
    trace_events.extend(std::mem::take(&mut runtime.trace_events));

    let (jit_blocks_compiled, jit_blocks_executed) = match &runtime.jit_runtime {
        Some(jit) => (jit.blocks_compiled, jit.blocks_executed),
        None => (0, 0),
    };
    let (jit_native_lowered, jit_helper_fallback) = crate::jit::jit_lowering_telemetry();
    let jit_telemetry = JitTelemetry::from_mode(
        &runtime.jit_mode,
        jit_blocks_compiled,
        jit_blocks_executed,
        jit_native_lowered,
        jit_helper_fallback,
    );

    Ok(PeExecutionResult {
        synthetic_pid: synthetic_pid(dtm),
        stdout: std::mem::take(&mut runtime.stdout),
        stderr: std::mem::take(&mut runtime.stderr),
        exit_code,
        guest_exceptions: Vec::new(),
        gfx_frames: std::mem::take(&mut runtime.gfx_frames),
        perf,
        trace_events,
        milestones: crate::steam_milestones::snapshot_milestones(),
        provenance: crate::steam_milestones::RunProvenance::from_env(),
        termination,
        termination_detail,
        jit_telemetry,
    })
}

/// Execute a managed (.NET) image on the real CoreCLR runtime installed on the
/// host.  .NET (Core) images with a runtime configuration run natively through
/// `dotnet exec`; Framework-only images fail with the runtime's real error.
pub(crate) fn execute_managed_image(
    program: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    dtm: bool,
) -> AppResult<PeExecutionResult> {
    let mut command = std::process::Command::new("dotnet");
    command.arg("exec").arg(program).args(args);
    command.current_dir(program.parent().unwrap_or_else(|| Path::new(".")));
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!(
                "no .NET runtime is available to execute the managed image {}",
                program.display()
            ),
            &error,
        )
        .with_hint("install a .NET runtime (dotnet) or use an image targeting it")
    })?;
    let exit_code = output.status.code().unwrap_or(-1);
    Ok(PeExecutionResult {
        synthetic_pid: synthetic_pid(dtm),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code,
        guest_exceptions: Vec::new(),
        gfx_frames: Vec::new(),
        perf: Vec::new(),
        trace_events: Vec::new(),
        milestones: crate::steam_milestones::snapshot_milestones(),
        provenance: crate::steam_milestones::RunProvenance::from_env(),
        termination: ExecutionTermination::GuestExit { code: exit_code },
        termination_detail: None,
        jit_telemetry: JitTelemetry::default(),
    })
}

/// Classify an execution error into the authoritative termination reason.
pub(crate) fn classify_execution_error(error: &AppError) -> ExecutionTermination {
    if error.message.contains("wall-clock deadline") {
        ExecutionTermination::HarnessDeadline
    } else if error.message.contains("instruction budget") {
        ExecutionTermination::InstructionBudget
    } else if error.code == ReasonCode::RcUnimplInsn {
        ExecutionTermination::UnsupportedInstruction
    } else if error.code == ReasonCode::RcMemoryAccessViolation {
        ExecutionTermination::GuestException
    } else {
        ExecutionTermination::HostError
    }
}
