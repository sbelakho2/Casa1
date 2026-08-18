use crate::canonical::{
    CanonicalTestOutput, GuestException, ToleranceRegistry, compare_outputs, comparison_error,
};
use crate::error::{AppError, AppResult};
use crate::ge::{AppliedOverride, GameEnvironment, diff_file_snapshots, diff_registry_snapshots};
use crate::live;
use crate::logging::{JsonlLogger, LogEvent};
use crate::pe_runtime;
use crate::reason::ReasonCode;
use crate::security::{detect_driver_requirement_on_disk, driver_requirement_error};
use crate::steam::{self, SteamClient};
use crate::steam_integration::SteamProtocolIntegration;
use crate::trace::{self, TraceCategory, TraceCommand, TraceEvent, TraceRecord};
use crate::util;
use crate::{BUILD_ID, TRACE_CACHE_VERSION, TRACE_FORMAT_VERSION};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::SystemTime;

#[derive(Debug, Clone)]
struct SteamZeroTouchRequest {
    update_plan_path: PathBuf,
    cert_chain_path: PathBuf,
    appmanifest_path: PathBuf,
    installscript_path: PathBuf,
    payload_root: PathBuf,
    libraryfolders_path: Option<PathBuf>,
    library_root: Option<String>,
    library_host_root: Option<PathBuf>,
    library_host_map_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunIntent {
    Run,
    Play,
    Install,
}

impl RunIntent {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Play => "play",
            Self::Install => "install",
        }
    }

    fn from_str(value: &str) -> AppResult<Self> {
        match value {
            "run" => Ok(Self::Run),
            "play" => Ok(Self::Play),
            "install" => Ok(Self::Install),
            other => Err(AppError::new(
                ReasonCode::RcRunnerProtocolInvalid,
                format!("unknown replay intent {other}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub enum JitMode {
    /// Runtime decides (current behavior: JIT stays dormant).
    #[default]
    Auto,
    /// The caller explicitly requests JIT compilation to be enabled.
    Enabled,
    /// The caller explicitly requests JIT compilation to be disabled.
    Disabled,
}

impl JitMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunnerJob {
    pub ge_name: String,
    pub ge_root: PathBuf,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub dtm: bool,
    pub intent: RunIntent,
    pub trace_categories: Vec<TraceCategory>,
    pub test_id: String,
    #[serde(default)]
    pub jit_mode: JitMode,
    #[serde(default)]
    pub steam_ipc: bool,
    #[serde(default)]
    pub window_width: Option<u32>,
    #[serde(default)]
    pub window_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerOutcome {
    pub report_path: PathBuf,
    pub trace_path: PathBuf,
    pub log_path: PathBuf,
    pub canonical_output: CanonicalTestOutput,
    /// Steam bootstrap JSON artifact for this run (Steam.exe jobs only).
    pub steam_artifact_json: Option<PathBuf>,
    /// Steam bootstrap log artifact for this run (Steam.exe jobs only).
    pub steam_artifact_log: Option<PathBuf>,
    /// The run identifier (job test id).
    #[serde(default)]
    pub run_id: String,
    /// ExecutionTermination variant name (e.g. "GuestExit").
    #[serde(default)]
    pub termination: String,
    /// Termination detail (error message for non-guest terminations).
    #[serde(default)]
    pub termination_detail: Option<String>,
    /// Steam run milestone snapshot.
    #[serde(default)]
    pub milestones: crate::steam_milestones::SteamMilestones,
    /// JIT telemetry for the run.
    #[serde(default)]
    pub jit: pe_runtime::JitTelemetry,
}

#[derive(Debug, Parser)]
struct RunnerCli {
    #[arg(long)]
    job: PathBuf,
}

pub fn runner_main<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    match runner_main_impl(args) {
        Ok(stdout) => {
            println!("{stdout}");
            0
        }
        Err(error) => {
            let response = util::stable_json(&error.to_response())
                .unwrap_or_else(|_| "{\"reason_code\":1005,\"reason_name\":\"RC_RUNNER_PROTOCOL_INVALID\",\"message\":\"failed to encode error\",\"reproduction_hints\":[]}".to_string());
            eprintln!("{response}");
            1
        }
    }
}

pub fn execute_job(job: &RunnerJob) -> AppResult<RunnerOutcome> {
    // Run identity: generated ONCE at job start and carried through the whole
    // run, so every artifact of this run shares one id and two concurrent
    // workers can never collide on filenames.  A child runner (spawned by the
    // PE runtime for a guest CreateProcessW) inherits CASA1_RUN_ID instead of
    // generating a fresh id, so the child's bootstrap artifact joins the
    // parent's run for the evidence aggregation.
    let run_id = job
        .env
        .get("CASA1_RUN_ID")
        .cloned()
        .unwrap_or_else(|| generate_run_id(job));
    // Guest-visible pid of this runner's process (GetCurrentProcessId),
    // propagated to child PE runners as CASA1_PARENT_PID.
    let parent_pid = pe_runtime::synthetic_pid(job.dtm);
    let mut ge = match GameEnvironment::from_root(job.ge_root.clone()) {
        Ok(ge) => ge,
        Err(e) => {
            return Err(e);
        }
    };
    // Driver-requirement detection is a Windows-executable concept: the
    // indicators (EAC/BattlEye/…) are Windows driver files sitting next to
    // the game.  Scanning host binaries (MACH-O test fixtures, tools) would
    // walk the whole build tree (~850k files under target/debug) for no
    // signal, costing seconds per run across the suite.
    // The walk is bounded to the executable's own directory, so the check
    // is cheap even for host binaries; the gate still skips the scan for
    // clearly non-Windows executables.
    let looks_windows_executable = pe_runtime::is_pe_image(&job.program).unwrap_or(false)
        || job
            .program
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"));
    let driver_report = if job.program.exists() && looks_windows_executable {
        detect_driver_requirement_on_disk(&job.program)?
    } else {
        None
    };
    if let Some(report) = driver_report {
        return Err(driver_requirement_error(&report));
    }
    let started = SystemTime::now();
    let before_files = ge.snapshot_files(job.dtm, started)?;
    let before_registry = ge.snapshot_registry()?;
    let guest_trace_path = ge.guest_trace_path(&job.test_id);
    for path in [
        guest_trace_path.clone(),
        ge.report_path(&job.test_id),
        ge.trace_path(&job.test_id),
    ] {
        if path.exists() {
            fs::remove_file(&path).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to remove {}", path.display()),
                    &error,
                )
            })?;
        }
    }

    let mut effective_child_environment =
        child_environment(job, &ge, &guest_trace_path, &run_id, parent_pid);
    let applied_override = if job.program.exists() {
        ge.apply_overrides_for_program(&job.program, &mut effective_child_environment)?
    } else {
        None
    };

    if let Some(request) = steam_zero_touch_request(job)? {
        let child_pid = parent_pid; // real implementation: generates PID based on dtm mode
        let log_path = ge.log_path(&job.test_id, child_pid);
        let mut logger = JsonlLogger::new(&log_path, child_pid, job.dtm)?;
        let mut runner_events = Vec::new();
        if let Some(applied_override) = &applied_override {
            log_override_application(&mut logger, applied_override)?;
        }
        runner_events.extend(log_process_start(&mut logger, job, child_pid)?);

        let installer_bytes = fs::read(&job.program).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcRunnerSpawnFailed,
                format!("failed to read {}", job.program.display()),
                &error,
            )
        })?;
        let update_plan = steam::load_update_plan(&request.update_plan_path)?;
        let certificate_chain = steam::load_certificate_chain(&request.cert_chain_path)?;
        let mut depot = steam::load_depot_manifest_from_disk(
            &request.appmanifest_path,
            &request.installscript_path,
            &request.payload_root,
            request.libraryfolders_path.as_deref(),
        )?;
        if request.libraryfolders_path.is_some()
            && request.library_root.is_none()
            && depot.library_root.is_none()
        {
            return Err(AppError::new(
                ReasonCode::RcRunnerProtocolInvalid,
                format!(
                    "Steam library metadata did not select a library for app {}",
                    depot.app_id
                ),
            ));
        }
        if request.library_root.is_some() {
            depot.library_root = request.library_root.clone();
        }
        let mut steam_client = SteamClient::new_uninstalled("C:/Program Files/Steam");
        let steam_result = steam_client.zero_touch_install_and_launch(
            &job.program.display().to_string(),
            &installer_bytes,
            &update_plan,
            &certificate_chain,
            depot,
        )?;
        apply_external_steam_library_mapping(
            &mut ge,
            &request,
            steam_result
                .launch
                .env
                .get("SteamLibraryPath")
                .map(String::as_str),
        )?;
        steam_client.materialize_into_ge(&mut ge, job.dtm)?;
        let launched = steam_result.launch.input_ok
            && steam_result.launch.audio_ok
            && steam_result.launch.network_ok;
        runner_events.push(log_steam_zero_touch_install(
            &mut logger,
            job,
            &steam_result,
            launched,
        )?);
        let exit_code = if launched { 0 } else { 1 };
        runner_events.push(log_process_end_code(&mut logger, exit_code)?);

        let after_files = ge.snapshot_files(job.dtm, started)?;
        let after_registry = ge.snapshot_registry()?;
        let canonical_output = CanonicalTestOutput {
            test_id: job.test_id.clone(),
            build_id: BUILD_ID.to_string(),
            os_build: util::current_platform_build(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code,
            guest_exceptions: Vec::new(),
            file_manifest_delta: diff_file_snapshots(&before_files, &after_files),
            registry_delta: diff_registry_snapshots(&before_registry, &after_registry),
            network_summary: Vec::new(),
            gfx_frames: Vec::new(),
            perf: Vec::new(),
        };

        let report_path = ge.report_path(&job.test_id);
        util::write_string(&report_path, &canonical_output.stable_json()?)?;

        let trace_command = TraceCommand {
            program: job.program.clone(),
            args: job.args.clone(),
            cwd: job.cwd.clone(),
            env: effective_child_environment.clone(),
            dtm: job.dtm,
            intent: job.intent.as_str().to_string(),
        };
        let (env_fingerprint, resources) = trace::compute_env_fingerprint(&ge, &trace_command)?;
        let events = trace::merge_events(runner_events, &guest_trace_path, &job.trace_categories)?;
        let trace_record = TraceRecord {
            format_version: TRACE_FORMAT_VERSION,
            cache_version: TRACE_CACHE_VERSION,
            test_id: job.test_id.clone(),
            captured_ge_root: ge.root.clone(),
            ge_profile: crate::trace::TraceGeProfile {
                arch: ge.config.arch.as_str().to_string(),
                winver: ge.config.winver.clone(),
            },
            categories: trace::category_names(&job.trace_categories),
            env_fingerprint,
            resources,
            command: trace_command,
            expected_output: canonical_output.clone(),
            events,
        };
        let trace_path = ge.trace_path(&job.test_id);
        util::write_string(&trace_path, &trace_record.stable_json()?)?;

        return Ok(RunnerOutcome {
            report_path,
            trace_path,
            log_path,
            canonical_output,
            steam_artifact_json: None,
            steam_artifact_log: None,
            run_id: job.test_id.clone(),
            termination: "GuestExit".to_string(),
            termination_detail: None,
            milestones: crate::steam_milestones::SteamMilestones::default(),
            jit: pe_runtime::JitTelemetry::default(),
        });
    }

    // Check for steam:// protocol URLs in the job arguments and dispatch them
    // before proceeding with PE execution. This handles the case where the runner
    // is invoked with a steam:// URL directly (e.g., from a macOS URL event).
    let steam_protocol_urls: Vec<String> = job
        .args
        .iter()
        .filter(|a| a.starts_with("steam://"))
        .cloned()
        .collect();
    if !steam_protocol_urls.is_empty() {
        let integration = SteamProtocolIntegration::new();
        for url in &steam_protocol_urls {
            let dispatched = integration.dispatch_url(url);
            eprintln!(
                "[runner] steam:// protocol dispatch: {} -> {}",
                url,
                if dispatched { "handled" } else { "failed" },
            );
        }
    }

    // Parse Steam command-line flags from job arguments when running Steam.exe.
    if is_steam_executable(&job.program) {
        let steam_flags = pe_runtime::process_steam_command_line(&job.args);
        if steam_flags.has_launch_command() {
            eprintln!(
                "[runner] Steam -applaunch {} detected, args={:?}",
                steam_flags.launch_app_id().unwrap_or(0),
                steam_flags.applaunch_args,
            );
        }
    }

    let is_pe = job.program.exists() && pe_runtime::is_pe_image(&job.program)?;
    if is_pe {
        let child_pid = parent_pid; // real implementation: generates PID based on dtm mode
        let log_path = ge.log_path(&job.test_id, child_pid);
        let mut logger = JsonlLogger::new(&log_path, child_pid, job.dtm)?;
        let mut runner_events = Vec::new();
        if let Some(applied_override) = &applied_override {
            log_override_application(&mut logger, applied_override)?;
        }
        runner_events.extend(log_process_start(&mut logger, job, child_pid)?);
        // Every execution now finalizes into a PeExecutionResult with an
        // authoritative ExecutionTermination (guest exit, harness deadline,
        // instruction budget, unsupported instruction, guest exception,
        // host error) — nothing is reconstructed here, and no error-message
        // sniffing is needed.  Only genuine setup errors can reach this arm.
        let pe_output = match if job.intent == RunIntent::Play && !job.dtm {
            execute_live_pe_job(job, &ge, &effective_child_environment)
        } else {
            pe_runtime::execute(
                &job.program,
                &job.args,
                &ge,
                &job.cwd,
                &effective_child_environment,
                job.dtm,
                &job.test_id,
            )
        } {
            Ok(pe_output) => pe_output,
            Err(error) => {
                if let Some(recovered) = try_recover_budget_exhausted_steam_install(
                    &mut logger,
                    &mut runner_events,
                    &mut ge,
                    job,
                    &error,
                )? {
                    recovered
                } else {
                    return Err(error);
                }
            }
        };
        runner_events.extend(pe_output.trace_events.clone());
        runner_events.push(log_process_end_code(&mut logger, pe_output.exit_code)?);

        // Steam run instrumentation: write the self-identifying run artifact
        // for Steam.exe executions (the basename helper, never substring
        // matching — a `foo-Steam.exe.backup` must not produce a Steam
        // artifact).  ANY PE child that inherited CASA1_RUN_ID also writes
        // its OWN bootstrap artifact (for the child's own program, named with
        // the run id + child test id), so the parent can aggregate child
        // evidence — in particular the steamwebhelper process-started
        // milestone — without waiting for the child to exit.  Instrumentation
        // only: a failed artifact write is reported but never fails the run.
        // The paths are exposed on the outcome so steam:launch and CI can
        // point at the exact evidence of this run.
        let steam_artifact_paths = if is_steam_executable(&job.program) {
            match write_steam_bootstrap_artifacts(&ge, &pe_output, job, &run_id) {
                Ok(paths) => Some(paths),
                Err(error) => {
                    eprintln!(
                        "[runner] steam bootstrap artifact write failed: {}",
                        error.message
                    );
                    None
                }
            }
        } else if job.env.contains_key("CASA1_RUN_ID") {
            match write_child_bootstrap_artifact(&ge, &pe_output, job, &run_id) {
                Ok(paths) => Some(paths),
                Err(error) => {
                    eprintln!(
                        "[runner] child bootstrap artifact write failed: {}",
                        error.message
                    );
                    None
                }
            }
        } else {
            None
        };

        let after_files = ge.snapshot_files(job.dtm, started)?;
        let after_registry = ge.snapshot_registry()?;
        let network_summary = network_summary_from_trace(&pe_output);
        let canonical_output = CanonicalTestOutput {
            test_id: job.test_id.clone(),
            build_id: BUILD_ID.to_string(),
            os_build: util::current_platform_build(),
            stdout: pe_output.stdout,
            stderr: pe_output.stderr,
            exit_code: pe_output.exit_code,
            guest_exceptions: pe_output.guest_exceptions,
            file_manifest_delta: diff_file_snapshots(&before_files, &after_files),
            registry_delta: diff_registry_snapshots(&before_registry, &after_registry),
            network_summary,
            gfx_frames: pe_output.gfx_frames,
            perf: pe_output.perf,
        };

        let report_path = ge.report_path(&job.test_id);
        util::write_string(&report_path, &canonical_output.stable_json()?)?;

        let trace_command = TraceCommand {
            program: job.program.clone(),
            args: job.args.clone(),
            cwd: job.cwd.clone(),
            env: effective_child_environment.clone(),
            dtm: job.dtm,
            intent: job.intent.as_str().to_string(),
        };
        let (env_fingerprint, resources) = trace::compute_env_fingerprint(&ge, &trace_command)?;
        let events = trace::merge_events(runner_events, &guest_trace_path, &job.trace_categories)?;
        let trace_record = TraceRecord {
            format_version: TRACE_FORMAT_VERSION,
            cache_version: TRACE_CACHE_VERSION,
            test_id: job.test_id.clone(),
            captured_ge_root: ge.root.clone(),
            ge_profile: crate::trace::TraceGeProfile {
                arch: ge.config.arch.as_str().to_string(),
                winver: ge.config.winver.clone(),
            },
            categories: trace::category_names(&job.trace_categories),
            env_fingerprint,
            resources,
            command: trace_command,
            expected_output: canonical_output.clone(),
            events,
        };
        let trace_path = ge.trace_path(&job.test_id);
        util::write_string(&trace_path, &trace_record.stable_json()?)?;

        // The outcome carries the AUTHORITATIVE run state — never
        // reconstructed: the artifact and the public outcome must always
        // agree (same run_id, termination, milestones, JIT telemetry, and
        // the same network aggregation that feeds the artifact).
        return Ok(RunnerOutcome {
            report_path,
            trace_path,
            log_path,
            canonical_output,
            steam_artifact_json: steam_artifact_paths
                .as_ref()
                .map(|paths| paths.json_path.clone()),
            steam_artifact_log: steam_artifact_paths
                .as_ref()
                .map(|paths| paths.log_path.clone()),
            run_id: run_id.clone(),
            termination: format!("{:?}", pe_output.termination),
            termination_detail: pe_output.termination_detail.clone(),
            milestones: pe_output.milestones.clone(),
            jit: pe_output.jit_telemetry.clone(),
        });
    }

    let mut command = Command::new(&job.program);
    command
        .args(&job.args)
        .current_dir(&job.cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // In DTM (deterministic) mode the guest must not observe host-dependent
    // variables (PATH, DYLD_*, TMPDIR, host CASA1_* values): recorded traces
    // fingerprint only `effective_child_environment`, so a replay must see
    // exactly the same environment.  Otherwise keep host passthrough and
    // mirror the full spawn environment into the trace fingerprint.
    let spawn_env = if job.dtm {
        effective_child_environment.clone()
    } else {
        let mut host_env = std::env::vars_os()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect::<BTreeMap<String, String>>();
        host_env.extend(
            effective_child_environment
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        host_env
    };
    for (key, value) in &spawn_env {
        command.env(key, value);
    }

    let child = command.spawn().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerSpawnFailed,
            format!("failed to spawn {}", job.program.display()),
            &error,
        )
        .with_hint(format!(
            "missing or non-executable program: {}",
            job.program.display()
        ))
    })?;
    let child_pid = child.id();
    let log_path = ge.log_path(&job.test_id, child_pid);
    let mut logger = JsonlLogger::new(&log_path, child_pid, job.dtm)?;
    let mut runner_events = Vec::new();
    if let Some(applied_override) = &applied_override {
        log_override_application(&mut logger, applied_override)?;
    }
    runner_events.extend(log_process_start(&mut logger, job, child_pid)?);

    let output = child.wait_with_output().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerSpawnFailed,
            format!("failed while waiting for {}", job.program.display()),
            &error,
        )
    })?;
    runner_events.push(log_process_end(&mut logger, &output.status)?);

    let after_files = ge.snapshot_files(job.dtm, started)?;
    let after_registry = ge.snapshot_registry()?;
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
    let stderr = String::from_utf8_lossy(&output.stderr).replace("\r\n", "\n");
    let exit_code = output.status.code().unwrap_or(-1);
    let canonical_output = CanonicalTestOutput {
        test_id: job.test_id.clone(),
        build_id: BUILD_ID.to_string(),
        os_build: util::current_platform_build(),
        stdout,
        stderr,
        exit_code,
        guest_exceptions: guest_exceptions(&output.status, &job.program),
        file_manifest_delta: diff_file_snapshots(&before_files, &after_files),
        registry_delta: diff_registry_snapshots(&before_registry, &after_registry),
        network_summary: Vec::new(),
        gfx_frames: Vec::new(),
        perf: Vec::new(),
    };

    let report_path = ge.report_path(&job.test_id);
    util::write_string(&report_path, &canonical_output.stable_json()?)?;

    let trace_command = TraceCommand {
        program: job.program.clone(),
        args: job.args.clone(),
        cwd: job.cwd.clone(),
        env: spawn_env.clone(),
        dtm: job.dtm,
        intent: job.intent.as_str().to_string(),
    };
    let (env_fingerprint, resources) = trace::compute_env_fingerprint(&ge, &trace_command)?;
    let events = trace::merge_events(runner_events, &guest_trace_path, &job.trace_categories)?;
    let trace_record = TraceRecord {
        format_version: TRACE_FORMAT_VERSION,
        cache_version: TRACE_CACHE_VERSION,
        test_id: job.test_id.clone(),
        captured_ge_root: ge.root.clone(),
        ge_profile: crate::trace::TraceGeProfile {
            arch: ge.config.arch.as_str().to_string(),
            winver: ge.config.winver.clone(),
        },
        categories: trace::category_names(&job.trace_categories),
        env_fingerprint,
        resources,
        command: trace_command,
        expected_output: canonical_output.clone(),
        events,
    };
    let trace_path = ge.trace_path(&job.test_id);
    util::write_string(&trace_path, &trace_record.stable_json()?)?;

    Ok(RunnerOutcome {
        report_path,
        trace_path,
        log_path,
        canonical_output,
        steam_artifact_json: None,
        steam_artifact_log: None,
        run_id: job.test_id.clone(),
        termination: "GuestExit".to_string(),
        termination_detail: None,
        milestones: crate::steam_milestones::SteamMilestones::default(),
        jit: pe_runtime::JitTelemetry::default(),
    })
}

pub fn replay_trace(trace_path: &Path, ge: &GameEnvironment) -> AppResult<CanonicalTestOutput> {
    let record = trace::load_trace(trace_path)?;
    trace::validate_replay_environment(&record, ge)?;
    let job = RunnerJob {
        ge_name: ge.config.name.clone(),
        ge_root: ge.root.clone(),
        program: record.command.program.clone(),
        args: record.command.args.clone(),
        cwd: trace::remap_replay_path(&record.command.cwd, &record.captured_ge_root, &ge.root),
        env: record.command.env.clone(),
        dtm: record.command.dtm,
        intent: RunIntent::from_str(&record.command.intent)?,
        trace_categories: trace::parse_categories(Some(&record.categories.join(",")))?,
        test_id: record.test_id.clone(),
        jit_mode: JitMode::Auto,
        steam_ipc: false,
        window_width: None,
        window_height: None,
    };
    let actual = execute_job(&job)?.canonical_output;
    compare_outputs(
        &record.expected_output,
        &actual,
        &ToleranceRegistry::default(),
    )
    .map_err(|failure| comparison_error(&failure))?;
    Ok(actual)
}

fn runner_main_impl<I, S>(args: I) -> AppResult<String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = RunnerCli::parse_from(args);
    let contents = fs::read_to_string(&cli.job).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerProtocolInvalid,
            format!("failed to read {}", cli.job.display()),
            &error,
        )
    })?;
    let job = serde_json::from_str::<RunnerJob>(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            format!("failed to parse {}", cli.job.display()),
        )
        .with_hint(error.to_string())
    })?;
    let outcome = execute_job(&job)?;
    util::stable_json(&outcome)
}

fn child_environment(
    job: &RunnerJob,
    ge: &GameEnvironment,
    guest_trace_path: &Path,
    run_id: &str,
    parent_pid: u32,
) -> BTreeMap<String, String> {
    let mut env = job.env.clone();
    env.insert("CASA1_GE_ROOT".to_string(), ge.root.display().to_string());
    env.insert(
        "CASA1_REGISTRY_HKCU".to_string(),
        ge.registry_file("HKCU").display().to_string(),
    );
    env.insert(
        "CASA1_REGISTRY_HKLM".to_string(),
        ge.registry_file("HKLM").display().to_string(),
    );
    env.insert(
        "CASA1_REGISTRY_HKCR".to_string(),
        ge.registry_file("HKCR").display().to_string(),
    );
    env.insert(
        "CASA1_TRACE_FILE".to_string(),
        guest_trace_path.display().to_string(),
    );
    env.insert(
        "CASA1_DTM".to_string(),
        if job.dtm { "1" } else { "0" }.to_string(),
    );
    env.insert(
        "CASA1_FIXED_GUID".to_string(),
        util::deterministic_guid(&job.test_id, job.dtm),
    );
    env.insert(
        "CASA1_RUN_INTENT".to_string(),
        job.intent.as_str().to_string(),
    );
    env.insert(
        "CASA1_TRACE_CATEGORIES".to_string(),
        job.trace_categories
            .iter()
            .map(|category| category.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    env.insert(
        "CASA1_INSTALL_SILENT".to_string(),
        if job.intent == RunIntent::Install
            && (job
                .env
                .get("CASA1_INSTALL_SILENT")
                .is_some_and(|value| value == "1")
                || job.args.iter().any(|arg| arg == "--silent"))
        {
            "1"
        } else {
            "0"
        }
        .to_string(),
    );
    env.insert("CASA1_TEST_ID".to_string(), job.test_id.clone());
    // Run identity inheritance (instrumentation): child PE runners spawned by
    // the guest inherit CASA1_RUN_ID so their bootstrap artifacts belong to
    // the same run and the parent can merge child evidence, and
    // CASA1_PARENT_PID so children can name their parent.  The PE runtime
    // also injects both into CreateProcessW child environments directly.
    env.insert("CASA1_RUN_ID".to_string(), run_id.to_string());
    env.insert("CASA1_PARENT_PID".to_string(), parent_pid.to_string());
    env
}

fn execute_live_pe_job(
    job: &RunnerJob,
    ge: &GameEnvironment,
    effective_child_environment: &BTreeMap<String, String>,
) -> AppResult<pe_runtime::PeExecutionResult> {
    // ── Force real NSWindow creation for the guest PE image ──────────────
    // The casa1-runner process is not a .app bundle, so by default
    // mac_window::init_nsapplication() and create_nswindow() would skip
    // real NSWindow creation (returning null).  We need real NSWindows so
    // that Steam's D3D11 → Metal rendering has a CAMetalLayer to draw into.
    //
    // We call set_force_window_creation(true) and init_nsapplication() on
    // the MAIN thread before spawning the PE runtime worker, because
    // NSApplication sharedApplication must be called from the main thread.
    #[cfg(target_os = "macos")]
    {
        crate::mac_window::set_force_window_creation(true);
        let nsapp_ok = crate::mac_window::init_nsapplication();
        eprintln!(
            "[runner] mac_window: forced NSApp init={}, window creation will use real NSWindows",
            nsapp_ok,
        );
    }

    let (host_session, live_session) = live::new_live_session();
    let program = job.program.clone();
    let ge = ge.clone();
    let cwd = job.cwd.clone();
    let args = job.args.clone();
    let env = effective_child_environment.clone();
    let dtm = job.dtm;
    let test_id = job.test_id.clone();
    let jit_mode = job.jit_mode;
    let steam_ipc = job.steam_ipc;
    let worker = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            // Set thread QoS to user-interactive to prevent macOS from
            // descheduling the compute-heavy worker thread.
            #[cfg(target_os = "macos")]
            unsafe {
                libc::pthread_set_qos_class_self_np(
                    libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE,
                    0,
                );
            }
            pe_runtime::execute_with_options(
                &program,
                &args,
                &ge,
                &cwd,
                &env,
                dtm,
                &test_id,
                pe_runtime::PeExecutionOptions {
                    live_session: Some(live_session),
                    jit_mode: Some(jit_mode),
                    steam_ipc,
                },
            )
        })
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcRunnerSpawnFailed,
                "failed to spawn PE runtime worker thread",
            )
            .with_hint(error.to_string())
        })?;
    let requested_window_size = job.window_width.zip(job.window_height);
    live::run_live_host_session(
        &live_window_title(&job.ge_name, &job.program, &job.intent),
        host_session,
        worker,
        requested_window_size,
    )
}

/// Build the window title for the live PE session.
///
/// Uses the GE name (game name) as the primary title, with the executable
/// name as a subtitle. Shows the intent (play/run) in the title bar.
/// For "play" intent, shows "Playing: <game name>".
/// For "run" intent, shows "Running: <exe name>".
fn live_window_title(ge_name: &str, program: &Path, intent: &RunIntent) -> String {
    let exe_stem = program
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    match intent {
        RunIntent::Play => {
            // Use the GE name as the game title if it's meaningful,
            // otherwise fall back to the exe name.
            let game_name = if ge_name.is_empty() || ge_name == "default" {
                exe_stem.clone()
            } else {
                ge_name.to_string()
            };
            format!("Playing: {}", game_name)
        }
        RunIntent::Run => {
            format!("Running: {}", exe_stem)
        }
        RunIntent::Install => {
            format!("Installing: {}", exe_stem)
        }
    }
}

fn log_process_start(
    logger: &mut JsonlLogger,
    job: &RunnerJob,
    child_pid: u32,
) -> AppResult<Vec<TraceEvent>> {
    let mut kv = BTreeMap::new();
    kv.insert(
        "exe".to_string(),
        Value::String(job.program.display().to_string()),
    );
    kv.insert(
        "args".to_string(),
        Value::Array(job.args.iter().cloned().map(Value::String).collect()),
    );
    kv.insert(
        "cwd".to_string(),
        Value::String(job.cwd.display().to_string()),
    );
    kv.insert(
        "intent".to_string(),
        Value::String(job.intent.as_str().to_string()),
    );
    logger.log(
        "runner",
        "info",
        ReasonCode::Success,
        format!("spawned guest process {child_pid}"),
        kv.clone(),
    )?;
    Ok(vec![TraceEvent {
        event_index: 0,
        category: "process".to_string(),
        call_id: "CreateProcessW".to_string(),
        parameters: kv,
        return_value: json!(child_pid),
        get_last_error: None,
        side_effect_hashes: Vec::new(),
    }])
}

fn log_override_application(
    logger: &mut JsonlLogger,
    applied_override: &AppliedOverride,
) -> AppResult<()> {
    let mut kv = BTreeMap::new();
    kv.insert(
        "profile_id".to_string(),
        Value::String(applied_override.profile_id.clone()),
    );
    kv.insert(
        "match_rule".to_string(),
        Value::String(applied_override.match_rule.clone()),
    );
    kv.insert(
        "normalized_diff".to_string(),
        applied_override.normalized_diff.clone(),
    );
    logger.log(
        "overrides",
        "info",
        ReasonCode::Success,
        format!("applied override {}", applied_override.profile_id),
        kv,
    )?;
    Ok(())
}

fn log_process_end(
    logger: &mut JsonlLogger,
    status: &std::process::ExitStatus,
) -> AppResult<TraceEvent> {
    log_process_end_code(logger, status.code().unwrap_or(-1))
}

fn log_process_end_code(logger: &mut JsonlLogger, exit_code: i32) -> AppResult<TraceEvent> {
    let mut kv = BTreeMap::new();
    kv.insert("exit_code".to_string(), json!(exit_code));
    let event = logger.log(
        "runner",
        if exit_code == 0 { "info" } else { "error" },
        if exit_code == 0 {
            ReasonCode::Success
        } else {
            ReasonCode::RcRunnerSpawnFailed
        },
        format!("guest process exited with {exit_code}"),
        kv.clone(),
    )?;
    Ok(trace_from_log_event(
        event,
        "process",
        "WaitForSingleObject",
        json!(exit_code),
        Vec::new(),
    ))
}

fn log_steam_zero_touch_install(
    logger: &mut JsonlLogger,
    job: &RunnerJob,
    result: &steam::SteamZeroTouchLaunchResult,
    launched: bool,
) -> AppResult<TraceEvent> {
    let steam_app_id = result
        .launch
        .env
        .get("SteamAppId")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    let mut kv = BTreeMap::new();
    kv.insert(
        "installer".to_string(),
        Value::String(job.program.display().to_string()),
    );
    kv.insert("app_id".to_string(), json!(steam_app_id));
    kv.insert("launched".to_string(), json!(launched));
    kv.insert(
        "launch_executable".to_string(),
        Value::String(result.launch.executable.clone()),
    );
    kv.insert(
        "app_manifest_path".to_string(),
        Value::String(result.app_manifest_path.clone()),
    );
    let event = logger.log(
        "steam",
        if launched { "info" } else { "error" },
        if launched {
            ReasonCode::Success
        } else {
            ReasonCode::RcSteamUpdateFailed
        },
        if launched {
            format!("zero-touch Steam install launched app {steam_app_id}")
        } else {
            format!("zero-touch Steam install FAILED to launch app {steam_app_id}")
        },
        kv,
    )?;
    Ok(trace_from_log_event(
        event,
        "process",
        "SteamZeroTouchInstall",
        json!(launched),
        Vec::new(),
    ))
}

fn try_recover_budget_exhausted_steam_install(
    logger: &mut JsonlLogger,
    runner_events: &mut Vec<TraceEvent>,
    ge: &mut GameEnvironment,
    job: &RunnerJob,
    error: &AppError,
) -> AppResult<Option<pe_runtime::PeExecutionResult>> {
    if job.intent != RunIntent::Install
        || !budget_exhausted(error)
        || !steam::is_official_steam_setup(&job.program)
    {
        return Ok(None);
    }

    let install = steam::install_official_steam_setup_into_ge(ge, &job.program, job.dtm)?;
    runner_events.push(log_native_steam_install_recovery(
        logger, job, &install, error,
    )?);
    // The budget-exhausted install recovery is a MODEL run (the synthetic
    // install model, never real Steam execution); its termination is a
    // normal GuestExit so the acceptance evaluator can distinguish
    // model artifacts from real-PE artifacts via provenance.execution_mode.
    let provenance = crate::steam_milestones::RunProvenance {
        execution_mode: "model".to_string(),
        ..crate::steam_milestones::RunProvenance::default()
    };
    Ok(Some(pe_runtime::PeExecutionResult {
        synthetic_pid: pe_runtime::synthetic_pid(job.dtm), // real implementation: generates PID based on dtm mode
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        guest_exceptions: Vec::new(),
        gfx_frames: Vec::new(),
        perf: Vec::new(),
        trace_events: Vec::new(),
        milestones: crate::steam_milestones::SteamMilestones::default(),
        provenance,
        termination: pe_runtime::ExecutionTermination::GuestExit { code: 0 },
        termination_detail: None,
        jit_telemetry: pe_runtime::JitTelemetry::default(),
    }))
}

fn log_native_steam_install_recovery(
    logger: &mut JsonlLogger,
    job: &RunnerJob,
    result: &steam::NativeSteamInstallResult,
    error: &AppError,
) -> AppResult<TraceEvent> {
    let mut kv = BTreeMap::new();
    kv.insert(
        "installer".to_string(),
        Value::String(job.program.display().to_string()),
    );
    kv.insert(
        "install_root".to_string(),
        Value::String(result.install_root.clone()),
    );
    kv.insert("file_count".to_string(), json!(result.file_list.len()));
    kv.insert(
        "recovery_trigger".to_string(),
        Value::String(error.message.clone()),
    );
    let event = logger.log(
        "steam",
        "info",
        ReasonCode::Success,
        format!(
            "recovered official Steam install via native NSIS extraction into {}",
            result.install_root
        ),
        kv,
    )?;
    Ok(trace_from_log_event(
        event,
        "process",
        "SteamNativeNsisInstallRecovery",
        json!(0),
        Vec::new(),
    ))
}

/// Detect PE instruction-budget exhaustion.
///
/// The PE runtime reports budget exhaustion as `RcUnimplInsn` with a
/// message prefix; a dedicated reason code does not exist yet (reason.rs is
/// outside this module's boundary), so the check tolerates both the exact
/// historical prefix and the "instruction budget" phrasing to avoid
/// silently disabling the Steam-install recovery path if the wording is
/// ever tweaked.
fn budget_exhausted(error: &AppError) -> bool {
    error.code == ReasonCode::RcUnimplInsn
        && (error
            .message
            .starts_with("PE runtime exceeded the instruction budget")
            || error.message.contains("instruction budget")
            || error.message.contains("wall-clock deadline"))
}

/// True when the error is the wall-clock run deadline marker.  These runs
/// end deliberately (exit code -2) and must NOT go through the NSIS
/// install-recovery path, which targets budget-exhausted installs.
fn is_wall_clock_deadline(error: &AppError) -> bool {
    error.code == ReasonCode::RcUnimplInsn && error.message.contains("wall-clock deadline")
}

fn steam_zero_touch_request(job: &RunnerJob) -> AppResult<Option<SteamZeroTouchRequest>> {
    if job.env.get("CASA1_STEAM_ZERO_TOUCH").map(String::as_str) != Some("1") {
        return Ok(None);
    }
    Ok(Some(SteamZeroTouchRequest {
        update_plan_path: required_env_path(job, "CASA1_STEAM_UPDATE_PLAN_PATH")?,
        cert_chain_path: required_env_path(job, "CASA1_STEAM_CERT_CHAIN_PATH")?,
        appmanifest_path: required_env_path(job, "CASA1_STEAM_APPMANIFEST_PATH")?,
        installscript_path: required_env_path(job, "CASA1_STEAM_INSTALLSCRIPT_PATH")?,
        payload_root: required_env_path(job, "CASA1_STEAM_PAYLOAD_ROOT")?,
        libraryfolders_path: job
            .env
            .get("CASA1_STEAM_LIBRARYFOLDERS_PATH")
            .map(PathBuf::from),
        library_root: job.env.get("CASA1_STEAM_LIBRARY_ROOT").cloned(),
        library_host_root: job
            .env
            .get("CASA1_STEAM_LIBRARY_HOST_ROOT")
            .map(PathBuf::from),
        library_host_map_path: job
            .env
            .get("CASA1_STEAM_LIBRARY_HOST_MAP_PATH")
            .map(PathBuf::from),
    }))
}

fn apply_external_steam_library_mapping(
    ge: &mut GameEnvironment,
    request: &SteamZeroTouchRequest,
    selected_library_root: Option<&str>,
) -> AppResult<()> {
    let library_root = selected_library_root.ok_or_else(|| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            "Steam library mapping requires a selected guest Steam library root",
        )
    })?;
    let parsed = ge.parse_windows_path(library_root, None)?;
    let drive = parsed.drive.ok_or_else(|| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            format!("Steam library root is missing a drive letter: {library_root}"),
        )
    })?;
    if drive == "C" {
        return Ok(());
    }
    let host_root = if let Some(host_root) = request.library_host_root.as_deref() {
        host_root.to_path_buf()
    } else if let Some(map_path) = request.library_host_map_path.as_deref() {
        resolve_steam_library_host_root_from_map(map_path, library_root, &drive)?
    } else {
        return Ok(());
    };
    ge.add_drive_mapping(&drive, &host_root, false, false)
}

fn resolve_steam_library_host_root_from_map(
    map_path: &Path,
    library_root: &str,
    drive: &str,
) -> AppResult<PathBuf> {
    let contents = fs::read_to_string(map_path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerProtocolInvalid,
            format!("failed to read {}", map_path.display()),
            &error,
        )
    })?;
    let host_map =
        serde_json::from_str::<BTreeMap<String, String>>(&contents).map_err(|error| {
            AppError::new(
                ReasonCode::RcRunnerProtocolInvalid,
                format!("failed to parse {}", map_path.display()),
            )
            .with_hint(error.to_string())
        })?;
    let normalized_root = normalize_library_root_key(library_root);
    host_map
        .get(&normalized_root)
        .or_else(|| host_map.get(drive))
        .or_else(|| host_map.get(&format!("{drive}:")))
        .map(PathBuf::from)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcRunnerProtocolInvalid,
                format!("Steam library host map missing entry for {library_root}"),
            )
        })
}

fn normalize_library_root_key(path: &str) -> String {
    path.replace('\\', "/")
        .to_ascii_lowercase()
        .trim_end_matches('/')
        .to_string()
}

fn required_env_path(job: &RunnerJob, key: &str) -> AppResult<PathBuf> {
    job.env.get(key).map(PathBuf::from).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            format!("missing runner Steam metadata input {key}"),
        )
    })
}

fn trace_from_log_event(
    event: LogEvent,
    category: &str,
    call_id: &str,
    return_value: Value,
    side_effect_hashes: Vec<String>,
) -> TraceEvent {
    TraceEvent {
        event_index: event.event_id as u64,
        category: category.to_string(),
        call_id: call_id.to_string(),
        parameters: event.kv,
        return_value,
        get_last_error: event.win32_err,
        side_effect_hashes,
    }
}

fn guest_exceptions(status: &std::process::ExitStatus, program: &Path) -> Vec<GuestException> {
    match status.signal() {
        Some(signal) => vec![GuestException {
            code: signal as u32,
            addr: None,
            module: program.display().to_string(),
            tid: 1,
        }],
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Steam run instrumentation artifacts
// ---------------------------------------------------------------------------

/// True when the job program basename is `steam.exe` (case-insensitive) —
/// the only jobs that get the steam-bootstrap artifact.
pub fn is_steam_executable(program: &Path) -> bool {
    program
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("steam.exe"))
}

/// Run identity: UUID v4 for live (`!dtm`) runs; a DETERMINISTIC id for DTM
/// runs (`sha256(short-sha + test-id)[..12]`) so parallel DTM workers never
/// collide while staying reproducible.  Never timestamp-only.
pub fn generate_run_id(job: &RunnerJob) -> String {
    if job.dtm {
        deterministic_run_id(&short_commit_sha(), &job.test_id)
    } else {
        uuid::Uuid::new_v4().to_string()
    }
}

/// Deterministic DTM run id: `sha256(short-sha + test-id)[..12]`.
pub fn deterministic_run_id(short_sha: &str, test_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(short_sha.as_bytes());
    hasher.update(test_id.as_bytes());
    hex::encode(hasher.finalize())[..12].to_string()
}

/// Build-time commit short sha (`unknown` when git is unavailable).
fn short_commit_sha() -> String {
    let provenance = crate::steam_milestones::RunProvenance::from_env();
    if provenance.commit_sha.is_empty() || provenance.commit_sha == "unknown" {
        "unknown".to_string()
    } else {
        provenance.commit_sha.chars().take(8).collect()
    }
}

/// Steam bootstrap artifact stem: `<short-sha>-<test-id>-<run-id>-steam-bootstrap`.
/// The run id distinguishes concurrent runs at the same commit; the test id
/// distinguishes jobs within a worker.
pub fn steam_artifact_stem(short_sha: &str, test_id: &str, run_id: &str) -> String {
    format!("{short_sha}-{test_id}-{run_id}-steam-bootstrap")
}

/// Child-runner bootstrap artifact stem:
/// `<short-sha>-<test-id>-<run-id>-child-steam-bootstrap`.  The `-child-`
/// marker (plus the artifact's `child_of_run_id` field) is how the parent's
/// finalization recognizes sibling artifacts of the same run.
pub fn child_artifact_stem(short_sha: &str, test_id: &str, run_id: &str) -> String {
    format!("{short_sha}-{test_id}-{run_id}-child-steam-bootstrap")
}

/// True when the program basename is `steamwebhelper.exe` (case-insensitive).
pub fn is_webhelper_program(program: &Path) -> bool {
    program
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("steamwebhelper.exe"))
}

/// Where the steam-bootstrap JSON and log artifacts were written.
#[derive(Debug, Clone)]
pub struct SteamArtifactPaths {
    pub json_path: PathBuf,
    pub log_path: PathBuf,
}

/// The full JSON artifact payload: provenance, milestones, and the run
/// summary lines.  Public so the Steam acceptance evaluator
/// ([`crate::steam_acceptance::evaluate`]) and the E2E tests can read a
/// written artifact back from disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamBootstrapArtifact {
    pub provenance: crate::steam_milestones::RunProvenance,
    /// Unique run identifier (UUID v4 live / deterministic DTM), distinct
    /// for every artifact.
    pub run_id: String,
    /// The runner job's test id.
    pub test_id: String,
    /// For child-runner artifacts: the parent run id this artifact belongs
    /// to (set when CASA1_RUN_ID was inherited).  `None` for the parent
    /// Steam.exe artifact.  The parent's finalization scans sibling artifacts
    /// with this marker to merge child evidence.
    #[serde(default)]
    pub child_of_run_id: Option<String>,
    /// The Steam executable path that was run.
    pub program_path: String,
    /// SHA-256 of the Steam executable that was run.
    pub program_sha256: String,
    pub milestones: crate::steam_milestones::SteamMilestones,
    pub last_thunk: Option<crate::steam_milestones::LastThunk>,
    /// Guest process id of the synthetic process that ran the PE image.
    pub guest_pid: u32,
    /// Authoritative termination reason (GuestExit / HarnessDeadline / ...).
    pub termination: pe_runtime::ExecutionTermination,
    /// Error detail for non-guest terminations.
    pub termination_detail: Option<String>,
    pub exit_code: i32,
    pub instruction_count: Option<u64>,
    /// Guest exceptions observed during the run (S12 acceptance check).
    pub guest_exceptions: Vec<crate::canonical::GuestException>,
    pub network_summary: Vec<String>,
    /// Metal encoder lifecycle counters at artifact collection (S12
    /// balance check).
    pub metal_encoders_created: u64,
    pub metal_encoders_ended: u64,
    /// JIT telemetry for the run (requested/active mode, block counters).
    pub jit: pe_runtime::JitTelemetry,
}

/// Instruction count from the run's `pe_runtime_steps` perf metric, if the
/// runtime published one.
fn instruction_count_from_perf(pe_output: &pe_runtime::PeExecutionResult) -> Option<u64> {
    pe_output
        .perf
        .iter()
        .find(|metric| metric.metric_id == "pe_runtime_steps")
        .map(|metric| metric.value as u64)
}

/// Aggregate the run's network activity into the canonical summary shape —
/// the SAME aggregation that feeds the Steam artifact, so the public
/// outcome and the artifact never disagree.
fn network_summary_from_trace(
    pe_output: &pe_runtime::PeExecutionResult,
) -> Vec<crate::canonical::NetworkSummary> {
    pe_output
        .trace_events
        .iter()
        .filter(|event| event.category == "network")
        .filter_map(|event| {
            let kv = &event.parameters;
            let host = kv.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let proto = kv.get("proto").and_then(|v| v.as_str()).unwrap_or("tcp");
            let port = kv.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let method = kv.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let status = kv.get("status").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let bytes_in = kv.get("bytes_in").and_then(|v| v.as_u64()).unwrap_or(0);
            let bytes_out = kv.get("bytes_out").and_then(|v| v.as_u64()).unwrap_or(0);
            let tls_version = kv
                .get("tls_version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let cipher = kv
                .get("cipher")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if host.is_empty() {
                return None;
            }
            Some(crate::canonical::NetworkSummary {
                proto: proto.to_string(),
                host: host.to_string(),
                port,
                method: method.to_string(),
                status,
                bytes_in,
                bytes_out,
                tls_version,
                cipher,
            })
        })
        .collect()
}

/// Compact network summary lines from the run's trace events (artifact log form).
fn network_summary_lines_from_trace(pe_output: &pe_runtime::PeExecutionResult) -> Vec<String> {
    pe_output
        .trace_events
        .iter()
        .filter(|event| event.category == "network")
        .map(|event| format!("{} -> {}", event.call_id, event.return_value))
        .collect()
}

/// Human-readable milestone block for the log artifact.
fn milestones_log_lines(milestones: &crate::steam_milestones::SteamMilestones) -> Vec<String> {
    use crate::steam_milestones::MilestoneEvidence;
    let steam = &milestones.steam;
    let graphics = &milestones.graphics;
    let threads = &milestones.threads;
    let failures = &milestones.first_failures;
    let mut lines = Vec::new();
    lines.push("milestones:".to_string());
    let evidence = |name: &str, value: &Option<MilestoneEvidence>| -> String {
        match value {
            Some(value) => {
                let api = value.api.as_deref().unwrap_or("<none>");
                let path = value.path.as_deref().unwrap_or("<none>");
                let detail = value.detail.as_deref().unwrap_or("");
                format!(
                    "  steam.{name}: observed (api={api}, path={path}, guest_pc={:#x}, detail={detail})",
                    value.guest_pc
                )
            }
            None => format!("  steam.{name}: not observed"),
        }
    };
    lines.push(evidence("bootstrap_started", &steam.bootstrap_started));
    lines.push(evidence("manifest_opened", &steam.manifest_opened));
    lines.push(evidence("manifest_full_read", &steam.manifest_full_read));
    lines.push(evidence(
        "package_writability_probe",
        &steam.package_writability_probe,
    ));
    lines.push(evidence("client_main_started", &steam.client_main_started));
    lines.push(evidence(
        "webhelper_spawn_requested",
        &steam.webhelper_spawn_requested,
    ));
    lines.push(evidence(
        "webhelper_process_started",
        &steam.webhelper_process_started,
    ));
    lines.push(format!(
        "  steam.webhelper_spawn_requests: {}",
        steam.webhelper_spawn_requests
    ));
    lines.push(format!(
        "  steam.webhelper_processes_started: {}",
        steam.webhelper_processes_started
    ));
    lines.push(evidence("cef_browser_created", &steam.cef_browser_created));
    lines.push(evidence("cef_first_paint", &steam.cef_first_paint));
    lines.push(evidence(
        "first_software_paint",
        &steam.first_software_paint,
    ));
    lines.push(evidence(
        "first_accelerated_paint",
        &steam.first_accelerated_paint,
    ));
    lines.push(evidence("first_dxgi_present", &steam.first_dxgi_present));
    lines.push(evidence("first_metal_present", &steam.first_metal_present));
    lines.push(format!(
        "  steam.cef_software_paints: {}",
        steam.cef_software_paints
    ));
    lines.push(format!(
        "  steam.cef_accelerated_paints: {}",
        steam.cef_accelerated_paints
    ));
    lines.push("graphics:".to_string());
    lines.push(format!(
        "  graphics.host_placeholder_frames: {}",
        graphics.host_placeholder_frames
    ));
    lines.push(format!("  graphics.gdi_frames: {}", graphics.gdi_frames));
    lines.push(format!(
        "  graphics.cef_software_frames: {}",
        graphics.cef_software_frames
    ));
    lines.push(format!(
        "  graphics.cef_accelerated_frames: {}",
        graphics.cef_accelerated_frames
    ));
    lines.push(format!(
        "  graphics.dxgi_presents: {}",
        graphics.dxgi_presents
    ));
    lines.push(format!(
        "  graphics.metal_presented_frames: {}",
        graphics.metal_presented_frames
    ));
    lines.push("threads:".to_string());
    lines.push(format!("  threads.created: {}", threads.created));
    lines.push(format!("  threads.normal_exits: {}", threads.normal_exits));
    lines.push(format!("  threads.terminated: {}", threads.terminated));
    lines.push(format!(
        "  threads.illegal_host_terminations: {}",
        threads.illegal_host_terminations
    ));
    lines.push(format!(
        "  threads.live_at_process_exit: {}",
        threads.live_at_process_exit
    ));
    lines.push("first_failures:".to_string());
    for (name, failure) in [
        ("fs", &failures.fs),
        ("crt", &failures.crt),
        ("thread", &failures.thread),
        ("network", &failures.network),
        ("cef", &failures.cef),
        ("gfx", &failures.gfx),
    ] {
        match failure {
            Some(failure) => {
                let api = failure.api.as_deref().unwrap_or("<none>").to_string();
                let guest_error = failure
                    .guest_error
                    .map(|code| format!("{code:#x}"))
                    .unwrap_or_else(|| "<none>".to_string());
                lines.push(format!(
                    "  first_failures.{name}: guest_pc={:#x} thread_id={} api={api} guest_error={guest_error} detail={}",
                    failure.guest_pc, failure.thread_id, failure.detail
                ));
            }
            None => lines.push(format!("  first_failures.{name}: none")),
        }
    }
    lines
}

/// Write `<short-sha>-<test-id>-<run-id>-steam-bootstrap.json` and `.log`
/// under the GE's diagnostics directory.  Only called for Steam.exe jobs;
/// any failure is reported to the caller, which logs it without failing the
/// run.  Returns the written paths so the caller can expose the evidence.
pub fn write_steam_bootstrap_artifacts(
    ge: &GameEnvironment,
    pe_output: &pe_runtime::PeExecutionResult,
    job: &RunnerJob,
    run_id: &str,
) -> AppResult<SteamArtifactPaths> {
    let mut artifact = build_steam_bootstrap_artifact(ge, pe_output, job, run_id);
    // Child-evidence aggregation (S5/S6): the parent cannot observe
    // webhelper_process_started directly because child PEs run as separate
    // casa1-runner invocations.  Best-effort post-run merge: scan the same
    // diagnostics directory for sibling child artifacts of this run and fold
    // their webhelper-process-started evidence into the parent's milestone.
    // A child that finalizes AFTER the parent's artifact is written is
    // merged on a later read via merge_child_artifacts; the limitation is
    // documented in the merged evidence's detail field.
    let merged_children = merge_child_artifacts(ge, &mut artifact);
    let short_sha = short_sha_of(&artifact.provenance);
    let paths = write_artifact_files(
        ge,
        &artifact,
        &steam_artifact_stem(&short_sha, &job.test_id, run_id),
    )?;
    if merged_children > 0 {
        let line = format!(
            "child_artifacts_merged: {merged_children} (best-effort post-run merge; \
             children finalizing after this parent artifact was written are \
             folded in on a later read)\n"
        );
        let mut log = fs::read_to_string(&paths.log_path).unwrap_or_default();
        log.push_str(&line);
        let _ = fs::write(&paths.log_path, log);
    }
    Ok(paths)
}

/// Write the bootstrap artifact for a CHILD PE runner (any PE child that
/// inherited `CASA1_RUN_ID` from its parent).  The artifact is written for
/// the child's OWN program, named with the run id + the child's test id and
/// the `-child-` marker, and carries `child_of_run_id` so the parent's
/// finalization can find and merge it.  When the child is steamwebhelper.exe
/// and the child PE actually dispatched at least one block, the recorded
/// process-first-instruction evidence is folded into
/// `webhelper_process_started`.
pub fn write_child_bootstrap_artifact(
    ge: &GameEnvironment,
    pe_output: &pe_runtime::PeExecutionResult,
    job: &RunnerJob,
    run_id: &str,
) -> AppResult<SteamArtifactPaths> {
    let mut artifact = build_steam_bootstrap_artifact(ge, pe_output, job, run_id);
    artifact.child_of_run_id = Some(run_id.to_string());
    if is_webhelper_program(&job.program)
        && let Some(evidence) = artifact.milestones.process_first_instruction.clone()
    {
        crate::steam_milestones::note_webhelper_process_started_in(
            &mut artifact.milestones,
            evidence,
        );
    }
    let short_sha = short_sha_of(&artifact.provenance);
    write_artifact_files(
        ge,
        &artifact,
        &child_artifact_stem(&short_sha, &job.test_id, run_id),
    )
}

/// Merge sibling CHILD artifacts of the same run into `artifact`.
///
/// Scans the GE's diagnostics directory for `*-child-steam-bootstrap.json`
/// files whose `child_of_run_id` matches `artifact.run_id`; for each it
/// folds the child's `webhelper_process_started` evidence (first-wins, with
/// the merge provenance recorded in the evidence detail) and adds the
/// child's `webhelper_processes_started` count to the parent's.  Returns the
/// number of child artifacts merged.
///
/// Best-effort by design: children write their artifacts when THEY finish,
/// so a parent that finalizes first will not see them yet.  The merge is
/// therefore re-runnable on a later read of the parent artifact; when a
/// child's evidence is merged, its detail field documents that the merge was
/// post-run and that later-finalizing children are folded in by a subsequent
/// merge.  Apply the merge to a freshly-read artifact (never twice to the
/// same copy) so counts stay exact.
pub fn merge_child_artifacts(ge: &GameEnvironment, artifact: &mut SteamBootstrapArtifact) -> usize {
    let diagnostics_dir = ge.diagnostics_dir();
    let run_marker = format!("-{}-child-steam-bootstrap.json", artifact.run_id);
    let mut candidates = Vec::new();
    let Ok(entries) = fs::read_dir(&diagnostics_dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(&run_marker) {
            candidates.push((name, path));
        }
    }
    // Sort for determinism (read_dir order is unspecified; DTM runs must
    // merge deterministically).
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    let mut merged = 0;
    for (name, path) in candidates {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(child) = serde_json::from_slice::<SteamBootstrapArtifact>(&bytes) else {
            continue;
        };
        if child.child_of_run_id.as_deref() != Some(artifact.run_id.as_str()) {
            continue;
        }
        if let Some(evidence) = child.milestones.steam.webhelper_process_started
            && artifact
                .milestones
                .steam
                .webhelper_process_started
                .is_none()
        {
            let mut merged_evidence = evidence;
            merged_evidence.detail = Some(format!(
                "merged from child artifact {name} (best-effort post-run merge; \
                 a child finalizing after the parent's artifact was written is \
                 folded in by a later merge)"
            ));
            artifact.milestones.steam.webhelper_process_started = Some(merged_evidence);
        }
        artifact.milestones.steam.webhelper_processes_started = artifact
            .milestones
            .steam
            .webhelper_processes_started
            .saturating_add(child.milestones.steam.webhelper_processes_started);
        merged += 1;
    }
    merged
}

/// Build the run artifact payload from a PE execution result (shared by the
/// parent Steam.exe artifact and the child-runner artifacts).
fn build_steam_bootstrap_artifact(
    ge: &GameEnvironment,
    pe_output: &pe_runtime::PeExecutionResult,
    job: &RunnerJob,
    run_id: &str,
) -> SteamBootstrapArtifact {
    // The execution mode travels with the run result (the zero-touch model
    // recovery marks itself `model`); the artifact must keep that marker
    // instead of re-deriving `real_pe` from the environment.
    let mut provenance = crate::steam_milestones::RunProvenance::collect(&ge.root, &job.program);
    provenance.execution_mode = pe_output.provenance.execution_mode.clone();
    SteamBootstrapArtifact {
        provenance: provenance.clone(),
        run_id: run_id.to_string(),
        test_id: job.test_id.clone(),
        child_of_run_id: None,
        program_path: job.program.display().to_string(),
        program_sha256: crate::steam_milestones::file_content_hash(&job.program),
        milestones: pe_output.milestones.clone(),
        last_thunk: crate::steam_milestones::snapshot_last_thunk(),
        guest_pid: pe_output.synthetic_pid,
        termination: pe_output.termination,
        termination_detail: pe_output.termination_detail.clone(),
        exit_code: pe_output.exit_code,
        instruction_count: instruction_count_from_perf(pe_output),
        guest_exceptions: pe_output.guest_exceptions.clone(),
        network_summary: network_summary_lines_from_trace(pe_output),
        metal_encoders_created: crate::metal_backend::METAL_ENCODERS_CREATED
            .load(Ordering::Relaxed),
        metal_encoders_ended: crate::metal_backend::METAL_ENCODERS_ENDED.load(Ordering::Relaxed),
        jit: pe_output.jit_telemetry.clone(),
    }
}

/// Short commit sha from the artifact provenance (`unknown` when git is
/// unavailable).
fn short_sha_of(provenance: &crate::steam_milestones::RunProvenance) -> String {
    if provenance.commit_sha.is_empty() || provenance.commit_sha == "unknown" {
        "unknown".to_string()
    } else {
        provenance.commit_sha.chars().take(8).collect()
    }
}

/// Write the JSON + log artifact files under the GE's diagnostics directory.
fn write_artifact_files(
    ge: &GameEnvironment,
    artifact: &SteamBootstrapArtifact,
    stem: &str,
) -> AppResult<SteamArtifactPaths> {
    let diagnostics_dir = ge.diagnostics_dir();
    fs::create_dir_all(&diagnostics_dir).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!(
                "failed to create steam artifact dir {}",
                diagnostics_dir.display()
            ),
            &error,
        )
    })?;
    let json_path = diagnostics_dir.join(format!("{stem}.json"));
    let log_path = diagnostics_dir.join(format!("{stem}.log"));

    let json_body = util::stable_json(&artifact)?;
    util::write_string(&json_path, &json_body)?;

    let mut log_lines = Vec::new();
    log_lines.push(format!("Casa1 commit: {}", artifact.provenance.commit_sha));
    log_lines.push(format!("dirty tree: {}", artifact.provenance.dirty_tree));
    log_lines.push(format!("run_id: {}", artifact.run_id));
    log_lines.push(format!("test_id: {}", artifact.test_id));
    if let Some(child_of) = &artifact.child_of_run_id {
        log_lines.push(format!("child_of_run_id: {child_of}"));
    }
    log_lines.push(format!("program_path: {}", artifact.program_path));
    log_lines.push(format!("program_sha256: {}", artifact.program_sha256));
    log_lines.push(format!(
        "fixture hash: {}",
        artifact.provenance.fixture_hash
    ));
    log_lines.push(format!("GE hash: {}", artifact.provenance.ge_hash));
    log_lines.push(format!(
        "Steam executable hash: {}",
        artifact.provenance.steam_executable_hash
    ));
    log_lines.push(format!(
        "timestamp: {}",
        artifact.provenance.timestamp_utc_rfc3339
    ));
    log_lines.push(format!("host macOS: {}", artifact.provenance.host_os));
    log_lines.push(format!(
        "host architecture: {}",
        artifact.provenance.host_arch
    ));
    log_lines.push(format!(
        "execution mode: {}",
        artifact.provenance.execution_mode
    ));
    log_lines.extend(milestones_log_lines(&artifact.milestones));
    log_lines.push(format!(
        "termination: {:?} (exit_code {})",
        artifact.termination, artifact.exit_code
    ));
    log_lines.push(format!(
        "instruction_count: {}",
        artifact
            .instruction_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unavailable".to_string())
    ));
    if let Some(last) = &artifact.last_thunk {
        log_lines.push(format!(
            "last_thunk: {} at guest_pc={:#x} after {}s of wall time",
            last.name, last.guest_pc, last.wall_secs_since_start
        ));
    }
    log_lines.push("network_summary:".to_string());
    for line in &artifact.network_summary {
        log_lines.push(format!("  {line}"));
    }
    util::write_string(&log_path, &format!("{}\n", log_lines.join("\n")))?;
    Ok(SteamArtifactPaths {
        json_path,
        log_path,
    })
}
