use crate::canonical::{compare_outputs, comparison_error, CanonicalTestOutput, GuestException, ToleranceRegistry};
use crate::error::{AppError, AppResult};
use crate::ge::{diff_file_snapshots, diff_registry_snapshots, AppliedOverride, GameEnvironment};
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
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerOutcome {
    pub report_path: PathBuf,
    pub trace_path: PathBuf,
    pub log_path: PathBuf,
    pub canonical_output: CanonicalTestOutput,
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
    let mut ge = GameEnvironment::from_root(job.ge_root.clone())?;
    if job.program.exists() {
        if let Some(report) = detect_driver_requirement_on_disk(&job.program)? {
            return Err(driver_requirement_error(&report));
        }
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

    let mut effective_child_environment = child_environment(job, &ge, &guest_trace_path);
    let applied_override = if job.program.exists() {
        ge.apply_overrides_for_program(&job.program, &mut effective_child_environment)?
    } else {
        None
    };

    if let Some(request) = steam_zero_touch_request(job)? {
        let child_pid = pe_runtime::synthetic_pid(job.dtm);
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
        if request.libraryfolders_path.is_some() && request.library_root.is_none() && depot.library_root.is_none() {
            return Err(AppError::new(
                ReasonCode::RcRunnerProtocolInvalid,
                format!("Steam library metadata did not select a library for app {}", depot.app_id),
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
            steam_result.launch.env.get("SteamLibraryPath").map(String::as_str),
        )?;
        steam_client.materialize_into_ge(&mut ge, job.dtm)?;
        runner_events.push(log_steam_zero_touch_install(
            &mut logger,
            job,
            &steam_result,
        )?);
        runner_events.push(log_process_end_code(&mut logger, 0)?);

        let after_files = ge.snapshot_files(job.dtm, started)?;
        let after_registry = ge.snapshot_registry()?;
        let canonical_output = CanonicalTestOutput {
            test_id: job.test_id.clone(),
            build_id: BUILD_ID.to_string(),
            os_build: util::current_platform_build(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
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
        });
    }

    // Check for steam:// protocol URLs in the job arguments and dispatch them
    // before proceeding with PE execution. This handles the case where the runner
    // is invoked with a steam:// URL directly (e.g., from a macOS URL event).
    let steam_protocol_urls: Vec<String> = job.args.iter()
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
    if job.program.to_string_lossy().contains("Steam.exe")
        || job.program.to_string_lossy().contains("steam.exe")
    {
        let steam_flags = pe_runtime::process_steam_command_line(&job.args);
        if steam_flags.has_launch_command() {
            eprintln!(
                "[runner] Steam -applaunch {} detected, args={:?}",
                steam_flags.launch_app_id().unwrap_or(0),
                steam_flags.applaunch_args,
            );
        }
    }

    if job.program.exists() && pe_runtime::is_pe_image(&job.program)? {
        let child_pid = pe_runtime::synthetic_pid(job.dtm);
        let log_path = ge.log_path(&job.test_id, child_pid);
        let mut logger = JsonlLogger::new(&log_path, child_pid, job.dtm)?;
        let mut runner_events = Vec::new();
        if let Some(applied_override) = &applied_override {
            log_override_application(&mut logger, applied_override)?;
        }
        runner_events.extend(log_process_start(&mut logger, job, child_pid)?);
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

        let after_files = ge.snapshot_files(job.dtm, started)?;
        let after_registry = ge.snapshot_registry()?;
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
            network_summary: Vec::new(),
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

        return Ok(RunnerOutcome {
            report_path,
            trace_path,
            log_path,
            canonical_output,
        });
    }

    let mut command = Command::new(&job.program);
    command
        .args(&job.args)
        .current_dir(&job.cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in std::env::vars() {
        command.env(&key, &value);
    }

    for (key, value) in &effective_child_environment {
        command.env(key, value);
    }

    let child = command.spawn().map_err(|error| {
        AppError::from_io(
            ReasonCode::RcRunnerSpawnFailed,
            format!("failed to spawn {}", job.program.display()),
            &error,
        )
        .with_hint(format!("missing or non-executable program: {}", job.program.display()))
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
    let mut runner_events = runner_events;
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

    Ok(RunnerOutcome {
        report_path,
        trace_path,
        log_path,
        canonical_output,
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
    };
    let actual = execute_job(&job)?.canonical_output;
    compare_outputs(&record.expected_output, &actual, &ToleranceRegistry::default())
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
            && (job.env.get("CASA1_INSTALL_SILENT").is_some_and(|value| value == "1")
                || job.args.iter().any(|arg| arg == "--silent"))
        {
            "1"
        } else {
            "0"
        }
        .to_string(),
    );
    env.insert("CASA1_TEST_ID".to_string(), job.test_id.clone());
    env
}

fn execute_live_pe_job(
    job: &RunnerJob,
    ge: &GameEnvironment,
    effective_child_environment: &BTreeMap<String, String>,
) -> AppResult<pe_runtime::PeExecutionResult> {
    let (host_session, live_session) = live::new_live_session();
    let program = job.program.clone();
    let ge = ge.clone();
    let cwd = job.cwd.clone();
    let args = job.args.clone();
    let env = effective_child_environment.clone();
    let dtm = job.dtm;
    let test_id = job.test_id.clone();
    let worker = std::thread::spawn(move || {
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
            },
        )
    });
    live::run_live_host_session(&live_window_title(&job.program), host_session, worker)
}

fn live_window_title(path: &Path) -> String {
    path.file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "Casa1 Live PE".to_string())
}

fn log_process_start(
    logger: &mut JsonlLogger,
    job: &RunnerJob,
    child_pid: u32,
) -> AppResult<Vec<TraceEvent>> {
    let mut kv = BTreeMap::new();
    kv.insert("exe".to_string(), Value::String(job.program.display().to_string()));
    kv.insert(
        "args".to_string(),
        Value::Array(job.args.iter().cloned().map(Value::String).collect()),
    );
    kv.insert("cwd".to_string(), Value::String(job.cwd.display().to_string()));
    kv.insert("intent".to_string(), Value::String(job.intent.as_str().to_string()));
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

fn log_process_end(logger: &mut JsonlLogger, status: &std::process::ExitStatus) -> AppResult<TraceEvent> {
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
    Ok(trace_from_log_event(event, "process", "WaitForSingleObject", json!(exit_code), Vec::new()))
}

fn log_steam_zero_touch_install(
    logger: &mut JsonlLogger,
    job: &RunnerJob,
    result: &steam::SteamZeroTouchLaunchResult,
) -> AppResult<TraceEvent> {
    let steam_app_id = result
        .launch
        .env
        .get("SteamAppId")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    let launched = result.launch.input_ok && result.launch.audio_ok && result.launch.network_ok;
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
        "info",
        ReasonCode::Success,
        format!("zero-touch Steam install launched app {steam_app_id}"),
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
    runner_events.push(log_native_steam_install_recovery(logger, job, &install, error)?);
    Ok(Some(pe_runtime::PeExecutionResult {
        synthetic_pid: pe_runtime::synthetic_pid(job.dtm),
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        guest_exceptions: Vec::new(),
        gfx_frames: Vec::new(),
        perf: Vec::new(),
        trace_events: Vec::new(),
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

fn budget_exhausted(error: &AppError) -> bool {
    error.code == ReasonCode::RcUnimplInsn
        && error
            .message
            .starts_with("PE runtime exceeded the instruction budget")
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
        libraryfolders_path: job.env.get("CASA1_STEAM_LIBRARYFOLDERS_PATH").map(PathBuf::from),
        library_root: job.env.get("CASA1_STEAM_LIBRARY_ROOT").cloned(),
        library_host_root: job.env.get("CASA1_STEAM_LIBRARY_HOST_ROOT").map(PathBuf::from),
        library_host_map_path: job.env.get("CASA1_STEAM_LIBRARY_HOST_MAP_PATH").map(PathBuf::from),
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
    let host_map = serde_json::from_str::<BTreeMap<String, String>>(&contents).map_err(|error| {
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
    path.replace('\\', "/").to_ascii_lowercase().trim_end_matches('/').to_string()
}

fn required_env_path(job: &RunnerJob, key: &str) -> AppResult<PathBuf> {
    job.env
        .get(key)
        .map(PathBuf::from)
        .ok_or_else(|| {
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