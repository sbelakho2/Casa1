use crate::diagnostics::{doctor, export_diagnostics};
use crate::error::{AppError, AppResult, ErrorResponse};
use crate::ge::{GameEnvironment, GeArch};
use crate::reason::ReasonCode;
use crate::runner::{RunIntent, RunnerJob, RunnerOutcome};
use crate::security::audit_embedded_entitlements;
use crate::trace;
use crate::util;
use crate::CLI_NAME;
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(name = CLI_NAME)]
pub struct HostCli {
    #[command(subcommand)]
    command: HostCommand,
}

#[derive(Debug, Subcommand)]
enum HostCommand {
    #[command(name = "ge:create")]
    GeCreate {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "x64")]
        arch: GeArch,
        #[arg(long, default_value = "win11-23h2")]
        winver: String,
    },
    #[command(name = "ge:run")]
    GeRun {
        #[arg(long)]
        ge: String,
        #[arg(long)]
        exe: PathBuf,
        #[arg(long)]
        input_replay: Option<PathBuf>,
        #[arg(long)]
        args: Option<String>,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long = "env")]
        env_pairs: Vec<String>,
        #[arg(long)]
        dtm: bool,
        #[arg(long)]
        trace_categories: Option<String>,
    },
    #[command(name = "ge:play")]
    GePlay {
        #[arg(long)]
        ge: String,
        #[arg(long)]
        exe: PathBuf,
        #[arg(long)]
        input_replay: Option<PathBuf>,
        #[arg(long)]
        args: Option<String>,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long = "env")]
        env_pairs: Vec<String>,
        #[arg(long)]
        trace_categories: Option<String>,
    },
    #[command(name = "ge:install")]
    GeInstall {
        #[arg(long)]
        ge: String,
        #[arg(long)]
        installer: PathBuf,
        #[arg(long)]
        silent: bool,
        #[arg(long)]
        dtm: bool,
        #[arg(long)]
        trace_categories: Option<String>,
    },
    #[command(name = "ge:export-diagnostics")]
    GeExportDiagnostics {
        #[arg(long)]
        ge: String,
        #[arg(long)]
        out: PathBuf,
    },
    #[command(name = "doctor")]
    Doctor {
        #[arg(long)]
        ge: String,
    },
    #[command(name = "security:audit-entitlements")]
    SecurityAuditEntitlements {
        #[arg(long)]
        jit_owner: String,
        #[arg(long = "binary", required = true)]
        binaries: Vec<PathBuf>,
        #[arg(long)]
        require_approved: bool,
    },
}

#[derive(Debug, Serialize)]
struct GeCreateResponse {
    pub name: String,
    pub ge_root: PathBuf,
    pub arch: String,
    pub winver: String,
}

pub fn host_main<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    match host_main_impl(args) {
        Ok(stdout) => {
            println!("{stdout}");
            0
        }
        Err(error) => {
            let response = util::stable_json(&error.to_response())
                .unwrap_or_else(|_| "{\"reason_code\":1000,\"reason_name\":\"RC_CLI_INVALID\",\"message\":\"failed to encode error\",\"reproduction_hints\":[]}".to_string());
            eprintln!("{response}");
            1
        }
    }
}

fn host_main_impl<I, S>(args: I) -> AppResult<String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = HostCli::parse_from(args);
    match cli.command {
        HostCommand::GeCreate { name, arch, winver } => {
            let ge = GameEnvironment::create(&name, arch.clone(), &winver)?;
            util::stable_json(&GeCreateResponse {
                name,
                ge_root: ge.root,
                arch: arch.as_str().to_string(),
                winver,
            })
        }
        HostCommand::GeRun {
            ge,
            exe,
            input_replay,
            args,
            cwd,
            env_pairs,
            dtm,
            trace_categories,
        } => {
            let ge = GameEnvironment::open(&ge)?;
            let mut env = parse_env_pairs(&env_pairs)?;
            insert_input_replay(&mut env, input_replay.as_deref())?;
            let job = RunnerJob {
                ge_name: ge.config.name.clone(),
                ge_root: ge.root.clone(),
                program: exe.clone(),
                args: parse_args(args.as_deref())?,
                cwd: cwd.unwrap_or_else(|| ge.root.clone()),
                env,
                dtm,
                intent: RunIntent::Run,
                trace_categories: resolve_trace_categories(trace_categories.as_deref(), RunIntent::Run)?,
                test_id: format!("run-{}", executable_stem(&exe)),
            };
            let outcome = dispatch_runner(&ge, &job)?;
            outcome.canonical_output.stable_json()
        }
        HostCommand::GePlay {
            ge,
            exe,
            input_replay,
            args,
            cwd,
            env_pairs,
            trace_categories,
        } => {
            let ge = GameEnvironment::open(&ge)?;
            let mut env = parse_env_pairs(&env_pairs)?;
            insert_input_replay(&mut env, input_replay.as_deref())?;
            let job = RunnerJob {
                ge_name: ge.config.name.clone(),
                ge_root: ge.root.clone(),
                program: exe.clone(),
                args: parse_args(args.as_deref())?,
                cwd: cwd.unwrap_or_else(|| ge.root.clone()),
                env,
                dtm: false,
                intent: RunIntent::Play,
                trace_categories: resolve_trace_categories(trace_categories.as_deref(), RunIntent::Play)?,
                test_id: format!("play-{}", executable_stem(&exe)),
            };
            let outcome = dispatch_runner(&ge, &job)?;
            outcome.canonical_output.stable_json()
        }
        HostCommand::GeInstall {
            ge,
            installer,
            silent,
            dtm,
            trace_categories,
        } => {
            let ge = GameEnvironment::open(&ge)?;
            let mut env = BTreeMap::new();
            if silent {
                env.insert("CASA1_INSTALL_SILENT".to_string(), "1".to_string());
            }
            let mut args = Vec::new();
            if silent {
                args.push("--silent".to_string());
            }
            let job = RunnerJob {
                ge_name: ge.config.name.clone(),
                ge_root: ge.root.clone(),
                program: installer.clone(),
                args,
                cwd: ge.root.clone(),
                env,
                dtm,
                intent: RunIntent::Install,
                trace_categories: resolve_trace_categories(trace_categories.as_deref(), RunIntent::Install)?,
                test_id: format!("install-{}", executable_stem(&installer)),
            };
            let outcome = dispatch_runner(&ge, &job)?;
            outcome.canonical_output.stable_json()
        }
        HostCommand::GeExportDiagnostics { ge, out } => {
            let ge = GameEnvironment::open(&ge)?;
            util::stable_json(&export_diagnostics(&ge, &out)?)
        }
        HostCommand::Doctor { ge } => {
            let ge = GameEnvironment::open(&ge)?;
            util::stable_json(&doctor(&ge)?)
        }
        HostCommand::SecurityAuditEntitlements {
            jit_owner,
            binaries,
            require_approved,
        } => {
            let report = audit_embedded_entitlements(&binaries, &jit_owner)?;
            if require_approved && !report.approved {
                let mut error = AppError::new(
                    ReasonCode::RcEntitlementAuditFailed,
                    format!(
                        "embedded entitlement audit failed for jit owner {}",
                        report.jit_owner
                    ),
                );
                for target in &report.unexpected_targets {
                    error = error.with_hint(format!("unexpected entitlement target: {target}"));
                }
                return Err(error);
            }
            util::stable_json(&report)
        }
    }
}

fn dispatch_runner(ge: &GameEnvironment, job: &RunnerJob) -> AppResult<RunnerOutcome> {
    let runner_binary = util::sibling_binary("casa1-runner")?;
    ensure_runner_binary_is_current(&runner_binary)?;
    let job_path = ge.job_path(&job.test_id);
    util::write_string(&job_path, &util::stable_json(job)?)?;
    let output = Command::new(&runner_binary)
        .arg("--job")
        .arg(&job_path)
        .output()
        .map_err(|error| {
            AppError::from_io(
                ReasonCode::RcRunnerSpawnFailed,
                format!("failed to run {}", runner_binary.display()),
                &error,
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if let Ok(response) = serde_json::from_str::<ErrorResponse>(&stderr) {
            return Err(AppError {
                code: ReasonCode::from_u32(response.reason_code).unwrap_or(ReasonCode::RcRunnerProtocolInvalid),
                message: response.message,
                reproduction_hints: response.reproduction_hints,
            });
        }
        return Err(AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            "runner failed without a valid JSON error response",
        )
        .with_hint(stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<RunnerOutcome>(&stdout).map_err(|error| {
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            "failed to parse runner output",
        )
        .with_hint(error.to_string())
    })
}

fn ensure_runner_binary_is_current(runner_binary: &Path) -> AppResult<()> {
    let current_executable = std::env::current_exe().map_err(|error| {
        AppError::from_io(ReasonCode::RcIo, "failed to resolve current executable", &error)
    })?;
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !manifest_dir.join("Cargo.toml").is_file() {
        return Ok(());
    }
    let runner_modified = fs::metadata(runner_binary)
        .and_then(|metadata| metadata.modified())
        .ok();
    let current_modified = fs::metadata(&current_executable)
        .and_then(|metadata| metadata.modified())
        .ok();
    let Some(runner_modified) = runner_modified else {
        return Ok(());
    };
    let Some(current_modified) = current_modified else {
        return Ok(());
    };
    if runner_modified >= current_modified {
        return Ok(());
    }

    let output = Command::new("cargo")
        .current_dir(manifest_dir)
        .args(["build", "--quiet", "--bin", "casa1-runner"])
        .output()
        .map_err(|error| {
            AppError::from_io(
                ReasonCode::RcRunnerSpawnFailed,
                "failed to refresh casa1-runner before launch",
                &error,
            )
        })?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut error = AppError::new(
        ReasonCode::RcRunnerSpawnFailed,
        "failed to rebuild casa1-runner before launch",
    );
    if !stderr.is_empty() {
        error = error.with_hint(stderr);
    }
    if !stdout.is_empty() {
        error = error.with_hint(stdout);
    }
    Err(error)
}

fn parse_args(args: Option<&str>) -> AppResult<Vec<String>> {
    match args {
        Some(value) => util::split_command_line(value),
        None => Ok(Vec::new()),
    }
}

fn parse_env_pairs(values: &[String]) -> AppResult<BTreeMap<String, String>> {
    let mut pairs = BTreeMap::new();
    for value in values {
        let (key, resolved_value) = util::parse_env_pair(value)?;
        pairs.insert(key, resolved_value);
    }
    Ok(pairs)
}

fn resolve_trace_categories(raw: Option<&str>, intent: RunIntent) -> AppResult<Vec<trace::TraceCategory>> {
    match raw {
        Some(value) => trace::parse_categories(Some(value)),
        None if intent == RunIntent::Play => trace::parse_categories(Some("process")),
        None => trace::parse_categories(None),
    }
}

fn insert_input_replay(env: &mut BTreeMap<String, String>, input_replay: Option<&Path>) -> AppResult<()> {
    if let Some(input_replay) = input_replay {
        env.insert(
            "CASA1_KEYBOARD_REPLAY_JSON".to_string(),
            read_input_replay(input_replay)?,
        );
    }
    Ok(())
}

fn read_input_replay(path: &Path) -> AppResult<String> {
    fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })
}

fn executable_stem(path: &Path) -> String {
    path.file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "guest".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn ge_play_parses_input_replay_flag() {
        let cli = HostCli::try_parse_from([
            "casa1",
            "ge:play",
            "--ge",
            "demo",
            "--exe",
            "guest.exe",
            "--input-replay",
            "replay.json",
        ])
        .expect("parse ge:play args");

        match cli.command {
            HostCommand::GePlay { input_replay, .. } => {
                assert_eq!(input_replay, Some(PathBuf::from("replay.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn insert_input_replay_loads_env_payload() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let replay_path = std::env::temp_dir().join(format!("casa1-cli-replay-{unique}.json"));
        fs::write(&replay_path, "[{\"scancode\":28}]").expect("write replay file");

        let mut env = BTreeMap::new();
        insert_input_replay(&mut env, Some(&replay_path)).expect("insert replay into env");

        assert_eq!(
            env.get("CASA1_KEYBOARD_REPLAY_JSON").map(String::as_str),
            Some("[{\"scancode\":28}]")
        );

        let _ = fs::remove_file(replay_path);
    }

    #[test]
    fn ge_play_defaults_to_process_trace_only() {
        let categories = resolve_trace_categories(None, RunIntent::Play).expect("default play trace categories");
        assert_eq!(categories, vec![trace::TraceCategory::Process]);
    }

    #[test]
    fn ge_run_defaults_to_all_trace_categories() {
        let categories = resolve_trace_categories(None, RunIntent::Run).expect("default run trace categories");
        assert_eq!(categories, trace::all_categories());
    }
}