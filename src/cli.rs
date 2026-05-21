use crate::app_bundle::{create_app_bundle, AppBundleConfig, is_app_registered, list_installed_apps, register_with_launch_services, uninstall_app};
use crate::diagnostics::{doctor, export_diagnostics};
use crate::error::{AppError, AppResult, ErrorResponse};
use crate::ge::{GameEnvironment, GeArch};
use crate::icon::extract_icon_from_pe;
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
        steam_update_plan: Option<PathBuf>,
        #[arg(long)]
        steam_cert_chain: Option<PathBuf>,
        #[arg(long)]
        steam_appmanifest: Option<PathBuf>,
        #[arg(long)]
        steam_installscript: Option<PathBuf>,
        #[arg(long)]
        steam_payload_root: Option<PathBuf>,
        #[arg(long)]
        steam_libraryfolders: Option<PathBuf>,
        #[arg(long)]
        steam_library_root: Option<String>,
        #[arg(long)]
        steam_library_host_root: Option<PathBuf>,
        #[arg(long)]
        steam_library_host_map: Option<PathBuf>,
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
    #[command(name = "apps:install")]
    AppsInstall {
        #[arg(long)]
        ge: String,
        #[arg(long)]
        exe: PathBuf,
        #[arg(long)]
        app_name: Option<String>,
        #[arg(long)]
        bundle_id: Option<String>,
        #[arg(long)]
        args: Option<String>,
        #[arg(long)]
        icon_source: Option<PathBuf>,
        #[arg(long)]
        skip_launch_services: bool,
        #[arg(long)]
        url_schemes: Vec<String>,
    },
    #[command(name = "apps:list")]
    AppsList,
    #[command(name = "apps:uninstall")]
    AppsUninstall {
        #[arg(long)]
        app_name: String,
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
            steam_update_plan,
            steam_cert_chain,
            steam_appmanifest,
            steam_installscript,
            steam_payload_root,
            steam_libraryfolders,
            steam_library_root,
            steam_library_host_root,
            steam_library_host_map,
            trace_categories,
        } => {
            let ge = GameEnvironment::open(&ge)?;
            let mut env = BTreeMap::new();
            if silent {
                env.insert("CASA1_INSTALL_SILENT".to_string(), "1".to_string());
            }
            insert_steam_zero_touch_inputs(
                &mut env,
                steam_update_plan.as_deref(),
                steam_cert_chain.as_deref(),
                steam_appmanifest.as_deref(),
                steam_installscript.as_deref(),
                steam_payload_root.as_deref(),
                steam_libraryfolders.as_deref(),
                steam_library_root.as_deref(),
                steam_library_host_root.as_deref(),
                steam_library_host_map.as_deref(),
            )?;
            let args = install_args(&installer, silent)?;
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
        HostCommand::AppsInstall {
            ge,
            exe,
            app_name,
            bundle_id,
            args,
            icon_source,
            skip_launch_services,
            url_schemes,
        } => {
                let ge = GameEnvironment::open(&ge)?;
                let name = app_name.unwrap_or_else(|| {
                    exe.file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Unnamed".to_string())
                });
                let apps_dir = ge.root.join("apps");
                fs::create_dir_all(&apps_dir).map_err(|e| {
                    AppError::from_io(ReasonCode::RcIo, format!("failed to create apps dir"), &e)
                })?;
    
                // Extract icon from the PE executable if no external icon source
                let icon_data = if let Some(icon_path) = icon_source {
                    Some(fs::read(&icon_path).map_err(|e| {
                        AppError::from_io(ReasonCode::RcIo, format!("failed to read icon file"), &e)
                    })?)
                } else {
                    extract_icon_from_pe(&exe)
                        .ok()
                        .flatten()
                        .and_then(|icon_img| crate::icon::icons_to_icns(&[icon_img]).ok())
                };
    
                let config = AppBundleConfig {
                    app_name: name.clone(),
                    executable_path: exe.to_string_lossy().to_string(),
                    args,
                    ge_name: ge.config.name.clone(),
                    icon_data,
                    bundle_id,
                    min_system_version: None,
                    high_resolution: None,
                    url_schemes,
                    app_category: None,
                };
    
                let app_path = create_app_bundle(&config, &apps_dir)?;
    
                if !skip_launch_services {
                    match register_with_launch_services(&app_path) {
                        Ok(_) => {},
                        Err(e) => {
                            eprintln!("Warning: Launch Services registration failed: {:?}", e);
                        }
                    }
                }
    
                util::stable_json(&serde_json::json!({
                    "app_name": name,
                    "app_path": app_path.to_string_lossy(),
                    "launch_services_registered": !skip_launch_services,
                }))
            }
            HostCommand::AppsList => {
                let apps_dir = find_apps_dir()?;
                let apps = list_installed_apps(&apps_dir)?;
                util::stable_json(&serde_json::json!({
                    "apps": apps,
                    "apps_dir": apps_dir.to_string_lossy(),
                }))
            }
            HostCommand::AppsUninstall { app_name } => {
                let apps_dir = find_apps_dir()?;
                let app_path = apps_dir.join(&app_name).with_extension("app");
                uninstall_app(&app_path)?;
                util::stable_json(&serde_json::json!({
                    "app_name": app_name,
                    "uninstalled": true,
                }))
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

fn install_args(installer: &Path, silent: bool) -> AppResult<Vec<String>> {
    if !silent {
        return Ok(Vec::new());
    }

    let bytes = fs::read(installer).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", installer.display()),
            &error,
        )
    })?;
    Ok(detect_installer_silent_args(&bytes))
}

fn detect_installer_silent_args(bytes: &[u8]) -> Vec<String> {
    if contains_ascii_marker(bytes, b"Nullsoft.NSIS.exehead")
        || contains_ascii_marker(bytes, b"Nullsoft Install System")
        || contains_ascii_marker(bytes, b"NullsoftInst")
    {
        return vec!["/S".to_string()];
    }
    if contains_ascii_marker(bytes, b"Inno Setup Setup Data")
        || contains_ascii_marker(bytes, b"inno setup")
    {
        return vec!["/VERYSILENT".to_string(), "/SUPPRESSMSGBOXES".to_string()];
    }
    vec!["--silent".to_string()]
}

fn contains_ascii_marker(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
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

fn insert_steam_zero_touch_inputs(
    env: &mut BTreeMap<String, String>,
    steam_update_plan: Option<&Path>,
    steam_cert_chain: Option<&Path>,
    steam_appmanifest: Option<&Path>,
    steam_installscript: Option<&Path>,
    steam_payload_root: Option<&Path>,
    steam_libraryfolders: Option<&Path>,
    steam_library_root: Option<&str>,
    steam_library_host_root: Option<&Path>,
    steam_library_host_map: Option<&Path>,
) -> AppResult<()> {
    let required_steam_args = [
        steam_update_plan.is_some(),
        steam_cert_chain.is_some(),
        steam_appmanifest.is_some(),
        steam_installscript.is_some(),
        steam_payload_root.is_some(),
    ];
    let has_any_steam_inputs = required_steam_args.iter().any(|present| *present)
        || steam_libraryfolders.is_some()
        || steam_library_root.is_some()
        || steam_library_host_root.is_some()
        || steam_library_host_map.is_some();
    if !has_any_steam_inputs {
        return Ok(());
    }
    if !required_steam_args.iter().all(|present| *present) {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "Steam zero-touch install requires all Steam metadata flags together",
        )
        .with_hint("required flags: --steam-update-plan, --steam-cert-chain, --steam-appmanifest, --steam-installscript, --steam-payload-root"));
    }
    if steam_library_host_root.is_some() && steam_library_root.is_none() {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "Steam library host root requires --steam-library-root",
        )
        .with_hint("provide both --steam-library-root and --steam-library-host-root to map a guest Steam library drive onto an external host path"));
    }
    if steam_library_host_map.is_some() && steam_library_root.is_none() && steam_libraryfolders.is_none() {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "Steam library host map requires --steam-library-root or --steam-libraryfolders",
        )
        .with_hint("provide --steam-libraryfolders for metadata-driven selection, or --steam-library-root for an explicit library target"));
    }
    if steam_library_host_root.is_some() && steam_library_host_map.is_some() {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "Steam library host root and host map are mutually exclusive",
        )
        .with_hint("use --steam-library-host-root for one explicit library, or --steam-library-host-map for metadata-driven multi-library selection"));
    }

    env.insert("CASA1_STEAM_ZERO_TOUCH".to_string(), "1".to_string());
    env.insert(
        "CASA1_STEAM_UPDATE_PLAN_PATH".to_string(),
        steam_update_plan.expect("validated").display().to_string(),
    );
    env.insert(
        "CASA1_STEAM_CERT_CHAIN_PATH".to_string(),
        steam_cert_chain.expect("validated").display().to_string(),
    );
    env.insert(
        "CASA1_STEAM_APPMANIFEST_PATH".to_string(),
        steam_appmanifest.expect("validated").display().to_string(),
    );
    env.insert(
        "CASA1_STEAM_INSTALLSCRIPT_PATH".to_string(),
        steam_installscript.expect("validated").display().to_string(),
    );
    env.insert(
        "CASA1_STEAM_PAYLOAD_ROOT".to_string(),
        steam_payload_root.expect("validated").display().to_string(),
    );
    if let Some(steam_libraryfolders) = steam_libraryfolders {
        env.insert(
            "CASA1_STEAM_LIBRARYFOLDERS_PATH".to_string(),
            steam_libraryfolders.display().to_string(),
        );
    }
    if let Some(steam_library_root) = steam_library_root {
        env.insert(
            "CASA1_STEAM_LIBRARY_ROOT".to_string(),
            steam_library_root.to_string(),
        );
    }
    if let Some(steam_library_host_root) = steam_library_host_root {
        env.insert(
            "CASA1_STEAM_LIBRARY_HOST_ROOT".to_string(),
            steam_library_host_root.display().to_string(),
        );
    }
    if let Some(steam_library_host_map) = steam_library_host_map {
        env.insert(
            "CASA1_STEAM_LIBRARY_HOST_MAP_PATH".to_string(),
            steam_library_host_map.display().to_string(),
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

/// Find the apps directory for Casa1 app bundles.
fn find_apps_dir() -> AppResult<PathBuf> {
    if let Ok(apps_dir) = std::env::var("CASA1_APPS_DIR") {
        let path = PathBuf::from(apps_dir);
        fs::create_dir_all(&path).map_err(|e| {
            AppError::from_io(ReasonCode::RcIo, "failed to create CASA1_APPS_DIR", &e)
        })?;
        return Ok(path);
    }
    let home = std::env::var("HOME").map_err(|_| {
        AppError::new(ReasonCode::RcIo, "HOME not set")
    })?;
    let apps_dir = PathBuf::from(home).join(".casa1").join("apps");
    fs::create_dir_all(&apps_dir).map_err(|e| {
        AppError::from_io(ReasonCode::RcIo, "failed to create ~/.casa1/apps", &e)
    })?;
    Ok(apps_dir)
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

    #[test]
    fn detect_installer_silent_args_prefers_nsis_switches() {
        let args = detect_installer_silent_args(b"Nullsoft.NSIS.exehead\0Nullsoft Install System v3.0");
        assert_eq!(args, vec!["/S".to_string()]);
    }
}