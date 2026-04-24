use crate::canonical::CanonicalTestOutput;
use crate::error::{AppError, AppResult};
use crate::ge::GameEnvironment;
use crate::reason::ReasonCode;
use crate::util;
use crate::TRACE_CACHE_VERSION;
use crate::TRACE_FORMAT_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TraceCategory {
    File,
    Registry,
    Process,
    Thread,
    Time,
    Input,
    Network,
    D3d12,
    Dxgi,
    Shader,
    Audio,
}

impl TraceCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Registry => "registry",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Time => "time",
            Self::Input => "input",
            Self::Network => "network",
            Self::D3d12 => "d3d12",
            Self::Dxgi => "dxgi",
            Self::Shader => "shader",
            Self::Audio => "audio",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEvent {
    pub event_index: u64,
    pub category: String,
    pub call_id: String,
    pub parameters: BTreeMap<String, Value>,
    pub return_value: Value,
    pub get_last_error: Option<u32>,
    pub side_effect_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceGeProfile {
    pub arch: String,
    pub winver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub dtm: bool,
    pub intent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRecord {
    pub format_version: u32,
    pub cache_version: u32,
    pub test_id: String,
    pub captured_ge_root: PathBuf,
    pub ge_profile: TraceGeProfile,
    pub categories: Vec<String>,
    pub env_fingerprint: String,
    pub resources: BTreeMap<String, String>,
    pub command: TraceCommand,
    pub expected_output: CanonicalTestOutput,
    pub events: Vec<TraceEvent>,
}

impl TraceRecord {
    pub fn stable_json(&self) -> AppResult<String> {
        util::stable_json(self)
    }
}

pub fn all_categories() -> Vec<TraceCategory> {
    vec![
        TraceCategory::File,
        TraceCategory::Registry,
        TraceCategory::Process,
        TraceCategory::Thread,
        TraceCategory::Time,
        TraceCategory::Input,
        TraceCategory::Network,
        TraceCategory::D3d12,
        TraceCategory::Dxgi,
        TraceCategory::Shader,
        TraceCategory::Audio,
    ]
}

pub fn parse_categories(input: Option<&str>) -> AppResult<Vec<TraceCategory>> {
    match input {
        None => Ok(all_categories()),
        Some(value) => {
            let mut categories = Vec::new();
            for part in value.split(',') {
                let category = match part.trim() {
                    "file" => TraceCategory::File,
                    "registry" => TraceCategory::Registry,
                    "process" => TraceCategory::Process,
                    "thread" => TraceCategory::Thread,
                    "time" => TraceCategory::Time,
                    "input" => TraceCategory::Input,
                    "network" => TraceCategory::Network,
                    "d3d12" => TraceCategory::D3d12,
                    "dxgi" => TraceCategory::Dxgi,
                    "shader" => TraceCategory::Shader,
                    "audio" => TraceCategory::Audio,
                    unknown => {
                        return Err(AppError::new(
                            ReasonCode::RcCliInvalid,
                            format!("unknown trace category {unknown}"),
                        ))
                    }
                };
                categories.push(category);
            }
            if categories.is_empty() {
                Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "at least one trace category is required",
                ))
            } else {
                Ok(categories)
            }
        }
    }
}

pub fn load_trace(path: &Path) -> AppResult<TraceRecord> {
    let contents = fs::read_to_string(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    serde_json::from_str(&contents).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to parse {}", path.display()),
        )
        .with_hint(error.to_string())
    })
}

pub fn compute_env_fingerprint(
    ge: &GameEnvironment,
    command: &TraceCommand,
) -> AppResult<(String, BTreeMap<String, String>)> {
    let program_hash = util::sha256_file(&command.program)?;
    let config_fingerprint = (
        ge.config.schema_version,
        ge.config.arch.as_str(),
        &ge.config.winver,
        &ge.config.user_name,
        ge.config.long_paths_enabled,
        &ge.config.drive_mappings,
        &ge.config.override_profiles,
    );
    let config_json = util::stable_json(&config_fingerprint)?;
    let mut resources = BTreeMap::new();
    resources.insert("program_sha256".to_string(), program_hash.clone());
    resources.insert("ge_config_sha256".to_string(), util::sha256_bytes(config_json.as_bytes()));
    resources.insert(
        "trace_cache_version".to_string(),
        TRACE_CACHE_VERSION.to_string(),
    );
    let normalized_cwd = normalize_replay_path(&command.cwd, &ge.root);
    let fingerprint_source = util::stable_json(&(
        &command.program,
        &command.args,
        normalized_cwd,
        &command.env,
        command.dtm,
        &command.intent,
        &config_fingerprint,
        &resources,
        util::current_platform_build(),
    ))?;
    Ok((util::sha256_bytes(fingerprint_source.as_bytes()), resources))
}

pub fn merge_events(
    runner_events: Vec<TraceEvent>,
    guest_trace_path: &Path,
    categories: &[TraceCategory],
) -> AppResult<Vec<TraceEvent>> {
    let allowed = categories
        .iter()
        .map(|category| category.as_str().to_string())
        .collect::<BTreeSet<_>>();
    let mut merged = runner_events
        .into_iter()
        .filter(|event| allowed.contains(&event.category))
        .collect::<Vec<_>>();

    if guest_trace_path.exists() {
        let guest_contents = fs::read_to_string(guest_trace_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read {}", guest_trace_path.display()),
                &error,
            )
        })?;
        let guest_events = serde_json::from_str::<Vec<TraceEvent>>(&guest_contents).map_err(|error| {
            AppError::new(
                ReasonCode::RcIo,
                format!("failed to parse {}", guest_trace_path.display()),
            )
            .with_hint(error.to_string())
        })?;
        merged.extend(
            guest_events
                .into_iter()
                .filter(|event| allowed.contains(&event.category)),
        );
    }

    for (index, event) in merged.iter_mut().enumerate() {
        event.event_index = index as u64;
    }
    Ok(merged)
}

pub fn category_names(categories: &[TraceCategory]) -> Vec<String> {
    categories.iter().map(|category| category.as_str().to_string()).collect()
}

pub fn validate_replay_environment(record: &TraceRecord, ge: &GameEnvironment) -> AppResult<()> {
    if record.format_version != TRACE_FORMAT_VERSION || record.cache_version != TRACE_CACHE_VERSION {
        return Err(AppError::new(
            ReasonCode::RcTraceEnvMismatch,
            "trace format or cache version mismatch during replay",
        )
        .with_hint(format!(
            "expected format {} cache {}, got format {} cache {}",
            TRACE_FORMAT_VERSION, TRACE_CACHE_VERSION, record.format_version, record.cache_version
        )));
    }
    let mut replay_command = record.command.clone();
    replay_command.cwd = remap_replay_path(&record.command.cwd, &record.captured_ge_root, &ge.root);
    let (current_fingerprint, _) = compute_env_fingerprint(ge, &replay_command)?;
    if current_fingerprint != record.env_fingerprint {
        return Err(AppError::new(
            ReasonCode::RcTraceEnvMismatch,
            "trace replay environment does not match captured environment",
        )
        .with_hint("the executable hash, GE config, or trace cache version changed"));
    }
    Ok(())
}

pub fn remap_replay_path(path: &Path, captured_ge_root: &Path, replay_ge_root: &Path) -> PathBuf {
    match path.strip_prefix(captured_ge_root) {
        Ok(relative) => replay_ge_root.join(relative),
        Err(_) => path.to_path_buf(),
    }
}

fn normalize_replay_path(path: &Path, ge_root: &Path) -> String {
    match path.strip_prefix(ge_root) {
        Ok(relative) => format!("<GE_ROOT>/{}", relative.display()),
        Err(_) => path.display().to_string(),
    }
}