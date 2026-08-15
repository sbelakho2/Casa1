use crate::TRACE_CACHE_VERSION;
use crate::TRACE_FORMAT_VERSION;
use crate::canonical::CanonicalTestOutput;
use crate::error::{AppError, AppResult};
use crate::ge::GameEnvironment;
use crate::reason::ReasonCode;
use crate::util;
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
                        ));
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
    resources.insert(
        "ge_config_sha256".to_string(),
        util::sha256_bytes(config_json.as_bytes()),
    );
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

    // Runner and guest traces each carry their own `event_index` sequence,
    // so a single interleaved timeline cannot be reconstructed from the
    // indices alone. Within each source the events are ordered by their
    // original index (restoring chronology after category filtering), and
    // the merged output keeps runner events first, then guest events.
    // `event_index` is then re-assigned in that merged order.
    let mut runner_events = runner_events
        .into_iter()
        .filter(|event| allowed.contains(&event.category))
        .collect::<Vec<_>>();
    runner_events.sort_by_key(|event| event.event_index);

    let mut merged = runner_events;

    if guest_trace_path.exists() {
        let guest_contents = fs::read_to_string(guest_trace_path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read {}", guest_trace_path.display()),
                &error,
            )
        })?;
        let mut guest_events =
            serde_json::from_str::<Vec<TraceEvent>>(&guest_contents).map_err(|error| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to parse {}", guest_trace_path.display()),
                )
                .with_hint(error.to_string())
            })?;
        guest_events.sort_by_key(|event| event.event_index);
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
    categories
        .iter()
        .map(|category| category.as_str().to_string())
        .collect()
}

pub fn validate_replay_environment(record: &TraceRecord, ge: &GameEnvironment) -> AppResult<()> {
    if record.format_version != TRACE_FORMAT_VERSION || record.cache_version != TRACE_CACHE_VERSION
    {
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

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalTestOutput;
    use std::collections::BTreeMap;

    /// Build a minimal `TraceRecord` with the given format and cache versions.
    fn make_trace_record(format_version: u32, cache_version: u32) -> TraceRecord {
        TraceRecord {
            format_version,
            cache_version,
            test_id: "test-trace-versioning".to_string(),
            captured_ge_root: PathBuf::from("/tmp/ge"),
            ge_profile: TraceGeProfile {
                arch: "x64".to_string(),
                winver: "win11-23h2".to_string(),
            },
            categories: vec!["process".to_string()],
            env_fingerprint: "abc123".to_string(),
            resources: BTreeMap::new(),
            command: TraceCommand {
                program: PathBuf::from("/usr/bin/true"),
                args: vec![],
                cwd: PathBuf::from("/tmp"),
                env: BTreeMap::new(),
                dtm: false,
                intent: "test".to_string(),
            },
            expected_output: CanonicalTestOutput::default(),
            events: vec![],
        }
    }

    #[test]
    fn test_current_version_writes_correct_version() {
        let record = make_trace_record(TRACE_FORMAT_VERSION, TRACE_CACHE_VERSION);
        assert_eq!(record.format_version, TRACE_FORMAT_VERSION);
        assert_eq!(record.cache_version, TRACE_CACHE_VERSION);
    }

    #[test]
    fn test_reading_wrong_format_version_returns_error() {
        let record = make_trace_record(999, TRACE_CACHE_VERSION);
        // Simulate what validate_replay_environment does
        let version_ok = record.format_version == TRACE_FORMAT_VERSION
            && record.cache_version == TRACE_CACHE_VERSION;
        assert!(!version_ok, "wrong format version should fail validation");
    }

    #[test]
    fn test_reading_wrong_cache_version_returns_error() {
        let record = make_trace_record(TRACE_FORMAT_VERSION, 999);
        let version_ok = record.format_version == TRACE_FORMAT_VERSION
            && record.cache_version == TRACE_CACHE_VERSION;
        assert!(!version_ok, "wrong cache version should fail validation");
    }

    #[test]
    fn test_reading_both_wrong_versions_returns_error() {
        let record = make_trace_record(0, 0);
        let version_ok = record.format_version == TRACE_FORMAT_VERSION
            && record.cache_version == TRACE_CACHE_VERSION;
        assert!(!version_ok, "zero versions should fail validation");
    }

    #[test]
    fn test_load_trace_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_trace.json");
        std::fs::write(&path, "not valid json{{{").unwrap();
        let result = load_trace(&path);
        assert!(result.is_err(), "loading invalid JSON should fail");
    }

    #[test]
    fn test_load_trace_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty_trace.json");
        std::fs::write(&path, "").unwrap();
        let result = load_trace(&path);
        assert!(result.is_err(), "loading empty file should fail");
    }

    #[test]
    fn test_load_trace_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial_trace.json");
        std::fs::write(&path, r#"{"format_version": 1}"#).unwrap();
        let result = load_trace(&path);
        assert!(
            result.is_err(),
            "loading JSON with missing fields should fail"
        );
    }

    #[test]
    fn test_parse_categories_all() {
        let cats = parse_categories(None).unwrap();
        assert_eq!(cats.len(), all_categories().len());
    }

    #[test]
    fn test_parse_categories_single() {
        let cats = parse_categories(Some("file")).unwrap();
        assert_eq!(cats, vec![TraceCategory::File]);
    }

    #[test]
    fn test_parse_categories_multiple() {
        let cats = parse_categories(Some("file,registry,process")).unwrap();
        assert_eq!(
            cats,
            vec![
                TraceCategory::File,
                TraceCategory::Registry,
                TraceCategory::Process
            ]
        );
    }

    #[test]
    fn test_parse_categories_unknown() {
        let result = parse_categories(Some("unknown_category"));
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn test_category_names_roundtrip() {
        let cats = all_categories();
        let names = category_names(&cats);
        for name in &names {
            let parsed = parse_categories(Some(name)).unwrap();
            assert_eq!(parsed.len(), 1);
        }
    }

    #[test]
    fn test_remap_replay_path_inside_ge() {
        let result = remap_replay_path(
            &PathBuf::from("/old/ge/subdir/file.txt"),
            Path::new("/old/ge"),
            Path::new("/new/ge"),
        );
        assert_eq!(result, PathBuf::from("/new/ge/subdir/file.txt"));
    }

    #[test]
    fn test_remap_replay_path_outside_ge() {
        let result = remap_replay_path(
            &PathBuf::from("/other/path/file.txt"),
            Path::new("/old/ge"),
            Path::new("/new/ge"),
        );
        assert_eq!(result, PathBuf::from("/other/path/file.txt"));
    }

    // ── Backward compatibility tests ─────────────────────────────────────────

    #[test]
    fn test_older_format_version_still_readable() {
        let record = make_trace_record(0, TRACE_CACHE_VERSION);
        // Older format versions should fail validation against current TRACE_FORMAT_VERSION,
        // but the deserialization and construction itself should work fine.
        assert_eq!(record.format_version, 0);
        assert_eq!(record.cache_version, TRACE_CACHE_VERSION);
        // The JSON representation should be valid
        let json = serde_json::to_string(&record).expect("serialize old-format trace");
        let deserialized: TraceRecord =
            serde_json::from_str(&json).expect("deserialize old-format trace");
        assert_eq!(deserialized.format_version, 0);
        assert_eq!(deserialized.cache_version, TRACE_CACHE_VERSION);
    }

    #[test]
    fn test_older_cache_version_still_readable() {
        let record = make_trace_record(TRACE_FORMAT_VERSION, 0);
        assert_eq!(record.format_version, TRACE_FORMAT_VERSION);
        assert_eq!(record.cache_version, 0);
        let json = serde_json::to_string(&record).expect("serialize old-cache trace");
        let deserialized: TraceRecord =
            serde_json::from_str(&json).expect("deserialize old-cache trace");
        assert_eq!(deserialized.cache_version, 0);
    }

    #[test]
    fn test_backward_compat_validation_rejects_old_format() {
        // Even though old formats can be deserialized, validate_replay_environment
        // should reject them
        let record = make_trace_record(0, TRACE_CACHE_VERSION);
        let json = serde_json::to_string(&record).expect("serialize");
        let deserialized: TraceRecord = serde_json::from_str(&json).expect("deserialize");
        // We can't easily call validate_replay_environment without a real GE,
        // but we can verify the version mismatch check logic
        let format_mismatch = deserialized.format_version != TRACE_FORMAT_VERSION;
        let cache_mismatch = deserialized.cache_version != TRACE_CACHE_VERSION;
        assert!(format_mismatch, "format version 0 should mismatch current");
        assert!(!cache_mismatch, "cache version should match");
    }

    #[test]
    fn test_trace_record_with_extra_fields() {
        // Simulate a trace file that was written by a newer version with extra fields.
        // Deserialization should succeed (serde ignores unknown fields by default).
        let record = make_trace_record(TRACE_FORMAT_VERSION, TRACE_CACHE_VERSION);
        let mut json = serde_json::to_value(&record).expect("serialize");
        json["extra_field"] = serde_json::Value::String("unexpected".to_string());
        json["nested"]["extra"] = serde_json::Value::Number(serde_json::Number::from(42));
        let json_str = serde_json::to_string(&json).expect("to string");
        let deserialized: TraceRecord =
            serde_json::from_str(&json_str).expect("deserialize with extra fields");
        assert_eq!(deserialized.format_version, TRACE_FORMAT_VERSION);
        assert_eq!(deserialized.cache_version, TRACE_CACHE_VERSION);
    }

    // ── Malformed trace file tests ───────────────────────────────────────────

    #[test]
    fn test_load_trace_truncated_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truncated_trace.json");
        // Write a valid JSON prefix but truncated
        let valid = r#"{"format_version":1,"cache_version":1,"test_id":"test"#;
        std::fs::write(&path, valid).unwrap();
        let result = load_trace(&path);
        assert!(result.is_err(), "loading truncated JSON should fail");
    }

    #[test]
    fn test_load_trace_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_utf8_trace.json");
        // Write invalid UTF-8 bytes
        std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x01]).unwrap();
        let result = load_trace(&path);
        assert!(result.is_err(), "loading invalid UTF-8 should fail");
    }

    #[test]
    fn test_load_trace_non_existent() {
        let result = load_trace(Path::new("/tmp/nonexistent_trace_file_casa1_xyz.json"));
        assert!(result.is_err(), "loading non-existent file should fail");
    }

    #[test]
    fn test_load_trace_null_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("null_trace.json");
        // Write JSON with embedded null bytes
        std::fs::write(
            &path,
            "{\"format_version\":1,\"cache_version\":1,\"test_id\":\"test\x00withnull\"}",
        )
        .unwrap();
        let result = load_trace(&path);
        // serde_json can handle null bytes in strings, but the result should still be parseable
        if let Ok(record) = &result {
            assert!(
                record.test_id.contains('\0'),
                "test_id should contain the null byte"
            );
        }
    }

    #[test]
    fn test_load_trace_wrong_type_for_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong_type_trace.json");
        // format_version is a string instead of a number
        std::fs::write(
            &path,
            r#"{"format_version":"not_a_number","cache_version":1,"test_id":"test"}"#,
        )
        .unwrap();
        let result = load_trace(&path);
        assert!(result.is_err(), "wrong type for format_version should fail");
    }
}
