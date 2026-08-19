// MODEL ONLY — not Windows truth.
//
// Everything in this module is a DETERMINISTIC FALLBACK implementation of
// Windows semantics, used by the host harness to generate expectations and
// to compute Casa1-side results for the differential oracle. The model can
// be wrong: a mistaken Windows assumption can live in the runtime and its
// model at the same time. The authoritative answer is the reference
// executable (`windows_reference/casa1-windows-reference`) running on real
// Windows 10/11; this module is only the fallback that makes the harness
// runnable without a Windows host, and the comparison pipeline exists
// precisely to detect where the model diverges from Windows.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

// ── Legacy suite schema types (section2 / section3 oracle output) ──────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathEdgeSuite {
    pub cases: Vec<PathEdgeCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathEdgeCase {
    pub input: String,
    pub long_paths_enabled: bool,
    pub outcome: PathEdgeOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathEdgeOutcome {
    Success {
        normalized_path: String,
        verbatim: bool,
        device_namespace: bool,
    },
    Error {
        reason_code: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseCollisionSuite {
    pub create_directory: String,
    pub collision_directory: String,
    pub ascii_file: String,
    pub unicode_file: String,
    pub unicode_lookup: String,
    pub enumeration_path: String,
    pub directory_collision_code: u32,
    pub unicode_collision_code: u32,
    pub resolved_unicode_path: String,
    pub enumeration: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockShareSuite {
    pub path: String,
    pub share_violation_code: u32,
    pub lock_violation_code: u32,
    pub first_lock_offset: u64,
    pub first_lock_length: u64,
    pub overlap_offset: u64,
    pub overlap_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryNotifySuite {
    pub hive: String,
    pub key: String,
    pub recursive: bool,
    pub operations: Vec<RegistryNotifyOperation>,
    pub expected_wake_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistryNotifyOperation {
    Set {
        value: String,
        value_type: String,
        data: Value,
    },
    Delete {
        value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DllOrderSuite {
    pub root_module: String,
    pub dependencies: BTreeMap<String, Vec<String>>,
    pub tls_callbacks: BTreeMap<String, Vec<u64>>,
    pub expected_log_lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleLogEntry {
    pub module: String,
    pub stage: String,
    pub value: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelayLoadSuite {
    pub cases: Vec<DelayLoadCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelayLoadCase {
    pub scenario: String,
    pub requested_module: String,
    pub symbol: DelayLoadSymbol,
    pub provider_exports: BTreeMap<String, Vec<ExportSpec>>,
    pub expected: DelayLoadExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelayLoadSymbol {
    ByName { name: String },
    // NOTE: kept as u16 to match the in-tree consumer `tests/section3.rs`
    // (`ImportSymbol::ByOrdinal` is u16 and is owned by another fixer batch).
    // Widening to u32 (consistent with `ExportSpec::ordinal`) requires a
    // coordinated change of that consumer first.
    ByOrdinal { ordinal: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSpec {
    pub ordinal: u32,
    pub name: Option<String>,
    pub target: ExportSpecTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExportSpecTarget {
    Rva { value: u32 },
    Forwarder { value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelayLoadExpectation {
    Resolved { export: ExportSpec },
    StructuredException { code: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiSetSuite {
    pub cases: Vec<ApiSetCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiSetCase {
    pub contract: String,
    pub expected_host: String,
}

// ── Legacy oracle constants (section2 / section3 model outputs) ────────────

pub const RC_FS_ALREADY_EXISTS: u32 = 1101;
pub const RC_FS_RESERVED_NAME: u32 = 1103;
pub const RC_FS_PATH_TOO_LONG: u32 = 1104;
pub const RC_FS_SHARING_VIOLATION: u32 = 1105;
pub const RC_FS_LOCK_VIOLATION: u32 = 1106;
pub const STATUS_DLL_NOT_FOUND: u32 = 0xc000_0135;
pub const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xc000_0139;

// ── Legacy model implementations (moved from the old casa1-oracle binary) ──

#[derive(Debug, Default)]
pub struct OracleDirectory {
    by_folded_name: BTreeMap<String, String>,
}

impl OracleDirectory {
    pub fn create(&mut self, name: &str) -> Result<(), u32> {
        let folded = oracle_fold_key(name);
        if self.by_folded_name.contains_key(&folded) {
            return Err(RC_FS_ALREADY_EXISTS);
        }
        self.by_folded_name.insert(folded, name.to_string());
        Ok(())
    }

    pub fn resolve(&self, requested: &str) -> Option<String> {
        self.by_folded_name
            .get(&oracle_fold_key(requested))
            .cloned()
    }

    pub fn enumeration(&self) -> Vec<String> {
        let mut values = self.by_folded_name.values().cloned().collect::<Vec<_>>();
        values.sort();
        values
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OracleFileAccess {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct OracleShareMode {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct OracleOpenState {
    pub desired_access: OracleFileAccess,
    pub share_mode: OracleShareMode,
}

pub fn oracle_parse_windows_path(input: &str, long_paths_enabled: bool) -> PathEdgeOutcome {
    let mut raw = input.replace('/', "\\");
    let verbatim = raw.starts_with("\\\\?\\");
    let device_namespace = raw.starts_with("\\\\.\\");
    if device_namespace {
        return PathEdgeOutcome::Success {
            normalized_path: raw,
            verbatim: false,
            device_namespace: true,
        };
    }
    if verbatim {
        raw = raw.trim_start_matches("\\\\?\\").to_string();
    }
    if raw.len() < 2 || !raw.as_bytes()[0].is_ascii_alphabetic() || raw.as_bytes()[1] != b':' {
        return PathEdgeOutcome::Error {
            reason_code: RC_FS_RESERVED_NAME,
        };
    }
    let drive = raw[0..1].to_ascii_uppercase();
    let mut remainder = raw[2..].to_string();
    if remainder.is_empty() {
        remainder.push('\\');
    }
    let mut components = Vec::new();
    for component in remainder.split('\\') {
        if component.is_empty() {
            continue;
        }
        let normalized_component = if verbatim {
            component.to_string()
        } else if component == "." {
            continue;
        } else if component == ".." {
            components.pop();
            continue;
        } else {
            let trimmed = component.trim_end_matches([' ', '.']);
            if trimmed.is_empty() {
                continue;
            }
            if is_reserved_dos_name(trimmed) {
                return PathEdgeOutcome::Error {
                    reason_code: RC_FS_RESERVED_NAME,
                };
            }
            trimmed.to_string()
        };
        components.push(normalized_component);
    }
    let normalized_path = if verbatim {
        format!("\\\\?\\{}", build_drive_path(&drive, &components))
    } else {
        build_drive_path(
            &drive,
            &components
                .iter()
                .map(|component| component.to_lowercase())
                .collect::<Vec<_>>(),
        )
    };
    if !verbatim && !long_paths_enabled && normalized_path.len() > 260 {
        return PathEdgeOutcome::Error {
            reason_code: RC_FS_PATH_TOO_LONG,
        };
    }
    PathEdgeOutcome::Success {
        normalized_path,
        verbatim,
        device_namespace: false,
    }
}

pub fn oracle_fold_key(value: &str) -> String {
    let mut folded = String::new();
    for character in value.chars() {
        let mut uppercase = character.to_uppercase();
        match (uppercase.next(), uppercase.next()) {
            (Some(single), None) => folded.push(single),
            _ => {
                let mut lowercase = character.to_lowercase();
                match (lowercase.next(), lowercase.next()) {
                    (Some(single), None) => folded.push(single),
                    _ => folded.push(character),
                }
            }
        }
    }
    folded
}

pub fn share_conflict(
    existing: &OracleOpenState,
    desired_access: OracleFileAccess,
    share_mode: OracleShareMode,
) -> bool {
    (desired_access.read && !existing.share_mode.read)
        || (desired_access.write && !existing.share_mode.write)
        || (desired_access.delete && !existing.share_mode.delete)
        || (existing.desired_access.read && !share_mode.read)
        || (existing.desired_access.write && !share_mode.write)
        || (existing.desired_access.delete && !share_mode.delete)
}

pub fn ranges_overlap(
    left_offset: u64,
    left_length: u64,
    right_offset: u64,
    right_length: u64,
) -> bool {
    let left_end = left_offset.saturating_add(left_length);
    let right_end = right_offset.saturating_add(right_length);
    left_offset < right_end && right_offset < left_end
}

pub fn oracle_load_order(
    root_module: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    oracle_visit(
        &normalize_module_name(root_module),
        dependencies,
        &mut visiting,
        &mut visited,
        &mut order,
    );
    order
}

fn oracle_visit(
    module: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if visited.contains(module) {
        return;
    }
    if !visiting.insert(module.to_string()) {
        return;
    }
    for dependency in dependencies.get(module).into_iter().flatten() {
        oracle_visit(
            &normalize_module_name(dependency),
            dependencies,
            visiting,
            visited,
            order,
        );
    }
    visiting.remove(module);
    visited.insert(module.to_string());
    order.push(module.to_string());
}

pub fn oracle_lifecycle_log_lines(
    load_order: &[String],
    tls_callbacks: &BTreeMap<String, Vec<u64>>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for module in load_order {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_process_attach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_process_attach", None));
    }
    for module in load_order {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_thread_attach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_thread_attach", None));
    }
    for module in load_order.iter().rev() {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_thread_detach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_thread_detach", None));
    }
    for module in load_order.iter().rev() {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_process_detach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_process_detach", None));
    }
    lines
}

fn log_line(module: &str, stage: &str, value: Option<u64>) -> String {
    serde_json::to_string(&LifecycleLogEntry {
        module: module.to_string(),
        stage: stage.to_string(),
        value,
    })
    .expect("encode lifecycle log line")
}

pub fn resolve_delay_expectation(
    requested_module: &str,
    symbol: &DelayLoadSymbol,
    provider_exports: &BTreeMap<String, Vec<ExportSpec>>,
) -> DelayLoadExpectation {
    let resolved_module = normalize_module_name(requested_module);
    let Some(exports) = provider_exports.get(&resolved_module) else {
        return DelayLoadExpectation::StructuredException {
            code: STATUS_DLL_NOT_FOUND,
        };
    };
    match oracle_lookup_export(
        symbol,
        &resolved_module,
        exports,
        provider_exports,
        &mut BTreeSet::new(),
    ) {
        Some(export) => DelayLoadExpectation::Resolved { export },
        None => DelayLoadExpectation::StructuredException {
            code: STATUS_ENTRYPOINT_NOT_FOUND,
        },
    }
}

fn oracle_lookup_export(
    symbol: &DelayLoadSymbol,
    current_module: &str,
    exports: &[ExportSpec],
    provider_exports: &BTreeMap<String, Vec<ExportSpec>>,
    visited: &mut BTreeSet<String>,
) -> Option<ExportSpec> {
    let visit_key = format!("{}::{symbol:?}", current_module);
    if !visited.insert(visit_key) {
        return None;
    }
    let export = match symbol {
        DelayLoadSymbol::ByName { name } => exports
            .iter()
            .find(|export| export.name.as_deref() == Some(name.as_str()))
            .cloned(),
        DelayLoadSymbol::ByOrdinal { ordinal } => exports
            .iter()
            .find(|export| export.ordinal == *ordinal as u32)
            .cloned(),
    }?;
    match &export.target {
        ExportSpecTarget::Rva { .. } => Some(export),
        ExportSpecTarget::Forwarder { value } => {
            let (module_name, forwarded_symbol) = parse_forwarder(value)?;
            let exports = provider_exports.get(&module_name)?;
            oracle_lookup_export(
                &forwarded_symbol,
                &module_name,
                exports,
                provider_exports,
                visited,
            )
        }
    }
}

fn parse_forwarder(value: &str) -> Option<(String, DelayLoadSymbol)> {
    let (module, symbol) = value.split_once('.')?;
    if let Some(rest) = symbol.strip_prefix('#') {
        // Parse failure (e.g. an ordinal beyond u16) fails loudly instead of
        // silently truncating; the model keeps u16 to match the in-tree
        // `ImportSymbol::ByOrdinal` consumer.
        let ordinal = rest.parse::<u16>().ok()?;
        Some((
            normalize_module_name(module),
            DelayLoadSymbol::ByOrdinal { ordinal },
        ))
    } else {
        Some((
            normalize_module_name(module),
            DelayLoadSymbol::ByName {
                name: symbol.to_string(),
            },
        ))
    }
}

pub fn oracle_api_set_resolve(dll_name: &str) -> String {
    let normalized = normalize_module_name(dll_name);
    // Check the COM api-set contracts first: every `api-ms-win-core-com-*`
    // name also starts with `api-ms-win-core-`, so the generic core arm must
    // not shadow it.
    if normalized.starts_with("api-ms-win-com-") || normalized.starts_with("api-ms-win-core-com-") {
        return "ole32.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-core-") {
        return "kernel32.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-crt-") {
        return "ucrtbase.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-security-")
        || normalized.starts_with("api-ms-win-service-")
    {
        return "advapi32.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-shell-") {
        return "shell32.dll".to_string();
    }
    if normalized.starts_with("ext-ms-win-ntuser-") {
        return "user32.dll".to_string();
    }
    normalized
}

pub fn normalize_module_name(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.contains('.') {
        normalized
    } else {
        format!("{normalized}.dll")
    }
}

fn build_drive_path(drive: &str, components: &[String]) -> String {
    if components.is_empty() {
        format!("{drive}:\\")
    } else {
        format!("{drive}:\\{}", components.join("\\"))
    }
}

pub fn is_reserved_dos_name(component: &str) -> bool {
    let name = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    matches!(
        name.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

// ── Differential-oracle model predictors ───────────────────────────────────
//
// Each `model_*` function predicts the reference executable's output for one
// vector category from the vector input alone. The predictions follow the
// documented Win32 semantics; where Windows behavior is version- or
// device-dependent the corpus avoids the ambiguous case (see
// docs/WINDOWS_ORACLE.md for the exact scope).

/// Win32 error codes used by the model predictions.
pub mod win32_errors {
    pub const ERROR_FILE_NOT_FOUND: u32 = 2;
    pub const ERROR_ACCESS_DENIED: u32 = 5;
    pub const ERROR_SHARING_VIOLATION: u32 = 32;
    pub const ERROR_LOCK_VIOLATION: u32 = 33;
    pub const ERROR_INVALID_PARAMETER: u32 = 87;
    pub const ERROR_INVALID_NAME: u32 = 123;
    pub const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
    pub const ERROR_NOT_OWNER: u32 = 288;
    pub const EINVAL: u32 = 22;
    pub const ERANGE: u32 = 34;
    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_TIMEOUT: u32 = 258;
    pub const WAIT_ABANDONED: u32 = 128;
    pub const TLS_OUT_OF_INDEXES: u32 = 0xffff_ffff;
    pub const TLS_MINIMUM_AVAILABLE: u32 = 64;
    pub const LONG_MAX: i64 = 2_147_483_647;
    pub const LONG_MIN: i64 = -2_147_483_648;
}

use win32_errors::*;

/// Dispatch a vector to its category model predictor. Unknown categories
/// produce an explicit placeholder result so the comparison can report them
/// instead of failing silently.
pub fn predict(category: &str, input: &Value) -> Value {
    match category {
        "path_normalize" => model_path_normalize(input),
        "case_fold" => model_case_fold(input),
        "file_sharing" => model_file_sharing(input),
        "file_lock" => model_file_lock(input),
        "delete_semantics" => model_delete_semantics(input),
        "api_set" => model_api_set(input),
        "registry" => model_registry(input),
        "synchronization" => model_synchronization(input),
        "crt_printf" => model_crt_printf(input),
        "thread_tls" => model_thread_tls(input),
        _ => json!({ "error": format!("unknown_category: {category}") }),
    }
}

// ── path_normalize ──────────────────────────────────────────────────────────

/// Classify a Windows path string into one of the documented Win32 path
/// kinds. This is a schema-level classification of the input shape (shared
/// by the model and the reference executor), not a Windows semantic.
pub fn classify_path_kind(input: &str) -> &'static str {
    if input.starts_with("\\\\?\\") {
        "verbatim"
    } else if input.starts_with("\\\\.\\") {
        "device"
    } else if input.starts_with("\\\\") {
        "unc"
    } else if input.len() >= 2
        && input.as_bytes()[0].is_ascii_alphabetic()
        && input.as_bytes()[1] == b':'
    {
        if input.len() == 2 || input.as_bytes()[2] != b'\\' {
            "drive_rel"
        } else {
            "drive_abs"
        }
    } else if input.starts_with('\\') {
        "rooted"
    } else {
        "relative"
    }
}

/// Whether the input contains an NTFS alternate-data-stream separator (`:`)
/// beyond the drive-letter colon (and beyond any verbatim/device prefix).
/// Shared by the model and the reference executor.
pub fn classify_has_ads(input: &str) -> bool {
    let mut rest = input;
    for prefix in ["\\\\?\\", "\\\\.\\"] {
        if rest.starts_with(prefix) {
            rest = &rest[prefix.len()..];
            break;
        }
    }
    if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
        rest = &rest[2..];
    }
    rest.contains(':')
}

pub fn model_path_normalize(input: &Value) -> Value {
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let cwd = input.get("cwd").and_then(Value::as_str).map(str::to_string);
    let long_paths_enabled = input
        .get("long_paths_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let kind = classify_path_kind(&path);
    let has_ads = classify_has_ads(&path);
    let (normalized, last_error) = match model_get_full_path_name(&path, cwd.as_deref()) {
        Ok(normalized) => {
            if !long_paths_enabled && !path.starts_with("\\\\?\\") && normalized.len() > 260 {
                (String::new(), ERROR_FILENAME_EXCED_RANGE)
            } else {
                (normalized, 0)
            }
        }
        Err(error) => (String::new(), error),
    };
    json!({
        "normalized": normalized,
        "kind": kind,
        "has_ads": has_ads,
        "last_error": last_error,
    })
}

/// Model of `GetFullPathNameW`: a pure string normalization. Device and
/// verbatim paths pass through unchanged; UNC/drive/rooted/relative paths
/// collapse separators and `.`/`..` components (clamped at their root) and
/// are joined with the reference working directory where needed. Case is
/// preserved, matching `GetFullPathNameW`.
fn model_get_full_path_name(path: &str, cwd: Option<&str>) -> Result<String, u32> {
    if path.is_empty() {
        return Err(ERROR_INVALID_NAME);
    }
    if path.starts_with("\\\\.\\") || path.starts_with("\\\\?\\") {
        return Ok(path.to_string());
    }
    if let Some(rest) = path.strip_prefix("\\\\") {
        let components = rest.split('\\').collect::<Vec<_>>();
        if components.len() < 2 || components[0].is_empty() || components[1].is_empty() {
            return Ok(path.to_string());
        }
        let root = format!("\\\\{}\\{}", components[0], components[1]);
        let mut stack: Vec<&str> = vec![components[0], components[1]];
        for component in components.iter().skip(2) {
            match *component {
                "" | "." => {}
                ".." => {
                    if stack.len() > 2 {
                        stack.pop();
                    }
                }
                other => stack.push(other),
            }
        }
        let mut out = root;
        for component in stack.iter().skip(2) {
            out.push('\\');
            out.push_str(component);
        }
        return Ok(out);
    }

    let drive: Option<char> =
        (path.len() >= 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':')
            .then(|| path.as_bytes()[0] as char);

    let (root, min_depth, body): (String, usize, &str) = if let Some(drive_letter) = drive {
        let rest = &path[2..];
        if rest.is_empty() {
            let root = cwd_on_drive(cwd, drive_letter);
            return Ok(format!("{drive_letter}:{root}\\"));
        }
        if rest.starts_with('\\') {
            (format!("{drive_letter}:"), 0, rest)
        } else {
            (
                format!("{drive_letter}:{}", cwd_on_drive(cwd, drive_letter)),
                0,
                rest,
            )
        }
    } else if path.starts_with('\\') {
        let root = if cwd.is_some_and(|value| value.len() >= 2) {
            cwd.as_ref()
                .map(|value| value[0..1].to_string() + ":")
                .unwrap_or_else(|| "C:".to_string())
        } else {
            "C:".to_string()
        };
        (root, 0, path)
    } else {
        (
            cwd.unwrap_or_default().trim_end_matches('\\').to_string(),
            0,
            path,
        )
    };

    let mut stack: Vec<String> = Vec::new();
    for component in body.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                if stack.len() > min_depth {
                    stack.pop();
                }
            }
            other => stack.push(other.to_string()),
        }
    }
    let mut out = root;
    for component in stack {
        out.push('\\');
        out.push_str(&component);
    }
    Ok(out)
}

/// The cwd portion (without the drive) of the reference working directory on
/// the given drive, used for drive-relative inputs (`C:foo`).
fn cwd_on_drive(cwd: Option<&str>, drive_letter: char) -> String {
    match cwd {
        Some(value) if value.len() >= 2 && value.as_bytes()[0].is_ascii_alphabetic() => {
            let value_drive = value.as_bytes()[0] as char;
            let value_drive = value_drive.to_ascii_uppercase();
            if value_drive == drive_letter.to_ascii_uppercase() {
                value[2..].trim_end_matches('\\').to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

// ── case_fold ───────────────────────────────────────────────────────────────

// C1_* character-type bits as returned by GetStringTypeW(CT_CTYPE1).
const C1_UPPER: u32 = 0x0001;
const C1_LOWER: u32 = 0x0002;
const C1_DIGIT: u32 = 0x0004;
const C1_SPACE: u32 = 0x0008;
const C1_PUNCT: u32 = 0x0010;
#[allow(dead_code)] // reserved for C1 control classification in case-fold vectors
const C1_CNTRL: u32 = 0x0020;
const C1_BLANK: u32 = 0x0040;
const C1_XDIGIT: u32 = 0x0080;
const C1_ALPHA: u32 = 0x0100;
const C1_DEFINED: u32 = 0x0200;

/// Simple-uppercase mapping used by `CompareStringOrdinal(IGNORE_CASE)`: the
/// ordinal fold is per-code-unit simple uppercasing, so `ß` stays `ß` (no
/// multi-char expansion) and `ς`/`µ` map to `Σ`/`Μ`.
fn ordinal_upcase(character: char) -> char {
    match character {
        'a'..='z' => character.to_ascii_uppercase(),
        'ς' => 'Σ',
        'µ' => 'Μ',
        'ß' => 'ß',
        // Latin-1 lowercase accented letters (the corpus uses é; the rest are
        // covered for completeness).
        '\u{00E0}'..='\u{00F6}' | '\u{00F8}'..='\u{00FE}' => {
            let upper = character.to_uppercase().next().unwrap_or(character);
            if upper.len_utf8() == 1 {
                upper
            } else {
                character
            }
        }
        // Greek lowercase letters (simple uppercase mapping).
        '\u{03B1}'..='\u{03C9}' => {
            let upper = character.to_uppercase().next().unwrap_or(character);
            if upper.len_utf8() == 1 {
                upper
            } else {
                character
            }
        }
        other => other,
    }
}

/// C1 character-type bits for the corpus characters, per the Windows
/// `GetStringTypeW` classification.
fn c1_type_bits(character: char) -> u32 {
    let mut bits = 0u32;
    let code = character as u32;
    if character.is_alphabetic() {
        bits |= C1_ALPHA;
    }
    match code {
        0x30..=0x39 => bits |= C1_DIGIT,
        0x20 => bits |= C1_SPACE | C1_BLANK,
        0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => bits |= C1_PUNCT,
        _ => {}
    }
    if (0x30..=0x39).contains(&code)
        || (0x41..=0x46).contains(&code)
        || (0x61..=0x66).contains(&code)
    {
        bits |= C1_XDIGIT;
    }
    if (0x41..=0x5A).contains(&code) || code == 0x03A3 || code == 0x039C || code == 0x00C9 {
        bits |= C1_UPPER;
    }
    if (0x61..=0x7A).contains(&code)
        || code == 0x03C2
        || code == 0x00DF
        || code == 0x00E9
        || code == 0x00B5
    {
        bits |= C1_LOWER;
    }
    if bits != 0 {
        bits |= C1_DEFINED;
    }
    bits
}

fn c1_bits_for_string(value: &str) -> Vec<u32> {
    value.chars().map(c1_type_bits).collect()
}

pub fn model_case_fold(input: &Value) -> Value {
    let left = input
        .get("left")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let right = input
        .get("right")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let equal = {
        let left_folded: String = left.chars().map(ordinal_upcase).collect();
        let right_folded: String = right.chars().map(ordinal_upcase).collect();
        left_folded == right_folded
    };
    json!({
        "ordinal_ignore_case_equal": equal,
        "left_c1_type_bits": c1_bits_for_string(left),
        "right_c1_type_bits": c1_bits_for_string(right),
    })
}

// ── file_sharing ────────────────────────────────────────────────────────────

/// Model of the Win32 share-conflict check for a SECOND open against an
/// existing open. Windows only checks whether the NEW open's requested
/// access is permitted by the EXISTING open's share mode — the new open's
/// share mode never constrains its own open. (This deliberately differs from
/// the legacy symmetric `share_conflict` above, which is kept for section2
/// compatibility.)
pub fn windows_share_conflict(
    existing_share: &crate::windows_oracle::ShareSpec,
    desired_access: &crate::windows_oracle::AccessSpec,
) -> bool {
    (desired_access.read && !existing_share.read)
        || (desired_access.write && !existing_share.write)
        || (desired_access.delete && !existing_share.delete)
}

pub fn model_file_sharing(input: &Value) -> Value {
    let parsed: Result<crate::windows_oracle::FileSharingInput, _> =
        serde_json::from_value(input.clone());
    let Ok(spec) = parsed else {
        return json!({ "second_open_succeeds": false, "second_error": ERROR_INVALID_PARAMETER });
    };
    let conflict = windows_share_conflict(&spec.first_share, &spec.second_access);
    if conflict {
        json!({ "second_open_succeeds": false, "second_error": ERROR_SHARING_VIOLATION })
    } else {
        json!({ "second_open_succeeds": true, "second_error": 0 })
    }
}

// ── file_lock ───────────────────────────────────────────────────────────────

pub fn model_file_lock(input: &Value) -> Value {
    let parsed: Result<crate::windows_oracle::FileLockInput, _> =
        serde_json::from_value(input.clone());
    let Ok(spec) = parsed else {
        return json!({ "lock1": null, "lock2": null, "unlock1": null, "lock3": null });
    };
    let overlapping = ranges_overlap(
        spec.first_offset,
        spec.first_length,
        spec.second_offset,
        spec.second_length,
    );
    let lock2_ok = !overlapping || spec.same_handle;
    let lock2 = json!({
        "performed": true,
        "succeeded": lock2_ok,
        "error": if lock2_ok { 0 } else { ERROR_LOCK_VIOLATION },
    });
    let unlock1 = json!({ "performed": spec.unlock_after_second, "succeeded": true, "error": 0 });
    json!({
        "lock1": { "performed": true, "succeeded": true, "error": 0 },
        "lock2": lock2,
        "unlock1": unlock1,
        "lock3": {
            "performed": spec.retry_after_unlock,
            "succeeded": spec.retry_after_unlock,
            "error": 0,
        },
    })
}

// ── delete_semantics ────────────────────────────────────────────────────────

pub fn model_delete_semantics(input: &Value) -> Value {
    let parsed: Result<crate::windows_oracle::DeleteSemanticsInput, _> =
        serde_json::from_value(input.clone());
    let Ok(spec) = parsed else {
        return json!({ "success": false, "error": ERROR_INVALID_PARAMETER, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": ERROR_INVALID_PARAMETER });
    };
    match spec.op.as_str() {
        "delete" => {
            if spec.first_open && !spec.first_share.delete {
                json!({ "success": false, "error": ERROR_SHARING_VIOLATION, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 0 })
            } else {
                json!({ "success": true, "error": 0, "file_exists_after": false, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 0 })
            }
        }
        "rename" => {
            if spec.first_open && !spec.first_share.delete {
                json!({ "success": false, "error": ERROR_SHARING_VIOLATION, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 0 })
            } else {
                json!({ "success": true, "error": 0, "file_exists_after": false, "rename_succeeded": true, "second_open_succeeded": false, "second_open_error": 0 })
            }
        }
        "delete_then_reopen" => {
            if spec.first_open && !spec.first_share.delete {
                json!({ "success": false, "error": ERROR_SHARING_VIOLATION, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 0 })
            } else {
                // Delete-pending: the file is removed from the namespace but
                // the open handle keeps it alive; a new open of the path
                // fails with ERROR_ACCESS_DENIED until the handle closes.
                json!({ "success": true, "error": 0, "file_exists_after": false, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": ERROR_ACCESS_DENIED })
            }
        }
        _ => {
            json!({ "success": false, "error": ERROR_INVALID_PARAMETER, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 0 })
        }
    }
}

// ── api_set ─────────────────────────────────────────────────────────────────

/// Expected api-set host DLLs for the corpus contracts. Per Microsoft's
/// api-set documentation the schema mapping is device-dependent; these are
/// the well-known Windows 10/11 x64 hosts and the differential comparison
/// reports any divergence (the loader's actual answer is authoritative).
pub fn api_set_expected_host(contract: &str) -> Option<String> {
    let normalized = crate::oracle_model::normalize_module_name(contract);
    match normalized.as_str() {
        "api-ms-win-core-file-l1-1-0.dll" => Some("kernelbase.dll".to_string()),
        "api-ms-win-core-synch-l1-1-0.dll" => Some("kernel32.dll".to_string()),
        "api-ms-win-core-com-l1-1-0.dll" => Some("ole32.dll".to_string()),
        "api-ms-win-crt-runtime-l1-1-0.dll" => Some("ucrtbase.dll".to_string()),
        "ext-ms-win-ntuser-window-l1-1-0.dll" => Some("user32.dll".to_string()),
        "kernel32.dll" => Some("kernel32.dll".to_string()),
        _ => None,
    }
}

pub fn model_api_set(input: &Value) -> Value {
    let contract = input
        .get("contract")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let probe = input
        .get("probe")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match api_set_expected_host(contract) {
        Some(host) => json!({
            "loads": true,
            "resolved_module": host,
            "export_resolvable": probe_export_expected(contract, probe),
        }),
        None => json!({
            "loads": false,
            "resolved_module": "",
            "export_resolvable": false,
        }),
    }
}

/// Whether the probe export is expected to resolve for a known contract.
fn probe_export_expected(contract: &str, probe: &str) -> bool {
    let known_probes = [
        ("api-ms-win-core-file-l1-1-0.dll", "CreateFileW"),
        ("api-ms-win-core-synch-l1-1-0.dll", "CreateEventW"),
        ("api-ms-win-core-com-l1-1-0.dll", "CoCreateInstance"),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "memset"),
        ("ext-ms-win-ntuser-window-l1-1-0.dll", "CreateWindowExW"),
        ("kernel32.dll", "BaseThreadInitThunk"),
    ];
    known_probes
        .iter()
        .any(|(known_contract, known_probe)| *known_contract == contract && *known_probe == probe)
}

// ── registry ────────────────────────────────────────────────────────────────

fn registry_type_code(value_type: &str) -> Option<u32> {
    match value_type {
        "REG_SZ" => Some(1),
        "REG_EXPAND_SZ" => Some(2),
        "REG_BINARY" => Some(3),
        "REG_DWORD" => Some(4),
        _ => None,
    }
}

pub fn model_registry(input: &Value) -> Value {
    let parsed: Result<crate::windows_oracle::RegistryInput, _> =
        serde_json::from_value(input.clone());
    let Ok(spec) = parsed else {
        return json!({ "error": ERROR_INVALID_PARAMETER, "value_bytes": "", "value_type": null });
    };
    match spec.op.as_str() {
        "query_missing" | "set_query_delete" => {
            json!({ "error": ERROR_FILE_NOT_FOUND, "value_bytes": "", "value_type": null })
        }
        "create_twice" => {
            json!({ "error": 0, "value_bytes": "", "value_type": null })
        }
        "set_query" => {
            let type_code = registry_type_code(&spec.value_type).unwrap_or(0);
            let bytes = registry_value_bytes(&spec.value_type, &spec.data);
            json!({ "error": 0, "value_bytes": crate::windows_oracle::hex_encode(&bytes), "value_type": type_code })
        }
        _ => json!({ "error": ERROR_INVALID_PARAMETER, "value_bytes": "", "value_type": null }),
    }
}

/// The exact byte payload RegSetValueExW stores for a typed value (this is
/// what RegQueryValueExW returns unchanged).
pub fn registry_value_bytes(value_type: &str, data: &Value) -> Vec<u8> {
    match value_type {
        "REG_DWORD" => {
            let value = data.as_u64().unwrap_or(0) as u32;
            value.to_le_bytes().to_vec()
        }
        "REG_SZ" | "REG_EXPAND_SZ" => {
            crate::windows_oracle::utf16le_with_nul(data.as_str().unwrap_or_default())
        }
        "REG_BINARY" => data
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_u64().unwrap_or(0) as u8)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

// ── synchronization ─────────────────────────────────────────────────────────

pub fn model_synchronization(input: &Value) -> Value {
    let kind = input
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match kind {
        "event_auto_reset" => json!({
            "waits": [WAIT_OBJECT_0, WAIT_TIMEOUT],
            "releases": [],
            "abandoned": false,
        }),
        "event_manual_reset" => json!({
            "waits": [WAIT_OBJECT_0, WAIT_OBJECT_0, WAIT_TIMEOUT],
            "releases": [],
            "abandoned": false,
        }),
        "mutex_recursion" => json!({
            "waits": [WAIT_OBJECT_0, WAIT_OBJECT_0, WAIT_OBJECT_0],
            "releases": [
                { "succeeded": true, "error": 0 },
                { "succeeded": true, "error": 0 },
                { "succeeded": true, "error": 0 },
                { "succeeded": false, "error": ERROR_NOT_OWNER },
            ],
            "abandoned": false,
        }),
        "mutex_non_owner_release" => json!({
            "waits": [WAIT_OBJECT_0],
            "releases": [
                { "succeeded": false, "error": ERROR_NOT_OWNER },
            ],
            "abandoned": false,
        }),
        "mutex_abandoned" => json!({
            "waits": [WAIT_OBJECT_0, WAIT_ABANDONED],
            "releases": [
                { "succeeded": true, "error": 0 },
            ],
            "abandoned": true,
        }),
        "semaphore" => json!({
            "waits": [WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_OBJECT_0, WAIT_OBJECT_0, WAIT_OBJECT_0, WAIT_TIMEOUT],
            "releases": [
                { "succeeded": true, "error": 0 },
                { "succeeded": true, "error": 0 },
            ],
            "abandoned": false,
        }),
        _ => json!({ "waits": [], "releases": [], "abandoned": false }),
    }
}

// ── crt_printf ──────────────────────────────────────────────────────────────

pub fn model_crt_printf(input: &Value) -> Value {
    let kind = input
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match kind {
        "percent_n_disabled" => json!({
            "handler_invoked": true,
            "ret": -1,
            "errno": EINVAL,
            "written": null,
            "value": null,
            "end_consumed": null,
            "buffer": null,
        }),
        "percent_n_enabled" => json!({
            "handler_invoked": false,
            "ret": 2,
            "errno": 0,
            "written": 2,
            "value": null,
            "end_consumed": null,
            "buffer": null,
        }),
        "strtol_overflow" => json!({
            "handler_invoked": false,
            "ret": null,
            "errno": ERANGE,
            "written": null,
            "value": LONG_MAX,
            "end_consumed": true,
            "buffer": null,
        }),
        "strtol_underflow" => json!({
            "handler_invoked": false,
            "ret": null,
            "errno": ERANGE,
            "written": null,
            "value": LONG_MIN,
            "end_consumed": true,
            "buffer": null,
        }),
        "strtol_bad_base" => json!({
            "handler_invoked": false,
            "ret": null,
            "errno": EINVAL,
            "written": null,
            "value": 0,
            "end_consumed": false,
            "buffer": null,
        }),
        "strtol_hex_ok" => json!({
            "handler_invoked": false,
            "ret": null,
            "errno": 0,
            "written": null,
            "value": 0x7fff_ffff,
            "end_consumed": true,
            "buffer": null,
        }),
        "snprintf_truncation" => json!({
            "handler_invoked": false,
            "ret": 6,
            "errno": 0,
            "written": null,
            "value": null,
            "end_consumed": null,
            "buffer": "abc",
        }),
        "snprintf_size_query" => json!({
            "handler_invoked": false,
            "ret": 1,
            "errno": 0,
            "written": null,
            "value": null,
            "end_consumed": null,
            "buffer": null,
        }),
        "snprintf_null_format" => json!({
            "handler_invoked": true,
            "ret": -1,
            "errno": EINVAL,
            "written": null,
            "value": null,
            "end_consumed": null,
            "buffer": null,
        }),
        _ => json!({
            "handler_invoked": false,
            "ret": null,
            "errno": 0,
            "written": null,
            "value": null,
            "end_consumed": null,
            "buffer": null,
        }),
    }
}

// ── thread_tls ──────────────────────────────────────────────────────────────

pub fn model_thread_tls(input: &Value) -> Value {
    let kind = input
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match kind {
        "alloc" => json!({ "index_valid": true }),
        "roundtrip" => json!({ "set_succeeded": true, "get_matches": true }),
        "thread_isolation" => json!({
            "other_thread_value_is_null": true,
            "main_value_preserved": true,
        }),
        "minimum_available" => json!({ "minimum_available": TLS_MINIMUM_AVAILABLE }),
        "free_succeeds" => json!({ "free_succeeded": true }),
        "realloc_valid" => json!({ "new_index_valid": true }),
        "set_invalid_index" => json!({ "succeeded": false, "error": ERROR_INVALID_PARAMETER }),
        "get_invalid_index" => json!({ "value_is_null": true, "error": ERROR_INVALID_PARAMETER }),
        _ => json!({ "error": ERROR_INVALID_PARAMETER }),
    }
}
