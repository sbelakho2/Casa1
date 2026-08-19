//! Wire protocol for the Windows differential oracle.
//!
//! This module defines the versioned vector/result schema shared between the
//! host harness (`casa1-oracle`) and the standalone reference executable
//! (`windows_reference/casa1-windows-reference`), plus the deterministic
//! vector corpus generator and the result comparison engine.
//!
//! The schema is deliberately small and extensible: each vector is
//! `{ "id", "category", "input" }` where `input` is a category-specific JSON
//! object, and each result is `{ "id", "category", "output" }`. Adding a new
//! category only requires a new `input`/`output` shape, a generator arm, a
//! model predictor in [`crate::oracle_model`], and an executor arm in the
//! reference crate — nothing in the wire format changes.
//!
//! `schema_version` is checked by both sides and must match; bump it whenever
//! an existing category's input/output shape changes incompatibly.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Version of the vector/result wire protocol. Both the host harness and the
/// reference executable reject files with a different `schema_version`.
pub const WINDOWS_ORACLE_SCHEMA_VERSION: u64 = 1;

/// Fixed working directory used for cwd-dependent `path_normalize` vectors.
/// The reference executable creates this directory and calls
/// `SetCurrentDirectoryW` into it so that relative/rooted/drive-relative
/// inputs normalize deterministically on every Windows host.
pub const REFERENCE_CWD: &str = "C:\\Windows\\Temp\\casa1-oracle-cwd";

/// Root directory under which file-based categories (`file_sharing`,
/// `file_lock`, `delete_semantics`) create their scratch files.
pub const REFERENCE_BASE_DIR: &str = "C:\\Windows\\Temp\\casa1-oracle";

/// All category names, in corpus generation order.
pub const ALL_CATEGORIES: [&str; 10] = [
    "path_normalize",
    "case_fold",
    "file_sharing",
    "file_lock",
    "delete_semantics",
    "api_set",
    "registry",
    "synchronization",
    "crt_printf",
    "thread_tls",
];

// ── Wire schema ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorFile {
    pub schema_version: u64,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub id: String,
    pub category: String,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceResultsFile {
    pub schema_version: u64,
    pub capture: CaptureHeader,
    pub results: Vec<VectorResult>,
}

/// Capture provenance header. Files produced by the real reference executable
/// on Windows carry `captured_by: "casa1-windows-reference"`; model-generated
/// fixtures keep the same shape but are explicitly marked as placeholders so
/// they can never be mistaken for real Windows captures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureHeader {
    pub source: String,
    pub captured_by: String,
    pub captured_on: String,
    pub capture_date: String,
    pub note: Option<String>,
}

impl CaptureHeader {
    /// Header for a file captured by the reference executable on real Windows.
    pub fn windows_capture() -> Self {
        CaptureHeader {
            source: "windows".to_string(),
            captured_by: "casa1-windows-reference".to_string(),
            captured_on: "windows-10-11".to_string(),
            capture_date: iso_date_now(),
            note: None,
        }
    }

    /// Header for a model-computed results file (bootstrap/golden fixtures).
    /// Marked explicitly so the file can never be mistaken for real Windows
    /// truth.
    pub fn model_generated() -> Self {
        CaptureHeader {
            source: "windows".to_string(),
            captured_by: "casa1-windows-reference".to_string(),
            captured_on: "windows-10-11".to_string(),
            capture_date: "model-generated".to_string(),
            note: Some(
                "MODEL-GENERATED placeholder — not captured from real Windows. \
                 Regenerate with the reference executable on Windows 10/11."
                    .to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorResult {
    pub id: String,
    pub category: String,
    pub output: Value,
}

// ── Category input/output shapes (typed mirrors of the wire JSON) ─────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathNormalizeInput {
    pub path: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub long_paths_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseFoldInput {
    pub left: String,
    pub right: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessSpec {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSpec {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSharingInput {
    pub path: String,
    pub first_access: AccessSpec,
    pub first_share: ShareSpec,
    pub second_access: AccessSpec,
    pub second_share: ShareSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLockInput {
    pub path: String,
    pub first_offset: u64,
    pub first_length: u64,
    pub second_offset: u64,
    pub second_length: u64,
    pub same_handle: bool,
    pub unlock_after_second: bool,
    pub retry_after_unlock: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSemanticsInput {
    pub path: String,
    /// "delete" | "rename" | "delete_then_reopen"
    pub op: String,
    pub first_open: bool,
    pub first_share: ShareSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSetInput {
    pub contract: String,
    /// ASCII export name probed on the loaded module to locate the
    /// implementing host DLL via GetProcAddress + GetModuleHandleExW.
    pub probe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInput {
    pub key: String,
    pub value_name: String,
    /// "REG_DWORD" | "REG_SZ" | "REG_EXPAND_SZ" | "REG_BINARY"
    pub value_type: String,
    pub data: Value,
    /// "set_query" | "query_missing" | "set_query_delete" | "create_twice"
    pub op: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncInput {
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrtInput {
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInput {
    pub kind: String,
}

// ── Corpus generation ──────────────────────────────────────────────────────

/// Generate the deterministic differential vector corpus for the given
/// categories (all categories when `categories` is empty). The generator is
/// pure host-side logic and produces byte-identical files on any platform.
pub fn generate_vectors(categories: &[String]) -> Vec<Vector> {
    let wanted: BTreeSet<&str> = if categories.is_empty() {
        ALL_CATEGORIES.iter().copied().collect()
    } else {
        categories.iter().map(|c| c.as_str()).collect()
    };
    let mut vectors = Vec::new();
    for category in ALL_CATEGORIES {
        if !wanted.contains(category) {
            continue;
        }
        let mut cases = generate_category(category);
        for (index, input) in cases.drain(..).enumerate() {
            vectors.push(Vector {
                id: format!("{category}:{index:03}"),
                category: category.to_string(),
                input,
            });
        }
    }
    vectors
}

fn generate_category(category: &str) -> Vec<Value> {
    match category {
        "path_normalize" => path_normalize_vectors(),
        "case_fold" => case_fold_vectors(),
        "file_sharing" => file_sharing_vectors(),
        "file_lock" => file_lock_vectors(),
        "delete_semantics" => delete_semantics_vectors(),
        "api_set" => api_set_vectors(),
        "registry" => registry_vectors(),
        "synchronization" => synchronization_vectors(),
        "crt_printf" => crt_printf_vectors(),
        "thread_tls" => thread_tls_vectors(),
        _ => Vec::new(),
    }
}

fn path_normalize_vectors() -> Vec<Value> {
    let cwd = Value::String(REFERENCE_CWD.to_string());
    vec![
        json!({ "path": "C:\\Alpha\\Beta\\.\\Gamma\\..\\File.txt", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "C:\\Alpha\\Beta\\..\\..\\..\\Gamma", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "C:\\Alpha\\\\Beta", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "c:\\Temp\\data.txt", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "\\\\server\\share\\dir\\..\\file.bin", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "\\\\server\\share\\file.bin", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "\\\\?\\C:\\Temp\\verbatim.txt", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "\\\\.\\pipe\\steam", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "foo.txt", "cwd": cwd.clone(), "long_paths_enabled": false }),
        json!({ "path": "..\\foo.txt", "cwd": cwd.clone(), "long_paths_enabled": false }),
        json!({ "path": "\\windows\\system32", "cwd": cwd.clone(), "long_paths_enabled": false }),
        json!({ "path": "C:relative.txt", "cwd": cwd.clone(), "long_paths_enabled": false }),
        json!({ "path": "C:\\Temp\\data.txt:stream", "cwd": null, "long_paths_enabled": false }),
        json!({ "path": "C:\\Alpha\\Beta\\.", "cwd": null, "long_paths_enabled": false }),
    ]
}

fn case_fold_vectors() -> Vec<Value> {
    vec![
        json!({ "left": "ReadMe.TXT", "right": "readme.txt" }),
        json!({ "left": "ς.txt", "right": "Σ.TXT" }),
        json!({ "left": "ß", "right": "SS" }),
        json!({ "left": "µ", "right": "Μ" }),
        json!({ "left": "Café", "right": "CAFÉ" }),
        json!({ "left": "123-456_7.8", "right": "123-456_7.8" }),
        json!({ "left": "Abc", "right": "AbC" }),
        json!({ "left": "one", "right": "two" }),
    ]
}

fn file_sharing_vectors() -> Vec<Value> {
    let base = format!("{}\\fs", REFERENCE_BASE_DIR);
    let access = |read: bool, write: bool, delete: bool| {
        json!({
            "read": read, "write": write, "delete": delete
        })
    };
    let share = |read: bool, write: bool, delete: bool| {
        json!({
            "read": read, "write": write, "delete": delete
        })
    };
    let first_access = access(true, true, false);
    vec![
        json!({ "path": format!("{base}\\fs-000.bin"), "first_access": first_access, "first_share": share(false, false, false), "second_access": access(true, false, false), "second_share": share(false, false, false) }),
        json!({ "path": format!("{base}\\fs-001.bin"), "first_access": first_access, "first_share": share(false, false, false), "second_access": access(false, true, false), "second_share": share(false, false, false) }),
        json!({ "path": format!("{base}\\fs-002.bin"), "first_access": first_access, "first_share": share(true, false, false), "second_access": access(false, true, false), "second_share": share(false, false, false) }),
        json!({ "path": format!("{base}\\fs-003.bin"), "first_access": first_access, "first_share": share(true, false, false), "second_access": access(true, false, false), "second_share": share(false, false, false) }),
        json!({ "path": format!("{base}\\fs-004.bin"), "first_access": first_access, "first_share": share(true, true, false), "second_access": access(true, true, false), "second_share": share(true, true, true) }),
        json!({ "path": format!("{base}\\fs-005.bin"), "first_access": first_access, "first_share": share(true, true, true), "second_access": access(true, false, true), "second_share": share(true, true, true) }),
        json!({ "path": format!("{base}\\fs-006.bin"), "first_access": first_access, "first_share": share(false, true, false), "second_access": access(true, false, false), "second_share": share(false, false, false) }),
        json!({ "path": format!("{base}\\fs-007.bin"), "first_access": first_access, "first_share": share(true, false, false), "second_access": access(true, false, true), "second_share": share(false, false, false) }),
    ]
}

fn file_lock_vectors() -> Vec<Value> {
    let base = format!("{}\\lock", REFERENCE_BASE_DIR);
    vec![
        json!({ "path": format!("{base}\\lock-000.bin"), "first_offset": 0, "first_length": 8, "second_offset": 4, "second_length": 4, "same_handle": false, "unlock_after_second": false, "retry_after_unlock": false }),
        json!({ "path": format!("{base}\\lock-001.bin"), "first_offset": 0, "first_length": 8, "second_offset": 8, "second_length": 4, "same_handle": false, "unlock_after_second": false, "retry_after_unlock": false }),
        json!({ "path": format!("{base}\\lock-002.bin"), "first_offset": 0, "first_length": 8, "second_offset": 4, "second_length": 4, "same_handle": true, "unlock_after_second": false, "retry_after_unlock": false }),
        json!({ "path": format!("{base}\\lock-003.bin"), "first_offset": 0, "first_length": 8, "second_offset": 4, "second_length": 4, "same_handle": false, "unlock_after_second": true, "retry_after_unlock": true }),
    ]
}

fn delete_semantics_vectors() -> Vec<Value> {
    let base = format!("{}\\del", REFERENCE_BASE_DIR);
    let share = |read: bool, write: bool, delete: bool| {
        json!({
            "read": read, "write": write, "delete": delete
        })
    };
    vec![
        json!({ "path": format!("{base}\\del-000.bin"), "op": "delete", "first_open": true, "first_share": share(true, true, false) }),
        json!({ "path": format!("{base}\\del-001.bin"), "op": "delete", "first_open": true, "first_share": share(true, true, true) }),
        json!({ "path": format!("{base}\\del-002.bin"), "op": "delete", "first_open": false, "first_share": share(false, false, false) }),
        json!({ "path": format!("{base}\\del-003.bin"), "op": "rename", "first_open": true, "first_share": share(true, true, false) }),
        json!({ "path": format!("{base}\\del-004.bin"), "op": "rename", "first_open": true, "first_share": share(true, true, true) }),
        json!({ "path": format!("{base}\\del-005.bin"), "op": "delete_then_reopen", "first_open": true, "first_share": share(true, true, true) }),
    ]
}

fn api_set_vectors() -> Vec<Value> {
    vec![
        json!({ "contract": "api-ms-win-core-file-l1-1-0.dll", "probe": "CreateFileW" }),
        json!({ "contract": "api-ms-win-core-synch-l1-1-0.dll", "probe": "CreateEventW" }),
        json!({ "contract": "api-ms-win-core-com-l1-1-0.dll", "probe": "CoCreateInstance" }),
        json!({ "contract": "api-ms-win-crt-runtime-l1-1-0.dll", "probe": "memset" }),
        json!({ "contract": "ext-ms-win-ntuser-window-l1-1-0.dll", "probe": "CreateWindowExW" }),
        json!({ "contract": "custom.dll", "probe": "Frobnicate" }),
        json!({ "contract": "kernel32.dll", "probe": "BaseThreadInitThunk" }),
    ]
}

fn registry_vectors() -> Vec<Value> {
    let key = "Software\\Casa1\\OracleRef";
    vec![
        json!({ "key": key, "value_name": "DwordValue", "value_type": "REG_DWORD", "data": 305419896, "op": "set_query" }),
        json!({ "key": key, "value_name": "SzValue", "value_type": "REG_SZ", "data": "Alpha Beta", "op": "set_query" }),
        json!({ "key": key, "value_name": "ExpandValue", "value_type": "REG_EXPAND_SZ", "data": "%PATH%;C:\\Extra", "op": "set_query" }),
        json!({ "key": key, "value_name": "BinaryValue", "value_type": "REG_BINARY", "data": [0, 1, 254, 255], "op": "set_query" }),
        json!({ "key": key, "value_name": "MissingValue", "value_type": "REG_SZ", "data": "", "op": "query_missing" }),
        json!({ "key": key, "value_name": "DeleteMe", "value_type": "REG_DWORD", "data": 7, "op": "set_query_delete" }),
        json!({ "key": key, "value_name": "", "value_type": "REG_SZ", "data": "", "op": "create_twice" }),
    ]
}

fn synchronization_vectors() -> Vec<Value> {
    vec![
        json!({ "kind": "event_auto_reset" }),
        json!({ "kind": "event_manual_reset" }),
        json!({ "kind": "mutex_recursion" }),
        json!({ "kind": "mutex_non_owner_release" }),
        json!({ "kind": "mutex_abandoned" }),
        json!({ "kind": "semaphore" }),
    ]
}

fn crt_printf_vectors() -> Vec<Value> {
    vec![
        json!({ "kind": "percent_n_disabled" }),
        json!({ "kind": "percent_n_enabled" }),
        json!({ "kind": "strtol_overflow" }),
        json!({ "kind": "strtol_underflow" }),
        json!({ "kind": "strtol_bad_base" }),
        json!({ "kind": "strtol_hex_ok" }),
        json!({ "kind": "snprintf_truncation" }),
        json!({ "kind": "snprintf_size_query" }),
        json!({ "kind": "snprintf_null_format" }),
    ]
}

fn thread_tls_vectors() -> Vec<Value> {
    vec![
        json!({ "kind": "alloc" }),
        json!({ "kind": "roundtrip" }),
        json!({ "kind": "thread_isolation" }),
        json!({ "kind": "minimum_available" }),
        json!({ "kind": "free_succeeds" }),
        json!({ "kind": "realloc_valid" }),
        json!({ "kind": "set_invalid_index" }),
        json!({ "kind": "get_invalid_index" }),
    ]
}

// ── Model results and comparison ───────────────────────────────────────────

/// Compute Casa1's expected results for every vector using the MODEL-ONLY
/// fallback implementations in [`crate::oracle_model`]. These are the values
/// the differential comparison validates against the real Windows reference.
pub fn compute_model_results(vectors: &[Vector]) -> Vec<VectorResult> {
    vectors
        .iter()
        .map(|vector| {
            let output = crate::oracle_model::predict(vector.category.as_str(), &vector.input);
            VectorResult {
                id: vector.id.clone(),
                category: vector.category.clone(),
                output,
            }
        })
        .collect()
}

/// Normalize a `resolved_module` path for comparison: strip to the file name
/// (last component) and lowercase. For `api_set` results, Windows may report
/// the virtual api-set alias (e.g. `api-ms-win-core-file-l1-1-0.dll`) instead
/// of the host DLL; the api-set schema explicitly does not guarantee a stable
/// host name across devices, so a virtual-alias name is accepted by the
/// comparator (see [`compare_outputs`]).
pub fn normalize_module_name(value: &str) -> String {
    let base = value.rsplit(['\\', '/']).next().unwrap_or(value);
    base.to_lowercase()
}

/// Whether a reported module name is a virtual api-set alias rather than a
/// physical host DLL.
pub fn is_virtual_apiset_alias(name: &str) -> bool {
    let normalized = normalize_module_name(name);
    normalized.starts_with("api-ms-") || normalized.starts_with("ext-ms-")
}

/// Compare one Casa1 (model) output against the reference output for a
/// vector, applying the documented per-category normalizations. Returns a
/// list of `(field, expected, actual)` diffs (empty when equal).
pub fn compare_outputs(category: &str, expected: &Value, actual: &Value) -> Vec<DiffEntry> {
    let mut diffs = Vec::new();
    compare_value("", category, expected, actual, &mut diffs);
    if category == "api_set" {
        // resolved_module: Windows may report the virtual api-set alias or
        // the physical host DLL path; both are legitimate reports of the
        // real loader behavior, so the module name comparison normalizes the
        // basename and accepts virtual aliases.
        let expected_module = expected
            .get("resolved_module")
            .and_then(Value::as_str)
            .map(normalize_module_name);
        let actual_module = actual
            .get("resolved_module")
            .and_then(Value::as_str)
            .map(normalize_module_name);
        match (expected_module, actual_module) {
            (Some(expected_name), Some(actual_name)) => {
                let virtual_reported = is_virtual_apiset_alias(&actual_name);
                if !virtual_reported && expected_name != actual_name {
                    diffs.push(DiffEntry {
                        id: String::new(),
                        category: category.to_string(),
                        field: "resolved_module".to_string(),
                        expected: json!(expected_name),
                        actual: json!(actual_name),
                    });
                }
            }
            (None, Some(actual_name)) => diffs.push(DiffEntry {
                id: String::new(),
                category: category.to_string(),
                field: "resolved_module".to_string(),
                expected: json!(null),
                actual: json!(actual_name),
            }),
            (Some(expected_name), None) => diffs.push(DiffEntry {
                id: String::new(),
                category: category.to_string(),
                field: "resolved_module".to_string(),
                expected: json!(expected_name),
                actual: json!(null),
            }),
            (None, None) => {}
        }
    }
    diffs
}

fn compare_value(
    prefix: &str,
    category: &str,
    expected: &Value,
    actual: &Value,
    diffs: &mut Vec<DiffEntry>,
) {
    match (expected, actual) {
        (Value::Object(expected_map), Value::Object(actual_map)) => {
            let mut keys: BTreeSet<&String> = expected_map.keys().collect();
            keys.extend(actual_map.keys());
            for key in keys {
                let field = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                match (expected_map.get(key), actual_map.get(key)) {
                    (Some(expected_value), Some(actual_value)) => {
                        compare_value(&field, category, expected_value, actual_value, diffs);
                    }
                    (Some(expected_value), None) => diffs.push(DiffEntry {
                        id: String::new(),
                        category: category.to_string(),
                        field,
                        expected: expected_value.clone(),
                        actual: Value::Null,
                    }),
                    (None, Some(actual_value)) => diffs.push(DiffEntry {
                        id: String::new(),
                        category: category.to_string(),
                        field,
                        expected: Value::Null,
                        actual: actual_value.clone(),
                    }),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(expected_items), Value::Array(actual_items)) => {
            let length = expected_items.len().max(actual_items.len());
            for index in 0..length {
                let field = format!("{prefix}[{index}]");
                match (expected_items.get(index), actual_items.get(index)) {
                    (Some(expected_item), Some(actual_item)) => {
                        compare_value(&field, category, expected_item, actual_item, diffs);
                    }
                    (Some(expected_item), None) => diffs.push(DiffEntry {
                        id: String::new(),
                        category: category.to_string(),
                        field,
                        expected: expected_item.clone(),
                        actual: Value::Null,
                    }),
                    (None, Some(actual_item)) => diffs.push(DiffEntry {
                        id: String::new(),
                        category: category.to_string(),
                        field,
                        expected: Value::Null,
                        actual: actual_item.clone(),
                    }),
                    (None, None) => {}
                }
            }
        }
        _ => {
            if expected != actual {
                diffs.push(DiffEntry {
                    id: String::new(),
                    category: category.to_string(),
                    field: prefix.to_string(),
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffEntry {
    pub id: String,
    pub category: String,
    pub field: String,
    pub expected: Value,
    pub actual: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategorySummary {
    pub vectors: usize,
    pub diffs: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonReport {
    pub schema_version: u64,
    pub vectors_total: usize,
    pub compared: usize,
    pub diff_count: usize,
    pub not_covered_categories: Vec<String>,
    pub categories: BTreeMap<String, CategorySummary>,
    pub diffs: Vec<DiffEntry>,
}

impl ComparisonReport {
    pub fn has_diffs(&self) -> bool {
        self.diff_count > 0
    }
}

/// Compare Casa1's model-computed results against reference results.
///
/// Only categories present in the reference results file are compared (a
/// reference file may legitimately cover a subset of the corpus, e.g. the
/// checked-in golden fixture). Categories in the corpus but absent from the
/// reference file are reported under `not_covered_categories` and do not
/// count as diffs.
pub fn compare_results(
    vectors: &[Vector],
    model_results: &[VectorResult],
    reference_results: &[VectorResult],
) -> ComparisonReport {
    let vector_by_id: BTreeMap<&str, &Vector> = vectors
        .iter()
        .map(|vector| (vector.id.as_str(), vector))
        .collect();
    let model_by_id: BTreeMap<&str, &Value> = model_results
        .iter()
        .map(|result| (result.id.as_str(), &result.output))
        .collect();
    let reference_by_id: BTreeMap<&str, &VectorResult> = reference_results
        .iter()
        .map(|result| (result.id.as_str(), result))
        .collect();

    let mut categories: BTreeMap<String, CategorySummary> = BTreeMap::new();
    let mut diffs: Vec<DiffEntry> = Vec::new();
    let mut compared = 0usize;
    let reference_ids: BTreeSet<&str> = reference_by_id.keys().copied().collect();

    for id in reference_ids {
        let reference = reference_by_id[id];
        let Some(_vector) = vector_by_id.get(id) else {
            // Reference covered a vector the current corpus does not know.
            diffs.push(DiffEntry {
                id: id.to_string(),
                category: reference.category.clone(),
                field: "(unknown vector in corpus)".to_string(),
                expected: Value::Null,
                actual: reference.output.clone(),
            });
            continue;
        };
        let summary = categories
            .entry(reference.category.clone())
            .or_insert_with(|| CategorySummary {
                vectors: 0,
                diffs: 0,
            });
        summary.vectors += 1;
        compared += 1;
        let Some(expected) = model_by_id.get(id) else {
            diffs.push(DiffEntry {
                id: id.to_string(),
                category: reference.category.clone(),
                field: "(no model result)".to_string(),
                expected: Value::Null,
                actual: reference.output.clone(),
            });
            summary.diffs += 1;
            continue;
        };
        let mut field_diffs = compare_outputs(&reference.category, expected, &reference.output);
        if !field_diffs.is_empty() {
            summary.diffs += 1;
        }
        for mut diff in field_diffs.drain(..) {
            diff.id = id.to_string();
            diffs.push(diff);
        }
    }

    let corpus_categories: BTreeSet<&str> = vectors
        .iter()
        .map(|vector| vector.category.as_str())
        .collect();
    let not_covered_categories = corpus_categories
        .iter()
        .filter(|category| !categories.contains_key(**category))
        .map(|category| (*category).to_string())
        .collect();

    ComparisonReport {
        schema_version: WINDOWS_ORACLE_SCHEMA_VERSION,
        vectors_total: vectors.len(),
        compared,
        diff_count: diffs.len(),
        not_covered_categories,
        categories,
        diffs,
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Lowercase hex encoding of a byte slice (used for registry value bytes).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// UTF-16LE byte encoding of a string including the trailing NUL code unit
/// (the on-disk representation of REG_SZ / REG_EXPAND_SZ values).
pub fn utf16le_with_nul(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

/// Current date as `YYYY-MM-DD` (UTC) without external date crates.
fn iso_date_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let (hour, minute, _second) = (
        (day_seconds / 3600) % 24,
        (day_seconds / 60) % 60,
        day_seconds % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}Z")
}

/// Convert days since 1970-01-01 to a civil (year, month, day) date.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}
