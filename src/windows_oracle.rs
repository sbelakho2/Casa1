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
//! executor arm in the
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
pub const ALL_CATEGORIES: [&str; 13] = [
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
    "d3d12_texture_address_mode",
    "d3d12_filter_reduction",
    "d3d12_filter_translation",
];

/// Every named D3D12_FILTER value with its d3d12.h name — the runtime-side
/// truth table for the `d3d12_filter_translation` differential (the Windows
/// reference carries the same 36 members hardcoded from d3d12.h). Values
/// not in this table are undefined per d3d12.h — a validation error.
pub const D3D12_FILTER_NAMES: &[(u32, &str)] = &[
    (0x0000_0000, "D3D12_FILTER_MIN_MAG_MIP_POINT"),
    (0x0000_0001, "D3D12_FILTER_MIN_MAG_POINT_MIP_LINEAR"),
    (0x0000_0004, "D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT"),
    (0x0000_0005, "D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0010, "D3D12_FILTER_MIN_LINEAR_MAG_MIP_POINT"),
    (0x0000_0011, "D3D12_FILTER_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
    (0x0000_0014, "D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
    (0x0000_0015, "D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
    (0x0000_0055, "D3D12_FILTER_ANISOTROPIC"),
    (0x0000_0080, "D3D12_FILTER_COMPARISON_MIN_MAG_MIP_POINT"),
    (
        0x0000_0081,
        "D3D12_FILTER_COMPARISON_MIN_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0084,
        "D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0085,
        "D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_LINEAR",
    ),
    (
        0x0000_0090,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_MIP_POINT",
    ),
    (
        0x0000_0091,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0094,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0095,
        "D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_00d5, "D3D12_FILTER_COMPARISON_ANISOTROPIC"),
    (0x0000_0100, "D3D12_FILTER_MINIMUM_MIN_MAG_MIP_POINT"),
    (0x0000_0101, "D3D12_FILTER_MINIMUM_MIN_MAG_POINT_MIP_LINEAR"),
    (
        0x0000_0104,
        "D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0105,
        "D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_0110, "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_MIP_POINT"),
    (
        0x0000_0111,
        "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0114,
        "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0115,
        "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_0155, "D3D12_FILTER_MINIMUM_ANISOTROPIC"),
    (0x0000_0180, "D3D12_FILTER_MAXIMUM_MIN_MAG_MIP_POINT"),
    (0x0000_0181, "D3D12_FILTER_MAXIMUM_MIN_MAG_POINT_MIP_LINEAR"),
    (
        0x0000_0184,
        "D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0185,
        "D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_0190, "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_MIP_POINT"),
    (
        0x0000_0191,
        "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR",
    ),
    (
        0x0000_0194,
        "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT",
    ),
    (
        0x0000_0195,
        "D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
    ),
    (0x0000_01d5, "D3D12_FILTER_MAXIMUM_ANISOTROPIC"),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D3d12AddressModeInput {
    pub mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D3d12FilterReductionInput {
    pub value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D3d12FilterTranslationInput {
    pub filter: u32,
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
        "d3d12_texture_address_mode" => d3d12_texture_address_mode_vectors(),
        "d3d12_filter_reduction" => d3d12_filter_reduction_vectors(),
        "d3d12_filter_translation" => d3d12_filter_translation_vectors(),
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

/// D3D12_TEXTURE_ADDRESS_MODE: every numeric input 0..=8. The reference
/// emits the REAL d3d12.h names for 0..=4 and marks 5..=8 as undefined
/// (validation error); the runtime must agree on every input.
fn d3d12_texture_address_mode_vectors() -> Vec<Value> {
    (0..=8).map(|mode| json!({ "mode": mode })).collect()
}

/// D3D12_FILTER_REDUCTION_TYPE: every numeric input 0..=8. The reference
/// emits STANDARD/COMPARISON/MINIMUM/MAXIMUM for 0..=3, marks 4..=8 as
/// undefined (validation error), and emits the full D3D12_FILTER bit
/// layout.
fn d3d12_filter_reduction_vectors() -> Vec<Value> {
    (0..=8).map(|value| json!({ "value": value })).collect()
}

/// D3D12_FILTER: every named enum value (36 members across the STANDARD,
/// COMPARISON, MINIMUM and MAXIMUM families). The reference emits the enum
/// decomposition for each; the runtime must decode identically.
fn d3d12_filter_translation_vectors() -> Vec<Value> {
    D3D12_FILTER_NAMES
        .iter()
        .map(|(filter, _)| json!({ "filter": filter }))
        .collect()
}

/// Compute the Casa1 RUNTIME's behavior for a differential vector.  This is
/// the emulated-Casa1 side of the differential: the reference executable's
/// captured result is the truth, and this function produces the Casa1
/// candidate the comparison validates.  Categories the runtime cannot
/// compute yet yield a `runtime_unavailable` marker that the comparison
/// reports honestly (never a silent pass).
pub fn compute_runtime_result(vector: &Vector) -> VectorResult {
    let output = match vector.category.as_str() {
        "path_normalize" => {
            let input = vector.input.as_str().unwrap_or_default();
            // The runtime's parser classifies the path; the normalized form
            // mirrors the reference's `normalized` field.
            let parsed = crate::real_fs::parse_windows_path(input);
            json!({
                "normalized": parsed.to_base_string(),
                "kind": runtime_path_kind(&parsed),
                "has_ads": parsed.ads_stream.is_some(),
                "last_error": 0,
            })
        }
        "d3d12_texture_address_mode" => {
            let mode = vector
                .input
                .get("mode")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32;
            // The runtime's production decode of D3D12_TEXTURE_ADDRESS_MODE
            // (0=WRAP..4=MIRROR_ONCE; outside 0..=4 is undefined per
            // d3d12.h — a validation error, never a silent default).
            let decoded = crate::gfx::D3D12TextureAddressMode::from_u32(mode);
            json!({
                "mode": mode,
                "name": decoded.map(crate::gfx::D3D12TextureAddressMode::d3d12_name),
                "valid": decoded.is_some(),
            })
        }
        "d3d12_filter_reduction" => {
            let value = vector
                .input
                .get("value")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32;
            // The runtime's production decode of D3D12_FILTER_REDUCTION_TYPE
            // (0=STANDARD..3=MAXIMUM; outside 0..=3 is undefined).
            let decoded = crate::gfx::D3D12FilterReduction::from_u32(value);
            let layout = crate::gfx::D3D12_FILTER_BIT_LAYOUT;
            json!({
                "value": value,
                "name": decoded.map(crate::gfx::D3D12FilterReduction::d3d12_name),
                "valid": decoded.is_some(),
                "bit_layout": {
                    "mip_filter_bits": [layout.mip_filter_bits.0, layout.mip_filter_bits.1],
                    "mag_filter_bits": [layout.mag_filter_bits.0, layout.mag_filter_bits.1],
                    "min_filter_bits": [layout.min_filter_bits.0, layout.min_filter_bits.1],
                    "anisotropic_bit": layout.anisotropic_bit,
                    "reduction_bits": [layout.reduction_bits.0, layout.reduction_bits.1],
                },
            })
        }
        "d3d12_filter_translation" => {
            let filter = vector
                .input
                .get("filter")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32;
            // The runtime's production decode of D3D12_FILTER (bits 0-1 mip,
            // 2-3 mag, 4-5 min, 6 anisotropic, 7-8 reduction).
            let mapping = crate::d3d12::D3d12Runtime::map_d3d12_filter_to_metal(filter);
            let name = D3D12_FILTER_NAMES
                .iter()
                .find(|(value, _)| *value == filter)
                .map(|(_, name)| *name);
            let field = |metal: &str| if metal == "linear" { "LINEAR" } else { "POINT" };
            json!({
                "filter": filter,
                "name": name,
                "min_filter": field(mapping.min_filter),
                "mag_filter": field(mapping.mag_filter),
                "mip_filter": field(mapping.mip_filter),
                "anisotropic": mapping.anisotropic,
                "reduction": mapping.reduction.as_u32(),
                "reduction_name": mapping.reduction.d3d12_name(),
                "valid": name.is_some(),
            })
        }
        _ => json!({ "runtime_unavailable": true }),
    };
    VectorResult {
        id: vector.id.clone(),
        category: vector.category.clone(),
        output,
    }
}

fn runtime_path_kind(parsed: &crate::real_fs::WindowsPath) -> &'static str {
    use crate::real_fs::WindowsPathKind::*;
    match &parsed.kind {
        DriveAbsolute { .. } => "drive_abs",
        DriveRelative { .. } => "drive_rel",
        RootedCurrentDrive { .. } => "rooted_current_drive",
        Relative { .. } => "relative",
        Unc { .. } => "unc",
        VerbatimDrive { .. } => "verbatim_drive",
        VerbatimUnc { .. } => "verbatim_unc",
        Device { .. } => "device",
    }
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
    /// Categories the Casa1 RUNTIME cannot compute yet (each vector reports
    /// `runtime_unavailable`).  Reported honestly — never counted as diffs
    /// and never as passes.
    pub runtime_uncovered_categories: Vec<String>,
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
    let mut runtime_uncovered: BTreeSet<String> = BTreeSet::new();
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
        // Casa1-runtime-unavailable marker: the category is honestly
        // reported as not yet covered by the runtime (never a diff, never a
        // pass) until the runtime implements the behavior.
        if expected
            .get("runtime_unavailable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            runtime_uncovered.insert(reference.category.clone());
            continue;
        }
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
        runtime_uncovered_categories: runtime_uncovered.into_iter().collect(),
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

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d3d12_categories_are_in_the_corpus() {
        for category in [
            "d3d12_texture_address_mode",
            "d3d12_filter_reduction",
            "d3d12_filter_translation",
        ] {
            assert!(
                ALL_CATEGORIES.contains(&category),
                "{category} must be part of the differential corpus"
            );
            let vectors = generate_vectors(&[category.to_string()]);
            assert!(!vectors.is_empty());
            for vector in &vectors {
                assert_eq!(vector.category, category);
            }
        }
    }

    #[test]
    fn d3d12_address_mode_runtime_matches_reference_derived_truth() {
        // Reference-derived truth (d3d12.h): 0=WRAP, 1=MIRROR, 2=CLAMP,
        // 3=BORDER, 4=MIRROR_ONCE; 5..=8 are undefined (validation error).
        let truth: [(u32, Option<&str>); 9] = [
            (0, Some("WRAP")),
            (1, Some("MIRROR")),
            (2, Some("CLAMP")),
            (3, Some("BORDER")),
            (4, Some("MIRROR_ONCE")),
            (5, None),
            (6, None),
            (7, None),
            (8, None),
        ];
        for (mode, name) in truth {
            let vector = Vector {
                id: format!("address:{mode}"),
                category: "d3d12_texture_address_mode".to_string(),
                input: json!({ "mode": mode }),
            };
            let result = compute_runtime_result(&vector);
            assert_eq!(
                result.output,
                json!({ "mode": mode, "name": name, "valid": name.is_some() }),
                "runtime must match the reference-derived truth for mode {mode}"
            );
            // The comparison machinery must report no diff against the
            // reference-shaped output.
            let diffs = compare_outputs(
                "d3d12_texture_address_mode",
                &json!({ "mode": mode, "name": name, "valid": name.is_some() }),
                &result.output,
            );
            assert!(diffs.is_empty(), "unexpected diffs: {diffs:?}");
        }
    }

    #[test]
    fn d3d12_filter_reduction_runtime_matches_reference_derived_truth() {
        // Reference-derived truth (d3d12.h): STANDARD=0, COMPARISON=1,
        // MINIMUM=2, MAXIMUM=3; 4..=8 are undefined (validation error).
        let truth: [(u32, Option<&str>); 9] = [
            (0, Some("STANDARD")),
            (1, Some("COMPARISON")),
            (2, Some("MINIMUM")),
            (3, Some("MAXIMUM")),
            (4, None),
            (5, None),
            (6, None),
            (7, None),
            (8, None),
        ];
        for (value, name) in truth {
            let vector = Vector {
                id: format!("reduction:{value}"),
                category: "d3d12_filter_reduction".to_string(),
                input: json!({ "value": value }),
            };
            let result = compute_runtime_result(&vector);
            // The bit layout is part of both sides' output — the runtime
            // must agree with the d3d12.h layout (mip 0-1, mag 2-3, min
            // 4-5, anisotropic 6, reduction 7-8).
            let reference_shaped = json!({
                "value": value,
                "name": name,
                "valid": name.is_some(),
                "bit_layout": {
                    "mip_filter_bits": [0, 1],
                    "mag_filter_bits": [2, 3],
                    "min_filter_bits": [4, 5],
                    "anisotropic_bit": 6,
                    "reduction_bits": [7, 8],
                },
            });
            assert_eq!(result.output, reference_shaped);
            let diffs =
                compare_outputs("d3d12_filter_reduction", &reference_shaped, &result.output);
            assert!(diffs.is_empty(), "unexpected diffs: {diffs:?}");
        }
    }

    #[test]
    fn d3d12_filter_translation_runtime_matches_reference_derived_truth() {
        struct FilterTruthCase {
            filter: u32,
            name: &'static str,
            min: &'static str,
            mag: &'static str,
            mip: &'static str,
            aniso: bool,
            reduction: u32,
            reduction_name: &'static str,
        }
        // Reference-derived truth: the runtime decodes every named
        // D3D12_FILTER exactly per the d3d12.h bit layout, including the
        // four-way reduction.
        let cases = [
            FilterTruthCase {
                filter: 0x00,
                name: "D3D12_FILTER_MIN_MAG_MIP_POINT",
                min: "POINT",
                mag: "POINT",
                mip: "POINT",
                aniso: false,
                reduction: 0,
                reduction_name: "STANDARD",
            },
            FilterTruthCase {
                filter: 0x15,
                name: "D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
                min: "LINEAR",
                mag: "LINEAR",
                mip: "LINEAR",
                aniso: false,
                reduction: 0,
                reduction_name: "STANDARD",
            },
            FilterTruthCase {
                filter: 0x55,
                name: "D3D12_FILTER_ANISOTROPIC",
                min: "LINEAR",
                mag: "LINEAR",
                mip: "LINEAR",
                aniso: true,
                reduction: 0,
                reduction_name: "STANDARD",
            },
            FilterTruthCase {
                filter: 0x80,
                name: "D3D12_FILTER_COMPARISON_MIN_MAG_MIP_POINT",
                min: "POINT",
                mag: "POINT",
                mip: "POINT",
                aniso: false,
                reduction: 1,
                reduction_name: "COMPARISON",
            },
            FilterTruthCase {
                filter: 0xD5,
                name: "D3D12_FILTER_COMPARISON_ANISOTROPIC",
                min: "LINEAR",
                mag: "LINEAR",
                mip: "LINEAR",
                aniso: true,
                reduction: 1,
                reduction_name: "COMPARISON",
            },
            FilterTruthCase {
                filter: 0x100,
                name: "D3D12_FILTER_MINIMUM_MIN_MAG_MIP_POINT",
                min: "POINT",
                mag: "POINT",
                mip: "POINT",
                aniso: false,
                reduction: 2,
                reduction_name: "MINIMUM",
            },
            FilterTruthCase {
                filter: 0x115,
                name: "D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR",
                min: "LINEAR",
                mag: "LINEAR",
                mip: "LINEAR",
                aniso: false,
                reduction: 2,
                reduction_name: "MINIMUM",
            },
            FilterTruthCase {
                filter: 0x180,
                name: "D3D12_FILTER_MAXIMUM_MIN_MAG_MIP_POINT",
                min: "POINT",
                mag: "POINT",
                mip: "POINT",
                aniso: false,
                reduction: 3,
                reduction_name: "MAXIMUM",
            },
        ];
        for case in cases {
            let vector = Vector {
                id: format!("filter:{:#x}", case.filter),
                category: "d3d12_filter_translation".to_string(),
                input: json!({ "filter": case.filter }),
            };
            let result = compute_runtime_result(&vector);
            let reference_shaped = json!({
                "filter": case.filter,
                "name": case.name,
                "min_filter": case.min,
                "mag_filter": case.mag,
                "mip_filter": case.mip,
                "anisotropic": case.aniso,
                "reduction": case.reduction,
                "reduction_name": case.reduction_name,
                "valid": true,
            });
            assert_eq!(result.output, reference_shaped, "filter {:#x}", case.filter);
            let diffs = compare_outputs(
                "d3d12_filter_translation",
                &reference_shaped,
                &result.output,
            );
            assert!(
                diffs.is_empty(),
                "filter {:#x} diffs: {diffs:?}",
                case.filter
            );
        }
        // Every named member of the corpus decodes valid; the runtime's
        // name table covers exactly the corpus.
        let vectors = generate_vectors(&["d3d12_filter_translation".to_string()]);
        assert_eq!(vectors.len(), D3D12_FILTER_NAMES.len());
        for vector in &vectors {
            let result = compute_runtime_result(vector);
            assert_eq!(result.output["valid"], json!(true), "{}", vector.id);
            assert!(result.output["name"].is_string(), "{}", vector.id);
        }
    }
}
