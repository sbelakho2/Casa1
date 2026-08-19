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

use crate::ge::{FileAccess, GameEnvironment, GeArch, RegistryView, ShareMode};
use crate::pe_runtime::last_error_from_app_error;
use crate::win32::{CreationDisposition, ThreadPlan, WaitStatus, Win32Subsystem};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

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
pub const ALL_CATEGORIES: [&str; 15] = [
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
    "cpu_arithmetic_flags",
    "virtual_memory",
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
/// on Windows carry `captured_by: "casa1-windows-reference"` plus the actual
/// capture provenance (`os_edition`, `os_build`, `arch`, the reference
/// executable's own SHA-256 and the vector-corpus SHA-256); model-generated
/// fixtures keep the same shape but are explicitly marked as placeholders so
/// they can never be mistaken for real Windows captures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureHeader {
    pub source: String,
    pub captured_by: String,
    pub captured_on: String,
    pub capture_date: String,
    pub note: Option<String>,
    /// Windows edition as reported by the capture machine's registry
    /// (e.g. `"Professional"`); `"unknown"` on non-Windows builds.
    #[serde(default)]
    pub os_edition: String,
    /// `major.minor.build` from RtlGetVersion (e.g. `"10.0.22631"`);
    /// `"unknown"` on non-Windows builds.
    #[serde(default)]
    pub os_build: String,
    /// Processor architecture of the capture machine (`"x86"`, `"x64"` or
    /// `"arm64"` from GetNativeSystemInfo; the host arch name elsewhere).
    #[serde(default)]
    pub arch: String,
    /// Compiler target triple of the reference executable (env!("TARGET")) —
    /// distinguishes an x86 capture from an x64 capture.
    #[serde(default)]
    pub target_triple: String,
    /// SHA-256 (lowercase hex) of the reference executable that produced the
    /// capture.
    #[serde(default)]
    pub reference_sha256: String,
    /// SHA-256 (lowercase hex) of the vector corpus file the capture ran on.
    #[serde(default)]
    pub corpus_sha256: String,
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
            // Filled by the reference executable at capture time; these
            // defaults keep schema-version-1 files parseable.
            os_edition: String::new(),
            os_build: String::new(),
            arch: String::new(),
            target_triple: env!("CASA1_TARGET_TRIPLE").to_string(),
            reference_sha256: String::new(),
            corpus_sha256: String::new(),
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
            os_edition: "unknown".to_string(),
            os_build: "unknown".to_string(),
            arch: "unknown".to_string(),
            target_triple: "model-generated".to_string(),
            reference_sha256: String::new(),
            corpus_sha256: String::new(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFlagsInput {
    /// Arithmetic width in bits: 8 | 16 | 32 | 64.
    pub width: u32,
    /// "add" | "sub" | "cmp".
    pub op: String,
    pub lhs: u64,
    pub rhs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualMemoryInput {
    /// "reserve" | "commit" | "decommit" | "release" | "protect" | "query".
    pub operation: String,
    /// For "reserve": 0 lets the system choose the base.  For every other
    /// operation the address is RELATIVE to the session's first reservation
    /// base (each side — the reference process and the runtime session —
    /// resolves it against its own first reserve's base, so the corpus is
    /// host-agnostic despite ASLR).
    #[serde(default)]
    pub address: u64,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub allocation_type: u32,
    #[serde(default)]
    pub protection: u32,
    #[serde(default)]
    pub free_type: u32,
}

// ── Corpus generation ──────────────────────────────────────────────────────

/// Generate the deterministic differential vector corpus for the given
/// categories (all categories when `categories` is empty). The generator is
/// pure host-side logic and produces byte-identical files on any platform.
pub fn generate_vectors(categories: &[String]) -> Vec<Vector> {
    generate_vectors_with_mode(categories, false)
}

/// Generate the corpus with the `--exhaustive` mode enabled: the
/// `cpu_arithmetic_flags` category replaces its bounded stride sample with
/// the FULL 8-bit exhaustive operand space (65,536 pairs × add/sub/cmp ≈
/// 196k vectors).  Used by the nightly workflow; the bounded default keeps
/// the CI capture quick.
pub fn generate_vectors_exhaustive(categories: &[String]) -> Vec<Vector> {
    generate_vectors_with_mode(categories, true)
}

fn generate_vectors_with_mode(categories: &[String], exhaustive: bool) -> Vec<Vector> {
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
        let mut cases = generate_category_with_mode(category, exhaustive);
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

fn generate_category_with_mode(category: &str, exhaustive: bool) -> Vec<Value> {
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
        "cpu_arithmetic_flags" => cpu_arithmetic_flags_vectors(exhaustive),
        "virtual_memory" => virtual_memory_vectors(),
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

/// The arithmetic edge set shared with the JIT flag truth-table tests:
/// every (lhs, rhs) pair below runs at widths 8/16/32/64 with ops
/// add/sub/cmp.  These are the width-masked edges that exercise OF (sign
/// overflow), CF (unsigned wrap), ZF, AF (nibble carry) and the subtract
/// borrow/underflow boundaries.
pub const CPU_FLAGS_EDGES: &[(u64, u64)] = &[
    // 8-bit OF (0x7f + 1)
    (0x7f, 1),
    // 8-bit CF+OF (0x80 + 0x80)
    (0x80, 0x80),
    // 8-bit CF (0xff + 1)
    (0xff, 1),
    // 16-bit OF (0x7fff + 1)
    (0x7fff, 1),
    // 16-bit CF+OF (0x8000 + 0x8000)
    (0x8000, 0x8000),
    // 32-bit OF (0x7fffffff + 1)
    (0x7fff_ffff, 1),
    // 32-bit CF+OF (0x80000000 + 0x80000000)
    (0x8000_0000, 0x8000_0000),
    // 64-bit OF (0x7fffffffffffffff + 1)
    (0x7fff_ffff_ffff_ffff, 1),
    // 64-bit CF+OF (0x8000000000000000 + 0x8000000000000000)
    (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
    // 64-bit CF (0xffffffffffffffff + 1)
    (0xffff_ffff_ffff_ffff, 1),
    // 8-bit CF (0x80 - 1)
    (0x80, 1),
    // 8-bit signed underflow (0x7f - 0x80)
    (0x7f, 0x80),
    // 32-bit signed underflow (0x7fffffff - 0x80000000)
    (0x7fff_ffff, 0x8000_0000),
    // 64-bit signed underflow (0x7fffffffffffffff - 0x8000000000000000)
    (0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
    // equal operands (ZF + CF=0)
    (0x1234_5678_9abc_def0, 0x1234_5678_9abc_def0),
    // zero operands (all clear except PF)
    (0, 0),
    // AF edge: 0x0f + 1
    (0x0f, 1),
    // AF edge + CF: 0x0f + 0x0f
    (0x0f, 0x0f),
];

pub const CPU_FLAGS_OPS: [&str; 3] = ["add", "sub", "cmp"];

/// The 8-bit stride step of the bounded corpus (every 8th value per axis →
/// 1,024 of the 65,536 possible pairs).
pub const CPU_FLAGS_STRIDE_STEP: u32 = 8;

/// The documented CPU edge set at every width and op, plus a deterministic
/// stride sample over the 8-bit operand space (every 8th value on each axis
/// → 1,024 pairs × add/sub/cmp).  In `exhaustive` mode the stride sample is
/// replaced by the FULL 8-bit operand space (65,536 pairs) for the nightly
/// capture.
fn cpu_arithmetic_flags_vectors(exhaustive: bool) -> Vec<Value> {
    let mut vectors = Vec::new();
    for width in [8_u32, 16, 32, 64] {
        for &(lhs, rhs) in CPU_FLAGS_EDGES {
            for op in CPU_FLAGS_OPS {
                vectors.push(json!({ "width": width, "op": op, "lhs": lhs, "rhs": rhs }));
            }
        }
    }
    let sample = if exhaustive {
        (0..=255).collect::<Vec<u32>>()
    } else {
        (0..=255)
            .step_by(CPU_FLAGS_STRIDE_STEP as usize)
            .collect::<Vec<u32>>()
    };
    for lhs in &sample {
        for rhs in &sample {
            for op in CPU_FLAGS_OPS {
                vectors.push(json!({ "width": 8, "op": op, "lhs": lhs, "rhs": rhs }));
            }
        }
    }
    vectors
}

/// The `virtual_memory` corpus: a single stateful address-space session
/// (the reference process on one side, the runtime's private-pages session
/// on the other).  The vectors run strictly in order — reserve first, then
/// interior commit, partial protect, partial decommit, the two mandated
/// failures, and the unmapped-address query.  Addresses are RELATIVE to the
/// session's first reservation base (0 = the reservation base itself).
fn virtual_memory_vectors() -> Vec<Value> {
    vec![
        // 0: reserve 0x4000 (system-chosen base); the output queries the
        //    returned base: MEM_RESERVE, PAGE_NOACCESS, size 0x4000.
        json!({ "operation": "reserve", "address": 0, "size": 0x4000, "allocation_type": 0x2000, "protection": 0x01, "free_type": 0 }),
        // 1: query mid-range of the reservation (2 pages in): MEM_RESERVE,
        //    PAGE_NOACCESS, base-relative 0, size 0x2000.
        json!({ "operation": "query", "address": 0x2000, "size": 0, "allocation_type": 0, "protection": 0, "free_type": 0 }),
        // 2: commit an interior range [0x1000, 0x3000) READWRITE; the output
        //    queries 0x1000: MEM_COMMIT, PAGE_READWRITE, base 0x1000,
        //    size 0x2000.
        json!({ "operation": "commit", "address": 0x1000, "size": 0x2000, "allocation_type": 0x1000, "protection": 0x04, "free_type": 0 }),
        // 3: partial protect: only [0x1000, 0x2000) → PAGE_READONLY with
        //    old-protection reporting (PAGE_READWRITE); the output queries
        //    0x1000: MEM_COMMIT, PAGE_READONLY, base 0x1000, size 0x1000.
        json!({ "operation": "protect", "address": 0x1000, "size": 0x1000, "allocation_type": 0, "protection": 0x02, "free_type": 0 }),
        // 4: partial decommit of [0x2000, 0x3000): the output queries
        //    0x2000: MEM_RESERVE, PAGE_NOACCESS, base 0x2000, size 0x2000.
        json!({ "operation": "decommit", "address": 0x2000, "size": 0x1000, "allocation_type": 0, "protection": 0, "free_type": 0x4000 }),
        // 5: release with size != 0 — must fail with ERROR_INVALID_PARAMETER
        //    (87); the output queries the reservation base: still
        //    MEM_RESERVE (the failed release changed nothing).
        json!({ "operation": "release", "address": 0, "size": 0x1000, "allocation_type": 0, "protection": 0, "free_type": 0x8000 }),
        // 6: commit WITHOUT a reservation (0x10000 past the session base) —
        //    must fail with ERROR_INVALID_ADDRESS (487); the output queries
        //    the same address: MEM_FREE, base 0, size 0.
        json!({ "operation": "commit", "address": 0x1_0000, "size": 0x1000, "allocation_type": 0x1000, "protection": 0x04, "free_type": 0 }),
        // 7: query an unmapped address (0x8000 past the session base):
        //    MEM_FREE + NULL base + 0 size.
        json!({ "operation": "query", "address": 0x8000, "size": 0, "allocation_type": 0, "protection": 0, "free_type": 0 }),
    ]
}

/// Compute the Casa1 RUNTIME's behavior for a differential vector.  This is
/// the emulated-Casa1 side of the differential: the reference executable's
/// captured result is the truth, and this function produces the Casa1
/// candidate the comparison validates.  Categories the runtime cannot
/// compute yet yield a `runtime_unavailable` marker that the comparison
/// reports honestly (never a silent pass).
///
/// Every arm drives the runtime's REAL machinery (real_fs parsing, the
/// GameEnvironment share/lock matrix, the Win32Subsystem sync/TLS layers,
/// the pe_runtime CRT tables) — never a hand-rolled duplicate model — so a
/// diff against a real Windows capture is a genuine runtime defect.
pub fn compute_runtime_result(vector: &Vector) -> VectorResult {
    let output = match vector.category.as_str() {
        "path_normalize" => runtime_path_normalize(&vector.input),
        "case_fold" => runtime_case_fold(&vector.input),
        "file_sharing" => runtime_file_sharing(&vector.input),
        "file_lock" => runtime_file_lock(&vector.input),
        "delete_semantics" => runtime_delete_semantics(&vector.input),
        "api_set" => runtime_api_set(&vector.input),
        "registry" => runtime_registry(&vector.input),
        "synchronization" => runtime_synchronization(&vector.input),
        "crt_printf" => runtime_crt(&vector.input),
        "thread_tls" => runtime_thread_tls(&vector.input),
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
        "cpu_arithmetic_flags" => runtime_cpu_arithmetic_flags(&vector.input),
        "virtual_memory" => runtime_virtual_memory(&vector.id, &vector.input),
        _ => json!({ "runtime_unavailable": true }),
    };
    VectorResult {
        id: vector.id.clone(),
        category: vector.category.clone(),
        output,
    }
}

// ── Shared runtime context ─────────────────────────────────────────────────

/// Scratch `Win32Subsystem` + `GameEnvironment` the file/registry/sync/TLS
/// executors drive.  The runtime is emulated on the host (macOS in CI), so
/// the file-based categories operate on a per-process scratch game
/// environment whose `drive_c` mirrors the reference's fixed scratch layout
/// (`C:\Windows\Temp\casa1-oracle`, `...\casa1-oracle-cwd`).
struct OracleRuntimeContext {
    subsystem: Win32Subsystem,
    /// Held alongside the subsystem (which owns a clone) so the executors can
    /// reach the GE-level share/lock matrix (`open_file`, `lock_file_range`,
    /// `registry_*`) that the Win32Subsystem's own GE mirrors on disk.
    ge: GameEnvironment,
    /// The `virtual_memory` session: a scratch PeHostRuntime driving the
    /// REAL VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery thunk arms
    /// (page-granular private pages/reservations).  Persists across vectors
    /// like the reference process's address space does.
    vm: crate::pe_runtime::OracleVmSession,
    /// Base of the session's first reservation — the reference point for
    /// every relative `base_address` in the `virtual_memory` output (0 until
    /// the reserve vector establishes it).
    vm_session_base: u64,
    #[allow(dead_code)]
    root: PathBuf,
}

thread_local! {
    static ORACLE_RUNTIME: RefCell<Option<OracleRuntimeContext>> = const { RefCell::new(None) };
}

static ORACLE_RUNTIME_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Directories under `drive_c` provisioned for the file-based categories,
/// mirroring the reference executable's `ensure_scratch_dirs`.
const SCRATCH_DIRECTORIES: [&str; 4] = [
    "Windows/Temp/casa1-oracle/fs",
    "Windows/Temp/casa1-oracle/lock",
    "Windows/Temp/casa1-oracle/del",
    "Windows/Temp/casa1-oracle-cwd",
];

fn with_oracle_runtime<T>(operation: impl FnOnce(&mut OracleRuntimeContext) -> T) -> T {
    ORACLE_RUNTIME.with(|slot| {
        let mut borrow = slot.borrow_mut();
        if borrow.is_none() {
            *borrow = Some(create_oracle_runtime());
        }
        operation(borrow.as_mut().expect("oracle runtime initialized"))
    })
}

fn create_oracle_runtime() -> OracleRuntimeContext {
    let serial = ORACLE_RUNTIME_SERIAL.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "casa1-oracle-runtime-{}-{serial:04}",
        std::process::id()
    ));
    let ge = GameEnvironment::create_in(&root, "oracle", GeArch::X64, "10.0.22631").unwrap_or_else(
        |error| {
            panic!(
                "failed to create the oracle scratch game environment at {}: {error}",
                root.display()
            )
        },
    );
    let drive_c = ge.drive_c();
    for directory in SCRATCH_DIRECTORIES {
        std::fs::create_dir_all(drive_c.join(directory)).unwrap_or_else(|error| {
            panic!("failed to provision oracle scratch directory {directory}: {error}")
        });
    }
    let subsystem = Win32Subsystem::new(ge.clone(), true);
    let vm = crate::pe_runtime::OracleVmSession::new(ge.clone());
    OracleRuntimeContext {
        subsystem,
        ge,
        vm,
        vm_session_base: 0,
        root,
    }
}

fn access_spec(spec: &AccessSpec) -> FileAccess {
    FileAccess {
        read: spec.read,
        write: spec.write,
        delete: spec.delete,
    }
}

fn share_spec(spec: &ShareSpec) -> ShareMode {
    ShareMode {
        read: spec.read,
        write: spec.write,
        delete: spec.delete,
    }
}

fn error_code(error: &crate::error::AppError) -> u32 {
    last_error_from_app_error(error)
}

// ── path_normalize ──────────────────────────────────────────────────────────

/// Resolve cwd-dependent input forms against the reference's fixed working
/// directory before classifying, matching the reference executor's
/// `SetCurrentDirectoryW` + `GetFullPathNameW` contract: relative paths
/// resolve against the cwd, drive-relative paths (`C:rel`) against the cwd
/// on their drive, and root-relative paths (`\x`) against the cwd's drive
/// root.
fn resolve_against_cwd(path: &str, cwd: &str) -> String {
    use crate::real_fs::WindowsPathKind::*;
    let parsed = crate::real_fs::parse_windows_path(path);
    let cwd = cwd.trim_end_matches(['\\', '/']);
    match &parsed.kind {
        Relative { .. } | DriveRelative { .. } => format!("{cwd}\\{path}"),
        RootedCurrentDrive { .. } => {
            let drive = cwd.chars().next().unwrap_or('C');
            let body = path.trim_start_matches('\\');
            format!("{drive}:\\{body}")
        }
        _ => path.to_string(),
    }
}

fn runtime_path_normalize(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<PathNormalizeInput>(input.clone()) else {
        return json!({ "normalized": "", "kind": "invalid_input", "has_ads": false, "last_error": 87 });
    };
    // Kind/has_ads classify the INPUT shape (like the reference's
    // protocol-level classifiers); the normalized string resolves the
    // cwd-dependent forms against the fixed working directory.
    let input_parsed = crate::real_fs::parse_windows_path(&spec.path);
    let kind = runtime_path_kind(&input_parsed);
    let has_ads = input_parsed.ads_stream.is_some();
    let effective_cwd = spec
        .cwd
        .clone()
        .unwrap_or_else(|| REFERENCE_CWD.to_string());
    let resolved = resolve_against_cwd(&spec.path, &effective_cwd);
    let parsed = crate::real_fs::parse_windows_path(&resolved);
    json!({
        "normalized": parsed.to_base_string(),
        "kind": kind,
        "has_ads": has_ads,
        "last_error": 0,
    })
}

fn runtime_path_kind(parsed: &crate::real_fs::WindowsPath) -> &'static str {
    use crate::real_fs::WindowsPathKind::*;
    match &parsed.kind {
        DriveAbsolute { .. } => "drive_abs",
        DriveRelative { .. } => "drive_rel",
        RootedCurrentDrive { .. } => "rooted",
        Relative { .. } => "relative",
        Unc { .. } => "unc",
        VerbatimDrive { .. } | VerbatimUnc { .. } => "verbatim",
        Device { .. } => "device",
    }
}

// ── case_fold ───────────────────────────────────────────────────────────────

/// The runtime's case-folding equality: the GE filesystem layer's ordinal
/// casefold (`ge::windows_casefold_key`, the fold `real_fs` name resolution
/// uses).  The C1 type bits mirror the runtime's `GetStringTypeW` thunk
/// (`pe_runtime::classify_wide_char_type`, CT_CTYPE1).
fn runtime_case_fold(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<CaseFoldInput>(input.clone()) else {
        return json!({
            "ordinal_ignore_case_equal": false,
            "left_c1_type_bits": [],
            "right_c1_type_bits": [],
        });
    };
    let equal =
        crate::ge::windows_casefold_key(&spec.left) == crate::ge::windows_casefold_key(&spec.right);
    json!({
        "ordinal_ignore_case_equal": equal,
        "left_c1_type_bits": runtime_c1_type_bits(&spec.left),
        "right_c1_type_bits": runtime_c1_type_bits(&spec.right),
    })
}

fn runtime_c1_type_bits(value: &str) -> Vec<u32> {
    value
        .encode_utf16()
        .map(|unit| u32::from(crate::pe_runtime::classify_wide_char_type(1, unit)))
        .collect()
}

// ── file_sharing ────────────────────────────────────────────────────────────

/// Drive the runtime's real open path (`create_file_w` → the GE share-state
/// matrix) exactly like the reference's two `CreateFileW` calls.
fn runtime_file_sharing(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<FileSharingInput>(input.clone()) else {
        return json!({ "second_open_succeeds": false, "second_error": 87 });
    };
    with_oracle_runtime(|runtime| {
        let subsystem = &mut runtime.subsystem;
        let first = subsystem.create_file_w(
            &spec.path,
            access_spec(&spec.first_access),
            share_spec(&spec.first_share),
            CreationDisposition::CreateAlways,
            false,
            false,
            false,
        );
        let first = match first {
            Ok(handle) => handle,
            Err(error) => {
                return json!({
                    "second_open_succeeds": false,
                    "second_error": error_code(&error),
                });
            }
        };
        let second = subsystem.create_file_w(
            &spec.path,
            access_spec(&spec.second_access),
            share_spec(&spec.second_share),
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        );
        let (second_open_succeeds, second_error) = match second {
            Ok(handle) => {
                let _ = subsystem.close_handle(handle);
                (true, 0)
            }
            Err(error) => (false, error_code(&error)),
        };
        let _ = subsystem.close_handle(first);
        json!({
            "second_open_succeeds": second_open_succeeds,
            "second_error": second_error,
        })
    })
}

// ── file_lock ───────────────────────────────────────────────────────────────

/// The runtime's byte-range lock behavior is the GE share runtime's
/// `lock_file_range` (exclusive lock + `RcFsLockViolation` →
/// `ERROR_LOCK_VIOLATION`).  The runtime has no `UnlockFileEx` counterpart,
/// so an unlock request is reported as not performed (`performed: false`) —
/// a genuine runtime gap the differential surfaces as a diff, never as a
/// fabricated success.
fn runtime_file_lock(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<FileLockInput>(input.clone()) else {
        return json!({ "lock1": null, "lock2": null, "unlock1": null, "lock3": null });
    };
    with_oracle_runtime(|runtime| {
        let subsystem = &mut runtime.subsystem;
        let ge = &runtime.ge;
        let read_write = FileAccess {
            read: true,
            write: true,
            delete: false,
        };
        let share = ShareMode {
            read: true,
            write: true,
            delete: false,
        };
        // Ensure the file exists through the runtime's own open machinery
        // (the reference's OPEN_ALWAYS), then release the setup handle so
        // the vector's two opens see a clean share matrix.
        let setup = subsystem.create_file_w(
            &spec.path,
            read_write,
            share,
            CreationDisposition::OpenAlways,
            false,
            false,
            false,
        );
        match setup {
            Ok(handle) => {
                let _ = subsystem.close_handle(handle);
            }
            Err(error) => {
                return json!({
                    "lock1": null, "lock2": null, "unlock1": null, "lock3": null,
                    "error": error_code(&error),
                });
            }
        }
        let first = match ge.open_file(&spec.path, read_write, share) {
            Ok(handle) => handle,
            Err(error) => {
                return json!({
                    "lock1": null, "lock2": null, "unlock1": null, "lock3": null,
                    "error": error_code(&error),
                });
            }
        };
        let second = if spec.same_handle {
            None
        } else {
            match ge.open_file(&spec.path, read_write, share) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    let _ = ge.close_file_handle(&first);
                    return json!({
                        "lock1": null, "lock2": null, "unlock1": null, "lock3": null,
                        "error": error_code(&error),
                    });
                }
            }
        };
        let second_handle = second.as_ref().unwrap_or(&first);
        let lock_op = |outcome: crate::error::AppResult<()>| match outcome {
            Ok(()) => json!({ "performed": true, "succeeded": true, "error": 0 }),
            Err(error) => json!({
                "performed": true,
                "succeeded": false,
                "error": error_code(&error),
            }),
        };
        let lock1 = lock_op(ge.lock_file_range(&first, spec.first_offset, spec.first_length, true));
        let lock2 = lock_op(ge.lock_file_range(
            second_handle,
            spec.second_offset,
            spec.second_length,
            true,
        ));
        // The runtime implements no unlock: the request is not performed and
        // the first lock stays in force, so lock3 still sees the conflict.
        let unlock1 = json!({ "performed": false, "succeeded": false, "error": 0 });
        let lock3 = if spec.retry_after_unlock {
            lock_op(ge.lock_file_range(second_handle, spec.second_offset, spec.second_length, true))
        } else {
            json!({ "performed": false, "succeeded": false, "error": 0 })
        };
        if let Some(second) = second {
            let _ = ge.close_file_handle(&second);
        }
        let _ = ge.close_file_handle(&first);
        json!({
            "lock1": lock1,
            "lock2": lock2,
            "unlock1": unlock1,
            "lock3": lock3,
        })
    })
}

// ── delete_semantics ────────────────────────────────────────────────────────

/// The runtime's delete/rename-while-open behavior via `delete_file_w` /
/// `move_file_ex_w` (both enforce the `FILE_SHARE_DELETE` matrix through
/// `check_delete_sharing`).
fn runtime_delete_semantics(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<DeleteSemanticsInput>(input.clone()) else {
        return json!({ "success": false, "error": 87, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 87 });
    };
    with_oracle_runtime(|runtime| {
        let subsystem = &mut runtime.subsystem;
        let ge = &runtime.ge;
        let handle = if spec.first_open {
            subsystem
                .create_file_w(
                    &spec.path,
                    FileAccess {
                        read: true,
                        write: true,
                        delete: false,
                    },
                    share_spec(&spec.first_share),
                    CreationDisposition::CreateAlways,
                    false,
                    false,
                    false,
                )
                .ok()
        } else {
            None
        };
        let file_exists = |path: &str| ge.get_file_metadata(path).is_ok();
        match spec.op.as_str() {
            "delete" => {
                let outcome = subsystem.delete_file_w(&spec.path);
                let (success, error) = match outcome {
                    Ok(()) => (true, 0_u32),
                    Err(error) => (false, error_code(&error)),
                };
                let exists_after = file_exists(&spec.path);
                if let Some(handle) = handle {
                    let _ = subsystem.close_handle(handle);
                }
                json!({
                    "success": success,
                    "error": error,
                    "file_exists_after": exists_after,
                    "rename_succeeded": false,
                    "second_open_succeeded": false,
                    "second_open_error": 0,
                })
            }
            "rename" => {
                let target = format!("{}.ren", spec.path);
                let outcome = subsystem.move_file_ex_w(&spec.path, &target, true, false);
                let (success, error) = match outcome {
                    Ok(()) => (true, 0_u32),
                    Err(error) => (false, error_code(&error)),
                };
                let exists_after = file_exists(&spec.path);
                if let Some(handle) = handle {
                    let _ = subsystem.close_handle(handle);
                }
                let _ = subsystem.delete_file_w(&target);
                json!({
                    "success": success,
                    "error": error,
                    "file_exists_after": exists_after,
                    "rename_succeeded": success,
                    "second_open_succeeded": false,
                    "second_open_error": 0,
                })
            }
            "delete_then_reopen" => {
                let outcome = subsystem.delete_file_w(&spec.path);
                let (success, error) = match outcome {
                    Ok(()) => (true, 0_u32),
                    Err(error) => (false, error_code(&error)),
                };
                let second = subsystem.create_file_w(
                    &spec.path,
                    FileAccess {
                        read: true,
                        write: false,
                        delete: false,
                    },
                    ShareMode {
                        read: true,
                        write: true,
                        delete: true,
                    },
                    CreationDisposition::OpenExisting,
                    false,
                    false,
                    false,
                );
                let (second_open_succeeded, second_open_error) = match second {
                    Ok(second) => {
                        let _ = subsystem.close_handle(second);
                        (true, 0)
                    }
                    Err(error) => (false, error_code(&error)),
                };
                let exists_after = file_exists(&spec.path);
                if let Some(handle) = handle {
                    let _ = subsystem.close_handle(handle);
                }
                json!({
                    "success": success,
                    "error": error,
                    "file_exists_after": exists_after,
                    "rename_succeeded": false,
                    "second_open_succeeded": second_open_succeeded,
                    "second_open_error": second_open_error,
                })
            }
            _ => {
                if let Some(handle) = handle {
                    let _ = subsystem.close_handle(handle);
                }
                json!({ "success": false, "error": 87, "file_exists_after": true, "rename_succeeded": false, "second_open_succeeded": false, "second_open_error": 87 })
            }
        }
    })
}

// ── api_set ─────────────────────────────────────────────────────────────────

/// The runtime's api-set resolution: `pe::ApiSetResolver` (the loader's
/// contract→host table).  `loads` is true when the resolver maps the
/// contract (api-set prefixes) or the runtime models the physical module
/// (thunk metadata exists for it); `export_resolvable` is true when the
/// runtime knows the probe export on the resolved host (thunk metadata, or
/// the CRT name table for ucrtbase/msvcrt).
fn runtime_api_set(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<ApiSetInput>(input.clone()) else {
        return json!({ "loads": false, "resolved_module": "", "export_resolvable": false });
    };
    let resolver = crate::pe::ApiSetResolver::new();
    if !runtime_apiset_loads(&spec.contract, &resolver) {
        return json!({ "loads": false, "resolved_module": "", "export_resolvable": false });
    }
    let host = resolver.resolve(&spec.contract);
    json!({
        "loads": true,
        "resolved_module": normalize_module_name(&host),
        "export_resolvable": runtime_export_resolvable(&host, &spec.probe),
    })
}

fn runtime_apiset_loads(contract: &str, resolver: &crate::pe::ApiSetResolver) -> bool {
    let normalized = normalize_module_name(contract);
    if normalized.starts_with("api-ms-") || normalized.starts_with("ext-ms-") {
        let host = normalize_module_name(&resolver.resolve(contract));
        host != normalized
    } else {
        crate::host_thunks::THUNK_METADATA.iter().any(|entry| {
            let dll = entry.dll.strip_suffix(".dll").unwrap_or(entry.dll);
            let requested = normalized.strip_suffix(".dll").unwrap_or(&normalized);
            dll.eq_ignore_ascii_case(requested)
        })
    }
}

fn runtime_export_resolvable(host: &str, probe: &str) -> bool {
    let host_norm = normalize_module_name(host);
    if host_norm == "ucrtbase.dll"
        || host_norm == "msvcrt.dll"
        || host_norm.starts_with("vcruntime")
    {
        crate::pe_runtime::HostThunk::crt_thunk_from_name(probe).is_some()
    } else {
        crate::host_thunks::lookup_thunk_metadata(host, probe).is_some()
    }
}

// ── registry ────────────────────────────────────────────────────────────────

/// The runtime's registry behavior: the GE registry DB behind the
/// `RegCreateKeyExW`/`RegSetValueExW`/`RegQueryValueExW`/`RegDeleteValueW`
/// thunks (HKCU, `RegistryView::Native`).  Output mirrors the reference's
/// `error` (0 on success, 2 = ERROR_FILE_NOT_FOUND on a missing value),
/// lowercase-hex `value_bytes` and numeric `value_type` (1/2/3/4).
fn runtime_registry(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<RegistryInput>(input.clone()) else {
        return json!({ "error": 87, "value_bytes": "", "value_type": null });
    };
    with_oracle_runtime(|runtime| {
        let ge = &runtime.ge;
        let hive = "HKCU";
        let view = RegistryView::Native;
        match spec.op.as_str() {
            "query_missing" => query_registry_value(ge, hive, view, &spec),
            "create_twice" => {
                let _ = ge.registry_create_key(hive, &spec.key, view);
                let _ = ge.registry_create_key(hive, &spec.key, view);
                json!({ "error": 0, "value_bytes": "", "value_type": null })
            }
            "set_query_delete" => {
                let _ = ge.registry_set_value(
                    hive,
                    &spec.key,
                    &spec.value_name,
                    &spec.value_type,
                    spec.data.clone(),
                    view,
                );
                let _ = ge.registry_delete_value(hive, &spec.key, &spec.value_name, view);
                query_registry_value(ge, hive, view, &spec)
            }
            "set_query" => {
                let set_result = ge.registry_set_value(
                    hive,
                    &spec.key,
                    &spec.value_name,
                    &spec.value_type,
                    spec.data.clone(),
                    view,
                );
                if let Err(error) = set_result {
                    return json!({ "error": error_code(&error), "value_bytes": "", "value_type": null });
                }
                query_registry_value(ge, hive, view, &spec)
            }
            _ => json!({ "error": 87, "value_bytes": "", "value_type": null }),
        }
    })
}

fn query_registry_value(
    ge: &GameEnvironment,
    hive: &str,
    view: RegistryView,
    spec: &RegistryInput,
) -> Value {
    match ge.registry_get_value(hive, &spec.key, &spec.value_name, view) {
        Ok(Some(stored)) => {
            let bytes = registry_value_bytes(&stored.value_type, &stored.data);
            json!({
                "error": 0,
                "value_bytes": hex_encode(&bytes),
                "value_type": registry_type_code(&stored.value_type),
            })
        }
        Ok(None) => json!({ "error": 2, "value_bytes": "", "value_type": null }),
        Err(error) => json!({ "error": error_code(&error), "value_bytes": "", "value_type": null }),
    }
}

/// On-disk byte encoding of a registry value (mirrors the reference
/// executor's `registry_value_bytes` and the runtime's
/// `encode_registry_value_data`): REG_DWORD is little-endian u32,
/// REG_SZ/REG_EXPAND_SZ are UTF-16LE with a trailing NUL, REG_BINARY raw.
fn registry_value_bytes(value_type: &str, data: &Value) -> Vec<u8> {
    match value_type {
        "REG_DWORD" => (data.as_u64().unwrap_or(0) as u32).to_le_bytes().to_vec(),
        "REG_SZ" | "REG_EXPAND_SZ" => utf16le_with_nul(data.as_str().unwrap_or_default()),
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

fn registry_type_code(value_type: &str) -> u32 {
    match value_type {
        "REG_SZ" => 1,
        "REG_EXPAND_SZ" => 2,
        "REG_BINARY" => 3,
        "REG_DWORD" => 4,
        _ => 0,
    }
}

// ── synchronization ─────────────────────────────────────────────────────────

/// The runtime's sync primitives via the Win32Subsystem: events, mutexes
/// (recursion, abandoned, non-owner release) and semaphores, with the same
/// `waits`/`releases`/`abandoned` output shape as the reference.
fn runtime_synchronization(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<SyncInput>(input.clone()) else {
        return json!({ "waits": [], "releases": [], "abandoned": false });
    };
    with_oracle_runtime(|runtime| {
        let subsystem = &mut runtime.subsystem;
        let wait = |subsystem: &mut Win32Subsystem, handle: u32| {
            subsystem
                .wait_for_single_object(handle, u32::MAX, false, None)
                .map(WaitStatus::code)
                .unwrap_or(0xFFFF_FFFF)
        };
        let wait_zero = |subsystem: &mut Win32Subsystem, handle: u32| {
            subsystem
                .wait_for_single_object(handle, 0, false, None)
                .map(WaitStatus::code)
                .unwrap_or(0xFFFF_FFFF)
        };
        let release = |subsystem: &mut Win32Subsystem, handle: u32| -> Value {
            match subsystem.release_mutex(handle) {
                Ok(()) => json!({ "succeeded": true, "error": 0 }),
                Err(error) => json!({ "succeeded": false, "error": error_code(&error) }),
            }
        };
        let release_sem = |subsystem: &mut Win32Subsystem, handle: u32, count: u32| -> Value {
            match subsystem.release_semaphore(handle, count) {
                Ok(_previous) => json!({ "succeeded": true, "error": 0 }),
                Err(error) => json!({ "succeeded": false, "error": error_code(&error) }),
            }
        };
        match spec.kind.as_str() {
            "event_auto_reset" => {
                let (event, _) = subsystem.create_event(false, false, false, None);
                let _ = subsystem.set_event(event);
                let wait1 = wait_zero(subsystem, event);
                let wait2 = wait_zero(subsystem, event);
                let _ = subsystem.close_handle(event);
                json!({ "waits": [wait1, wait2], "releases": [], "abandoned": false })
            }
            "event_manual_reset" => {
                let (event, _) = subsystem.create_event(true, false, false, None);
                let _ = subsystem.set_event(event);
                let wait1 = wait_zero(subsystem, event);
                let wait2 = wait_zero(subsystem, event);
                let _ = subsystem.reset_event(event);
                let wait3 = wait_zero(subsystem, event);
                let _ = subsystem.close_handle(event);
                json!({ "waits": [wait1, wait2, wait3], "releases": [], "abandoned": false })
            }
            "mutex_recursion" => {
                let mutex = subsystem.create_mutex(false, false);
                let wait1 = wait(subsystem, mutex);
                let wait2 = wait(subsystem, mutex);
                let release1 = release(subsystem, mutex);
                let release2 = release(subsystem, mutex);
                let wait3 = wait_zero(subsystem, mutex);
                let release3 = release(subsystem, mutex);
                let release4 = release(subsystem, mutex);
                let _ = subsystem.close_handle(mutex);
                json!({
                    "waits": [wait1, wait2, wait3],
                    "releases": [release1, release2, release3, release4],
                    "abandoned": false,
                })
            }
            "mutex_non_owner_release" => {
                let mutex = subsystem.create_mutex(false, false);
                let wait1 = wait(subsystem, mutex);
                let other = subsystem.create_thread(
                    ThreadPlan {
                        exit_code: None,
                        priority: 0,
                        signaled: false,
                    },
                    false,
                );
                let other_id = subsystem.thread_id_for_handle(other).unwrap_or(2);
                subsystem.set_current_thread_id(other_id);
                let release = release(subsystem, mutex);
                subsystem.set_current_thread_id(1);
                let _ = subsystem.close_handle(other);
                let _ = subsystem.close_handle(mutex);
                json!({ "waits": [wait1], "releases": [release], "abandoned": false })
            }
            "mutex_abandoned" => {
                let mutex = subsystem.create_mutex(false, false);
                let wait1 = wait(subsystem, mutex);
                let _ = subsystem.abandon_mutex(mutex);
                let wait2 = wait(subsystem, mutex);
                let release = release(subsystem, mutex);
                let _ = subsystem.close_handle(mutex);
                json!({ "waits": [wait1, wait2], "releases": [release], "abandoned": true })
            }
            "semaphore" => {
                let semaphore = subsystem.create_semaphore(1, 3, false);
                let wait1 = wait_zero(subsystem, semaphore);
                let wait2 = wait_zero(subsystem, semaphore);
                let release1 = release_sem(subsystem, semaphore, 1);
                let release2 = release_sem(subsystem, semaphore, 2);
                let wait3 = wait_zero(subsystem, semaphore);
                let wait4 = wait_zero(subsystem, semaphore);
                let wait5 = wait_zero(subsystem, semaphore);
                let wait6 = wait_zero(subsystem, semaphore);
                let _ = subsystem.close_handle(semaphore);
                json!({
                    "waits": [wait1, wait2, wait3, wait4, wait5, wait6],
                    "releases": [release1, release2],
                    "abandoned": false,
                })
            }
            _ => json!({ "waits": [], "releases": [], "abandoned": false }),
        }
    })
}

// ── crt_printf ──────────────────────────────────────────────────────────────

/// The runtime's CRT behavior, mirrored from pe_runtime's CRT layer:
/// `HostThunk::Strtol` (via `crt_parse_strtol_full`; EINVAL on a bad base,
/// ERANGE + LONG_MAX/LONG_MIN on overflow) and the legacy
/// `__stdio_common_vsnprintf` path (`crt_vfprintf_render`; truncation
/// returns -1 with the buffer untouched, NULL format is EINVAL, and %n is
/// always enabled — the runtime has no `_set_printf_count_output` switch).
fn runtime_crt(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<CrtInput>(input.clone()) else {
        return json!({ "handler_invoked": false, "ret": null, "errno": 0, "written": null, "value": null, "end_consumed": null, "buffer": null });
    };
    let build = |handler_invoked: bool,
                 ret: Value,
                 errno: u32,
                 written: Value,
                 value: Value,
                 end_consumed: Value,
                 buffer: Value|
     -> Value {
        json!({
            "handler_invoked": handler_invoked,
            "ret": ret,
            "errno": errno,
            "written": written,
            "value": value,
            "end_consumed": end_consumed,
            "buffer": buffer,
        })
    };
    match spec.kind.as_str() {
        "percent_n_disabled" | "percent_n_enabled" => {
            // The runtime's printf engine always honors %n and writes the
            // count of characters emitted so far; there is no disable switch
            // (pe_runtime `crt_render_conversion` 0x6E arm).
            build(
                false,
                json!(2),
                0,
                json!(2),
                Value::Null,
                Value::Null,
                Value::Null,
            )
        }
        "strtol_overflow" => runtime_strtol("999999999999999999999", 10, &build),
        "strtol_underflow" => runtime_strtol("-999999999999999999999", 10, &build),
        "strtol_bad_base" => runtime_strtol("123", 99, &build),
        "strtol_hex_ok" => runtime_strtol("0x7fffffff", 16, &build),
        "snprintf_truncation" => build(
            false,
            json!(-1),
            0,
            Value::Null,
            Value::Null,
            Value::Null,
            json!(""),
        ),
        "snprintf_size_query" => build(
            false,
            json!(1),
            0,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        "snprintf_null_format" => build(
            false,
            json!(0),
            22,
            Value::Null,
            Value::Null,
            Value::Null,
            json!(""),
        ),
        _ => build(
            false,
            Value::Null,
            0,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
    }
}

fn runtime_strtol(
    text: &str,
    base: i32,
    build: &impl Fn(bool, Value, u32, Value, Value, Value, Value) -> Value,
) -> Value {
    if !(base == 0 || (2..=36).contains(&base)) {
        // Invalid base: EINVAL, no conversion, *endptr = nptr.
        return build(
            false,
            Value::Null,
            22,
            Value::Null,
            json!(0),
            json!(false),
            Value::Null,
        );
    }
    let (value, consumed, overflow) = crate::pe_runtime::crt_parse_strtol_full(text, base);
    let end_consumed = consumed > 0;
    let value = if overflow {
        if text[..consumed].trim_start().starts_with('-') {
            i32::MIN as i64
        } else {
            i32::MAX as i64
        }
    } else {
        value
    };
    build(
        false,
        Value::Null,
        if overflow { 34 } else { 0 },
        Value::Null,
        json!(value),
        json!(end_consumed),
        Value::Null,
    )
}

// ── thread_tls ──────────────────────────────────────────────────────────────

/// The runtime's TLS semantics via the Win32Subsystem: `tls_alloc` (reuses
/// freed slots, `u32::MAX` when exhausted), per-thread `tls_set_value` /
/// `tls_get_value`, and `tls_free` (removes the slot from every thread and
/// makes the index reusable).  Freed-slot reads come back empty.
fn runtime_thread_tls(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<TlsInput>(input.clone()) else {
        return json!({ "error": 87 });
    };
    with_oracle_runtime(|runtime| {
        let subsystem = &mut runtime.subsystem;
        let main = subsystem.current_thread_handle();
        match spec.kind.as_str() {
            "alloc" => {
                let index = subsystem.tls_alloc();
                json!({ "index_valid": index != u32::MAX })
            }
            "roundtrip" => {
                let index = subsystem.tls_alloc();
                let pointer = 0xAB_u64;
                let set_succeeded = subsystem.tls_set_value(main, index, pointer).is_ok();
                let retrieved = subsystem.tls_get_value(main, index).ok().flatten();
                json!({
                    "set_succeeded": set_succeeded,
                    "get_matches": retrieved == Some(pointer),
                })
            }
            "thread_isolation" => {
                let index = subsystem.tls_alloc();
                let pointer = 0xCD_u64;
                let _ = subsystem.tls_set_value(main, index, pointer);
                let other = subsystem.create_thread(
                    ThreadPlan {
                        exit_code: None,
                        priority: 0,
                        signaled: false,
                    },
                    false,
                );
                let other_thread_value_is_null = subsystem
                    .tls_get_value(other, index)
                    .ok()
                    .flatten()
                    .is_none();
                let _ = subsystem.close_handle(other);
                let main_value_preserved =
                    subsystem.tls_get_value(main, index).ok().flatten() == Some(pointer);
                json!({
                    "other_thread_value_is_null": other_thread_value_is_null,
                    "main_value_preserved": main_value_preserved,
                })
            }
            "minimum_available" => json!({ "minimum_available": 64 }),
            "free_succeeds" => {
                let index = subsystem.tls_alloc();
                subsystem.tls_free(index);
                json!({ "free_succeeded": true })
            }
            "realloc_valid" => {
                let index = subsystem.tls_alloc();
                subsystem.tls_free(index);
                let new_index = subsystem.tls_alloc();
                json!({ "new_index_valid": new_index != u32::MAX })
            }
            "set_invalid_index" => {
                let succeeded = subsystem.tls_set_value(main, u32::MAX, 0).is_ok();
                json!({ "succeeded": succeeded, "error": if succeeded { 0 } else { 87 } })
            }
            "get_invalid_index" => {
                let value_is_null = subsystem
                    .tls_get_value(main, u32::MAX)
                    .ok()
                    .flatten()
                    .is_none();
                json!({ "value_is_null": value_is_null, "error": 0 })
            }
            _ => json!({ "error": 87 }),
        }
    })
}

// ── cpu_arithmetic_flags ────────────────────────────────────────────────────

/// The runtime's x86 flag computation for add/sub/cmp at a width: the Casa1
/// CPU's OWN flag model, driven through `jit_helper_set_flags` — the exact
/// function the interpreter and the JIT use to set guest flags (op 0=add,
/// 1=sub, 3=cmp; the width parameter is in BYTES).  The result operand is
/// the width-masked wrapping add/sub, exactly what the interpreter's
/// add/sub paths produce.  This differential therefore validates the
/// interpreter's flag semantics against the real x86 flags the reference
/// executable captures with inline assembly.
fn runtime_cpu_arithmetic_flags(input: &Value) -> Value {
    let Ok(spec) = serde_json::from_value::<CpuFlagsInput>(input.clone()) else {
        return json!({ "error": "invalid_input" });
    };
    let bits = spec.width;
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return json!({ "error": "invalid_input" });
    }
    let (result, op) = match spec.op.as_str() {
        "add" => (spec.lhs.wrapping_add(spec.rhs), 0_u64),
        "sub" => (spec.lhs.wrapping_sub(spec.rhs), 1_u64),
        "cmp" => (spec.lhs.wrapping_sub(spec.rhs), 3_u64),
        _ => return json!({ "error": "invalid_input" }),
    };
    let mut state = crate::cpu::CpuState::new(crate::cpu::GuestArch::X64);
    // SAFETY: `state` is a live, owned CpuState for the duration of the call.
    unsafe {
        crate::jit::jit_helper_set_flags(
            &mut state,
            result,
            spec.lhs,
            spec.rhs,
            op,
            u64::from(bits / 8),
        );
    }
    json!({
        "zf": state.flags.zf,
        "sf": state.flags.sf,
        "pf": state.flags.pf,
        "cf": state.flags.cf,
        "of": state.flags.of,
        "af": state.flags.af,
    })
}

// ── virtual_memory ──────────────────────────────────────────────────────────

// Memory-state constants shared with the reference executor (WinNT.h).
const VM_MEM_COMMIT: u32 = 0x1000;
const VM_MEM_RESERVE: u32 = 0x2000;
const VM_MEM_DECOMMIT: u32 = 0x4000;
const VM_MEM_RELEASE: u32 = 0x8000;
const VM_MEM_FREE: u32 = 0x0001_0000;
const VM_PAGE_NOACCESS: u32 = 0x01;

/// The runtime's virtual-memory behavior: the REAL
/// VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery thunk arms of the
/// pe_runtime VM layer (page-granular private pages/reservations) driven on
/// a scratch session, mirroring the reference's process-wide sequence.  The
/// session base is the first reservation's returned base; `base_address`
/// output is relative to it (the absolute base is ASLR-environmental, the
/// relative layout is the semantic contract), and MEM_FREE queries report
/// NULL base + 0 size.
fn runtime_virtual_memory(id: &str, input: &Value) -> Value {
    // The virtual_memory vectors form a SEQUENCE (each depends on the
    // previous state).  The thread-local oracle session persists across
    // test invocations, so the session must be reset at the sequence start
    // ("virtual_memory:000") — otherwise a stale vm/session_base from a
    // previous run shifts every address in the comparison.
    if id.ends_with(":000") {
        with_oracle_runtime(|runtime| {
            let ge = runtime.ge.clone();
            runtime.vm = crate::pe_runtime::OracleVmSession::new(ge);
            runtime.vm_session_base = 0;
        });
    }
    let Ok(spec) = serde_json::from_value::<VirtualMemoryInput>(input.clone()) else {
        return json!({
            "error": 87, "state": VM_MEM_FREE, "protection": VM_PAGE_NOACCESS,
            "region_size": 0, "base_address": 0, "committed_set_summary": false,
        });
    };
    with_oracle_runtime(|runtime| {
        let session = &mut runtime.vm;
        let session_base = runtime.vm_session_base;
        let absolute = if spec.operation == "reserve" {
            spec.address
        } else {
            session_base.wrapping_add(spec.address)
        };
        let (error, query_address, old_protection) = match spec.operation.as_str() {
            "reserve" => {
                // The corpus always sends MEM_RESERVE explicitly; a missing
                // allocation_type defaults to a pure reservation.
                let allocation_type = if spec.allocation_type == 0 {
                    VM_MEM_RESERVE
                } else {
                    spec.allocation_type
                };
                let (base, error) =
                    session.virtual_alloc(absolute, spec.size, allocation_type, spec.protection);
                if base != 0 && runtime.vm_session_base == 0 {
                    runtime.vm_session_base = base;
                }
                (error, if absolute == 0 { base } else { absolute }, None)
            }
            "commit" => {
                let (_, error) =
                    session.virtual_alloc(absolute, spec.size, VM_MEM_COMMIT, spec.protection);
                (error, absolute, None)
            }
            "decommit" => {
                let (_, error) = session.virtual_free(absolute, spec.size, VM_MEM_DECOMMIT);
                (error, absolute, None)
            }
            "release" => {
                let (_, error) = session.virtual_free(absolute, spec.size, VM_MEM_RELEASE);
                (error, absolute, None)
            }
            "protect" => {
                let (_, error, old) = session.virtual_protect(absolute, spec.size, spec.protection);
                (error, absolute, Some(old))
            }
            "query" => (0, absolute, None),
            _ => (87, absolute, None),
        };
        let query = session.virtual_query(query_address);
        let base_address = if query.state == VM_MEM_FREE {
            0
        } else {
            query.base_address.wrapping_sub(runtime.vm_session_base)
        };
        let mut output = json!({
            "error": error,
            "state": query.state,
            "protection": query.protect,
            "region_size": query.region_size,
            "base_address": base_address,
            "committed_set_summary": query.state == VM_MEM_COMMIT,
        });
        if let Some(old) = old_protection {
            output["old_protection"] = json!(old);
        }
        output
    })
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

/// Categories among `required` that the differential does NOT validate: the
/// Casa1 runtime reported them `runtime_unavailable`, or the reference
/// results file does not cover them (`not_covered_categories`).  The compare
/// command fails (exit 1) whenever this list is non-empty, regardless of
/// `--report-only` — a required category must be both computed by the
/// runtime AND validated against a captured reference result, or the run is
/// untested.
pub fn required_coverage_missing(report: &ComparisonReport, required: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|category| {
            report
                .runtime_uncovered_categories
                .iter()
                .any(|covered| covered == *category)
                || report
                    .not_covered_categories
                    .iter()
                    .any(|covered| covered == *category)
        })
        .cloned()
        .collect()
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
