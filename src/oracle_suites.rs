//! Oracle suite data contracts for the differential tests (sections 2/3).
//!
//! These are pure DATA shapes: the EXPECTED outcomes come exclusively from
//! the Windows reference executable's captured results
//! ([`crate::windows_oracle::ReferenceResultsFile`]) — never from a
//! Casa1-side semantic model.  The Casa1-side model was removed entirely;
//! a test comparing Casa1 behavior against Casa1-computed expectations is
//! not Windows conformance.
//!
//! [`suites_from_reference`] pairs the deterministic vector corpus with the
//! captured reference results and derives the suites the section tests
//! consume.  Categories the reference does not yet cover yield `None` and
//! the corresponding tests are skipped (never silently passed).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::windows_oracle::{ReferenceResultsFile, VectorFile};

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

/// All suites derivable from a captured reference results file.  `None`
/// means the reference does not yet cover that category and the
/// corresponding tests must be skipped (never silently passed).
#[derive(Debug, Clone, Default)]
pub struct OracleSuites {
    pub path: Option<PathEdgeSuite>,
    pub case: Option<CaseCollisionSuite>,
    pub lock_share: Option<LockShareSuite>,
    pub registry_notify: Option<RegistryNotifySuite>,
    pub dll_order: Option<DllOrderSuite>,
    pub delay_load: Option<DelayLoadSuite>,
    pub api_set: Option<ApiSetSuite>,
}

/// True when the results file is a REAL Windows capture (produced by the
/// reference executable) and not a model-generated placeholder.
///
/// Since the reference executable records ACTUAL capture provenance, the
/// check also requires the provenance fields to be present and meaningful:
/// a known os edition/build, a Windows architecture, and the SHA-256 of the
/// reference executable and of the vector corpus.  Old schema-version-1
/// files without these fields (serde defaults) are not real captures.
pub fn is_real_windows_capture(results: &ReferenceResultsFile) -> bool {
    let header = &results.capture;
    header.captured_by == "casa1-windows-reference"
        && header.capture_date != "model-generated"
        && header
            .note
            .as_deref()
            .is_none_or(|note| !note.contains("MODEL-GENERATED"))
        && !header.os_edition.is_empty()
        && header.os_edition != "unknown"
        && !header.os_build.is_empty()
        && header.os_build != "unknown"
        && matches!(header.arch.as_str(), "x86" | "x64" | "arm64")
        && header.reference_sha256.len() == 64
        && header.corpus_sha256.len() == 64
}

fn result_for<'a>(
    vectors: &'a VectorFile,
    results: &'a ReferenceResultsFile,
    category: &str,
) -> Vec<(&'a str, &'a Value, &'a Value)> {
    vectors
        .vectors
        .iter()
        .filter(|vector| vector.category == category)
        .filter_map(|vector| {
            results
                .results
                .iter()
                .find(|result| result.id == vector.id)
                .map(|result| (vector.id.as_str(), &vector.input, &result.output))
        })
        .collect()
}

fn value_as_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn value_as_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

/// Derive the suites from the deterministic vector corpus and the captured
/// Windows reference results.  Categories the reference does not cover
/// yield `None`.
pub fn suites_from_reference(vectors: &VectorFile, results: &ReferenceResultsFile) -> OracleSuites {
    let mut suites = OracleSuites::default();

    // ── path_normalize → PathEdgeSuite ─────────────────────────────────────
    let path_cases = result_for(vectors, results, "path_normalize")
        .into_iter()
        .filter_map(|(_, input, output)| {
            let input_str = input.as_str()?;
            let long_paths_enabled = input
                .get("long_paths_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let outcome = if let Some(normalized) = value_as_str(output, "normalized") {
                PathEdgeOutcome::Success {
                    normalized_path: normalized,
                    verbatim: value_as_str(output, "kind").is_some_and(|kind| {
                        kind == "verbatim_drive" || kind == "verbatim_unc" || kind == "device"
                    }),
                    device_namespace: value_as_str(output, "kind")
                        .is_some_and(|kind| kind == "device"),
                }
            } else {
                PathEdgeOutcome::Error {
                    reason_code: value_as_u64(output, "last_error").unwrap_or(0) as u32,
                }
            };
            Some(PathEdgeCase {
                input: input_str.to_string(),
                long_paths_enabled,
                outcome,
            })
        })
        .collect::<Vec<_>>();
    if !path_cases.is_empty() {
        suites.path = Some(PathEdgeSuite { cases: path_cases });
    }

    // ── api_set → ApiSetSuite ──────────────────────────────────────────────
    let api_cases = result_for(vectors, results, "api_set")
        .into_iter()
        .filter_map(|(_, input, output)| {
            let contract = input.as_str()?;
            let loads = output
                .get("loads")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let host = if loads {
                value_as_str(output, "resolved_module").unwrap_or_default()
            } else {
                String::new()
            };
            Some(ApiSetCase {
                contract: contract.to_string(),
                expected_host: host,
            })
        })
        .collect::<Vec<_>>();
    if !api_cases.is_empty() {
        suites.api_set = Some(ApiSetSuite { cases: api_cases });
    }

    // ── file_sharing + file_lock → LockShareSuite ──────────────────────────
    let share = result_for(vectors, results, "file_sharing");
    let lock = result_for(vectors, results, "file_lock");
    if !share.is_empty() && !lock.is_empty() {
        suites.lock_share = Some(LockShareSuite {
            path: share
                .first()
                .and_then(|(_, input, _)| value_as_str(input, "path"))
                .unwrap_or_default(),
            share_violation_code: share
                .first()
                .and_then(|(_, _, output)| value_as_u64(output, "second_error"))
                .unwrap_or(0) as u32,
            lock_violation_code: lock
                .first()
                .and_then(|(_, _, output)| value_as_u64(output, "error"))
                .unwrap_or(0) as u32,
            first_lock_offset: lock
                .first()
                .and_then(|(_, input, _)| value_as_u64(input, "offset"))
                .unwrap_or(0),
            first_lock_length: lock
                .first()
                .and_then(|(_, input, _)| value_as_u64(input, "length"))
                .unwrap_or(0),
            overlap_offset: lock
                .get(1)
                .and_then(|(_, input, _)| value_as_u64(input, "offset"))
                .unwrap_or(0),
            overlap_length: lock
                .get(1)
                .and_then(|(_, input, _)| value_as_u64(input, "length"))
                .unwrap_or(0),
        });
    }

    // case_fold / registry / dll_order / delay_load: the reference does not
    // yet cover these in a suite-shaped form; the corresponding tests skip
    // until the categories are extended.  Deliberately absent.

    suites
}
