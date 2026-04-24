use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

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