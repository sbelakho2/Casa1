use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedTimes {
    pub created_ms: u64,
    pub accessed_ms: u64,
    pub modified_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestException {
    pub code: u32,
    pub addr: Option<String>,
    pub module: String,
    pub tid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifestDelta {
    pub op: String,
    pub path_norm: String,
    pub sha256: String,
    pub size: u64,
    pub times_norm: NormalizedTimes,
    pub attrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryDelta {
    pub op: String,
    pub hive: String,
    pub key_norm: String,
    pub value: String,
    #[serde(rename = "type")]
    pub value_type: String,
    pub data_norm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSummary {
    pub proto: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tls_version: String,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GfxFrame {
    pub scene_id: String,
    pub frame_index: u32,
    pub hash: String,
    pub ssim: f64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerfMetric {
    pub metric_id: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalTestOutput {
    pub test_id: String,
    pub build_id: String,
    pub os_build: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub guest_exceptions: Vec<GuestException>,
    pub file_manifest_delta: Vec<FileManifestDelta>,
    pub registry_delta: Vec<RegistryDelta>,
    pub network_summary: Vec<NetworkSummary>,
    pub gfx_frames: Vec<GfxFrame>,
    pub perf: Vec<PerfMetric>,
}

impl CanonicalTestOutput {
    pub fn stable_json(&self) -> AppResult<String> {
        util::stable_json(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ToleranceRegistry {
    pub rules: BTreeMap<String, BTreeMap<String, ToleranceRule>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToleranceRule {
    pub epsilon: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparisonFailure {
    pub path: String,
    pub expected: Value,
    pub actual: Value,
    pub message: String,
}

pub fn compare_outputs(
    expected: &CanonicalTestOutput,
    actual: &CanonicalTestOutput,
    tolerance_registry: &ToleranceRegistry,
) -> Result<(), ComparisonFailure> {
    let expected_value = serde_json::to_value(expected).map_err(|error| ComparisonFailure {
        path: "<root>".to_string(),
        expected: Value::Null,
        actual: Value::Null,
        message: format!("failed to serialize expected canonical output: {error}"),
    })?;
    let actual_value = serde_json::to_value(actual).map_err(|error| ComparisonFailure {
        path: "<root>".to_string(),
        expected: Value::Null,
        actual: Value::Null,
        message: format!("failed to serialize actual canonical output: {error}"),
    })?;
    compare_value(
        &expected.test_id,
        "",
        &expected_value,
        &actual_value,
        tolerance_registry,
    )
}

pub fn comparison_error(failure: &ComparisonFailure) -> AppError {
    AppError::new(
        ReasonCode::RcCompareMismatch,
        format!("canonical outputs diverged at {}", failure.path),
    )
    .with_hint(failure.message.clone())
}

fn compare_value(
    test_id: &str,
    path: &str,
    expected: &Value,
    actual: &Value,
    tolerance_registry: &ToleranceRegistry,
) -> Result<(), ComparisonFailure> {
    match (expected, actual) {
        (Value::Object(expected_map), Value::Object(actual_map)) => {
            let expected_keys: Vec<_> = expected_map.keys().collect();
            let actual_keys: Vec<_> = actual_map.keys().collect();
            if expected_keys != actual_keys {
                return Err(failure(
                    path,
                    expected,
                    actual,
                    "object keys differ between expected and actual outputs",
                ));
            }

            for key in expected_keys {
                let next_path = join_path(path, key);
                compare_value(
                    test_id,
                    &next_path,
                    &expected_map[key],
                    &actual_map[key],
                    tolerance_registry,
                )?;
            }
            Ok(())
        }
        (Value::Array(expected_items), Value::Array(actual_items)) => {
            if expected_items.len() != actual_items.len() {
                return Err(failure(
                    path,
                    expected,
                    actual,
                    "array lengths differ between expected and actual outputs",
                ));
            }

            for (index, (expected_item, actual_item)) in
                expected_items.iter().zip(actual_items.iter()).enumerate()
            {
                let next_path = format!("{path}[{index}]");
                compare_value(test_id, &next_path, expected_item, actual_item, tolerance_registry)?;
            }
            Ok(())
        }
        (Value::Number(expected_number), Value::Number(actual_number)) => {
            let tolerance = tolerance_registry
                .rules
                .get(test_id)
                .and_then(|fields| fields.get(path));
            if let Some(rule) = tolerance {
                let Some(expected_float) = expected_number.as_f64() else {
                    return Err(failure(path, expected, actual, "expected number is not representable as f64"));
                };
                let Some(actual_float) = actual_number.as_f64() else {
                    return Err(failure(path, expected, actual, "actual number is not representable as f64"));
                };
                if (expected_float - actual_float).abs() <= rule.epsilon {
                    Ok(())
                } else {
                    Err(failure(
                        path,
                        expected,
                        actual,
                        &format!("numeric difference exceeded tolerance epsilon {}", rule.epsilon),
                    ))
                }
            } else if expected_number == actual_number {
                Ok(())
            } else {
                Err(failure(path, expected, actual, "numeric values differ"))
            }
        }
        _ if expected == actual => Ok(()),
        _ => Err(failure(path, expected, actual, "values differ")),
    }
}

fn failure(path: &str, expected: &Value, actual: &Value, message: &str) -> ComparisonFailure {
    ComparisonFailure {
        path: if path.is_empty() {
            "<root>".to_string()
        } else {
            path.to_string()
        },
        expected: expected.clone(),
        actual: actual.clone(),
        message: message.to_string(),
    }
}

fn join_path(current: &str, segment: &str) -> String {
    if current.is_empty() {
        segment.to_string()
    } else {
        format!("{current}.{segment}")
    }
}