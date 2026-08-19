//! section42 — Windows differential-oracle harness.
//!
//! Covers the host-side harness end to end:
//!   - vector corpus generation is deterministic and versioned;
//!   - the Casa1-runtime-vs-reference comparison reports diffs (exit 1)
//!     against the placeholder fixture on non-Windows hosts — the designed
//!     fail-loud behavior (there is NO Casa1-side model to substitute);
//!   - the capture-header validation refuses model-generated placeholders.
//!
//! The authoritative differential validation (real Windows 10/11 reference
//! capture vs. the Casa1 runtime) runs in .github/workflows/windows-oracle.yml.

mod support;

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn oracle_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_casa1-oracle"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn golden_fixture() -> PathBuf {
    repo_root().join("tests/fixtures/section42/golden_windows_reference_results.json")
}

fn run_oracle(args: &[&str]) -> (std::process::ExitStatus, String) {
    let output = Command::new(oracle_bin())
        .args(args)
        .output()
        .expect("run casa1-oracle");
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn compare_report(stdout: &str) -> Value {
    serde_json::from_str(stdout).expect("parse comparison report JSON")
}

#[test]
fn vector_corpus_is_versioned_and_deterministic() {
    let temp = TempDir::new().expect("temp dir");
    let first = temp.path().join("vectors-a.json");
    let second = temp.path().join("vectors-b.json");
    let (status_a, _) = run_oracle(&["vectors", "--out", first.to_str().expect("path")]);
    assert!(status_a.success());
    let (status_b, _) = run_oracle(&["vectors", "--out", second.to_str().expect("path")]);
    assert!(status_b.success());
    let bytes_a = std::fs::read(&first).expect("read vectors a");
    let bytes_b = std::fs::read(&second).expect("read vectors b");
    assert_eq!(bytes_a, bytes_b, "corpus generation must be deterministic");

    let file: Value = serde_json::from_slice(&bytes_a).expect("parse vectors");
    assert_eq!(file["schema_version"], 1);
    let vectors = file["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    let ids: BTreeSet<&str> = vectors
        .iter()
        .map(|vector| vector["id"].as_str().expect("vector id"))
        .collect();
    assert_eq!(ids.len(), vectors.len(), "vector ids must be unique");
    for vector in vectors {
        let category = vector["category"].as_str().expect("category");
        assert!(
            matches!(
                category,
                "path_normalize"
                    | "case_fold"
                    | "file_sharing"
                    | "file_lock"
                    | "delete_semantics"
                    | "api_set"
                    | "registry"
                    | "synchronization"
                    | "crt_printf"
                    | "thread_tls"
                    | "d3d12_texture_address_mode"
                    | "d3d12_filter_reduction"
                    | "d3d12_filter_translation"
            ),
            "unexpected category {category}"
        );
    }
}

/// The D3D12 enum categories carry the reference-derived differential
/// corpus: every numeric input 0..=8 for the address-mode and reduction
/// enums (including the undefined range), and every named D3D12_FILTER.
#[test]
fn d3d12_enum_corpus_covers_the_reference_derived_range() {
    let vectors: Vec<Value> = {
        let temp = TempDir::new().expect("temp dir");
        let path = temp.path().join("vectors.json");
        run_oracle(&["vectors", "--out", path.to_str().expect("path")]);
        let file: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse vectors");
        file["vectors"].as_array().expect("vectors").clone()
    };
    let modes: Vec<u32> = vectors
        .iter()
        .filter(|vector| vector["category"] == "d3d12_texture_address_mode")
        .filter_map(|vector| vector["input"]["mode"].as_u64().map(|mode| mode as u32))
        .collect();
    assert_eq!(modes, (0..=8).collect::<Vec<u32>>());
    let reductions: Vec<u32> = vectors
        .iter()
        .filter(|vector| vector["category"] == "d3d12_filter_reduction")
        .filter_map(|vector| vector["input"]["value"].as_u64().map(|value| value as u32))
        .collect();
    assert_eq!(reductions, (0..=8).collect::<Vec<u32>>());
    let filters: Vec<u64> = vectors
        .iter()
        .filter(|vector| vector["category"] == "d3d12_filter_translation")
        .filter_map(|vector| vector["input"]["filter"].as_u64())
        .collect();
    // 36 named D3D12_FILTER members (4 families x 8 combos + 4 aniso).
    assert_eq!(filters.len(), 36);
    assert_eq!(
        filters
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        36,
        "filter vectors must be unique"
    );
}

/// The Casa1 runtime's D3D12 enum mapping must match the reference-derived
/// truth (d3d12.h) on every vector of the three D3D12 categories. The truth
/// file below is built from the documented d3d12.h facts — the same facts
/// the Windows reference executable hardcodes — so this end-to-end run
/// proves the differential machinery passes exactly when the runtime agrees
/// with Windows.
#[test]
fn d3d12_enum_runtime_matches_reference_derived_truth() {
    let temp = TempDir::new().expect("temp dir");
    let vectors_path = temp.path().join("d3d12-vectors.json");
    let truth_path = temp.path().join("d3d12-truth.json");
    let (status, _) = run_oracle(&[
        "vectors",
        "--out",
        vectors_path.to_str().expect("path"),
        "--categories",
        "d3d12_texture_address_mode,d3d12_filter_reduction,d3d12_filter_translation",
    ]);
    assert!(status.success());
    let vector_file: Value =
        serde_json::from_slice(&std::fs::read(&vectors_path).expect("read vectors"))
            .expect("parse vectors");
    let results: Vec<Value> = vector_file["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(reference_derived_truth)
        .collect();
    let truth_file = serde_json::json!({
        "schema_version": 1,
        "capture": {
            "source": "windows",
            "captured_by": "casa1-windows-reference",
            "captured_on": "windows-10-11",
            "capture_date": "model-generated",
            "note": "REFERENCE-DERIVED d3d12.h truth for the section42 differential test"
        },
        "results": results,
    });
    std::fs::write(
        &truth_path,
        serde_json::to_vec_pretty(&truth_file).expect("encode truth"),
    )
    .expect("write truth");
    let (status, stdout) = run_oracle(&[
        "compare",
        "--vectors",
        vectors_path.to_str().expect("path"),
        "--results",
        truth_path.to_str().expect("path"),
    ]);
    assert!(
        status.success(),
        "runtime must match the reference-derived d3d12.h truth:\n{stdout}"
    );
    let report = compare_report(&stdout);
    assert_eq!(report["diff_count"].as_u64(), Some(0));
}

/// The reference-derived d3d12.h truth for one vector — the same facts the
/// Windows reference executable hardcodes (0-based address modes, the four
/// reduction types, the D3D12_FILTER bit layout, the 36 named filters).
fn reference_derived_truth(vector: &Value) -> Value {
    let category = vector["category"].as_str().expect("category");
    let input = &vector["input"];
    match category {
        "d3d12_texture_address_mode" => {
            let mode = input["mode"].as_u64().expect("mode") as u32;
            let name = match mode {
                0 => Some("WRAP"),
                1 => Some("MIRROR"),
                2 => Some("CLAMP"),
                3 => Some("BORDER"),
                4 => Some("MIRROR_ONCE"),
                _ => None,
            };
            serde_json::json!({
                "id": vector["id"],
                "category": category,
                "output": {
                    "mode": mode,
                    "name": name,
                    "valid": name.is_some(),
                },
            })
        }
        "d3d12_filter_reduction" => {
            let value = input["value"].as_u64().expect("value") as u32;
            let name = match value {
                0 => Some("STANDARD"),
                1 => Some("COMPARISON"),
                2 => Some("MINIMUM"),
                3 => Some("MAXIMUM"),
                _ => None,
            };
            serde_json::json!({
                "id": vector["id"],
                "category": category,
                "output": {
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
                },
            })
        }
        "d3d12_filter_translation" => {
            let filter = input["filter"].as_u64().expect("filter") as u32;
            let (name, min, mag, mip, aniso, reduction, reduction_name) = match filter {
                0x0000_0000 => (
                    Some("D3D12_FILTER_MIN_MAG_MIP_POINT"),
                    "POINT",
                    "POINT",
                    "POINT",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0001 => (
                    Some("D3D12_FILTER_MIN_MAG_POINT_MIP_LINEAR"),
                    "POINT",
                    "POINT",
                    "LINEAR",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0004 => (
                    Some("D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT"),
                    "POINT",
                    "LINEAR",
                    "POINT",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0005 => (
                    Some("D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
                    "POINT",
                    "LINEAR",
                    "LINEAR",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0010 => (
                    Some("D3D12_FILTER_MIN_LINEAR_MAG_MIP_POINT"),
                    "LINEAR",
                    "POINT",
                    "POINT",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0011 => (
                    Some("D3D12_FILTER_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
                    "LINEAR",
                    "POINT",
                    "LINEAR",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0014 => (
                    Some("D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
                    "LINEAR",
                    "LINEAR",
                    "POINT",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0015 => (
                    Some("D3D12_FILTER_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    false,
                    0,
                    "STANDARD",
                ),
                0x0000_0055 => (
                    Some("D3D12_FILTER_ANISOTROPIC"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    true,
                    0,
                    "STANDARD",
                ),
                0x0000_0080 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_MAG_MIP_POINT"),
                    "POINT",
                    "POINT",
                    "POINT",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0081 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_MAG_POINT_MIP_LINEAR"),
                    "POINT",
                    "POINT",
                    "LINEAR",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0084 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_POINT"),
                    "POINT",
                    "LINEAR",
                    "POINT",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0085 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
                    "POINT",
                    "LINEAR",
                    "LINEAR",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0090 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_MIP_POINT"),
                    "LINEAR",
                    "POINT",
                    "POINT",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0091 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
                    "LINEAR",
                    "POINT",
                    "LINEAR",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0094 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
                    "LINEAR",
                    "LINEAR",
                    "POINT",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_0095 => (
                    Some("D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    false,
                    1,
                    "COMPARISON",
                ),
                0x0000_00d5 => (
                    Some("D3D12_FILTER_COMPARISON_ANISOTROPIC"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    true,
                    1,
                    "COMPARISON",
                ),
                0x0000_0100 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_MAG_MIP_POINT"),
                    "POINT",
                    "POINT",
                    "POINT",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0101 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_MAG_POINT_MIP_LINEAR"),
                    "POINT",
                    "POINT",
                    "LINEAR",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0104 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT"),
                    "POINT",
                    "LINEAR",
                    "POINT",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0105 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
                    "POINT",
                    "LINEAR",
                    "LINEAR",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0110 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_MIP_POINT"),
                    "LINEAR",
                    "POINT",
                    "POINT",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0111 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
                    "LINEAR",
                    "POINT",
                    "LINEAR",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0114 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
                    "LINEAR",
                    "LINEAR",
                    "POINT",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0115 => (
                    Some("D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    false,
                    2,
                    "MINIMUM",
                ),
                0x0000_0155 => (
                    Some("D3D12_FILTER_MINIMUM_ANISOTROPIC"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    true,
                    2,
                    "MINIMUM",
                ),
                0x0000_0180 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_MAG_MIP_POINT"),
                    "POINT",
                    "POINT",
                    "POINT",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0181 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_MAG_POINT_MIP_LINEAR"),
                    "POINT",
                    "POINT",
                    "LINEAR",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0184 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_POINT"),
                    "POINT",
                    "LINEAR",
                    "POINT",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0185 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_POINT_MAG_LINEAR_MIP_LINEAR"),
                    "POINT",
                    "LINEAR",
                    "LINEAR",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0190 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_MIP_POINT"),
                    "LINEAR",
                    "POINT",
                    "POINT",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0191 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_POINT_MIP_LINEAR"),
                    "LINEAR",
                    "POINT",
                    "LINEAR",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0194 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_POINT"),
                    "LINEAR",
                    "LINEAR",
                    "POINT",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_0195 => (
                    Some("D3D12_FILTER_MAXIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    false,
                    3,
                    "MAXIMUM",
                ),
                0x0000_01d5 => (
                    Some("D3D12_FILTER_MAXIMUM_ANISOTROPIC"),
                    "LINEAR",
                    "LINEAR",
                    "LINEAR",
                    true,
                    3,
                    "MAXIMUM",
                ),
                _ => panic!("unexpected filter vector {filter:#x}"),
            };
            serde_json::json!({
                "id": vector["id"],
                "category": category,
                "output": {
                    "filter": filter,
                    "name": name,
                    "min_filter": min,
                    "mag_filter": mag,
                    "mip_filter": mip,
                    "anisotropic": aniso,
                    "reduction": reduction,
                    "reduction_name": reduction_name,
                    "valid": name.is_some(),
                },
            })
        }
        _ => panic!("unexpected category {category}"),
    }
}

#[test]
fn placeholder_golden_is_refused_and_compare_fails_loud() {
    // The checked-in golden is a MODEL-GENERATED placeholder (no real
    // Windows capture yet).  The reference-results consumer must REFUSE it,
    // and the compare must FAIL (exit 1): with no Casa1-side model there is
    // nothing that can "validate clean" against a placeholder.
    assert!(
        support::reference_results().is_none(),
        "the model-generated placeholder must be refused by the reference-results consumer"
    );
    let (status, stdout) = run_oracle(&[
        "compare",
        "--results",
        golden_fixture().to_str().expect("path"),
    ]);
    assert!(
        !status.success(),
        "comparing against a non-Windows placeholder must fail loud"
    );
    let report = compare_report(&stdout);
    // The runtime candidate genuinely differs from the placeholder values
    // (the placeholder was never Windows truth), so the report carries
    // diffs — the honest fail-loud signal until a real capture exists.
    assert!(report["diff_count"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn mutated_reference_results_change_the_diff_set() {
    // Mutation detection on a REAL capture is validated by the Windows CI
    // capture; here we prove the compare machinery distinguishes mutated
    // results from the original placeholder by a different diff signature.
    let temp = TempDir::new().expect("temp dir");
    let mutated = temp.path().join("golden-mutated.json");
    let mut file: Value =
        serde_json::from_slice(&std::fs::read(golden_fixture()).expect("read golden"))
            .expect("parse golden");
    for result in file["results"].as_array_mut().expect("results") {
        if result["id"] == "path_normalize:000" {
            result["output"]["normalized"] = serde_json::json!("C:\\MUTATED");
        }
    }
    std::fs::write(&mutated, serde_json::to_vec(&file).expect("encode")).expect("write");
    let (status, stdout) = run_oracle(&["compare", "--results", mutated.to_str().expect("path")]);
    assert!(
        !status.success(),
        "mutated results must fail the comparison"
    );
    let report = compare_report(&stdout);
    // The mutation must be present in the reported diffs.
    let ids: Vec<&str> = report["diffs"]
        .as_array()
        .expect("diffs")
        .iter()
        .filter_map(|diff| diff["id"].as_str())
        .collect();
    assert!(
        ids.contains(&"path_normalize:000"),
        "the mutated vector must appear in the diff set: {ids:?}"
    );
}

#[test]
fn reference_executable_on_non_windows_reports_diffs() {
    // The reference executable must be runnable everywhere; on non-Windows
    // hosts its stubs return unsupported_platform for every vector, which
    // the comparison reports as diffs (exit 1) — the designed fail-loud
    // behavior. This also proves the crate builds outside Windows.
    let build = Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(repo_root().join("windows_reference/Cargo.toml"))
        .output()
        .expect("build the reference crate");
    assert!(
        build.status.success(),
        "windows_reference crate failed to build: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let reference_exe = repo_root().join("windows_reference/target/debug/casa1-windows-reference");
    assert!(reference_exe.exists(), "reference exe missing after build");
    let output = Command::new(oracle_bin())
        .arg("vectors")
        .env("CASA1_WINDOWS_REFERENCE_EXE", &reference_exe)
        .output()
        .expect("run env-driven comparison");
    assert!(
        !output.status.success(),
        "non-Windows reference results must fail the comparison"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout).expect("parse comparison report JSON");
    assert!(
        report["diff_count"].as_u64().expect("diff count") > 0,
        "stub results must produce diffs"
    );
}
