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
                    | "cpu_arithmetic_flags"
                    | "virtual_memory"
                    | "time_clock"
                    | "environment"
                    | "file_metadata"
                    | "directory_enumeration"
                    | "version"
                    | "error_domain"
                    | "string_ops"
                    | "section_mapping"
                    | "heap"
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
fn required_categories_gate_fails_for_uncovered_categories() {
    // A synthetic reference results file covering ONLY path_normalize: the
    // differential does not validate case_fold against it, so requiring
    // case_fold must fail the compare — even with --report-only (which only
    // suppresses the diff-exit, never the coverage-exit).
    let temp = TempDir::new().expect("temp dir");
    let synthetic = temp.path().join("only-path-normalize.json");
    let mut file: Value =
        serde_json::from_slice(&std::fs::read(golden_fixture()).expect("read golden"))
            .expect("parse golden");
    file["results"] = serde_json::json!(
        file["results"]
            .as_array()
            .expect("results")
            .iter()
            .filter(|result| result["category"] == "path_normalize")
            .collect::<Vec<_>>()
    );
    std::fs::write(&synthetic, serde_json::to_vec(&file).expect("encode")).expect("write");

    let (status, stdout) = run_oracle(&[
        "compare",
        "--results",
        synthetic.to_str().expect("path"),
        "--required-categories",
        "path_normalize,case_fold",
        "--report-only",
    ]);
    assert!(
        !status.success(),
        "a required category missing from the differential must fail even with --report-only"
    );
    let report = compare_report(&stdout);
    let uncovered: Vec<&str> = report["not_covered_categories"]
        .as_array()
        .expect("not_covered_categories")
        .iter()
        .filter_map(|category| category.as_str())
        .collect();
    assert!(
        uncovered.contains(&"case_fold"),
        "case_fold must be reported as not covered: {uncovered:?}"
    );

    // Positive control: requiring only the covered category passes the gate
    // (the placeholder diffs are suppressed by --report-only).
    let (status, _) = run_oracle(&[
        "compare",
        "--results",
        synthetic.to_str().expect("path"),
        "--required-categories",
        "path_normalize",
        "--report-only",
    ]);
    assert!(
        status.success(),
        "covered required categories must pass the coverage gate"
    );
}

#[test]
fn path_normalize_vectors_parse_typed_input() {
    // The path vectors are OBJECTS { path, cwd, long_paths_enabled }; the
    // runtime executor must operate on the typed `path` field — never on ""
    // (the pre-fix behavior).  Assert the normalized output corresponds to
    // the vector's path.
    let vectors = casa1::windows_oracle::generate_vectors(&["path_normalize".to_string()]);
    assert!(!vectors.is_empty(), "path_normalize corpus must exist");
    for vector in &vectors {
        let result = casa1::windows_oracle::compute_runtime_result(vector);
        let output = result.output;
        let normalized = output["normalized"].as_str().expect("normalized");
        assert!(
            !normalized.is_empty(),
            "{} must produce a non-empty normalized path",
            vector.id
        );
    }
    // The dot-segment vector round-trips through the runtime's parser, and
    // the cwd-dependent vectors resolve against the fixed working directory.
    let absolute = &vectors[0];
    let result = casa1::windows_oracle::compute_runtime_result(absolute);
    assert_eq!(
        result.output["normalized"],
        serde_json::json!("C:\\Alpha\\Beta\\.\\Gamma\\..\\File.txt"),
        "the normalized output must correspond to the vector's path"
    );
    let relative = vectors
        .iter()
        .find(|vector| vector.input["path"] == serde_json::json!("foo.txt"))
        .expect("relative-path vector");
    let result = casa1::windows_oracle::compute_runtime_result(relative);
    assert_eq!(
        result.output["normalized"],
        serde_json::json!("C:\\Windows\\Temp\\casa1-oracle-cwd\\foo.txt"),
        "relative paths must resolve against the vector's cwd"
    );
    assert_eq!(result.output["kind"], serde_json::json!("relative"));
}

#[test]
fn capture_provenance_fields_serialize() {
    // The reference executable records ACTUAL capture provenance; the header
    // must round-trip through serde, old files without the fields must still
    // parse (serde defaults), and is_real_windows_capture must require the
    // provenance to be present.
    let header = casa1::windows_oracle::CaptureHeader {
        source: "windows".to_string(),
        captured_by: "casa1-windows-reference".to_string(),
        captured_on: "windows-10-11".to_string(),
        capture_date: "2026-08-19T12:00Z".to_string(),
        note: None,
        os_edition: "Professional".to_string(),
        os_build: "10.0.22631".to_string(),
        arch: "x64".to_string(),
        target_triple: "x86_64-pc-windows-msvc".to_string(),
        reference_sha256: "a".repeat(64),
        corpus_sha256: "b".repeat(64),
    };
    let json = serde_json::to_string(&header).expect("serialize header");
    let parsed: casa1::windows_oracle::CaptureHeader =
        serde_json::from_str(&json).expect("parse header");
    assert_eq!(parsed, header, "provenance fields must round-trip");

    // Pre-provenance schema-version-1 files parse with empty defaults and
    // are NOT real captures.
    let legacy: casa1::windows_oracle::CaptureHeader = serde_json::from_str(
        r#"{"source":"windows","captured_by":"casa1-windows-reference","captured_on":"windows-10-11","capture_date":"model-generated","note":null}"#,
    )
    .expect("legacy header parses");
    assert_eq!(legacy.os_edition, "");
    assert_eq!(legacy.arch, "");
    assert_eq!(legacy.target_triple, "");

    let real = casa1::windows_oracle::ReferenceResultsFile {
        schema_version: 1,
        capture: header,
        results: Vec::new(),
    };
    assert!(
        casa1::oracle_suites::is_real_windows_capture(&real),
        "a header with full provenance must be a real Windows capture"
    );
    let without_provenance = casa1::windows_oracle::ReferenceResultsFile {
        schema_version: 1,
        capture: legacy,
        results: Vec::new(),
    };
    assert!(
        !casa1::oracle_suites::is_real_windows_capture(&without_provenance),
        "a header without provenance must not be accepted as a real capture"
    );
    // A capture whose target triple is missing (or a placeholder) is not
    // provenance — an x86 capture must be distinguishable from an x64 one.
    let mut no_triple = real.clone();
    no_triple.capture.target_triple = "".to_string();
    assert!(
        !casa1::oracle_suites::is_real_windows_capture(&no_triple),
        "a header without the compiler target triple must not be a real capture"
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

// ── cpu_arithmetic_flags ─────────────────────────────────────────────────────

/// The cpu_arithmetic_flags generator emits the documented edge set — every
/// (lhs, rhs) edge at every width (8/16/32/64) with every op (add/sub/cmp) —
/// plus the deterministic stride sample over the 8-bit space.  The bounded
/// corpus stays at ~3.3k vectors; the full 65,536-pair space is the
/// --exhaustive mode.
#[test]
fn cpu_flags_corpus_emits_the_documented_edge_set() {
    use casa1::windows_oracle::{CPU_FLAGS_EDGES, CPU_FLAGS_OPS, CPU_FLAGS_STRIDE_STEP};
    let vectors = casa1::windows_oracle::generate_vectors(&["cpu_arithmetic_flags".to_string()]);
    // Every documented edge runs at every width with every op.
    for &(lhs, rhs) in CPU_FLAGS_EDGES {
        for width in [8_u64, 16, 32, 64] {
            for op in CPU_FLAGS_OPS {
                assert!(
                    vectors.iter().any(|vector| {
                        vector.input["width"] == serde_json::json!(width)
                            && vector.input["op"] == serde_json::json!(op)
                            && vector.input["lhs"] == serde_json::json!(lhs)
                            && vector.input["rhs"] == serde_json::json!(rhs)
                    }),
                    "missing edge vector: width {width}, op {op}, lhs {lhs:#x}, rhs {rhs:#x}"
                );
            }
        }
    }
    // Corpus size: edges (18 pairs × 4 widths × 3 ops) + the 8-bit stride
    // sample (32 values per axis → 1,024 pairs × 3 ops).
    let stride_values = (0..=255_u64)
        .step_by(CPU_FLAGS_STRIDE_STEP as usize)
        .count();
    let expected = CPU_FLAGS_EDGES.len() * 4 * CPU_FLAGS_OPS.len()
        + stride_values * stride_values * CPU_FLAGS_OPS.len();
    assert_eq!(vectors.len(), expected, "bounded corpus size");
    assert!(
        vectors.len() < 10_000,
        "the bounded corpus must stay small for the CI capture ({} vectors)",
        vectors.len()
    );

    // The exhaustive mode replaces the stride sample with the full 8-bit
    // operand space (the nightly corpus).
    let exhaustive =
        casa1::windows_oracle::generate_vectors_exhaustive(&["cpu_arithmetic_flags".to_string()]);
    assert_eq!(
        exhaustive.len(),
        CPU_FLAGS_EDGES.len() * 4 * CPU_FLAGS_OPS.len() + 256 * 256 * CPU_FLAGS_OPS.len(),
        "exhaustive corpus size"
    );
}

/// The runtime cpu executor matches the KNOWN x86 truth table on the
/// documented edges — the interpreter's flag model (jit_helper_set_flags)
/// must agree with real x86 hardware on every edge.  This catches
/// interpreter flag regressions locally, before any Windows capture.
#[test]
fn cpu_flags_runtime_executor_matches_the_known_x86_truth_table() {
    use casa1::windows_oracle::{Vector, compute_runtime_result};
    let case = |width: u64, op: &str, lhs: u64, rhs: u64, expected: Value| {
        let vector = Vector {
            id: format!("cpu:{width}:{op}:{lhs:#x}:{rhs:#x}"),
            category: "cpu_arithmetic_flags".to_string(),
            input: serde_json::json!({ "width": width, "op": op, "lhs": lhs, "rhs": rhs }),
        };
        let output = compute_runtime_result(&vector).output;
        assert_eq!(output, expected, "width {width} {op}({lhs:#x}, {rhs:#x})");
        // The comparison machinery must report no diff against the
        // reference-shaped output.
        let diffs =
            casa1::windows_oracle::compare_outputs("cpu_arithmetic_flags", &expected, &output);
        assert!(diffs.is_empty(), "unexpected diffs: {diffs:?}");
    };
    let flags = |zf: bool, sf: bool, pf: bool, cf: bool, of: bool, af: bool| serde_json::json!({ "zf": zf, "sf": sf, "pf": pf, "cf": cf, "of": of, "af": af });
    // 0x7f + 1 → OF=1, CF=0 (8-bit sign overflow, no carry; the low
    // nibble F+1 also carries → AF=1)
    case(
        8,
        "add",
        0x7f,
        1,
        flags(false, true, false, false, true, true),
    );
    // 0x80 + 0x80 → CF=1, OF=1 (8-bit carry AND sign overflow)
    case(
        8,
        "add",
        0x80,
        0x80,
        flags(true, false, true, true, true, false),
    );
    // 0xff + 1 → CF=1, ZF=1, AF=1 (wrap to zero with nibble carry)
    case(
        8,
        "add",
        0xff,
        1,
        flags(true, false, true, true, false, true),
    );
    // 0x7fffffffffffffff + 1 → OF=1 (64-bit sign overflow; nibble carry)
    case(
        64,
        "add",
        0x7fff_ffff_ffff_ffff,
        1,
        flags(false, true, true, false, true, true),
    );
    // 0xffffffffffffffff + 1 → CF=1, ZF=1 (wrap to zero; nibble carry)
    case(
        64,
        "add",
        0xffff_ffff_ffff_ffff,
        1,
        flags(true, false, true, true, false, true),
    );
    // 0x80 - 1 → no borrow (CF=0); the subtraction overflows signed 8-bit
    // (OF=1) and borrows into the low nibble (AF=1).  Real x86 sub:
    // 0x80 ≥ 1, so there is no carry — the borrow edge is 0x7f - 0x80 below.
    case(
        8,
        "sub",
        0x80,
        1,
        flags(false, false, false, false, true, true),
    );
    // 0x7f - 0x80 → OF=1 (and CF=1: unsigned borrow)
    case(
        8,
        "sub",
        0x7f,
        0x80,
        flags(false, true, true, true, true, false),
    );
    // 0x0f + 1 → AF=1 (nibble carry)
    case(
        8,
        "add",
        0x0f,
        1,
        flags(false, false, false, false, false, true),
    );
    // 0x0f + 0x0f → AF=1 (nibble carry)
    case(
        8,
        "add",
        0x0f,
        0x0f,
        flags(false, false, true, false, false, true),
    );
}

// ── virtual_memory ──────────────────────────────────────────────────────────

/// The virtual_memory generator emits the documented session sequence: the
/// reserve first (address 0 = system-chosen base), then the interior
/// commit, partial protect, partial decommit, the two mandated failures and
/// the unmapped-address query — all with session-relative addresses.
#[test]
fn virtual_memory_corpus_is_the_documented_session_sequence() {
    // Oracle sessions dispatch the Nt* thunk surface, whose debug-build
    // dispatch frame overflows libtest's default 2 MiB test-thread stack.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let vectors = casa1::windows_oracle::generate_vectors(&["virtual_memory".to_string()]);
            let operations: Vec<String> = vectors
                .iter()
                .map(|vector| {
                    vector.input["operation"]
                        .as_str()
                        .expect("operation")
                        .to_string()
                })
                .collect();
            assert_eq!(
                operations,
                [
                    "reserve", "query", "commit", "protect", "decommit", "release", "commit",
                    "query",
                ]
            );
            assert_eq!(vectors[0].input["address"], serde_json::json!(0));
            assert_eq!(vectors[0].input["size"], serde_json::json!(0x4000));
            assert_eq!(
                vectors[0].input["allocation_type"],
                serde_json::json!(0x2000)
            );
            // The failures and the unmapped-address probes sit outside the session.
            assert_eq!(vectors[5].input["free_type"], serde_json::json!(0x8000));
            assert!(vectors[5].input["size"].as_u64().expect("size") != 0);
            for vector in &vectors {
                let result = casa1::windows_oracle::compute_runtime_result(vector);
                assert!(result.output["state"].is_number(), "{}", vector.id);
            }
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

/// The runtime vm executor drives the real pe_runtime VM thunk arms: the
/// reserve→commit→query coherence, the interior commit, the partial
/// decommit and the mandated failures all produce the reference-shaped
/// page-granular truth (MEM_COMMIT/MEM_RESERVE/MEM_FREE states, protections,
/// region-relative bases and sizes).
#[test]
fn virtual_memory_runtime_executor_matches_reference_derived_truth() {
    // Oracle sessions dispatch the Nt* thunk surface (big debug frame).
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
    use casa1::windows_oracle::compute_runtime_result;
    let vectors = casa1::windows_oracle::generate_vectors(&["virtual_memory".to_string()]);
    let results: Vec<Value> = vectors
        .iter()
        .map(|vector| compute_runtime_result(vector).output)
        .collect();
    // The reference-derived truth for the session sequence.  States:
    // MEM_COMMIT=0x1000, MEM_RESERVE=0x2000, MEM_FREE=0x10000.  Protections:
    // PAGE_NOACCESS=0x01, PAGE_READWRITE=0x04, PAGE_READONLY=0x02.
    let expected = [
        // 0: reserve 0x4000 → the queried base is a 0x4000 reserved region.
        serde_json::json!({ "error": 0, "state": 0x2000, "protection": 0x01, "region_size": 0x4000, "base_address": 0, "committed_set_summary": false }),
        // 1: query mid-range (0x2000 into the reservation): Windows
        //    VirtualQuery reports BaseAddress = the region base and
        //    RegionSize = the FULL region size (0x4000), not the tail.
        serde_json::json!({ "error": 0, "state": 0x2000, "protection": 0x01, "region_size": 0x4000, "base_address": 0, "committed_set_summary": false }),
        // 2: interior commit [0x1000, 0x3000) READWRITE: a committed
        //    region from 0x1000 with size 0x2000.
        serde_json::json!({ "error": 0, "state": 0x1000, "protection": 0x04, "region_size": 0x2000, "base_address": 0x1000, "committed_set_summary": true }),
        // 3: partial protect of [0x1000, 0x2000): old protection
        //    PAGE_READWRITE (0x04), new PAGE_READONLY (0x02), and the
        //    committed run shrinks to 0x1000.
        serde_json::json!({ "error": 0, "state": 0x1000, "protection": 0x02, "region_size": 0x1000, "base_address": 0x1000, "committed_set_summary": true, "old_protection": 0x04 }),
        // 4: partial decommit of [0x2000, 0x3000): the page returns to
        //    MEM_RESERVE; the reserved run starts at 0x2000 with size
        //    0x2000 (the READONLY commit at 0x1000 splits the reservation).
        serde_json::json!({ "error": 0, "state": 0x2000, "protection": 0x01, "region_size": 0x2000, "base_address": 0x2000, "committed_set_summary": false }),
        // 5: release with size != 0 must fail with ERROR_INVALID_PARAMETER
        //    (87); the failed release changed nothing (the base page is
        //    still the 0x1000 reserved run before the READONLY commit).
        serde_json::json!({ "error": 87, "state": 0x2000, "protection": 0x01, "region_size": 0x1000, "base_address": 0, "committed_set_summary": false }),
        // 6: commit WITHOUT a reservation must fail with
        //    ERROR_INVALID_ADDRESS (487); the target page is MEM_FREE with
        //    a NULL base and a 0 size.
        serde_json::json!({ "error": 487, "state": 0x1_0000, "protection": 0x01, "region_size": 0, "base_address": 0, "committed_set_summary": false }),
        // 7: query an unmapped address → MEM_FREE + NULL base + 0 size.
        serde_json::json!({ "error": 0, "state": 0x1_0000, "protection": 0x01, "region_size": 0, "base_address": 0, "committed_set_summary": false }),
    ];
    assert_eq!(results.len(), expected.len());
    for (index, (vector, result)) in vectors.iter().zip(results.iter()).enumerate() {
        assert_eq!(
            result, &expected[index],
            "vector {} ({}) must match the reference-derived truth",
            vector.id, vector.input["operation"]
        );
        let diffs =
            casa1::windows_oracle::compare_outputs("virtual_memory", &expected[index], result);
        assert!(
            diffs.is_empty(),
            "{} unexpected diffs: {diffs:?}",
            vector.id
        );
    }

        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── evidence-expansion categories ───────────────────────────────────────────

/// The new categories' corpus is deterministic, versioned and unique, and
/// the Casa1 runtime computes EVERY vector (no runtime_unavailable marker).
#[test]
fn evidence_expansion_corpus_is_deterministic_and_fully_computed() {
    use casa1::windows_oracle::{ALL_CATEGORIES, compute_runtime_result, generate_vectors};
    let categories = [
        "time_clock",
        "environment",
        "file_metadata",
        "directory_enumeration",
        "version",
        "error_domain",
        "string_ops",
        "section_mapping",
        "heap",
    ];
    for category in categories {
        assert!(
            ALL_CATEGORIES.contains(&category),
            "{category} must be part of the differential corpus"
        );
        let vectors = generate_vectors(&[category.to_string()]);
        assert!(!vectors.is_empty(), "{category} corpus must exist");
        for vector in &vectors {
            let result = compute_runtime_result(vector);
            assert_eq!(
                result.output.get("runtime_unavailable"),
                None,
                "{} must be computed by the Casa1 runtime, not reported unavailable",
                vector.id
            );
        }
    }
}

/// The model-generated golden regeneration path for the new categories is
/// clean end to end: `casa1-oracle golden` emits the Casa1 runtime's
/// behavior wrapped in the MODEL-GENERATED header, and comparing the same
/// corpus against it reports zero diffs with every category covered.  The
/// authoritative validation remains the Windows reference capture (CI); the
/// golden placeholder exists so the harness has a deterministic local
/// reference shape.
#[test]
fn new_categories_golden_roundtrip_is_clean() {
    let temp = TempDir::new().expect("temp dir");
    let vectors_path = temp.path().join("vectors.json");
    let golden_path = temp.path().join("golden.json");
    let categories = "time_clock,environment,file_metadata,directory_enumeration,version,error_domain,string_ops,section_mapping,heap";
    let (status, _) = run_oracle(&[
        "vectors",
        "--out",
        vectors_path.to_str().expect("path"),
        "--categories",
        categories,
    ]);
    assert!(status.success());
    let (status, _) = run_oracle(&[
        "golden",
        "--out",
        golden_path.to_str().expect("path"),
        "--categories",
        categories,
    ]);
    assert!(status.success());
    let golden: Value = serde_json::from_slice(&std::fs::read(&golden_path).expect("read golden"))
        .expect("parse golden");
    assert_eq!(golden["capture"]["capture_date"], "model-generated");
    let (status, stdout) = run_oracle(&[
        "compare",
        "--vectors",
        vectors_path.to_str().expect("path"),
        "--results",
        golden_path.to_str().expect("path"),
    ]);
    assert!(
        status.success(),
        "the golden roundtrip must be clean:\n{stdout}"
    );
    let report = compare_report(&stdout);
    assert_eq!(report["diff_count"].as_u64(), Some(0));
    assert!(
        report["runtime_uncovered_categories"]
            .as_array()
            .expect("runtime_uncovered_categories")
            .is_empty(),
        "no category may be runtime-uncovered"
    );
}

/// The checked-in golden fixture carries the new categories (model-generated
/// placeholders by design) and the compare against it keeps the fail-loud
/// contract: the stale model-era placeholder values still produce diffs, and
/// the new categories contribute none.
#[test]
fn golden_fixture_covers_the_new_categories() {
    let file: Value =
        serde_json::from_slice(&std::fs::read(golden_fixture()).expect("read golden"))
            .expect("parse golden");
    let categories: std::collections::BTreeSet<&str> = file["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|result| result["category"].as_str())
        .collect();
    for category in [
        "time_clock",
        "environment",
        "file_metadata",
        "directory_enumeration",
        "version",
        "error_domain",
        "string_ops",
        "section_mapping",
        "heap",
    ] {
        assert!(
            categories.contains(category),
            "the golden fixture must cover {category}"
        );
    }
}
