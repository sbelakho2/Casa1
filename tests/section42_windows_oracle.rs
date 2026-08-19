//! section42 — Windows differential-oracle harness.
//!
//! Covers the host-side harness end to end:
//!   - vector corpus generation is deterministic and versioned;
//!   - model-vs-model round trip (both sides computed with the MODEL-ONLY
//!     implementations in `casa1::oracle_model`) reports zero diffs;
//!   - the checked-in golden reference-results fixture (marked as
//!     captured-from-Windows with a capture header) validates clean and
//!     detects mutations;
//!   - on a non-Windows host the reference executable's stubs produce diffs
//!     against the model, and the comparison reports them (exit 1), which is
//!     the designed fail-loud behavior.
//!
//! The authoritative differential validation (real Windows 10/11 reference
//! capture vs. model) runs in .github/workflows/windows-oracle.yml.

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
            ),
            "unexpected category {category}"
        );
    }
}

#[test]
fn model_vs_model_round_trip_reports_no_diffs() {
    let temp = TempDir::new().expect("temp dir");
    let vectors = temp.path().join("vectors.json");
    let model_results = temp.path().join("model.json");
    assert!(
        run_oracle(&["vectors", "--out", vectors.to_str().expect("path")])
            .0
            .success()
    );
    assert!(
        run_oracle(&[
            "model-results",
            "--vectors",
            vectors.to_str().expect("path"),
            "--out",
            model_results.to_str().expect("path"),
        ])
        .0
        .success()
    );
    let (status, stdout) = run_oracle(&[
        "compare",
        "--vectors",
        vectors.to_str().expect("path"),
        "--results",
        model_results.to_str().expect("path"),
    ]);
    assert!(status.success(), "model-vs-model must not fail");
    let report = compare_report(&stdout);
    assert_eq!(report["diff_count"], 0);
    assert_eq!(report["compared"], report["vectors_total"]);
    assert!(
        !report["categories"]
            .as_object()
            .expect("categories")
            .is_empty()
    );
}

#[test]
fn model_results_carry_capture_header_marked_model_generated() {
    let temp = TempDir::new().expect("temp dir");
    let vectors = temp.path().join("vectors.json");
    let model_results = temp.path().join("model.json");
    assert!(
        run_oracle(&["vectors", "--out", vectors.to_str().expect("path")])
            .0
            .success()
    );
    assert!(
        run_oracle(&[
            "model-results",
            "--vectors",
            vectors.to_str().expect("path"),
            "--out",
            model_results.to_str().expect("path"),
        ])
        .0
        .success()
    );
    let file: Value = serde_json::from_slice(&std::fs::read(&model_results).expect("read"))
        .expect("parse model results");
    assert_eq!(file["schema_version"], 1);
    let capture = &file["capture"];
    assert_eq!(capture["source"], "windows");
    assert_eq!(capture["captured_by"], "casa1-windows-reference");
    assert_eq!(capture["captured_on"], "windows-10-11");
    assert_eq!(capture["capture_date"], "model-generated");
    assert!(
        capture["note"]
            .as_str()
            .expect("note")
            .contains("MODEL-GENERATED"),
        "model-generated files must be explicitly marked"
    );
}

#[test]
fn golden_fixture_validates_clean() {
    let (status, stdout) = run_oracle(&[
        "compare",
        "--results",
        golden_fixture().to_str().expect("path"),
    ]);
    assert!(status.success(), "golden fixture must validate clean");
    let report = compare_report(&stdout);
    assert_eq!(report["diff_count"], 0);
    // The golden covers exactly the path/case/sharing vectors.
    let categories = report["categories"].as_object().expect("categories");
    let category_keys: BTreeSet<&str> = categories.keys().map(String::as_str).collect();
    assert_eq!(
        category_keys,
        ["path_normalize", "case_fold", "file_sharing"]
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(report["compared"], 30);
    // Everything else is reported as not covered, not as a diff.
    assert!(
        !report["not_covered_categories"]
            .as_array()
            .expect("list")
            .is_empty()
    );
}

#[test]
fn golden_fixture_detects_mutation() {
    let temp = TempDir::new().expect("temp dir");
    let mutated = temp.path().join("golden-mutated.json");
    let mut file: Value =
        serde_json::from_slice(&std::fs::read(golden_fixture()).expect("read golden"))
            .expect("parse golden");
    for result in file["results"].as_array_mut().expect("results") {
        if result["id"] == "file_sharing:000" {
            result["output"]["second_error"] = serde_json::json!(999);
        }
    }
    std::fs::write(&mutated, serde_json::to_vec(&file).expect("encode")).expect("write");
    let (status, stdout) = run_oracle(&["compare", "--results", mutated.to_str().expect("path")]);
    assert!(!status.success(), "mutated golden must fail the comparison");
    let report = compare_report(&stdout);
    assert_eq!(report["diff_count"], 1);
    let diff = &report["diffs"][0];
    assert_eq!(diff["id"], "file_sharing:000");
    assert_eq!(diff["field"], "second_error");
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
