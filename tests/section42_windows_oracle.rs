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
            ),
            "unexpected category {category}"
        );
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
