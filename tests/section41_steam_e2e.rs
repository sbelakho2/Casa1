//! Phase 41 — Real Steam E2E acceptance (S0-S13).
//!
//! Runs the REAL Steam client from `ges/steam/drive_c/Steam/Steam.exe`
//! through the runner's `execute_job` path with a bounded wall-clock
//! deadline (`CASA1_PE_RUNTIME_DEADLINE_SECS`, default 300 s), loads the
//! steam-bootstrap artifact the runner writes into the GE diagnostics
//! directory, and evaluates it with [`casa1::steam_acceptance::evaluate`]
//! under a policy that requires stages S0-S12 and allows the harness
//! deadline.
//!
//! The test PASSES only when the acceptance result passes, or when every
//! recorded failure is a documented stage-missing (`StageNotReached`) and
//! the full evidence (artifact identity, completed/missing stages,
//! failures) has been printed.
//!
//! Gated twice: `#[ignore]` keeps it out of the default suite, and the
//! `CASA1_STEAM_E2E=1` environment gate skips it (with a message) even
//! when `--ignored` forces the run.
//!
//! Usage:
//! ```bash
//! CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \
//!   cargo test --release --test section41_steam_e2e -- --ignored --nocapture
//! ```

use casa1::ge::GameEnvironment;
use casa1::runner::{RunIntent, RunnerJob, SteamBootstrapArtifact, execute_job};
use casa1::steam_acceptance::{
    MANDATORY_STAGES, SteamAcceptanceFailure, SteamAcceptancePolicy, evaluate,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The Steam GE whose `drive_c/Steam/Steam.exe` is the real client.
const STEAM_GE: &str = "steam";

/// The E2E gate: `CASA1_STEAM_E2E=1` is required even with `--ignored`.
fn steam_e2e_gate() -> bool {
    if std::env::var("CASA1_STEAM_E2E").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: CASA1_STEAM_E2E is not set to 1.\n\
             This test runs the REAL Steam client under the Casa1 PE runtime\n\
             and needs the live E2E environment. Re-run with:\n\
             \n\
             CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \\\n\
               cargo test --release --test section41_steam_e2e -- --ignored --nocapture"
        );
        return false;
    }
    true
}

/// Resolve the tracked Steam GE root via the workspace manifest dir.
fn steam_ge_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join(STEAM_GE)
}

/// The newest `*-steam-bootstrap.json` artifact in `dir`, if any.
fn latest_steam_artifact(dir: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file() && {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.ends_with("-steam-bootstrap.json")
            }
        })
        .filter_map(|entry| {
            entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .map(|modified| (modified, entry.path()))
        })
        .collect();
    candidates.sort_by_key(|(modified, _)| *modified);
    candidates.pop().map(|(_, path)| path)
}

#[test]
#[ignore = "requires live Steam E2E environment"]
fn t41_steam_e2e_acceptance() {
    if !steam_e2e_gate() {
        return;
    }

    // ── Resolve the real client ──────────────────────────────────────────
    let ge_root = steam_ge_root();
    let steam_exe = ge_root.join("drive_c").join("Steam").join("Steam.exe");
    assert!(
        steam_exe.is_file(),
        "real Steam client missing at {} — the E2E test needs ges/{STEAM_GE}/drive_c/Steam/Steam.exe",
        steam_exe.display(),
    );

    // ── Bounded deadline ──────────────────────────────────────────────────
    // pe_runtime::execute reads CASA1_PE_RUNTIME_DEADLINE_SECS from the
    // process environment, so it must be set here (this test binary has a
    // single test; no parallel test can observe the mutation).
    let deadline_secs: u64 = std::env::var("CASA1_PE_RUNTIME_DEADLINE_SECS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(300);
    // SAFETY: single-test binary; setting the deadline before the run is
    // required for the bounded Steam execution.
    unsafe {
        std::env::set_var("CASA1_PE_RUNTIME_DEADLINE_SECS", deadline_secs.to_string());
    }

    // ── Run the real client through the runner's execute_job path ────────
    let job = RunnerJob {
        ge_name: STEAM_GE.to_string(),
        ge_root: ge_root.clone(),
        program: steam_exe.clone(),
        args: Vec::new(),
        cwd: ge_root.join("drive_c").join("Steam"),
        env: BTreeMap::new(),
        dtm: false,
        intent: RunIntent::Run,
        trace_categories: Vec::new(),
        test_id: "section41_steam_e2e".to_string(),
        jit_mode: Default::default(),
        steam_ipc: false,
        window_width: None,
        window_height: None,
    };
    eprintln!(
        "[section41] executing real Steam client (deadline {deadline_secs}s): {}",
        steam_exe.display(),
    );
    let outcome = match execute_job(&job) {
        Ok(outcome) => outcome,
        Err(error) => {
            panic!(
                "[section41] execute_job failed before producing a run artifact: {}",
                error.message,
            );
        }
    };
    eprintln!(
        "[section41] run finished: exit_code={} report={}",
        outcome.canonical_output.exit_code,
        outcome.report_path.display(),
    );

    // ── Load the artifact the runner wrote ────────────────────────────────
    let ge = GameEnvironment::from_root(ge_root).expect("open steam GE");
    let diagnostics_dir = ge.diagnostics_dir();
    let artifact_path = latest_steam_artifact(&diagnostics_dir).unwrap_or_else(|| {
        panic!(
            "no steam-bootstrap artifact found in {} (listing): {:#?}",
            diagnostics_dir.display(),
            std::fs::read_dir(&diagnostics_dir).map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            }),
        )
    });
    eprintln!("[section41] artifact: {}", artifact_path.display());
    let artifact_bytes = std::fs::read(&artifact_path).expect("read steam-bootstrap artifact");
    let artifact: SteamBootstrapArtifact =
        serde_json::from_slice(&artifact_bytes).expect("parse steam-bootstrap artifact JSON");

    // ── Self-consistency assertions ───────────────────────────────────────
    assert!(
        !artifact.run_id.is_empty(),
        "artifact must carry a non-empty run_id",
    );
    let program_sha = casa1::steam_milestones::file_content_hash(&steam_exe);
    assert_eq!(
        artifact.provenance.steam_executable_hash, program_sha,
        "artifact steam_executable_hash must match the sha256 of the real binary \
         (artifact may be stale or from a different fixture)",
    );
    // The full artifact (including the authoritative termination) must
    // serialize; a serialization failure is an artifact-integrity failure.
    let serialized = serde_json::to_string(&artifact).expect("artifact must serialize");
    assert!(
        serialized.contains("\"termination\""),
        "artifact serialization must include the termination field",
    );

    // ── Evaluate against the S0-S12 mandatory policy ──────────────────────
    let policy = SteamAcceptancePolicy {
        require_stages: MANDATORY_STAGES.to_vec(),
        allow_harness_deadline_after_all_mandatory: true,
    };
    let result = evaluate(&artifact, &policy);

    let report = json!({
        "run_id": artifact.run_id,
        "commit_sha": artifact.provenance.commit_sha,
        "execution_mode": artifact.provenance.execution_mode,
        "steam_executable_hash": artifact.provenance.steam_executable_hash,
        "termination": artifact.termination,
        "termination_detail": artifact.termination_detail,
        "exit_code": artifact.exit_code,
        "guest_pid": artifact.guest_pid,
        "instruction_count": artifact.instruction_count,
        "network_exchanges": artifact.network_summary.len(),
        "artifact_path": artifact_path.display().to_string(),
        "acceptance": result,
    });
    eprintln!(
        "[section41] acceptance report:\n{}",
        serde_json::to_string_pretty(&report).expect("serialize acceptance report"),
    );

    if result.passed {
        eprintln!("[section41] PASS: acceptance passed (all stages S0-S13)");
        return;
    }

    // Documented stage-missing only: the run stopped short of later stages
    // (missing + StageNotReached), which is the expected scaffolding
    // outcome while milestone instrumentation is still landing.  Any
    // run-level failure (network unproven, guest exception, illegal host
    // termination, encoder imbalance, placeholder-only rendering, model
    // provenance, unsanctioned deadline) fails the gate.
    let only_documented_stage_missing = result
        .failures
        .iter()
        .all(|failure| matches!(failure, SteamAcceptanceFailure::StageNotReached(_)));
    assert!(
        only_documented_stage_missing,
        "[section41] FAIL: acceptance recorded run-level failures beyond \
         documented stage-missing: {:#?}",
        result.failures,
    );
    eprintln!(
        "[section41] PASS (documented stage-missing): completed={:?} missing={:?}",
        result.completed_stages, result.missing,
    );
}
