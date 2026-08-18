//! Phase 1 — Steam first-divergence diagnostic (real Steam, S0-S13 ladder).
//!
//! Runs the REAL Steam client from `ges/steam/drive_c/Steam/Steam.exe`
//! through the runner's `execute_job` path, stops on the configured
//! wall-clock deadline (`CASA1_PE_RUNTIME_DEADLINE_SECS`, default 300 s),
//! reads the steam-bootstrap artifact the runner writes, and prints the
//! first-divergence report:
//!
//! - last successful milestone (highest completed acceptance stage),
//! - first failure by subsystem (fs / crt / thread / network / cef / gfx),
//! - last dispatched guest thunk,
//! - guest PC / TID / PID at divergence,
//! - next missing mandatory milestone (first S0-S12 stage not completed).
//!
//! No fixed-RVA assumptions: the diagnostic reads only the artifact's
//! evidence fields (milestones, first-failure records, last thunk,
//! guest pid) and the acceptance evaluator's stage ladder.
//!
//! Gated twice: `#[ignore]` keeps it out of the default suite, and the
//! `CASA1_STEAM_E2E=1` environment gate skips it (with a message) even
//! when `--ignored` forces the run.
//!
//! Usage:
//! ```bash
//! CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \
//!   cargo test --release --test section23 -- --ignored --nocapture
//! ```

use casa1::ge::GameEnvironment;
use casa1::runner::{RunIntent, RunnerJob, SteamBootstrapArtifact, execute_job};
use casa1::steam_acceptance::{MANDATORY_STAGES, Stage, SteamAcceptancePolicy, evaluate};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The Steam GE whose `drive_c/Steam/Steam.exe` is the real client — the
/// same fixture the section41 acceptance test runs.
const STEAM_GE: &str = "steam";

/// The E2E gate: `CASA1_STEAM_E2E=1` is required even with `--ignored`.
fn steam_e2e_gate() -> bool {
    if std::env::var("CASA1_STEAM_E2E").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: CASA1_STEAM_E2E is not set to 1.\n\
             This diagnostic runs the REAL Steam client under the Casa1 PE\n\
             runtime and needs the live E2E environment. Re-run with:\n\
             \n\
             CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \\\n\
               cargo test --release --test section23 -- --ignored --nocapture"
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
fn t23_steam_first_divergence() {
    if !steam_e2e_gate() {
        return;
    }

    // ── Resolve the real client ──────────────────────────────────────────
    let ge_root = steam_ge_root();
    let steam_exe = ge_root.join("drive_c").join("Steam").join("Steam.exe");
    assert!(
        steam_exe.is_file(),
        "real Steam client missing at {} — the diagnostic needs ges/{STEAM_GE}/drive_c/Steam/Steam.exe",
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
        test_id: "section23_first_divergence".to_string(),
    };
    eprintln!(
        "[section23] executing real Steam client (deadline {deadline_secs}s): {}",
        steam_exe.display(),
    );
    match execute_job(&job) {
        Ok(outcome) => eprintln!(
            "[section23] run finished: exit_code={}",
            outcome.canonical_output.exit_code,
        ),
        Err(error) => {
            eprintln!(
                "[section23] execute_job failed before producing a run artifact: {}",
                error.message,
            );
        }
    }

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
    let artifact_bytes = std::fs::read(&artifact_path).expect("read steam-bootstrap artifact");
    let artifact: SteamBootstrapArtifact =
        serde_json::from_slice(&artifact_bytes).expect("parse steam-bootstrap artifact JSON");

    // ── First-divergence report ───────────────────────────────────────────
    eprintln!("=== Steam first-divergence report ===");
    eprintln!("artifact: {}", artifact_path.display());
    eprintln!("run_id: {}", artifact.run_id);
    eprintln!(
        "termination: {:?} (exit_code {})",
        artifact.termination, artifact.exit_code
    );

    // Last successful milestone: highest completed acceptance stage.
    let policy = SteamAcceptancePolicy {
        require_stages: MANDATORY_STAGES.to_vec(),
        allow_harness_deadline_after_all_mandatory: true,
    };
    let result = evaluate(&artifact, &policy);
    let last_successful = result.completed_stages.last().copied();
    eprintln!(
        "last successful milestone: {}",
        last_successful
            .map(|stage| stage.as_str().to_string())
            .unwrap_or_else(|| "none (S0 not reached)".to_string()),
    );

    // Next missing mandatory milestone (first S0-S12 stage not completed).
    let next_missing = Stage::ALL
        .iter()
        .copied()
        .find(|stage| *stage != Stage::S13 && !result.completed_stages.contains(stage));
    eprintln!(
        "next missing mandatory milestone: {}",
        next_missing
            .map(|stage| stage.as_str().to_string())
            .unwrap_or_else(|| "none (all S0-S12 completed)".to_string()),
    );

    // First failure by subsystem.
    let failures = &artifact.milestones.first_failures;
    eprintln!("first failure by subsystem:");
    for (name, failure) in [
        ("fs", &failures.fs),
        ("crt", &failures.crt),
        ("thread", &failures.thread),
        ("network", &failures.network),
        ("cef", &failures.cef),
        ("gfx", &failures.gfx),
    ] {
        match failure {
            Some(failure) => {
                let api = failure.api.as_deref().unwrap_or("<none>");
                let guest_error = failure
                    .guest_error
                    .map(|code| format!("{code:#x}"))
                    .unwrap_or_else(|| "<none>".to_string());
                eprintln!(
                    "  {name}: guest_pc={:#x} thread_id={} api={api} guest_error={guest_error} detail={}",
                    failure.guest_pc, failure.thread_id, failure.detail,
                );
            }
            None => eprintln!("  {name}: none"),
        }
    }

    // Last thunk + guest PC/TID/PID.
    match &artifact.last_thunk {
        Some(last) => eprintln!(
            "last thunk: {} at guest_pc={:#x} after {}s of wall time",
            last.name, last.guest_pc, last.wall_secs_since_start,
        ),
        None => eprintln!("last thunk: none recorded"),
    }
    let first_failure_tid = [
        failures.fs.as_ref(),
        failures.crt.as_ref(),
        failures.thread.as_ref(),
        failures.network.as_ref(),
        failures.cef.as_ref(),
        failures.gfx.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|failure| failure.thread_id)
    .next();
    eprintln!(
        "guest pc: {}",
        artifact
            .last_thunk
            .as_ref()
            .map(|last| format!("{:#x}", last.guest_pc))
            .unwrap_or_else(|| "unknown".to_string()),
    );
    eprintln!(
        "guest tid: {}",
        first_failure_tid
            .map(|tid| tid.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    );
    eprintln!("guest pid: {}", artifact.guest_pid);

    // Summary line in the acceptance ladder's own terms.
    eprintln!(
        "stages: completed={:?} missing={:?} failures={:?}",
        result.completed_stages, result.missing, result.failures,
    );
    eprintln!("=== end of first-divergence report ===");
}
