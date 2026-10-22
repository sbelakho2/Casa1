#![allow(dead_code, unused_imports)]
//! Steam first-divergence diagnostic (artifact-driven).
//!
//! Runs the real Steam.exe through the runner's `execute_job` path with a
//! configured wall-clock deadline, then reads the authoritative
//! steam-bootstrap artifact and prints:
//!
//! - the last successfully observed milestone;
//! - the next missing mandatory stage (S0-S13 from `steam_acceptance`);
//! - the first failure per subsystem (fs/crt/thread/network/cef/gfx);
//! - the last dispatched thunk with guest PC / thread / wall time;
//! - the structured termination and JIT state.
//!
//! No fixed Steam version-specific crash RVA is assumed: this is a pure
//! first-divergence locator driven by the run artifact.
//!
//! Usage:
//!   CASA1_STEAM_E2E=1 cargo test --test section23 -- --ignored --nocapture

const STEAM_GE: &str = "steam";

fn last_observed_milestone(artifact: &casa1::runner::SteamBootstrapArtifact) -> String {
    let steam = &artifact.milestones.steam;
    let candidates = [
        ("bootstrap_started", &steam.bootstrap_started),
        ("manifest_opened", &steam.manifest_opened),
        ("manifest_full_read", &steam.manifest_full_read),
        (
            "package_writability_probe",
            &steam.package_writability_probe,
        ),
        ("client_main_started", &steam.client_main_started),
        (
            "webhelper_spawn_requested",
            &steam.webhelper_spawn_requested,
        ),
        (
            "webhelper_process_started",
            &steam.webhelper_process_started,
        ),
        ("cef_browser_created", &steam.cef_browser_created),
        ("cef_first_paint", &steam.cef_first_paint),
    ];
    for (name, evidence) in candidates.iter().rev() {
        if evidence.is_some() {
            return name.to_string();
        }
    }
    "none".to_string()
}
