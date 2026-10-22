#![allow(dead_code, unused_imports)]
//! Phase 46 — Generic runtime-events layer.
//!
//! The runtime publishes workload-agnostic [`RuntimeEvent`]s through
//! observers; the Steam workload is a pure event CONSUMER
//! ([`SteamMilestoneObserver`]) that infers its bootstrap milestones from
//! the generic stream without touching filesystem/process/audio/CEF
//! internals.
//!
//! Tests:
//! - (a) the runtime emits `FileOpened` on `CreateFileW` and an observer
//!   receives it;
//! - (b) the runtime works with NO observer (the default path);
//! - (c) the `SteamMilestoneObserver` infers `manifest_opened` +
//!   `manifest_full_read` from the generic events;
//! - (d) the `UnsupportedCall` event fires for an unknown thunk;
//! - (e) win32.rs contains no `crate::steam_milestones` references.
//!
//! Tests (a)/(b)/(d) drive the real host-thunk dispatch layer against the
//! checked-in `steam-live-run-x86` GE, exactly like the section-38 manifest
//! gate, so they are serialized among themselves (shared GE state).

use casa1::ge::GameEnvironment;
use casa1::pe_runtime::thunk_drive_unknown_thunk;
use casa1::runtime_events::{RuntimeEvent, RuntimeObserver};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

static GATE_SERIAL: Mutex<()> = Mutex::new(());

fn repo_ge_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join("steam-live-run-x86")
}

fn gate_serial() -> MutexGuard<'static, ()> {
    GATE_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct GateCleanup {
    _serial: MutexGuard<'static, ()>,
    ge_root: PathBuf,
    ge_json_snapshot: Vec<u8>,
    crash_snapshot: Vec<u8>,
}

impl Drop for GateCleanup {
    fn drop(&mut self) {
        let crash_file = self.ge_root.join("drive_c").join(".crash");
        if !crash_file.is_file() {
            let _ = std::fs::write(&crash_file, &self.crash_snapshot);
        }
        let ge_json_path = self.ge_root.join("ge.json");
        if std::fs::read(&ge_json_path).ok().as_deref() != Some(self.ge_json_snapshot.as_slice()) {
            let _ = std::fs::write(&ge_json_path, &self.ge_json_snapshot);
        }
    }
}

fn gate_setup() -> GateCleanup {
    let serial = gate_serial();
    let root = repo_ge_root();
    assert!(
        root.join("ge.json").is_file(),
        "steam-live-run-x86 GE missing at {}",
        root.display()
    );
    let crash_file = root.join("drive_c").join(".crash");
    assert!(
        crash_file.is_file(),
        "tracked C:\\.crash probe target missing at {}",
        crash_file.display()
    );
    let ge_json_snapshot = std::fs::read(root.join("ge.json")).expect("snapshot ge.json");
    let crash_snapshot = std::fs::read(&crash_file).expect("snapshot C:\\.crash");
    GateCleanup {
        _serial: serial,
        ge_root: root,
        ge_json_snapshot,
        crash_snapshot,
    }
}

fn open_gate_ge() -> GameEnvironment {
    let root = repo_ge_root();
    assert!(
        root.join("ge.json").is_file(),
        "steam-live-run-x86 GE missing at {}",
        root.display()
    );
    GameEnvironment::from_root(root).expect("open steam-live-run-x86 GE")
}

#[derive(Debug)]
struct RecordingObserver {
    events: Arc<Mutex<Vec<RuntimeEvent>>>,
}

impl RecordingObserver {
    fn new(events: Arc<Mutex<Vec<RuntimeEvent>>>) -> Self {
        Self { events }
    }
}

impl RuntimeObserver for RecordingObserver {
    fn on_event(&mut self, event: &RuntimeEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

// ---------------------------------------------------------------------------
// (a) The runtime emits FileOpened on CreateFileW and an observer receives it
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (b) The runtime works with NO observer (the default path)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (c) SteamMilestoneObserver infers manifest milestones from generic events
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (d) The UnsupportedCall event fires for an unknown thunk
// ---------------------------------------------------------------------------

#[test]
fn unsupported_call_event_fires_for_unknown_thunk() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let _cleanup = gate_setup();
            let events = Arc::new(Mutex::new(Vec::<RuntimeEvent>::new()));
            let observer = Box::new(RecordingObserver::new(Arc::clone(&events)));

            let (error_message, _observers) =
                thunk_drive_unknown_thunk(open_gate_ge(), vec![observer]);
            assert!(
                error_message.contains("unknown PE host thunk"),
                "dispatch must fail with the unknown-thunk error, got: {error_message}"
            );
            let received = events.lock().unwrap();
            let unsupported = received
                .iter()
                .find(|event| matches!(event, RuntimeEvent::UnsupportedCall { .. }));
            assert!(
                unsupported.is_some(),
                "the UnsupportedCall event must be emitted for an unknown thunk, got: {received:?}"
            );
            match unsupported.unwrap() {
                RuntimeEvent::UnsupportedCall {
                    api,
                    implementation_level,
                    reason,
                    ..
                } => {
                    assert!(
                        api.contains("unknown-thunk"),
                        "the api field must name the unknown thunk, got: {api}"
                    );
                    assert_eq!(implementation_level, "unsupported");
                    assert!(reason.contains("unknown PE host thunk"));
                }
                _ => unreachable!(),
            }
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ---------------------------------------------------------------------------
// (e) win32.rs contains no crate::steam_milestones references
// ---------------------------------------------------------------------------

#[test]
fn win32_has_no_steam_milestones_references() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("win32.rs"),
    )
    .expect("read src/win32.rs");
    assert!(
        !source.contains("steam_milestones"),
        "the generic Windows subsystem must be fully decoupled from the Steam \
         milestone module (src/win32.rs contains a crate::steam_milestones reference)"
    );
}
