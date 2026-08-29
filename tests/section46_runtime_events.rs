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
use casa1::pe_runtime::{thunk_drive_manifest_gate_with_observers, thunk_drive_unknown_thunk};
use casa1::runtime_events::{RuntimeEvent, RuntimeObserver};
use casa1::workloads::steam::SteamMilestoneObserver;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// Serializes the thunk-driven tests: they share the checked-in GE (ge.json
/// is rewritten by fs_state syncs), and the Steam observer writes through to
/// the process-wide milestone static, so a concurrent test could observe
/// another test's mid-cycle state.
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

/// Restores the checked-in GE when a thunk-driven test finishes (success or
/// panic): recreates the tracked `C:\.crash` target if the probe deleted it
/// and rewrites ge.json from its start-of-test bytes when the win32 fs_state
/// syncs changed it (same contract as the section-38 gate cleanup).
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

/// Snapshots the checked-in GE and holds the serialization guard until the
/// test finishes (returned FIRST so it drops LAST).
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

/// Test observer that records every received event into a shared buffer the
/// test can inspect after the runtime consumed the observer.
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

#[test]
fn runtime_emits_file_opened_on_create_file_w() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
    let _cleanup = gate_setup();
    let events = Arc::new(Mutex::new(Vec::<RuntimeEvent>::new()));
    let observer = Box::new(RecordingObserver::new(Arc::clone(&events)));

    let result = thunk_drive_manifest_gate_with_observers(open_gate_ge(), vec![observer])
        .expect("manifest gate through the thunk layer");

    assert!(
        result.manifest_open_ok,
        "CreateFileW must open the manifest"
    );
    assert!(result.manifest_read_ok, "ReadFile must succeed");
    let received = events.lock().unwrap();
    let file_opened = received
        .iter()
        .find(|event| matches!(event, RuntimeEvent::FileOpened { .. }));
    assert!(
        file_opened.is_some(),
        "an observer attached to the runtime must receive FileOpened, got: {received:?}"
    );
    assert!(
        received.iter().any(|event| matches!(
            event,
            RuntimeEvent::FileOpened { path, .. } if path == r"C:\package\steam_client_win32.installed"
        )),
        "the manifest open must be reported with its normalized path, got: {received:?}"
    );
    assert!(
        received
            .iter()
            .any(|event| matches!(event, RuntimeEvent::FileRead { path, .. } if path == r"C:\package\steam_client_win32.installed")),
        "the manifest read must be reported as FileRead, got: {received:?}"
    );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ---------------------------------------------------------------------------
// (b) The runtime works with NO observer (the default path)
// ---------------------------------------------------------------------------

#[test]
fn runtime_works_with_no_observer() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let _cleanup = gate_setup();
            // No observers attached — the default.  The gate must run perfectly and
            // produce a usable result; without an observer NOTHING is recorded into
            // the milestone state (the runtime never records Steam milestones on its
            // own).
            let result = thunk_drive_manifest_gate_with_observers(open_gate_ge(), Vec::new())
                .expect("manifest gate must run with no observer attached");
            assert!(result.manifest_open_ok, "CreateFileW must still succeed");
            assert!(result.manifest_read_ok, "ReadFile must still succeed");
            assert!(
                result.milestones.steam.manifest_opened.is_none(),
                "no observer attached → no milestone inference may leak into the result"
            );
            assert!(
                result.milestones.steam.manifest_full_read.is_none(),
                "no observer attached → no milestone inference may leak into the result"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ---------------------------------------------------------------------------
// (c) SteamMilestoneObserver infers manifest milestones from generic events
// ---------------------------------------------------------------------------

#[test]
fn steam_observer_infers_manifest_milestones_from_generic_events() {
    let _serial = gate_serial();
    let mut observer = SteamMilestoneObserver::default();
    let manifest = r"C:\package\steam_client_win32.installed";

    // A non-manifest open changes nothing.
    observer.on_event(&RuntimeEvent::FileOpened {
        path: r"C:\Windows\system32\kernel32.dll".to_string(),
        desired_access: 0x8000_0000,
        share_mode: 7,
        disposition: 3,
    });
    assert!(observer.snapshot().steam.manifest_opened.is_none());
    assert!(observer.snapshot().steam.manifest_full_read.is_none());

    // Opening the manifest sets manifest_opened only.
    observer.on_event(&RuntimeEvent::FileOpened {
        path: manifest.to_string(),
        desired_access: 0x8000_0000,
        share_mode: 7,
        disposition: 3,
    });
    let milestones = observer.snapshot();
    assert!(
        milestones.steam.manifest_opened.is_some(),
        "FileOpened on the manifest path must set manifest_opened"
    );
    assert!(
        milestones.steam.manifest_full_read.is_none(),
        "an open alone must not prove a full read"
    );

    // A full read of the manifest proves open AND readable.
    observer.on_event(&RuntimeEvent::FileRead {
        path: manifest.to_string(),
        bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
    });
    let milestones = observer.snapshot();
    assert!(
        milestones.steam.manifest_full_read.is_some(),
        "FileRead on the manifest path must set manifest_full_read"
    );
    assert!(
        milestones.steam.manifest_opened.is_some(),
        "the full read proves the manifest was opened too"
    );

    // The observer also infers the webhelper spawn milestone from the
    // generic process events.
    observer.on_event(&RuntimeEvent::ProcessSpawnRequested {
        image: "steamwebhelper.exe".to_string(),
        command_line: r"C:\Program Files (x86)\Steam\steamwebhelper.exe -nocrashdialog".to_string(),
        parent_pid: 42,
    });
    let milestones = observer.snapshot();
    assert_eq!(milestones.steam.webhelper_spawn_requests, 1);
    assert!(milestones.steam.webhelper_spawn_requested.is_some());
    observer.on_event(&RuntimeEvent::ProcessSpawnRequested {
        image: "notepad.exe".to_string(),
        command_line: "notepad.exe".to_string(),
        parent_pid: 42,
    });
    assert_eq!(
        observer.snapshot().steam.webhelper_spawn_requests,
        1,
        "non-webhelper spawns must not count"
    );

    // Presentation: a DXGI present is inferred from FramePresented.
    observer.on_event(&RuntimeEvent::FramePresented {
        producer: "dxgi".to_string(),
        width: 1920,
        height: 1080,
        sequence: 1,
    });
    let milestones = observer.snapshot();
    assert!(milestones.steam.first_dxgi_present.is_some());
}

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
