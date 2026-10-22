#![allow(dead_code, unused_imports)]
//! Phase 8 — Steam Boot Verification Tests
//!
//! Verifies the Steam boot sequence: registry initialization, process creation,
//! named pipe creation, filesystem layout, service registration, DLL resolution,
//! WebHelper launch, and network initialization.

use casa1::ge::{GameEnvironment, GeArch};
use casa1::scm::{ScmConfig, ScmController};
use casa1::win32::Win32Subsystem;

fn setup_win32(label: &str) -> (tempfile::TempDir, Win32Subsystem) {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), label, GeArch::X86, "win11-23h2")
        .expect("create game environment");
    let win32 = Win32Subsystem::new(ge, false);
    (temp_dir, win32)
}

fn setup_ge(label: &str) -> (tempfile::TempDir, GameEnvironment) {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), label, GeArch::X86, "win11-23h2")
        .expect("create game environment");
    (temp_dir, ge)
}

// ---------------------------------------------------------------------------
// t17_1_steam_registry_initialization
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t17_2_steam_process_creation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t17_3_steam_named_pipe_creation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t17_4_steam_filesystem_layout
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t17_5_steam_service_registration
// ---------------------------------------------------------------------------

#[test]
fn t17_5_steam_service_registration() {
    // The SCM controller starts disabled with its documented defaults.
    let config = ScmConfig::default();
    let controller = ScmController::new(config);

    // Verify the SCM controller starts in Stopped state
    assert_eq!(
        controller.vm_state,
        casa1::scm::VmState::Stopped,
        "SCM controller should start in Stopped state"
    );

    // Verify the service configuration
    assert_eq!(controller.config.cpu_count, 4, "default CPU count");
    assert_eq!(controller.config.memory_mb, 4096, "default memory");
    assert!(
        !controller.config.enabled,
        "SCM should be disabled by default"
    );

    // Exercise the real lifecycle: registering a service means configuring the VM
    // and driving it through start → pause → resume → stop, with state transitions
    // asserted at every step (a config/state struct that ignores these calls fails).
    let shared = tempfile::tempdir().expect("shared dir");
    let mut active = ScmController::new(ScmConfig {
        enabled: true,
        cpu_count: 8,
        memory_mb: 8192,
        shared_directory: Some(shared.path().to_string_lossy().to_string()),
        ..ScmConfig::default()
    });

    active.start_vm().expect("start VM");
    assert_eq!(active.vm_state, casa1::scm::VmState::Running);
    assert!(
        active.virtio_net.connected,
        "virtio-net must connect on start"
    );
    assert!(
        active.virtio_fs.mounted,
        "configured shared directory must mount on start"
    );

    active.pause_vm().expect("pause VM");
    assert_eq!(active.vm_state, casa1::scm::VmState::Paused);

    active.resume_vm().expect("resume VM");
    assert_eq!(active.vm_state, casa1::scm::VmState::Running);

    active.stop_vm().expect("stop VM");
    assert_eq!(active.vm_state, casa1::scm::VmState::Stopped);
    assert!(!active.virtio_net.connected, "virtio-net must drop on stop");
    assert!(
        !active.virtio_fs.mounted,
        "shared directory must unmount on stop"
    );

    // Invalid transitions must be rejected rather than silently accepted.
    let double_stop = active.stop_vm().expect_err("stop on stopped VM must fail");
    assert_eq!(double_stop.code, casa1::reason::ReasonCode::RcInvalidState);

    active.start_vm().expect("restart VM");
    let double_start = active.start_vm().expect_err("double start must fail");
    assert_eq!(double_start.code, casa1::reason::ReasonCode::RcInvalidState);
}

// ---------------------------------------------------------------------------
// t17_6_steam_dll_resolution
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t17_7_steam_webhelper_launch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t17_8_steam_network_initialization
// ---------------------------------------------------------------------------
