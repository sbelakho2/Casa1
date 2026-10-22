#![allow(dead_code, unused_imports)]
//! Phase 3 integration tests: WebSocket (P3.2), NTFS ADS (P3.3),
//! Registry Change Notifications (P3.4), XAPO Audio Effects (P3.5),
//! Named Pipes (P3.6), InstallShield (P3.7).

use casa1::ge::{GameEnvironment, GeArch};
use casa1::installer::{ISSetupDllStub, InstallShieldEngine};
use casa1::real_audio::{VoiceEffectChain, XapoManager};
use casa1::real_fs::{
    RealFilesystem, WindowsPathResolver, ads_sidecar_to_stream, backup_read_file,
};
use casa1::real_win32::RegistryChangeTracker;
use casa1::win32::{PIPE_ACCESS_DUPLEX, PIPE_WAIT, Win32Subsystem};
use casa1::winhttp::{WinHttpStack, WinHttpWebSocketBufferType, WinHttpWebSocketCloseStatus};
use tempfile::TempDir;

fn setup_win32(label: &str) -> (TempDir, Win32Subsystem) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), label, GeArch::X64, "win11-23h2")
        .expect("create game environment");
    let win32 = Win32Subsystem::new(ge, false);
    (temp_dir, win32)
}

// ===========================================================================
// P3.2 — WebSocket Support (F-17)
// ===========================================================================

#[test]
fn t34_websocket_send_and_close() {
    let mut stack = WinHttpStack::new();
    let session = stack.win_http_open(Some("Test"), 0, None, None);
    let conn = stack
        .win_http_connect(session, "example.com", 80, false)
        .expect("connect");
    let req = stack
        .win_http_open_request(conn, "GET", "/ws", None)
        .expect("open request");
    stack.win_http_send_request(req, None, None).expect("send");
    stack.win_http_receive_response(req).expect("receive");

    let ws = stack.websocket_complete_upgrade(req).expect("upgrade");

    // Send binary data
    stack
        .websocket_send(
            ws,
            WinHttpWebSocketBufferType::BinaryMessageBuffer,
            b"hello",
        )
        .expect("send");

    // Send text data
    stack
        .websocket_send(ws, WinHttpWebSocketBufferType::Utf8MessageBuffer, b"world")
        .expect("send text");

    // Close
    stack
        .websocket_close(ws, WinHttpWebSocketCloseStatus::Success, Some("done"))
        .expect("close");

    // Verify can't send after close
    assert!(
        stack
            .websocket_send(ws, WinHttpWebSocketBufferType::BinaryMessageBuffer, b"fail")
            .is_err()
    );
}

#[test]
fn t34_websocket_close_handle_cleans_up() {
    let mut stack = WinHttpStack::new();
    let session = stack.win_http_open(Some("Test"), 0, None, None);
    let conn = stack
        .win_http_connect(session, "example.com", 80, false)
        .expect("connect");
    let req = stack
        .win_http_open_request(conn, "GET", "/ws", None)
        .expect("open request");
    stack.win_http_send_request(req, None, None).expect("send");
    stack.win_http_receive_response(req).expect("receive");

    let ws = stack.websocket_complete_upgrade(req).expect("upgrade");

    // Close the handle
    let _result = stack.win_http_close_handle(ws);
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");

    // Double close should fail
    let _result = stack.win_http_close_handle(ws);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
}

// ===========================================================================
// P3.3 — NTFS Alternate Data Streams (F-18)
// ===========================================================================

#[test]
fn t34_ntfs_sidecar_to_stream_invalid_returns_none() {
    let p = std::path::Path::new("random_file.txt");
    assert!(ads_sidecar_to_stream(p).is_none());
}

#[test]
fn t34_ntfs_backup_read_write() {
    let tmp = TempDir::new().unwrap();
    let resolver = WindowsPathResolver::new(tmp.path());
    let rfs = RealFilesystem::new(resolver);
    rfs.initialize().unwrap();

    // Write a file
    let mut file = rfs
        .open_file("C:\\test_backup.txt", false, true, true, false)
        .unwrap();
    file.write(b"main data").unwrap();
    file.flush().unwrap();
    drop(file);

    // Backup read
    let result = backup_read_file(&rfs, "C:\\test_backup.txt").unwrap();
    assert!(result.main_stream().is_some());
    assert_eq!(result.main_stream().unwrap().data, b"main data");

    // Write an ADS
    rfs.write_alternate_stream("C:\\test_backup.txt", "Zone.Identifier", b"[ZoneTransfer]")
        .unwrap();

    // Backup read again - should include ADS
    let result2 = backup_read_file(&rfs, "C:\\test_backup.txt").unwrap();
    assert!(result2.main_stream().is_some());
    let ads = result2.alternate_streams();
    assert!(!ads.is_empty());
}

// ===========================================================================
// P3.4 — Registry Change Notifications (F-20)
// ===========================================================================

#[test]
fn t34_registry_change_tracker_has_changed() {
    let mut tracker = RegistryChangeTracker::new();
    assert!(!tracker.has_changed("HKLM\\Software\\MyApp", 0, false));

    tracker.notify_change("HKLM\\Software\\MyApp");
    assert!(tracker.has_changed("HKLM\\Software\\MyApp", 0, false));
    assert!(!tracker.has_changed("HKLM\\Software\\MyApp", 1, false));
}

#[test]
fn t34_registry_change_tracker_subtree() {
    let mut tracker = RegistryChangeTracker::new();
    tracker.notify_change("HKLM\\Software\\MyApp\\SubKey");

    // Not changed at parent level without subtree
    assert!(!tracker.has_changed("HKLM\\Software\\MyApp", 0, false));
    // Changed when watching subtree
    assert!(tracker.has_changed("HKLM\\Software\\MyApp", 0, true));
}

// ===========================================================================
// P3.5 — XAPO Audio Effects (F-21)
// ===========================================================================

#[test]
fn t34_xapo_voice_effect_chain() {
    let mut mgr = XapoManager::new();
    mgr.register_builtins();

    let voice_id = 1u64;
    let mut vec = VoiceEffectChain::new(voice_id);
    assert_eq!(vec.voice_id(), 1);
    assert!(vec.is_enabled());

    vec.set_enabled(false);
    assert!(!vec.is_enabled());

    // Add an effect to the chain
    let eq_clsid = [
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07,
    ];
    let eq_id = mgr.create_instance(&eq_clsid).expect("create eq");
    vec.chain_mut().push(eq_id);
    assert_eq!(vec.chain().len(), 1);
}

// ===========================================================================
// P3.6 — Named Pipes (F-22)
// ===========================================================================

#[test]
fn t34_named_pipe_duplicate_creation_fails() {
    let (_tmp, mut win32) = setup_win32("dup-pipe");
    let _h1 = win32
        .create_named_pipe_w(
            "\\\\.\\pipe\\DupTest",
            PIPE_ACCESS_DUPLEX,
            PIPE_WAIT,
            1,
            4096,
            4096,
            5000,
            false,
            None,
            None,
        )
        .expect("create first");

    let result = win32.create_named_pipe_w(
        "\\\\.\\pipe\\DupTest",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        false,
        None,
        None,
    );
    assert!(result.is_err(), "expected Err, got {result:?}");
}

// ===========================================================================
// P3.7 — InstallShield Installer (F-23)
// ===========================================================================

#[test]
fn t34_issetup_dll_stub_handles_calls() {
    let mut stub = ISSetupDllStub::new();
    assert_eq!(stub.call_count(), 0);

    assert!(stub.handle_call("OnBegin"));
    assert!(stub.handle_call("OnMoving"));
    assert!(stub.handle_call("OnMoved"));
    assert!(stub.handle_call("OnEnd"));

    assert_eq!(stub.call_count(), 4);
    assert!(stub.was_called("OnBegin"));
    assert!(stub.was_called("OnEnd"));
    assert!(!stub.was_called("OnUnknown"));
}

#[test]
fn t34_installshield_detect_invalid_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("not_installer.exe");
    std::fs::write(&path, b"This is not an installer").unwrap();
    assert!(!InstallShieldEngine::detect(&path));
}
