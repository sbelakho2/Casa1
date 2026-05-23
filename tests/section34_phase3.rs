//! Phase 3 integration tests: WebSocket (P3.2), NTFS ADS (P3.3),
//! Registry Change Notifications (P3.4), XAPO Audio Effects (P3.5),
//! Named Pipes (P3.6), InstallShield (P3.7).

use casa1::winhttp::{
    WinHttpStack, WinHttpWebSocketBufferType, WinHttpWebSocketCloseStatus,
};
use casa1::real_fs::{
    parse_ntfs_path, ads_sidecar_path_for, ads_sidecar_to_stream,
    backup_read_file, backup_write_file,
    ADS_STREAM_TYPE_DATA,
    RealFilesystem, WindowsPathResolver,
};
use casa1::real_win32::{
    RegistryChangeTracker, RegNotifyResult,
    REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_ATTRIBUTES,
    REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_SECURITY,
    reg_notify_change_key_value,
};
use casa1::real_audio::{
    XapoManager, XapoEqualizer, XapoEffect, XapoEffectChain, VoiceEffectChain,
    EqualizerParameters, ReverbParameters, CompressorParameters, EchoParameters,
    XAPO_FLAG_INPLACE,
};
use casa1::win32::{
    pipe_name_to_uds_path, PIPE_SOCKET_BASE_DIR,
    PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
    PIPE_WAIT, PIPE_NOWAIT, Win32Subsystem,
};
use casa1::ge::{GameEnvironment, GeArch};
use casa1::installer::{
    IssScript, IssCommand, ISSetupDllStub, ISSetupActionType,
    InstallShieldEngine,
};
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper: create a temporary GameEnvironment and Win32Subsystem for named pipe tests.
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
fn t34_websocket_close_status_from_code() {
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1000), WinHttpWebSocketCloseStatus::Success);
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1001), WinHttpWebSocketCloseStatus::EndpointUnavailable);
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1002), WinHttpWebSocketCloseStatus::ProtocolError);
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1003), WinHttpWebSocketCloseStatus::InvalidDataType);
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1008), WinHttpWebSocketCloseStatus::PolicyViolation);
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1009), WinHttpWebSocketCloseStatus::MessageTooBig);
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(1011), WinHttpWebSocketCloseStatus::InternalError);
    // Unknown code defaults to InternalError
    assert_eq!(WinHttpWebSocketCloseStatus::from_code(9999), WinHttpWebSocketCloseStatus::InternalError);
}

#[test]
fn t34_websocket_buffer_types() {
    // Verify all buffer types are usable
    let types = [
        WinHttpWebSocketBufferType::BinaryMessageBuffer,
        WinHttpWebSocketBufferType::BinaryFragmentBuffer,
        WinHttpWebSocketBufferType::Utf8MessageBuffer,
        WinHttpWebSocketBufferType::Utf8FragmentBuffer,
        WinHttpWebSocketBufferType::CloseBuffer,
        WinHttpWebSocketBufferType::PingPongBuffer,
    ];
    assert_eq!(types.len(), 6);
}

#[test]
fn t34_websocket_upgrade_creates_state() {
    let mut stack = WinHttpStack::new();
    let session = stack.win_http_open(Some("Test"), 0, None, None);
    let conn = stack.win_http_connect(session, "example.com", 80, false).expect("connect");
    let req = stack.win_http_open_request(conn, "GET", "/ws", None).expect("open request");

    // Complete the request to get it into Complete state
    stack.win_http_send_request(req, None, None).expect("send");
    stack.win_http_receive_response(req).expect("receive");

    // Now upgrade should work
    let ws_handle = stack.websocket_complete_upgrade(req).expect("upgrade");
    assert!(ws_handle > 0);

    // Verify state
    let ws_state = stack.websocket_query_close_status(ws_handle).expect("query");
    assert_eq!(ws_state.0, WinHttpWebSocketCloseStatus::Success);
}

#[test]
fn t34_websocket_send_and_close() {
    let mut stack = WinHttpStack::new();
    let session = stack.win_http_open(Some("Test"), 0, None, None);
    let conn = stack.win_http_connect(session, "example.com", 80, false).expect("connect");
    let req = stack.win_http_open_request(conn, "GET", "/ws", None).expect("open request");
    stack.win_http_send_request(req, None, None).expect("send");
    stack.win_http_receive_response(req).expect("receive");

    let ws = stack.websocket_complete_upgrade(req).expect("upgrade");

    // Send binary data
    stack.websocket_send(ws, WinHttpWebSocketBufferType::BinaryMessageBuffer, b"hello").expect("send");

    // Send text data
    stack.websocket_send(ws, WinHttpWebSocketBufferType::Utf8MessageBuffer, b"world").expect("send text");

    // Close
    stack.websocket_close(ws, WinHttpWebSocketCloseStatus::Success, Some("done")).expect("close");

    // Verify can't send after close
    assert!(stack.websocket_send(ws, WinHttpWebSocketBufferType::BinaryMessageBuffer, b"fail").is_err());
}

#[test]
fn t34_websocket_close_handle_cleans_up() {
    let mut stack = WinHttpStack::new();
    let session = stack.win_http_open(Some("Test"), 0, None, None);
    let conn = stack.win_http_connect(session, "example.com", 80, false).expect("connect");
    let req = stack.win_http_open_request(conn, "GET", "/ws", None).expect("open request");
    stack.win_http_send_request(req, None, None).expect("send");
    stack.win_http_receive_response(req).expect("receive");

    let ws = stack.websocket_complete_upgrade(req).expect("upgrade");

    // Close the handle
    assert!(stack.win_http_close_handle(ws).is_ok());

    // Double close should fail
    assert!(stack.win_http_close_handle(ws).is_err());
}

// ===========================================================================
// P3.3 — NTFS Alternate Data Streams (F-18)
// ===========================================================================

#[test]
fn t34_ntfs_parse_simple_ads_path() {
    let (file, stream) = parse_ntfs_path("file.exe:Zone.Identifier");
    assert_eq!(file, "file.exe");
    assert!(stream.is_some());
    let s = stream.unwrap();
    assert_eq!(s.stream_name, "Zone.Identifier");
    assert_eq!(s.stream_type, "$DATA");
}

#[test]
fn t34_ntfs_parse_ads_path_with_type() {
    let (file, stream) = parse_ntfs_path("file.exe:Zone.Identifier:$DATA");
    assert_eq!(file, "file.exe");
    let s = stream.unwrap();
    assert_eq!(s.stream_name, "Zone.Identifier");
    assert_eq!(s.stream_type, "$DATA");
}

#[test]
fn t34_ntfs_parse_drive_letter_path() {
    let (file, stream) = parse_ntfs_path("C:\\path\\file.exe");
    assert_eq!(file, "C:\\path\\file.exe");
    assert!(stream.is_none());
}

#[test]
fn t34_ntfs_parse_drive_with_ads() {
    let (file, stream) = parse_ntfs_path("C:\\path\\file.exe:Zone.Identifier");
    assert_eq!(file, "C:\\path\\file.exe");
    let s = stream.unwrap();
    assert_eq!(s.stream_name, "Zone.Identifier");
}

#[test]
fn t34_ntfs_sidecar_path_format() {
    let real_path = std::path::Path::new("/data/ge/drive_c/file.txt");
    let sidecar = ads_sidecar_path_for(real_path, "Zone.Identifier");
    assert!(sidecar.to_string_lossy().contains(".casa1_ads"));
    assert!(sidecar.to_string_lossy().contains("file.txt__Zone.Identifier"));
}

#[test]
fn t34_ntfs_sidecar_roundtrip() {
    let real_path = std::path::Path::new("/data/ge/drive_c/docs/readme.txt");
    let sidecar = ads_sidecar_path_for(real_path, "Zone.Identifier");

    let (base_name, stream_name) = ads_sidecar_to_stream(&sidecar).unwrap();
    assert_eq!(base_name, "readme.txt");
    assert_eq!(stream_name, "Zone.Identifier");
}

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
    let mut file = rfs.open_file("C:\\test_backup.txt", false, true, true, false).unwrap();
    file.write(b"main data").unwrap();
    file.flush().unwrap();
    drop(file);

    // Backup read
    let result = backup_read_file(&rfs, "C:\\test_backup.txt").unwrap();
    assert!(result.main_stream().is_some());
    assert_eq!(result.main_stream().unwrap().data, b"main data");

    // Write an ADS
    rfs.write_alternate_stream("C:\\test_backup.txt", "Zone.Identifier", b"[ZoneTransfer]").unwrap();

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
fn t34_registry_change_tracker_initial_version() {
    let tracker = RegistryChangeTracker::new();
    assert_eq!(tracker.version("HKLM\\Software\\MyApp"), 0);
}

#[test]
fn t34_registry_change_tracker_notify_bumps_version() {
    let mut tracker = RegistryChangeTracker::new();
    tracker.notify_change("HKLM\\Software\\MyApp");
    assert_eq!(tracker.version("HKLM\\Software\\MyApp"), 1);
    tracker.notify_change("HKLM\\Software\\MyApp");
    assert_eq!(tracker.version("HKLM\\Software\\MyApp"), 2);
}

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

#[test]
fn t34_registry_notify_flags() {
    // Verify flag constants
    assert_eq!(REG_NOTIFY_CHANGE_NAME, 0x0000_0001);
    assert_eq!(REG_NOTIFY_CHANGE_ATTRIBUTES, 0x0000_0002);
    assert_eq!(REG_NOTIFY_CHANGE_LAST_SET, 0x0000_0004);
    assert_eq!(REG_NOTIFY_CHANGE_SECURITY, 0x0000_0008);
}

#[test]
fn t34_reg_notify_immediate_change() {
    let mut tracker = RegistryChangeTracker::new();
    tracker.notify_change("HKLM\\Software\\Test");

    let (version, result) = reg_notify_change_key_value(
        &mut tracker,
        "HKLM\\Software\\Test",
        false,
        REG_NOTIFY_CHANGE_LAST_SET,
        false,
        0,
        0,
        std::time::Duration::from_millis(0),
    );
    assert_eq!(version, 1);
    assert_eq!(result, RegNotifyResult::Changed);
}

#[test]
fn t34_reg_notify_async_pending() {
    let mut tracker = RegistryChangeTracker::new();

    let (version, result) = reg_notify_change_key_value(
        &mut tracker,
        "HKLM\\Software\\Test",
        false,
        REG_NOTIFY_CHANGE_LAST_SET,
        true, // async
        42,   // event handle
        0,
        std::time::Duration::from_secs(5),
    );
    assert_eq!(version, 0);
    assert_eq!(result, RegNotifyResult::Pending);
}

#[test]
fn t34_reg_notify_subscribe_unsubscribe() {
    let mut tracker = RegistryChangeTracker::new();
    tracker.subscribe("HKLM\\Software\\Test", 42, REG_NOTIFY_CHANGE_LAST_SET, false);
    let subs = tracker.subscriptions_for_key("HKLM\\Software\\Test");
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].0, 42);

    tracker.unsubscribe(42);
    let subs = tracker.subscriptions_for_key("HKLM\\Software\\Test");
    assert!(subs.is_empty());
}

// ===========================================================================
// P3.5 — XAPO Audio Effects (F-21)
// ===========================================================================

#[test]
fn t34_xapo_equalizer_default_parameters() {
    let params = EqualizerParameters::default();
    assert_eq!(params.band_gains_db, [0.0, 0.0, 0.0, 0.0]);
    assert_eq!(params.band_frequencies, [100.0, 500.0, 2000.0, 8000.0]);
    assert_eq!(params.band_q, [1.0, 1.0, 1.0, 1.0]);
}

#[test]
fn t34_xapo_equalizer_processes_audio() {
    let params = EqualizerParameters {
        band_gains_db: [6.0, 0.0, -3.0, 0.0],
        band_frequencies: [100.0, 500.0, 2000.0, 8000.0],
        band_q: [1.0, 1.0, 1.0, 1.0],
    };
    let mut eq = XapoEqualizer::new(params, 1, 48000);
    let input = vec![0.5f32; 256];
    let mut output = vec![0.0f32; 256];

    eq.process(&input, &mut output).unwrap();

    // Output should not be all zeros (the EQ is doing something)
    assert!(output.iter().any(|&s| s != 0.0));
}

#[test]
fn t34_xapo_equalizer_reset() {
    let mut eq = XapoEqualizer::new(EqualizerParameters::default(), 2, 48000);
    let input = vec![0.5f32; 128];
    let mut output = vec![0.0f32; 128];
    eq.process(&input, &mut output).unwrap();

    // Reset should clear internal state
    eq.reset();

    // Process silence after reset
    let silence = vec![0.0f32; 128];
    let mut output2 = vec![0.0f32; 128];
    eq.process(&silence, &mut output2).unwrap();
    assert!(output2.iter().all(|&s| s == 0.0));
}

#[test]
fn t34_xapo_equalizer_registration() {
    let eq = XapoEqualizer::new(EqualizerParameters::default(), 2, 48000);
    let reg = eq.registration();
    assert_eq!(reg.flags, XAPO_FLAG_INPLACE);
    assert_eq!(eq.channels(), 2);
    assert_eq!(eq.sample_rate(), 48000);
}

#[test]
fn t34_xapo_manager_registers_equalizer() {
    let mut mgr = XapoManager::new();
    mgr.register_builtins();
    // Should have 7 built-in effects: reverb, lowpass, highpass, echo, compressor, normalize, equalizer
    assert_eq!(mgr.registered_count(), 7);
}

#[test]
fn t34_xapo_effect_chain_process() {
    let mut mgr = XapoManager::new();
    mgr.register_builtins();

    // Create two effect instances
    let reverb_clsid = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let echo_clsid = [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let reverb_id = mgr.create_instance(&reverb_clsid).expect("create reverb");
    let echo_id = mgr.create_instance(&echo_clsid).expect("create echo");

    let mut chain = XapoEffectChain::from_handles(vec![reverb_id, echo_id]);
    assert_eq!(chain.len(), 2);

    let input = vec![0.5f32; 256];
    let mut output = vec![0.0f32; 256];
    chain.process_chain(&mut mgr, &input, &mut output).unwrap();

    // Output should not be all zeros
    assert!(output.iter().any(|&s| s != 0.0));
}

#[test]
fn t34_xapo_effect_chain_empty_passthrough() {
    let mut mgr = XapoManager::new();
    let mut chain = XapoEffectChain::new();
    assert!(chain.is_empty());

    let input = vec![0.5f32; 64];
    let mut output = vec![0.0f32; 64];
    chain.process_chain(&mut mgr, &input, &mut output).unwrap();

    // Should pass through unchanged
    for i in 0..64 {
        assert!((output[i] - input[i]).abs() < 0.001);
    }
}

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
    let eq_clsid = [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07];
    let eq_id = mgr.create_instance(&eq_clsid).expect("create eq");
    vec.chain_mut().push(eq_id);
    assert_eq!(vec.chain().len(), 1);
}

#[test]
fn t34_xapo_effect_parameter_structures() {
    // Verify all parameter structures can be created with defaults
    let reverb_params = ReverbParameters::default();
    assert!((reverb_params.wet_dry_mix - 0.5).abs() < 0.001);

    let eq_params = EqualizerParameters::default();
    assert_eq!(eq_params.band_gains_db.len(), 4);

    let comp_params = CompressorParameters::default();
    assert!((comp_params.threshold_db - (-24.0)).abs() < 0.001);

    let echo_params = EchoParameters::default();
    assert!((echo_params.delay_ms - 200.0).abs() < 0.001);
}

// ===========================================================================
// P3.6 — Named Pipes (F-22)
// ===========================================================================

#[test]
fn t34_pipe_name_to_uds_path() {
    let path = pipe_name_to_uds_path("\\\\.\\pipe\\MyPipe");
    assert_eq!(path, "/tmp/casa1_pipes/MyPipe");

    let path2 = pipe_name_to_uds_path("\\\\.\\pipe\\steam_service");
    assert_eq!(path2, "/tmp/casa1_pipes/steam_service");
}

#[test]
fn t34_pipe_constants() {
    assert_eq!(PIPE_ACCESS_DUPLEX, 0x0000_0003);
    assert_eq!(PIPE_ACCESS_INBOUND, 0x0000_0001);
    assert_eq!(PIPE_ACCESS_OUTBOUND, 0x0000_0002);
    assert_eq!(PIPE_WAIT, 0x0000_0000);
    assert_eq!(PIPE_NOWAIT, 0x0000_0001);
}

#[test]
fn t34_create_named_pipe_w_creates_pipe() {
    let (_tmp, mut win32) = setup_win32("create-pipe");
    let handle = win32.create_named_pipe_w(
        "\\\\.\\pipe\\TestPipe",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        false,
        None,
        None,
    ).expect("create named pipe");
    assert!(handle > 0);
}

#[test]
fn t34_named_pipe_connect_disconnect() {
    let (_tmp, mut win32) = setup_win32("connect-pipe");
    let handle = win32.create_named_pipe_w(
        "\\\\.\\pipe\\ConnTest",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        false,
        None,
        None,
    ).expect("create pipe");

    win32.connect_named_pipe(handle).expect("connect");
    win32.disconnect_named_pipe(handle).expect("disconnect");
}

#[test]
fn t34_named_pipe_duplicate_creation_fails() {
    let (_tmp, mut win32) = setup_win32("dup-pipe");
    let _h1 = win32.create_named_pipe_w(
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
    ).expect("create first");

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
    assert!(result.is_err());
}

#[test]
fn t34_named_pipe_wait_available() {
    let (_tmp, mut win32) = setup_win32("wait-pipe");
    let _handle = win32.create_named_pipe_w(
        "\\\\.\\pipe\\WaitTest",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        false,
        None,
        None,
    ).expect("create pipe");

    win32.wait_named_pipe_w("\\\\.\\pipe\\WaitTest", 5000).expect("wait");
}

#[test]
fn t34_named_pipe_set_mode() {
    let (_tmp, mut win32) = setup_win32("mode-pipe");
    let handle = win32.create_named_pipe_w(
        "\\\\.\\pipe\\ModeTest",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        false,
        None,
        None,
    ).expect("create pipe");

    // Set to non-blocking mode
    win32.set_named_pipe_handle_state(handle, Some(PIPE_NOWAIT), None, None).expect("set mode");
}

#[test]
fn t34_named_pipe_get_info() {
    let (_tmp, mut win32) = setup_win32("info-pipe");
    let handle = win32.create_named_pipe_w(
        "\\\\.\\pipe\\InfoTest",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        8192,
        4096,
        5000,
        false,
        None,
        None,
    ).expect("create pipe");

    let (mode, max_inst, out_buf, in_buf) = win32.get_named_pipe_info(handle).expect("get info");
    assert!(out_buf >= 4096);
    assert!(in_buf >= 4096);
}

#[test]
fn t34_named_pipe_client_connect() {
    let (_tmp, mut win32) = setup_win32("client-pipe");
    let server = win32.create_named_pipe_w(
        "\\\\.\\pipe\\ClientTest",
        PIPE_ACCESS_DUPLEX,
        PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        false,
        None,
        None,
    ).expect("create server");

    let client = win32.open_named_pipe_client("\\\\.\\pipe\\ClientTest", false).expect("open client");
    assert!(client > 0);
    assert_ne!(server, client);
}

// ===========================================================================
// P3.7 — InstallShield Installer (F-23)
// ===========================================================================

#[test]
fn t34_iss_parse_basic_script() {
    let script = r#"
[Install]
InstallDir=C:\Program Files\MyApp
Silent=1

[Registry]
HKLM\Software\MyApp,Version,1.0.0

[PostInstall]
Run=notepad.exe readme.txt
"#;
    let parsed = IssScript::parse(script);
    assert!(parsed.is_valid);
    assert_eq!(parsed.section_count, 3);
    assert!(parsed.commands.len() >= 4);
}

#[test]
fn t34_iss_parse_variables() {
    let script = r#"
[Install]
Dir=C:\Test
Mode=Silent
"#;
    let parsed = IssScript::parse(script);
    let vars = parsed.variables_for_section("Install");
    assert_eq!(vars.len(), 2);

    let dir_var = vars.iter().find(|(k, _)| k == "Dir").unwrap();
    assert_eq!(dir_var.1, "C:\\Test");
}

#[test]
fn t34_iss_parse_registry_operations() {
    let script = r#"
[Registry]
HKLM\Software\MyApp,Version,1.0.0
HKCU\Software\MyApp,Setting,Enabled
"#;
    let parsed = IssScript::parse(script);
    let reg_ops = parsed.registry_operations();
    assert_eq!(reg_ops.len(), 2);
}

#[test]
fn t34_iss_parse_post_install() {
    let script = r#"
[PostInstall]
RunAfter=notepad.exe readme.txt
"#;
    let parsed = IssScript::parse(script);
    let post = parsed.post_install_commands();
    assert_eq!(post.len(), 1);
}

#[test]
fn t34_iss_parse_comments_ignored() {
    let script = r#"
; This is a comment
# Another comment
// Yet another comment
[Install]
Key=Value
"#;
    let parsed = IssScript::parse(script);
    assert!(parsed.is_valid);
    let comments: Vec<_> = parsed.commands.iter()
        .filter(|c| matches!(c, IssCommand::Comment(_)))
        .collect();
    assert_eq!(comments.len(), 3);
}

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
fn t34_issetup_dll_stub_custom_action() {
    let mut stub = ISSetupDllStub::new();
    stub.handle_call("CustomAction1");
    stub.handle_call("OnRegisterFiles");

    let custom_calls = stub.calls_of_type(&ISSetupActionType::Custom("CustomAction1".to_string()));
    assert_eq!(custom_calls.len(), 1);

    let reg_calls = stub.calls_of_type(&ISSetupActionType::OnRegisterFiles);
    assert_eq!(reg_calls.len(), 1);
}

#[test]
fn t34_installshield_detect_invalid_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("not_installer.exe");
    std::fs::write(&path, b"This is not an installer").unwrap();
    assert!(!InstallShieldEngine::detect(&path));
}

#[test]
fn t34_installshield_detect_with_isc_magic() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("setup.exe");
    // Create a minimal PE-like file with ISc( magic
    let mut data = vec![0u8; 512];
    // MZ header
    data[0] = b'M';
    data[1] = b'Z';
    // ISc( magic somewhere in the file
    data[256] = b'I';
    data[257] = b'S';
    data[258] = b'c';
    data[259] = b'(';
    std::fs::write(&path, &data).unwrap();
    assert!(InstallShieldEngine::detect(&path));
}
