use casa1::network::Certificate;
use casa1::reason::ReasonCode;
use casa1::steam::{DepotManifest, SteamClient, SteamUpdatePlan};
use std::collections::BTreeMap;

fn trusted_chain() -> Vec<Certificate> {
    let root = Certificate {
        subject: "Casa1 Root".to_string(),
        issuer: "Casa1 Root".to_string(),
        fingerprint: "root-1".to_string(),
        valid_hostnames: vec!["api.example.com".to_string(), "launcher.example.com".to_string()],
        not_after_day: 10_000,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    let leaf = Certificate {
        subject: "api.example.com".to_string(),
        issuer: "Casa1 Root".to_string(),
        fingerprint: "leaf-1".to_string(),
        valid_hostnames: vec!["api.example.com".to_string(), "launcher.example.com".to_string()],
        not_after_day: 10_000,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    vec![leaf, root]
}

fn install_test_depot(client: &mut SteamClient) -> casa1::steam::DepotInstallResult {
    client
        .install_depot(DepotManifest {
            app_id: 480,
            game_name: "Test Game".to_string(),
            install_dir: "Test Game".to_string(),
            launch_exe: "Bin/TestGame.exe".to_string(),
            files: BTreeMap::from([
                ("Bin/TestGame.exe".to_string(), b"test-game-exe".to_vec()),
                ("Data/pack.pak".to_string(), b"pack-data".to_vec()),
                ("data/PACK.PAK".to_string(), b"pack-data".to_vec()),
                ("steam_api.dll".to_string(), b"steam-api".to_vec()),
            ]),
        })
        .expect("install depot")
}

#[test]
fn t13_1_automated_steam_smoke_installs_logs_in_downloads_launches_and_reaches_checkpoint() {
    let mut client = SteamClient::new("C:/GEs/SteamFresh");
    client.network_mut().import_certificate(trusted_chain()[1].clone());
    let boot = client.boot().expect("boot Steam in fresh GE");
    assert_eq!(boot.login_window_title, "Steam Login");

    client.prime_ipc_channel(r"\\.\pipe\SteamClient", "SteamSharedMem", b"ready");
    let ipc = client
        .ipc_roundtrip(r"\\.\pipe\SteamClient", "SteamSharedMem", b"hello")
        .expect("Steam IPC roundtrip");
    assert_eq!(ipc.response, b"ready");

    let login = client.login(&trusted_chain()).expect("Steam login succeeds");
    assert_eq!(login.store_window_title, "Steam Store");
    assert_eq!(login.cipher_suite, "TLS_AES_128_GCM_SHA256");

    install_test_depot(&mut client);
    let launch = client.launch_game(480).expect("launch Steam game");
    assert_eq!(launch.executable, "c:/ges/steamfresh/steamapps/common/Test Game/Bin/TestGame.exe");
    assert_eq!(launch.cwd, "c:/ges/steamfresh/steamapps/common/Test Game/Bin");
    assert_eq!(launch.window_title, "Test Game - Main Menu");
    assert!(launch.input_ok);
    assert!(launch.audio_ok);
    assert!(launch.network_ok);
    assert_eq!(launch.env["SteamAppId"], "480");
    assert!(client.steam_api_init(480));
    assert_eq!(client.overlay_command(480, "activate").unwrap(), 0);
    assert!(client.overlay_active(480));
    assert_eq!(client.overlay_command(480, "pump").unwrap(), 1);
    assert_eq!(client.overlay_command(480, "deactivate").unwrap(), 0);
    assert!(!client.overlay_active(480));
}

#[test]
fn t13_2_steam_update_robustness_relaunches_after_success_and_logs_reason_code_on_failure() {
    let mut client = SteamClient::new("C:/GEs/SteamUpdate");
    client.boot().expect("initial boot");
    client
        .self_update(&SteamUpdatePlan {
            files: BTreeMap::from([
                (
                    "C:/GEs/SteamUpdate/package/steamui.dll".to_string(),
                    b"steam-ui-v2".to_vec(),
                ),
                (
                    "C:/GEs/SteamUpdate/steam.exe".to_string(),
                    b"steam-bootstrap-v2".to_vec(),
                ),
            ]),
            fail_after_write: None,
        })
        .expect("self update succeeds");
    let relaunch = client.boot().expect("Steam relaunches after update");
    assert_eq!(relaunch.login_window_title, "Steam Login");
    assert!(client
        .file_list()
        .iter()
        .all(|path| path.to_ascii_lowercase().starts_with("c:/ges/steamupdate")));

    let error = client
        .self_update(&SteamUpdatePlan {
            files: BTreeMap::from([(
                "C:/outside/escape.dll".to_string(),
                b"escape".to_vec(),
            )]),
            fail_after_write: None,
        })
        .expect_err("out-of-root update must fail");
    assert_eq!(error.code, ReasonCode::RcSteamUpdateFailed);
    assert!(client
        .logs()
        .iter()
        .any(|entry| entry.contains("RC_STEAM_UPDATE_FAILED")));
    assert!(client.boot().is_ok());
}

#[test]
fn t13_3_depot_integrity_matches_windows_reference_and_preserves_install_path_rules() {
    let mut client = SteamClient::new("C:/GEs/SteamDepot");
    let installed = install_test_depot(&mut client);
    let verified = client.verify_integrity(480).expect("verify depot integrity");
    assert_eq!(verified.normalized_tree_hash, installed.normalized_tree_hash);
    assert_eq!(verified.file_list, installed.file_list);
    assert_eq!(
        verified.file_list,
        vec![
            "c:/ges/steamdepot/steamapps/common/Test Game/Bin/TestGame.exe".to_string(),
            "c:/ges/steamdepot/steamapps/common/Test Game/Data/pack.pak".to_string(),
            "c:/ges/steamdepot/steamapps/common/Test Game/steam_api.dll".to_string(),
        ]
    );
    assert_eq!(client.overlay_command(480, "pump").unwrap(), 0);
}

#[test]
fn t13_4_driver_required_steam_titles_fail_fast_with_stable_reason_code() {
    let mut client = SteamClient::new("C:/GEs/SteamDriverRequired");
    client
        .install_depot(DepotManifest {
            app_id: 481,
            game_name: "Driver Required Game".to_string(),
            install_dir: "Driver Required Game".to_string(),
            launch_exe: "Bin/TestGame.exe".to_string(),
            files: BTreeMap::from([
                ("Bin/TestGame.exe".to_string(), b"test-game-exe".to_vec()),
                (
                    "EasyAntiCheat/EasyAntiCheat.sys".to_string(),
                    b"kernel-driver".to_vec(),
                ),
            ]),
        })
        .expect("install driver-required depot");

    let error = client
        .launch_game(481)
        .expect_err("driver-required Steam game must fail fast");
    assert_eq!(error.code, ReasonCode::RcAnticheatDriverDetected);
    assert!(error.message.contains("driver-required title"));
    assert!(error
        .reproduction_hints
        .iter()
        .any(|hint| hint.contains("Easy Anti-Cheat kernel driver")));
}