use casa1::network::Certificate;
use casa1::reason::ReasonCode;
use casa1::steam::{
    load_depot_manifest_from_disk, DepotManifest, SteamClient, SteamGamePrerequisite, SteamUpdatePlan,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::TempDir;

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
            library_root: None,
            prerequisites: Vec::new(),
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
            "c:/ges/steamdepot/steamapps/appmanifest_480.acf".to_string(),
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
            library_root: None,
            prerequisites: Vec::new(),
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

#[test]
fn t13_5_launch_game_auto_installs_first_run_prerequisites() {
    let mut client = SteamClient::new("C:/GEs/SteamAutoPrereq");
    client
        .install_depot(DepotManifest {
            app_id: 482,
            game_name: "Prereq Game".to_string(),
            install_dir: "Prereq Game".to_string(),
            launch_exe: "Bin/PrereqGame.exe".to_string(),
            library_root: None,
            prerequisites: vec![
                SteamGamePrerequisite::DirectX {
                    dll: "d3dcompiler_43.dll".to_string(),
                },
                SteamGamePrerequisite::VisualCpp {
                    version: "vc143".to_string(),
                    dlls: vec!["vcruntime140.dll".to_string(), "msvcp140.dll".to_string()],
                },
                SteamGamePrerequisite::DotNet {
                    version: "net8.0".to_string(),
                },
            ],
            files: BTreeMap::from([
                ("Bin/PrereqGame.exe".to_string(), b"prereq-game-exe".to_vec()),
                ("steam_api64.dll".to_string(), b"steam-api64".to_vec()),
            ]),
        })
        .expect("install prereq depot");

    assert!(!client.has_directx_component("d3dcompiler_43.dll"));
    assert!(!client.has_vc_runtime("vc143", &["vcruntime140.dll", "msvcp140.dll"]));

    let launch = client.launch_game(482).expect("launch prereq game");

    assert_eq!(launch.window_title, "Prereq Game - Main Menu");
    assert!(client.has_directx_component("d3dcompiler_43.dll"));
    assert!(client.has_vc_runtime("vc143", &["vcruntime140.dll", "msvcp140.dll"]));
    assert!(client.supports_dotnet("net8.0"));
    assert!(client.logs().iter().any(|entry| entry == "prereq:482:directx:d3dcompiler_43.dll"));
    assert!(client
        .logs()
        .iter()
        .any(|entry| entry == "prereq:482:vcredist:vc143:vcruntime140.dll,msvcp140.dll"));
    assert!(client.logs().iter().any(|entry| entry == "prereq:482:dotnet:net8.0"));
}

#[test]
fn t13_6_zero_touch_downloaded_steam_setup_installs_updates_and_launches_without_manual_steps() {
    let mut client = SteamClient::new_uninstalled("C:/GEs/SteamZeroTouch");
    assert_eq!(
        client.boot().expect_err("fresh GE without Steam install must not boot").code,
        ReasonCode::RcSteamUpdateFailed
    );

    let result = client
        .zero_touch_install_and_launch(
            "C:/Users/Casa1/Downloads/SteamSetup.exe",
            b"steam-setup-payload",
            &SteamUpdatePlan {
                files: BTreeMap::from([
                    (
                        "c:/ges/steamzerotouch/steam.exe".to_string(),
                        b"steam-bootstrap-v2".to_vec(),
                    ),
                    (
                        "c:/ges/steamzerotouch/package/steamui.dll".to_string(),
                        b"steam-ui-v2".to_vec(),
                    ),
                ]),
                fail_after_write: None,
            },
            &trusted_chain(),
            DepotManifest {
                app_id: 570,
                game_name: "Zero Touch Game".to_string(),
                install_dir: "Zero Touch Game".to_string(),
                launch_exe: "Bin/ZeroTouch.exe".to_string(),
                library_root: None,
                prerequisites: vec![
                    SteamGamePrerequisite::DirectX {
                        dll: "xinput1_3.dll".to_string(),
                    },
                    SteamGamePrerequisite::VisualCpp {
                        version: "vc143".to_string(),
                        dlls: vec!["vcruntime140.dll".to_string(), "msvcp140.dll".to_string()],
                    },
                    SteamGamePrerequisite::DotNet {
                        version: "net8.0".to_string(),
                    },
                ],
                files: BTreeMap::from([
                    ("Bin/ZeroTouch.exe".to_string(), b"zero-touch-game".to_vec()),
                    ("steam_api64.dll".to_string(), b"steam-api64".to_vec()),
                ]),
            },
        )
        .expect("zero touch Steam bootstrap succeeds");

    assert_eq!(result.install_telemetry.installer_id, "steam-setup");
    assert_eq!(result.install_telemetry.silent_flags, vec!["/S".to_string()]);
    assert_eq!(result.install_telemetry.window_titles, vec!["Steam Setup".to_string()]);
    assert_eq!(result.boot.login_window_title, "Steam Login");
    assert_eq!(result.login.store_window_title, "Steam Store");
    assert_eq!(result.launch.executable, "c:/ges/steamzerotouch/steamapps/common/Zero Touch Game/Bin/ZeroTouch.exe");
    assert_eq!(result.launch.env["SteamPath"], "c:/ges/steamzerotouch/steam.exe");
    assert!(client.has_file(&result.app_manifest_path));
    assert!(client.file_list().iter().any(|path| path == &result.app_manifest_path));
    assert!(client.has_directx_component("xinput1_3.dll"));
    assert!(client.has_vc_runtime("vc143", &["vcruntime140.dll", "msvcp140.dll"]));
    assert!(client.supports_dotnet("net8.0"));
    assert_eq!(result.prerequisite_actions.len(), 3);
    assert!(client.logs().iter().any(|entry| entry == "steam-install-silent:/S"));
    assert!(client.logs().iter().any(|entry| entry == "update-success"));
}

#[test]
fn t13_7_multi_library_install_launches_from_registered_library_without_user_input() {
    let mut client = SteamClient::new("C:/GEs/SteamLibrariesPrimary");
    client.register_library_folder("C:/GEs/SteamLibrariesArcade");
    let installed = client
        .install_depot(DepotManifest {
            app_id: 483,
            game_name: "Arcade Game".to_string(),
            install_dir: "Arcade Game".to_string(),
            launch_exe: "Bin/Arcade.exe".to_string(),
            library_root: Some("C:/GEs/SteamLibrariesArcade".to_string()),
            prerequisites: vec![SteamGamePrerequisite::DirectX {
                dll: "xinput1_3.dll".to_string(),
            }],
            files: BTreeMap::from([
                ("Bin/Arcade.exe".to_string(), b"arcade-exe".to_vec()),
                ("steam_api64.dll".to_string(), b"steam-api64".to_vec()),
            ]),
        })
        .expect("install game into secondary Steam library");

    let launch = client.launch_game(483).expect("launch from secondary Steam library");
    let verified = client.verify_integrity(483).expect("verify secondary library install");

    assert_eq!(
        launch.executable,
        "c:/ges/steamlibrariesarcade/steamapps/common/Arcade Game/Bin/Arcade.exe"
    );
    assert_eq!(launch.cwd, "c:/ges/steamlibrariesarcade/steamapps/common/Arcade Game/Bin");
    assert!(client.has_directx_component("xinput1_3.dll"));
    assert_eq!(installed.file_list, verified.file_list);
    assert!(installed
        .file_list
        .iter()
        .any(|path| path == "c:/ges/steamlibrariesarcade/steamapps/appmanifest_483.acf"));
    assert!(client
        .logs()
        .iter()
        .any(|entry| entry == "library-folder:c:/ges/steamlibrariesarcade"));
}

#[test]
fn t13_8_loader_rejects_malformed_appmanifest_and_installscript_metadata() {
    let temp_dir = TempDir::new().expect("temp dir");
    let payload_root = temp_dir.path().join("payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload root");
    fs::write(payload_root.join("Bin/Game.exe"), b"game-exe").expect("write payload exe");

    let appmanifest_path = temp_dir.path().join("appmanifest_700.acf");
    let installscript_path = temp_dir.path().join("installscript.vdf");

    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"not-a-number\"\n",
            "\t\"name\"\t\"Broken Game\"\n",
            "\t\"installdir\"\t\"Broken Game\"\n",
            "}\n"
        ),
    )
    .expect("write malformed appmanifest");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/Game.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");

    let appmanifest_error = load_depot_manifest_from_disk(
        &appmanifest_path,
        &installscript_path,
        &payload_root,
        None,
    )
        .expect_err("non-numeric appid must fail");
    assert!(appmanifest_error.message.contains("appid must be numeric"));

    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"700\"\n",
            "\t\"name\"\t\"Broken Game\"\n",
            "\t\"installdir\"\t\"Broken Game\"\n",
            "}\n"
        ),
    )
    .expect("write valid appmanifest");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write malformed installscript");

    let installscript_error = load_depot_manifest_from_disk(
        &appmanifest_path,
        &installscript_path,
        &payload_root,
        None,
    )
        .expect_err("missing launch executable must fail");
    assert!(installscript_error.message.contains("missing Steam metadata field Executable"));
}

#[test]
fn t13_9_loader_selects_library_from_libraryfolders_metadata() {
    let temp_dir = TempDir::new().expect("temp dir");
    let payload_root = temp_dir.path().join("payload");
    fs::create_dir_all(payload_root.join("Bin")).expect("create payload root");
    fs::write(payload_root.join("Bin/Racing.exe"), b"racing-exe").expect("write payload exe");

    let appmanifest_path = temp_dir.path().join("appmanifest_701.acf");
    let installscript_path = temp_dir.path().join("installscript.vdf");
    let libraryfolders_path = temp_dir.path().join("libraryfolders.vdf");

    fs::write(
        &appmanifest_path,
        concat!(
            "\"AppState\"\n",
            "{\n",
            "\t\"appid\"\t\"701\"\n",
            "\t\"name\"\t\"Racing Game\"\n",
            "\t\"installdir\"\t\"Racing Game\"\n",
            "}\n"
        ),
    )
    .expect("write appmanifest");
    fs::write(
        &installscript_path,
        concat!(
            "\"InstallScript\"\n",
            "{\n",
            "\t\"Launch\"\n",
            "\t{\n",
            "\t\t\"Executable\"\t\"Bin/Racing.exe\"\n",
            "\t}\n",
            "\t\"Redistributables\"\n",
            "\t{\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write installscript");
    fs::write(
        &libraryfolders_path,
        concat!(
            "\"libraryfolders\"\n",
            "{\n",
            "\t\"0\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"C:\\\\Program Files\\\\Steam\"\n",
            "\t}\n",
            "\t\"1\"\n",
            "\t{\n",
            "\t\t\"path\"\t\"E:\\\\SteamLibraryRacing\"\n",
            "\t\t\"apps\"\n",
            "\t\t{\n",
            "\t\t\t\"701\"\t\"1\"\n",
            "\t\t}\n",
            "\t}\n",
            "}\n"
        ),
    )
    .expect("write libraryfolders");

    let manifest = load_depot_manifest_from_disk(
        &appmanifest_path,
        &installscript_path,
        &payload_root,
        Some(&libraryfolders_path),
    )
    .expect("load depot manifest with libraryfolders metadata");

    assert_eq!(manifest.app_id, 701);
    assert_eq!(manifest.library_root, Some("e:/steamlibraryracing".to_string()));
    assert_eq!(manifest.launch_exe, "Bin/Racing.exe");
}