use casa1::installer::{
    CustomAction, GuiWindowPlan, InstallerEngine, InstallerFramework, InstallerSpec,
    MsiComponent, MsiInstallOptions, MsiPackage, PatchOperation, RuntimeAssembly,
};
use casa1::reason::ReasonCode;
use std::collections::BTreeMap;

fn expected_manifest_hash(files: &[(&str, &[u8])], registry: &[(&str, &str)]) -> String {
    let mut entries = Vec::new();
    for (path, bytes) in files {
        entries.push(format!(
            "{}|{}",
            path.to_ascii_lowercase(),
            casa1::util::sha256_bytes(bytes)
        ));
    }
    for (key, value) in registry {
        entries.push(format!("{}={}", key, value));
    }
    entries.sort();
    casa1::util::sha256_bytes(entries.join("\n").as_bytes())
}

#[test]
fn t12_1_installer_farm_compare_file_and_registry_manifests_against_reference() {
    let mut engine = InstallerEngine::new();
    let nsis = InstallerSpec {
        id: "nsis-game".to_string(),
        executable_name: "setup_nsis.exe".to_string(),
        framework: InstallerFramework::Nsis,
        gui_windows: vec![
            GuiWindowPlan {
                title: "Setup Wizard".to_string(),
                modal: true,
                controls: vec!["Next".to_string(), "Cancel".to_string()],
            },
            GuiWindowPlan {
                title: "Install Complete".to_string(),
                modal: true,
                controls: vec!["Finish".to_string()],
            },
        ],
        files: BTreeMap::from([
            ("C:/Games/TestGame/game.exe".to_string(), b"game-binary".to_vec()),
            ("C:/Games/TestGame/data.pak".to_string(), b"data-pak".to_vec()),
        ]),
        registry: BTreeMap::from([(
            "HKLM\\Software\\Casa1\\TestGame\\InstallPath".to_string(),
            "C:/Games/TestGame".to_string(),
        )]),
        logs: vec!["launch-ui".to_string(), "copy-files".to_string(), "write-registry".to_string()],
    };
    let inno = InstallerSpec {
        id: "inno-tools".to_string(),
        executable_name: "setup_inno.exe".to_string(),
        framework: InstallerFramework::InnoSetup,
        gui_windows: vec![GuiWindowPlan {
            title: "Inno Setup".to_string(),
            modal: true,
            controls: vec!["Install".to_string()],
        }],
        files: BTreeMap::from([(
            "C:/Program Files/Tools/tool.exe".to_string(),
            b"tool-binary".to_vec(),
        )]),
        registry: BTreeMap::from([(
            "HKCU\\Software\\Casa1\\Tools\\Version".to_string(),
            "1.0.0".to_string(),
        )]),
        logs: vec!["wizard-finish".to_string()],
    };
    let custom = InstallerSpec {
        id: "custom-launcher".to_string(),
        executable_name: "launcher_bootstrapper.exe".to_string(),
        framework: InstallerFramework::Custom,
        gui_windows: vec![GuiWindowPlan {
            title: "Launcher Installer".to_string(),
            modal: false,
            controls: vec!["Install".to_string(), "Browse".to_string()],
        }],
        files: BTreeMap::from([(
            "C:/Launchers/CasaLauncher/launcher.exe".to_string(),
            b"launcher-binary".to_vec(),
        )]),
        registry: BTreeMap::from([(
            "HKLM\\Software\\Casa1\\Launcher\\Channel".to_string(),
            "stable".to_string(),
        )]),
        logs: vec!["custom-flags-fallback".to_string()],
    };

    let nsis_run = engine.run_gui_installer(&nsis, None).expect("run NSIS installer");
    let inno_run = engine.run_gui_installer(&inno, None).expect("run Inno installer");
    let custom_run = engine
        .run_gui_installer(&custom, Some(vec!["/headless".to_string(), "/skip-eula".to_string()]))
        .expect("run custom installer");

    assert_eq!(nsis_run.telemetry.silent_flags, vec!["/S"]);
    assert_eq!(
        inno_run.telemetry.silent_flags,
        vec!["/VERYSILENT", "/SUPPRESSMSGBOXES"]
    );
    assert_eq!(custom_run.telemetry.silent_flags, vec!["/headless", "/skip-eula"]);
    assert_eq!(nsis_run.telemetry.window_titles, vec!["Setup Wizard", "Install Complete"]);

    let expected = expected_manifest_hash(
        &[
            ("c:/games/testgame/game.exe", b"game-binary"),
            ("c:/games/testgame/data.pak", b"data-pak"),
            ("c:/program files/tools/tool.exe", b"tool-binary"),
            ("c:/launchers/casalauncher/launcher.exe", b"launcher-binary"),
        ],
        &[
            ("HKCU\\Software\\Casa1\\Tools\\Version", "1.0.0"),
            ("HKLM\\Software\\Casa1\\Launcher\\Channel", "stable"),
            (
                "HKLM\\Software\\Casa1\\TestGame\\InstallPath",
                "C:/Games/TestGame",
            ),
        ],
    );
    assert_eq!(custom_run.manifest_hash, expected);
    assert_eq!(engine.telemetry_log().len(), 3);
}

#[test]
fn t12_2_msi_rollback_torture_restores_preinstall_snapshot_exactly() {
    let mut engine = InstallerEngine::new();
    engine
        .run_gui_installer(
            &InstallerSpec {
                id: "baseline".to_string(),
                executable_name: "baseline.exe".to_string(),
                framework: InstallerFramework::Custom,
                gui_windows: vec![],
                files: BTreeMap::from([(
                    "C:/Games/Stable/baseline.txt".to_string(),
                    b"baseline".to_vec(),
                )]),
                registry: BTreeMap::from([(
                    "HKLM\\Software\\Casa1\\Baseline".to_string(),
                    "present".to_string(),
                )]),
                logs: vec![],
            },
            None,
        )
        .expect("install baseline state");
    let before_files = engine.files().clone();
    let before_registry = engine.registry().clone();
    let package = MsiPackage {
        product_code: "{GUID-TEST-MSI}".to_string(),
        components: vec![MsiComponent {
            id: "core".to_string(),
            keypath: "C:/Games/Stable/core.dll".to_string(),
            files: BTreeMap::from([(
                "C:/Games/Stable/core.dll".to_string(),
                b"core-bits".to_vec(),
            )]),
            registry: BTreeMap::from([(
                "HKLM\\Software\\Casa1\\Msi\\Core".to_string(),
                "1".to_string(),
            )]),
        }],
        custom_actions: vec![
            CustomAction::Exe {
                id: "launch_helper".to_string(),
                command: "helper.exe /register".to_string(),
                env: BTreeMap::from([("CASA1_GE".to_string(), "stable".to_string())]),
            },
            CustomAction::Dll {
                id: "dll_ca".to_string(),
                dll_path: "custom.dll".to_string(),
                entrypoint: "Install".to_string(),
            },
        ],
        rollback_script: vec![
            "remove-file:core.dll".to_string(),
            "delete-reg:HKLM\\Software\\Casa1\\Msi\\Core".to_string(),
        ],
    };
    let error = engine
        .msiexec_install(
            package,
            &MsiInstallOptions {
                fail_after_custom_action: Some("launch_helper".to_string()),
                scm_vm_mode: false,
            },
        )
        .expect_err("MSI failure should roll back state");
    assert_eq!(error.code, ReasonCode::RcIo);
    assert_eq!(engine.files(), &before_files);
    assert_eq!(engine.registry(), &before_registry);
    assert!(error
        .reproduction_hints
        .iter()
        .any(|hint| hint.contains("remove-file:core.dll")));
}

#[test]
fn t12_3_redist_verification_activates_vc_runtime_provides_d3dcompiler_and_rejects_unsupported_dotnet() {
    let mut engine = InstallerEngine::new();
    engine.install_vc_runtime(RuntimeAssembly {
        version: "vc143".to_string(),
        manifest: "Microsoft.VC143.CRT".to_string(),
        dlls: vec!["msvcp140.dll".to_string(), "vcruntime140.dll".to_string()],
    });
    engine.provide_directx_component("d3dcompiler_47.dll");
    engine.provide_directx_component("d3dx9_43.dll");

    assert!(engine.activate_vc_runtime("vc143", &["msvcp140.dll", "vcruntime140.dll"]));
    assert!(engine.has_directx_component("d3dcompiler_47.dll"));
    assert!(engine.has_directx_component("D3DX9_43.DLL"));
    assert!(engine.require_dotnet("net8.0").is_ok());
    let unsupported = engine.require_dotnet("netfx35").expect_err("unsupported .NET must fail");
    assert_eq!(unsupported.code, ReasonCode::RcDotnetUnsupported);

    let service_package = MsiPackage {
        product_code: "{GUID-SERVICE}".to_string(),
        components: vec![MsiComponent {
            id: "svc".to_string(),
            keypath: "C:/Program Files/Game/service.dat".to_string(),
            files: BTreeMap::from([(
                "C:/Program Files/Game/service.dat".to_string(),
                b"svc".to_vec(),
            )]),
            registry: BTreeMap::new(),
        }],
        custom_actions: vec![CustomAction::ServiceInstall {
            id: "install_service".to_string(),
            service_name: "CasaGameService".to_string(),
        }],
        rollback_script: vec!["remove-service:CasaGameService".to_string()],
    };
    let blocked = engine
        .msiexec_install(service_package.clone(), &MsiInstallOptions::default())
        .expect_err("service install CA must be blocked outside SCM VM mode");
    assert_eq!(blocked.code, ReasonCode::RcMsiCustomActionServiceBlocked);
    assert!(engine
        .msiexec_install(
            service_package,
            &MsiInstallOptions {
                fail_after_custom_action: None,
                scm_vm_mode: true,
            },
        )
        .is_ok());
}

#[test]
fn t12_4_patch_cycle_handles_atomic_replace_delete_on_close_and_case_insensitive_resume() {
    let mut engine = InstallerEngine::new();
    engine
        .run_gui_installer(
            &InstallerSpec {
                id: "patch-base".to_string(),
                executable_name: "base.exe".to_string(),
                framework: InstallerFramework::Custom,
                gui_windows: vec![],
                files: BTreeMap::from([
                    ("C:/Games/PatchGame/game.exe".to_string(), b"v1-game".to_vec()),
                    ("C:/Games/PatchGame/data.pak".to_string(), b"v1-data".to_vec()),
                ]),
                registry: BTreeMap::new(),
                logs: vec![],
            },
            None,
        )
        .expect("install base patch tree");
    engine.lock_file("C:/Games/PatchGame/data.pak", true);
    let result = engine
        .apply_patch_cycle(&[
            PatchOperation {
                target_path: "C:/Games/PatchGame/game.exe".to_string(),
                expected_old: b"v1-game".to_vec(),
                replacement: b"v2-game".to_vec(),
                download_chunks: vec![
                    ("c:/games/patchgame/GAME.EXE".to_string(), 0, b"v2-".to_vec()),
                    ("C:/Games/PatchGame/game.exe".to_string(), 3, b"game".to_vec()),
                ],
            },
            PatchOperation {
                target_path: "C:/Games/PatchGame/data.pak".to_string(),
                expected_old: b"v1-data".to_vec(),
                replacement: b"v2-data".to_vec(),
                download_chunks: vec![
                    ("C:/GAMES/PATCHGAME/DATA.PAK".to_string(), 0, b"v2-".to_vec()),
                    ("c:/games/patchgame/data.pak".to_string(), 3, b"data".to_vec()),
                ],
            },
        ])
        .expect("apply patch cycle");

    assert!(result
        .operation_log
        .iter()
        .any(|entry| entry == "delete_on_close:c:/games/patchgame/data.pak"));
    let expected_hash = expected_manifest_hash(
        &[
            ("c:/games/patchgame/game.exe", b"v2-game"),
            ("c:/games/patchgame/data.pak", b"v2-data"),
        ],
        &[],
    );
    assert_eq!(result.final_tree_hash, expected_hash);
    engine.unlock_file("C:/Games/PatchGame/data.pak");

    let repair_package = MsiPackage {
        product_code: "{GUID-REPAIR}".to_string(),
        components: vec![MsiComponent {
            id: "repair".to_string(),
            keypath: "C:/Games/PatchGame/repair.dll".to_string(),
            files: BTreeMap::from([(
                "C:/Games/PatchGame/repair.dll".to_string(),
                b"repair-dll".to_vec(),
            )]),
            registry: BTreeMap::new(),
        }],
        custom_actions: vec![],
        rollback_script: vec![],
    };
    engine
        .msiexec_install(repair_package.clone(), &MsiInstallOptions::default())
        .expect("install repair package");
    engine.remove_file("C:/Games/PatchGame/repair.dll");
    let repair = engine.msiexec_repair("{GUID-REPAIR}").expect("repair package");
    assert_eq!(repair.created_files, vec!["c:/games/patchgame/repair.dll"]);
    engine.msiexec_uninstall("{GUID-REPAIR}").expect("uninstall repair package");
}