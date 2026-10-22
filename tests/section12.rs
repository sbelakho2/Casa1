#![allow(dead_code, unused_imports)]
use casa1::installer::{
    CustomAction, InstallerEngine, MsiComponent, MsiInstallOptions, MsiPackage, RuntimeAssembly,
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

const GOLDEN_CUMULATIVE_MANIFEST_HASH: &str =
    "d39f5e3eb7cb858e5260bb7a0e6763f1e7af3083f091b90d75af6cabc6db6a1f";

#[test]
fn t12_3_redist_verification_activates_vc_runtime_provides_d3dcompiler_and_rejects_unsupported_dotnet()
 {
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
    let _result = engine.require_dotnet("net8.0");
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    let unsupported = engine
        .require_dotnet("netfx35")
        .expect_err("unsupported .NET must fail");
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
    assert!(
        engine
            .msiexec_install(
                service_package,
                &MsiInstallOptions {
                    fail_after_custom_action: None,
                    scm_vm_mode: true,
                },
            )
            .is_ok()
    );
}
