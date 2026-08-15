use casa1::canonical::GuestException;
use casa1::error::ErrorResponse;
use casa1::ge::{NetworkPolicy, NetworkProfile};
use casa1::installer::parse_msi_script;
use casa1::media::MediaShim;
use casa1::pe;
use casa1::reason::ReasonCode;
use casa1::security::{
    CrashModule, CrashSnapshot, CrashThread, EntitlementAuditReport, EntitlementAuditTarget,
    FilesystemSandbox, NetworkPolicyEnforcer, audit_embedded_entitlements,
    audit_entitlement_targets, collect_crash_artifact, nightly_sanitizer_commands,
    parse_http_request,
};
use casa1::shader;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex pair");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn load_fixture(name: &str) -> Vec<u8> {
    let text = match name {
        "msi_invalid" => include_str!("fixtures/section16/msi_invalid.hex"),
        "media_truncated" => include_str!("fixtures/section16/media_truncated.hex"),
        "http_invalid" => include_str!("fixtures/section16/http_invalid.hex"),
        "pe_short" => include_str!("fixtures/section16/pe_short.hex"),
        "dxil_short" => include_str!("fixtures/section16/dxil_short.hex"),
        other => panic!("unknown fixture {other}"),
    };
    decode_hex(text)
}

fn sign_binary_copy(source: &Path, destination: &Path, entitlements_xml: &str) {
    fs::copy(source, destination).expect("copy binary");
    let permissions = fs::metadata(source).expect("source metadata").permissions();
    fs::set_permissions(destination, permissions).expect("preserve binary permissions");

    let entitlements_path = destination.with_extension("entitlements.plist");
    fs::write(&entitlements_path, entitlements_xml).expect("write entitlements plist");

    let output = Command::new("/usr/bin/codesign")
        .arg("--force")
        .arg("--sign")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements_path)
        .arg(destination)
        .output()
        .expect("run codesign");
    assert!(
        output.status.success(),
        "codesign failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_macwin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_macwin"))
        .args(args)
        .output()
        .expect("run macwin")
}

#[test]
fn t16_1_entitlement_audit_allows_only_runner_jit_entitlements() {
    let runner_xml = r#"<?xml version="1.0"?><plist><dict>
        <key>com.apple.security.cs.allow-jit</key><true/>
        <key>com.apple.security.cs.allow-unsigned-executable-memory</key><false/>
    </dict></plist>"#;
    let helper_xml = r#"<?xml version="1.0"?><plist><dict>
        <key>com.apple.security.cs.allow-jit</key><false/>
        <key>com.apple.security.cs.allow-unsigned-executable-memory</key><false/>
    </dict></plist>"#;
    let report = audit_entitlement_targets(
        &[
            EntitlementAuditTarget {
                binary_name: "casa1-runner".to_string(),
                entitlements_xml: runner_xml.to_string(),
            },
            EntitlementAuditTarget {
                binary_name: "casa1-helper".to_string(),
                entitlements_xml: helper_xml.to_string(),
            },
            EntitlementAuditTarget {
                binary_name: "casa1".to_string(),
                entitlements_xml: helper_xml.to_string(),
            },
        ],
        "casa1-runner",
    )
    .expect("audit entitlement targets");
    assert!(report.approved);
    assert_eq!(report.jit_targets, vec!["casa1-runner"]);

    let rejected = audit_entitlement_targets(
        &[
            EntitlementAuditTarget {
                binary_name: "casa1-runner".to_string(),
                entitlements_xml: runner_xml.to_string(),
            },
            EntitlementAuditTarget {
                binary_name: "casa1-helper".to_string(),
                entitlements_xml: runner_xml.to_string(),
            },
        ],
        "casa1-runner",
    )
    .expect("audit rejected target");
    assert!(!rejected.approved);
    assert!(
        rejected
            .unexpected_targets
            .contains(&"casa1-helper".to_string())
    );
}

#[test]
fn t16_1_entitlement_audit_treats_metadata_only_codesign_output_as_empty_entitlements() {
    let report = audit_entitlement_targets(
        &[EntitlementAuditTarget {
            binary_name: "casa1-helper".to_string(),
            entitlements_xml:
                "Executable=/tmp/casa1-helper\nwarning: Specifying ':' in the path is deprecated\n"
                    .to_string(),
        }],
        "casa1-runner",
    )
    .expect("metadata-only codesign output should parse as empty entitlements");

    assert!(report.approved);
    assert!(report.jit_targets.is_empty());
    assert!(report.unexpected_targets.is_empty());
}

#[test]
fn t16_1_embedded_entitlement_audit_reads_actual_signed_binaries() {
    if !cfg!(target_os = "macos") {
        return;
    }

    let runner_xml = r#"<?xml version="1.0"?><plist><dict>
        <key>com.apple.security.cs.allow-jit</key><true/>
    </dict></plist>"#;
    let helper_xml = r#"<?xml version="1.0"?><plist><dict></dict></plist>"#;

    let directory = tempdir().expect("temporary directory");
    let source = std::env::current_exe().expect("current test binary");
    let runner = directory.path().join("casa1-runner");
    let helper = directory.path().join("casa1-helper");
    sign_binary_copy(&source, &runner, runner_xml);
    sign_binary_copy(&source, &helper, helper_xml);

    let report = audit_embedded_entitlements(&[runner.clone(), helper.clone()], "casa1-runner")
        .expect("audit embedded entitlements");
    assert!(report.approved);
    assert_eq!(report.jit_targets, vec!["casa1-runner"]);

    let bad_helper = directory.path().join("casa1-helper-bad");
    sign_binary_copy(&source, &bad_helper, runner_xml);
    let rejected = audit_embedded_entitlements(&[runner, bad_helper], "casa1-runner")
        .expect("audit rejected embedded entitlements");
    assert!(!rejected.approved);
    assert!(
        rejected
            .unexpected_targets
            .contains(&"casa1-helper-bad".to_string())
    );
}

#[test]
fn t16_1_entitlement_audit_cli_enforces_signed_binary_set_end_to_end() {
    if !cfg!(target_os = "macos") {
        return;
    }

    let runner_xml = r#"<?xml version="1.0"?><plist><dict>
        <key>com.apple.security.cs.allow-jit</key><true/>
    </dict></plist>"#;
    let helper_xml = r#"<?xml version="1.0"?><plist><dict></dict></plist>"#;

    let directory = tempdir().expect("temporary directory");
    let source = std::env::current_exe().expect("current test binary");
    let runner = directory.path().join("casa1-runner");
    let helper = directory.path().join("casa1-helper");
    let helper_bad = directory.path().join("casa1-helper-bad");
    sign_binary_copy(&source, &runner, runner_xml);
    sign_binary_copy(&source, &helper, helper_xml);
    sign_binary_copy(&source, &helper_bad, runner_xml);

    let runner_arg = runner.display().to_string();
    let helper_arg = helper.display().to_string();
    let helper_bad_arg = helper_bad.display().to_string();

    let success = run_macwin(&[
        "security:audit-entitlements",
        "--jit-owner",
        "casa1-runner",
        "--binary",
        &runner_arg,
        "--binary",
        &helper_arg,
        "--require-approved",
    ]);
    assert!(
        success.status.success(),
        "audit success path failed: {}",
        String::from_utf8_lossy(&success.stderr)
    );
    let report: EntitlementAuditReport =
        serde_json::from_slice(&success.stdout).expect("parse entitlement audit report");
    assert!(report.approved);
    assert_eq!(report.jit_targets, vec!["casa1-runner"]);

    let rejected = run_macwin(&[
        "security:audit-entitlements",
        "--jit-owner",
        "casa1-runner",
        "--binary",
        &runner_arg,
        "--binary",
        &helper_bad_arg,
        "--require-approved",
    ]);
    assert!(!rejected.status.success());
    let error: ErrorResponse =
        serde_json::from_slice(&rejected.stderr).expect("parse entitlement audit error");
    assert_eq!(
        error.reason_code,
        ReasonCode::RcEntitlementAuditFailed.as_u32()
    );
    assert!(
        error
            .reproduction_hints
            .iter()
            .any(|hint| hint.contains("casa1-helper-bad"))
    );
}

#[test]
fn t16_2_sandbox_escape_suite_blocks_traversal_sensitive_paths_and_toctou() {
    let sandbox = FilesystemSandbox::new(
        "/Users/test/Casa1/GE",
        &["/Users/test/Documents".to_string()],
    );
    assert!(
        sandbox
            .authorize(
                "/Users/test/Casa1/GE/game/save.dat",
                "/Users/test/Casa1/GE/game/save.dat",
                "/Users/test/Casa1/GE/game/save.dat",
            )
            .is_ok()
    );
    assert!(
        sandbox
            .authorize(
                "/Users/test/Documents/mods/mod.zip",
                "/Users/test/Documents/mods/mod.zip",
                "/Users/test/Documents/mods/mod.zip",
            )
            .is_ok()
    );
    let traversal = sandbox
        .authorize(
            "../secret.txt",
            "/Users/test/Casa1/GE/../secret.txt",
            "/Users/test/Casa1/secret.txt",
        )
        .expect_err("traversal must fail");
    assert_eq!(traversal.code, ReasonCode::RcFsPathInvalid);
    let system = sandbox
        .authorize(
            "/System/Library/foo",
            "/System/Library/foo",
            "/System/Library/foo",
        )
        .expect_err("system path must fail");
    assert_eq!(system.code, ReasonCode::RcFsSandboxEscape);
    let other_home = sandbox
        .authorize(
            "/Users/other/Documents/secret.txt",
            "/Users/other/Documents/secret.txt",
            "/Users/other/Documents/secret.txt",
        )
        .expect_err("other user home must fail");
    assert_eq!(other_home.code, ReasonCode::RcFsSandboxEscape);
    let device = sandbox
        .authorize("/dev/disk0", "/dev/disk0", "/dev/disk0")
        .expect_err("device node must fail");
    assert_eq!(device.code, ReasonCode::RcFsSandboxEscape);
    let toctou = sandbox
        .authorize(
            "/Users/test/Casa1/GE/mods/live.link",
            "/Users/test/Casa1/GE/mods/live.link",
            "/Users/other/escape/link",
        )
        .expect_err("TOCTOU path swap must fail");
    assert_eq!(toctou.code, ReasonCode::RcFsSandboxEscape);
}

#[test]
fn t16_3_network_deny_mode_returns_stable_windows_unreachable_errors_and_logs() {
    let mut deny = NetworkPolicyEnforcer::new(NetworkProfile {
        policy: NetworkPolicy::DenyAll,
        whitelist: Vec::new(),
    });
    let error = deny
        .connect("api.example.com", "203.0.113.10")
        .expect_err("deny-all must block connect");
    assert_eq!(error.code, ReasonCode::RcNetworkUnreachable);
    assert_eq!(deny.last_winsock_error(), Some(10051));
    assert_eq!(deny.log()[0].winsock_error, Some(10051));

    let mut allow = NetworkPolicyEnforcer::new(NetworkProfile {
        policy: NetworkPolicy::AllowAll,
        whitelist: Vec::new(),
    });
    let _result = allow.connect("api.example.com", "203.0.113.10");
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");

    let mut whitelist = NetworkPolicyEnforcer::new(NetworkProfile {
        policy: NetworkPolicy::AllowOnlyWhitelist,
        whitelist: vec!["api.example.com".to_string(), "203.0.113.20".to_string()],
    });
    let _result = whitelist.connect("api.example.com", "203.0.113.10");
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    let _result = whitelist.connect("launcher.example.com", "203.0.113.20");
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    let _result = whitelist.connect("blocked.example.com", "203.0.113.99");
    assert!(_result.is_err(), "expected Err, got {_result:?}");
}

#[test]
fn t16_4_fuzz_regression_suite_classifies_permanent_inputs_and_crash_artifact_is_deterministic() {
    let msi_error = parse_msi_script(&load_fixture("msi_invalid"))
        .expect_err("MSI regression input must classify");
    assert_eq!(msi_error.code, ReasonCode::RcMsiInvalid);

    let media = MediaShim::new("C:/GEs/FuzzMedia");
    let media_error = media
        .parse_container(&load_fixture("media_truncated"))
        .expect_err("media regression input must classify");
    assert_eq!(media_error.code, ReasonCode::RcMediaInvalid);

    let http_error = parse_http_request(&load_fixture("http_invalid"))
        .expect_err("HTTP regression input must classify");
    assert_eq!(http_error.code, ReasonCode::RcNetworkProtocolInvalid);

    let pe_error =
        pe::parse(&load_fixture("pe_short")).expect_err("PE regression input must classify");
    assert_eq!(pe_error.code, ReasonCode::RcPeParseInvalid);

    let dxil_summary = shader::fuzz_summary(&load_fixture("dxil_short"));
    assert!(dxil_summary.starts_with("err:2101:"));

    let commands = nightly_sanitizer_commands("aarch64-apple-darwin");
    assert_eq!(commands.len(), 1);
    assert!(commands[0].contains("-Zsanitizer=address"));
    assert!(commands[0].contains("--test-threads=1"));

    let directory = tempdir().expect("temporary directory");
    let output = directory.path().join("crash.zip");
    let snapshot = CrashSnapshot {
        exception: GuestException {
            code: 0xC000_0005,
            addr: Some("0x140001000".to_string()),
            module: "game.exe".to_string(),
            tid: 42,
        },
        modules: vec![
            CrashModule {
                name: "game.exe".to_string(),
                base_address: 0x1400_0000,
            },
            CrashModule {
                name: "steam_api.dll".to_string(),
                base_address: 0x1800_0000,
            },
        ],
        threads: vec![CrashThread {
            tid: 42,
            stack: vec![
                "game.exe!Crash+0x10".to_string(),
                "kernel32!BaseThreadInitThunk".to_string(),
            ],
        }],
        host_stack: vec![
            "macwin!dispatch_runner".to_string(),
            "casa1-runner!execute_job".to_string(),
        ],
        log_lines: vec![
            "user email player@example.com".to_string(),
            "/Users/alice/Casa1/GE/game.log".to_string(),
            "last line".to_string(),
        ],
        applied_profile: BTreeMap::from([("gfx".to_string(), "default".to_string())]),
    };
    let summary = collect_crash_artifact(&snapshot, &output).expect("collect crash artifact");
    assert_eq!(
        summary.entries,
        vec![
            "artifact/exception.json",
            "artifact/host_stack.json",
            "artifact/log_tail.txt",
            "artifact/modules.json",
            "artifact/profile.json",
            "artifact/threads.json",
        ]
    );
    let file = fs::File::open(output).expect("open crash zip");
    let mut archive = zip::ZipArchive::new(file).expect("read crash zip");
    let log_tail = {
        let mut entry = archive
            .by_name("artifact/log_tail.txt")
            .expect("log tail entry");
        let mut text = String::new();
        use std::io::Read;
        entry.read_to_string(&mut text).expect("read log tail");
        text
    };
    assert!(!log_tail.contains("player@example.com"));
    assert!(!log_tail.contains("/Users/alice/"));
    assert!(log_tail.contains("<redacted-email>"));
    assert!(log_tail.contains("/Users/<redacted>/Casa1/GE/game.log"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t16_5 — Shader translation: resource bindings, samplers, push constants
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t16_5_shader_resource_binding_translation() {
    // Build a root signature with descriptor table entries for SRV, UAV, sampler
    // Root signature format: [count:u32][root_constants:u32][descriptors:6*N bytes]
    // descriptor = kind:u8 reg:u8 space:u8 desc_count:u8 arg_idx:u8 bind_idx:u8
    let root_sig = vec![
        0x03, 0x00, 0x00, 0x00, // 3 descriptors
        0x00, 0x00, 0x00, 0x00, // 0 root constants
        // SRV (kind=0): register 0, space 0, count 1, arg 0, bind 0
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        // UAV (kind=1): register 1, space 0, count 1, arg 0, bind 1
        0x01, 0x01, 0x00, 0x01, 0x00, 0x01,
        // Sampler (kind=2): register 0, space 0, count 1, arg 0, bind 2
        0x02, 0x00, 0x00, 0x01, 0x00, 0x02,
    ];
    let root_info = shader::parse_root_signature(&root_sig).expect("parse root sig");
    assert_eq!(root_info.descriptors.len(), 3);
    assert_eq!(root_info.root_constants_count, 0);

    let arg_bufs = shader::build_argument_buffers(&root_info);
    assert_eq!(arg_bufs.len(), 3);
    assert_eq!(arg_bufs[0].table_index, 0);
    assert_eq!(arg_bufs[0].binding_count, 1);
    assert_eq!(arg_bufs[0].bindings[0].register, 0);

    // Test root constants plan
    let plan = shader::RootConstantsPlan {
        constant_buffer_size: 32,
        binding_index: 0,
    };
    assert_eq!(plan.constant_buffer_size, 32);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t16_6 — DXIL parser: malformed container offsets / oversized chunks
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t16_6_dxil_parser_malformed_offsets() {
    // Too short (<12 bytes) — fails header check
    let too_short = b"DX";
    let result = shader::parse_dxil_container(too_short);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Magic only but no version/part count (exactly 4 bytes)
    let magic_only = b"DXIL";
    let result = shader::parse_dxil_container(magic_only);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // 12 bytes with valid magic but version != 1
    let bad_version = {
        let mut buf = Vec::from(b"DXIL");
        buf.extend_from_slice(&2u32.to_le_bytes()); // version = 2
        buf.extend_from_slice(&0u32.to_le_bytes()); // part count = 0
        buf
    };
    let result = shader::parse_dxil_container(&bad_version);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Part count of 0 should be rejected
    let zero_parts = {
        let mut buf = Vec::from(b"DXIL");
        buf.extend_from_slice(&1u32.to_le_bytes()); // version = 1
        buf.extend_from_slice(&0u32.to_le_bytes()); // part count = 0
        buf
    };
    let result = shader::parse_dxil_container(&zero_parts);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Part count exceeding MAX_PARTS (16) should be rejected
    let too_many_parts = {
        let mut buf = Vec::from(b"DXIL");
        buf.extend_from_slice(&1u32.to_le_bytes()); // version = 1
        buf.extend_from_slice(&20u32.to_le_bytes()); // part count = 20 (>16)
        buf
    };
    let result = shader::parse_dxil_container(&too_many_parts);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Part offset overlapping header region should be rejected
    let overlap_part = {
        let mut buf = Vec::from(b"DXIL");
        buf.extend_from_slice(&1u32.to_le_bytes()); // version = 1
        buf.extend_from_slice(&1u32.to_le_bytes()); // part count = 1
        // Part descriptor: kind="PROG", offset=0 (overlaps header), size=16
        buf.extend_from_slice(b"PROG");
        buf.extend_from_slice(&0u32.to_le_bytes()); // offset = 0 (bad)
        buf.extend_from_slice(&16u32.to_le_bytes()); // size = 16
        buf
    };
    let result = shader::parse_dxil_container(&overlap_part);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Verify existing fixture
    let fixture = load_fixture("dxil_short");
    let summary = shader::fuzz_summary(&fixture);
    assert!(summary.starts_with("err:"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t16_7 — GLSL translation error tests (via GlslToMslTranslator)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t16_7_glsl_translation_errors() {
    use casa1::vkgl::{GlslShaderStage, GlslToMslTranslator};

    // Empty source should still produce output
    let result = GlslToMslTranslator::translate("", GlslShaderStage::Vertex);
    assert!(result.is_ok(), "expected Ok, got {result:?}");

    // Basic vertex shader translation
    let vs_source = "void main() { gl_Position = vec4(0.0); }";
    let result = GlslToMslTranslator::translate(vs_source, GlslShaderStage::Vertex);
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let msl = result.unwrap();
    assert!(msl.contains("vertex"));

    // Fragment shader translation
    let fs_source = "void main() { gl_FragColor = vec4(1.0); }";
    let result = GlslToMslTranslator::translate(fs_source, GlslShaderStage::Fragment);
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let msl = result.unwrap();
    assert!(msl.contains("fragment"));

    // Shader with uniforms should translate uniform lines
    let uniform_source = "uniform float uTime; void main() {}";
    let result = GlslToMslTranslator::translate(uniform_source, GlslShaderStage::Vertex);
    assert!(result.is_ok(), "expected Ok, got {result:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t16_8 — Cbuffer packing and structured buffer packing
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t16_8_cbuffer_and_structured_packing() {
    use casa1::shader::{CbufferField, StructuredField};

    // Pack a simple cbuffer with scalar fields
    let fields = vec![
        CbufferField {
            name: "offsetA".into(),
            rows: 1,
            cols: 1,
            row_major: false,
            is_bool: false,
            array_len: 0,
        },
        CbufferField {
            name: "offsetB".into(),
            rows: 1,
            cols: 4,
            row_major: false,
            is_bool: false,
            array_len: 0,
        },
    ];
    let packed = shader::pack_cbuffer(&fields);
    assert_eq!(packed.fields.len(), 2);
    assert_eq!(packed.fields[0].name, "offsetA");
    assert_eq!(packed.fields[1].name, "offsetB");

    // Pack structured buffer fields
    let struct_fields = vec![
        StructuredField {
            name: "pos".into(),
            size_bytes: 12,
            alignment: 4,
        },
        StructuredField {
            name: "uv".into(),
            size_bytes: 8,
            alignment: 4,
        },
    ];
    let packing = shader::pack_structured_fields(&struct_fields);
    assert_eq!(packing.stride, 20);
}
