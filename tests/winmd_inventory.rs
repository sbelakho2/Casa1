//! Adversarial WinMD inventory tests: synthetic ECMA-335 metadata is emitted
//! at test time (no checked-in binaries) and parsed with the production reader.

mod winmd_fixture;

use casa1::api_database::ApiDatabase;
use casa1::reason::ReasonCode;
use casa1::util;
use casa1::winmd_inventory::{build_report, diff_against_registry, inventory_path, winmd_bytes};
use std::fs;
use std::process::Command;
use tempfile::TempDir;
use winmd_fixture::{BuiltWinmd, MethodSpec, TypeSpec, WinmdSpec, build};

fn fixture_spec() -> WinmdSpec {
    WinmdSpec {
        module_refs: vec!["KERNEL32.dll".to_string(), "notreal.dll".to_string()],
        types: vec![
            TypeSpec::api(
                "Windows.Win32.Foundation",
                vec![
                    MethodSpec::imported("CreateFileW", 0, "CreateFileW"),
                    MethodSpec::imported("NotModeled", 1, "Nope"),
                ],
            ),
            TypeSpec::interface(
                "Windows.Win32.Graphics.Direct3D11",
                "ID3D11Device",
                vec![
                    MethodSpec::plain("CreatePixelShader"),
                    MethodSpec::plain("BogusMethod"),
                ],
            ),
        ],
        ..WinmdSpec::default()
    }
}

fn assert_error(bytes: &[u8], code: ReasonCode, message: &str) {
    let error = winmd_bytes(bytes).expect_err("metadata must be rejected");
    assert_eq!(error.code, code);
    assert_eq!(error.message, message);
}

fn write_winmd(dir: &TempDir, name: &str, built: &BuiltWinmd) {
    fs::write(dir.path().join(name), &built.bytes).expect("write winmd fixture");
}

#[test]
fn winmd_inventory_rejects_malformed_and_truncated_metadata_exactly() {
    let built = build(&fixture_spec());

    assert_eq!(
        winmd_bytes(&[0u8])
            .expect_err("one byte is not a PE")
            .message,
        "invalid DOS signature"
    );
    assert_error(
        &[0u8],
        ReasonCode::RcPeParseInvalid,
        "invalid DOS signature",
    );

    let mut bad_pe = built.bytes.clone();
    let pe = u32::from_le_bytes([bad_pe[0x3c], bad_pe[0x3d], bad_pe[0x3e], bad_pe[0x3f]]) as usize;
    bad_pe[pe..pe + 4].copy_from_slice(b"NE\0\0");
    assert_error(
        &bad_pe,
        ReasonCode::RcPeParseInvalid,
        "PE signature missing",
    );

    let truncated = &built.bytes[..built.metadata_offset + 10];
    assert_error(
        truncated,
        ReasonCode::RcParserTruncated,
        "metadata directory exceeds file size",
    );

    let mut short_metadata = built.bytes.clone();
    short_metadata[built.clr_offset + 12..built.clr_offset + 16]
        .copy_from_slice(&8u32.to_le_bytes());
    assert_error(
        &short_metadata,
        ReasonCode::RcParserTruncated,
        "metadata root exceeds metadata size",
    );

    let mut bad_version = built.bytes.clone();
    bad_version[built.metadata_offset + 12..built.metadata_offset + 16]
        .copy_from_slice(&0xffffu32.to_le_bytes());
    assert_error(
        &bad_version,
        ReasonCode::RcParserTruncated,
        "metadata stream header exceeds metadata size",
    );

    let mut bad_stream_offset = built.bytes.clone();
    bad_stream_offset[built.metadata_offset + built.root_header_offset
        ..built.metadata_offset + built.root_header_offset + 4]
        .copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert_error(
        &bad_stream_offset,
        ReasonCode::RcParserTruncated,
        "metadata stream exceeds metadata size",
    );

    let mut bad_count = built.bytes.clone();
    bad_count[built.tables_offset + 28..built.tables_offset + 32]
        .copy_from_slice(&0xffffu32.to_le_bytes());
    assert_error(
        &bad_count,
        ReasonCode::RcParserTruncated,
        "metadata table rows exceed stream size",
    );

    let mut unsupported_table = built.bytes.clone();
    let valid_offset = built.tables_offset + 8;
    let mut valid = u64::from_le_bytes(
        unsupported_table[valid_offset..valid_offset + 8]
            .try_into()
            .expect("valid mask"),
    );
    valid |= 1u64 << 45;
    unsupported_table[valid_offset..valid_offset + 8].copy_from_slice(&valid.to_le_bytes());
    assert_error(
        &unsupported_table,
        ReasonCode::RcInputUnsupported,
        "unsupported metadata table",
    );

    let mut missing_tables = built.bytes.clone();
    let name_offset = built.metadata_offset + built.root_header_offset + 8;
    missing_tables[name_offset..name_offset + 2].copy_from_slice(b"#X");
    assert_error(
        &missing_tables,
        ReasonCode::RcInputUnsupported,
        "missing #~ metadata table stream",
    );
}

#[test]
fn winmd_missing_type_tables_yield_empty_universe_without_phantom_coverage() {
    let built = build(&WinmdSpec::default());
    let parsed = winmd_bytes(&built.bytes).expect("module-only metadata is valid");
    assert_eq!(parsed.assembly.as_deref(), Some("Fixture.Winmd"));
    assert_eq!(parsed.types.len(), 0);
    assert_eq!(parsed.functions.len(), 0);

    let dir = TempDir::new().expect("temp dir");
    write_winmd(&dir, "empty.winmd", &built);
    let universe = inventory_path(dir.path()).expect("inventory");
    assert_eq!(universe.type_count, 0);
    assert_eq!(universe.function_count, 0);
    assert_eq!(universe.interface_count, 0);
    assert_eq!(universe.duplicate_type_count, 0);
    assert_eq!(universe.errors.len(), 0);
}

#[test]
fn winmd_duplicate_types_and_functions_collapse_deterministically() {
    let spec = WinmdSpec {
        module_refs: vec!["KERNEL32.dll".to_string()],
        types: vec![TypeSpec::api(
            "Windows.Win32.Foundation",
            vec![MethodSpec::imported("CreateFileW", 0, "CreateFileW")],
        )],
        ..WinmdSpec::default()
    };
    let built = build(&spec);
    let dir = TempDir::new().expect("temp dir");
    write_winmd(&dir, "a.winmd", &built);
    write_winmd(&dir, "b.winmd", &built);

    let universe = inventory_path(dir.path()).expect("inventory");
    assert_eq!(universe.winmd_file_count, 2);
    assert_eq!(universe.type_count, 1);
    assert_eq!(universe.duplicate_type_count, 1);
    assert_eq!(universe.function_count, 1);
    assert_eq!(universe.functions[0].export, "CreateFileW");
    assert_eq!(universe.modules.len(), 1);
    assert_eq!(universe.modules[0].function_count, 1);

    let first = serde_json::to_string(&universe).expect("encode");
    let second = inventory_path(dir.path()).expect("inventory again");
    assert_eq!(first, serde_json::to_string(&second).expect("encode again"));
}

#[test]
fn winmd_unknown_signature_blobs_do_not_corrupt_method_names() {
    let spec = WinmdSpec {
        module_refs: vec!["KERNEL32.dll".to_string()],
        types: vec![TypeSpec::api(
            "Windows.Win32.Foundation",
            vec![MethodSpec {
                name: "WeirdSignature".to_string(),
                signature: vec![0xff, 0xfe, 0xfd, 0x00, 0x42],
                import: Some(winmd_fixture::ImportSpec {
                    module_ref: 0,
                    name: "WeirdExport".to_string(),
                }),
            }],
        )],
        ..WinmdSpec::default()
    };
    let built = build(&spec);
    let parsed = winmd_bytes(&built.bytes).expect("opaque signatures are tolerated");
    assert_eq!(parsed.types.len(), 1);
    assert_eq!(parsed.types[0].methods, vec!["WeirdSignature".to_string()]);
    assert_eq!(parsed.functions.len(), 1);
    assert_eq!(parsed.functions[0].export, "WeirdExport");
    assert_eq!(parsed.functions[0].method, "WeirdSignature");
}

#[test]
fn winmd_diff_reports_missing_modules_interfaces_and_extra_registry_rows() {
    let built = build(&fixture_spec());
    let dir = TempDir::new().expect("temp dir");
    write_winmd(&dir, "fixture.winmd", &built);
    let universe = inventory_path(dir.path()).expect("inventory");
    let database = ApiDatabase::from_thunk_metadata();
    let diff = diff_against_registry(&universe, &database);

    assert_eq!(diff.summary.metadata_function_count, 2);
    assert_eq!(diff.summary.modeled_function_count, 1);
    assert_eq!(diff.summary.missing_function_count, 1);
    assert_eq!(diff.missing_exports.len(), 1);
    assert_eq!(diff.missing_exports[0].export, "Nope");
    assert_eq!(diff.missing_exports[0].module, "notreal.dll");
    assert_eq!(diff.missing_exports[0].canonical_module, "notreal");
    assert_eq!(diff.missing_exports[0].type_name, "Apis");
    assert_eq!(diff.missing_exports[0].method, "NotModeled");

    assert_eq!(diff.modules.len(), 2);
    let kernel = diff
        .modules
        .iter()
        .find(|module| module.canonical_module == "kernel32")
        .expect("kernel32 module");
    assert_eq!(kernel.function_count, 1);
    assert_eq!(kernel.modeled_function_count, 1);
    assert_eq!(kernel.missing_function_count, 0);
    assert_eq!(diff.summary.missing_module_count, 1);

    assert_eq!(diff.types.len(), 1);
    assert_eq!(diff.types[0].type_name, "Apis");
    assert_eq!(diff.types[0].missing_function_count, 1);

    assert_eq!(
        diff.extra_registry_exports
            .iter()
            .filter(|row| row.export == "CloseHandle")
            .count(),
        1
    );
    assert_eq!(
        diff.extra_registry_exports
            .iter()
            .filter(|row| row.export == "CreateFileW")
            .count(),
        0
    );

    assert_eq!(diff.summary.interface_count, 1);
    assert_eq!(diff.summary.fully_modeled_interface_count, 0);
    assert_eq!(diff.summary.partially_modeled_interface_count, 1);
    assert_eq!(diff.summary.missing_interface_count, 0);
    assert_eq!(diff.missing_interface_methods.len(), 1);
    assert_eq!(diff.missing_interface_methods[0].interface, "ID3D11Device");
    assert_eq!(diff.missing_interface_methods[0].method, "BogusMethod");
    assert!(diff.missing_interface_methods[0].interface_known);
    assert_eq!(
        diff.extra_registry_interface_methods
            .iter()
            .filter(|row| row.interface == "ID3D11Device" && row.method == "CreateBuffer")
            .count(),
        1
    );
}

#[test]
fn winmd_report_has_no_mismatch_across_two_runs() {
    let built = build(&fixture_spec());
    let dir = TempDir::new().expect("temp dir");
    write_winmd(&dir, "fixture.winmd", &built);
    let database = ApiDatabase::from_thunk_metadata();
    let first = build_report(dir.path(), &database).expect("first report");
    let second = build_report(dir.path(), &database).expect("second report");
    assert_eq!(
        serde_json::to_string(&first).expect("encode first"),
        serde_json::to_string(&second).expect("encode second")
    );
    assert_eq!(
        first.universe.metadata_fingerprint,
        second.universe.metadata_fingerprint
    );
    assert_eq!(first.universe.winmd_file_count, 1);
    assert_eq!(
        first.universe.files[0].sha256,
        util::sha256_bytes(&built.bytes)
    );
    assert_eq!(
        first.diff.summary.metadata_function_count,
        second.diff.summary.metadata_function_count
    );
}

#[test]
fn winmd_empty_directory_rejects_phantom_coverage() {
    let dir = TempDir::new().expect("temp dir");
    let universe = inventory_path(dir.path()).expect("empty inventory");
    assert_eq!(universe.winmd_file_count, 0);
    assert_eq!(universe.type_count, 0);
    assert_eq!(universe.function_count, 0);
    assert_eq!(universe.interface_count, 0);
    assert_eq!(universe.errors.len(), 0);
    assert_eq!(universe.metadata_fingerprint, util::sha256_bytes(b""));
}

#[test]
fn winmd_cli_rejects_missing_and_conflicting_inventory_inputs() {
    let dir = TempDir::new().expect("temp dir");
    let out = dir.path().join("out.json");
    let oracle = env!("CARGO_BIN_EXE_casa1-oracle");

    let missing = Command::new(oracle)
        .args(["inventory", "--winmd"])
        .arg(dir.path().join("absent"))
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run oracle");
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&missing.stderr).contains("RC_FS_NOT_FOUND"),
        true
    );
    assert_eq!(out.exists(), false);

    let conflict = Command::new(oracle)
        .args(["inventory", "--pe-dir", ".", "--winmd", ".", "--out"])
        .arg(&out)
        .output()
        .expect("run oracle");
    assert_eq!(conflict.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&conflict.stderr).trim(),
        "inventory: --pe-dir and --winmd are mutually exclusive"
    );

    let neither = Command::new(oracle)
        .args(["inventory", "--out"])
        .arg(&out)
        .output()
        .expect("run oracle");
    assert_eq!(neither.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&neither.stderr).trim(),
        "inventory: one of --pe-dir or --winmd is required"
    );
}

#[test]
fn winmd_directory_records_malformed_file_without_aborting() {
    let dir = TempDir::new().expect("temp dir");
    write_winmd(&dir, "good.winmd", &build(&fixture_spec()));
    fs::write(dir.path().join("bad.winmd"), b"not a winmd").expect("write bad metadata");
    fs::write(dir.path().join("ignored.txt"), b"not metadata").expect("write text");
    let universe = inventory_path(dir.path()).expect("inventory walk");
    assert_eq!(universe.winmd_file_count, 2);
    assert_eq!(universe.files.len(), 1);
    assert_eq!(universe.errors.len(), 1);
    assert_eq!(universe.errors[0].path, "bad.winmd");
    assert_eq!(universe.errors[0].reason_code, 2000);
    assert_eq!(universe.errors[0].reason_name, "RC_PE_PARSE_INVALID");
    assert_eq!(universe.errors[0].message, "invalid DOS signature");
}
