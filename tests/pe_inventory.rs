//! Real PE inventory tests: synthetic PE32/PE32+ fixtures are emitted at test
//! time (no checked-in binaries) and parsed with the production `pe` parser.

mod pe_fixture;

use casa1::api_database::ApiDatabase;
use casa1::pe_inventory::{
    InventorySymbol, build_report, canonical_dll, diff_against_registry, inventory_bytes,
    inventory_directory,
};
use casa1::reason::ReasonCode;
use casa1::util;
use pe_fixture::{ExportSpec, ImportSpec, ImportSymbolSpec, PeSpec, build, call_iat_then_exit};
use std::fs;
use tempfile::TempDir;

fn write_module(
    dir: &TempDir,
    relative: &str,
    spec: &PeSpec,
) -> casa1::pe_inventory::InventoryModule {
    let path = dir.path().join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture dir");
    }
    let built = build(spec);
    fs::write(&path, &built.bytes).expect("write fixture PE");
    inventory_bytes(
        relative,
        &util::sha256_bytes(&built.bytes),
        built.bytes.len() as u64,
        &built.bytes,
    )
    .expect("parse fixture PE")
}

#[test]
fn inventory_rejects_malformed_pe_while_accepting_pe32_and_pe32plus() {
    let pe32 = PeSpec {
        pe32plus: false,
        ..PeSpec::default()
    };
    let built32 = build(&pe32);
    let module32 = inventory_bytes("x86.dll", "h32", built32.bytes.len() as u64, &built32.bytes)
        .expect("PE32 must parse");
    assert_eq!(module32.format, "PE32");
    assert_eq!(module32.machine, 0x014c);

    let pe64 = PeSpec::default();
    let built64 = build(&pe64);
    let module64 = inventory_bytes("x64.dll", "h64", built64.bytes.len() as u64, &built64.bytes)
        .expect("PE32+ must parse");
    assert_eq!(module64.format, "PE32+");
    assert_eq!(module64.machine, 0x8664);

    let error = inventory_bytes("bad.exe", "bad", 6, b"notpe").expect_err("must reject DOS junk");
    assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
    assert_eq!(error.message, "invalid DOS signature");
}

#[test]
fn inventory_reports_truncated_pe_with_exact_parser_error() {
    let built = build(&PeSpec::default());
    let truncated = &built.bytes[..0x50];
    let error = inventory_bytes("truncated.exe", "t", truncated.len() as u64, truncated)
        .expect_err("must reject truncated headers");
    assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
    assert_eq!(error.message, "NT headers exceeds file size");
}

#[test]
fn inventory_rejects_name_assumption_for_ordinal_only_and_forwarded_exports() {
    let spec = PeSpec {
        exports: vec![
            ExportSpec {
                ordinal: 5,
                name: None,
                forwarder: None,
                rva: Some(0x1500),
            },
            ExportSpec {
                ordinal: 6,
                name: Some("Named".to_string()),
                forwarder: None,
                rva: Some(0x1500),
            },
            ExportSpec {
                ordinal: 7,
                name: Some("Forwarded".to_string()),
                forwarder: Some("KERNELBASE.Sleep".to_string()),
                rva: None,
            },
        ],
        ..PeSpec::default()
    };
    let built = build(&spec);
    let module = inventory_bytes("exports.dll", "e", built.bytes.len() as u64, &built.bytes)
        .expect("parse exports");
    assert_eq!(module.exports.len(), 3);
    let ordinal_only = module
        .exports
        .iter()
        .find(|export| export.ordinal == 5)
        .expect("ordinal-only export");
    assert_eq!(ordinal_only.name, None);
    assert_eq!(ordinal_only.rva, Some(0x1500));
    assert_eq!(ordinal_only.forwarder, None);
    let forwarded = module
        .exports
        .iter()
        .find(|export| export.ordinal == 7)
        .expect("forwarded export");
    assert_eq!(forwarded.name.as_deref(), Some("Forwarded"));
    assert_eq!(forwarded.forwarder.as_deref(), Some("KERNELBASE.Sleep"));
    assert_eq!(forwarded.rva, None);
}

#[test]
fn inventory_distinguishes_delay_load_from_eager_imports_without_mismatch() {
    let spec = PeSpec {
        imports: vec![
            ImportSpec {
                dll: "kernel32.dll".to_string(),
                delay_load: false,
                symbols: vec![ImportSymbolSpec::Name("CreateFileW".to_string())],
            },
            ImportSpec {
                dll: "user32.dll".to_string(),
                delay_load: true,
                symbols: vec![
                    ImportSymbolSpec::Name("MessageBoxW".to_string()),
                    ImportSymbolSpec::Ordinal(17),
                ],
            },
        ],
        ..PeSpec::default()
    };
    let built = build(&spec);
    let module = inventory_bytes("imports.exe", "i", built.bytes.len() as u64, &built.bytes)
        .expect("parse imports");
    assert_eq!(module.imports.len(), 2);
    let eager = module
        .imports
        .iter()
        .find(|import| import.dll == "kernel32.dll")
        .expect("eager import");
    assert!(!eager.delay_load);
    let delayed = module
        .imports
        .iter()
        .find(|import| import.dll == "user32.dll")
        .expect("delay import");
    assert!(delayed.delay_load);
    assert!(matches!(
        &delayed.symbols[0],
        InventorySymbol::Name { name, .. } if name == "MessageBoxW"
    ));
    assert!(
        delayed
            .symbols
            .iter()
            .any(|symbol| matches!(symbol, InventorySymbol::Ordinal { ordinal } if *ordinal == 17))
    );
}

#[test]
fn inventory_empty_directory_rejects_phantom_coverage() {
    let dir = TempDir::new().expect("temp dir");
    let inventory = inventory_directory(dir.path()).expect("empty inventory");
    assert_eq!(inventory.pe_file_count, 0);
    assert_eq!(inventory.modules.len(), 0);
    assert_eq!(inventory.errors.len(), 0);
    assert_eq!(inventory.corpus_fingerprint, util::sha256_bytes(b""));
}

#[test]
fn inventory_directory_records_malformed_pe_instead_of_aborting() {
    let dir = TempDir::new().expect("temp dir");
    let valid = build(&PeSpec::default());
    fs::write(dir.path().join("good.exe"), &valid.bytes).expect("write good");
    fs::write(dir.path().join("malformed.exe"), b"MZ truncated").expect("write malformed");
    fs::write(dir.path().join("ignored.txt"), b"not a PE").expect("write text");
    let inventory = inventory_directory(dir.path()).expect("inventory walk");
    assert_eq!(inventory.pe_file_count, 2);
    assert_eq!(inventory.modules.len(), 1);
    assert_eq!(inventory.modules[0].path, "good.exe");
    assert_eq!(inventory.errors.len(), 1);
    assert_eq!(inventory.errors[0].path, "malformed.exe");
    assert_eq!(inventory.errors[0].reason_code, 2000);
    assert_eq!(inventory.errors[0].reason_name, "RC_PE_PARSE_INVALID");
}

#[test]
fn inventory_diff_reports_missing_and_extra_symbols_exactly() {
    let dir = TempDir::new().expect("temp dir");
    let spec = PeSpec {
        imports: vec![
            ImportSpec {
                dll: "kernel32.dll".to_string(),
                delay_load: false,
                symbols: vec![ImportSymbolSpec::Name("CreateFileW".to_string())],
            },
            ImportSpec {
                dll: "notreal.dll".to_string(),
                delay_load: false,
                symbols: vec![ImportSymbolSpec::Name("Nope".to_string())],
            },
        ],
        ..PeSpec::default()
    };
    let built = build(&spec);
    let path = dir.path().join("titles/sample.exe");
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(&path, &built.bytes).expect("write");
    let inventory = inventory_directory(dir.path()).expect("inventory");
    let database = ApiDatabase::from_thunk_metadata();
    let diff = diff_against_registry(&inventory, &database);

    assert_eq!(diff.summary.imported_symbol_count, 2);
    assert_eq!(diff.summary.modeled_import_count, 1);
    assert_eq!(diff.summary.unmodeled_import_count, 1);
    assert_eq!(diff.unmodeled_imports.len(), 1);
    let unmodeled = &diff.unmodeled_imports[0];
    assert_eq!(unmodeled.dll, "notreal.dll");
    assert_eq!(unmodeled.canonical_dll, "notreal");
    assert_eq!(unmodeled.symbol, "Nope");
    assert_eq!(unmodeled.symbol_kind, "name");
    assert_eq!(unmodeled.resolution_note, None);
    assert_eq!(unmodeled.modules, vec!["titles/sample.exe".to_string()]);

    assert!(diff.unimported_registry_rows.iter().any(|row| {
        row.dll.eq_ignore_ascii_case("kernel32.dll") && row.export == "CloseHandle"
    }));
    assert!(!diff.unimported_registry_rows.iter().any(|row| {
        row.dll.eq_ignore_ascii_case("kernel32.dll") && row.export == "CreateFileW"
    }));
    assert_eq!(diff.summary.parse_error_count, 0);
}

#[test]
fn inventory_diff_resolves_api_set_alias_without_false_unmodeled_error() {
    let dir = TempDir::new().expect("temp dir");
    let spec = PeSpec {
        imports: vec![ImportSpec {
            dll: "api-ms-win-core-file-l1-1-0.dll".to_string(),
            delay_load: false,
            symbols: vec![ImportSymbolSpec::Name("CreateFileW".to_string())],
        }],
        ..PeSpec::default()
    };
    let built = build(&spec);
    fs::write(dir.path().join("alias.exe"), &built.bytes).expect("write");
    let inventory = inventory_directory(dir.path()).expect("inventory");
    let database = ApiDatabase::from_thunk_metadata();
    let diff = diff_against_registry(&inventory, &database);

    assert_eq!(diff.summary.unmodeled_import_count, 0);
    assert_eq!(diff.summary.modeled_import_count, 1);
    assert_eq!(diff.summary.alias_count, 1);
    assert_eq!(diff.aliases[0].observed, "api-ms-win-core-file-l1-1-0.dll");
    assert_eq!(diff.aliases[0].resolved, "kernel32.dll");
    assert_eq!(diff.aliases[0].kind, "api_set");
    assert_eq!(canonical_dll("KERNEL32.DLL"), canonical_dll("kernel32"));
}

#[test]
fn inventory_report_never_mismatches_across_repeated_walks() {
    let dir = TempDir::new().expect("temp dir");
    let _ = write_module(
        &dir,
        "a/one.dll",
        &PeSpec {
            exports: vec![ExportSpec {
                ordinal: 1,
                name: Some("Alpha".to_string()),
                forwarder: None,
                rva: Some(0x1500),
            }],
            ..PeSpec::default()
        },
    );
    let nested = dir.path().join("a");
    fs::create_dir_all(&nested).expect("nested");
    let import_spec = PeSpec {
        imports: vec![ImportSpec {
            dll: "kernel32.dll".to_string(),
            delay_load: false,
            symbols: vec![ImportSymbolSpec::Name("CreateFileW".to_string())],
        }],
        ..PeSpec::default()
    };
    let built = build(&import_spec);
    let mut patched = built.bytes.clone();
    let iat = built.iat_rvas[0].2;
    pe_fixture::patch_text(&mut patched, &call_iat_then_exit(iat));
    fs::write(nested.join("two.exe"), &patched).expect("write second");

    let database = ApiDatabase::from_thunk_metadata();
    let first = build_report(dir.path(), &database).expect("first report");
    let second = build_report(dir.path(), &database).expect("second report");
    assert_eq!(
        serde_json::to_string(&first).expect("json"),
        serde_json::to_string(&second).expect("json")
    );
    assert_eq!(first.inventory.modules.len(), 2);
    assert_eq!(first.diff.summary.parse_error_count, 0);
}
