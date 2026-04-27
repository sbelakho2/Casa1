mod support;

use casa1::pe::{
    self, ApiSetResolver, DelayLoadOutcome, ExportSymbol, ExportTarget, ImportSymbol, ImportThunk,
    LifecycleStage,
};
use casa1::oracle_model::{
    ApiSetSuite, DelayLoadCase, DelayLoadExpectation, DelayLoadSuite, DelayLoadSymbol,
    DllOrderSuite, ExportSpec, ExportSpecTarget,
};
use casa1::reason::ReasonCode;
use std::collections::BTreeMap;
use std::fs;
use tempfile::TempDir;

#[test]
fn pe_parser_validates_headers_directories_load_config_and_resources() {
    let bytes = support::sample_pe_bytes();
    let image = pe::parse(&bytes).expect("parse synthetic PE32+ fixture");

    assert_eq!(image.machine, 0x8664);
    assert_eq!(image.sections.len(), 5);
    assert!(image.directory(pe::IMAGE_DIRECTORY_ENTRY_IMPORT).virtual_address > 0);
    assert!(image.directory(pe::IMAGE_DIRECTORY_ENTRY_EXPORT).virtual_address > 0);
    assert!(image.directory(pe::IMAGE_DIRECTORY_ENTRY_RESOURCE).virtual_address > 0);
    assert!(image.directory(pe::IMAGE_DIRECTORY_ENTRY_TLS).virtual_address > 0);
    assert!(image.directory(pe::IMAGE_DIRECTORY_ENTRY_DEBUG).virtual_address > 0);
    assert!(image.directory(pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG).virtual_address > 0);

    let load_config = image.load_config.as_ref().expect("load config present");
    assert_eq!(load_config.guard_flags, 0x500);
    assert_eq!(load_config.se_handler_count, 1);
    assert_eq!(image.debug_entries.len(), 1);
    assert_eq!(image.version_info.product_name.as_deref(), Some("Casa1 Demo"));
    assert_eq!(image.version_info.file_version.as_deref(), Some("1.2.3.4"));

    let manifest = image.embedded_manifest.expect("embedded manifest present");
    assert_eq!(manifest.dpi_awareness.as_deref(), Some("PerMonitorV2"));
    assert!(manifest
        .supported_os
        .iter()
        .any(|value| value == "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"));
}

#[test]
fn pe32_parser_accepts_32_bit_optional_headers_and_mapping() {
    let bytes = support::sample_pe32_bytes();
    let image = pe::parse(&bytes).expect("parse synthetic PE32 fixture");

    assert_eq!(image.machine, 0x014c);
    assert_eq!(image.pointer_bytes(), 4);
    assert_eq!(image.image_base, support::SAMPLE_IMAGE_BASE_X86);
    assert_eq!(image.imports[0].imports[1].iat_rva - image.imports[0].imports[0].iat_rva, 4);

    let load_config = image.load_config.as_ref().expect("load config present");
    assert_eq!(load_config.guard_flags, 0x500);
    assert_eq!(load_config.se_handler_count, 1);

    let tls_directory = image.tls_directory.as_ref().expect("TLS directory present");
    assert_eq!(
        tls_directory.callbacks,
        vec![support::SAMPLE_IMAGE_BASE_X86 + support::SAMPLE_TLS_CALLBACK_RVA as u64]
    );

    let mapped = pe::map_image(&bytes, &image, support::SAMPLE_HASH, true)
        .expect("map deterministic PE32 image");
    assert!(mapped.selected_base <= u32::MAX as u64);

    let relocated = u32::from_le_bytes(
        mapped.memory[support::SAMPLE_RELOC_TARGET_RVA as usize..support::SAMPLE_RELOC_TARGET_RVA as usize + 4]
            .try_into()
            .expect("relocated dword"),
    );
    assert_eq!(relocated as u64, mapped.selected_base + 0x1234);
}

#[test]
fn mapping_relocations_and_deterministic_aslr_work() {
    let bytes = support::sample_pe_bytes();
    let image = pe::parse(&bytes).expect("parse synthetic PE32+ fixture");

    let mapped_a = pe::map_image(&bytes, &image, support::SAMPLE_HASH, true)
        .expect("map deterministic image");
    let mapped_b = pe::map_image(&bytes, &image, support::SAMPLE_HASH, true)
        .expect("map deterministic image twice");
    assert_eq!(mapped_a.selected_base, mapped_b.selected_base);
    assert_ne!(mapped_a.selected_base, image.image_base);

    let nondtm_base = pe::select_image_base(&image, support::SAMPLE_HASH, false);
    assert_ne!(mapped_a.selected_base, nondtm_base);

    let text = mapped_a
        .sections
        .iter()
        .find(|section| section.name == ".text")
        .expect("text section mapping");
    assert!(text.protection.read);
    assert!(text.protection.execute);
    assert!(!text.protection.write);

    let data = mapped_a
        .sections
        .iter()
        .find(|section| section.name == ".data")
        .expect("data section mapping");
    assert!(data.protection.read);
    assert!(data.protection.write);
    assert!(!data.protection.execute);

    let relocated = u64::from_le_bytes(
        mapped_a.memory[support::SAMPLE_RELOC_TARGET_RVA as usize..support::SAMPLE_RELOC_TARGET_RVA as usize + 8]
            .try_into()
            .expect("relocated qword"),
    );
    assert_eq!(relocated, mapped_a.selected_base + 0x1234);

    let mut unsupported_relocation = image.clone();
    unsupported_relocation.relocations[0].entries[0].kind = pe::RelocationType::Unsupported(7);
    let relocation_error = pe::map_image(&bytes, &unsupported_relocation, support::SAMPLE_HASH, true)
        .expect_err("unsupported relocation should fail deterministically");
    assert_eq!(relocation_error.code, ReasonCode::RcPeParseInvalid);
}

#[test]
fn imports_exports_forwarders_delay_loads_and_api_sets_resolve() {
    let bytes = support::sample_pe_bytes();
    let image = pe::parse(&bytes).expect("parse synthetic PE32+ fixture");

    assert_eq!(image.imports.len(), 1);
    assert_eq!(image.delay_imports.len(), 1);
    assert_eq!(image.imports[0].dll_name, "api-ms-win-core-file-l1-1-0.dll");
    assert_eq!(image.imports[0].imports.len(), 2);
    assert_eq!(image.delay_imports[0].dll_name, "kernel32.dll");
    assert_eq!(image.delay_imports[0].imports.len(), 1);

    let forwarded_export = image
        .exports
        .iter()
        .find(|export| export.name.as_deref() == Some("Forwarded"))
        .expect("forwarded export parsed");
    assert_eq!(
        forwarded_export.target,
        ExportTarget::Forwarder("KERNELBASE.Sleep".to_string())
    );

    let export_tables = BTreeMap::from([
        (
            "kernel32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 17,
                    name: Some("CreateFileW".to_string()),
                    target: ExportTarget::Rva(0x1500),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("Forwarded".to_string()),
                    target: ExportTarget::Forwarder("KERNELBASE.Sleep".to_string()),
                },
            ],
        ),
        (
            "kernelbase.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("Sleep".to_string()),
                target: ExportTarget::Rva(0x2500),
            }],
        ),
    ]);
    let resolver = ApiSetResolver::new().with_mapping(
        "api-ms-win-core-file-l1-1-0.dll",
        "kernel32.dll",
    );
    let resolved = pe::resolve_imports(&image, &export_tables, &resolver)
        .expect("resolve imports and forwarders");
    assert_eq!(resolved.len(), 3);

    let missing_import_provider = pe::resolve_imports(&image, &BTreeMap::new(), &resolver)
        .expect_err("missing eager import provider should fail");
    assert_eq!(missing_import_provider.code, ReasonCode::RcImportMissing);

    let create_file = resolved
        .iter()
        .find(|import| import.symbol == ImportSymbol::ByName {
            hint: 0,
            name: "CreateFileW".to_string(),
        })
        .expect("CreateFileW resolved");
    assert_eq!(create_file.resolved_module, "kernel32.dll");
    assert_ne!(create_file.iat_rva, 0);
    assert_eq!(create_file.export.target, ExportTarget::Rva(0x1500));

    let ordinal = resolved
        .iter()
        .find(|import| import.symbol == ImportSymbol::ByOrdinal { ordinal: 17 })
        .expect("ordinal 17 resolved");
    assert_eq!(ordinal.export.ordinal, 17);

    let forwarded = resolved
        .iter()
        .find(|import| import.symbol == ImportSymbol::ByName {
            hint: 0,
            name: "Forwarded".to_string(),
        })
        .expect("forwarded delay import resolved");
    assert_eq!(forwarded.export.target, ExportTarget::Rva(0x2500));

    let delay_loads = pe::resolve_delay_imports(&image, &export_tables, &resolver)
        .expect("resolve delay-load thunking");
    assert_eq!(delay_loads.len(), 1);
    assert_eq!(
        delay_loads[0].outcome,
        DelayLoadOutcome::Resolved(ExportSymbol {
            ordinal: 1,
            name: Some("Sleep".to_string()),
            target: ExportTarget::Rva(0x2500),
        })
    );

    let missing_provider = pe::resolve_delay_imports(&image, &BTreeMap::new(), &resolver)
        .expect("encode missing provider as Windows delay-load exception");
    assert_eq!(
        missing_provider[0].outcome,
        DelayLoadOutcome::StructuredException {
            code: pe::STATUS_DLL_NOT_FOUND,
        }
    );

    let missing_entrypoint = pe::resolve_delay_imports(
        &image,
        &BTreeMap::from([("kernel32.dll".to_string(), Vec::new())]),
        &resolver,
    )
    .expect("encode missing symbol as Windows delay-load exception");
    assert_eq!(
        missing_entrypoint[0].outcome,
        DelayLoadOutcome::StructuredException {
            code: pe::STATUS_ENTRYPOINT_NOT_FOUND,
        }
    );
}

#[test]
fn t3_2_dll_ordering_matches_independent_oracle_logs() {
    let suite: DllOrderSuite = support::run_oracle("section3-dll-order");
    let plan = pe::plan_lifecycle(&suite.root_module, &suite.dependencies, &suite.tls_callbacks)
        .expect("build lifecycle plan from oracle suite");
    assert_eq!(support::lifecycle_log_lines(&plan), suite.expected_log_lines);
}

#[test]
fn t3_3_delay_load_exception_codes_match_independent_oracle() {
    let suite: DelayLoadSuite = support::run_oracle("section3-delay-load");
    let image = pe::parse(&support::sample_pe_bytes()).expect("parse synthetic PE32+ fixture");

    for case in suite.cases {
        let mut scenario_image = image.clone();
        scenario_image.imports.clear();
        scenario_image.delay_imports = vec![pe::ImportDescriptor {
            dll_name: case.requested_module.clone(),
            imports: vec![ImportThunk {
                symbol: delay_symbol_to_import_symbol(&case.symbol),
                iat_rva: 0x6000,
            }],
            delay_load: true,
        }];
        let export_tables = build_export_tables(&case);
        let results = pe::resolve_delay_imports(&scenario_image, &export_tables, &ApiSetResolver::new())
            .expect("resolve oracle delay-load case");
        assert_eq!(results.len(), 1);
        match &case.expected {
            DelayLoadExpectation::Resolved { export } => assert_eq!(
                results[0].outcome,
                DelayLoadOutcome::Resolved(export_spec_to_export_symbol(export))
            ),
            DelayLoadExpectation::StructuredException { code } => assert_eq!(
                results[0].outcome,
                DelayLoadOutcome::StructuredException { code: *code }
            ),
        }
    }
}

#[test]
fn t3_4_api_set_resolution_matches_independent_oracle() {
    let suite: ApiSetSuite = support::run_oracle("section3-apiset");
    let resolver = ApiSetResolver::new();
    for case in suite.cases {
        assert_eq!(resolver.resolve(&case.contract), case.expected_host);
    }
}

#[test]
fn lifecycle_and_manifest_activation_plans_cover_attach_detach_and_external_manifest() {
    let bytes = support::sample_pe_bytes();
    let image = pe::parse(&bytes).expect("parse synthetic PE32+ fixture");
    let tls_callbacks = BTreeMap::from([
        (
            "kernel32.dll".to_string(),
            vec![0x1800_2000],
        ),
        (
            "game.exe".to_string(),
            image
                .tls_directory
                .clone()
                .expect("TLS directory")
                .callbacks,
        ),
    ]);
    let dependencies = BTreeMap::from([
        (
            "game.exe".to_string(),
            vec!["kernel32.dll".to_string(), "user32.dll".to_string()],
        ),
        (
            "user32.dll".to_string(),
            vec!["gdi32.dll".to_string()],
        ),
        ("gdi32.dll".to_string(), Vec::new()),
        ("kernel32.dll".to_string(), Vec::new()),
    ]);
    let plan = pe::plan_lifecycle("game.exe", &dependencies, &tls_callbacks)
        .expect("build lifecycle plan");
    assert_eq!(
        plan.load_order,
        vec![
            "kernel32.dll".to_string(),
            "gdi32.dll".to_string(),
            "user32.dll".to_string(),
            "game.exe".to_string(),
        ]
    );
    assert_eq!(
        plan.process_attach.first().expect("attach event").stage,
        LifecycleStage::TlsProcessAttach(0x1800_2000)
    );
    assert_eq!(
        plan.process_attach[1].stage,
        LifecycleStage::DllMainProcessAttach
    );
    assert_eq!(
        plan.thread_start[0].stage,
        LifecycleStage::TlsThreadAttach(0x1800_2000)
    );
    assert_eq!(
        plan.thread_end.last().expect("thread-end event").stage,
        LifecycleStage::DllMainThreadDetach
    );
    assert_eq!(
        plan.process_detach.first().expect("detach event").module,
        "game.exe"
    );
    assert_eq!(
        plan.thread_start
            .iter()
            .filter(|event| event.stage == LifecycleStage::DllMainThreadAttach)
            .map(|event| event.module.clone())
            .collect::<Vec<_>>(),
        plan.load_order,
        "every loaded module should receive a thread-attach DllMain notification"
    );
    assert_eq!(
        plan.thread_end
            .iter()
            .filter(|event| event.stage == LifecycleStage::DllMainThreadDetach)
            .map(|event| event.module.clone())
            .collect::<Vec<_>>(),
        plan.load_order.iter().rev().cloned().collect::<Vec<_>>(),
        "every loaded module should receive a thread-detach DllMain notification in reverse order"
    );

    let activation = pe::build_activation_context(
        &image.embedded_manifest.clone().expect("embedded manifest"),
    );
    assert!(activation
        .vc_runtime_assemblies
        .iter()
        .any(|assembly| assembly.name == "Microsoft.VC143.CRT"));
    assert_eq!(activation.vc_runtime_bindings.len(), 1);
    assert_eq!(
        activation.vc_runtime_bindings[0].activation_key,
        "microsoft.vc143.crt|14.36.32532.0|amd64|1fc8b3b9a1e18e3b"
    );
    assert_eq!(
        activation.vc_runtime_bindings[0].dlls,
        vec![
            "concrt140.dll".to_string(),
            "msvcp140.dll".to_string(),
            "vcruntime140.dll".to_string(),
            "vcruntime140_1.dll".to_string(),
        ]
    );

    let temp_dir = TempDir::new().expect("temp dir");
    let exe_path = temp_dir.path().join("sample.exe");
    let manifest_path = temp_dir.path().join("sample.exe.manifest");
    fs::write(&exe_path, &bytes).expect("write sample PE");
    fs::write(&manifest_path, support::external_manifest_xml()).expect("write external manifest");
    let parsed_from_file = pe::parse_from_file(&exe_path).expect("parse PE from file");
    let external = parsed_from_file.external_manifest.expect("external manifest present");
    assert_eq!(external.dpi_awareness.as_deref(), Some("System"));
}

#[test]
fn pe_parser_mutation_corpus_is_deterministic_and_bounds_checked() {
    let seed = support::sample_pe_bytes();
    for index in 0..128_usize {
        let mutated = mutation_case(&seed, index);
        let first = parse_summary(&mutated);
        let second = parse_summary(&mutated);
        assert_eq!(first, second, "mutation case {index} produced nondeterministic parse results");
    }
}

fn mutation_case(seed: &[u8], index: usize) -> Vec<u8> {
    let mut mutated = seed.to_vec();
    match index % 8 {
        0 => {
            mutated.truncate(index.min(mutated.len()));
        }
        1 => {
            if !mutated.is_empty() {
                mutated[0] ^= index as u8;
            }
        }
        2 => {
            if mutated.len() > 0x3f {
                mutated[0x3c..0x40].copy_from_slice(&(0xffff_ff00_u32).to_le_bytes());
            }
        }
        3 => {
            if mutated.len() > 0x200 {
                mutated[0x18c..0x190].copy_from_slice(&(0xffff_ffff_u32).to_le_bytes());
            }
        }
        4 => {
            if mutated.len() > 0x180 {
                mutated[0x168..0x16c].copy_from_slice(&(0xffff_fff0_u32).to_le_bytes());
            }
        }
        5 => {
            if mutated.len() > 0x170 {
                mutated[0x170..0x174].copy_from_slice(&(0xffff_fff0_u32).to_le_bytes());
            }
        }
        6 => {
            if mutated.len() > 0x194 {
                mutated[0x194..0x198].copy_from_slice(&(0x7fff_ffff_u32).to_le_bytes());
            }
        }
        _ => {
            for offset in (index % 16)..mutated.len().min((index % 16) + 16) {
                mutated[offset] = mutated[offset].wrapping_add(index as u8);
            }
        }
    }
    mutated
}

fn parse_summary(bytes: &[u8]) -> String {
    match pe::parse(bytes) {
        Ok(image) => format!(
            "ok:{}:{}:{}:{}",
            image.sections.len(),
            image.imports.len(),
            image.exports.len(),
            image.relocations.len()
        ),
        Err(error) => format!("err:{}:{}", error.code.as_u32(), error.message),
    }
}

fn build_export_tables(case: &DelayLoadCase) -> BTreeMap<String, Vec<ExportSymbol>> {
    case.provider_exports
        .iter()
        .map(|(module, exports)| {
            (
                module.clone(),
                exports
                    .iter()
                    .map(export_spec_to_export_symbol)
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn delay_symbol_to_import_symbol(symbol: &DelayLoadSymbol) -> ImportSymbol {
    match symbol {
        DelayLoadSymbol::ByName { name } => ImportSymbol::ByName {
            hint: 0,
            name: name.clone(),
        },
        DelayLoadSymbol::ByOrdinal { ordinal } => ImportSymbol::ByOrdinal { ordinal: *ordinal },
    }
}

fn export_spec_to_export_symbol(export: &ExportSpec) -> ExportSymbol {
    ExportSymbol {
        ordinal: export.ordinal,
        name: export.name.clone(),
        target: match &export.target {
            ExportSpecTarget::Rva { value } => ExportTarget::Rva(*value),
            ExportSpecTarget::Forwarder { value } => ExportTarget::Forwarder(value.clone()),
        },
    }
}