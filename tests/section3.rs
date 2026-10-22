#![allow(dead_code, unused_imports)]
mod support;

use casa1::oracle_suites::{DelayLoadCase, DelayLoadSymbol, ExportSpec, ExportSpecTarget};
use casa1::pe::{self, ApiSetResolver, DelayLoadOutcome, ExportSymbol, ExportTarget, ImportSymbol};
use casa1::reason::ReasonCode;
use std::collections::BTreeMap;

#[test]
fn mapping_relocations_and_deterministic_aslr_work() {
    let bytes = support::sample_pe_bytes();
    let image = pe::parse(&bytes).expect("parse synthetic PE32+ fixture");

    let mapped_a =
        pe::map_image(&bytes, &image, support::SAMPLE_HASH, true).expect("map deterministic image");
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
        mapped_a.memory[support::SAMPLE_RELOC_TARGET_RVA as usize
            ..support::SAMPLE_RELOC_TARGET_RVA as usize + 8]
            .try_into()
            .expect("relocated qword"),
    );
    assert_eq!(relocated, mapped_a.selected_base + 0x1234);

    let mut unsupported_relocation = image.clone();
    unsupported_relocation.relocations[0].entries[0].kind = pe::RelocationType::Unsupported(7);
    let relocation_error =
        pe::map_image(&bytes, &unsupported_relocation, support::SAMPLE_HASH, true)
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
    let resolver =
        ApiSetResolver::new().with_mapping("api-ms-win-core-file-l1-1-0.dll", "kernel32.dll");
    let resolved = pe::resolve_imports(&image, &export_tables, &resolver)
        .expect("resolve imports and forwarders");
    assert_eq!(resolved.len(), 3);

    let missing_import_provider = pe::resolve_imports(&image, &BTreeMap::new(), &resolver)
        .expect_err("missing eager import provider should fail");
    assert_eq!(missing_import_provider.code, ReasonCode::RcImportMissing);

    let create_file = resolved
        .iter()
        .find(|import| {
            import.symbol
                == ImportSymbol::ByName {
                    hint: 0,
                    name: "CreateFileW".to_string(),
                }
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
        .find(|import| {
            import.symbol
                == ImportSymbol::ByName {
                    hint: 0,
                    name: "Forwarded".to_string(),
                }
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
fn pe_parser_mutation_corpus_is_deterministic_and_bounds_checked() {
    let seed = support::sample_pe_bytes();
    for index in 0..128_usize {
        let mutated = mutation_case(&seed, index);
        let first = parse_summary(&mutated);
        let second = parse_summary(&mutated);
        assert_eq!(
            first, second,
            "mutation case {index} produced nondeterministic parse results"
        );
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
