use casa1::reason::ReasonCode;
use casa1::shader::{
    CbufferField, CompileFlags, OfflineCompiler, ResourceAccess, RootConstantsPlan, ShaderCache,
    ShaderStage, ShaderTranslationInput, StructuredField, build_argument_buffers,
    build_cache_entry, compile_with_cache, discover_dxil_files, pack_cbuffer,
    pack_structured_fields, parse_root_signature, pso_cache_key, shader_cache_key,
    translate_shader,
};
use tempfile::TempDir;

fn build_root_signature(root_constants: u32, descriptors: &[(u8, u8, u8, u8, u8, u8)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&(descriptors.len() as u32).to_le_bytes());
    bytes.extend(&root_constants.to_le_bytes());
    for descriptor in descriptors {
        bytes.extend([
            descriptor.0,
            descriptor.1,
            descriptor.2,
            descriptor.3,
            descriptor.4,
            descriptor.5,
        ]);
    }
    bytes
}

fn build_program_part(
    instruction_count: u32,
    ir_size: u32,
    threadgroup_size: (u32, u32, u32),
    uses: &[(u8, u8, u8, u8, u8, u16)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&instruction_count.to_le_bytes());
    bytes.extend(&ir_size.to_le_bytes());
    bytes.extend(&threadgroup_size.0.to_le_bytes());
    bytes.extend(&threadgroup_size.1.to_le_bytes());
    bytes.extend(&threadgroup_size.2.to_le_bytes());
    bytes.extend(&(uses.len() as u32).to_le_bytes());
    for entry in uses {
        bytes.extend([
            entry.0,
            entry.1,
            entry.2,
            entry.3,
            entry.4,
            entry.5 as u8,
            (entry.5 >> 8) as u8,
            0,
        ]);
    }
    bytes
}

fn build_reflection_part(
    resources: &[(u8, u8, u8, u8, u8, u8, u8)],
    cbuffers: &[(u8, u8, u16, u32)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&(resources.len() as u32).to_le_bytes());
    for resource in resources {
        bytes.extend([
            resource.0, resource.1, resource.2, resource.3, resource.4, resource.5, resource.6,
        ]);
    }
    bytes.extend(&(cbuffers.len() as u32).to_le_bytes());
    for cbuffer in cbuffers {
        bytes.extend([
            cbuffer.0,
            cbuffer.1,
            cbuffer.2 as u8,
            (cbuffer.2 >> 8) as u8,
            cbuffer.3 as u8,
            (cbuffer.3 >> 8) as u8,
            (cbuffer.3 >> 16) as u8,
            (cbuffer.3 >> 24) as u8,
        ]);
    }
    bytes
}

fn build_container(entry_name: &str, parts: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
    let header_size = 12 + parts.len() * 12;
    let mut offset = header_size as u32;
    let descriptors = parts
        .iter()
        .map(|(kind, payload)| {
            let descriptor = (*kind, offset, payload.len() as u32);
            offset += payload.len() as u32;
            descriptor
        })
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    bytes.extend(b"DXIL");
    bytes.extend(&1_u32.to_le_bytes());
    bytes.extend(&(parts.len() as u32).to_le_bytes());
    for (kind, offset, size) in &descriptors {
        bytes.extend(kind);
        bytes.extend(&offset.to_le_bytes());
        bytes.extend(&size.to_le_bytes());
    }
    for (_, payload) in parts {
        bytes.extend(payload);
    }
    let mut meta = vec![entry_name.len() as u8];
    meta.extend(entry_name.as_bytes());
    let parts_without_meta = bytes[12 + descriptors.len() * 12..].to_vec();
    let mut rewritten = Vec::new();
    rewritten.extend(b"DXIL");
    rewritten.extend(&1_u32.to_le_bytes());
    rewritten.extend(&((descriptors.len() + 1) as u32).to_le_bytes());
    let mut running_offset = (12 + (descriptors.len() + 1) * 12) as u32;
    for (kind, _, size) in descriptors {
        rewritten.extend(kind);
        rewritten.extend(&running_offset.to_le_bytes());
        rewritten.extend(&size.to_le_bytes());
        running_offset += size;
    }
    rewritten.extend(*b"META");
    rewritten.extend(&running_offset.to_le_bytes());
    rewritten.extend(&(meta.len() as u32).to_le_bytes());
    rewritten.extend(parts_without_meta);
    rewritten.extend(meta);
    rewritten
}

fn compile_flags() -> CompileFlags {
    CompileFlags {
        fast_math: true,
        denorm_mode: "preserve".to_string(),
        debug: false,
        optimization_level: 3,
    }
}

fn translation_input(
    stage: ShaderStage,
    dxil: Vec<u8>,
    root_signature: Vec<u8>,
) -> ShaderTranslationInput {
    ShaderTranslationInput {
        dxil,
        stage,
        root_signature,
        compile_flags: compile_flags(),
        gpu_family: "apple8".to_string(),
        os_build: "macos-14.5".to_string(),
        macwin_version: "0.1.0".to_string(),
    }
}

fn reflected_fixture(entry_name: &str, stage: ShaderStage) -> ShaderTranslationInput {
    let root_signature = build_root_signature(
        8,
        &[(1, 0, 0, 1, 0, 0), (2, 0, 0, 1, 1, 0), (3, 0, 0, 1, 2, 0)],
    );
    let dxil = build_container(
        entry_name,
        vec![
            (
                *b"PROG",
                build_program_part(
                    32,
                    512,
                    (8, 8, 1),
                    &[(1, 0, 0, 0, 1, 0), (2, 0, 0, 0, 3, 0), (3, 0, 0, 0, 0, 64)],
                ),
            ),
            (*b"SIGN", b"input-signature-output-signature".to_vec()),
            (
                *b"RFLX",
                build_reflection_part(
                    &[(1, 0, 0, 0, 0, 0, 1), (2, 0, 0, 1, 0, 0, 3)],
                    &[(0, 0, 64, 0x0102_0304)],
                ),
            ),
        ],
    );
    translation_input(stage, dxil, root_signature)
}

fn reconstructable_fixture(entry_name: &str, stage: ShaderStage) -> ShaderTranslationInput {
    let root_signature = build_root_signature(
        12,
        &[(1, 0, 0, 1, 0, 0), (2, 0, 0, 1, 1, 0), (3, 0, 0, 1, 2, 0)],
    );
    let dxil = build_container(
        entry_name,
        vec![
            (
                *b"PROG",
                build_program_part(
                    48,
                    768,
                    (16, 8, 1),
                    &[(1, 0, 0, 0, 0, 0), (2, 0, 0, 0, 3, 0), (3, 0, 0, 0, 0, 64)],
                ),
            ),
            (*b"SIGN", b"reconstruct-input-reconstruct-output".to_vec()),
        ],
    );
    translation_input(stage, dxil, root_signature)
}

fn ambiguous_fixture(entry_name: &str) -> ShaderTranslationInput {
    let root_signature = build_root_signature(4, &[(1, 0, 0, 1, 0, 0), (1, 0, 0, 1, 1, 0)]);
    let dxil = build_container(
        entry_name,
        vec![
            (
                *b"PROG",
                build_program_part(12, 256, (1, 1, 1), &[(1, 0, 0, 0, 0, 0)]),
            ),
            (*b"SIGN", b"ambiguous-in-ambiguous-out".to_vec()),
        ],
    );
    translation_input(ShaderStage::Ps, dxil, root_signature)
}

fn invalid_fixture(entry_name: &str) -> ShaderTranslationInput {
    let root_signature = build_root_signature(0, &[(1, 0, 0, 1, 0, 0)]);
    let dxil = build_container(
        entry_name,
        vec![
            (
                *b"PROG",
                build_program_part(5001, 512, (1, 1, 1), &[(1, 0, 0, 0, 0, 0)]),
            ),
            (*b"SIGN", b"bad-input-bad-output".to_vec()),
        ],
    );
    translation_input(ShaderStage::Vs, dxil, root_signature)
}

#[test]
fn t8_1_dxil_corpus_compile_is_deterministic_and_classified_by_hash() {
    let corpus = vec![
        reflected_fixture("main_vs", ShaderStage::Vs),
        reconstructable_fixture("main_cs", ShaderStage::Cs),
        invalid_fixture("broken_vs"),
    ];

    for input in corpus {
        let first = translate_shader(&input);
        let second = translate_shader(&input);
        match (first, second) {
            (Ok(left), Ok(right)) => {
                assert_eq!(left.cache_key, right.cache_key);
                assert_eq!(left.mtl_library_bytes, right.mtl_library_bytes);
                assert_eq!(left.function_mapping, right.function_mapping);
            }
            (Err(left), Err(right)) => {
                assert_eq!(left.reason_code, right.reason_code);
                assert_eq!(left.dxil_hash, right.dxil_hash);
                assert_eq!(left.failing_pass, right.failing_pass);
                assert_eq!(left.message, right.message);
            }
            _ => panic!("translation results diverged between identical runs"),
        }
    }

    let invalid = translate_shader(&invalid_fixture("broken_vs"))
        .expect_err("invalid fixture must fail deterministically");
    assert_eq!(invalid.reason_code, ReasonCode::RcDxilInvalid);
    assert_eq!(
        invalid.dxil_hash,
        casa1::util::sha256_bytes(&invalid_fixture("broken_vs").dxil)
    );
}

#[test]
fn t8_2_binding_reconstruction_oracle_matches_expected_bindings_and_detects_ambiguity() {
    let output = translate_shader(&reconstructable_fixture("reconstruct_ps", ShaderStage::Ps))
        .expect("reconstructable fixture should translate");
    assert_eq!(
        output
            .reflection
            .resources
            .iter()
            .map(|resource| (
                resource.kind,
                resource.register,
                resource.space,
                resource.arg_buffer_index,
                resource.binding_index,
                resource.access
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                casa1::shader::ResourceKind::Texture,
                0,
                0,
                0,
                0,
                ResourceAccess::Read
            ),
            (
                casa1::shader::ResourceKind::Sampler,
                0,
                0,
                1,
                0,
                ResourceAccess::Read
            ),
        ]
    );
    assert_eq!(output.reflection.cbuffers[0].register, 0);
    assert_eq!(output.reflection.cbuffers[0].space, 0);
    assert_eq!(output.reflection.cbuffers[0].size_bytes, 64);
    assert_eq!(
        output.argument_buffers,
        vec![
            casa1::shader::ArgumentBufferLayout {
                table_index: 0,
                binding_count: 1,
                bindless_indirection: false,
                bindings: vec![casa1::shader::ArgumentBinding {
                    kind: "texture".to_string(),
                    register: 0,
                    space: 0,
                    binding_index: 0,
                }],
            },
            casa1::shader::ArgumentBufferLayout {
                table_index: 1,
                binding_count: 1,
                bindless_indirection: false,
                bindings: vec![casa1::shader::ArgumentBinding {
                    kind: "sampler".to_string(),
                    register: 0,
                    space: 0,
                    binding_index: 0,
                }],
            },
            casa1::shader::ArgumentBufferLayout {
                table_index: 2,
                binding_count: 1,
                bindless_indirection: false,
                bindings: vec![casa1::shader::ArgumentBinding {
                    kind: "cbuffer".to_string(),
                    register: 0,
                    space: 0,
                    binding_index: 0,
                }],
            },
        ]
    );
    assert_eq!(
        output.root_constants,
        RootConstantsPlan {
            constant_buffer_size: 48,
            binding_index: 0,
        }
    );

    let bindless_root = parse_root_signature(&build_root_signature(0, &[(1, 0, 0, 80, 0, 0)]))
        .expect("parse bindless root signature");
    let bindless = build_argument_buffers(&bindless_root);
    assert!(bindless[0].bindless_indirection);
    assert_eq!(bindless[0].binding_count, 80);

    let ambiguous = translate_shader(&ambiguous_fixture("ambiguous_ps"))
        .expect_err("ambiguous binding reconstruction must fail");
    assert_eq!(ambiguous.reason_code, ReasonCode::RcDxilBindingAmbiguous);
}

#[test]
fn t8_3_hlsl_packing_and_structured_layout_hashes_match_reference_offsets() {
    let packed = pack_cbuffer(&[
        CbufferField {
            name: "flag".to_string(),
            rows: 1,
            cols: 1,
            row_major: false,
            is_bool: true,
            array_len: 1,
        },
        CbufferField {
            name: "uv".to_string(),
            rows: 1,
            cols: 2,
            row_major: false,
            is_bool: false,
            array_len: 1,
        },
        CbufferField {
            name: "transform".to_string(),
            rows: 4,
            cols: 4,
            row_major: false,
            is_bool: false,
            array_len: 1,
        },
        CbufferField {
            name: "weights".to_string(),
            rows: 1,
            cols: 4,
            row_major: false,
            is_bool: false,
            array_len: 2,
        },
    ]);
    assert_eq!(
        packed
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field.offset, field.size_bytes))
            .collect::<Vec<_>>(),
        vec![
            ("flag", 0, 4),
            ("uv", 4, 8),
            ("transform", 16, 64),
            ("weights", 80, 32),
        ]
    );
    assert_eq!(packed.size_bytes, 112);

    let structured = pack_structured_fields(&[
        StructuredField {
            name: "position".to_string(),
            size_bytes: 12,
            alignment: 4,
        },
        StructuredField {
            name: "normal".to_string(),
            size_bytes: 12,
            alignment: 4,
        },
        StructuredField {
            name: "tangent".to_string(),
            size_bytes: 16,
            alignment: 16,
        },
    ]);
    assert_eq!(structured.stride, 48);
}

#[test]
fn t8_4_cache_keys_entries_and_corruption_handling_are_deterministic() {
    let input = reflected_fixture("cache_vs", ShaderStage::Vs);
    let output_a = translate_shader(&input).expect("first translation");
    let output_b = translate_shader(&input).expect("second translation");
    assert_eq!(output_a.cache_key, output_b.cache_key);
    assert_eq!(
        shader_cache_key(&input).expect("shader cache key"),
        output_a.cache_key
    );
    let entry_a = build_cache_entry(&output_a.cache_key, &output_a, 42, Some(vec![1, 2, 3]))
        .expect("first cache entry");
    let entry_b = build_cache_entry(&output_b.cache_key, &output_b, 42, Some(vec![1, 2, 3]))
        .expect("second cache entry");
    assert_eq!(entry_a.checksum, entry_b.checksum);
    assert_eq!(
        pso_cache_key(
            Some(&output_a.cache_key),
            Some(&output_a.cache_key),
            None,
            b"render-state",
            b"formats",
            1,
            "triangle",
        ),
        pso_cache_key(
            Some(&output_b.cache_key),
            Some(&output_b.cache_key),
            None,
            b"render-state",
            b"formats",
            1,
            "triangle",
        )
    );

    let mut cache = ShaderCache::new(4096);
    let mut corrupted = entry_a.clone();
    corrupted.checksum.replace_range(0..1, "f");
    let encoded = serde_json::to_vec(&corrupted).expect("encode corrupted cache entry");
    assert!(cache.load_encoded(&output_a.cache_key, &encoded).is_none());
    assert_eq!(cache.logs(), &[ReasonCode::RcCacheCorrupt]);
}

#[test]
fn t8_5_cache_effectiveness_and_offline_compilation_scheduling_match_reference() {
    let inputs = (0..20)
        .map(|index| reconstructable_fixture(&format!("scene_{index}"), ShaderStage::Cs))
        .collect::<Vec<_>>();
    let mut cache = ShaderCache::new(1 << 20);
    let first_run = compile_with_cache(&inputs, &mut cache);
    let second_run = compile_with_cache(&inputs, &mut cache);
    assert_eq!(first_run.hits, 0);
    assert_eq!(first_run.misses, 20);
    assert_eq!(second_run.hits, 20);
    assert_eq!(second_run.compile_stalls, 0);
    assert!((second_run.hits as f32 / inputs.len() as f32) >= 0.95);

    let temp_dir = TempDir::new().expect("temp dir for offline compile scan");
    let discovered_a = temp_dir.path().join("alpha.dxil");
    let discovered_b = temp_dir.path().join("nested/beta.dxil");
    std::fs::create_dir_all(discovered_b.parent().expect("beta parent"))
        .expect("create nested fixture directory");
    std::fs::write(&discovered_a, &inputs[0].dxil).expect("write alpha DXIL fixture");
    std::fs::write(&discovered_b, &inputs[1].dxil).expect("write beta DXIL fixture");
    std::fs::write(temp_dir.path().join("ignored.bin"), b"not dxil").expect("write ignored binary");

    let mut offline = OfflineCompiler::default();
    let discovered = offline
        .scan_directory(temp_dir.path())
        .expect("discover DXIL files");
    assert_eq!(
        discovered,
        discover_dxil_files(temp_dir.path()).expect("standalone discovery")
    );
    assert_eq!(discovered.len(), 2);
    let runtime_key = shader_cache_key(&inputs[0]).expect("runtime shader key");
    offline.intercept_runtime_shader_creation(&runtime_key);
    let plan = offline.schedule(40, 8);
    assert_eq!(plan.total_shaders, 3);
    assert_eq!(plan.worker_count, 4);
    assert_eq!(plan.cpu_cap_percent, 40);
    assert!(plan.io_priority_low);
    assert!(!plan.blocks_ui_thread);
    assert_eq!(plan.scheduled_keys, vec![runtime_key.clone()]);

    let failure = translate_shader(&invalid_fixture("offline_fail"))
        .expect_err("invalid offline shader should fail");
    let report = offline.report(2, vec![failure.clone()], 0);
    assert_eq!(report.total_shaders, 3);
    assert_eq!(report.compiled, 2);
    assert_eq!(report.failed, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.failures, vec![failure]);
}

#[test]
fn t8_6_dxil_fuzzer_classification_is_deterministic_across_mutations() {
    let valid = reflected_fixture("fuzz_vs", ShaderStage::Vs).dxil;
    let mut excessive = valid.clone();
    excessive[12 + 12 * 3] = 0x89;
    excessive[12 + 12 * 3 + 1] = 0x13;
    let truncated = valid[..valid.len() / 2].to_vec();
    let bad_magic = {
        let mut bytes = valid.clone();
        bytes[..4].copy_from_slice(b"ZZZZ");
        bytes
    };

    for payload in [&valid[..], &truncated[..], &bad_magic[..], &excessive[..]] {
        let first = casa1::shader::fuzz_summary(payload);
        let second = casa1::shader::fuzz_summary(payload);
        assert_eq!(first, second);
    }
    assert!(casa1::shader::fuzz_summary(&valid).starts_with("ok:"));
    assert!(
        casa1::shader::fuzz_summary(&truncated)
            .starts_with(&format!("err:{}", ReasonCode::RcDxilInvalid.as_u32()))
    );
    assert!(
        casa1::shader::fuzz_summary(&bad_magic)
            .starts_with(&format!("err:{}", ReasonCode::RcDxilInvalid.as_u32()))
    );
}
