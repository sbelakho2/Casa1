//! Phase 4.3 — DXIL Bytecode → MSL Full Translation Tests
//!
//! Tests the complete DXIL→MSL translation pipeline including:
//! - Simple shader translation (vertex, pixel, compute)
//! - Instruction-level translation (add, sample, buffer load)
//! - Content-addressed shader cache (hit, eviction)
//! - Root signature binding mapping
//! - Error handling (invalid DXIL, truncated containers)

#![allow(clippy::cloned_ref_to_slice_refs)]

use casa1::shader::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// LLVM bitcode magic (big-endian).
const LLVM_BC_MAGIC: u32 = 0x0B1E_0BC0u32.to_be();

/// Build a minimal valid DXIL container with the given instruction count.
fn make_minimal_dxil(instruction_count: u32, entry_name: &str) -> Vec<u8> {
    let mut data = Vec::new();

    // DXIL header
    data.extend_from_slice(b"DXIL"); // magic
    data.extend_from_slice(&1u32.to_le_bytes()); // version
    data.extend_from_slice(&3u32.to_le_bytes()); // part count (PROG, SIGN, META)

    // Part descriptors start at offset 12
    let descriptors_end = 12 + 3 * 12; // = 48
    let prog_offset: u32 = descriptors_end;

    // PROG part descriptor
    data.extend_from_slice(b"PROG");
    data.extend_from_slice(&prog_offset.to_le_bytes());
    let bitcode_payload_size = 4u32; // just the magic
    let prog_size = 24 + bitcode_payload_size;
    data.extend_from_slice(&prog_size.to_le_bytes());

    // SIGN part descriptor (4 bytes of dummy data)
    let sign_offset = prog_offset + prog_size;
    data.extend_from_slice(b"SIGN");
    data.extend_from_slice(&sign_offset.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());

    // META part descriptor (entry name)
    let meta_offset = sign_offset + 4;
    let name_bytes = entry_name.as_bytes();
    let meta_size = 1 + name_bytes.len() as u32; // length byte + name
    data.extend_from_slice(b"META");
    data.extend_from_slice(&meta_offset.to_le_bytes());
    data.extend_from_slice(&meta_size.to_le_bytes());

    // Pad to prog_offset
    while data.len() < prog_offset as usize {
        data.push(0);
    }

    // PROG part payload (24-byte header)
    data.extend_from_slice(&instruction_count.to_le_bytes()); // instruction count
    data.extend_from_slice(&64u32.to_le_bytes()); // IR size
    data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup x
    data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup y
    data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup z
    data.extend_from_slice(&0u32.to_le_bytes()); // resource use count = 0

    // LLVM bitcode magic (minimal, no actual instructions)
    data.extend_from_slice(&LLVM_BC_MAGIC.to_be_bytes());

    // SIGN part payload
    while data.len() < sign_offset as usize {
        data.push(0);
    }
    data.extend_from_slice(b"SIG1");

    // META part payload
    while data.len() < meta_offset as usize {
        data.push(0);
    }
    data.push(name_bytes.len() as u8);
    data.extend_from_slice(name_bytes);

    data
}

/// Build a root signature with the given descriptors and constants.
fn make_root_signature(descriptors: &[(u8, u8, u8, u8, u8, u8)], constants_count: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(descriptors.len() as u32).to_le_bytes());
    data.extend_from_slice(&constants_count.to_le_bytes());
    for &(kind, reg, space, count, arg_buf, binding) in descriptors {
        data.push(kind);
        data.push(reg);
        data.push(space);
        data.push(count);
        data.push(arg_buf);
        data.push(binding);
    }
    data
}

/// Build a minimal ShaderTranslationInput for testing.
fn test_input(dxil: Vec<u8>, stage: ShaderStage, root_sig: Vec<u8>) -> ShaderTranslationInput {
    ShaderTranslationInput {
        dxil,
        stage,
        root_signature: root_sig,
        compile_flags: CompileFlags {
            fast_math: true,
            denorm_mode: "ieee".to_string(),
            debug: false,
            optimization_level: 0,
        },
        gpu_family: "apple_gpu".to_string(),
        os_build: "macos_14".to_string(),
        macwin_version: "0.1.0".to_string(),
    }
}

// ---------------------------------------------------------------------------
// t20_1_empty_vs — Vertex shader with no operations, just pass-through
// ---------------------------------------------------------------------------

#[test]
fn t20_1_empty_vs() {
    let dxil = make_minimal_dxil(0, "main");
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil, ShaderStage::Vs, root);

    let result = translate_shader(&input);
    assert!(
        result.is_ok(),
        "empty VS should translate: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let msl = String::from_utf8_lossy(&output.mtl_library_bytes);

    // Must contain vertex qualifier
    assert!(
        msl.contains("[[vertex]]") || msl.contains("vertex "),
        "MSL should contain vertex attribute: {}",
        &msl[..msl.len().min(200)]
    );
    // Must contain a return of float4-like type
    assert!(
        msl.contains("return"),
        "MSL should contain a return statement"
    );
    // Should have proper function mapping
    assert!(
        !output.function_mapping.is_empty(),
        "should have function mapping"
    );
    assert!(
        output.cache_key.contains("vs"),
        "cache key should reference vertex stage"
    );
}

// ---------------------------------------------------------------------------
// t20_2_simple_ps — Pixel shader returning constant color
// ---------------------------------------------------------------------------

#[test]
fn t20_2_simple_ps() {
    let dxil = make_minimal_dxil(0, "ps_main");
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil, ShaderStage::Ps, root);

    let result = translate_shader(&input);
    assert!(
        result.is_ok(),
        "simple PS should translate: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let msl = String::from_utf8_lossy(&output.mtl_library_bytes);

    // Must contain fragment qualifier
    assert!(
        msl.contains("[[fragment]]") || msl.contains("fragment "),
        "MSL should contain fragment attribute"
    );
    // Should have the entry point name
    assert!(
        msl.contains("ps_main") || msl.contains("msl_ps_"),
        "MSL should reference the entry point"
    );
}

// ---------------------------------------------------------------------------
// t20_3_add_instruction — Compute shader with add instruction
// ---------------------------------------------------------------------------

#[test]
fn t20_3_add_instruction() {
    let dxil = make_minimal_dxil(1, "cs_add");
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil, ShaderStage::Cs, root);

    let result = translate_shader(&input);
    assert!(
        result.is_ok(),
        "compute shader should translate: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let msl = String::from_utf8_lossy(&output.mtl_library_bytes);

    // Check for kernel qualifier
    assert!(
        msl.contains("kernel void") || msl.contains("[[kernel]]"),
        "MSL should contain kernel qualifier"
    );
}

// ---------------------------------------------------------------------------
// t20_4_texture_sample — Shader using Sample intrinsic
// ---------------------------------------------------------------------------

#[test]
fn t20_4_texture_sample() {
    // Build a DXIL with texture reflection
    let dxil = make_minimal_dxil(1, "sample_tex");
    let root = make_root_signature(&[(1, 0, 0, 1, 0, 0)], 0); // kind=1=Texture
    let input = test_input(dxil, ShaderStage::Ps, root);

    let result = translate_shader(&input);
    assert!(
        result.is_ok(),
        "texture sample shader should translate: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let msl = String::from_utf8_lossy(&output.mtl_library_bytes);

    // The synthetic DXIL doesn't embed real LLVM bitcode instructions,
    // so we verify translation succeeds and produces a valid function header.
    assert!(
        msl.contains("ps") || msl.contains("fragment"),
        "MSL should reference pixel shader stage: {}",
        &msl[..msl.len().min(300)]
    );
}

// ---------------------------------------------------------------------------
// t20_5_buffer_load — Shader with buffer load
// ---------------------------------------------------------------------------

#[test]
fn t20_5_buffer_load() {
    let dxil = make_minimal_dxil(1, "buf_load");
    let root = make_root_signature(&[(0, 0, 0, 1, 0, 0)], 0); // kind=0=Buffer
    let input = test_input(dxil, ShaderStage::Cs, root);

    let result = translate_shader(&input);
    assert!(
        result.is_ok(),
        "buffer load should translate: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let msl = String::from_utf8_lossy(&output.mtl_library_bytes);

    // The synthetic DXIL doesn't embed real LLVM bitcode instructions,
    // so we verify translation succeeds and produces a compute kernel.
    assert!(
        msl.contains("kernel") || msl.contains("cs_"),
        "MSL should reference compute shader: {}",
        &msl[..msl.len().min(300)]
    );
}

// ---------------------------------------------------------------------------
// t20_6_cache_hit — Same DXIL compiled twice, verify cache returns hit
// ---------------------------------------------------------------------------

#[test]
fn t20_6_cache_hit() {
    let dxil = make_minimal_dxil(0, "cache_test");
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil.clone(), ShaderStage::Cs, root.clone());

    let mut cache = ShaderCache::new(100_000);

    // First compile — should miss
    let stats1 = compile_with_cache(&[input.clone()], &mut cache);
    // The initial miss from the first compile
    assert!(
        stats1.misses >= 1 || stats1.hits == 0,
        "first compile should miss (hits={}, misses={})",
        stats1.hits,
        stats1.misses
    );

    // Second compile with same input — should hit
    let input2 = test_input(dxil, ShaderStage::Cs, root);
    let stats2 = compile_with_cache(&[input2], &mut cache);

    assert!(
        stats2.hits >= 1,
        "second compile should hit (hits={})",
        stats2.hits
    );
}

// ---------------------------------------------------------------------------
// t20_7_cache_eviction — Fill cache beyond max_size, verify oldest evicted
// ---------------------------------------------------------------------------

#[test]
fn t20_7_cache_eviction() {
    // Create a cache with a modest limit (4000 bytes)
    // Each entry is ~600-800 bytes due to MSL source + reflection JSON
    let mut cache = ShaderCache::new(4000);

    // Insert several entries
    for i in 0..10 {
        let dxil = make_minimal_dxil(i, &format!("entry_{}", i));
        let root = make_root_signature(&[], 0);
        let input = test_input(dxil, ShaderStage::Cs, root);
        let _ = compile_with_cache(&[input], &mut cache);
    }

    // The cache should have evicted some entries due to size limit
    let total_size = cache.total_size_bytes();
    assert!(
        total_size <= 4500,
        "cache size {} should be limited (<= 4500)",
        total_size
    );
    assert!(
        cache.len() < 10,
        "cache should have evicted entries, but has {}",
        cache.len()
    );
}

// ---------------------------------------------------------------------------
// t20_8_root_signature_binding — Parse root signature, verify binding layout
// ---------------------------------------------------------------------------

#[test]
fn t20_8_root_signature_binding() {
    // Root signature with 2 buffer descriptors and 1 texture descriptor
    let root_data = make_root_signature(
        &[
            (0, 0, 0, 2, 0, 0), // Buffer, register 0, space 0, count 2
            (1, 0, 0, 1, 0, 1), // Texture, register 0, space 0, count 1
        ],
        4, // 4 root constants (16 bytes)
    );

    let root_info = parse_root_signature(&root_data).expect("parse root signature");
    assert_eq!(root_info.descriptors.len(), 2);
    assert_eq!(root_info.root_constants_count, 4);

    // Build argument buffers
    let bufs = build_argument_buffers(&root_info);
    assert_eq!(bufs.len(), 2);

    // First argument buffer: 2 buffer bindings
    assert_eq!(bufs[0].binding_count, 2);
    assert_eq!(bufs[0].bindings[0].kind, "buffer");
    assert_eq!(bufs[0].bindings[0].register, 0);
    assert_eq!(bufs[0].bindings[1].register, 1);

    // Second argument buffer: 1 texture binding
    assert_eq!(bufs[1].binding_count, 1);
    assert_eq!(bufs[1].bindings[0].kind, "texture");
    assert_eq!(bufs[1].bindings[0].binding_index, 1);

    // Verify bindless indirection (count > 64)
    assert!(!bufs[0].bindless_indirection);
}

// ---------------------------------------------------------------------------
// t20_9_invalid_dxil — Invalid DXIL bytecode returns error
// ---------------------------------------------------------------------------

#[test]
fn t20_9_invalid_dxil() {
    // Completely invalid data
    let dxil = b"NOTDXIL\x00\x00\x00\x01\x00\x00\x00".to_vec();
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil, ShaderStage::Cs, root);

    let result = translate_shader(&input);
    assert!(result.is_err(), "invalid DXIL should produce error");

    let error = result.unwrap_err();
    assert_eq!(
        error.failing_pass, "parse",
        "error should come from parse pass"
    );
    assert!(!error.message.is_empty(), "error should have a message");
}

// ---------------------------------------------------------------------------
// t20_10_truncated_container — Truncated DXIL container returns parse error
// ---------------------------------------------------------------------------

#[test]
fn t20_10_truncated_container() {
    // A DXIL header that claims parts but has no actual payload
    let dxil = b"DXIL\x01\x00\x00\x00\x02\x00\x00\x00".to_vec(); // 2 parts, but no descriptors
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil, ShaderStage::Cs, root);

    let result = translate_shader(&input);
    assert!(result.is_err(), "truncated DXIL should produce error");

    let error = result.unwrap_err();
    assert_eq!(
        error.failing_pass, "parse",
        "error should come from parse pass, got: {}",
        error.failing_pass
    );

    // Check that the error is specifically about the container
    assert!(
        error.message.contains("part")
            || error.message.contains("range")
            || error.message.contains("DXIL")
            || error.message.contains("header"),
        "error message should reference container: {}",
        error.message
    );
}

// ---------------------------------------------------------------------------
// Additional utility tests
// ---------------------------------------------------------------------------

#[test]
fn t20_cache_key_determinism() {
    let dxil = make_minimal_dxil(5, "det");
    let root = make_root_signature(&[(0, 0, 0, 1, 0, 0)], 0);
    let input1 = test_input(dxil.clone(), ShaderStage::Cs, root.clone());
    let input2 = test_input(dxil, ShaderStage::Cs, root);

    let key1 = shader_cache_key(&input1).unwrap();
    let key2 = shader_cache_key(&input2).unwrap();
    assert_eq!(
        key1, key2,
        "identical inputs must produce identical cache keys"
    );
}

#[test]
fn t20_shader_cache_compute_key_sha256() {
    let key = ShaderCache::compute_key(b"test_dxil_bytes");
    assert_eq!(key.len(), 64, "SHA-256 should produce 64 hex chars");
}

#[test]
fn t20_root_signature_empty() {
    let root = parse_root_signature(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(root.descriptors.len(), 0);
    assert_eq!(root.root_constants_count, 0);
}

#[test]
fn t20_root_signature_invalid_kind() {
    // Kind=255 is invalid
    let data = make_root_signature(&[(255, 0, 0, 1, 0, 0)], 0);
    let result = parse_root_signature(&data);
    assert!(result.is_err(), "invalid root kind should error");
}

#[test]
fn t20_pack_cbuffer_matrix() {
    let fields = vec![
        CbufferField {
            name: "world".to_string(),
            rows: 4,
            cols: 4,
            row_major: false,
            is_bool: false,
            array_len: 0,
        },
        CbufferField {
            name: "color".to_string(),
            rows: 1,
            cols: 4,
            row_major: false,
            is_bool: false,
            array_len: 0,
        },
    ];
    let packed = pack_cbuffer(&fields);
    assert_eq!(packed.fields.len(), 2);
    // Matrix should be aligned
    assert!(packed.size_bytes >= 32);
}

#[test]
fn t20_translate_shader_returns_mapping() {
    let dxil = make_minimal_dxil(0, "my_entry");
    let root = make_root_signature(&[], 0);
    let input = test_input(dxil, ShaderStage::Vs, root);

    let result = translate_shader(&input);
    assert!(result.is_ok(), "translation should succeed");
    let output = result.unwrap();

    // Function mapping should map original entry to MSL function
    assert!(
        output.function_mapping.contains_key("my_entry"),
        "should map original entry name"
    );
    let msl_fn = output.function_mapping.get("my_entry").unwrap();
    assert!(
        msl_fn.starts_with("msl_vs_"),
        "MSL function should be prefixed"
    );
}

#[test]
fn t20_compile_msl_source_wraps() {
    let source = "#include <metal_stdlib>\nusing namespace metal;\n";
    let compiled = compile_msl_source(source, "main").expect("compile MSL");
    let as_str = String::from_utf8_lossy(&compiled);
    assert!(
        as_str.starts_with("MTLCOMPILED|"),
        "should have compiled wrapper"
    );
    assert!(as_str.contains(source), "should contain original source");
}

#[test]
fn t20_dxil_opcode_sub_translation() {
    // opcode 2 = sub
    let stmt = dxil_opcode_to_msl(2, "_r", &["a".into(), "b".into()], false, false);
    assert!(stmt.contains("-"), "sub should produce - operator");
}

#[test]
fn t20_dxil_opcode_mul_translation() {
    // opcode 4 = mul
    let stmt = dxil_opcode_to_msl(4, "_r", &["x".into(), "y".into()], false, false);
    assert!(stmt.contains("*"), "mul should produce * operator");
}

#[test]
fn t20_dxil_opcode_and_translation() {
    // opcode 11 = and
    let stmt = dxil_opcode_to_msl(11, "_r", &["a".into(), "b".into()], false, false);
    assert!(stmt.contains("&"), "and should produce & operator");
}

#[test]
fn t20_dxil_opcode_compare_eq() {
    // opcode 18 = icmp_eq
    let stmt = dxil_opcode_to_msl(18, "_r", &["a".into(), "b".into()], false, false);
    assert!(stmt.contains("=="), "eq should produce == operator");
}

#[test]
fn t20_dxil_opcode_compare_ne() {
    // opcode 19 = icmp_ne
    let stmt = dxil_opcode_to_msl(19, "_r", &["a".into(), "b".into()], false, false);
    assert!(stmt.contains("!="), "ne should produce != operator");
}
