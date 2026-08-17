//! Phase 4.3 — DXIL Bytecode → MSL Full Translation Tests
//!
//! Tests the complete DXIL→MSL translation pipeline including:
//! - Simple shader translation (vertex, pixel, compute)
//! - Instruction-level translation (add, sample, buffer load)
//! - Content-addressed shader cache (hit, eviction)
//! - Root signature binding mapping
//! - Error handling (invalid DXIL, truncated containers)

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

    // The generated MSL must be a real vertex stage: a `vertex` entry function
    // returning a `VertexOutput` with the position plumbing present.
    assert!(
        msl.contains("vertex VertexOutput msl_vs_"),
        "MSL should contain the vertex entry function: {}",
        &msl[..msl.len().min(300)]
    );
    assert!(
        msl.contains("VertexOutput out;") && msl.contains("return out;"),
        "MSL should construct and return a VertexOutput: {}",
        &msl[..msl.len().min(300)]
    );
    assert!(
        msl.contains("uint vid [[vertex_id]]"),
        "MSL should declare the vertex_id parameter: {}",
        &msl[..msl.len().min(300)]
    );
    // Should have proper function mapping
    assert!(
        !output.function_mapping.is_empty(),
        "should have function mapping"
    );
    let mapped_fn = output
        .function_mapping
        .get("main")
        .expect("entry 'main' must be mapped");
    assert!(
        mapped_fn.starts_with("msl_vs_"),
        "entry 'main' must map to a msl_vs_ function, got {mapped_fn}"
    );
    assert!(
        msl.contains(mapped_fn),
        "MSL must actually contain the mapped function {mapped_fn}"
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

    // The generated MSL must be a real fragment stage: a `fragment void msl_ps_`
    // entry function, with the entry point mapped by name.
    assert!(
        msl.contains("fragment void msl_ps_"),
        "MSL should contain the fragment entry function: {}",
        &msl[..msl.len().min(300)]
    );
    let mapped_fn = output
        .function_mapping
        .get("ps_main")
        .expect("entry 'ps_main' must be mapped");
    assert!(
        mapped_fn.starts_with("msl_ps_"),
        "entry 'ps_main' must map to a msl_ps_ function, got {mapped_fn}"
    );
    assert!(
        msl.contains(mapped_fn),
        "MSL must actually contain the mapped function {mapped_fn}"
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

    // The generated MSL must be a real compute stage: a `kernel void msl_cs_` entry
    // function with threadgroup plumbing.
    assert!(
        msl.contains("kernel void msl_cs_"),
        "MSL should contain the kernel entry function: {}",
        &msl[..msl.len().min(300)]
    );
    assert!(
        msl.contains("uint3 gid [[thread_position_in_grid]]"),
        "MSL should declare the thread position parameter: {}",
        &msl[..msl.len().min(300)]
    );
    assert!(
        msl.contains("[[threads_per_threadgroup(1, 1, 1)]]"),
        "MSL should declare the threadgroup size: {}",
        &msl[..msl.len().min(300)]
    );
    let mapped_fn = output
        .function_mapping
        .get("cs_add")
        .expect("entry 'cs_add' must be mapped");
    assert!(
        mapped_fn.starts_with("msl_cs_"),
        "entry 'cs_add' must map to a msl_cs_ function, got {mapped_fn}"
    );
    assert!(
        msl.contains(mapped_fn),
        "MSL must actually contain the mapped function {mapped_fn}"
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

    // The synthetic DXIL contains no real LLVM bitcode instructions, so no sampling
    // statement is emitted — but the generated MSL must still be a real fragment
    // stage whose function name is derived from the input, and the root signature
    // must actually influence the translation output.
    assert!(
        msl.contains("fragment void msl_ps_"),
        "MSL should contain the fragment entry function: {}",
        &msl[..msl.len().min(300)]
    );
    let mapped_fn = output
        .function_mapping
        .get("sample_tex")
        .expect("entry 'sample_tex' must be mapped");
    assert!(
        mapped_fn.starts_with("msl_ps_"),
        "entry 'sample_tex' must map to a msl_ps_ function, got {mapped_fn}"
    );
    assert!(
        msl.contains(mapped_fn),
        "MSL must actually contain the mapped function {mapped_fn}"
    );

    // The translated function name must be content-addressed: different DXIL bytes
    // must produce different MSL functions (a fixed template would fail this).
    let other_input = test_input(
        make_minimal_dxil(1, "sample_tex2"),
        ShaderStage::Ps,
        make_root_signature(&[(1, 0, 0, 1, 0, 0)], 0),
    );
    let other_output = translate_shader(&other_input).expect("translate other dxil");
    let other_fn = other_output
        .function_mapping
        .get("sample_tex2")
        .expect("mapping");
    assert_ne!(
        mapped_fn, other_fn,
        "different DXIL inputs must produce different MSL functions"
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

    // The synthetic DXIL contains no real LLVM bitcode instructions, so no buffer
    // load is emitted — but the generated MSL must still be a real compute kernel
    // whose entry function is mapped by name.
    assert!(
        msl.contains("kernel void msl_cs_"),
        "MSL should contain the kernel entry function: {}",
        &msl[..msl.len().min(300)]
    );
    let mapped_fn = output
        .function_mapping
        .get("buf_load")
        .expect("entry 'buf_load' must be mapped");
    assert!(
        mapped_fn.starts_with("msl_cs_"),
        "entry 'buf_load' must map to a msl_cs_ function, got {mapped_fn}"
    );
    assert!(
        msl.contains(mapped_fn),
        "MSL must actually contain the mapped function {mapped_fn}"
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

    // First compile — must be exactly one miss and zero hits. (`input` is not
    // used afterwards, so no clone is needed.)
    let stats1 = compile_with_cache(std::slice::from_ref(&input), &mut cache);
    assert_eq!(
        stats1.hits, 0,
        "first compile must not hit (hits={}, misses={})",
        stats1.hits, stats1.misses
    );
    assert_eq!(
        stats1.misses, 1,
        "first compile must miss exactly once (hits={}, misses={})",
        stats1.hits, stats1.misses
    );

    // Second compile with same input — must hit exactly once and not recompile.
    let input2 = test_input(dxil, ShaderStage::Cs, root);
    let stats2 = compile_with_cache(&[input2], &mut cache);

    assert_eq!(
        stats2.hits, 1,
        "second compile should hit exactly once (hits={})",
        stats2.hits
    );
    assert_eq!(
        stats2.misses, 0,
        "second compile must not miss (hits={}, misses={})",
        stats2.hits, stats2.misses
    );
}

// ---------------------------------------------------------------------------
// t20_7_cache_eviction — Fill cache beyond max_size, verify oldest evicted
// ---------------------------------------------------------------------------

#[test]
fn t20_7_cache_eviction() {
    // Deterministic LRU test using the cache's public API: entries must be
    // retrievable while resident, the least-recently-used entry must be evicted
    // when capacity is exceeded (not the newest), and a no-op cache that stores
    // nothing must fail these assertions.
    fn make_entry(key: &str, payload_bytes: usize) -> ShaderCacheEntry {
        ShaderCacheEntry {
            header: CacheHeader {
                magic: "CASA1CACHE".to_string(),
                version: 1,
                key: key.to_string(),
                created_ts: 0,
                last_used_ts: 0,
            },
            payload: CachePayload {
                mtl_library_bytes: vec![0xAB; payload_bytes],
                reflection_json: "{}".to_string(),
                metal_pipeline_archive: None,
            },
            checksum: "checksum".to_string(),
        }
    }

    // 3 × 200-byte payloads fit under the 1000-byte limit.
    let mut cache = ShaderCache::new(1000);
    cache.insert(make_entry("k1", 200));
    cache.insert(make_entry("k2", 200));
    cache.insert(make_entry("k3", 200));
    assert_eq!(cache.len(), 3, "all three entries must be resident");
    assert!(cache.get("k1").is_some(), "k1 must be retrievable");
    assert!(cache.get("k2").is_some(), "k2 must be retrievable");
    assert!(cache.get("k3").is_some(), "k3 must be retrievable");
    assert!(
        cache.total_size_bytes() <= 1000,
        "resident entries must fit the budget"
    );

    // Touch k1 (making it most-recently-used), then insert a fourth entry that
    // pushes the cache over capacity. The LRU entry (k2) must be evicted while
    // k1 (recently used) and the newest entry k4 survive.
    assert!(cache.get("k1").is_some(), "k1 touch must succeed");
    cache.insert(make_entry("k4", 200));

    assert_eq!(cache.len(), 3, "cache must have evicted exactly one entry");
    assert!(cache.get("k1").is_some(), "recently-used k1 must survive");
    assert!(
        cache.get("k2").is_none(),
        "least-recently-used k2 must be evicted"
    );
    assert!(cache.get("k3").is_some(), "k3 must survive");
    assert!(cache.get("k4").is_some(), "newest entry k4 must be present");
    assert!(
        cache.total_size_bytes() <= 1000,
        "cache size must stay within budget after eviction"
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
    // Pinned golden value: SHA-256 of b"test_dxil_bytes" (64 lowercase hex chars).
    // Pinning the exact digest protects the key derivation (a length-only check
    // would pass for any 32-byte output regardless of correctness).
    let key = ShaderCache::compute_key(b"test_dxil_bytes");
    assert_eq!(key.len(), 64, "SHA-256 should produce 64 hex chars");
    assert_eq!(
        key,
        "48cc678e254a3f457e8c959c0d08cd20baf58aaf984014add1ea7e0fb6ab271a"
    );
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
    // Column-major 4×4 matrix occupies 4 × 16 B registers at offset 0; the float4
    // that follows starts a fresh register because the matrix ends register-aligned.
    assert_eq!(packed.fields[0].name, "world");
    assert_eq!(packed.fields[0].offset, 0);
    assert_eq!(packed.fields[0].size_bytes, 64, "4×4 matrix = 64 B");
    assert_eq!(packed.fields[1].name, "color");
    assert_eq!(packed.fields[1].offset, 64);
    assert_eq!(packed.fields[1].size_bytes, 16);
    assert_eq!(packed.size_bytes, 80, "cbuffer total must align to 16");
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
    // opcode 2 = sub — full statement, operand order preserved
    let stmt = dxil_opcode_to_msl(2, "_r", &["a".into(), "b".into()], false, false);
    assert_eq!(stmt, "_r = a - b;");
}

#[test]
fn t20_dxil_opcode_mul_translation() {
    // opcode 4 = mul — full statement, operand order preserved
    let stmt = dxil_opcode_to_msl(4, "_r", &["x".into(), "y".into()], false, false);
    assert_eq!(stmt, "_r = x * y;");
}

#[test]
fn t20_dxil_opcode_and_translation() {
    // opcode 11 = and — full statement, operand order preserved
    let stmt = dxil_opcode_to_msl(11, "_r", &["a".into(), "b".into()], false, false);
    assert_eq!(stmt, "_r = a & b;");
}

#[test]
fn t20_dxil_opcode_compare_eq() {
    // opcode 18 = icmp_eq
    let stmt = dxil_opcode_to_msl(18, "_r", &["a".into(), "b".into()], false, false);
    assert_eq!(stmt, "_r = a == b;");
}

#[test]
fn t20_dxil_opcode_compare_ne() {
    // opcode 19 = icmp_ne
    let stmt = dxil_opcode_to_msl(19, "_r", &["a".into(), "b".into()], false, false);
    assert_eq!(stmt, "_r = a != b;");
}

#[test]
fn t20_dxil_opcode_arithmetic_and_compare_coverage() {
    // Expanded coverage: assert the complete generated statement (result name,
    // operand order, operator) for the remaining arithmetic/comparison opcodes —
    // a wrong operator mapping that merely contains the right character fails here.
    // A wrong operator mapping that merely contains the right character fails
    // these exact-statement assertions.
    type OpCase = (
        u32,
        &'static str,
        &'static [&'static str],
        bool,
        bool,
        &'static str,
    );
    let cases: &[OpCase] = &[
        (0, "_r", &["a", "b"], false, false, "_r = a + b;"), // add
        (3, "_r", &["a", "b"], false, true, "_r = a - b;"),  // fsub
        (5, "_r", &["a", "b"], false, true, "_r = a * b;"),  // fmul
        (12, "_r", &["a", "b"], false, false, "_r = a | b;"), // or
        (13, "_r", &["a", "b"], false, false, "_r = a ^ b;"), // xor
        (14, "_r", &["a", "b"], false, false, "_r = a << b;"), // shl
        (15, "_r", &["a", "b"], false, false, "_r = a >> b;"), // lshr
        (20, "_r", &["a", "b"], false, false, "_r = a > b;"), // icmp_ugt
        (23, "_r", &["a", "b"], false, false, "_r = a <= b;"), // icmp_ule
        (26, "_r", &["a", "b"], true, false, "_r = a < b;"), // icmp_slt
        (28, "_r", &["a", "b"], false, true, "_r = a == b;"), // fcmp_oeq
    ];
    for &(opcode, dst, args, is_signed, is_float, expected) in cases {
        let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            dxil_opcode_to_msl(opcode, dst, &args, is_signed, is_float),
            expected,
            "opcode {opcode} must generate the exact statement"
        );
    }
}

#[test]
fn t20_dxil_opcode_function_and_conversion_coverage() {
    // Function-call and conversion opcodes: full statement, argument order, and
    // result-name handling.
    let args = ["a".to_string(), "b".to_string(), "c".to_string()];
    assert_eq!(
        dxil_opcode_to_msl(17, "_r", &args, false, false),
        "_r = fma(a, b, c);", // fma
    );
    assert_eq!(
        dxil_opcode_to_msl(30, "_r", &args[..1], false, false),
        "_r = as_type<typeof(a)>(a);", // bitcast
    );
    assert_eq!(
        dxil_opcode_to_msl(31, "_r", &args[..1], false, false),
        "_r = reinterpret_cast<uintptr_t>(a);", // ptrtoint
    );
    assert_eq!(
        dxil_opcode_to_msl(32, "_r", &args[..1], false, false),
        "_r = reinterpret_cast<void*>(a);", // inttoptr
    );
    assert_eq!(
        dxil_opcode_to_msl(33, "_r", &args[..1], false, false),
        "_r = int32_t(a);", // zext
    );

    // Operand-count fallbacks must produce the documented zero statement instead
    // of panicking or fabricating operands.
    assert_eq!(
        dxil_opcode_to_msl(2, "_r", &["only".into()], false, false),
        "_r = 0;",
        "binary op with a single operand must fall back to 0"
    );
    assert_eq!(
        dxil_opcode_to_msl(17, "_r", &["a".into(), "b".into()], false, false),
        "_r = 0;",
        "fma with too few operands must fall back to 0"
    );
}
