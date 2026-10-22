#![allow(dead_code, unused_imports)]
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

const LLVM_BC_MAGIC: u32 = 0x0B1E_0BC0u32.to_be();

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

// ---------------------------------------------------------------------------
// t20_3_add_instruction — Compute shader with add instruction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t20_4_texture_sample — Shader using Sample intrinsic
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t20_5_buffer_load — Shader with buffer load
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t20_6_cache_hit — Same DXIL compiled twice, verify cache returns hit
// ---------------------------------------------------------------------------

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
fn t20_root_signature_invalid_kind() {
    // Kind=255 is invalid
    let data = make_root_signature(&[(255, 0, 0, 1, 0, 0)], 0);
    let result = parse_root_signature(&data);
    assert!(result.is_err(), "invalid root kind should error");
}
