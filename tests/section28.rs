//! Section 28 — DXR Raytracing Conformance Tests
//!
//! Verifies the D3D12 raytracing bridge to Metal 3.0 acceleration structures:
//!   - BLAS (Bottom-Level Acceleration Structure) creation
//!   - TLAS (Top-Level Acceleration Structure) creation
//!   - Build/copy/postbuild info operations
//!   - DispatchRays shader table setup
//!   - D3D12_RAYTRACING_TIER_1_1 feature level verification
//!   - Metal acceleration structure handle management
//!   - Pipeline state object (set_pipeline_state1) integration

mod support;

use casa1::d3d12::{
    D3D12BuildAccelerationStructureDesc, D3D12BuildRaytracingInputs, D3D12DispatchRaysDesc,
    D3D12RaytracingGeometryDesc, D3d12Runtime,
};
use casa1::gfx::{GraphicsBackend, PipelineStateDesc, RootSignatureDesc};

// ---------------------------------------------------------------------------
// Helper: create a D3d12Runtime with a GraphicsBackend
// ---------------------------------------------------------------------------

fn create_runtime() -> D3d12Runtime {
    D3d12Runtime::new()
}

#[allow(dead_code)]
fn create_runtime_with_backend() -> D3d12Runtime {
    let backend = GraphicsBackend::new();
    D3d12Runtime::from_backend(backend)
}

/// Set up the common command-list scaffolding (allocator, root signature,
/// compute PSO, graphics command list) used by every raytracing test.
fn setup_command_list(runtime: &mut D3d12Runtime, label: &str) -> u64 {
    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 0,
        ..Default::default()
    });
    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: label.to_string(),
            compute: true,
            render_target_formats: vec![],
            depth_format: None,
        },
    );
    runtime.create_graphics_command_list(allocator, pso, false)
}

// ---------------------------------------------------------------------------
// t28_01: BLAS creation — bottom-level acceleration structure
// ---------------------------------------------------------------------------

#[test]
fn t28_01_blas_creation_bottom_level() {
    let mut runtime = create_runtime();

    // Build a BLAS description with triangle geometry
    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0, // D3D12_RAYTRACING_GEOMETRY_TYPE_TRIANGLES
        flags: 0,
        vertex_buffer: 0x1000,
        vertex_format: 71, // DXGI_FORMAT_R32G32B32_FLOAT
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0x2000,
        index_format: 57, // DXGI_FORMAT_R16_UINT
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0, // BOTTOM_LEVEL
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x1_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x1_0000_1000,
    };

    // Build the BLAS
    let list_id = setup_command_list(&mut runtime, "raytrace_blas");

    let result = runtime.build_raytracing_acceleration_structure(list_id, &desc);
    assert!(result.is_ok(), "BLAS build should succeed");

    let gpu_address = result.unwrap();
    assert_eq!(
        gpu_address, 0x1_0000_0000,
        "BLAS should return dest_address"
    );

    // Verify the acceleration structure metadata
    let accel = runtime.acceleration_structure(0x1_0000_0000);
    assert!(accel.is_some(), "BLAS should be stored");
    let accel = accel.unwrap();
    assert!(!accel.is_top_level, "BLAS should not be top-level");
    assert!(accel.built, "BLAS should be marked as built");
    assert!(
        accel.gpu_address == 0x1_0000_0000,
        "GPU address should match"
    );
    assert!(
        accel.metal_accel_handle > 0,
        "Metal handle should be non-zero"
    );
    assert!(accel.size > 0, "BLAS size should be non-zero");
}

// ---------------------------------------------------------------------------
// t28_02: TLAS creation — top-level acceleration structure
// ---------------------------------------------------------------------------

#[test]
fn t28_02_tlas_creation_top_level() {
    let mut runtime = create_runtime();

    // Build a TLAS description (instance-based, no explicit geometries)
    let inputs = D3D12BuildRaytracingInputs {
        ty: 1, // TOP_LEVEL
        flags: 0,
        num_descs: 2, // 2 instances
        geometries: vec![],
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x2_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x2_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_tlas");

    let result = runtime.build_raytracing_acceleration_structure(list_id, &desc);
    assert!(result.is_ok(), "TLAS build should succeed");

    let gpu_address = result.unwrap();
    assert_eq!(
        gpu_address, 0x2_0000_0000,
        "TLAS should return dest_address"
    );

    // Verify metadata
    let accel = runtime.acceleration_structure(0x2_0000_0000);
    assert!(accel.is_some(), "TLAS should be stored");
    let accel = accel.unwrap();
    assert!(accel.is_top_level, "TLAS should be top-level");
    assert!(accel.built, "TLAS should be marked as built");
    // Documented TLAS sizing (src/d3d12.rs): 64-byte header + 72-byte
    // instance descriptor per instance, floored at the 256-byte minimum
    // viable size. 64 + 2*72 = 208 < 256, so the floor applies.
    assert_eq!(
        accel.size, 256,
        "TLAS size must be the documented header + per-instance size, floored at 256"
    );
}

// ---------------------------------------------------------------------------
// t28_03: Copy acceleration structure (COPY mode)
// ---------------------------------------------------------------------------

#[test]
fn t28_03_copy_acceleration_structure() {
    let mut runtime = create_runtime();

    // First, build a BLAS
    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0x1000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0x2000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x3_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x3_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_copy_src");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Now copy the BLAS to a new address
    let result = runtime.copy_raytracing_acceleration_structure(
        list_id,
        0x3_0000_2000, // dest
        0x3_0000_0000, // source
        0,             // COPY mode
    );
    assert!(result.is_ok(), "Copy AS should succeed");

    // Verify both source and dest exist
    assert!(
        runtime.acceleration_structure(0x3_0000_0000).is_some(),
        "Source AS should exist"
    );
    assert!(
        runtime.acceleration_structure(0x3_0000_2000).is_some(),
        "Dest AS should exist"
    );

    let src = runtime.acceleration_structure(0x3_0000_0000).unwrap();
    let dst = runtime.acceleration_structure(0x3_0000_2000).unwrap();
    assert_eq!(src.size, dst.size, "Copied AS should have same size");
    assert_eq!(
        src.is_top_level, dst.is_top_level,
        "Copied AS should have same type"
    );
    assert_eq!(
        dst.gpu_address, 0x3_0000_2000,
        "Dest GPU address should be updated"
    );
}

// ---------------------------------------------------------------------------
// t28_04: Compact acceleration structure (COMPACT mode)
// ---------------------------------------------------------------------------

#[test]
fn t28_04_compact_acceleration_structure() {
    let mut runtime = create_runtime();

    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0x4000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0x5000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x4_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x4_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_compact");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Compact the AS
    let result = runtime.copy_raytracing_acceleration_structure(
        list_id,
        0x4_0000_2000, // dest
        0x4_0000_0000, // source
        1,             // COMPACT mode
    );
    assert!(result.is_ok(), "Compact AS should succeed");
    assert!(
        runtime.acceleration_structure(0x4_0000_2000).is_some(),
        "Compacted AS should exist"
    );
}

// ---------------------------------------------------------------------------
// t28_05: Post-build info — compacted size query
// ---------------------------------------------------------------------------

#[test]
fn t28_05_postbuild_info_compacted_size() {
    let mut runtime = create_runtime();

    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0x5000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0x6000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x5_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x5_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_postbuild");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Query POSTBUILD_INFO_COMPACTED_SIZE (type 1)
    let mut output_buf = vec![0u8; 16];
    let result = runtime.emit_raytracing_acceleration_structure_postbuild_info(
        list_id,
        1, // D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_COMPACTED_SIZE
        &[0x5_0000_0000],
        &mut output_buf,
    );
    assert!(result.is_ok(), "Post-build info should succeed");

    // Verify the compacted size was written (non-zero)
    let compacted_size = u64::from_le_bytes(output_buf[0..8].try_into().unwrap());
    assert!(compacted_size > 0, "Compacted size should be non-zero");
}

// ---------------------------------------------------------------------------
// t28_06: Post-build info — serialization info
// ---------------------------------------------------------------------------

#[test]
fn t28_06_postbuild_info_serialization() {
    let mut runtime = create_runtime();

    // Build a BLAS
    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0x6000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0x7000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x6_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x6_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_serialize");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Query POSTBUILD_INFO_SERIALIZATION (type 3)
    let mut output_buf = vec![0u8; 32];
    let result = runtime.emit_raytracing_acceleration_structure_postbuild_info(
        list_id,
        3, // D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_SERIALIZATION
        &[0x6_0000_0000],
        &mut output_buf,
    );
    assert!(
        result.is_ok(),
        "Serialization post-build info should succeed"
    );

    let serialized_size = u64::from_le_bytes(output_buf[0..8].try_into().unwrap());
    assert!(serialized_size > 0, "Serialized size should be non-zero");

    let num_blas_pointers = u64::from_le_bytes(output_buf[8..16].try_into().unwrap());
    // For a BLAS, num bottom-level pointers should be 0
    assert_eq!(
        num_blas_pointers, 0,
        "BLAS serialization should have 0 bottom-level pointers"
    );
}

// ---------------------------------------------------------------------------
// t28_07: DispatchRays — shader table setup and dispatch
// ---------------------------------------------------------------------------

#[test]
fn t28_07_dispatch_rays_shader_table() {
    let mut runtime = create_runtime();

    let list_id = setup_command_list(&mut runtime, "raytrace_dispatch");

    // Set up a raytracing pipeline state
    let dxil_bytecode = vec![
        0x44, 0x58, 0x42, 0x43, 0x00, // DXBC header mock
    ];
    let pso_result = runtime.set_pipeline_state1(list_id, 0x7000_0000, dxil_bytecode);
    assert!(pso_result.is_ok(), "set_pipeline_state1 should succeed");

    // Verify the pipeline state was stored
    let pso = runtime.get_raytracing_pipeline_state(0x7000_0000);
    assert!(pso.is_some(), "Raytracing PSO should be stored");
    let pso = pso.unwrap();
    assert_eq!(
        pso.max_recursion_depth, 1,
        "Default max recursion depth should be 1"
    );
    assert_eq!(pso.payload_size, 32, "Default payload size should be 32");
    assert_eq!(pso.attribute_size, 8, "Default attribute size should be 8");

    // Dispatch rays with shader table addresses
    let dispatch_desc = D3D12DispatchRaysDesc {
        raygen_shader_start_address: 0x7000_0100,
        raygen_shader_size: 256,
        miss_shader_start_address: 0x7000_0200,
        miss_shader_size: 128,
        miss_shader_stride: 128,
        hit_group_start_address: 0x7000_0300,
        hit_group_size: 512,
        hit_group_stride: 256,
        callable_shader_start_address: 0,
        callable_shader_size: 0,
        callable_shader_stride: 0,
        width: 32,
        height: 32,
        depth: 1,
    };

    let dispatch_result = runtime.dispatch_rays(list_id, &dispatch_desc);
    assert!(dispatch_result.is_ok(), "DispatchRays should succeed");
}

// ---------------------------------------------------------------------------
// t28_08: DispatchRays with zero dimensions — should not error
// ---------------------------------------------------------------------------

#[test]
fn t28_08_dispatch_rays_zero_dimensions() {
    let mut runtime = create_runtime();

    let list_id = setup_command_list(&mut runtime, "raytrace_zero");

    // Dispatch with zero dimensions — should still return Ok
    let dispatch_desc = D3D12DispatchRaysDesc {
        raygen_shader_start_address: 0x8000_0100,
        raygen_shader_size: 256,
        miss_shader_start_address: 0x8000_0200,
        miss_shader_size: 128,
        miss_shader_stride: 128,
        hit_group_start_address: 0x8000_0300,
        hit_group_size: 512,
        hit_group_stride: 256,
        callable_shader_start_address: 0,
        callable_shader_size: 0,
        callable_shader_stride: 0,
        width: 0,
        height: 0,
        depth: 0,
    };

    let dispatch_result = runtime.dispatch_rays(list_id, &dispatch_desc);
    assert!(
        dispatch_result.is_ok(),
        "DispatchRays with zero dimensions should not error"
    );
}

// ---------------------------------------------------------------------------
// t28_09: Acceleration structure serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn t28_09_as_serialization_deserialization() {
    let mut runtime = create_runtime();

    // Build a BLAS
    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0x9000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0xA000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x9_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0x9_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_serde");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // SERIALIZE: copy to serialize output address
    let serialize_result = runtime.copy_raytracing_acceleration_structure(
        list_id,
        0x9_0000_2000, // serialize dest
        0x9_0000_0000, // source
        3,             // SERIALIZE mode
    );
    assert!(serialize_result.is_ok(), "Serialize AS should succeed");

    // DESERIALIZE: copy from serialize output to final address
    let deserialize_result = runtime.copy_raytracing_acceleration_structure(
        list_id,
        0x9_0000_3000, // deserialize dest
        0x9_0000_2000, // serialize source
        4,             // DESERIALIZE mode
    );
    assert!(deserialize_result.is_ok(), "Deserialize AS should succeed");

    // Verify the final AS exists and that the round trip propagated the
    // source AS metadata: the deserialized structure must have the same size,
    // type, and built state as the original BLAS (a round trip that drops or
    // fabricates metadata fails here).
    let src = runtime
        .acceleration_structure(0x9_0000_0000)
        .expect("source AS should exist");
    let serialized = runtime
        .acceleration_structure(0x9_0000_2000)
        .expect("serialized AS should exist");
    let deserialized = runtime
        .acceleration_structure(0x9_0000_3000)
        .expect("deserialized AS should exist");
    for (stage, record) in [("serialized", serialized), ("deserialized", deserialized)] {
        assert_eq!(
            record.size, src.size,
            "{stage} AS must preserve the source size"
        );
        assert_eq!(
            record.is_top_level, src.is_top_level,
            "{stage} AS must preserve the source type"
        );
        assert_eq!(record.built, src.built, "{stage} AS must stay built");
        assert!(
            record.metal_accel_handle > 0,
            "{stage} AS must carry a Metal handle"
        );
    }
}

// ---------------------------------------------------------------------------
// t28_10: Serialize/deserialize TLAS with bottom-level pointers
// ---------------------------------------------------------------------------

#[test]
fn t28_10_tlas_serialization_info() {
    let mut runtime = create_runtime();

    // Build a TLAS
    let inputs = D3D12BuildRaytracingInputs {
        ty: 1, // TOP_LEVEL
        flags: 0,
        num_descs: 3,
        geometries: vec![],
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0xA_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0xA_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_tlas_ser");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Query serialization info on TLAS
    let mut output_buf = vec![0u8; 32];
    let result = runtime.emit_raytracing_acceleration_structure_postbuild_info(
        list_id,
        3, // D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_SERIALIZATION
        &[0xA_0000_0000],
        &mut output_buf,
    );
    assert!(
        result.is_ok(),
        "TLAS serialization post-build info should succeed"
    );

    let num_blas = u64::from_le_bytes(output_buf[8..16].try_into().unwrap());
    // The documented serialization model (src/d3d12.rs): a top-level AS reports
    // exactly one bottom-level pointer entry; a bottom-level AS reports zero
    // (covered by t28_06). Cross-check the serialized size against the stored
    // record so the query must agree with the acceleration structure itself.
    assert_eq!(
        num_blas, 1,
        "TLAS serialization should report 1 bottom-level pointer"
    );
    let serialized_size = u64::from_le_bytes(output_buf[0..8].try_into().unwrap());
    assert_eq!(
        serialized_size,
        runtime
            .acceleration_structure(0xA_0000_0000)
            .expect("TLAS should be stored")
            .size,
        "serialized size must match the stored TLAS record"
    );
}

// ---------------------------------------------------------------------------
// t28_11: D3D12_RAYTRACING_TIER_1_1 feature level verification
// ---------------------------------------------------------------------------

#[test]
fn t28_11_raytracing_tier_feature_detection() {
    let runtime = create_runtime();

    // Check device info for raytracing capability
    let device_info = runtime.device_info();

    // The D3d12FeatureOptions raytracing flag must mirror the backend
    // capability (src/d3d12.rs `device_info`), and the adapter must be
    // identified — a runtime whose feature reporting is disconnected from
    // its backend fails here.
    let caps = runtime.backend().capabilities();
    assert_eq!(
        device_info.features.raytracing, caps.raytracing,
        "D3D12 raytracing feature flag must mirror the backend capability"
    );
    assert!(
        !device_info.adapter.name.is_empty(),
        "device info must report a named adapter"
    );

    // D3D12_RAYTRACING_TIER_1_1 contract: any raytracing-capable device must
    // also support argument buffers (the Metal feature raytracing depends on
    // for resource binding, per host_gpu_profile_from_name).
    if device_info.features.raytracing {
        assert!(
            caps.argument_buffers,
            "raytracing-capable device must support argument buffers"
        );
    }

    // Tearing is the documented always-on presentation feature.
    assert!(
        runtime
            .backend()
            .query_feature(casa1::gfx::FeatureQuery::Tearing),
        "Tearing must be reported"
    );
}

// ---------------------------------------------------------------------------
// t28_12: Raytracing pipeline state object management
// ---------------------------------------------------------------------------

#[test]
fn t28_12_raytracing_pipeline_state_management() {
    let mut runtime = create_runtime();

    let list_id = setup_command_list(&mut runtime, "raytrace_pso");

    // Create multiple raytracing PSOs
    let dxil_bytecode_1 = vec![0x44, 0x58, 0x42, 0x43, 0x01];
    let dxil_bytecode_2 = vec![0x44, 0x58, 0x42, 0x43, 0x02];

    runtime
        .set_pipeline_state1(list_id, 0xB000_0000, dxil_bytecode_1)
        .unwrap();
    runtime
        .set_pipeline_state1(list_id, 0xB000_0100, dxil_bytecode_2)
        .unwrap();

    // Verify both are stored independently
    let pso1 = runtime.get_raytracing_pipeline_state(0xB000_0000);
    let pso2 = runtime.get_raytracing_pipeline_state(0xB000_0100);

    assert!(pso1.is_some(), "First PSO should be stored");
    assert!(pso2.is_some(), "Second PSO should be stored");

    // Verify they have different DXIL bytecodes
    assert_ne!(
        pso1.unwrap().dxil_bytecode,
        pso2.unwrap().dxil_bytecode,
        "Different PSOs should have different DXIL bytecodes"
    );

    // Non-existent PSO should return None
    let nonexistent = runtime.get_raytracing_pipeline_state(0xFFFF_FFFF);
    assert!(nonexistent.is_none(), "Non-existent PSO should return None");
}

// ---------------------------------------------------------------------------
// t28_13: Multiple acceleration structures with unique handles
// ---------------------------------------------------------------------------

#[test]
fn t28_13_multiple_acceleration_structures() {
    let mut runtime = create_runtime();

    let list_id = setup_command_list(&mut runtime, "raytrace_multi_as");

    // Build multiple BLASes
    for i in 0..5 {
        let base = 0xC_0000_0000 + (i as u64) * 0x1000_0000;
        let geometries = vec![D3D12RaytracingGeometryDesc {
            ty: 0,
            flags: 0,
            vertex_buffer: base + 0x1000,
            vertex_format: 71,
            vertex_stride: 12,
            vertex_count: 3 + i,
            index_buffer: base + 0x2000,
            index_format: 57,
            index_count: 3 + i,
        }];

        let inputs = D3D12BuildRaytracingInputs {
            ty: 0,
            flags: 0,
            num_descs: 1,
            geometries,
        };

        let desc = D3D12BuildAccelerationStructureDesc {
            dest_address: base,
            inputs,
            source_address: 0,
            scratch_address: base + 0x1000,
        };

        let result = runtime.build_raytracing_acceleration_structure(list_id, &desc);
        assert!(result.is_ok(), "BLAS {} build should succeed", i);
    }

    // Verify all 5 BLASes exist with unique metal handles
    let mut metal_handles = std::collections::HashSet::new();
    for i in 0..5 {
        let base = 0xC_0000_0000 + (i as u64) * 0x1000_0000;
        let accel = runtime.acceleration_structure(base);
        assert!(accel.is_some(), "BLAS {} should exist", i);
        let accel = accel.unwrap();
        assert!(
            metal_handles.insert(accel.metal_accel_handle),
            "Metal handle {} should be unique",
            accel.metal_accel_handle
        );
    }

    assert_eq!(
        metal_handles.len(),
        5,
        "All 5 BLAS should have unique Metal handles"
    );
}

// ---------------------------------------------------------------------------
// t28_14: Visualization copy mode
// ---------------------------------------------------------------------------

#[test]
fn t28_14_visualization_copy_mode() {
    let mut runtime = create_runtime();

    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0xD000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0xE000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0xD_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0xD_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_viz");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Visualization copy (mode 2)
    let result = runtime.copy_raytracing_acceleration_structure(
        list_id,
        0xD_0000_2000,
        0xD_0000_0000,
        2, // VISUALIZATION mode
    );
    assert!(result.is_ok(), "Visualization copy should succeed");
    assert!(
        runtime.acceleration_structure(0xD_0000_2000).is_some(),
        "Visualization target should exist"
    );
}

// ---------------------------------------------------------------------------
// t28_15: Post-build info — tools visualization size
// ---------------------------------------------------------------------------

#[test]
fn t28_15_postbuild_info_tools_visualization() {
    let mut runtime = create_runtime();

    let geometries = vec![D3D12RaytracingGeometryDesc {
        ty: 0,
        flags: 0,
        vertex_buffer: 0xE000,
        vertex_format: 71,
        vertex_stride: 12,
        vertex_count: 3,
        index_buffer: 0xF000,
        index_format: 57,
        index_count: 3,
    }];

    let inputs = D3D12BuildRaytracingInputs {
        ty: 0,
        flags: 0,
        num_descs: 1,
        geometries,
    };

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0xE_0000_0000,
        inputs,
        source_address: 0,
        scratch_address: 0xE_0000_1000,
    };

    let list_id = setup_command_list(&mut runtime, "raytrace_tools_viz");

    runtime
        .build_raytracing_acceleration_structure(list_id, &desc)
        .unwrap();

    // Query POSTBUILD_INFO_TOOLS_VISUALIZATION (type 2)
    let mut output_buf = vec![0u8; 16];
    let result = runtime.emit_raytracing_acceleration_structure_postbuild_info(
        list_id,
        2, // D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_TOOLS_VISUALIZATION
        &[0xE_0000_0000],
        &mut output_buf,
    );
    assert!(
        result.is_ok(),
        "Tools visualization post-build info should succeed"
    );

    let vis_size = u64::from_le_bytes(output_buf[0..8].try_into().unwrap());
    assert!(vis_size > 0, "Visualization size should be non-zero");
}
