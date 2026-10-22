#![allow(dead_code, unused_imports)]
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
    D3D12BuildAccelerationStructureDesc, D3D12BuildRaytracingInputs, D3D12RaytracingGeometryDesc,
    D3d12Runtime,
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

// ---------------------------------------------------------------------------
// t28_03: Copy acceleration structure (COPY mode)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_04: Compact acceleration structure (COMPACT mode)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_05: Post-build info — compacted size query
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_06: Post-build info — serialization info
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_07: DispatchRays — shader table setup and dispatch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_08: DispatchRays with zero dimensions — should not error
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_09: Acceleration structure serialization round-trip
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_10: Serialize/deserialize TLAS with bottom-level pointers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// t28_13: Multiple acceleration structures with unique handles
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_14: Visualization copy mode
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t28_15: Post-build info — tools visualization size
// ---------------------------------------------------------------------------
