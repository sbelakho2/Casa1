#![allow(dead_code, unused_imports)]
//! Section 35 — Direct3D 10/11/12 translation layer tests (items 167–171).
//!
//! This file covers:
//!  167 — D3D10-to-D3D11 adapter behaviour
//!  168 — D3D11 resource creation, views, mapping, updates, copies, deferred contexts
//!  169 — D3D12 descriptor heaps, root signatures, command lists, fences, barriers
//!  170 — DXGI format conversion edge cases
//!  171 — Invalid resource dimensions and unsupported formats

use casa1::d3d10::{
    D3D10_BIND_CONSTANT_BUFFER, D3D10_CPU_ACCESS_WRITE, D3D10_SDK_VERSION, D3D10_USAGE_DYNAMIC,
    D3d10BufferDesc, D3d10DriverType, d3d10_create_device,
};
use casa1::d3d11::{D3d11Device, DeviceCreationRequest, FeatureLevel, d3d11_create_device};
use casa1::d3d12::D3d12Runtime;
use casa1::gfx::{DxgiFormat, PipelineStateDesc, ResourceState};

// ============================================================================
// Item 167 — D3D10-to-D3D11 adapter behaviour
// ============================================================================

#[test]
fn t35_04_d3d10_map_unmap_update_roundtrip() {
    let mut device =
        d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
            .expect("create device");

    let desc = D3d10BufferDesc {
        byte_width: 256,
        usage: D3D10_USAGE_DYNAMIC,
        bind_flags: D3D10_BIND_CONSTANT_BUFFER,
        cpu_access_flags: D3D10_CPU_ACCESS_WRITE,
        misc_flags: 0,
    };
    let buf_id = device.create_buffer(&desc, None).expect("create buffer");

    // Update via update_subresource
    let data: Vec<u8> = (0..64).collect();
    device
        .update_subresource(buf_id, &data)
        .expect("update subresource");

    // Map and check contents
    let mapped = device.map(buf_id).expect("map");
    assert!(!mapped.is_empty(), "mapped data should not be empty");

    // Unmap with modified data
    let modified: Vec<u8> = (128..192).collect();
    device.unmap(buf_id, &modified).expect("unmap");

    // Re-map and verify the unmapped data was actually persisted at the start
    // of the 256-byte buffer (a map/unmap that drops writes fails here).
    let re_mapped = device.map(buf_id).expect("re-map");
    assert_eq!(re_mapped.len(), 256, "buffer size must be preserved");
    assert_eq!(
        &re_mapped[..modified.len()],
        modified.as_slice(),
        "unmap must persist the written data for later maps"
    );
}

#[test]
fn t35_06_d3d10_invalid_resource_id_errors() {
    let device = d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
        .expect("create device");

    let result = device.get_d3d11_resource_id(99999);
    assert!(
        result.is_err(),
        "invalid resource id should produce an error"
    );
}

// ============================================================================
// Item 168 — D3D11 resource creation, views, mapping, updates, copies, deferred
// ============================================================================

fn make_d3d11_device() -> D3d11Device {
    d3d11_create_device(DeviceCreationRequest {
        requested_feature_levels: vec![FeatureLevel::Level10_1],
    })
    .expect("D3D11 device creation")
}

// ============================================================================
// Item 169 — D3D12 descriptor heaps, root signatures, command lists, fences, barriers
// ============================================================================

#[test]
fn t35_16_d3d12_runtime_default() {
    let rt = D3d12Runtime::new();
    let info = rt.device_info();
    assert!(!info.adapter.name.is_empty());
}

// ============================================================================
// Item 170 — DXGI format conversion edge cases
// ============================================================================

#[test]
fn t35_26_dxgi_format_unknown_value_diagnostics_only_fallback() {
    let before = DxgiFormat::format_fallback_count();
    let fmt = DxgiFormat::from_u32_diagnostics(9999);
    assert_eq!(format!("{:?}", fmt), "R8G8B8A8Unorm");
    assert!(
        DxgiFormat::format_fallback_count() > before,
        "the lossy fallback must be recorded"
    );
    // The checked production path never substitutes.
    assert!(DxgiFormat::from_u32_checked(9999).is_err());
}

#[test]
fn t35_26b_dxgi_format_checked_rejects_inexact_values() {
    // Typeless (R8G8B8A8_TYPELESS = 27), SINT (R8G8B8A8_SINT = 32),
    // SNORM-without-variant (R8G8B8A8_SNORM = 31), R8G8 (49), BC6H (95),
    // YUV (NV12 = 103) — none of these may map to a different format.
    for raw in [
        1, 4, 9, 13, 27, 31, 32, 38, 48, 49, 55, 63, 65, 66, 81, 84, 86, 89, 93, 94, 95, 96, 100,
        103, 111, 115, 133, 134,
    ] {
        assert!(
            DxgiFormat::from_u32_checked(raw).is_err(),
            "DXGI_FORMAT {raw} has no exact representation and must be rejected, not substituted"
        );
    }
}

// ============================================================================
// Item 171 — Invalid resource dimensions and unsupported formats
// ============================================================================

#[test]
fn t35_29_d3d11_invalid_resource_desc_errors() {
    let device = make_d3d11_device();
    let result = device.resource_desc(99999);
    assert!(result.is_err(), "invalid resource id should error");
}

// ============================================================================
// Additional infrastructure tests for D3D types
// ============================================================================

#[test]
fn t35_31_resource_state_from_d3d12_bits() {
    let states = ResourceState::from_d3d12_bits(0);
    assert!(!states.is_empty(), "zero bits should give Common");
    assert!(states.contains(&ResourceState::Common));
}

#[test]
fn t35_32_resource_state_read_only() {
    assert!(ResourceState::Common.is_read_only());
    assert!(ResourceState::PixelShaderResource.is_read_only());
    assert!(ResourceState::NonPixelShaderResource.is_read_only());
    assert!(ResourceState::CopySource.is_read_only());
    assert!(!ResourceState::RenderTarget.is_read_only());
    assert!(!ResourceState::UnorderedAccess.is_read_only());
    assert!(!ResourceState::CopyDest.is_read_only());
}

#[test]
fn t35_38_pipeline_state_desc() {
    let desc = PipelineStateDesc {
        label: "test-pso".into(),
        compute: false,
        render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
        depth_format: Some(DxgiFormat::D24UnormS8Uint),
    };
    assert_eq!(desc.label, "test-pso");
    assert!(!desc.compute);
}

#[test]
fn t35_39_d3d11_gpu_profile_signature() {
    let device = make_d3d11_device();
    let sig = device.gpu_profile_signature();
    assert!(!sig.is_empty(), "GPU profile signature should not be empty");
}
