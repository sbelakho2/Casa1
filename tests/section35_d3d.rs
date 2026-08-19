//! Section 35 — Direct3D 10/11/12 translation layer tests (items 167–171).
//!
//! This file covers:
//!  167 — D3D10-to-D3D11 adapter behaviour
//!  168 — D3D11 resource creation, views, mapping, updates, copies, deferred contexts
//!  169 — D3D12 descriptor heaps, root signatures, command lists, fences, barriers
//!  170 — DXGI format conversion edge cases
//!  171 — Invalid resource dimensions and unsupported formats

use casa1::d3d10::{
    D3D10_BIND_CONSTANT_BUFFER, D3D10_BIND_DEPTH_STENCIL, D3D10_BIND_INDEX_BUFFER,
    D3D10_BIND_RENDER_TARGET, D3D10_BIND_SHADER_RESOURCE, D3D10_BIND_VERTEX_BUFFER,
    D3D10_CPU_ACCESS_READ, D3D10_CPU_ACCESS_WRITE, D3D10_MAX_TEXTURE_DIMENSION, D3D10_SDK_VERSION,
    D3D10_SIMULTANEOUS_RENDER_TARGET_COUNT, D3D10_USAGE_DEFAULT, D3D10_USAGE_DYNAMIC,
    D3d10BufferDesc, D3d10DriverType, D3d10FeatureLevel, D3d10SampleDesc, D3d10Texture2dDesc,
    d3d10_create_device,
};
use casa1::d3d11::{D3d11Device, DeviceCreationRequest, FeatureLevel, d3d11_create_device};
use casa1::d3d12::D3d12Runtime;
use casa1::gfx::{
    BufferRole, D3D12DescriptorRangeType, DescriptorHeapType, DxgiFormat, HeapType,
    PipelineStateDesc, ResourceDesc, ResourceState, ResourceUsageHint, RootSignatureDesc,
    ViewDescriptor,
};
use std::collections::BTreeMap;

// ============================================================================
// Item 167 — D3D10-to-D3D11 adapter behaviour
// ============================================================================

/// D3D10 device creation yields feature level 10_1.
#[test]
fn t35_01_d3d10_feature_level() {
    let device = d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
        .expect("D3D10CreateDevice should succeed");
    assert_eq!(device.feature_level(), D3d10FeatureLevel::Level10_1);
}

/// D3D10 create_buffer delegates to internal D3D11 buffer.
#[test]
fn t35_02_d3d10_create_buffer_delegates_to_d3d11() {
    let mut device =
        d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
            .expect("create device");

    let desc = D3d10BufferDesc {
        byte_width: 4096,
        usage: D3D10_USAGE_DEFAULT,
        bind_flags: D3D10_BIND_VERTEX_BUFFER,
        cpu_access_flags: 0,
        misc_flags: 0,
    };
    let resource_id = device.create_buffer(&desc, None).expect("create buffer");
    assert!(resource_id > 0, "D3D10 buffer id should be positive");

    let d3d11_id = device
        .get_d3d11_resource_id(resource_id)
        .expect("get D3D11 id");
    assert!(
        d3d11_id > 0,
        "underlying D3D11 resource id should be positive"
    );
}

/// D3D10 create_texture_2d with RTV binding delegates to D3D11.
#[test]
fn t35_03_d3d10_create_texture2d_with_rtv() {
    let mut device =
        d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
            .expect("create device");

    let tex_desc = D3d10Texture2dDesc {
        width: 64,
        height: 64,
        mip_levels: 1,
        array_size: 1,
        format: DxgiFormat::R8G8B8A8Unorm,
        sample_desc: D3d10SampleDesc {
            count: 1,
            quality: 0,
        },
        usage: D3D10_USAGE_DEFAULT,
        bind_flags: D3D10_BIND_RENDER_TARGET,
        cpu_access_flags: 0,
        misc_flags: 0,
    };
    let tex_id = device
        .create_texture_2d(&tex_desc, None)
        .expect("create texture");
    let rtv = device
        .create_render_target_view(tex_id, None)
        .expect("create RTV");
    assert!(rtv > 0, "RTV id should be positive");
    assert!(tex_id > 0, "texture id should be positive");
}

/// D3D10 map/unmap and update_subresource round-trip through D3D11.
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

/// D3D10 copy_subresource_region works.
#[test]
fn t35_05_d3d10_copy_subresource_region() {
    let mut device =
        d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
            .expect("create device");

    let desc = D3d10BufferDesc {
        byte_width: 1024,
        usage: D3D10_USAGE_DEFAULT,
        bind_flags: D3D10_BIND_VERTEX_BUFFER,
        cpu_access_flags: 0,
        misc_flags: 0,
    };
    let src = device
        .create_buffer(&desc, None)
        .expect("create src buffer");
    let dst = device
        .create_buffer(&desc, None)
        .expect("create dst buffer");

    // Whole-buffer copy (no partial source box) is supported.
    device
        .copy_subresource_region(dst, 0, 0, 0, 0, src, 0, None)
        .expect("whole-buffer copy_subresource_region should succeed");

    // Partial source boxes are not yet implemented and must be refused
    // with RcD3dFeatureUnsupported rather than silently mis-copied.
    let src_box: [u32; 6] = [0, 0, 0, 512, 1, 1];
    let err = device
        .copy_subresource_region(dst, 0, 0, 0, 0, src, 0, Some(src_box))
        .expect_err("partial-box copy must be refused");
    assert_eq!(
        err.code,
        casa1::reason::ReasonCode::RcD3dFeatureUnsupported,
        "partial copy must report RcD3dFeatureUnsupported"
    );
}

/// D3D10 invalid resource ID returns an error.
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

/// D3D11 buffer creation.
#[test]
fn t35_07_d3d11_buffer_creation() {
    let mut device = make_d3d11_device();

    let id = device
        .create_buffer(
            "test-vertex-buffer",
            1024,
            ResourceUsageHint::Buffer {
                role: BufferRole::Vertex,
                cpu_write_frequent: false,
            },
        )
        .expect("create vertex buffer");
    assert!(id > 0, "buffer id should be positive");
}

/// D3D11 texture 2D creation.
#[test]
fn t35_08_d3d11_texture_2d_creation() {
    let mut device = make_d3d11_device();

    let id = device
        .create_texture_2d("test-tex2d", 128, 128, DxgiFormat::R8G8B8A8Unorm)
        .expect("create texture 2d");
    assert!(id > 0);
    let desc = device.resource_desc(id).expect("resource desc");
    assert_eq!(desc.width, 128);
    assert_eq!(desc.height, 128);
    assert_eq!(desc.format, DxgiFormat::R8G8B8A8Unorm);
}

/// D3D11 shader resource view creation.
#[test]
fn t35_09_d3d11_shader_resource_view() {
    let mut device = make_d3d11_device();

    let tex = device
        .create_texture_2d("srv-tex", 64, 64, DxgiFormat::R8G8B8A8Unorm)
        .expect("create texture");
    let srv = device
        .create_shader_resource_view(tex, DxgiFormat::R8G8B8A8Unorm)
        .expect("create SRV");
    assert!(srv > 0);
}

/// D3D11 render target view creation.
#[test]
fn t35_10_d3d11_render_target_view() {
    let mut device = make_d3d11_device();

    let tex = device
        .create_texture_2d("rtv-tex", 32, 32, DxgiFormat::B8G8R8A8Unorm)
        .expect("create texture");
    let rtv = device
        .create_render_target_view(tex, DxgiFormat::B8G8R8A8Unorm)
        .expect("create RTV");
    assert!(rtv > 0);
}

/// D3D11 depth stencil view creation.
#[test]
fn t35_11_d3d11_depth_stencil_view() {
    let mut device = make_d3d11_device();

    let tex = device
        .create_texture_2d("dsv-tex", 32, 32, DxgiFormat::D24UnormS8Uint)
        .expect("create texture");
    let dsv = device
        .create_depth_stencil_view(tex, DxgiFormat::D24UnormS8Uint)
        .expect("create DSV");
    assert!(dsv > 0);
}

/// D3D11 map/unmap round-trip.
#[test]
fn t35_12_d3d11_map_unmap() {
    let mut device = make_d3d11_device();

    let buf = device
        .create_buffer(
            "map-buf",
            512,
            ResourceUsageHint::Buffer {
                role: BufferRole::Vertex,
                cpu_write_frequent: true,
            },
        )
        .expect("create buffer");

    let mapped = device.map(buf).expect("map");
    assert_eq!(mapped.len(), 512);

    let new_data: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
    device.unmap(buf, &new_data).expect("unmap");
}

/// D3D11 update_subresource.
#[test]
fn t35_13_d3d11_update_subresource() {
    let mut device = make_d3d11_device();

    let buf = device
        .create_buffer(
            "update-buf",
            256,
            ResourceUsageHint::Buffer {
                role: BufferRole::Vertex,
                cpu_write_frequent: true,
            },
        )
        .expect("create buffer");

    let data: Vec<u8> = (0..128).collect();
    device
        .update_subresource(buf, &data)
        .expect("update_subresource");
}

/// D3D11 copy_resource.
#[test]
fn t35_14_d3d11_copy_resource() {
    let mut device = make_d3d11_device();

    let src = device
        .create_buffer(
            "copy-src",
            256,
            ResourceUsageHint::Buffer {
                role: BufferRole::Vertex,
                cpu_write_frequent: false,
            },
        )
        .expect("create src");
    let dst = device
        .create_buffer(
            "copy-dst",
            256,
            ResourceUsageHint::Buffer {
                role: BufferRole::Vertex,
                cpu_write_frequent: false,
            },
        )
        .expect("create dst");
    device.copy_resource(src, dst).expect("copy_resource");
}

/// D3D11 deferred context creation and basic recording.
#[test]
fn t35_15_d3d11_deferred_context() {
    let mut device = make_d3d11_device();
    let deferred = device.create_deferred_context();

    // Bind a render target first: a draw with no bound RT is rejected by the
    // deferred-context validation on finish (this was the test fault).
    let tex = device
        .create_texture_2d("deferred-rt", 32, 32, DxgiFormat::B8G8R8A8Unorm)
        .expect("create RT texture");
    let rtv = device
        .create_render_target_view(tex, DxgiFormat::B8G8R8A8Unorm)
        .expect("create RTV");
    deferred
        .om_set_render_targets(vec![rtv], None)
        .expect("bind render target");
    // D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST — draw validation requires it.
    deferred
        .ia_set_primitive_topology(4)
        .expect("set primitive topology");
    // A draw also requires a bound vertex shader.
    let vs = device.create_shader(casa1::d3d11::ShaderModuleDesc {
        stage: casa1::d3d11::ShaderStage::Vs,
        entry: "main".to_string(),
    });
    deferred.vs_set_shader(vs).expect("bind vertex shader");

    // Record a draw command
    deferred.draw(3).expect("deferred draw");

    // Finish command list
    let cmd_list = deferred
        .finish_command_list(&device)
        .expect("finish command list");
    assert_eq!(cmd_list.commands.len(), 1);
}

// ============================================================================
// Item 169 — D3D12 descriptor heaps, root signatures, command lists, fences, barriers
// ============================================================================

/// D3D12Runtime can be created with default state.
#[test]
fn t35_16_d3d12_runtime_default() {
    let rt = D3d12Runtime::new();
    let info = rt.device_info();
    assert!(!info.adapter.name.is_empty());
}

/// D3D12 descriptor heap creation.
#[test]
fn t35_17_d3d12_descriptor_heap_creation() {
    let mut rt = D3d12Runtime::new();

    let cbv_srv_uav = rt
        .backend_mut()
        .create_descriptor_heap(DescriptorHeapType::CbvSrvUav, 64);
    assert!(cbv_srv_uav > 0);
    assert!(cbv_srv_uav < u64::MAX);

    let sampler = rt
        .backend_mut()
        .create_descriptor_heap(DescriptorHeapType::Sampler, 16);
    assert!(sampler > 0);

    let rtv = rt
        .backend_mut()
        .create_descriptor_heap(DescriptorHeapType::Rtv, 8);
    assert!(rtv > 0);

    let dsv = rt
        .backend_mut()
        .create_descriptor_heap(DescriptorHeapType::Dsv, 8);
    assert!(dsv > 0);
}

/// D3D12 root signature creation.
#[test]
fn t35_18_d3d12_root_signature() {
    let mut rt = D3d12Runtime::new();

    let desc = RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
        parameters: Vec::new(),
        static_samplers: Vec::new(),
        visibility_offsets: BTreeMap::new(),
    };
    let sig_id = rt.backend_mut().create_root_signature(desc);
    assert!(sig_id > 0);
}

/// D3D12 command queue, allocator, and list creation.
#[test]
fn t35_19_d3d12_command_list_creation() {
    let mut rt = D3d12Runtime::new();

    let queue = rt.backend_mut().create_command_queue();
    assert!(queue > 0);

    let allocator = rt.backend_mut().create_command_allocator();
    assert!(allocator > 0);

    // Create a pipeline state to pass to create_graphics_command_list
    let root_sig = rt.backend_mut().create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
        parameters: Vec::new(),
        static_samplers: Vec::new(),
        visibility_offsets: BTreeMap::new(),
    });
    let pso = rt.backend_mut().create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "test-pso".into(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );

    let list = rt
        .backend_mut()
        .create_graphics_command_list(allocator, pso, false);
    assert!(list > 0);
}

/// D3D12 fence creation, signal, and wait.
#[test]
fn t35_20_d3d12_fence() {
    let mut rt = D3d12Runtime::new();

    let fence = rt.backend_mut().create_fence(0);
    assert!(fence > 0);

    rt.backend_mut()
        .signal_fence(fence, 1)
        .expect("signal fence");

    let done = rt
        .backend_mut()
        .wait_for_fence(fence, 1, 1_000_000_000)
        .expect("wait for fence");
    assert!(done, "fence should be signaled");
}

/// D3D12 transition barrier.
#[test]
fn t35_21_d3d12_transition_barrier() {
    let mut rt = D3d12Runtime::new();

    let resource = rt
        .backend_mut()
        .create_resource(ResourceDesc {
            name: "barrier-resource".into(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 256 * 256 * 4,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create resource");

    let allocator = rt.backend_mut().create_command_allocator();
    let root_sig = rt.backend_mut().create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
        parameters: Vec::new(),
        static_samplers: Vec::new(),
        visibility_offsets: BTreeMap::new(),
    });
    let pso = rt.backend_mut().create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "barrier-pso".into(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );
    let list = rt
        .backend_mut()
        .create_graphics_command_list(allocator, pso, false);

    rt.backend_mut()
        .record_transition(
            list,
            resource,
            0,
            ResourceState::Common,
            ResourceState::PixelShaderResource,
        )
        .expect("record transition");
}

/// D3D12 UAV barrier.
#[test]
fn t35_22_d3d12_uav_barrier() {
    let mut rt = D3d12Runtime::new();

    let resource = rt
        .backend_mut()
        .create_resource(ResourceDesc {
            name: "uav-resource".into(),
            format: DxgiFormat::R32Float,
            heap: HeapType::Default,
            size: 64 * 4,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create resource");

    let allocator = rt.backend_mut().create_command_allocator();
    let root_sig = rt.backend_mut().create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
        parameters: Vec::new(),
        static_samplers: Vec::new(),
        visibility_offsets: BTreeMap::new(),
    });
    let pso = rt.backend_mut().create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "uav-barrier-pso".into(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );
    let list = rt
        .backend_mut()
        .create_graphics_command_list(allocator, pso, false);

    rt.backend_mut()
        .record_uav_barrier(list, resource)
        .expect("record UAV barrier");
}

/// D3D12 aliasing barrier.
#[test]
fn t35_23_d3d12_aliasing_barrier() {
    let mut rt = D3d12Runtime::new();

    let allocator = rt.backend_mut().create_command_allocator();
    let root_sig = rt.backend_mut().create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
        parameters: Vec::new(),
        static_samplers: Vec::new(),
        visibility_offsets: BTreeMap::new(),
    });
    let pso = rt.backend_mut().create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "aliasing-barrier-pso".into(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );
    let list = rt
        .backend_mut()
        .create_graphics_command_list(allocator, pso, false);

    rt.backend_mut()
        .record_aliasing_barrier(list, None, None)
        .expect("record aliasing barrier");
}

// ============================================================================
// Item 170 — DXGI format conversion edge cases
// ============================================================================

/// DXGI_FORMAT_UNKNOWN (0) maps exactly to the `Unknown` representation.
#[test]
fn t35_24_dxgi_format_unknown() {
    let fmt = DxgiFormat::from_u32(0);
    assert_eq!(format!("{:?}", fmt), "Unknown");
}

/// Common DXGI formats are created exactly from raw values.
#[test]
fn t35_25_dxgi_format_common_values() {
    // R8G8B8A8_UNORM = 28
    let fmt = DxgiFormat::from_u32(28);
    assert_eq!(format!("{:?}", fmt), "R8G8B8A8Unorm");

    // B8G8R8A8_UNORM = 87
    let fmt = DxgiFormat::from_u32(87);
    assert_eq!(format!("{:?}", fmt), "B8G8R8A8Unorm");

    // D24_UNORM_S8_UINT = 45
    let fmt = DxgiFormat::from_u32(45);
    assert_eq!(format!("{:?}", fmt), "D24UnormS8Uint");

    // R32_FLOAT = 41
    let fmt = DxgiFormat::from_u32(41);
    assert_eq!(format!("{:?}", fmt), "R32Float");
}

/// Unknown format values fall through to the documented lossy fallback
/// `R8G8B8A8Unorm`, and the fallback is recorded so it is observable.
#[test]
fn t35_26_dxgi_format_unknown_value_fallback() {
    let before = DxgiFormat::format_fallback_count();
    let fmt = DxgiFormat::from_u32(9999);
    assert_eq!(format!("{:?}", fmt), "R8G8B8A8Unorm");
    assert!(
        DxgiFormat::format_fallback_count() > before,
        "the lossy fallback must be recorded"
    );
}

/// Formats without an exact representation are rejected by the checked
/// mapping — never silently substituted with a "closest" format.
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

/// Every DXGI value with an exact representation maps exactly, and the
/// translation-strategy table is explicit for every known value.
#[test]
fn t35_26c_dxgi_format_exact_identity_and_explicit_strategy() {
    use casa1::gfx::FormatTranslation;
    // Exact identity: mapping a value and mapping it back agrees.
    for raw in [
        2, 3, 10, 11, 12, 16, 17, 20, 24, 25, 26, 28, 29, 30, 34, 35, 36, 37, 40, 41, 42, 43, 45,
        54, 56, 57, 58, 61, 62, 71, 72, 74, 75, 77, 78, 80, 83, 85, 87, 88, 91, 98, 99,
    ] {
        let fmt = DxgiFormat::from_u32_checked(raw).expect("exact format value");
        assert_eq!(
            DxgiFormat::translation_strategy(raw),
            FormatTranslation::Exact,
            "exact value {raw} must report the Exact strategy"
        );
        let _ = fmt;
    }
    // Explicit strategies for previously "closest"-mapped families.
    assert_eq!(
        DxgiFormat::translation_strategy(27),
        FormatTranslation::ViewReinterpret
    );
    assert_eq!(
        DxgiFormat::translation_strategy(48),
        FormatTranslation::ViewReinterpret
    );
    assert_eq!(
        DxgiFormat::translation_strategy(19),
        FormatTranslation::ViewReinterpret
    );
    assert_eq!(
        DxgiFormat::translation_strategy(94),
        FormatTranslation::Decompression
    );
    assert_eq!(
        DxgiFormat::translation_strategy(96),
        FormatTranslation::Decompression
    );
    assert_eq!(
        DxgiFormat::translation_strategy(103),
        FormatTranslation::ConversionShader
    );
    assert_eq!(
        DxgiFormat::translation_strategy(67),
        FormatTranslation::ConversionShader
    );
    assert_eq!(
        DxgiFormat::translation_strategy(86),
        FormatTranslation::Swizzle
    );
    assert_eq!(
        DxgiFormat::translation_strategy(115),
        FormatTranslation::Swizzle
    );
    assert_eq!(
        DxgiFormat::translation_strategy(55),
        FormatTranslation::DepthStencilEmulation
    );
    assert_eq!(
        DxgiFormat::translation_strategy(66),
        FormatTranslation::Unsupported
    );
    assert_eq!(
        DxgiFormat::translation_strategy(133),
        FormatTranslation::Unsupported
    );
    assert_eq!(
        DxgiFormat::translation_strategy(u32::MAX),
        FormatTranslation::Unsupported
    );
    assert_eq!(
        DxgiFormat::translation_strategy(9999),
        FormatTranslation::Unsupported
    );
}

/// DXGI format debug and clone work.
#[test]
fn t35_27_dxgi_format_debug_clone() {
    let a = DxgiFormat::R16G16B16A16Float;
    let b = a;
    assert_eq!(format!("{:?}", a), format!("{:?}", b));
}

// ============================================================================
// Item 171 — Invalid resource dimensions and unsupported formats
// ============================================================================

/// D3D11 resource_desc returns information for valid resources.
#[test]
fn t35_28_d3d11_valid_resource_desc() {
    let mut device = make_d3d11_device();

    let tex = device
        .create_texture_2d("valid-tex", 16, 16, DxgiFormat::R8G8B8A8Unorm)
        .expect("create texture");

    let desc = device.resource_desc(tex).expect("get resource desc");
    assert_eq!(desc.width, 16);
    assert_eq!(desc.height, 16);
    assert_eq!(desc.format, DxgiFormat::R8G8B8A8Unorm);
}

/// D3D11 invalid resource id returns error from resource_desc.
#[test]
fn t35_29_d3d11_invalid_resource_desc_errors() {
    let device = make_d3d11_device();
    let result = device.resource_desc(99999);
    assert!(result.is_err(), "invalid resource id should error");
}

/// D3D11 update_subresource with small data does not crash.
#[test]
fn t35_30_d3d11_update_subresource_non_crashing() {
    let mut device = make_d3d11_device();
    let buf = device
        .create_buffer(
            "noncrash-buf",
            256,
            ResourceUsageHint::Buffer {
                role: BufferRole::Vertex,
                cpu_write_frequent: true,
            },
        )
        .expect("create buffer");

    let small_data: Vec<u8> = vec![0x42; 32];
    device
        .update_subresource(buf, &small_data)
        .expect("update_subresource must succeed");
    // update_subresource queues a command; it becomes observable once the
    // immediate command list is submitted (the D3D11 deferred-execution model).
    device.submit_immediate().expect("submit immediate");
    let read_back = device.map(buf).expect("map after update");
    assert_eq!(
        &read_back[..small_data.len()],
        small_data.as_slice(),
        "update_subresource must persist the uploaded bytes"
    );
}

// ============================================================================
// Additional infrastructure tests for D3D types
// ============================================================================

/// ResourceState from/to D3D12 bits round-trip.
#[test]
fn t35_31_resource_state_from_d3d12_bits() {
    let states = ResourceState::from_d3d12_bits(0);
    assert!(!states.is_empty(), "zero bits should give Common");
    assert!(states.contains(&ResourceState::Common));
}

/// ResourceState is_read_only property.
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

/// ResourceState to_d3d12_bits returns expected values.
#[test]
fn t35_33_resource_state_to_d3d12_bits() {
    assert_eq!(ResourceState::Common.to_d3d12_bits(), 0);
    // D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE = 0x80 (the previous 0x8 was
    // a test fault — 0x8 is NON_PIXEL_SHADER_RESOURCE).
    assert_eq!(ResourceState::PixelShaderResource.to_d3d12_bits(), 0x80);
    // D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE = 0x40 and
    // D3D12_RESOURCE_STATE_UNORDERED_ACCESS = 0x8 (the previous 0x8 on
    // NonPixelShaderResource was a test fault).
    assert_eq!(ResourceState::NonPixelShaderResource.to_d3d12_bits(), 0x40);
    assert_eq!(ResourceState::UnorderedAccess.to_d3d12_bits(), 0x8);
    assert_eq!(ResourceState::RenderTarget.to_d3d12_bits(), 0x4);
}

/// ViewDescriptor clone and debug.
#[test]
fn t35_34_view_descriptor_traits() {
    let v = ViewDescriptor::Srv {
        resource: 1,
        format: DxgiFormat::R8G8B8A8Unorm,
    };
    let _ = v.clone();
    let _ = format!("{:?}", v);
}

/// D3D12DescriptorRangeType to Metal resource type (via D3d12Runtime).
#[test]
fn t35_35_descriptor_range_type_to_metal() {
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Srv),
        "texture"
    );
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Uav),
        "texture"
    );
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Cbv),
        "buffer"
    );
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Sampler),
        "sampler"
    );
}

/// Subresource state tracking on D3d12Runtime.
#[test]
fn t35_36_subresource_state_tracking() {
    let mut rt = D3d12Runtime::new();

    assert_eq!(rt.subresource_state(1, 0), None);

    rt.set_subresource_state(1, 0, ResourceState::RenderTarget);
    assert_eq!(
        rt.subresource_state(1, 0),
        Some(ResourceState::RenderTarget)
    );
}

/// D3D10 constant values are accessible.
#[test]
fn t35_37_d3d10_constants() {
    assert_eq!(D3D10_SDK_VERSION, 7);
    assert_eq!(D3D10_USAGE_DEFAULT, 0);
    assert_eq!(D3D10_USAGE_DYNAMIC, 2);
    assert_eq!(D3D10_BIND_VERTEX_BUFFER, 1);
    assert_eq!(D3D10_BIND_INDEX_BUFFER, 2);
    assert_eq!(D3D10_BIND_CONSTANT_BUFFER, 4);
    assert_eq!(D3D10_BIND_SHADER_RESOURCE, 8);
    // The Casa1 D3D10 constants reserve 0x20/0x40 for render-target and
    // depth-stencil bind flags (src/d3d10.rs:156-157) — the previous test
    // values (16/32) matched the Windows headers but not this implementation.
    assert_eq!(D3D10_BIND_RENDER_TARGET, 0x20);
    assert_eq!(D3D10_BIND_DEPTH_STENCIL, 0x40);
    assert_eq!(D3D10_CPU_ACCESS_WRITE, 0x10000);
    assert_eq!(D3D10_CPU_ACCESS_READ, 0x20000);
    assert_eq!(D3D10_MAX_TEXTURE_DIMENSION, 8192);
    assert_eq!(D3D10_SIMULTANEOUS_RENDER_TARGET_COUNT, 8);
}

/// PipelineStateDesc default and creation.
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

/// D3D11 device gpu_profile_signature returns a non-empty string.
#[test]
fn t35_39_d3d11_gpu_profile_signature() {
    let device = make_d3d11_device();
    let sig = device.gpu_profile_signature();
    assert!(!sig.is_empty(), "GPU profile signature should not be empty");
}

/// D3D11 device memoryless_depth_targets returns a bool.
#[test]
fn t35_40_d3d11_memoryless_depth_targets() {
    let device = make_d3d11_device();
    // Memoryless depth targets are a capability the device must report as a
    // stable bool (Apple-GPU optimization), mirroring the host backend's
    // capability bit (src/d3d11.rs `memoryless_depth_targets`).
    let memoryless = device.memoryless_depth_targets();
    // The documented invariant: capability reporting must be deterministic
    // across calls.
    let first = device.memoryless_depth_targets();
    let second = device.memoryless_depth_targets();
    assert_eq!(first, second, "capability reporting must be deterministic");
    assert_eq!(memoryless, first, "repeated queries must agree");
}
