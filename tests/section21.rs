//! Phase 8 — D3D12 Rendering Tests
//!
//! Tests the D3D12 runtime: device creation, command allocator/list, render target,
//! command list recording, fence synchronization, descriptor heap management,
//! resource creation, root signature, pipeline state, and swapchain creation.
//!
//! All tests use the simulated graphics backend (no real GPU required).

use casa1::d3d12::D3d12Runtime;
use casa1::gfx::{
    DescriptorHeapType, DxgiFormat, HeapType, PipelineStateDesc, ResourceDesc, ResourceState,
    ResourceUsageHint, RootSignatureDesc, SwapchainDesc, ViewDescriptor,
};

/// Helper: create a D3D12 runtime with the simulated backend.
fn create_runtime() -> D3d12Runtime {
    D3d12Runtime::new()
}

// ---------------------------------------------------------------------------
// t21_1_d3d12_device_creation
// ---------------------------------------------------------------------------

#[test]
fn t21_1_d3d12_device_creation() {
    let mut runtime = create_runtime();

    // Create a command queue (equivalent to creating a D3D12 device)
    let queue = runtime.create_command_queue();
    assert!(queue > 0, "command queue ID should be non-zero");

    // Verify device info
    let info = runtime.device_info();
    assert!(
        !info.adapter.name.is_empty(),
        "adapter name should not be empty"
    );
}

// ---------------------------------------------------------------------------
// t21_2_command_allocator_and_list
// ---------------------------------------------------------------------------

#[test]
fn t21_2_command_allocator_and_list() {
    let mut runtime = create_runtime();

    // Create command allocator
    let allocator = runtime.create_command_allocator();
    assert!(allocator > 0, "command allocator ID should be non-zero");

    // Create a pipeline state (needed for command list creation)
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![1],
        root_constants: 4,
    });

    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "test_pipeline".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );
    assert!(pso > 0, "pipeline state ID should be non-zero");

    // Create command list
    let list = runtime.create_graphics_command_list(allocator, pso);
    assert!(list > 0, "command list ID should be non-zero");
}

// ---------------------------------------------------------------------------
// t21_3_render_target_creation
// ---------------------------------------------------------------------------

#[test]
fn t21_3_render_target_creation() {
    let mut runtime = create_runtime();

    // Create a render target texture resource
    let resource = runtime
        .create_committed_resource(ResourceDesc {
            name: "render_target".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 1280 * 720 * 4,
            subresources: 1,
            initial_state: ResourceState::RenderTarget,
            usage_hint: ResourceUsageHint::Texture {
                sampled: false,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        })
        .expect("create render target resource");

    assert!(resource > 0, "resource ID should be non-zero");

    // Create RTV descriptor heap
    let rtv_heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);

    // Write RTV descriptor
    runtime
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write RTV descriptor");
}

// ---------------------------------------------------------------------------
// t21_4_command_list_recording
// ---------------------------------------------------------------------------

#[test]
fn t21_4_command_list_recording() {
    let mut runtime = create_runtime();

    // Set up pipeline
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![1],
        root_constants: 4,
    });
    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "recording_test".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );

    // Create resource and RTV
    let backbuffer = runtime
        .create_committed_resource(ResourceDesc {
            name: "backbuffer".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 1280 * 720 * 4,
            subresources: 1,
            initial_state: ResourceState::RenderTarget,
            usage_hint: ResourceUsageHint::SwapchainBackbuffer,
        })
        .expect("create backbuffer");

    let rtv_heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
    runtime
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: backbuffer,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write RTV");

    // Create command allocator and list
    let allocator = runtime.create_command_allocator();
    let list = runtime.create_graphics_command_list(allocator, pso);

    // Record commands: begin render pass, clear RTV, draw, end render pass
    runtime
        .record_begin_render_pass(
            list,
            vec![DxgiFormat::R8G8B8A8Unorm],
            None,
            "clear",
            "store",
        )
        .expect("begin render pass");

    runtime.record_clear_rtv(list, rtv_heap, 0).expect("clear RTV");
    runtime.record_draw(list, 3).expect("draw");
    runtime.end_render_pass(list).expect("end render pass");

    // Close the command list
    let stream = runtime.close_command_list(list).expect("close list");

    // Execute
    let queue = runtime.create_command_queue();
    let fence = runtime.create_fence(0);
    let plan = runtime
        .execute_command_lists(queue, &[stream], Some((fence, 1)))
        .expect("execute");

    assert_eq!(plan.render_passes.len(), 1, "should have 1 render pass");
    assert_eq!(plan.render_passes[0].draw_calls, 1, "should have 1 draw call");
}

// ---------------------------------------------------------------------------
// t21_5_fence_synchronization
// ---------------------------------------------------------------------------

#[test]
fn t21_5_fence_synchronization() {
    let mut runtime = create_runtime();

    // Create fence with initial value 0
    let fence = runtime.create_fence(0);

    // Verify initial value
    let initial = runtime.fence_value(fence).expect("fence value");
    assert_eq!(initial, 0, "initial fence value should be 0");

    // Signal fence to value 1
    runtime.signal_fence(fence, 1).expect("signal fence");

    let after_signal = runtime.fence_value(fence).expect("fence value after signal");
    assert_eq!(after_signal, 1, "fence value should be 1 after signal");

    // Signal to higher value
    runtime.signal_fence(fence, 42).expect("signal fence to 42");

    let final_value = runtime.fence_value(fence).expect("final fence value");
    assert_eq!(final_value, 42, "fence value should be 42 after second signal");
}

// ---------------------------------------------------------------------------
// t21_6_descriptor_heap_management
// ---------------------------------------------------------------------------

#[test]
fn t21_6_descriptor_heap_management() {
    let mut runtime = create_runtime();

    // Create descriptor heaps of different types
    let rtv_heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 4);
    let cbv_srv_uav_heap = runtime.create_descriptor_heap(DescriptorHeapType::CbvSrvUav, 8);
    let sampler_heap = runtime.create_descriptor_heap(DescriptorHeapType::Sampler, 2);
    let dsv_heap = runtime.create_descriptor_heap(DescriptorHeapType::Dsv, 1);

    assert!(rtv_heap > 0, "RTV heap should be valid");
    assert!(cbv_srv_uav_heap > 0, "CBV/SRV/UAV heap should be valid");
    assert!(sampler_heap > 0, "sampler heap should be valid");
    assert!(dsv_heap > 0, "DSV heap should be valid");

    // Create a resource and write descriptors
    let resource = runtime
        .create_committed_resource(ResourceDesc {
            name: "test_texture".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 256 * 256 * 4,
            subresources: 1,
            initial_state: ResourceState::RenderTarget,
            usage_hint: ResourceUsageHint::Texture {
                sampled: true,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        })
        .expect("create resource");

    // Write RTV descriptor
    runtime
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write RTV");

    // Write SRV descriptor
    runtime
        .write_descriptor(
            cbv_srv_uav_heap,
            0,
            ViewDescriptor::Srv {
                resource,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write SRV");

    // Write sampler descriptor
    runtime
        .write_descriptor(
            sampler_heap,
            0,
            ViewDescriptor::Sampler {
                filter: casa1::gfx::FilterMode::Linear,
            },
        )
        .expect("write sampler");

    // Verify descriptors via snapshot
    let snapshot = runtime
        .descriptor_heap_snapshot(rtv_heap)
        .expect("RTV heap snapshot");
    assert_eq!(snapshot.len(), 4, "RTV heap should have 4 slots");
    assert!(snapshot[0].is_some(), "first slot should be occupied");

    // Copy descriptors
    let rtv_heap2 = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 4);
    runtime
        .copy_descriptors_simple(rtv_heap, 0, rtv_heap2, 0, 1)
        .expect("copy descriptors");
}

// ---------------------------------------------------------------------------
// t21_7_resource_creation
// ---------------------------------------------------------------------------

#[test]
fn t21_7_resource_creation() {
    let mut runtime = create_runtime();

    // Create a buffer resource
    let buffer = runtime
        .create_committed_resource(ResourceDesc {
            name: "vertex_buffer".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Upload,
            size: 1024,
            subresources: 1,
            initial_state: ResourceState::GenericRead,
            usage_hint: ResourceUsageHint::Buffer {
                role: casa1::gfx::BufferRole::Vertex,
                cpu_write_frequent: true,
            },
        })
        .expect("create buffer");

    assert!(buffer > 0, "buffer resource ID should be non-zero");

    // Create a texture resource
    let texture = runtime
        .create_committed_resource(ResourceDesc {
            name: "diffuse_texture".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 512 * 512 * 4,
            subresources: 1,
            initial_state: ResourceState::PixelShaderResource,
            usage_hint: ResourceUsageHint::Texture {
                sampled: true,
                render_target: false,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        })
        .expect("create texture");

    assert!(texture > 0, "texture resource ID should be non-zero");

    // Verify resource states
    let buffer_state = runtime
        .resource_state(buffer, 0)
        .expect("buffer state");
    assert_eq!(
        buffer_state,
        ResourceState::GenericRead,
        "buffer should be in GenericRead state"
    );

    let texture_state = runtime
        .resource_state(texture, 0)
        .expect("texture state");
    assert_eq!(
        texture_state,
        ResourceState::PixelShaderResource,
        "texture should be in PixelShaderResource state"
    );

    // Upload data to buffer
    let data = vec![0xABu8; 256];
    runtime
        .upload_write(buffer, 0, &data)
        .expect("upload to buffer");

    // Create a readback buffer and copy data into it for readback
    let readback_buf = runtime
        .create_committed_resource(ResourceDesc {
            name: "readback_buf".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Readback,
            size: 1024,
            subresources: 1,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Buffer {
                role: casa1::gfx::BufferRole::Generic,
                cpu_write_frequent: false,
            },
        })
        .expect("create readback buffer");

    // Copy data into readback buffer
    runtime
        .overwrite_resource_bytes(readback_buf, &data)
        .expect("copy to readback");

    // Read back from the readback buffer
    let fence = runtime.create_fence(0);
    runtime.signal_fence(fence, 1).expect("signal");
    let read_back = runtime
        .readback(readback_buf, fence, 1)
        .expect("readback");
    assert_eq!(read_back.len(), 1024, "readback should return full buffer size");
    assert_eq!(&read_back[..256], &data[..], "readback data should match uploaded data");

    // Destroy resources
    runtime.destroy_resource(buffer).expect("destroy buffer");
    runtime.destroy_resource(texture).expect("destroy texture");
    runtime.destroy_resource(readback_buf).expect("destroy readback buffer");
}

// ---------------------------------------------------------------------------
// t21_8_root_signature
// ---------------------------------------------------------------------------

#[test]
fn t21_8_root_signature() {
    let mut runtime = create_runtime();

    // Create root signature with constants and descriptor tables
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![2, 3, 1],
        root_constants: 8,
    });

    assert!(root_sig > 0, "root signature ID should be non-zero");

    // Create a second root signature with different layout
    let root_sig2 = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![1],
        root_constants: 16,
    });

    assert!(root_sig2 > 0, "second root signature ID should be non-zero");
    assert_ne!(root_sig, root_sig2, "root signatures should have unique IDs");
}

// ---------------------------------------------------------------------------
// t21_9_pipeline_state
// ---------------------------------------------------------------------------

#[test]
fn t21_9_pipeline_state() {
    let mut runtime = create_runtime();

    // Create root signature
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![1],
        root_constants: 4,
    });

    // Create graphics pipeline state
    let graphics_pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "graphics_pipeline".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );

    assert!(graphics_pso > 0, "graphics PSO ID should be non-zero");

    // Create compute pipeline state
    let compute_pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "compute_pipeline".to_string(),
            compute: true,
            render_target_formats: vec![],
            depth_format: None,
        },
    );

    assert!(compute_pso > 0, "compute PSO ID should be non-zero");
    assert_ne!(
        graphics_pso, compute_pso,
        "graphics and compute PSOs should have unique IDs"
    );
}

// ---------------------------------------------------------------------------
// t21_10_swapchain_creation
// ---------------------------------------------------------------------------

#[test]
fn t21_10_swapchain_creation() {
    let mut runtime = create_runtime();

    // Create swapchain with 2 buffers
    let swapchain = runtime
        .create_swapchain(SwapchainDesc {
            width: 1280,
            height: 720,
            format: DxgiFormat::R8G8B8A8Unorm,
            buffer_count: 2,
        })
        .expect("create swapchain");

    assert!(swapchain > 0, "swapchain ID should be non-zero");

    // Verify swapchain state
    let state = runtime.swapchain_state(swapchain).expect("swapchain state");
    assert_eq!(state.desc.width, 1280, "width should be 1280");
    assert_eq!(state.desc.height, 720, "height should be 720");
    assert_eq!(state.desc.format, DxgiFormat::R8G8B8A8Unorm, "format should match");
    assert_eq!(state.desc.buffer_count, 2, "buffer count should be 2");
    assert_eq!(state.backbuffers.len(), 2, "should have 2 backbuffers");

    // Set maximum frame latency
    runtime
        .set_maximum_frame_latency(swapchain, 1)
        .expect("set frame latency");

    // Present a frame
    let present = runtime.present(swapchain, 1, false).expect("present");
    assert_eq!(present.effective_sync_interval, 1, "sync interval should be 1");
    assert_eq!(present.queued_frames, 1, "should have 1 queued frame");
}
