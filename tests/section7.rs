use casa1::gfx::{
    Command, DescriptorHeapType, DxgiFormat, EmulationStrategy, FeatureQuery, FilterMode,
    GraphicsBackend, HeapType, PipelineStateDesc, QueryType, ResourceDesc, ResourceState,
    ResourceUsageHint, RootSignatureDesc, SceneSpec, SwapchainDesc, ViewDescriptor,
};
use casa1::reason::ReasonCode;
use std::fs;
use tempfile::tempdir;

#[test]
fn t7_1_dxgi_swapchain_oracle_suite_matches_expected_present_resize_and_latency_behavior() {
    let mut backend = GraphicsBackend::new();
    // The adapter is derived from the real host GPU (detected_host_gpu_profile,
    // src/gfx.rs:1186-1187), so vendor/device assertions must be
    // environment-agnostic: any of the three supported vendors, a non-zero
    // device id, and a Metal-family tag.
    assert!(
        matches!(backend.adapter().vendor_id, 0x106b | 0x10de | 0x1002),
        "adapter vendor must be Apple/NVIDIA/AMD; got {:#x}",
        backend.adapter().vendor_id
    );
    assert_ne!(backend.adapter().device_id, 0, "device id must be populated");
    assert!(
        backend.adapter().metal_family.starts_with("apple"),
        "metal family must be apple<family>; got {}",
        backend.adapter().metal_family
    );
    // Output topology is fixed by the backend profile (two hardcoded outputs).
    assert_eq!(backend.outputs().len(), 2);
    assert_eq!(backend.outputs()[0].modes[0].width, 2560);
    assert_eq!(backend.outputs()[0].modes[0].refresh_numerator, 60_000);
    assert!(backend.query_feature(FeatureQuery::Tearing));
    assert!(backend.query_feature(FeatureQuery::TimestampQueries));
    // Mesh shaders follow the documented family contract: family >= 9
    // (src/gfx.rs:3325). Parse the family from the adapter tag and pin the
    // feature mapping against it.
    let family = backend
        .adapter()
        .metal_family
        .strip_prefix("apple")
        .and_then(|value| value.parse::<u8>().ok())
        .expect("parse metal family");
    assert_eq!(
        backend.query_feature(FeatureQuery::MeshShaders),
        family >= 9,
        "MeshShaders must be reported exactly for Metal family >= 9"
    );
    assert_eq!(
        backend
            .query_format_support(DxgiFormat::Bc1Unorm)
            .expect("BC1 support")
            .strategy,
        EmulationStrategy::ConversionShader
    );
    assert_eq!(
        backend
            .query_format_support(DxgiFormat::B5G6R5Unorm)
            .expect("B5G6R5 support")
            .strategy,
        EmulationStrategy::Swizzle
    );

    let swapchain = backend
        .create_swapchain(SwapchainDesc {
            width: 1280,
            height: 720,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count: 3,
        })
        .expect("create swapchain");
    backend
        .set_maximum_frame_latency(swapchain, 2)
        .expect("set maximum frame latency");
    let present0 = backend
        .present(swapchain, 0, true)
        .expect("tearing present");
    let present1 = backend.present(swapchain, 4, false).expect("vsync present");
    let present2 = backend
        .present(swapchain, 1, false)
        .expect("bounded queue depth present");
    assert!(present0.tearing_allowed);
    assert_eq!(present0.effective_sync_interval, 0);
    assert_eq!(present1.effective_sync_interval, 4);
    assert_eq!(present2.queued_frames, 2);

    let before_resize = backend
        .swapchain_state(swapchain)
        .expect("swapchain state before resize");
    let old_backbuffers = before_resize.backbuffers.clone();
    backend
        .resize_buffers(swapchain, 2, 1920, 1080, DxgiFormat::R8G8B8A8Unorm)
        .expect("resize swapchain buffers");
    let after_resize = backend
        .swapchain_state(swapchain)
        .expect("swapchain state after resize");
    assert_eq!(after_resize.id, before_resize.id);
    assert_eq!(after_resize.desc.buffer_count, 2);
    assert_eq!(after_resize.desc.width, 1920);
    assert_eq!(after_resize.desc.format, DxgiFormat::R8G8B8A8Unorm);
    assert_ne!(after_resize.backbuffers, old_backbuffers);
    assert_eq!(backend.live_resource_count(), 2);
}

#[test]
fn t7_host_present_exports_ppm_frame() {
    let mut backend = GraphicsBackend::new();
    let swapchain = backend
        .create_swapchain(SwapchainDesc {
            width: 4,
            height: 2,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count: 2,
        })
        .expect("create swapchain");
    backend.present(swapchain, 1, false).expect("present frame");

    let temp_dir = tempdir().expect("temp dir");
    let frame_path = temp_dir.path().join("frame.ppm");
    backend
        .export_presented_frame_ppm(swapchain, &frame_path)
        .expect("export presented frame");

    let bytes = fs::read(&frame_path).expect("read exported frame");
    let header = b"P6\n4 2\n255\n";
    assert!(bytes.starts_with(header));
    assert_eq!(bytes.len(), header.len() + (4 * 2 * 3));
}

#[test]
fn t7_2_d3d12_microtests_cover_barriers_descriptors_aliasing_root_constants_queries_and_readback() {
    let mut backend = GraphicsBackend::new();
    let color = backend
        .create_resource(ResourceDesc {
            name: "color".to_string(),
            format: DxgiFormat::B8G8R8A8Unorm,
            heap: HeapType::Default,
            size: 64,
            subresources: 2,
            initial_state: ResourceState::Common,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create color resource");
    let depth = backend
        .create_resource(ResourceDesc {
            name: "depth".to_string(),
            format: DxgiFormat::D24UnormS8Uint,
            heap: HeapType::Default,
            size: 64,
            subresources: 1,
            initial_state: ResourceState::DepthWrite,
            usage_hint: ResourceUsageHint::DepthStencil,
        })
        .expect("create depth resource");
    let upload = backend
        .create_resource(ResourceDesc {
            name: "upload".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Upload,
            size: 16,
            subresources: 1,
            initial_state: ResourceState::GenericRead,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create upload resource");
    let readback = backend
        .create_resource(ResourceDesc {
            name: "readback".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Readback,
            size: 16,
            subresources: 1,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create readback resource");

    backend
        .transition_resource(color, 0, ResourceState::Common, ResourceState::RenderTarget)
        .expect("transition color subresource 0 to render target");
    backend
        .transition_resource(color, 1, ResourceState::Common, ResourceState::CopyDest)
        .expect("transition color subresource 1 to copy destination");
    assert_eq!(
        backend.resource_state(color, 0).expect("resource state 0"),
        ResourceState::RenderTarget
    );
    let wrong_barrier = backend
        .transition_resource(
            color,
            1,
            ResourceState::RenderTarget,
            ResourceState::PixelShaderResource,
        )
        .expect_err("mismatched barrier must fail");
    assert_eq!(wrong_barrier.code, ReasonCode::RcD3dInvalidState);

    let cbv_srv_uav_heap = backend.create_descriptor_heap(DescriptorHeapType::CbvSrvUav, 4);
    let rtv_heap = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
    let dsv_heap = backend.create_descriptor_heap(DescriptorHeapType::Dsv, 1);
    let sampler_heap = backend.create_descriptor_heap(DescriptorHeapType::Sampler, 1);

    backend
        .upload_write(upload, 0, &[1, 2, 3, 4])
        .expect("write upload bytes");
    backend
        .write_descriptor(
            cbv_srv_uav_heap,
            0,
            ViewDescriptor::Cbv {
                resource: upload,
                size: 16,
            },
        )
        .expect("write CBV");
    backend
        .write_descriptor(
            cbv_srv_uav_heap,
            1,
            ViewDescriptor::Srv {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect("write SRV");
    backend
        .write_descriptor(
            cbv_srv_uav_heap,
            2,
            ViewDescriptor::Uav {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect("write UAV");
    backend
        .write_descriptor(
            sampler_heap,
            0,
            ViewDescriptor::Sampler {
                filter: FilterMode::Linear,
            },
        )
        .expect("write sampler");
    backend
        .copy_descriptors(cbv_srv_uav_heap, 0, cbv_srv_uav_heap, 1, 3)
        .expect("copy overlapping descriptors with exact staging semantics");
    assert_eq!(
        backend
            .descriptor_heap_type(cbv_srv_uav_heap)
            .expect("CBV/SRV/UAV heap type"),
        DescriptorHeapType::CbvSrvUav
    );
    assert_eq!(
        backend
            .descriptor_heap_snapshot(cbv_srv_uav_heap)
            .expect("descriptor snapshot"),
        vec![
            Some(ViewDescriptor::Cbv {
                resource: upload,
                size: 16,
            }),
            Some(ViewDescriptor::Cbv {
                resource: upload,
                size: 16,
            }),
            Some(ViewDescriptor::Srv {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            }),
            Some(ViewDescriptor::Uav {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            }),
        ]
    );
    assert_eq!(
        backend
            .translate_descriptor_heap(cbv_srv_uav_heap)
            .expect("translate descriptor heap")
            .iter()
            .map(|binding| binding.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["cbv", "cbv", "srv", "uav"]
    );

    backend
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect("write RTV");
    backend
        .write_descriptor(
            dsv_heap,
            0,
            ViewDescriptor::Dsv {
                resource: depth,
                format: DxgiFormat::D24UnormS8Uint,
            },
        )
        .expect("write DSV");
    let invalid_rtv = backend
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: depth,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect_err("depth resource cannot be reinterpreted as RTV");
    assert_eq!(invalid_rtv.code, ReasonCode::RcD3dFeatureUnsupported);
    backend
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect("rewrite RTV after negative test");

    let root_signature = backend.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![4],
        root_constants: 4,
        ..Default::default()
    });
    let pipeline_state = backend.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: "micro".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );
    let queue = backend.create_command_queue();
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    backend
        .record_set_root_constants(list, vec![1, 2, 3, 4])
        .expect("set root constants");
    backend
        .record_clear_rtv(list, rtv_heap, 0)
        .expect("clear RTV");
    backend
        .record_clear_dsv(list, dsv_heap, 0)
        .expect("clear DSV");
    backend.record_draw(list, 3).expect("record draw");
    backend
        .record_uav_barrier(list, color)
        .expect("record UAV barrier");
    backend
        .record_aliasing_barrier(list, Some(color), Some(readback))
        .expect("record aliasing barrier");
    backend
        .record_copy_resource(list, upload, readback)
        .expect("record upload to readback copy");
    let closed = backend
        .close_command_list(list)
        .expect("close command list");
    assert!(matches!(
        closed.commands[0],
        Command::SetRootConstants { .. }
    ));
    let fence = backend.create_fence(0);
    let plan = backend
        .execute_command_lists(queue, &[closed], Some((fence, 7)))
        .expect("execute command lists");
    assert!(plan.validation_errors.is_empty());
    assert_eq!(plan.render_passes.len(), 1);
    assert_eq!(plan.render_passes[0].draw_calls, 1);
    assert_eq!(plan.blit_passes, 1);
    assert_eq!(plan.root_constants_log, vec![vec![1, 2, 3, 4]]);
    assert_eq!(plan.signaled_fences, vec![(fence, 7)]);
    assert_eq!(backend.fence_value(fence).expect("fence value"), 7);
    assert_eq!(
        backend
            .readback(readback, fence, 7)
            .expect("readback bytes")[..4],
        [1, 2, 3, 4]
    );

    let timestamp_heap = backend.create_query_heap(QueryType::Timestamp, 2);
    let first_timestamp = backend
        .write_timestamp(timestamp_heap, 0)
        .expect("first timestamp query");
    let second_timestamp = backend
        .write_timestamp(timestamp_heap, 1)
        .expect("second timestamp query");
    assert!(second_timestamp > first_timestamp);
    assert_eq!(
        backend
            .resolve_query_data(timestamp_heap)
            .expect("resolve timestamps"),
        casa1::gfx::QueryResolveResult {
            values: vec![first_timestamp, second_timestamp],
            emulated: true,
        }
    );
    let occlusion_heap = backend.create_query_heap(QueryType::Occlusion, 1);
    backend
        .write_occlusion(occlusion_heap, 0, 77)
        .expect("write occlusion sample count");
    assert_eq!(
        backend
            .resolve_query_data(occlusion_heap)
            .expect("resolve occlusion"),
        casa1::gfx::QueryResolveResult {
            values: vec![77],
            emulated: false,
        }
    );
}

#[test]
fn t7_3_frame_hash_and_ssim_suite_matches_reference_frames() {
    let backend = GraphicsBackend::new();
    let scenes = vec![
        SceneSpec {
            name: "triangle".to_string(),
            format: DxgiFormat::B8G8R8A8Unorm,
            clear_color: [16, 32, 48, 255],
            draw_calls: 1,
            compute_dispatches: 0,
        },
        SceneSpec {
            name: "postprocess".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            clear_color: [2, 4, 8, 255],
            draw_calls: 2,
            compute_dispatches: 1,
        },
        SceneSpec {
            name: "bc1-sprite".to_string(),
            format: DxgiFormat::Bc1Unorm,
            clear_color: [0, 0, 0, 255],
            draw_calls: 3,
            compute_dispatches: 0,
        },
    ];

    // Checked-in golden signatures for the scene-hash format documented at
    // src/gfx.rs:2705-2716 (`name|format|clear_color|draws|dispatches|strategy`).
    // These are literal constants, not re-derived through engine functions, so
    // any change to the canonical format or the format-mapping strategy breaks
    // the test.
    let golden_hashes = [
        "e996c1581ca75d935636706f021c9c5cd3d66efb65363095c9db07c39f5cb9e7",
        "89a76eeb4a57fa5fd0499d679ab958b456156c9cbd730d2d73a874688dc35b03",
        "d9a9e1808e297ff255d1fa49592b92abbc4831c41d581e80f97c8aa084840105",
    ];

    for (scene, golden) in scenes.into_iter().zip(golden_hashes) {
        let artifact = backend.render_scene(&scene).expect("render modeled scene");
        assert_eq!(
            artifact.hash, golden,
            "scene {:?} hash must match the checked-in golden value",
            scene.name
        );
    }
    // NOTE: `ssim` is not asserted. render_scene hardcodes ssim: 1.0 and never
    // renders actual pixels (src/gfx.rs:2717-2721), so asserting ssim ≈ 1.0
    // would only enshrine the stub. A real SSIM check requires an actual
    // rasterized frame, which the current backend does not produce.
}

#[test]
fn t7_4_metal_validation_gate_reports_errors_for_invalid_scenes() {
    // The Metal validation gate lives in execute_command_lists
    // (src/gfx.rs:2472-2537), not in render_scene (which always reports zero
    // validation errors, src/gfx.rs:2717-2721). Exercise the real gate: valid
    // command streams must validate clean, invalid ones must produce errors.

    let mut backend = GraphicsBackend::new();
    let color = backend
        .create_resource(ResourceDesc {
            name: "validation-color".to_string(),
            format: DxgiFormat::B8G8R8A8Unorm,
            heap: HeapType::Default,
            size: 64,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create validation color resource");

    // Valid scene: begin render pass, clear RTV, draw.
    let rtv_heap = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
    backend
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect("write validation RTV");
    let root_signature = backend.create_root_signature(RootSignatureDesc::default());
    let pipeline_state = backend.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: "validation".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: None,
        },
    );
    let queue = backend.create_command_queue();
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    backend
        .record_begin_render_pass(
            list,
            vec![DxgiFormat::B8G8R8A8Unorm],
            None,
            "clear",
            "store",
        )
        .expect("begin render pass");
    backend
        .record_clear_rtv(list, rtv_heap, 0)
        .expect("clear RTV");
    backend.record_draw(list, 3).expect("record draw");
    let closed = backend
        .close_command_list(list)
        .expect("close valid command list");
    let fence = backend.create_fence(0);
    let valid_plan = backend
        .execute_command_lists(queue, &[closed], Some((fence, 1)))
        .expect("execute valid command list");
    assert!(
        valid_plan.validation_errors.is_empty(),
        "valid command stream must validate clean; got {:?}",
        valid_plan.validation_errors
    );

    // Invalid scene 1: draw without an active render pass.
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    backend.record_draw(list, 3).expect("record orphan draw");
    let closed = backend
        .close_command_list(list)
        .expect("close invalid command list");
    let fence = backend.create_fence(0);
    let invalid_plan = backend
        .execute_command_lists(queue, &[closed], Some((fence, 2)))
        .expect("execute invalid command list");
    assert!(
        invalid_plan
            .validation_errors
            .iter()
            .any(|error| error.contains("draw without active render pass")),
        "orphan draw must be reported by the validation gate; got {:?}",
        invalid_plan.validation_errors
    );

    // Invalid scene 2: clearing an RTV slot that holds a non-RTV descriptor
    // is rejected eagerly at record time by the descriptor validation gate
    // (record_clear_rtv -> validate_rtv_descriptor, src/gfx.rs:1987-1998).
    let sampler_heap = backend.create_descriptor_heap(DescriptorHeapType::Sampler, 1);
    backend
        .write_descriptor(
            sampler_heap,
            0,
            ViewDescriptor::Sampler {
                filter: FilterMode::Point,
            },
        )
        .expect("write sampler descriptor");
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    let misattached = backend.record_clear_rtv(list, sampler_heap, 0);
    assert!(
        misattached.is_err(),
        "clear on a non-RTV descriptor must be rejected; got {misattached:?}"
    );
    assert_eq!(
        misattached.expect_err("misattached clear").code,
        ReasonCode::RcD3dInvalidState
    );
}

#[test]
fn t7_5_resource_create_destroy_soak_keeps_live_set_bounded_and_frame_times_stable() {
    let mut backend = GraphicsBackend::new();
    let swapchain = backend
        .create_swapchain(SwapchainDesc {
            width: 800,
            height: 600,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count: 2,
        })
        .expect("create soak swapchain");
    let mut frame_times = Vec::new();
    for iteration in 0..512 {
        let resource = backend
            .create_resource(ResourceDesc {
                name: format!("temp-{iteration}"),
                format: DxgiFormat::R16Float,
                heap: HeapType::Default,
                size: 32,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create transient resource");
        backend
            .destroy_resource(resource)
            .expect("destroy transient resource");
        frame_times.push(
            backend
                .present(swapchain, 1, false)
                .expect("present soak frame")
                .frame_time_us,
        );
    }
    assert_eq!(backend.live_resource_count(), 2);
    // frame_time_us is a pure function of the sync interval (16_666 µs per
    // vsync frame, src/gfx.rs:1390-1393), so pin the value rather than
    // asserting min == max on a constant sequence.
    for frame_time_us in &frame_times {
        assert_eq!(*frame_time_us, 16_666);
    }
}
