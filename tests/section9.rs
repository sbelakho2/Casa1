use casa1::d3d11::{
    BlendStateDesc, D3DPT_TRIANGLELIST, DepthStencilStateDesc, DeviceCreationRequest, FeatureLevel,
    FixedFunctionScene, InputElementDesc, InputLayoutDesc, RasterizerStateDesc,
    RenderTargetBlendDesc, SamplerStateDesc, ShaderModuleDesc, ShaderStage, ViewKind, Viewport,
    d3d11_create_device, d3d11_create_device_and_swapchain, direct3d_create9,
};
use casa1::gfx::{DxgiFormat, FilterMode, ResourceUsageHint, SwapchainDesc};
use casa1::reason::ReasonCode;

fn sha(bytes: &[u8]) -> String {
    casa1::util::sha256_bytes(bytes)
}

#[test]
fn t9_1_d3d11_conformance_microtests_and_frame_diffs_match_reference() {
    let unsupported = d3d11_create_device(DeviceCreationRequest {
        requested_feature_levels: vec![FeatureLevel::Level11_0],
    })
    .expect_err("11_0-only device request must fail truthfully");
    assert_eq!(unsupported.code, ReasonCode::RcD3dFeatureUnsupported);

    let mut device = d3d11_create_device_and_swapchain(
        DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level11_0, FeatureLevel::Level10_1],
        },
        SwapchainDesc {
            width: 1280,
            height: 720,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count: 3,
        },
    )
    .expect("create D3D11 device and swapchain");
    assert_eq!(device.feature_level(), FeatureLevel::Level10_1);
    assert!(!device.caps().geometry_shader);
    assert_eq!(
        device
            .swapchain_state()
            .expect("swapchain state")
            .desc
            .buffer_count,
        3
    );

    let color = device
        .create_texture_2d("color", 4, 4, DxgiFormat::B8G8R8A8Unorm)
        .expect("create color target");
    let depth = device
        .create_texture_2d("depth", 4, 4, DxgiFormat::D24UnormS8Uint)
        .expect("create depth target");
    let tex1d = device
        .create_texture_1d("tex1d", 4, DxgiFormat::R8G8B8A8Unorm)
        .expect("create texture1d");
    let volume = device
        .create_texture_3d("volume", 2, 2, 2, DxgiFormat::R8G8B8A8Unorm)
        .expect("create texture3d");
    let vertex = device
        .create_buffer("vertex", 16, ResourceUsageHint::Generic)
        .expect("create vertex buffer");
    let constants = device
        .create_buffer("constants", 16, ResourceUsageHint::Generic)
        .expect("create constant buffer");
    let staging = device
        .create_buffer("staging", 16, ResourceUsageHint::Generic)
        .expect("create staging buffer");
    let mirror = device
        .create_buffer("mirror", 16, ResourceUsageHint::Generic)
        .expect("create mirror buffer");

    assert_eq!(
        device.resource_desc(volume).expect("volume desc").dimension,
        casa1::d3d11::ResourceDimension::Texture3D
    );

    let color_rtv = device
        .create_render_target_view(color, DxgiFormat::B8G8R8A8Unorm)
        .expect("create RTV");
    let depth_dsv = device
        .create_depth_stencil_view(depth, DxgiFormat::D24UnormS8Uint)
        .expect("create DSV");
    let color_srv = device
        .create_shader_resource_view(color, DxgiFormat::B8G8R8A8Unorm)
        .expect("create SRV");
    let volume_uav = device
        .create_unordered_access_view(volume, DxgiFormat::R8G8B8A8Unorm)
        .expect("create UAV");
    assert_eq!(
        device.view_info(color_srv).expect("SRV info").kind,
        ViewKind::Srv
    );
    assert_eq!(
        device.view_info(volume_uav).expect("UAV info").kind,
        ViewKind::Uav
    );

    let blend = device.create_blend_state(BlendStateDesc {
        alpha_to_coverage_enable: false,
        independent_blend_enable: false,
        render_target: [RenderTargetBlendDesc {
            blend_enable: true,
            ..Default::default()
        }; 8],
    });
    let raster = device.create_rasterizer_state(RasterizerStateDesc {
        fill_mode: "solid".to_string(),
        cull_mode: "back".to_string(),
        front_counter_clockwise: false,
        depth_bias: 0,
        depth_bias_clamp: 0.0,
        slope_scaled_depth_bias: 0.0,
        depth_clip_enable: true,
        scissor_enable: false,
        multisample_enable: false,
        antialiased_line_enable: false,
    });
    let depth_state = device.create_depth_stencil_state(DepthStencilStateDesc {
        depth_enable: true,
        depth_write_mask: 0xFF,
        depth_func: 2,
        stencil_enable: false,
        stencil_read_mask: 0xFF,
        stencil_write_mask: 0xFF,
        front_stencil_fail_op: 1,
        front_stencil_depth_fail_op: 1,
        front_stencil_pass_op: 1,
        front_stencil_func: 2,
        back_stencil_fail_op: 1,
        back_stencil_depth_fail_op: 1,
        back_stencil_pass_op: 1,
        back_stencil_func: 2,
    });
    let sampler = device.create_sampler_state(SamplerStateDesc {
        filter: FilterMode::Linear,
        address_u: "wrap".to_string(),
        address_v: "clamp".to_string(),
        address_w: "wrap".to_string(),
        mip_lod_bias: 0.0,
        max_anisotropy: 16,
        comparison_func: 2,
        border_color: [0.0, 0.0, 0.0, 0.0],
        min_lod: -3.40282347e+38,
        max_lod: 3.40282347e+38,
    });
    let input_layout = device.create_input_layout(InputLayoutDesc {
        elements: vec![
            InputElementDesc {
                semantic: "POSITION".to_string(),
                format: DxgiFormat::R32Float,
                slot: 0,
            },
            InputElementDesc {
                semantic: "TEXCOORD".to_string(),
                format: DxgiFormat::R32Float,
                slot: 0,
            },
        ],
    });
    let vs = device.create_shader(ShaderModuleDesc {
        stage: ShaderStage::Vs,
        entry: "vs_main".to_string(),
    });
    let ps = device.create_shader(ShaderModuleDesc {
        stage: ShaderStage::Ps,
        entry: "ps_main".to_string(),
    });
    let cs = device.create_shader(ShaderModuleDesc {
        stage: ShaderStage::Cs,
        entry: "cs_main".to_string(),
    });

    device
        .update_subresource(constants, &[9, 8, 7, 6, 5, 4, 3, 2])
        .expect("update constants");
    device
        .update_subresource(staging, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        .expect("update staging");
    let mut mapped = device.map(vertex).expect("map vertex buffer");
    mapped[..4].copy_from_slice(&[1, 2, 3, 4]);
    device.unmap(vertex, &mapped).expect("unmap vertex buffer");
    device
        .copy_subresource_region(staging, mirror, 2, 4, 6)
        .expect("copy region");
    device
        .copy_resource(staging, mirror)
        .expect("copy resource");

    device.om_set_render_targets(vec![color_rtv], Some(depth_dsv));
    device.om_set_blend_state(blend);
    device.om_set_depth_stencil_state(depth_state);
    device.rs_set_state(raster);
    device.rs_set_viewports(Viewport {
        x: 0.0,
        y: 0.0,
        width: 1280.0,
        height: 720.0,
    });
    device.ia_set_vertex_buffers(vec![vertex]);
    device.ia_set_index_buffer(staging);
    device.ia_set_input_layout(input_layout);
    device.vs_set_shader(vs);
    device.ps_set_shader(ps);
    device.cs_set_shader(cs);
    device.vs_set_constant_buffers(vec![constants]);
    device.ps_set_constant_buffers(vec![constants]);
    device.ps_set_shader_resources(vec![color_srv]);
    device.cs_set_shader_resources(vec![volume_uav]);
    device.ps_set_samplers(vec![sampler]);

    device
        .clear_render_target_view(color_rtv, [0x11, 0x22, 0x33, 0x44])
        .expect("clear RTV");
    device
        .clear_depth_stencil_view(depth_dsv, 0x00ab_cdef, 0x7f)
        .expect("clear DSV");
    device.draw(3);
    device.draw_indexed(6);
    device.dispatch(2, 3, 1);
    let submission = device.submit_immediate().expect("submit immediate context");

    // The canonical submission signature (src/d3d11.rs:4092-4136) is
    //   gpu={profile}|fl={feature_level}|lists=...|validation=N
    //   |bind[i]={binding signature}   (per recorded binding)
    //   |rp={formats}:{depth}:{draws}:{load}:{store}   (per render pass)
    //   |res[{label}]={digest}   (per resource, sorted by label)
    // The gpu profile and depth store action are host-dependent, so the test
    // parses the signature and asserts each semantic segment exactly instead
    // of comparing a hand-reassembled full string.
    assert_eq!(submission.draw_calls, 1);
    assert_eq!(submission.indexed_draw_calls, 1);
    assert_eq!(submission.dispatch_calls, 1);
    assert_eq!(submission.backend_plan.render_passes.len(), 1);
    assert_eq!(submission.backend_plan.compute_passes, 1);
    assert_eq!(submission.backend_plan.blit_passes, 1);

    let gpu_profile = device.gpu_profile_signature();
    let depth_store_action = if device.memoryless_depth_targets() {
        "store+depth-discard"
    } else {
        "store"
    };
    let header = format!(
        "gpu={gpu_profile}|fl=Level10_1|lists=1|draw=1|draw_indexed=1|dispatch=1|\
         render_passes=1|compute_passes=1|blit_passes=1|validation=0"
    );
    assert!(
        submission.signature.starts_with(&header),
        "signature must start with the canonical header; got: {}",
        submission.signature
    );

    // bind[0] carries the full per-binding state; assert the semantic fields
    // in canonical order (the gpu profile prefix is host-derived, so compare
    // the segment tail exactly).
    let binding_segment = format!(
        "gpu={gpu_profile}|rtv=[Rtv:color]|dsv=depth|vp=0.0,0.0,1280.0,720.0|scissor=none|\
         vb=[vertex]|ib=staging|topo=none|il=POSITION:R32Float:0,TEXCOORD:R32Float:0|\
         blend=false:false:true|rast=solid:back:true:false:0|depth=true:255:false:2|\
         shaders=[Vs:vs_main,Ps:ps_main,Cs:cs_main,Gs:none,Hs:none,Ds:none]|\
         cb=[Vs=[constants];Ps=[constants];Cs=[];Gs=[];Hs=[];Ds=[]]|\
         srv=[Vs=[];Ps=[color];Cs=[volume];Gs=[];Hs=[];Ds=[]]|\
         samp=[Vs=[];Ps=[Linear:wrap:clamp];Cs=[];Gs=[];Hs=[];Ds=[]]"
    );
    let binding = {
        let marker = "|bind[0]=";
        let start = submission
            .signature
            .find(marker)
            .expect("signature must contain bind[0]")
            + marker.len();
        let end = submission.signature[start..]
            .find("|rp=")
            .map(|offset| start + offset)
            .unwrap_or(submission.signature.len());
        &submission.signature[start..end]
    };
    assert_eq!(
        binding, binding_segment,
        "bind[0] must carry the exact canonical binding state; got: {binding}"
    );

    // Render pass plan segment (draw calls 2: one Draw + one DrawIndexed).
    let render_pass = format!(
        "|rp=[Bgra8Unorm]:Some(Depth24UnormStencil8):2:clear:{depth_store_action}"
    );
    assert!(
        submission.signature.contains(&render_pass),
        "signature must contain the exact render pass segment {render_pass}; got: {}",
        submission.signature
    );

    let color_digest = sha(&[0x11, 0x22, 0x33, 0x44].repeat(16));
    let constants_bytes = [9, 8, 7, 6, 5, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0];
    let constants_digest = sha(&constants_bytes);
    let depth_bytes = {
        let mut bytes = Vec::new();
        for _ in 0..12 {
            bytes.extend([0xef, 0xcd, 0xab, 0x00, 0x7f]);
        }
        bytes.extend([0xef, 0xcd, 0xab, 0x00]);
        bytes
    };
    let depth_digest = sha(&depth_bytes);
    let mirror_digest = sha(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0]);
    let staging_digest = mirror_digest.clone();
    let texture_1d_digest = sha(&[0; 16]);
    let texture_3d_digest = sha(&[0; 32]);
    let vertex_digest = sha(&[1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        device.resource_digest(tex1d).expect("tex1d digest"),
        texture_1d_digest
    );
    // Every resource digest must be present under its label (labels sort
    // alphabetically in the signature).
    let resource_segments = [
        ("color", &color_digest),
        ("constants", &constants_digest),
        ("depth", &depth_digest),
        ("mirror", &mirror_digest),
        ("staging", &staging_digest),
        ("tex1d", &texture_1d_digest),
        ("vertex", &vertex_digest),
        ("volume", &texture_3d_digest),
    ];
    for (label, digest) in resource_segments {
        assert!(
            submission
                .signature
                .contains(&format!("|res[{label}]={digest}")),
            "signature must contain the digest for resource '{label}'; got: {}",
            submission.signature
        );
    }
    // The submission hash is the sha256 of the signature itself.
    assert_eq!(submission.hash, sha(submission.signature.as_bytes()));
}

#[test]
fn t9_2_deferred_context_stress_multi_thread_record_execute_no_races_and_deterministic_output() {
    let mut device = d3d11_create_device(DeviceCreationRequest {
        requested_feature_levels: vec![FeatureLevel::Level10_1],
    })
    .expect("create D3D11 device");

    let color = device
        .create_texture_2d("color", 4, 4, DxgiFormat::B8G8R8A8Unorm)
        .expect("create color target");
    let depth = device
        .create_texture_2d("depth", 4, 4, DxgiFormat::D24UnormS8Uint)
        .expect("create depth target");
    let vertex = device
        .create_buffer("vertex", 16, ResourceUsageHint::Generic)
        .expect("create vertex buffer");
    let constants = device
        .create_buffer("constants", 16, ResourceUsageHint::Generic)
        .expect("create constants buffer");
    let color_rtv = device
        .create_render_target_view(color, DxgiFormat::B8G8R8A8Unorm)
        .expect("create RTV");
    let depth_dsv = device
        .create_depth_stencil_view(depth, DxgiFormat::D24UnormS8Uint)
        .expect("create DSV");
    let color_srv = device
        .create_shader_resource_view(color, DxgiFormat::B8G8R8A8Unorm)
        .expect("create SRV");
    let blend = device.create_blend_state(BlendStateDesc {
        alpha_to_coverage_enable: false,
        independent_blend_enable: false,
        render_target: [RenderTargetBlendDesc {
            blend_enable: false,
            ..Default::default()
        }; 8],
    });
    let raster = device.create_rasterizer_state(RasterizerStateDesc {
        fill_mode: "wireframe".to_string(),
        cull_mode: "none".to_string(),
        front_counter_clockwise: false,
        depth_bias: 0,
        depth_bias_clamp: 0.0,
        slope_scaled_depth_bias: 0.0,
        depth_clip_enable: true,
        scissor_enable: false,
        multisample_enable: false,
        antialiased_line_enable: false,
    });
    let depth_state = device.create_depth_stencil_state(DepthStencilStateDesc {
        depth_enable: true,
        depth_write_mask: 0x00,
        depth_func: 2,
        stencil_enable: false,
        stencil_read_mask: 0xFF,
        stencil_write_mask: 0xFF,
        front_stencil_fail_op: 1,
        front_stencil_depth_fail_op: 1,
        front_stencil_pass_op: 1,
        front_stencil_func: 2,
        back_stencil_fail_op: 1,
        back_stencil_depth_fail_op: 1,
        back_stencil_pass_op: 1,
        back_stencil_func: 2,
    });
    let sampler = device.create_sampler_state(SamplerStateDesc {
        filter: FilterMode::Point,
        address_u: "clamp".to_string(),
        address_v: "clamp".to_string(),
        address_w: "clamp".to_string(),
        mip_lod_bias: 0.0,
        max_anisotropy: 1,
        comparison_func: 2,
        border_color: [0.0, 0.0, 0.0, 0.0],
        min_lod: -3.40282347e+38,
        max_lod: 3.40282347e+38,
    });
    let input_layout = device.create_input_layout(InputLayoutDesc {
        elements: vec![InputElementDesc {
            semantic: "POSITION".to_string(),
            format: DxgiFormat::R32Float,
            slot: 0,
        }],
    });
    let vs = device.create_shader(ShaderModuleDesc {
        stage: ShaderStage::Vs,
        entry: "vs_threaded".to_string(),
    });
    let ps = device.create_shader(ShaderModuleDesc {
        stage: ShaderStage::Ps,
        entry: "ps_threaded".to_string(),
    });
    let cs = device.create_shader(ShaderModuleDesc {
        stage: ShaderStage::Cs,
        entry: "cs_threaded".to_string(),
    });

    let mut handles = Vec::new();
    for index in 0..4 {
        let deferred = device.create_deferred_context();
        handles.push(std::thread::spawn(move || {
            deferred
                .om_set_render_targets(vec![color_rtv], Some(depth_dsv))
                .expect("bind targets");
            deferred.om_set_blend_state(blend).expect("bind blend");
            deferred.rs_set_state(raster).expect("bind rasterizer");
            deferred
                .om_set_depth_stencil_state(depth_state)
                .expect("bind depth state");
            deferred
                .rs_set_viewports(Viewport {
                    x: index as f32,
                    y: index as f32,
                    width: 640.0,
                    height: 360.0,
                })
                .expect("bind viewport");
            deferred
                .ia_set_vertex_buffers(vec![vertex])
                .expect("bind vertex buffer");
            deferred
                .ia_set_index_buffer(vertex)
                .expect("bind index buffer");
            deferred
                .ia_set_input_layout(input_layout)
                .expect("bind input layout");
            deferred.vs_set_shader(vs).expect("bind VS");
            deferred.ps_set_shader(ps).expect("bind PS");
            deferred.cs_set_shader(cs).expect("bind CS");
            deferred
                .vs_set_constant_buffers(vec![constants])
                .expect("bind constants");
            deferred
                .ps_set_shader_resources(vec![color_srv])
                .expect("bind SRV");
            deferred
                .ps_set_samplers(vec![sampler])
                .expect("bind sampler");
            deferred
                .update_subresource(constants, &[index as u8; 4])
                .expect("update constants");
            deferred
                .clear_render_target_view(color_rtv, [index as u8, 0, 0, 0xff])
                .expect("clear RTV");
            deferred
                .clear_depth_stencil_view(depth_dsv, index, index as u8)
                .expect("clear DSV");
            deferred
                .ia_set_primitive_topology(D3DPT_TRIANGLELIST)
                .expect("set topology");
            deferred.draw(3 + index).expect("record draw");
            deferred
                .draw_indexed(6 + index)
                .expect("record indexed draw");
            deferred.dispatch(1, index + 1, 1).expect("record dispatch");
            deferred
        }));
    }

    let mut lists = Vec::new();
    for handle in handles {
        let deferred = handle.join().expect("join recorder thread");
        lists.push(
            deferred
                .finish_command_list(&device)
                .expect("finish deferred command list"),
        );
    }
    let first = device
        .execute_deferred_command_lists(&lists)
        .expect("execute deferred command lists");
    let second = device
        .execute_deferred_command_lists(&lists)
        .expect("execute deferred command lists again deterministically");

    assert_eq!(first.executed_command_lists, 4);
    assert_eq!(first.draw_calls, 4);
    assert_eq!(first.indexed_draw_calls, 4);
    assert_eq!(first.dispatch_calls, 4);
    assert_eq!(first.backend_plan.render_passes.len(), 4);
    assert_eq!(first.backend_plan.compute_passes, 4);
    assert_eq!(first.backend_plan.validation_errors.len(), 0);
    assert_eq!(first.signature, second.signature);
    assert_eq!(first.hash, second.hash);
}

#[test]
fn t9_3_state_leak_tests_random_state_churn_output_matches_oracle() {
    fn build_device() -> casa1::d3d11::D3d11Device {
        d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create D3D11 device")
    }

    fn baseline_submission(device: &mut casa1::d3d11::D3d11Device) -> String {
        let color = device
            .create_texture_2d("color", 4, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("create color target");
        let depth = device
            .create_texture_2d("depth", 4, 4, DxgiFormat::D24UnormS8Uint)
            .expect("create depth target");
        let buffer = device
            .create_buffer("vb", 16, ResourceUsageHint::Generic)
            .expect("create vertex buffer");
        let constants = device
            .create_buffer("cb", 16, ResourceUsageHint::Generic)
            .expect("create constant buffer");
        let rtv = device
            .create_render_target_view(color, DxgiFormat::B8G8R8A8Unorm)
            .expect("create RTV");
        let dsv = device
            .create_depth_stencil_view(depth, DxgiFormat::D24UnormS8Uint)
            .expect("create DSV");
        let srv = device
            .create_shader_resource_view(color, DxgiFormat::B8G8R8A8Unorm)
            .expect("create SRV");
        let blend = device.create_blend_state(BlendStateDesc {
            alpha_to_coverage_enable: false,
            independent_blend_enable: false,
            render_target: [RenderTargetBlendDesc {
                blend_enable: true,
                ..Default::default()
            }; 8],
        });
        let raster = device.create_rasterizer_state(RasterizerStateDesc {
            fill_mode: "solid".to_string(),
            cull_mode: "back".to_string(),
            front_counter_clockwise: false,
            depth_bias: 0,
            depth_bias_clamp: 0.0,
            slope_scaled_depth_bias: 0.0,
            depth_clip_enable: true,
            scissor_enable: false,
            multisample_enable: false,
            antialiased_line_enable: false,
        });
        let depth_state = device.create_depth_stencil_state(DepthStencilStateDesc {
            depth_enable: true,
            depth_write_mask: 0xFF,
            depth_func: 2,
            stencil_enable: false,
            stencil_read_mask: 0xFF,
            stencil_write_mask: 0xFF,
            front_stencil_fail_op: 1,
            front_stencil_depth_fail_op: 1,
            front_stencil_pass_op: 1,
            front_stencil_func: 2,
            back_stencil_fail_op: 1,
            back_stencil_depth_fail_op: 1,
            back_stencil_pass_op: 1,
            back_stencil_func: 2,
        });
        let sampler = device.create_sampler_state(SamplerStateDesc {
            filter: FilterMode::Linear,
            address_u: "wrap".to_string(),
            address_v: "wrap".to_string(),
            address_w: "wrap".to_string(),
            mip_lod_bias: 0.0,
            max_anisotropy: 16,
            comparison_func: 2,
            border_color: [0.0, 0.0, 0.0, 0.0],
            min_lod: -3.40282347e+38,
            max_lod: 3.40282347e+38,
        });
        let input_layout = device.create_input_layout(InputLayoutDesc {
            elements: vec![InputElementDesc {
                semantic: "POSITION".to_string(),
                format: DxgiFormat::R32Float,
                slot: 0,
            }],
        });
        let vs = device.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Vs,
            entry: "vs_baseline".to_string(),
        });
        let ps = device.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Ps,
            entry: "ps_baseline".to_string(),
        });

        device.om_set_render_targets(vec![rtv], Some(dsv));
        device.om_set_blend_state(blend);
        device.om_set_depth_stencil_state(depth_state);
        device.rs_set_state(raster);
        device.rs_set_viewports(Viewport {
            x: 0.0,
            y: 0.0,
            width: 800.0,
            height: 600.0,
        });
        device.ia_set_vertex_buffers(vec![buffer]);
        device.ia_set_index_buffer(buffer);
        device.ia_set_input_layout(input_layout);
        device.vs_set_shader(vs);
        device.ps_set_shader(ps);
        device.vs_set_constant_buffers(vec![constants]);
        device.ps_set_shader_resources(vec![srv]);
        device.ps_set_samplers(vec![sampler]);
        device
            .update_subresource(constants, &[1, 2, 3, 4])
            .expect("update constants");
        device
            .clear_render_target_view(rtv, [0xaa, 0xbb, 0xcc, 0xdd])
            .expect("clear RTV");
        device
            .clear_depth_stencil_view(dsv, 1, 0)
            .expect("clear DSV");
        device.draw(3);
        device
            .submit_immediate()
            .expect("submit immediate")
            .signature
    }

    let mut churned = build_device();
    for step in 0..12 {
        let blend = churned.create_blend_state(BlendStateDesc {
            alpha_to_coverage_enable: step % 3 == 0,
            independent_blend_enable: false,
            render_target: [RenderTargetBlendDesc {
                blend_enable: step % 2 == 0,
                ..Default::default()
            }; 8],
        });
        let raster = churned.create_rasterizer_state(RasterizerStateDesc {
            fill_mode: if step % 2 == 0 { "solid" } else { "wireframe" }.to_string(),
            cull_mode: if step % 3 == 0 { "back" } else { "none" }.to_string(),
            front_counter_clockwise: false,
            depth_bias: 0,
            depth_bias_clamp: 0.0,
            slope_scaled_depth_bias: 0.0,
            depth_clip_enable: true,
            scissor_enable: false,
            multisample_enable: false,
            antialiased_line_enable: false,
        });
        let depth_state = churned.create_depth_stencil_state(DepthStencilStateDesc {
            depth_enable: step % 2 == 0,
            depth_write_mask: if step % 4 != 0 { 0xFF } else { 0x00 },
            depth_func: 2,
            stencil_enable: false,
            stencil_read_mask: 0xFF,
            stencil_write_mask: 0xFF,
            front_stencil_fail_op: 1,
            front_stencil_depth_fail_op: 1,
            front_stencil_pass_op: 1,
            front_stencil_func: 2,
            back_stencil_fail_op: 1,
            back_stencil_depth_fail_op: 1,
            back_stencil_pass_op: 1,
            back_stencil_func: 2,
        });
        churned.om_set_blend_state(blend);
        churned.rs_set_state(raster);
        churned.om_set_depth_stencil_state(depth_state);
        churned.rs_set_viewports(Viewport {
            x: step as f32,
            y: step as f32,
            width: 320.0 + step as f32,
            height: 200.0 + step as f32,
        });
    }
    let churned_signature = baseline_submission(&mut churned);
    let clean_signature = baseline_submission(&mut build_device());
    assert_eq!(churned_signature, clean_signature);
}

#[test]
fn t9_4_d3d9_legacy_suite_covers_golden_frames_and_exact_not_supported_errors() {
    let mut d3d9 = direct3d_create9(true);
    let device = d3d9.create_device().expect("create D3D9 device");
    let scene = FixedFunctionScene {
        texture_factor: 0x1122_3344,
        diffuse_color: [0xaa, 0xbb, 0xcc, 0xdd],
        fog_enable: true,
        alpha_blend_enable: false,
        primitive_count: 12,
    };
    let frame = device
        .render_fixed_function_scene(&scene)
        .expect("render fixed-function scene");
    let expected_signature =
        "d3d9:id=1|tf=11223344|diff=aabbccdd|fog=true|blend=false|prim=12|640x480";
    assert_eq!(frame.signature, expected_signature);
    assert_eq!(frame.hash, sha(expected_signature.as_bytes()));

    let mut disabled = direct3d_create9(false);
    let error = disabled
        .create_device()
        .expect_err("disabled D3D9 shim must fail with exact reason code");
    assert_eq!(error.code, ReasonCode::RcD3d9NotSupported);
    assert!(
        error
            .reproduction_hints
            .iter()
            .any(|hint| hint.contains("Direct3D9 compatibility shim"))
    );
}
