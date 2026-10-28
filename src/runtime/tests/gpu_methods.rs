use super::*;

const METHOD_TEST_STACK: u64 = 0x50_000;

const D3D11_DEVICE_IID: [u8; 16] = [
    0xdd, 0x6f, 0xf6, 0xdb, 0x77, 0xac, 0x88, 0x4e, 0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40,
];
const D3D11_CONTEXT_IID: [u8; 16] = [
    0xf0, 0xa0, 0xbf, 0xc1, 0x33, 0x51, 0xe0, 0x4a, 0xbb, 0xc4, 0xf1, 0x11, 0x43, 0x5b, 0x09, 0xaf,
];
const D3D12_QUEUE_IID: [u8; 16] = [
    0xa6, 0x70, 0x08, 0x0e, 0x7e, 0x5d, 0x22, 0x4c, 0x8c, 0xfc, 0x5b, 0xaa, 0xe0, 0x76, 0x16, 0xed,
];
const D3D12_HEAP_IID: [u8; 16] = [
    0x1d, 0x47, 0xfb, 0x8e, 0x6c, 0x61, 0x49, 0x4f, 0x90, 0xf7, 0x12, 0x7b, 0xb7, 0x63, 0xfa, 0x51,
];
const D3D12_FENCE_IID: [u8; 16] = [
    0xcf, 0xdc, 0x53, 0x0a, 0xd8, 0xc4, 0x91, 0x4b, 0xad, 0xf6, 0xbe, 0x5a, 0x60, 0xd9, 0x5a, 0x76,
];
const D3D12_LIST_IID: [u8; 16] = [
    0x0f, 0x16, 0x0d, 0x5b, 0x1b, 0xac, 0x85, 0x41, 0x8b, 0xa8, 0xb3, 0xae, 0x42, 0xa5, 0xa4, 0x57,
];
const DXGI_FACTORY_IID: [u8; 16] = [
    0xec, 0x71, 0x6b, 0x7b, 0xc7, 0x21, 0x44, 0xae, 0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1e, 0xa3, 0x69,
];
const DXGI_SWAPCHAIN_IID: [u8; 16] = [
    0xa0, 0x36, 0x0d, 0x31, 0xe7, 0xd2, 0x0a, 0x4c, 0xaa, 0x04, 0x6a, 0x9d, 0x23, 0xb8, 0x88, 0x6a,
];
const METHOD_TEST_UNKNOWN_IID: [u8; 16] = [0xab; 16];
const DXGI_ERROR_UNSUPPORTED: u64 = 0x887A_0004;

fn vtable_slot_thunk(memory: &MemoryImage, object: u64, slot: usize) -> AppResult<u64> {
    let vtable = memory.read_u64(object)?;
    memory.read_u64(vtable + slot as u64 * 8)
}

fn try_vtable_call(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    object: u64,
    slot: usize,
    args: &[u64],
) -> AppResult<u64> {
    let thunk = vtable_slot_thunk(memory, object, slot)?;
    memory.map_bytes(METHOD_TEST_STACK, &[0u8; 0x400]);
    memory.write_u64(METHOD_TEST_STACK, 0xDEAD_BEEF);
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, METHOD_TEST_STACK);
    if let Some(arg) = args.first() {
        state.set(Register::Rcx, *arg);
    }
    if let Some(arg) = args.get(1) {
        state.set(Register::Rdx, *arg);
    }
    if let Some(arg) = args.get(2) {
        state.set(Register::R8, *arg);
    }
    if let Some(arg) = args.get(3) {
        state.set(Register::R9, *arg);
    }
    for (index, arg) in args.iter().enumerate().skip(4) {
        memory.write_u64(METHOD_TEST_STACK + 0x28 + (index as u64 - 4) * 8, *arg);
    }
    runtime.dispatch_import(thunk, &mut state, memory)?;
    Ok(state.get(Register::Rax))
}

fn vtable_ok(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    object: u64,
    slot: usize,
    args: &[u64],
) -> u64 {
    let value = try_vtable_call(runtime, memory, object, slot, args)
        .unwrap_or_else(|error| panic!("vtable slot {slot} must dispatch: {error}"));
    assert_eq!(value, 0, "vtable slot {slot} must return S_OK");
    value
}

fn vtable_err(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    object: u64,
    slot: usize,
    args: &[u64],
) -> AppError {
    try_vtable_call(runtime, memory, object, slot, args)
        .expect_err("the invalid input must fail the vtable call")
}

#[test]
fn d3d11_device_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d11-device-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x10_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x30000]);

        let device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create d3d11 device");
        let device_object = runtime
            .alloc_d3d11_device_object(&mut memory, device)
            .expect("alloc d3d11 device");
        let context_object = runtime
            .d3d11_device(device_object)
            .expect("device host")
            .context_object;

        let out0 = base + 0x1000;

        let iid_ptr = base + 0x2000;
        memory.map_bytes(iid_ptr, &D3D11_DEVICE_IID);
        memory.map_bytes(out0, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                0,
                &[device_object, iid_ptr, out0]
            )
            .expect("device QueryInterface"),
            0
        );
        assert_eq!(memory.read_u64(out0).expect("QI output"), device_object);
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                0,
                &[device_object, iid_ptr, out0]
            )
            .expect("device QueryInterface unknown"),
            E_NOINTERFACE
        );
        memory.map_bytes(iid_ptr, &D3D11_DEVICE_IID);
        assert_ne!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                1,
                &[device_object]
            )
            .expect("device AddRef"),
            0
        );
        let _ = try_vtable_call(
            &mut runtime,
            &mut memory,
            device_object,
            2,
            &[device_object],
        )
        .expect("device Release");

        let buffer_desc = base + 0x2100;
        write_u32(&mut memory, buffer_desc, 256);
        write_u32(&mut memory, buffer_desc + 4, 0);
        write_u32(&mut memory, buffer_desc + 8, 0x4);
        write_u32(&mut memory, buffer_desc + 12, 0);
        let buffer_out = base + 0x4000;
        memory.map_bytes(buffer_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            3,
            &[device_object, buffer_desc, 0, buffer_out],
        );
        let buffer_object = memory.read_u64(buffer_out).expect("buffer object");
        assert_eq!(
            runtime
                .guest_object_kind(buffer_object)
                .expect("buffer kind"),
            GuestObjectKind::D3d11Buffer
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                3,
                &[device_object, 0, 0, buffer_out]
            )
            .expect("CreateBuffer invalid descriptor"),
            E_INVALIDARG
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                device_object,
                3,
                &[context_object, buffer_desc, 0, buffer_out],
            )
            .message
            .contains("CreateBuffer")
        );

        let texture1d_desc = base + 0x2200;
        write_u32(&mut memory, texture1d_desc, 4);
        write_u32(&mut memory, texture1d_desc + 12, 28);
        let texture1d_out = base + 0x4010;
        memory.map_bytes(texture1d_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            4,
            &[device_object, texture1d_desc, 0, texture1d_out],
        );
        let _texture1d_object = memory.read_u64(texture1d_out).expect("texture1d");

        let texture2d_desc = base + 0x2300;
        write_u32(&mut memory, texture2d_desc, 4);
        write_u32(&mut memory, texture2d_desc + 4, 4);
        write_u32(&mut memory, texture2d_desc + 8, 1);
        write_u32(&mut memory, texture2d_desc + 12, 1);
        write_u32(&mut memory, texture2d_desc + 16, 28);
        write_u32(&mut memory, texture2d_desc + 20, 1);
        write_u32(&mut memory, texture2d_desc + 28, 0);
        write_u32(&mut memory, texture2d_desc + 32, 0x28);
        let texture2d_out = base + 0x4020;
        memory.map_bytes(texture2d_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            5,
            &[device_object, texture2d_desc, 0, texture2d_out],
        );
        let texture2d_object = memory.read_u64(texture2d_out).expect("texture2d");
        assert_eq!(
            runtime
                .guest_object_kind(texture2d_object)
                .expect("texture kind"),
            GuestObjectKind::D3d11Texture2D
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                5,
                &[device_object, texture2d_desc, 0, 0],
            )
            .expect("CreateTexture2D null out"),
            E_INVALIDARG
        );

        let texture3d_desc = base + 0x2400;
        write_u32(&mut memory, texture3d_desc, 4);
        write_u32(&mut memory, texture3d_desc + 4, 4);
        write_u32(&mut memory, texture3d_desc + 8, 1);
        write_u32(&mut memory, texture3d_desc + 16, 28);
        let texture3d_out = base + 0x4030;
        memory.map_bytes(texture3d_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            6,
            &[device_object, texture3d_desc, 0, texture3d_out],
        );

        let depth_desc = base + 0x2480;
        write_u32(&mut memory, depth_desc, 4);
        write_u32(&mut memory, depth_desc + 4, 4);
        write_u32(&mut memory, depth_desc + 8, 1);
        write_u32(&mut memory, depth_desc + 12, 1);
        write_u32(&mut memory, depth_desc + 16, 45);
        write_u32(&mut memory, depth_desc + 20, 1);
        write_u32(&mut memory, depth_desc + 32, 0x40);
        let depth_out = base + 0x4040;
        memory.map_bytes(depth_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            5,
            &[device_object, depth_desc, 0, depth_out],
        );
        let depth_texture_object = memory.read_u64(depth_out).expect("depth texture");

        let view_out = base + 0x2500;
        for (slot, resource) in [
            (7usize, texture2d_object),
            (8usize, buffer_object),
            (9usize, texture2d_object),
            (10usize, depth_texture_object),
        ] {
            memory.map_bytes(view_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, resource, 0, view_out],
            );
            let view = memory.read_u64(view_out).expect("view object");
            assert_eq!(
                runtime.guest_object_kind(view).expect("view kind"),
                GuestObjectKind::D3d11View
            );
        }
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                7,
                &[device_object, 0, 0, view_out],
            )
            .expect("CreateShaderResourceView null resource"),
            E_INVALIDARG
        );

        let semantic_ptr = base + 0x2600;
        memory.map_bytes(semantic_ptr, b"POSITION\0");
        let element_ptr = base + 0x2640;
        memory.map_bytes(element_ptr, &[0u8; 32]);
        write_u64(&mut memory, element_ptr, semantic_ptr);
        write_u32(&mut memory, element_ptr + 12, 28);
        write_u32(&mut memory, element_ptr + 16, 0);
        let bytecode = embedded_root_pixel_shader_dxil();
        let bytecode_ptr = base + 0x2700;
        memory.map_bytes(bytecode_ptr, &bytecode);
        let layout_out = base + 0x2680;
        memory.map_bytes(layout_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            11,
            &[
                device_object,
                element_ptr,
                1,
                bytecode_ptr,
                bytecode.len() as u64,
                layout_out,
            ],
        );
        let layout_object = memory.read_u64(layout_out).expect("input layout");
        assert_eq!(
            runtime
                .guest_object_kind(layout_object)
                .expect("layout kind"),
            GuestObjectKind::D3d11InputLayout
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                11,
                &[device_object, 0, 0, 0, 0, layout_out],
            )
            .expect("CreateInputLayout invalid"),
            E_INVALIDARG
        );

        let shader_out = base + 0x2800;
        for (slot, stage, uses_stack_out) in [
            (12usize, D3d11ShaderStage::Vs, true),
            (13usize, D3d11ShaderStage::Gs, false),
            (14usize, D3d11ShaderStage::Gs, false),
            (15usize, D3d11ShaderStage::Ps, true),
            (16usize, D3d11ShaderStage::Hs, false),
            (17usize, D3d11ShaderStage::Ds, false),
            (18usize, D3d11ShaderStage::Cs, true),
        ] {
            memory.map_bytes(shader_out, &[0u8; 8]);
            let args: &[u64] = if uses_stack_out {
                &[
                    device_object,
                    bytecode_ptr,
                    bytecode.len() as u64,
                    0,
                    shader_out,
                ]
            } else {
                &[
                    device_object,
                    bytecode_ptr,
                    bytecode.len() as u64,
                    shader_out,
                ]
            };
            vtable_ok(&mut runtime, &mut memory, device_object, slot, args);
            let shader_object = memory.read_u64(shader_out).expect("shader object");
            assert_ne!(shader_object, 0, "shader slot {slot}");
            assert_eq!(
                runtime
                    .d3d11_shader(shader_object)
                    .expect("shader host")
                    .stage,
                stage
            );
        }
        memory.map_bytes(shader_out, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                12,
                &[device_object, 0, 0, 0, shader_out],
            )
            .expect("CreateVertexShader null bytecode"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                15,
                &[
                    device_object,
                    bytecode_ptr,
                    bytecode.len() as u64,
                    1,
                    shader_out
                ],
            )
            .expect("CreatePixelShader class linkage"),
            E_INVALIDARG
        );

        let linkage_out = base + 0x2900;
        memory.map_bytes(linkage_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            19,
            &[device_object, linkage_out],
        );
        assert_ne!(memory.read_u64(linkage_out).expect("linkage"), 0);

        let blend_desc = base + 0x2a00;
        memory.map_bytes(blend_desc, &[0u8; 64]);
        let depth_desc_ptr = base + 0x2a40;
        memory.map_bytes(depth_desc_ptr, &[0u8; 64]);
        let raster_desc = base + 0x2a80;
        memory.map_bytes(raster_desc, &[0u8; 64]);
        write_u32(&mut memory, raster_desc, 3);
        write_u32(&mut memory, raster_desc + 4, 1);
        let sampler_desc = base + 0x2ac0;
        memory.map_bytes(sampler_desc, &[0u8; 64]);
        write_u32(&mut memory, sampler_desc, 21);
        write_u32(&mut memory, sampler_desc + 4, 1);
        write_u32(&mut memory, sampler_desc + 8, 1);
        write_u32(&mut memory, sampler_desc + 12, 1);
        for (slot, desc) in [
            (20usize, blend_desc),
            (21usize, depth_desc_ptr),
            (22usize, raster_desc),
            (23usize, sampler_desc),
        ] {
            let state_out = base + 0x2b00;
            memory.map_bytes(state_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, desc, state_out],
            );
            assert_ne!(memory.read_u64(state_out).expect("state object"), 0);
        }
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                20,
                &[device_object, 0, base + 0x2b00],
            )
            .expect("CreateBlendState null desc"),
            E_INVALIDARG
        );

        let query_out = base + 0x2c00;
        for slot in [24usize, 25usize, 26usize] {
            memory.map_bytes(query_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, 0, query_out],
            );
            assert_eq!(
                runtime
                    .guest_object_kind(memory.read_u64(query_out).expect("query"))
                    .expect("query kind"),
                GuestObjectKind::D3d11Query
            );
        }

        for slot in [27usize, 41usize] {
            let deferred_out = base + 0x2d00;
            memory.map_bytes(deferred_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, 0, deferred_out],
            );
            assert_eq!(
                runtime
                    .guest_object_kind(memory.read_u64(deferred_out).expect("deferred"))
                    .expect("deferred kind"),
                GuestObjectKind::D3d11DeferredContext
            );
        }
        assert_eq!(
            vtable_err(
                &mut runtime,
                &mut memory,
                device_object,
                27,
                &[context_object, 0, base + 0x2d00],
            )
            .code,
            ReasonCode::RcUnimplInsn
        );

        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                28,
                &[device_object, 0, 0, 0],
            )
            .expect("OpenSharedResource"),
            0x8007_0057_u64.wrapping_neg()
        );

        let support_out = base + 0x2e00;
        memory.map_bytes(support_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            29,
            &[device_object, 28, support_out],
        );
        assert_ne!(memory.read_u64(support_out).expect("format support"), 0);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                29,
                &[device_object, 0xffff, support_out],
            )
            .expect("CheckFormatSupport unknown format"),
            E_INVALIDARG
        );
        let quality_out = base + 0x2e08;
        memory.map_bytes(quality_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            30,
            &[device_object, 28, 4, quality_out],
        );
        assert_eq!(memory.read_u64(quality_out).expect("quality"), 1);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                30,
                &[device_object, 28, 3, quality_out],
            )
            .expect("CheckMultisampleQualityLevels invalid count"),
            E_INVALIDARG
        );
        let counter_info = base + 0x2e10;
        memory.map_bytes(counter_info, &[0u8; 12]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            31,
            &[device_object, counter_info],
        );
        assert_eq!(
            read_guest_u32(&memory, counter_info).expect("counter info"),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, counter_info + 4).expect("max counters"),
            4
        );
        assert_eq!(
            read_guest_u32(&memory, counter_info + 8).expect("simultaneous counters"),
            1
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                32,
                &[device_object, 0, 0, 0],
            )
            .expect("CheckCounter"),
            1
        );
        let feature_out = base + 0x2e20;
        memory.map_bytes(feature_out, &[0u8; 16]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            33,
            &[device_object, 0, feature_out, 8],
        );
        assert_eq!(memory.read_u8(feature_out).expect("threading"), 1);
        assert_eq!(memory.read_u8(feature_out + 1).expect("command lists"), 1);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                33,
                &[device_object, 99, feature_out, 8],
            )
            .expect("CheckFeatureSupport unknown feature"),
            E_INVALIDARG
        );

        let guid = base + 0x2f00;
        memory.map_bytes(guid, &[0x22; 16]);
        let size_ptr = base + 0x2f10;
        memory.map_bytes(size_ptr, &[0u8; 4]);
        let data_ptr = base + 0x2f20;
        memory.map_bytes(data_ptr, b"data");
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                34,
                &[device_object, guid, size_ptr, data_ptr],
            )
            .expect("GetPrivateData"),
            0x8007_004E_u64.wrapping_neg()
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            35,
            &[device_object, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            37,
            &[device_object, guid, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device_object,
                36,
                &[device_object],
            )
            .expect("GetDeviceRemovedReason"),
            0
        );

        let level_out = base + 0x3000;
        memory.map_bytes(level_out, &[0u8; 4]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            38,
            &[device_object, level_out],
        );
        assert_eq!(
            read_guest_u32(&memory, level_out).expect("feature level"),
            0xb000
        );
        for slot in [39usize, 40usize, 42usize] {
            let context_out = base + 0x3010;
            memory.map_bytes(context_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, context_out],
            );
            assert_eq!(
                memory.read_u64(context_out).expect("immediate context"),
                context_object
            );
        }
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                device_object,
                40,
                &[context_object, base + 0x3010],
            )
            .message
            .contains("GetImmediateContext")
        );
    });
}

#[test]
fn d3d11_context_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d11-context-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x20_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x40000]);

        let device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create d3d11 device");
        let device_object = runtime
            .alloc_d3d11_device_object(&mut memory, device)
            .expect("alloc d3d11 device");
        let context_object = runtime
            .d3d11_device(device_object)
            .expect("device host")
            .context_object;

        let buffer_desc = base + 0x1000;
        write_u32(&mut memory, buffer_desc, 256);
        write_u32(&mut memory, buffer_desc + 8, 0x4);
        let buffer_out = base + 0x1010;
        let mut buffers = [0u64; 2];
        for (index, slot) in buffers.iter_mut().enumerate() {
            memory.map_bytes(buffer_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                3,
                &[device_object, buffer_desc, 0, buffer_out],
            );
            *slot = memory.read_u64(buffer_out).expect("buffer object");
            assert_ne!(*slot, 0, "buffer {index}");
        }

        let texture_desc = base + 0x1100;
        write_u32(&mut memory, texture_desc, 4);
        write_u32(&mut memory, texture_desc + 4, 4);
        write_u32(&mut memory, texture_desc + 8, 1);
        write_u32(&mut memory, texture_desc + 12, 1);
        write_u32(&mut memory, texture_desc + 16, 28);
        write_u32(&mut memory, texture_desc + 20, 1);
        write_u32(&mut memory, texture_desc + 32, 0x28);
        let texture_out = base + 0x3000;
        let mut textures = [0u64; 3];
        for (index, slot) in textures.iter_mut().enumerate() {
            write_u32(
                &mut memory,
                texture_desc + 16,
                if index == 2 { 45 } else { 28 },
            );
            write_u32(
                &mut memory,
                texture_desc + 32,
                if index == 2 { 0x40 } else { 0x28 },
            );
            memory.map_bytes(texture_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                5,
                &[device_object, texture_desc, 0, texture_out],
            );
            *slot = memory.read_u64(texture_out).expect("texture object");
            assert_ne!(*slot, 0, "texture {index}");
        }

        let view_out = base + 0x1200;
        let mut srv = 0u64;
        let mut uav = 0u64;
        let mut rtv = 0u64;
        let mut dsv = 0u64;
        for (slot, resource, target) in [
            (7usize, textures[0], &mut srv),
            (8usize, buffers[0], &mut uav),
            (9usize, textures[0], &mut rtv),
            (10usize, textures[2], &mut dsv),
        ] {
            memory.map_bytes(view_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, resource, 0, view_out],
            );
            *target = memory.read_u64(view_out).expect("view object");
            assert_ne!(*target, 0);
        }

        let semantic_ptr = base + 0x1300;
        memory.map_bytes(semantic_ptr, b"POSITION\0");
        let element_ptr = base + 0x1340;
        memory.map_bytes(element_ptr, &[0u8; 32]);
        write_u64(&mut memory, element_ptr, semantic_ptr);
        write_u32(&mut memory, element_ptr + 12, 28);
        let bytecode = embedded_root_pixel_shader_dxil();
        let bytecode_ptr = base + 0x1400;
        memory.map_bytes(bytecode_ptr, &bytecode);
        let layout_out = base + 0x1380;
        memory.map_bytes(layout_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            11,
            &[
                device_object,
                element_ptr,
                1,
                bytecode_ptr,
                bytecode.len() as u64,
                layout_out,
            ],
        );
        let layout_object = memory.read_u64(layout_out).expect("input layout");

        let shader_out = base + 0x1500;
        let mut shaders = [0u64; 6];
        for (index, (slot, uses_stack_out)) in [
            (12usize, true),
            (13, false),
            (15, true),
            (16, false),
            (17, false),
            (18, true),
        ]
        .into_iter()
        .enumerate()
        {
            memory.map_bytes(shader_out, &[0u8; 8]);
            let args: &[u64] = if uses_stack_out {
                &[
                    device_object,
                    bytecode_ptr,
                    bytecode.len() as u64,
                    0,
                    shader_out,
                ]
            } else {
                &[
                    device_object,
                    bytecode_ptr,
                    bytecode.len() as u64,
                    shader_out,
                ]
            };
            vtable_ok(&mut runtime, &mut memory, device_object, slot, args);
            shaders[index] = memory.read_u64(shader_out).expect("shader object");
            assert_ne!(shaders[index], 0);
        }

        let blend_desc = base + 0x1600;
        memory.map_bytes(blend_desc, &[0u8; 64]);
        let depth_desc = base + 0x1640;
        memory.map_bytes(depth_desc, &[0u8; 64]);
        let raster_desc = base + 0x1680;
        memory.map_bytes(raster_desc, &[0u8; 64]);
        write_u32(&mut memory, raster_desc, 3);
        write_u32(&mut memory, raster_desc + 4, 1);
        let sampler_desc = base + 0x16c0;
        memory.map_bytes(sampler_desc, &[0u8; 64]);
        write_u32(&mut memory, sampler_desc, 21);
        write_u32(&mut memory, sampler_desc + 4, 1);
        write_u32(&mut memory, sampler_desc + 8, 1);
        write_u32(&mut memory, sampler_desc + 12, 1);
        let state_out = base + 0x1700;
        let mut states = [0u64; 4];
        for (index, (slot, desc)) in [
            (20usize, blend_desc),
            (21usize, depth_desc),
            (22usize, raster_desc),
            (23usize, sampler_desc),
        ]
        .into_iter()
        .enumerate()
        {
            memory.map_bytes(state_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, desc, state_out],
            );
            states[index] = memory.read_u64(state_out).expect("state object");
            assert_ne!(states[index], 0);
        }
        let query_out = base + 0x1710;
        memory.map_bytes(query_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            24,
            &[device_object, 0, query_out],
        );
        let query_object = memory.read_u64(query_out).expect("query object");
        let [blend, depth_state, raster, sampler] = states;
        let [buffer_a, buffer_b] = buffers;
        let [texture_a, texture_b, _depth_texture] = textures;
        let [vs, gs, ps, hs, ds, cs] = shaders;

        let buffer_array = base + 0x1800;
        let srv_array = base + 0x1810;
        let uav_array = base + 0x1820;
        let rtv_array = base + 0x1830;
        let sampler_array = base + 0x1840;
        let stride_ptr = base + 0x1850;
        let offset_ptr = base + 0x1858;
        write_u64(&mut memory, buffer_array, buffer_a);
        write_u64(&mut memory, srv_array, srv);
        write_u64(&mut memory, uav_array, uav);
        write_u64(&mut memory, rtv_array, rtv);
        write_u64(&mut memory, sampler_array, sampler);
        write_u32(&mut memory, stride_ptr, 4);
        write_u32(&mut memory, offset_ptr, 0);
        let viewport_ptr = base + 0x1860;
        write_u32(&mut memory, viewport_ptr, 0.0f32.to_bits());
        write_u32(&mut memory, viewport_ptr + 4, 0.0f32.to_bits());
        write_u32(&mut memory, viewport_ptr + 8, 4.0f32.to_bits());
        write_u32(&mut memory, viewport_ptr + 12, 4.0f32.to_bits());
        let scissor_ptr = base + 0x1870;
        write_u32(&mut memory, scissor_ptr, 0);
        write_u32(&mut memory, scissor_ptr + 4, 0);
        write_u32(&mut memory, scissor_ptr + 8, 4);
        write_u32(&mut memory, scissor_ptr + 12, 4);
        let upload_ptr = base + 0x1900;
        memory.map_bytes(upload_ptr, &[0x5a; 64]);
        let color_ptr = base + 0x1980;
        memory.map_bytes(color_ptr, &[0u8; 8]);
        let private_guid = base + 0x1a00;
        memory.map_bytes(private_guid, &[0x33; 16]);
        let private_size = base + 0x1a10;
        memory.map_bytes(private_size, &[0u8; 4]);
        let private_data = base + 0x1a20;
        memory.map_bytes(private_data, b"ctx-data");
        let lod_out = base + 0x1a50;
        memory.map_bytes(lod_out, &[0u8; 4]);
        let predication_out = base + 0x1a58;
        memory.map_bytes(predication_out, &[0u8; 8]);

        let iid_ptr = base + 0x1b00;
        memory.map_bytes(iid_ptr, &D3D11_CONTEXT_IID);
        let qi_out = base + 0x1b10;
        memory.map_bytes(qi_out, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                0,
                &[context_object, iid_ptr, qi_out],
            )
            .expect("context QueryInterface"),
            0
        );
        assert_eq!(memory.read_u64(qi_out).expect("context QI"), context_object);
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                0,
                &[context_object, iid_ptr, qi_out],
            )
            .expect("context QueryInterface unknown"),
            E_NOINTERFACE
        );
        assert_ne!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                1,
                &[context_object]
            )
            .expect("context AddRef"),
            0
        );
        let _ = try_vtable_call(
            &mut runtime,
            &mut memory,
            context_object,
            2,
            &[context_object],
        )
        .expect("context Release");

        let device_out = base + 0x1c00;
        memory.map_bytes(device_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            3,
            &[context_object, device_out],
        );
        assert_eq!(
            memory.read_u64(device_out).expect("context device"),
            device_object
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                4,
                &[context_object, private_guid, private_size, private_data],
            )
            .expect("context GetPrivateData"),
            0x8007_004E_u64.wrapping_neg()
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            5,
            &[context_object, private_guid, 4, private_data],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            6,
            &[context_object, private_guid, 0],
        );

        for slot in [7usize, 23usize, 28usize, 32usize, 46usize] {
            vtable_ok(
                &mut runtime,
                &mut memory,
                context_object,
                slot,
                &[context_object, 0, 1, buffer_array],
            );
        }
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            7,
            &[context_object, 0, 0, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                7,
                &[context_object, 1, 0, 0],
            )
            .expect("VSSetConstantBuffers non-zero start slot"),
            E_INVALIDARG
        );
        for slot in [8usize, 25usize, 29usize, 34usize, 38usize, 40usize] {
            vtable_ok(
                &mut runtime,
                &mut memory,
                context_object,
                slot,
                &[context_object, 0, 1, srv_array],
            );
        }
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                8,
                &[context_object, 1, 0, 0],
            )
            .expect("PSSetShaderResources non-zero start slot"),
            E_INVALIDARG
        );
        for slot in [10usize, 26usize, 30usize, 37usize, 39usize, 42usize] {
            vtable_ok(
                &mut runtime,
                &mut memory,
                context_object,
                slot,
                &[context_object, 0, 1, sampler_array],
            );
        }
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                10,
                &[context_object, 1, 0, 0],
            )
            .expect("PSSetSamplers non-zero start slot"),
            E_INVALIDARG
        );
        for (slot, shader) in [
            (9usize, ps),
            (11usize, vs),
            (22usize, gs),
            (27usize, hs),
            (31usize, ds),
            (69usize, cs),
        ] {
            vtable_ok(
                &mut runtime,
                &mut memory,
                context_object,
                slot,
                &[context_object, shader, 0, 0],
            );
        }
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                9,
                &[context_object, vs, 0, 0],
            )
            .expect("PSSetShader wrong stage"),
            E_INVALIDARG
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                context_object,
                22,
                &[0xdead_beef, gs, 0, 0],
            )
            .message
            .contains("context")
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            12,
            &[context_object, 3, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            13,
            &[context_object, 3, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            14,
            &[context_object],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            20,
            &[context_object, 3, 1, 0, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            21,
            &[context_object, 3, 1, 0, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                12,
                &[context_object, 3, 1, 0],
            )
            .expect("DrawIndexed non-zero start index"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                13,
                &[context_object, 3, 1],
            )
            .expect("Draw non-zero start vertex"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                20,
                &[context_object, 3, 1, 1, 0, 0],
            )
            .expect("DrawIndexedInstanced non-zero start index"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                21,
                &[context_object, 3, 1, 1, 0],
            )
            .expect("DrawInstanced non-zero start vertex"),
            E_INVALIDARG
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                context_object,
                13,
                &[0xdead_beef, 3, 0],
            )
            .message
            .contains("context")
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            15,
            &[context_object, rtv, 0, 0, 0, 0, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            16,
            &[context_object, dsv, 1, 0, 0],
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            17,
            &[context_object, layout_object],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            18,
            &[context_object, 0, 1, buffer_array, stride_ptr, offset_ptr],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                18,
                &[context_object, 1, 0, 0, stride_ptr, offset_ptr],
            )
            .expect("IASetVertexBuffers non-zero start slot"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            19,
            &[context_object, buffer_a, 42, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                19,
                &[context_object, buffer_a, 0, 0],
            )
            .expect("IASetIndexBuffer invalid format"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            24,
            &[context_object, 4],
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            33,
            &[context_object, 1, rtv_array, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                33,
                &[context_object, 1, 0, 0],
            )
            .expect("OMSetRenderTargets null array"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            35,
            &[context_object, blend, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            36,
            &[context_object, depth_state, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            43,
            &[context_object, raster, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            44,
            &[context_object, 1, viewport_ptr],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                44,
                &[context_object, 2, viewport_ptr],
            )
            .expect("RSSetViewports too many viewports"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            45,
            &[context_object, 1, scissor_ptr],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                45,
                &[context_object, 2, scissor_ptr],
            )
            .expect("RSSetScissorRects too many rects"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            41,
            &[context_object, 0, 1, uav_array],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                41,
                &[context_object, 1, 0, 0],
            )
            .expect("CSSetUnorderedAccessViews non-zero start slot"),
            E_INVALIDARG
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            47,
            &[context_object, buffer_b, 0, 0, 0, 0, buffer_a, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            48,
            &[context_object, texture_a, 0, 0, upload_ptr, 16, 0],
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                context_object,
                48,
                &[context_object, texture_a, 0, 0, 0, 16, 0],
            )
            .message
            .contains("source upload")
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            49,
            &[context_object, buffer_b, buffer_a],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            50,
            &[context_object, buffer_b, uav, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                context_object,
                57,
                &[context_object, buffer_a, color_ptr, 0],
            )
            .expect("Map"),
            0x887A_0005u64
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            58,
            &[context_object, buffer_a, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            59,
            &[context_object, srv],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            60,
            &[context_object, texture_a, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            61,
            &[context_object, texture_a, lod_out],
        );
        assert_eq!(read_guest_u32(&memory, lod_out).expect("LOD bits"), 0);
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            62,
            &[context_object, 0, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            63,
            &[context_object, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            64,
            &[context_object],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            65,
            &[context_object, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            66,
            &[context_object],
        );
        let uav_values = base + 0x1d00;
        memory.map_bytes(uav_values, &[0u8; 16]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            67,
            &[context_object, uav, uav_values],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            68,
            &[context_object, uav, uav_values],
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            51,
            &[context_object, query_object],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            52,
            &[context_object, query_object],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            53,
            &[context_object, query_object, predication_out, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            54,
            &[context_object, texture_b, 0, texture_a, 0, 28],
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                context_object,
                54,
                &[context_object, buffer_a, 0, buffer_b, 0, 28],
            )
            .message
            .contains("texture")
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            55,
            &[context_object, query_object, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            context_object,
            56,
            &[context_object, predication_out, 0],
        );
        assert_eq!(memory.read_u64(predication_out).expect("predicate"), 0);

        for (name, object) in [
            ("buffer", buffer_a),
            ("texture", texture_a),
            ("srv", srv),
            ("uav", uav),
            ("rtv", rtv),
            ("dsv", dsv),
            ("layout", layout_object),
            ("vs", vs),
            ("gs", gs),
            ("ps", ps),
            ("hs", hs),
            ("ds", ds),
            ("cs", cs),
            ("query", query_object),
        ] {
            assert_ne!(
                try_vtable_call(&mut runtime, &mut memory, object, 1, &[object])
                    .unwrap_or_else(|e| panic!("child {name} AddRef: {e}")),
                0
            );
            let released = try_vtable_call(&mut runtime, &mut memory, object, 2, &[object])
                .unwrap_or_else(|e| panic!("child {name} Release: {e}"));
            assert_ne!(released, u64::MAX);
        }
    });
}

#[test]
fn d3d11_resource_and_query_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d11-resource-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x30_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x30000]);

        let device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create d3d11 device");
        let device_object = runtime
            .alloc_d3d11_device_object(&mut memory, device)
            .expect("alloc d3d11 device");

        let buffer_desc = base + 0x1000;
        write_u32(&mut memory, buffer_desc, 64);
        let out_ptr = base + 0x1010;
        memory.map_bytes(out_ptr, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            3,
            &[device_object, buffer_desc, 0, out_ptr],
        );
        let buffer = memory.read_u64(out_ptr).expect("buffer");

        let texture_desc = base + 0x1100;
        write_u32(&mut memory, texture_desc, 2);
        write_u32(&mut memory, texture_desc + 4, 2);
        write_u32(&mut memory, texture_desc + 8, 1);
        write_u32(&mut memory, texture_desc + 12, 1);
        write_u32(&mut memory, texture_desc + 16, 28);
        write_u32(&mut memory, texture_desc + 20, 1);
        memory.map_bytes(out_ptr, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            5,
            &[device_object, texture_desc, 0, out_ptr],
        );
        let texture = memory.read_u64(out_ptr).expect("texture");

        memory.map_bytes(out_ptr, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            7,
            &[device_object, texture, 0, out_ptr],
        );
        let view = memory.read_u64(out_ptr).expect("view");

        let semantic_ptr = base + 0x1200;
        memory.map_bytes(semantic_ptr, b"POSITION\0");
        let element_ptr = base + 0x1240;
        memory.map_bytes(element_ptr, &[0u8; 32]);
        write_u64(&mut memory, element_ptr, semantic_ptr);
        write_u32(&mut memory, element_ptr + 12, 28);
        let bytecode = embedded_root_pixel_shader_dxil();
        let bytecode_ptr = base + 0x1300;
        memory.map_bytes(bytecode_ptr, &bytecode);
        let layout_out = base + 0x1280;
        memory.map_bytes(layout_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            11,
            &[
                device_object,
                element_ptr,
                1,
                bytecode_ptr,
                bytecode.len() as u64,
                layout_out,
            ],
        );
        let layout = memory.read_u64(layout_out).expect("layout");

        let shader_out = base + 0x1400;
        memory.map_bytes(shader_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            12,
            &[
                device_object,
                bytecode_ptr,
                bytecode.len() as u64,
                0,
                shader_out,
            ],
        );
        let shader = memory.read_u64(shader_out).expect("shader");

        let blend_desc = base + 0x1500;
        memory.map_bytes(blend_desc, &[0u8; 64]);
        let depth_desc = base + 0x1540;
        memory.map_bytes(depth_desc, &[0u8; 64]);
        let raster_desc = base + 0x1580;
        memory.map_bytes(raster_desc, &[0u8; 64]);
        write_u32(&mut memory, raster_desc, 3);
        write_u32(&mut memory, raster_desc + 4, 1);
        let sampler_desc = base + 0x15c0;
        memory.map_bytes(sampler_desc, &[0u8; 64]);
        write_u32(&mut memory, sampler_desc, 21);
        write_u32(&mut memory, sampler_desc + 4, 1);
        write_u32(&mut memory, sampler_desc + 8, 1);
        write_u32(&mut memory, sampler_desc + 12, 1);
        let state_out = base + 0x1600;
        let mut states = [0u64; 4];
        for (index, (slot, desc)) in [
            (20usize, blend_desc),
            (21usize, depth_desc),
            (22usize, raster_desc),
            (23usize, sampler_desc),
        ]
        .into_iter()
        .enumerate()
        {
            memory.map_bytes(state_out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device_object,
                slot,
                &[device_object, desc, state_out],
            );
            states[index] = memory.read_u64(state_out).expect("state");
        }

        let query_out = base + 0x1700;
        memory.map_bytes(query_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device_object,
            24,
            &[device_object, 0, query_out],
        );
        let query = memory.read_u64(query_out).expect("query");

        for object in [
            buffer, texture, view, layout, shader, states[0], states[1], states[2], states[3],
        ] {
            assert_ne!(
                try_vtable_call(&mut runtime, &mut memory, object, 1, &[object])
                    .expect("DeviceChild AddRef"),
                0
            );
            let released = try_vtable_call(&mut runtime, &mut memory, object, 2, &[object])
                .expect("DeviceChild Release");
            assert_ne!(released, u64::MAX);
        }

        assert!(try_vtable_call(&mut runtime, &mut memory, buffer, 0, &[buffer, 0, 0]).is_err());
        assert!(try_vtable_call(&mut runtime, &mut memory, texture, 0, &[texture, 0, 0]).is_err());
        assert!(try_vtable_call(&mut runtime, &mut memory, view, 0, &[view, 0, 0]).is_err());
        assert!(try_vtable_call(&mut runtime, &mut memory, query, 0, &[query, 0, 0]).is_err());

        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, query, 1, &[query]).expect("query AddRef"),
            0
        );
        let _ =
            try_vtable_call(&mut runtime, &mut memory, query, 2, &[query]).expect("query Release");
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, query, 3, &[query])
                .expect("query GetDevice placeholder"),
            0
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, query, 4, &[query]).expect("GetDataSize"),
            0
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, query, 5, &[query, 0, 0, 0])
                .expect("GetData"),
            1
        );
        let desc_out = base + 0x1800;
        memory.map_bytes(desc_out, &[0xAA; 8]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, query, 6, &[query, desc_out])
                .expect("GetDesc"),
            0
        );
        assert_eq!(read_guest_u32(&memory, desc_out).expect("query type"), 0);
        assert_eq!(
            read_guest_u32(&memory, desc_out + 4).expect("query misc"),
            0
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, query, 6, &[query, 0])
                .expect("GetDesc null"),
            0
        );
    });
}

#[test]
fn d3d12_device_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-device-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x40_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x60000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x1000);

        let out = base + 0x1100;
        let queue_desc = base + 0x1200;
        memory.map_bytes(queue_desc, &[0u8; 16]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            8,
            &[device, queue_desc, 0, out],
        );
        let queue = memory.read_u64(out).expect("queue");
        assert_eq!(
            runtime.guest_object_kind(queue).expect("queue kind"),
            GuestObjectKind::D3d12CommandQueue
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 8, &[device, 0, 0, out])
                .expect("CreateCommandQueue null desc"),
            E_INVALIDARG
        );

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, device, 9, &[device, 0, 0, out]);
        let allocator = memory.read_u64(out).expect("allocator");
        assert_eq!(
            runtime
                .guest_object_kind(allocator)
                .expect("allocator kind"),
            GuestObjectKind::D3d12CommandAllocator
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 9, &[device, 0, 0, 0])
                .expect("CreateCommandAllocator null out"),
            E_INVALIDARG
        );

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            12,
            &[device, 0, 0, allocator, 0, 0, out],
        );
        let list = memory.read_u64(out).expect("list");
        assert_eq!(
            runtime.guest_object_kind(list).expect("list kind"),
            GuestObjectKind::D3d12GraphicsCommandList
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                12,
                &[device, 0, 0, allocator, 1, 0, out],
            )
            .expect("CreateCommandList non-null initial state"),
            E_INVALIDARG
        );

        let feature_out = base + 0x1300;
        memory.map_bytes(feature_out, &[0u8; 64]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            13,
            &[device, 0, feature_out, 60],
        );
        assert_ne!(
            read_guest_u32(&memory, feature_out + 12).expect("binding tier"),
            0
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                13,
                &[device, 0xffff, feature_out, 60],
            )
            .expect("CheckFeatureSupport unknown feature"),
            E_INVALIDARG
        );

        let heap_desc = base + 0x1400;
        let mut heap_handles = [0u64; 4];
        for (index, (ty, count)) in [(0u32, 4u32), (1, 2), (2, 2), (3, 1)]
            .into_iter()
            .enumerate()
        {
            memory.map_bytes(heap_desc, &[0u8; 16]);
            write_u32(&mut memory, heap_desc, ty);
            write_u32(&mut memory, heap_desc + 4, count);
            memory.map_bytes(out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device,
                14,
                &[device, heap_desc, 0, out],
            );
            let heap = memory.read_u64(out).expect("heap");
            assert_eq!(
                runtime.guest_object_kind(heap).expect("heap kind"),
                GuestObjectKind::D3d12DescriptorHeap
            );
            let handle = try_vtable_call(&mut runtime, &mut memory, heap, 9, &[heap])
                .expect("GetCPUDescriptorHandleForHeapStart");
            assert_ne!(handle, 0);
            heap_handles[index] = handle;
        }
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 14, &[device, 0, 0, out])
                .expect("CreateDescriptorHeap null desc"),
            E_INVALIDARG
        );

        let resource_desc = base + 0x1500;
        memory.map_bytes(resource_desc, &[0u8; 48]);
        write_u32(&mut memory, resource_desc, 28);
        write_u32(&mut memory, resource_desc + 4, 3);
        write_u64(&mut memory, resource_desc + 8, 4);
        write_u32(&mut memory, resource_desc + 16, 4);
        write_u16(&mut memory, resource_desc + 20, 1);
        write_u16(&mut memory, resource_desc + 24, 1);
        write_u32(&mut memory, resource_desc + 28, 1);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            24,
            &[device, 0, 0, resource_desc, 0, 0, out],
        );
        let resource = memory.read_u64(out).expect("resource");
        assert_eq!(
            runtime.guest_object_kind(resource).expect("resource kind"),
            GuestObjectKind::D3d12Resource
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                24,
                &[device, 0, 0, 0, 0, 0, out],
            )
            .expect("CreateCommittedResource null desc"),
            E_INVALIDARG
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, resource, 1, &[resource])
                .expect("D3D12Resource AddRef"),
            0
        );
        let _ = try_vtable_call(&mut runtime, &mut memory, resource, 2, &[resource])
            .expect("D3D12Resource Release");
        assert!(
            try_vtable_call(&mut runtime, &mut memory, resource, 0, &[resource, 0, 0]).is_err()
        );

        let depth_resource_desc = base + 0x1f00;
        memory.map_bytes(depth_resource_desc, &[0u8; 48]);
        write_u32(&mut memory, depth_resource_desc, 45);
        write_u32(&mut memory, depth_resource_desc + 4, 3);
        write_u64(&mut memory, depth_resource_desc + 8, 4);
        write_u32(&mut memory, depth_resource_desc + 16, 4);
        write_u16(&mut memory, depth_resource_desc + 20, 1);
        write_u16(&mut memory, depth_resource_desc + 24, 1);
        write_u32(&mut memory, depth_resource_desc + 28, 1);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            24,
            &[device, 0, 0, depth_resource_desc, 0, 0, out],
        );
        let depth_resource = memory.read_u64(out).expect("depth resource");

        let vs = make_test_dxil_container(0);
        let ps = make_test_dxil_container(0);
        let vs_ptr = base + 0x1600;
        let ps_ptr = base + 0x1700;
        memory.map_bytes(vs_ptr, &vs);
        memory.map_bytes(ps_ptr, &ps);
        let pso_desc = base + 0x1800;
        memory.map_bytes(pso_desc, &[0u8; 0x80]);
        write_u64(&mut memory, pso_desc + 8, vs_ptr);
        write_u64(&mut memory, pso_desc + 16, vs.len() as u64);
        write_u64(&mut memory, pso_desc + 24, ps_ptr);
        write_u64(&mut memory, pso_desc + 32, ps.len() as u64);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            4,
            &[device, pso_desc, 0, out],
        );
        let pso = memory.read_u64(out).expect("pso");
        assert_ne!(pso, 0);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 4, &[device, 0, 0, out])
                .expect("CreateGraphicsPipelineState null desc"),
            E_INVALIDARG
        );

        let compute_desc = base + 0x1900;
        memory.map_bytes(compute_desc, &[0u8; 0x40]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            5,
            &[device, compute_desc, 0, out],
        );
        assert_ne!(memory.read_u64(out).expect("compute pso"), 0);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 5, &[device, 0, 0, out])
                .expect("CreateComputePipelineState null desc"),
            E_INVALIDARG
        );

        let root_desc = base + 0x1a00;
        memory.map_bytes(root_desc, &[0u8; 0x20]);
        for slot in [6usize, 7usize] {
            memory.map_bytes(out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device,
                slot,
                &[device, root_desc, 0, out],
            );
            assert_ne!(memory.read_u64(out).expect("root signature"), 0);
            assert_eq!(
                try_vtable_call(
                    &mut runtime,
                    &mut memory,
                    device,
                    slot,
                    &[device, 0, 0, out]
                )
                .expect("CreateRootSignature null desc"),
                E_INVALIDARG
            );
        }

        let signature_desc = base + 0x1b00;
        memory.map_bytes(signature_desc, &[0u8; 0x20]);
        let signature_arg = base + 0x1b40;
        memory.map_bytes(signature_arg, &[0u8; 0x10]);
        write_u32(&mut memory, signature_desc, 16);
        write_u32(&mut memory, signature_desc + 4, 1);
        write_u64(&mut memory, signature_desc + 8, signature_arg);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            10,
            &[device, signature_desc, 0, 0, out],
        );
        assert_eq!(
            runtime
                .guest_object_kind(memory.read_u64(out).expect("signature"))
                .expect("signature kind"),
            GuestObjectKind::D3d12CommandSignature
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                10,
                &[device, 0, 0, 0, out],
            )
            .expect("CreateCommandSignature null desc"),
            E_INVALIDARG
        );

        let stride = 0x20u64;
        let cbv_handle = heap_handles[0] + 2 * stride;
        let srv_handle = heap_handles[0];
        let uav_handle = heap_handles[0] + stride;
        let sampler_handle = heap_handles[1];
        let rtv_handle = heap_handles[2];
        let dsv_handle = heap_handles[3];
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            15,
            &[device, 0, sampler_handle],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            19,
            &[device, 0, cbv_handle],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                19,
                &[device, resource_desc, cbv_handle],
            )
            .expect("CreateConstantBufferView GPU virtual address"),
            E_NOTIMPL
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            20,
            &[device, resource, 0, rtv_handle],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            21,
            &[device, resource, 0, srv_handle],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            22,
            &[device, resource, 0, uav_handle, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            23,
            &[device, depth_resource, 0, dsv_handle],
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                device,
                20,
                &[device, resource, 0, 0xdead_beef],
            )
            .message
            .contains("descriptor")
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                device,
                20,
                &[device, 0, 0, rtv_handle],
            )
            .message
            .contains("0x0")
        );

        let dst_handles = base + 0x1c00;
        let src_handles = base + 0x1c10;
        let dst_sizes = base + 0x1c20;
        let src_sizes = base + 0x1c28;
        write_u64(&mut memory, dst_handles, cbv_handle);
        write_u64(&mut memory, src_handles, srv_handle);
        write_u32(&mut memory, dst_sizes, 1);
        write_u32(&mut memory, src_sizes, 1);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            16,
            &[
                device,
                1,
                dst_handles,
                1,
                dst_sizes,
                src_handles,
                src_sizes,
                0,
            ],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                16,
                &[device, 0, 0, 0, 0, 0, 0, 0],
            )
            .expect("CopyDescriptors empty ranges"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            17,
            &[device, 1, cbv_handle, srv_handle, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                device,
                17,
                &[device, 0, cbv_handle, srv_handle, 0],
            )
            .expect("CopyDescriptorsSimple zero count"),
            E_INVALIDARG
        );
        let increment = try_vtable_call(&mut runtime, &mut memory, device, 18, &[device, 0])
            .expect("GetDescriptorHandleIncrementSize");
        assert_ne!(increment, 0);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 18, &[device, 9])
                .expect("GetDescriptorHandleIncrementSize invalid"),
            E_INVALIDARG
        );

        vtable_ok(&mut runtime, &mut memory, device, 11, &[device, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, device, 34, &[device, 0, 0]);
        let heap_props = base + 0x1d00;
        memory.map_bytes(heap_props, &[0u8; 0x20]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            25,
            &[device, heap_props, 0, out],
        );
        assert_eq!(memory.read_u64(out).expect("heap handle"), 1);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 25, &[device, 0, 0, out])
                .expect("CreateHeap null desc"),
            E_INVALIDARG
        );
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            26,
            &[device, 1, 0, resource_desc, out],
        );
        assert_ne!(memory.read_u64(out).expect("placed"), 0);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            27,
            &[device, 0, 0, resource_desc, out],
        );
        assert_ne!(memory.read_u64(out).expect("reserved"), 0);
        vtable_ok(&mut runtime, &mut memory, device, 28, &[device, 0, 0, 0, 0]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, device, 29, &[device, 0, out]);
        assert_eq!(memory.read_u64(out).expect("shared handle"), 0);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 29, &[device, 0, 0])
                .expect("OpenSharedHandle null out"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, device, 30, &[device, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, device, 31, &[device, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, device, 32, &[device, 0, 0]);
        let query_heap_desc = base + 0x1e00;
        write_u32(&mut memory, query_heap_desc, 1);
        write_u32(&mut memory, query_heap_desc + 8, 4);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            33,
            &[device, query_heap_desc, 0, out],
        );
        assert_ne!(memory.read_u64(out).expect("query heap"), 0);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 33, &[device, 0, 0, out])
                .expect("CreateQueryHeap null desc"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, device, 35, &[device, 0, 0, 0]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            36,
            &[device, 5, 0, 0, out],
        );
        assert_eq!(
            runtime
                .guest_object_kind(memory.read_u64(out).expect("fence"))
                .expect("fence kind"),
            GuestObjectKind::D3d12Fence
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 36, &[device, 5, 0, 0, 0],)
                .expect("CreateFence null out"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, device, 37, &[device])
                .expect("GetNodeCount"),
            1
        );
        vtable_ok(&mut runtime, &mut memory, device, 3, &[device, 0]);

        for slot in [38usize, 39, 40, 41, 42, 43] {
            memory.map_bytes(out, &[0xAA; 8]);
            vtable_ok(&mut runtime, &mut memory, device, slot, &[device, 0, out]);
            assert_eq!(memory.read_u64(out).expect("versioned srv"), 0);
        }
    });
}

#[test]
fn d3d12_queue_heap_and_fence_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-queue-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x50_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x40000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x1000);

        let out = base + 0x1100;
        let queue_desc = base + 0x1200;
        memory.map_bytes(queue_desc, &[0u8; 16]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            8,
            &[device, queue_desc, 0, out],
        );
        let queue = memory.read_u64(out).expect("queue");

        let heap_desc = base + 0x1300;
        memory.map_bytes(heap_desc, &[0u8; 16]);
        write_u32(&mut memory, heap_desc, 0);
        write_u32(&mut memory, heap_desc + 4, 2);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            14,
            &[device, heap_desc, 0, out],
        );
        let heap = memory.read_u64(out).expect("heap");

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            36,
            &[device, 5, 0, 0, out],
        );
        let fence = memory.read_u64(out).expect("fence");
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, fence, 8, &[fence])
                .expect("initial GetCompletedValue"),
            5
        );

        let iid_ptr = base + 0x1400;
        let qi_out = base + 0x1410;
        let guid = base + 0x1420;
        memory.map_bytes(guid, &[0x44; 16]);
        let data_ptr = base + 0x1440;
        memory.map_bytes(data_ptr, b"queue-data");
        let name_ptr = base + 0x1460;
        for (index, unit) in "queue".encode_utf16().enumerate() {
            memory.write_u16(name_ptr + index as u64 * 2, unit);
        }
        let gpu_out = base + 0x14a0;
        let cpu_out = base + 0x14a8;
        memory.map_bytes(gpu_out, &[0u8; 8]);
        memory.map_bytes(cpu_out, &[0u8; 8]);

        memory.map_bytes(iid_ptr, &D3D12_QUEUE_IID);
        memory.map_bytes(qi_out, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                queue,
                0,
                &[queue, iid_ptr, qi_out]
            )
            .expect("queue QueryInterface"),
            0
        );
        assert_eq!(memory.read_u64(qi_out).expect("queue QI"), queue);
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                queue,
                0,
                &[queue, iid_ptr, qi_out]
            )
            .expect("queue QueryInterface unknown"),
            E_NOINTERFACE
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, queue, 1, &[queue]).expect("queue AddRef"),
            0
        );
        let _ =
            try_vtable_call(&mut runtime, &mut memory, queue, 2, &[queue]).expect("queue Release");
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, queue, 3, &[queue, guid, 0, 0])
                .expect("queue GetPrivateData"),
            0x8007_004e
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            queue,
            4,
            &[queue, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            queue,
            5,
            &[queue, guid, 4, data_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, queue, 6, &[queue, name_ptr]);
        let device_out = base + 0x1500;
        memory.map_bytes(device_out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, queue, 7, &[queue, device_out]);
        assert_eq!(memory.read_u64(device_out).expect("queue device"), device);
        let desc_out = base + 0x1510;
        memory.map_bytes(desc_out, &[0u8; 16]);
        vtable_ok(&mut runtime, &mut memory, queue, 8, &[queue, desc_out]);
        assert_eq!(read_guest_u32(&memory, desc_out).expect("queue type"), 3);
        let frequency_out = base + 0x1520;
        memory.map_bytes(frequency_out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, queue, 9, &[queue, frequency_out]);
        assert_eq!(
            memory.read_u64(frequency_out).expect("frequency"),
            1_000_000_000
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, queue, 9, &[queue, 0])
                .expect("GetTimestampFrequency null out"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            queue,
            10,
            &[queue, gpu_out, cpu_out],
        );
        assert_eq!(
            memory.read_u64(gpu_out).expect("gpu timestamp"),
            memory.read_u64(cpu_out).expect("cpu timestamp")
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, queue, 10, &[queue, gpu_out, 0])
                .expect("GetClockCalibration null out"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, queue, 11, &[queue, 0, 0]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, queue, 11, &[queue, 1, 0])
                .expect("ExecuteCommandLists null array"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, queue, 12, &[queue, fence, 1]);
        vtable_ok(&mut runtime, &mut memory, queue, 13, &[queue, fence, 1]);
        assert!(
            vtable_err(&mut runtime, &mut memory, queue, 12, &[queue, 0, 1])
                .message
                .contains("fence")
        );

        memory.map_bytes(iid_ptr, &D3D12_HEAP_IID);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, heap, 0, &[heap, iid_ptr, qi_out])
                .expect("heap QueryInterface"),
            0
        );
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, heap, 0, &[heap, iid_ptr, qi_out])
                .expect("heap QueryInterface unknown"),
            E_NOINTERFACE
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, heap, 1, &[heap]).expect("heap AddRef"),
            0
        );
        let _ = try_vtable_call(&mut runtime, &mut memory, heap, 2, &[heap]).expect("heap Release");
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, heap, 3, &[heap, guid, 0, 0])
                .expect("heap GetPrivateData"),
            0x8007_004e
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            heap,
            4,
            &[heap, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            heap,
            5,
            &[heap, guid, 4, data_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, heap, 6, &[heap, name_ptr]);
        memory.map_bytes(device_out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, heap, 7, &[heap, device_out]);
        assert_eq!(memory.read_u64(device_out).expect("heap device"), device);
        memory.map_bytes(desc_out, &[0u8; 16]);
        vtable_ok(&mut runtime, &mut memory, heap, 8, &[heap, desc_out]);
        assert_eq!(read_guest_u32(&memory, desc_out).expect("heap type"), 2);
        assert_eq!(
            read_guest_u32(&memory, desc_out + 4).expect("heap count"),
            1
        );
        let cpu_handle = try_vtable_call(&mut runtime, &mut memory, heap, 9, &[heap])
            .expect("GetCPUDescriptorHandleForHeapStart");
        assert_ne!(cpu_handle, 0);
        let gpu_handle_out = base + 0x1600;
        memory.map_bytes(gpu_handle_out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, heap, 10, &[heap, gpu_handle_out]);
        assert_eq!(
            memory.read_u64(gpu_handle_out).expect("gpu handle"),
            cpu_handle
        );

        memory.map_bytes(iid_ptr, &D3D12_FENCE_IID);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                fence,
                0,
                &[fence, iid_ptr, qi_out]
            )
            .expect("fence QueryInterface"),
            0
        );
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                fence,
                0,
                &[fence, iid_ptr, qi_out]
            )
            .expect("fence QueryInterface unknown"),
            E_NOINTERFACE
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, fence, 1, &[fence]).expect("fence AddRef"),
            0
        );
        let _ =
            try_vtable_call(&mut runtime, &mut memory, fence, 2, &[fence]).expect("fence Release");
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, fence, 3, &[fence, guid, 0, 0])
                .expect("fence GetPrivateData"),
            0x8007_004e
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            fence,
            4,
            &[fence, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            fence,
            5,
            &[fence, guid, 4, data_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, fence, 6, &[fence, name_ptr]);
        memory.map_bytes(device_out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, fence, 7, &[fence, device_out]);
        assert_eq!(memory.read_u64(device_out).expect("fence device"), device);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, fence, 8, &[fence])
                .expect("GetCompletedValue after queue signal"),
            1
        );
        vtable_ok(&mut runtime, &mut memory, fence, 9, &[fence, 0, 7]);
        vtable_ok(&mut runtime, &mut memory, fence, 10, &[fence, 7]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, fence, 8, &[fence])
                .expect("GetCompletedValue after signal"),
            7
        );
        assert!(
            vtable_err(&mut runtime, &mut memory, fence, 10, &[0xdead_beef, 1])
                .message
                .contains("fence")
        );
    });
}

#[test]
fn d3d12_graphics_command_list_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-list-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x60_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x60000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x1000);

        let out = base + 0x1100;
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, device, 9, &[device, 0, 0, out]);
        let allocator = memory.read_u64(out).expect("allocator");
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            12,
            &[device, 0, 0, allocator, 0, 0, out],
        );
        let list = memory.read_u64(out).expect("command list");

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            12,
            &[device, 0, 1, allocator, 0, 0, out],
        );
        let bundle = memory.read_u64(out).expect("bundle list");
        vtable_ok(&mut runtime, &mut memory, bundle, 9, &[bundle]);

        let heap_desc = base + 0x1200;
        memory.map_bytes(heap_desc, &[0u8; 16]);
        write_u32(&mut memory, heap_desc, 2);
        write_u32(&mut memory, heap_desc + 4, 2);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            14,
            &[device, heap_desc, 0, out],
        );
        let rtv_heap = memory.read_u64(out).expect("rtv heap");
        let rtv_handle = try_vtable_call(&mut runtime, &mut memory, rtv_heap, 9, &[rtv_heap])
            .expect("RTV handle");

        let resource_desc = base + 0x1300;
        memory.map_bytes(resource_desc, &[0u8; 48]);
        write_u32(&mut memory, resource_desc, 28);
        write_u32(&mut memory, resource_desc + 4, 3);
        write_u64(&mut memory, resource_desc + 8, 4);
        write_u32(&mut memory, resource_desc + 16, 4);
        write_u16(&mut memory, resource_desc + 20, 1);
        write_u16(&mut memory, resource_desc + 24, 1);
        write_u32(&mut memory, resource_desc + 28, 1);
        let mut resources = [0u64; 2];
        for slot in resources.iter_mut() {
            memory.map_bytes(out, &[0u8; 8]);
            vtable_ok(
                &mut runtime,
                &mut memory,
                device,
                24,
                &[device, 0, 0, resource_desc, 0, 0, out],
            );
            *slot = memory.read_u64(out).expect("resource");
        }
        let [resource_a, resource_b] = resources;
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            20,
            &[device, resource_a, 0, rtv_handle],
        );
        let rtv_array = base + 0x1400;
        write_u64(&mut memory, rtv_array, rtv_handle);
        let pso = runtime.ensure_d3d12_guest_pipeline_state() as u64;
        let query_heap_desc = base + 0x1a00;
        write_u32(&mut memory, query_heap_desc, 0);
        write_u32(&mut memory, query_heap_desc + 8, 4);
        let query_heap_out = base + 0x1a10;
        memory.map_bytes(query_heap_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            33,
            &[device, query_heap_desc, 0, query_heap_out],
        );
        let query_heap = memory.read_u64(query_heap_out).expect("query heap");

        let iid_ptr = base + 0x1600;
        let qi_out = base + 0x1610;
        let guid = base + 0x1620;
        memory.map_bytes(guid, &[0x55; 16]);
        let data_ptr = base + 0x1640;
        memory.map_bytes(data_ptr, b"list-data");
        let name_ptr = base + 0x1660;
        for (index, unit) in "list".encode_utf16().enumerate() {
            memory.write_u16(name_ptr + index as u64 * 2, unit);
        }
        let device_out = base + 0x1680;
        memory.map_bytes(device_out, &[0u8; 8]);
        let viewport_ptr = base + 0x1740;
        memory.map_bytes(viewport_ptr, &[0u8; 32]);
        let scissor_ptr = base + 0x1780;
        memory.map_bytes(scissor_ptr, &[0u8; 32]);
        let constants_ptr = base + 0x17c0;
        write_u32(&mut memory, constants_ptr, 0x3f80_0000);
        let vertex_ptr = base + 0x1800;
        memory.map_bytes(vertex_ptr, &[0u8; 24]);
        write_u64(&mut memory, vertex_ptr, resource_a);
        write_u32(&mut memory, vertex_ptr + 16, 4);
        write_u32(&mut memory, vertex_ptr + 20, 16);
        let index_ptr = base + 0x1820;
        memory.map_bytes(index_ptr, &[0u8; 24]);
        write_u64(&mut memory, index_ptr, resource_a);
        write_u32(&mut memory, index_ptr + 16, 16);
        write_u32(&mut memory, index_ptr + 20, 42);
        let values_ptr = base + 0x1840;
        let destinations_ptr = base + 0x1850;
        memory.map_bytes(values_ptr, &[0u8; 16]);
        memory.map_bytes(destinations_ptr, &[0u8; 16]);
        let predication_ptr = base + 0x1860;
        memory.map_bytes(predication_ptr, &[0u8; 8]);

        memory.map_bytes(iid_ptr, &D3D12_LIST_IID);
        memory.map_bytes(qi_out, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 0, &[list, iid_ptr, qi_out])
                .expect("list QueryInterface"),
            0
        );
        assert_eq!(memory.read_u64(qi_out).expect("list QI"), list);
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 0, &[list, iid_ptr, qi_out])
                .expect("list QueryInterface unknown"),
            E_NOINTERFACE
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, list, 1, &[list]).expect("list AddRef"),
            0
        );
        let _ = try_vtable_call(&mut runtime, &mut memory, list, 2, &[list]).expect("list Release");
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 3, &[list, guid, 0, 0])
                .expect("list GetPrivateData"),
            0x8007_004e
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            4,
            &[list, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            5,
            &[list, guid, 4, data_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, list, 6, &[list, name_ptr]);
        vtable_ok(&mut runtime, &mut memory, list, 7, &[list, device_out]);
        assert_eq!(memory.read_u64(device_out).expect("list device"), device);

        vtable_ok(&mut runtime, &mut memory, list, 12, &[list, 3, 1, 0, 0]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 12, &[list, 3, 1, 1, 0])
                .expect("DrawInstanced non-zero start vertex"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, list, 14, &[list, 1, 1, 1]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            16,
            &[list, resource_a, 0, 0, 0, 0, resource_b, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            17,
            &[list, resource_a, resource_b],
        );
        vtable_ok(&mut runtime, &mut memory, list, 20, &[list, 4]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            21,
            &[list, 1, viewport_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, list, 22, &[list, 1, scissor_ptr]);
        vtable_ok(&mut runtime, &mut memory, list, 23, &[list, pso]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 23, &[list, 0xdead_beef])
                .expect("SetPipelineState unknown"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, list, 24, &[list, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 25, &[list, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 26, &[list, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 27, &[list, bundle]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 27, &[list, list])
                .expect("ExecuteBundle non-bundle"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, list, 28, &[list, 0, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 29, &[list, 0, 0, 0]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            30,
            &[list, query_heap, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            31,
            &[list, query_heap, 0, 0],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            32,
            &[list, query_heap, 0, 0, 1, resource_a, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                list,
                32,
                &[list, query_heap, 0, 0, 1, 0, 0],
            )
            .expect("ResolveQueryData null destination"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, list, 33, &[list, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 34, &[list, 0, 0]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            35,
            &[list, 0, 1, constants_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            36,
            &[list, 0, 1, vertex_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, list, 37, &[list, index_ptr]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            38,
            &[list, 1, rtv_array, 0, 0],
        );
        vtable_ok(&mut runtime, &mut memory, list, 39, &[list, constants_ptr]);
        vtable_ok(&mut runtime, &mut memory, list, 40, &[list, 0]);

        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                list,
                47,
                &[list, 0xdead_beef, 1, 0, 0, 0, 0],
            )
            .expect("ExecuteIndirect unknown signature"),
            E_INVALIDARG
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            48,
            &[list, rtv_handle, 0, 0, 0, 0],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                list,
                48,
                &[list, rtv_handle, 0, 1, 0],
            )
            .expect("ClearRenderTargetView rects"),
            E_INVALIDARG
        );

        vtable_ok(&mut runtime, &mut memory, list, 49, &[list]);
        vtable_ok(&mut runtime, &mut memory, list, 50, &[list]);
        vtable_ok(&mut runtime, &mut memory, list, 51, &[list, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 52, &[list, 1, 1]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            list,
            53,
            &[
                list, resource_a, 0, 0, 0, 0, resource_b, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
        vtable_ok(&mut runtime, &mut memory, list, 54, &[list, 0xff]);
        vtable_ok(&mut runtime, &mut memory, list, 55, &[list, 0, 0]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 55, &[list, 1, 0])
                .expect("WriteBufferImmediate null arrays"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, list, 56, &[list, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 57, &[list, 0, 0, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 58, &[list]);
        vtable_ok(&mut runtime, &mut memory, list, 59, &[list]);
        vtable_ok(&mut runtime, &mut memory, list, 60, &[list]);
        vtable_ok(&mut runtime, &mut memory, list, 61, &[list, 0, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 62, &[list, 0, 0, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 63, &[list, 0, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 64, &[list, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 65, &[list, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 66, &[list, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 67, &[list, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 68, &[list, 1, 1, 1]);
        vtable_ok(&mut runtime, &mut memory, list, 69, &[list, 0, 0]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 69, &[list, 1, 0])
                .expect("Barrier null groups"),
            E_INVALIDARG
        );
        vtable_ok(&mut runtime, &mut memory, list, 70, &[list, 1, 2]);
        vtable_ok(&mut runtime, &mut memory, list, 71, &[list, 0, 0, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 72, &[list, 0]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 73, &[list, 0])
                .expect("SetProgram null desc"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 74, &[list, 0])
                .expect("DispatchGraph null desc"),
            E_INVALIDARG
        );

        vtable_ok(&mut runtime, &mut memory, list, 9, &[list]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, list, 9, &[list]).expect("double Close"),
            E_INVALIDARG
        );
        for slot in [
            10usize, 12, 14, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
            63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        ] {
            assert!(
                try_vtable_call(
                    &mut runtime,
                    &mut memory,
                    list,
                    slot,
                    &[list, 0, 0, 0, 0, 0]
                )
                .is_err(),
                "closed list slot {slot} must fail"
            );
        }
        vtable_ok(&mut runtime, &mut memory, list, 10, &[list, allocator, 0]);
        vtable_ok(&mut runtime, &mut memory, list, 9, &[list]);
    });
}

#[test]
fn dxgi_factory_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "dxgi-factory-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x70_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x50000]);
        let factory = runtime
            .alloc_dxgi_factory_object(&mut memory)
            .expect("factory");
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x1000);

        let out = base + 0x1100;
        let queue_desc = base + 0x1200;
        memory.map_bytes(queue_desc, &[0u8; 16]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            8,
            &[device, queue_desc, 0, out],
        );
        let queue = memory.read_u64(out).expect("queue");

        let swapchain_desc = base + 0x1300;
        memory.map_bytes(swapchain_desc, &[0u8; 64]);
        write_u32(&mut memory, swapchain_desc, 8);
        write_u32(&mut memory, swapchain_desc + 4, 8);
        write_u32(&mut memory, swapchain_desc + 16, 28);
        write_u32(&mut memory, swapchain_desc + 28, 1);
        write_u32(&mut memory, swapchain_desc + 40, 2);
        write_u64(&mut memory, swapchain_desc + 48, 0x1234);

        let desc1 = base + 0x1380;
        memory.map_bytes(desc1, &[0u8; 64]);
        write_u32(&mut memory, desc1, 8);
        write_u32(&mut memory, desc1 + 4, 8);
        write_u32(&mut memory, desc1 + 8, 28);
        write_u32(&mut memory, desc1 + 16, 1);
        write_u32(&mut memory, desc1 + 28, 2);

        let iid_ptr = base + 0x1400;
        let qi_out = base + 0x1410;
        let guid = base + 0x1420;
        memory.map_bytes(guid, &[0x66; 16]);
        let data_ptr = base + 0x1440;
        memory.map_bytes(data_ptr, b"factory-data");
        let size_ptr = base + 0x1450;
        memory.map_bytes(size_ptr, &[0u8; 4]);

        memory.map_bytes(iid_ptr, &DXGI_FACTORY_IID);
        memory.map_bytes(qi_out, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                0,
                &[factory, iid_ptr, qi_out],
            )
            .expect("factory QueryInterface"),
            0
        );
        assert_eq!(memory.read_u64(qi_out).expect("factory QI"), factory);
        memory.map_bytes(iid_ptr, &METHOD_TEST_UNKNOWN_IID);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                0,
                &[factory, iid_ptr, qi_out],
            )
            .expect("factory QueryInterface unknown"),
            E_NOINTERFACE
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, factory, 1, &[factory])
                .expect("factory AddRef"),
            0
        );
        let _ = try_vtable_call(&mut runtime, &mut memory, factory, 2, &[factory])
            .expect("factory Release");
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            3,
            &[factory, guid, 4, data_ptr],
        );
        vtable_ok(&mut runtime, &mut memory, factory, 4, &[factory, guid, 0]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                5,
                &[factory, guid, size_ptr, data_ptr],
            )
            .expect("factory GetPrivateData"),
            0x8007_004E_u64.wrapping_neg()
        );
        let parent_out = base + 0x1500;
        memory.map_bytes(parent_out, &[0u8; 8]);
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                6,
                &[factory, 0, parent_out],
            )
            .expect("factory GetParent"),
            0x8004_0154u64
        );
        assert_eq!(memory.read_u64(parent_out).expect("parent"), 0);

        let adapter_out = base + 0x1510;
        memory.map_bytes(adapter_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            7,
            &[factory, 0, adapter_out],
        );
        let adapter = memory.read_u64(adapter_out).expect("adapter");
        assert_eq!(
            runtime.guest_object_kind(adapter).expect("adapter kind"),
            GuestObjectKind::DxgiAdapter
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                7,
                &[factory, 1, adapter_out]
            )
            .expect("EnumAdapters out of range"),
            DXGI_ERROR_NOT_FOUND
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, factory, 7, &[factory, 0, 0])
                .expect("EnumAdapters null out"),
            E_INVALIDARG
        );

        vtable_ok(&mut runtime, &mut memory, factory, 8, &[factory, 0x1234, 0]);
        let hwnd_out = base + 0x1520;
        memory.map_bytes(hwnd_out, &[0u8; 8]);
        vtable_ok(&mut runtime, &mut memory, factory, 9, &[factory, hwnd_out]);
        assert_eq!(
            memory.read_u64(hwnd_out).expect("window association"),
            0x1234
        );

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            10,
            &[factory, queue, swapchain_desc, out],
        );
        assert_eq!(
            runtime
                .guest_object_kind(memory.read_u64(out).expect("swapchain"))
                .expect("swapchain kind"),
            GuestObjectKind::DxgiSwapChain
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                10,
                &[factory, queue, 0, out],
            )
            .expect("CreateSwapChain null desc"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, factory, 11, &[factory, 0, out])
                .expect("CreateSoftwareAdapter"),
            DXGI_ERROR_UNSUPPORTED
        );

        memory.map_bytes(adapter_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            12,
            &[factory, 0, adapter_out],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                12,
                &[factory, 1, adapter_out]
            )
            .expect("EnumAdapters1 out of range"),
            DXGI_ERROR_NOT_FOUND
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, factory, 13, &[factory]).expect("IsCurrent"),
            1
        );

        let cookie_out = base + 0x1530;
        memory.map_bytes(cookie_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            14,
            &[factory, 0x100, cookie_out],
        );
        let cookie = memory.read_u64(cookie_out).expect("stereo cookie");
        assert_ne!(cookie, 0);

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            15,
            &[factory, queue, 0x1234, desc1, 0, 0, out],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                15,
                &[factory, queue, 0, desc1, 0, 0, out],
            )
            .expect("CreateSwapChainForHwnd null hwnd"),
            E_INVALIDARG
        );

        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            16,
            &[factory, queue, 0x2222, desc1, 0, 0, out],
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                16,
                &[factory, queue, 0x2222, 0, 0, 0, out],
            )
            .expect("CreateSwapChainForCoreWindow null desc"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                17,
                &[factory, queue, desc1, out],
            )
            .expect("CreateSwapChainForComposition"),
            DXGI_ERROR_UNSUPPORTED
        );

        memory.map_bytes(cookie_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            18,
            &[factory, 0x101, cookie_out],
        );
        assert_ne!(memory.read_u64(cookie_out).expect("stereo event cookie"), 0);
        vtable_ok(&mut runtime, &mut memory, factory, 19, &[factory, cookie]);
        memory.map_bytes(cookie_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            20,
            &[factory, 0x102, cookie_out],
        );
        assert_ne!(memory.read_u64(cookie_out).expect("occlusion cookie"), 0);
        memory.map_bytes(cookie_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            21,
            &[factory, 0x103, cookie_out],
        );
        assert_ne!(
            memory.read_u64(cookie_out).expect("occlusion event cookie"),
            0
        );
        vtable_ok(&mut runtime, &mut memory, factory, 22, &[factory, cookie]);
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, factory, 23, &[factory])
                .expect("GetCreationFlags"),
            0
        );
        memory.map_bytes(adapter_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            24,
            &[factory, 0, 0, adapter_out],
        );
        assert_eq!(
            runtime
                .guest_object_kind(memory.read_u64(adapter_out).expect("luid adapter"))
                .expect("luid adapter kind"),
            GuestObjectKind::DxgiAdapter
        );
        assert_eq!(
            try_vtable_call(&mut runtime, &mut memory, factory, 24, &[factory, 0, 0, 0])
                .expect("EnumAdapterByLuid null out"),
            E_INVALIDARG
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                factory,
                25,
                &[factory, 0, adapter_out]
            )
            .expect("EnumWarpAdapter"),
            DXGI_ERROR_UNSUPPORTED
        );
    });
}

#[test]
fn dxgi_swapchain_methods_reject_invalid_input_and_pin_vtable_outputs() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "dxgi-swapchain-methods",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x80_0000u64;
        memory.map_bytes(base, &vec![0u8; 0x50000]);
        let factory = runtime
            .alloc_dxgi_factory_object(&mut memory)
            .expect("factory");
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x1000);

        let out = base + 0x1100;
        let queue_desc = base + 0x1200;
        memory.map_bytes(queue_desc, &[0u8; 16]);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            device,
            8,
            &[device, queue_desc, 0, out],
        );
        let queue = memory.read_u64(out).expect("queue");

        let desc1 = base + 0x1300;
        memory.map_bytes(desc1, &[0u8; 64]);
        write_u32(&mut memory, desc1, 8);
        write_u32(&mut memory, desc1 + 4, 8);
        write_u32(&mut memory, desc1 + 8, 28);
        write_u32(&mut memory, desc1 + 16, 1);
        write_u32(&mut memory, desc1 + 28, 2);
        memory.map_bytes(out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            factory,
            15,
            &[factory, queue, 0x1234, desc1, 0, 0, out],
        );
        let swapchain = memory.read_u64(out).expect("swapchain");

        let iid_ptr = base + 0x1400;
        let qi_out = base + 0x1410;
        let guid = base + 0x1420;
        memory.map_bytes(guid, &[0x77; 16]);
        let data_ptr = base + 0x1440;
        memory.map_bytes(data_ptr, b"swapchain-data");
        let name_ptr = base + 0x1460;
        for (index, unit) in "swapchain".encode_utf16().enumerate() {
            memory.write_u16(name_ptr + index as u64 * 2, unit);
        }

        memory.map_bytes(iid_ptr, &DXGI_SWAPCHAIN_IID);
        assert!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                swapchain,
                0,
                &[swapchain, iid_ptr, qi_out],
            )
            .is_err()
        );
        assert_ne!(
            try_vtable_call(&mut runtime, &mut memory, swapchain, 1, &[swapchain])
                .expect("swapchain AddRef"),
            0
        );
        let _ = try_vtable_call(&mut runtime, &mut memory, swapchain, 2, &[swapchain])
            .expect("swapchain Release");
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                swapchain,
                3,
                &[swapchain, guid, 0, 0],
            )
            .expect("swapchain GetPrivateData"),
            0x8007_004e
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            4,
            &[swapchain, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            5,
            &[swapchain, guid, 4, data_ptr],
        );
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            6,
            &[swapchain, name_ptr],
        );

        vtable_ok(&mut runtime, &mut memory, swapchain, 8, &[swapchain, 1, 0]);
        let buffer_out = base + 0x1500;
        memory.map_bytes(buffer_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            9,
            &[swapchain, 0, 0, buffer_out],
        );
        assert_eq!(
            runtime
                .guest_object_kind(memory.read_u64(buffer_out).expect("backbuffer"))
                .expect("backbuffer kind"),
            GuestObjectKind::D3d12Resource
        );
        assert_eq!(
            try_vtable_call(
                &mut runtime,
                &mut memory,
                swapchain,
                9,
                &[swapchain, 0, 0, 0],
            )
            .expect("GetBuffer null out"),
            E_INVALIDARG
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                swapchain,
                9,
                &[swapchain, 4, 0, buffer_out],
            )
            .message
            .contains("bounds")
        );

        vtable_ok(&mut runtime, &mut memory, swapchain, 10, &[swapchain, 1, 0]);
        let fullscreen_out = base + 0x1510;
        memory.map_bytes(fullscreen_out, &[0u8; 4]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            11,
            &[swapchain, fullscreen_out],
        );
        assert_eq!(
            read_guest_u32(&memory, fullscreen_out).expect("fullscreen"),
            1
        );
        let desc_out = base + 0x1520;
        memory.map_bytes(desc_out, &[0u8; 80]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            12,
            &[swapchain, desc_out],
        );
        assert_eq!(read_guest_u32(&memory, desc_out).expect("width"), 640);
        assert_eq!(read_guest_u32(&memory, desc_out + 4).expect("height"), 480);
        assert_eq!(read_guest_u32(&memory, desc_out + 8).expect("format"), 28);
        assert_eq!(
            read_guest_u32(&memory, desc_out + 52).expect("buffer count"),
            2
        );

        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            13,
            &[swapchain, 2, 8, 8, 28, 0],
        );
        let target_desc = base + 0x1600;
        write_u32(&mut memory, target_desc, 16);
        write_u32(&mut memory, target_desc + 4, 16);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            14,
            &[swapchain, target_desc],
        );
        let output_out = base + 0x1610;
        memory.map_bytes(output_out, &[0u8; 8]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            15,
            &[swapchain, output_out],
        );
        assert_eq!(memory.read_u64(output_out).expect("output"), 1);
        let stats_out = base + 0x1620;
        memory.map_bytes(stats_out, &[0u8; 32]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            16,
            &[swapchain, stats_out],
        );
        assert_eq!(
            read_guest_u32(&memory, stats_out).expect("present count"),
            1
        );
        let last_present = base + 0x1640;
        memory.map_bytes(last_present, &[0u8; 4]);
        vtable_ok(
            &mut runtime,
            &mut memory,
            swapchain,
            17,
            &[swapchain, last_present],
        );
        assert_eq!(
            read_guest_u32(&memory, last_present).expect("last present"),
            1
        );

        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                swapchain,
                8,
                &[0xdead_beef, 1, 0],
            )
            .message
            .contains("swapchain")
        );
        assert!(
            vtable_err(
                &mut runtime,
                &mut memory,
                swapchain,
                13,
                &[0xdead_beef, 2, 8, 8, 28, 0],
            )
            .message
            .contains("swapchain")
        );
    });
}
