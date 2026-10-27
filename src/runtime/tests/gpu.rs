use super::support::*;
use super::*;

#[test]
fn dxgi_adapter_desc_luid_mismatch_guard() {
    let gpu = crate::hardware_identity::host_identity().gpu.clone();
    let profile = host_gpu_profile_from_name(&gpu.name);
    let bytes = build_dxgi_adapter_desc_bytes(&profile.adapter, true, false);
    let low = u32::from_le_bytes(bytes[296..300].try_into().expect("luid low"));
    let high = u32::from_le_bytes(bytes[300..304].try_into().expect("luid high")) as i32;
    assert_eq!(low, gpu.luid_low);
    assert_eq!(high, gpu.luid_high);
}

#[test]
fn pe_runtime_d3d11_pixel_shader_thunks_translate_and_bind_dxil() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "shader-thunk", GeArch::X64, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create d3d11 device");
        let device_object = runtime
            .alloc_d3d11_device_object(&mut memory, device)
            .expect("alloc guest d3d11 device");
        let context_object = runtime
            .d3d11_device(device_object)
            .expect("device host")
            .context_object;

        let device_vtable = memory.read_u64(device_object).expect("device vtable");
        let create_pixel_shader_thunk = memory
            .read_u64(device_vtable + 15 * 8)
            .expect("CreatePixelShader thunk");
        let context_vtable = memory.read_u64(context_object).expect("context vtable");
        let ps_set_shader_thunk = memory
            .read_u64(context_vtable + 9 * 8)
            .expect("PSSetShader thunk");

        let stack_base = 0x20_000;
        memory.map_bytes(stack_base, &vec![0_u8; 0x100]);
        let bytecode_address = 0x21_000;
        let bytecode = embedded_root_pixel_shader_dxil();
        memory.map_bytes(bytecode_address, &bytecode);
        let shader_out_ptr = 0x22_000;
        memory.map_bytes(shader_out_ptr, &[0; 8]);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, bytecode_address);
        state.set(Register::R8, bytecode.len() as u64);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base, 0xDEAD_BEEF);
        memory.write_u64(stack_base + 0x28, shader_out_ptr);

        runtime
            .dispatch_import(create_pixel_shader_thunk, &mut state, &mut memory)
            .expect("dispatch CreatePixelShader");
        assert_eq!(state.get(Register::Rax), 0);
        let shader_object = memory.read_u64(shader_out_ptr).expect("read shader object");
        let guest_shader = runtime
            .d3d11_shader(shader_object)
            .expect("guest shader metadata");
        assert_eq!(guest_shader.stage, D3d11ShaderStage::Ps);

        state.set(Register::Rsp, stack_base + 0x40);
        memory.write_u64(stack_base + 0x40, 0xCAFE_BABE);
        state.set(Register::Rcx, context_object);
        state.set(Register::Rdx, shader_object);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        runtime
            .dispatch_import(ps_set_shader_thunk, &mut state, &mut memory)
            .expect("dispatch PSSetShader");
        assert_eq!(state.get(Register::Rax), 0);

        let device_host = runtime
            .d3d11_device(device_object)
            .expect("device host after bind");
        let cache_key = device_host
            .device
            .shader_translation_cache_key(guest_shader.shader_id)
            .expect("shader cache key")
            .expect("translated shader cache key");
        let submission = runtime
            .d3d11_device_mut(device_object)
            .expect("mutable device host")
            .device
            .submit_immediate()
            .expect("submit immediate with bound shader");
        assert!(submission.signature.contains(&cache_key));
        assert!(submission.signature.contains("msl_ps_"));

        state.set(Register::Rsp, stack_base + 0x80);
        memory.write_u64(stack_base + 0x80, 0xABCD_EF01);
        state.set(Register::Rcx, context_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        runtime
            .dispatch_import(ps_set_shader_thunk, &mut state, &mut memory)
            .expect("dispatch PSSetShader null clear");
        assert_eq!(state.get(Register::Rax), 0);

        let cleared_submission = runtime
            .d3d11_device_mut(device_object)
            .expect("mutable device host after clear")
            .device
            .submit_immediate()
            .expect("submit immediate after clearing shader");
        assert!(!cleared_submission.signature.contains(&cache_key));

        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D11Device::CreatePixelShader")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D11DeviceContext::PSSetShader")
        );
    })
}

#[test]
fn pe_runtime_dxgi_adapter_enumeration_exposes_vendor_compatible_descriptors() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "dxgi-adapter", GeArch::X64, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.d3d12_runtime = D3d12Runtime::from_backend(GraphicsBackend::with_host_profile(
            host_gpu_profile_from_name("NVIDIA GeForce RTX 4080"),
        ));
        let mut memory = MemoryImage::default();
        let stack_base = 0x34_000;
        let factory_out_ptr = 0x35_000;
        let adapter_out_ptr = 0x35_008;
        let desc1_ptr = 0x36_000;

        memory.map_bytes(stack_base, &vec![0_u8; 0x100]);
        memory.map_bytes(factory_out_ptr, &[0; 8]);
        memory.map_bytes(adapter_out_ptr, &[0; 8]);
        memory.map_bytes(desc1_ptr, &[0; 320]);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, factory_out_ptr);
        memory.write_u64(stack_base, 0x1111_0001);

        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory1);
        runtime
            .dispatch_import(create_factory, &mut state, &mut memory)
            .expect("dispatch CreateDXGIFactory1");
        let factory_object = memory.read_u64(factory_out_ptr).expect("factory object");

        let factory_vtable = memory.read_u64(factory_object).expect("factory vtable");
        let enum_adapters1_thunk = memory
            .read_u64(factory_vtable + 12 * 8)
            .expect("EnumAdapters1 thunk");
        state.set(Register::Rsp, stack_base + 0x20);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, adapter_out_ptr);
        memory.write_u64(stack_base + 0x20, 0x1111_0002);
        runtime
            .dispatch_import(enum_adapters1_thunk, &mut state, &mut memory)
            .expect("dispatch EnumAdapters1");
        let adapter_object = memory.read_u64(adapter_out_ptr).expect("adapter object");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            runtime
                .guest_object_kind(adapter_object)
                .expect("adapter kind"),
            GuestObjectKind::DxgiAdapter
        );

        let adapter_vtable = memory.read_u64(adapter_object).expect("adapter vtable");
        let get_desc1_thunk = memory
            .read_u64(adapter_vtable + 10 * 8)
            .expect("GetDesc1 thunk");
        state.set(Register::Rsp, stack_base + 0x40);
        state.set(Register::Rcx, adapter_object);
        state.set(Register::Rdx, desc1_ptr);
        memory.write_u64(stack_base + 0x40, 0x1111_0003);
        runtime
            .dispatch_import(get_desc1_thunk, &mut state, &mut memory)
            .expect("dispatch GetDesc1");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            read_guest_u32(&memory, desc1_ptr + 256).expect("vendor id"),
            0x10de
        );
        assert_eq!(
            read_guest_u32(&memory, desc1_ptr + 260).expect("device id"),
            0x2008
        );
        assert_eq!(read_guest_u32(&memory, desc1_ptr + 304).expect("flags"), 0);
        assert_eq!(
            read_guest_utf16_string(&memory, desc1_ptr, DXGI_ADAPTER_DESC_DESCRIPTION_CHARS),
            "NVIDIA GeForce RTX 4080"
        );

        state.set(Register::Rsp, stack_base + 0x60);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, adapter_out_ptr);
        memory.write_u64(stack_base + 0x60, 0x1111_0004);
        runtime
            .dispatch_import(enum_adapters1_thunk, &mut state, &mut memory)
            .expect("dispatch EnumAdapters1 miss");
        assert_eq!(state.get(Register::Rax), DXGI_ERROR_NOT_FOUND);

        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "IDXGIFactory1::EnumAdapters1")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "IDXGIAdapter1::GetDesc1")
        );
    })
}

#[test]
fn pe_runtime_d3d12_swapchain_and_command_list_thunks_submit_and_present() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-swapchain",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();

        let stack_base = 0x40_000;
        let factory_out_ptr = 0x41_000;
        let device_out_ptr = 0x41_008;
        let queue_out_ptr = 0x41_010;
        let swapchain_out_ptr = 0x41_018;
        let backbuffer_out_ptr = 0x41_020;
        let allocator_out_ptr = 0x41_028;
        let command_list_out_ptr = 0x41_030;
        let command_list_array_ptr = 0x41_038;
        let descriptor_heap_out_ptr = 0x41_040;
        let queue_desc_ptr = 0x42_000;
        let swapchain_desc1_ptr = 0x42_100;
        let descriptor_heap_desc_ptr = 0x42_140;
        let first_barrier_ptr = 0x42_180;
        let second_barrier_ptr = 0x42_1a0;

        memory.map_bytes(stack_base, &vec![0_u8; 0x280]);
        memory.map_bytes(factory_out_ptr, &[0; 8]);
        memory.map_bytes(device_out_ptr, &[0; 8]);
        memory.map_bytes(queue_out_ptr, &[0; 8]);
        memory.map_bytes(swapchain_out_ptr, &[0; 8]);
        memory.map_bytes(backbuffer_out_ptr, &[0; 8]);
        memory.map_bytes(allocator_out_ptr, &[0; 8]);
        memory.map_bytes(command_list_out_ptr, &[0; 8]);
        memory.map_bytes(command_list_array_ptr, &[0; 8]);
        memory.map_bytes(descriptor_heap_out_ptr, &[0; 8]);
        memory.map_bytes(queue_desc_ptr, &[0; 16]);
        memory.map_bytes(swapchain_desc1_ptr, &[0; 64]);
        memory.map_bytes(descriptor_heap_desc_ptr, &[0; 16]);
        memory.map_bytes(first_barrier_ptr, &[0; 32]);
        memory.map_bytes(second_barrier_ptr, &[0; 32]);

        write_u32(&mut memory, swapchain_desc1_ptr, 2);
        write_u32(&mut memory, swapchain_desc1_ptr + 4, 2);
        write_u32(&mut memory, swapchain_desc1_ptr + 8, 28);
        write_u32(&mut memory, swapchain_desc1_ptr + 16, 1);
        write_u32(&mut memory, swapchain_desc1_ptr + 20, 0);
        write_u32(&mut memory, swapchain_desc1_ptr + 28, 2);

        write_u32(&mut memory, descriptor_heap_desc_ptr, 2);
        write_u32(&mut memory, descriptor_heap_desc_ptr + 4, 1);
        write_u32(&mut memory, descriptor_heap_desc_ptr + 8, 0);
        write_u32(&mut memory, descriptor_heap_desc_ptr + 12, 0);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, factory_out_ptr);
        memory.write_u64(stack_base, 0x1000_0001);

        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory1);
        runtime
            .dispatch_import(create_factory, &mut state, &mut memory)
            .expect("dispatch CreateDXGIFactory1");
        let factory_object = memory.read_u64(factory_out_ptr).expect("factory object");

        state.set(Register::Rsp, stack_base + 0x20);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, device_out_ptr);
        memory.write_u64(stack_base + 0x20, 0x1000_0002);

        let create_device = runtime.alloc_host_thunk(HostThunk::D3D12CreateDevice);
        runtime
            .dispatch_import(create_device, &mut state, &mut memory)
            .expect("dispatch D3D12CreateDevice");
        let device_object = memory.read_u64(device_out_ptr).expect("device object");

        let device_vtable = memory.read_u64(device_object).expect("device vtable");
        let create_queue_thunk = memory
            .read_u64(device_vtable + 8 * 8)
            .expect("CreateCommandQueue thunk");
        let create_allocator_thunk = memory
            .read_u64(device_vtable + 9 * 8)
            .expect("CreateCommandAllocator thunk");
        let create_command_list_thunk = memory
            .read_u64(device_vtable + 12 * 8)
            .expect("CreateCommandList thunk");
        let create_descriptor_heap_thunk = memory
            .read_u64(device_vtable + 14 * 8)
            .expect("CreateDescriptorHeap thunk");
        let create_rtv_thunk = memory
            .read_u64(device_vtable + 20 * 8)
            .expect("CreateRenderTargetView thunk");

        state.set(Register::Rsp, stack_base + 0x40);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, queue_desc_ptr);
        state.set(Register::R8, 0);
        state.set(Register::R9, queue_out_ptr);
        memory.write_u64(stack_base + 0x40, 0x1000_0003);
        runtime
            .dispatch_import(create_queue_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandQueue");
        let queue_object = memory.read_u64(queue_out_ptr).expect("queue object");

        let factory_vtable = memory.read_u64(factory_object).expect("factory vtable");
        let create_swapchain_for_hwnd_thunk = memory
            .read_u64(factory_vtable + 15 * 8)
            .expect("CreateSwapChainForHwnd thunk");
        state.set(Register::Rsp, stack_base + 0x60);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, queue_object);
        state.set(Register::R8, 0x1234);
        state.set(Register::R9, swapchain_desc1_ptr);
        memory.write_u64(stack_base + 0x60, 0x1000_0004);
        memory.write_u64(stack_base + 0x60 + 0x28, 0);
        memory.write_u64(stack_base + 0x60 + 0x30, 0);
        memory.write_u64(stack_base + 0x60 + 0x38, swapchain_out_ptr);
        runtime
            .dispatch_import(create_swapchain_for_hwnd_thunk, &mut state, &mut memory)
            .expect("dispatch CreateSwapChainForHwnd");
        let swapchain_object = memory
            .read_u64(swapchain_out_ptr)
            .expect("swapchain object");
        assert_eq!(
            runtime
                .guest_object_kind(swapchain_object)
                .expect("swapchain kind"),
            GuestObjectKind::DxgiSwapChain
        );

        let swapchain_vtable = memory.read_u64(swapchain_object).expect("swapchain vtable");
        let resize_buffers_thunk = memory
            .read_u64(swapchain_vtable + 13 * 8)
            .expect("ResizeBuffers thunk");
        state.set(Register::Rsp, stack_base + 0x78);
        state.set(Register::Rcx, swapchain_object);
        state.set(Register::Rdx, 2);
        state.set(Register::R8, 4);
        state.set(Register::R9, 4);
        memory.write_u64(stack_base + 0x78, 0x1000_0045);
        write_u32(&mut memory, stack_base + 0x78 + 0x28, 28);
        write_u32(&mut memory, stack_base + 0x78 + 0x30, 0);
        runtime
            .dispatch_import(resize_buffers_thunk, &mut state, &mut memory)
            .expect("dispatch ResizeBuffers");
        assert_eq!(state.get(Register::Rax), 0);

        state.set(Register::Rsp, stack_base + 0x80);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, descriptor_heap_desc_ptr);
        state.set(Register::R8, 0);
        state.set(Register::R9, descriptor_heap_out_ptr);
        memory.write_u64(stack_base + 0x80, 0x1000_0005);
        runtime
            .dispatch_import(create_descriptor_heap_thunk, &mut state, &mut memory)
            .expect("dispatch CreateDescriptorHeap");
        let descriptor_heap_object = memory
            .read_u64(descriptor_heap_out_ptr)
            .expect("descriptor heap object");
        assert_eq!(
            runtime
                .guest_object_kind(descriptor_heap_object)
                .expect("descriptor heap kind"),
            GuestObjectKind::D3d12DescriptorHeap
        );
        let descriptor_heap_vtable = memory
            .read_u64(descriptor_heap_object)
            .expect("descriptor heap vtable");
        let get_cpu_handle_thunk = memory
            .read_u64(descriptor_heap_vtable + 9 * 8)
            .expect("GetCPUDescriptorHandleForHeapStart thunk");
        state.set(Register::Rsp, stack_base + 0x98);
        state.set(Register::Rcx, descriptor_heap_object);
        memory.write_u64(stack_base + 0x98, 0x1000_0006);
        runtime
            .dispatch_import(get_cpu_handle_thunk, &mut state, &mut memory)
            .expect("dispatch GetCPUDescriptorHandleForHeapStart");
        let rtv_handle = state.get(Register::Rax);

        let get_buffer_thunk = memory
            .read_u64(swapchain_vtable + 9 * 8)
            .expect("GetBuffer thunk");
        state.set(Register::Rsp, stack_base + 0xB0);
        state.set(Register::Rcx, swapchain_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, backbuffer_out_ptr);
        memory.write_u64(stack_base + 0xB0, 0x1000_0007);
        runtime
            .dispatch_import(get_buffer_thunk, &mut state, &mut memory)
            .expect("dispatch GetBuffer");
        let backbuffer_object = memory
            .read_u64(backbuffer_out_ptr)
            .expect("backbuffer object");
        assert_eq!(
            runtime
                .guest_object_kind(backbuffer_object)
                .expect("backbuffer kind"),
            GuestObjectKind::D3d12Resource
        );

        state.set(Register::Rsp, stack_base + 0xC8);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, backbuffer_object);
        state.set(Register::R8, 0);
        state.set(Register::R9, rtv_handle);
        memory.write_u64(stack_base + 0xC8, 0x1000_0008);
        runtime
            .dispatch_import(create_rtv_thunk, &mut state, &mut memory)
            .expect("dispatch CreateRenderTargetView");

        state.set(Register::Rsp, stack_base + 0xE0);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, allocator_out_ptr);
        memory.write_u64(stack_base + 0xE0, 0x1000_0009);
        runtime
            .dispatch_import(create_allocator_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandAllocator");
        let allocator_object = memory
            .read_u64(allocator_out_ptr)
            .expect("allocator object");
        assert_eq!(
            runtime
                .guest_object_kind(allocator_object)
                .expect("allocator kind"),
            GuestObjectKind::D3d12CommandAllocator
        );

        state.set(Register::Rsp, stack_base + 0x100);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, allocator_object);
        memory.write_u64(stack_base + 0x100, 0x1000_000a);
        memory.write_u64(stack_base + 0x100 + 0x28, 0);
        memory.write_u64(stack_base + 0x100 + 0x38, command_list_out_ptr);
        runtime
            .dispatch_import(create_command_list_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandList");
        let command_list_object = memory
            .read_u64(command_list_out_ptr)
            .expect("command list object");
        assert_eq!(
            runtime
                .guest_object_kind(command_list_object)
                .expect("command list kind"),
            GuestObjectKind::D3d12GraphicsCommandList
        );

        let command_list_vtable = memory
            .read_u64(command_list_object)
            .expect("command list vtable");
        let resource_barrier_thunk = memory
            .read_u64(command_list_vtable + 26 * 8)
            .expect("ResourceBarrier thunk");
        let clear_rtv_thunk = memory
            .read_u64(command_list_vtable + 48 * 8)
            .expect("ClearRenderTargetView thunk");
        let draw_instanced_thunk = memory
            .read_u64(command_list_vtable + 12 * 8)
            .expect("DrawInstanced thunk");
        let close_thunk = memory
            .read_u64(command_list_vtable + 9 * 8)
            .expect("Close thunk");

        write_u32(&mut memory, first_barrier_ptr, 0);
        memory.write_u64(first_barrier_ptr + 8, backbuffer_object);
        write_u32(&mut memory, first_barrier_ptr + 16, 0);
        write_u32(&mut memory, first_barrier_ptr + 20, 0);
        write_u32(&mut memory, first_barrier_ptr + 24, 0x4);
        state.set(Register::Rsp, stack_base + 0x120);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, first_barrier_ptr);
        memory.write_u64(stack_base + 0x120, 0x1000_000b);
        runtime
            .dispatch_import(resource_barrier_thunk, &mut state, &mut memory)
            .expect("dispatch ResourceBarrier to render target");

        state.set(Register::Rsp, stack_base + 0x138);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, rtv_handle);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base + 0x138, 0x1000_000c);
        runtime
            .dispatch_import(clear_rtv_thunk, &mut state, &mut memory)
            .expect("dispatch ClearRenderTargetView");

        state.set(Register::Rsp, stack_base + 0x150);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, 3);
        state.set(Register::R8, 2);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base + 0x150, 0x1000_000d);
        write_u32(&mut memory, stack_base + 0x150 + 0x28, 0);
        runtime
            .dispatch_import(draw_instanced_thunk, &mut state, &mut memory)
            .expect("dispatch DrawInstanced");

        write_u32(&mut memory, second_barrier_ptr, 0);
        memory.write_u64(second_barrier_ptr + 8, backbuffer_object);
        write_u32(&mut memory, second_barrier_ptr + 16, 0);
        write_u32(&mut memory, second_barrier_ptr + 20, 0x4);
        write_u32(&mut memory, second_barrier_ptr + 24, 0);
        state.set(Register::Rsp, stack_base + 0x168);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, second_barrier_ptr);
        memory.write_u64(stack_base + 0x168, 0x1000_000e);
        runtime
            .dispatch_import(resource_barrier_thunk, &mut state, &mut memory)
            .expect("dispatch ResourceBarrier to present");

        state.set(Register::Rsp, stack_base + 0x180);
        state.set(Register::Rcx, command_list_object);
        memory.write_u64(stack_base + 0x180, 0x1000_000f);
        runtime
            .dispatch_import(close_thunk, &mut state, &mut memory)
            .expect("dispatch Close");
        assert_eq!(state.get(Register::Rax), 0);

        let queue_vtable = memory.read_u64(queue_object).expect("queue vtable");
        // ExecuteCommandLists is slot 11 of the true ID3D12CommandQueue
        // order (the ID3D12Object private-data/name methods 3-6,
        // GetDevice 7, GetDesc 8, GetTimestampFrequency 9,
        // GetClockCalibration 10, ExecuteCommandLists 11, Signal 12,
        // Wait 13).
        let execute_thunk = memory
            .read_u64(queue_vtable + 11 * 8)
            .expect("ExecuteCommandLists thunk");
        memory.write_u64(command_list_array_ptr, command_list_object);
        state.set(Register::Rsp, stack_base + 0x198);
        state.set(Register::Rcx, queue_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, command_list_array_ptr);
        memory.write_u64(stack_base + 0x198, 0x1000_0010);
        runtime
            .dispatch_import(execute_thunk, &mut state, &mut memory)
            .expect("dispatch ExecuteCommandLists");
        assert_eq!(state.get(Register::Rax), 0);

        let present_thunk = memory
            .read_u64(swapchain_vtable + 8 * 8)
            .expect("Present thunk");
        state.set(Register::Rsp, stack_base + 0x1b0);
        state.set(Register::Rcx, swapchain_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, 0);
        memory.write_u64(stack_base + 0x1b0, 0x1000_0011);
        runtime
            .dispatch_import(present_thunk, &mut state, &mut memory)
            .expect("dispatch Present");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.gfx_frames.len(), 1);
        assert_eq!(runtime.gfx_frames[0].scene_id, "pe-runtime-d3d12");

        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "IDXGIFactory2::CreateSwapChainForHwnd")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "IDXGISwapChain::ResizeBuffers")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "IDXGISwapChain::GetBuffer")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12Device::CreateDescriptorHeap")
        );
        assert!(runtime.trace_events.iter().any(
            |event| event.call_id == "ID3D12DescriptorHeap::GetCPUDescriptorHandleForHeapStart"
        ));
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12Device::CreateRenderTargetView")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12Device::CreateCommandAllocator")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12Device::CreateCommandList")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12GraphicsCommandList::ResourceBarrier")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12GraphicsCommandList::ClearRenderTargetView")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12GraphicsCommandList::DrawInstanced")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12GraphicsCommandList::Close")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "ID3D12CommandQueue::ExecuteCommandLists")
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| event.call_id == "IDXGISwapChain::Present")
        );
    })
}

// -----------------------------------------------------------------------
// Item 111: Tests for PE import resolution, delay-load, forwarded exports,
// and missing DLL behavior
// -----------------------------------------------------------------------
#[test]
fn test_pe_import_resolution_d3d11() {
    with_big_stack(|| {
        let dll = "d3d11.dll";
        let symbol = ImportSymbol::ByName {
            hint: 0,
            name: "D3D11CreateDevice".to_string(),
        };
        let import = crate::pe::ResolvedImport {
            requested_module: dll.to_string(),
            resolved_module: dll.to_string(),
            symbol,
            iat_rva: 0x3000,
            export: ExportSymbol {
                ordinal: 1,
                name: Some("D3D11CreateDevice".to_string()),
                target: ExportTarget::Rva(0x3000),
            },
        };
        let thunk = HostThunk::from_import(&import);
        assert!(matches!(thunk, HostThunk::D3D11CreateDevice));
    })
}

#[test]
fn live_pipeline_reports_zero_real_frames_before_guest_paint() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "live-real-frames",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let (host_session, live_session) = crate::live::new_live_session();
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), Some(live_session), None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // A fresh runtime has never seen a real guest frame of any kind.
        assert_eq!(runtime.real_guest_frames, 0);
        assert!(runtime.last_real_gdi_frame.is_none());
        assert!(!runtime.first_real_guest_frame_seen);
        // Nothing may have been sent on the live channel yet.
        assert!(host_session.frame_rx.try_recv().is_err());

        // Synthetic paths must not count: no real window surfaces exist, so
        // the preview publisher sends nothing and leaves no cached frame.
        runtime.publish_live_window_preview_if_needed();
        assert_eq!(runtime.real_guest_frames, 0);
        assert!(runtime.last_real_gdi_frame.is_none());
        assert!(!runtime.first_real_guest_frame_seen);
        assert!(host_session.frame_rx.try_recv().is_err());

        // Real GDI extraction (memory-DC conversion) is real GDI pixels but
        // NOT a guest present: it caches a frame without counting one.
        runtime.dc_selected_objects.insert(0x100, 0x200);
        runtime.gdi_bitmaps.insert(
            0x200,
            MemoryBitmap {
                width: 2,
                height: 1,
                bpp: 4,
                bytes: vec![0x11, 0x22, 0x33, 0xff, 0x44, 0x55, 0x66, 0xff],
                guest_pixel_ptr: 0,
            },
        );
        let gathered = runtime.gather_dc_pixels(&mut memory, 0x100);
        assert!(
            gathered.is_some(),
            "real memory-DC pixels must be extractable"
        );
        let (w, h, pixels) = gathered.unwrap();
        assert_eq!((w, h), (2, 1));
        assert_eq!(&pixels[..4], &[0x11, 0x22, 0x33, 0xff]);
        assert!(runtime.last_real_gdi_frame.is_some());
        assert_eq!(runtime.real_guest_frames, 0, "GDI pixels are not presents");
        assert!(!runtime.first_real_guest_frame_seen);
        assert!(host_session.frame_rx.try_recv().is_err());

        // A real D3D11 guest present counts as a real guest frame and flips
        // the first-frame flag; the live channel receives the presented frame.
        let device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create d3d11 device and swapchain");
        runtime.d3d11_devices.insert(
            0x1000,
            GuestD3d11Device {
                device,
                context_object: 0,
                swapchain_object: Some(0x2000),
                backbuffer_objects: BTreeMap::new(),
            },
        );
        runtime.d3d11_swapchains.insert(
            0x2000,
            GuestDxgiSwapChain {
                device_object: 0x1000,
            },
        );
        let mut state = CpuState::new(GuestArch::X64);
        runtime
            .dispatch_d3d11_swapchain_present(1, false, 0x2000, &mut state)
            .expect("d3d11 present");

        assert_eq!(runtime.real_guest_frames, 1);
        assert!(runtime.first_real_guest_frame_seen);
        let live_frame = host_session
            .frame_rx
            .try_recv()
            .expect("a real present must publish a live frame");
        assert_eq!(live_frame.width, 2);
        assert_eq!(live_frame.height, 1);
    })
}

#[test]
fn builtin_chrome_never_publishes_until_a_real_guest_blit_lands() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "f1-builtin-provenance",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let (host_session, live_session) = crate::live::new_live_session();
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), Some(live_session), None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // Drive the guest through the builtin-control path: a BUTTON window
        // receives WM_PAINT, which paints host-invented chrome into the
        // window surface.
        let hwnd = create_probe_window(&mut runtime, "BUTTON", "OK", 120, 30);
        runtime
            .dispatch_builtin_window_message(hwnd, 0x000f, 0, 0)
            .expect("builtin paint");
        let surface = runtime
            .window_surfaces
            .get(&hwnd)
            .expect("builtin chrome surface must exist for guest-visible behavior");
        assert!(
            !surface.real_pixels,
            "host-invented chrome must never carry real-pixel provenance"
        );
        assert!(surface.bytes.iter().any(|byte| *byte != 0));

        // The publish path must refuse to publish: no REAL surface exists.
        runtime.publish_live_window_preview_if_needed();
        assert!(
            runtime.last_real_gdi_frame.is_none(),
            "synthetic chrome must never be cached as a real GDI frame"
        );
        assert_eq!(runtime.real_guest_frames, 0);
        assert!(host_session.frame_rx.try_recv().is_err());

        // Now a REAL guest blit (memory DC → window DC) lands guest pixels.
        runtime.device_contexts.insert(0x100, Some(hwnd));
        runtime.device_contexts.insert(0x200, None);
        runtime.dc_selected_objects.insert(0x200, 0x300);
        runtime.gdi_bitmaps.insert(
            0x300,
            MemoryBitmap {
                width: 120,
                height: 30,
                bpp: 4,
                bytes: [0x11, 0x22, 0x33, 0xff].repeat(120 * 30),
                guest_pixel_ptr: 0,
            },
        );
        runtime.blit_dc_to_dc(
            &mut memory,
            0x100,
            0,
            0,
            120,
            30,
            0x200,
            0,
            0,
            120,
            30,
            0x00CC0020,
        );
        let surface = runtime
            .window_surfaces
            .get(&hwnd)
            .expect("window surface after blit");
        assert!(
            surface.real_pixels,
            "a real guest blit must mark the surface as real"
        );
        assert!(
            runtime.last_real_gdi_frame.is_some(),
            "a real guest blit must cache the real GDI frame"
        );
        // Rate limit is 33 ms from the previous publish timestamp; the
        // publish timestamp is only advanced by actual publishes, so wait
        // out the window before the first real publish.
        std::thread::sleep(std::time::Duration::from_millis(35));
        runtime.publish_live_window_preview_if_needed();
        let live_frame = host_session
            .frame_rx
            .try_recv()
            .expect("a real guest blit must publish a live frame");
        assert!(live_frame.width > 0 && live_frame.height > 0);
    })
}

#[test]
fn blit_from_surfaceless_window_dc_publishes_nothing() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "f4-no-surface-blit",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let (host_session, live_session) = crate::live::new_live_session();
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), Some(live_session), None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // Two window DCs; neither window has ever received real pixels.
        let hwnd_src = create_probe_window(&mut runtime, "STATIC", "src", 64, 16);
        let hwnd_dest = create_probe_window(&mut runtime, "STATIC", "dest", 64, 16);
        runtime.device_contexts.insert(0x100, Some(hwnd_dest));
        runtime.device_contexts.insert(0x200, Some(hwnd_src));

        // Gathering pixels from a window DC with no surface must return
        // None instead of a fabricated blank buffer.
        let gathered = runtime.gather_dc_pixels(&mut memory, 0x200);
        assert!(
            gathered.is_none(),
            "a window DC without a real surface must yield no pixels"
        );
        assert!(
            runtime.last_real_gdi_frame.is_none(),
            "no-surface readback must not cache a real GDI frame"
        );

        // A guest blit whose source has no real surface must be a no-op for
        // the live pipeline: nothing cached, nothing published.
        runtime.blit_dc_to_dc(
            &mut memory,
            0x100,
            0,
            0,
            64,
            16,
            0x200,
            0,
            0,
            64,
            16,
            0x00CC0020,
        );
        assert!(
            runtime.last_real_gdi_frame.is_none(),
            "blit from a surfaceless window DC must not cache a frame"
        );
        assert_eq!(runtime.real_guest_frames, 0);
        assert!(host_session.frame_rx.try_recv().is_err());

        // Builtin chrome alone still does not count: paint the source window
        // synthetically and repeat the blit.
        runtime
            .dispatch_builtin_window_message(hwnd_src, 0x000f, 0, 0)
            .expect("builtin paint");
        runtime.blit_dc_to_dc(
            &mut memory,
            0x100,
            0,
            0,
            64,
            16,
            0x200,
            0,
            0,
            64,
            16,
            0x00CC0020,
        );
        assert!(
            runtime.last_real_gdi_frame.is_none(),
            "blit of synthetic chrome must not be cached as real"
        );
        assert!(host_session.frame_rx.try_recv().is_err());
    })
}

// -----------------------------------------------------------------------
// Item F3: D3D9 present provenance.  The fixed-function placeholder
// rasterizer and the blank present fallback are host-synthesized; they
// must never increment `real_guest_frames` or publish to the live
// channel.  Only a render target holding real guest pixels may.
// -----------------------------------------------------------------------
#[test]
fn d3d9_synthesized_presents_never_count_or_publish() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "f3-d3d9-provenance",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let (host_session, live_session) = crate::live::new_live_session();
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), Some(live_session), None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // Set up the D3D9 shim + device exactly as D3d9FactoryCreateDevice
        // would leave them.
        let mut shim = crate::d3d11::direct3d_create9();
        let device = shim.create_device().expect("create d3d9 device");
        let (swapchain_width, swapchain_height) = (device.swapchain_width, device.swapchain_height);
        runtime.d3d9_shim = Some(shim);
        runtime.d3d9_devices.insert(0x1000, device);

        let present_thunk = runtime.alloc_host_thunk(HostThunk::D3d9DevicePresent);
        let mut present_state = CpuState::new(GuestArch::X86);
        present_state.set(Register::Rcx, 0x1000);
        runtime
            .dispatch_import(present_thunk, &mut present_state, &mut memory)
            .expect("dispatch blank-fallback present");
        // Blank fallback: no render target at all — host-fabricated pixels.
        assert_eq!(runtime.real_guest_frames, 0);
        assert!(!runtime.first_real_guest_frame_seen);
        assert!(host_session.frame_rx.try_recv().is_err());

        // A guest DrawPrimitive routes through the fixed-function placeholder
        // rasterizer (host-synthesized pixels) into the render target.
        let draw_thunk = runtime.alloc_host_thunk(HostThunk::D3d9DeviceDrawPrimitive);
        let mut draw_state = CpuState::new(GuestArch::X86);
        draw_state.set(Register::Rcx, 0x1000);
        draw_state.set(Register::Rdx, 4); // D3DPT_TRIANGLELIST
        draw_state.set(Register::R8, 0);
        draw_state.set(Register::R9, 3);
        runtime
            .dispatch_import(draw_thunk, &mut draw_state, &mut memory)
            .expect("dispatch DrawPrimitive");
        assert!(
            runtime
                .d3d9_shim
                .as_ref()
                .expect("shim")
                .render_target
                .as_ref()
                .expect("render target")
                .synthesized,
            "fixed-function rasterizer output must be marked synthesized"
        );

        // Presenting that synthesized render target must NOT count as a real
        // guest frame and must NOT publish to the live channel.
        let mut present_state = CpuState::new(GuestArch::X86);
        present_state.set(Register::Rcx, 0x1000);
        runtime
            .dispatch_import(present_thunk, &mut present_state, &mut memory)
            .expect("dispatch synthesized present");
        assert_eq!(
            runtime.real_guest_frames, 0,
            "a synthesized D3D9 present must not count as a real guest frame"
        );
        assert!(!runtime.first_real_guest_frame_seen);
        assert!(host_session.frame_rx.try_recv().is_err());

        // A render target holding REAL guest pixels (e.g. a guest-driven
        // Clear color) counts and publishes.
        runtime.d3d9_shim.as_mut().expect("shim").render_target =
            Some(crate::d3d11::D3d9RenderTarget {
                width: swapchain_width,
                height: swapchain_height,
                pixels: vec![0x11; (swapchain_width as usize) * (swapchain_height as usize) * 4],
                synthesized: false,
            });
        let mut real_state = CpuState::new(GuestArch::X86);
        real_state.set(Register::Rcx, 0x1000);
        runtime
            .dispatch_import(present_thunk, &mut real_state, &mut memory)
            .expect("dispatch real present");
        assert_eq!(
            runtime.real_guest_frames, 1,
            "a real D3D9 present must count exactly once"
        );
        assert!(runtime.first_real_guest_frame_seen);
        let live_frame = host_session
            .frame_rx
            .try_recv()
            .expect("a real D3D9 present must publish a live frame");
        assert_eq!(live_frame.width, swapchain_width);
        assert_eq!(live_frame.height, swapchain_height);
    })
}

#[test]
fn d3d9_direct3d_create9_and_create9_ex_dispatch() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("d3d9-create");
        let mut memory = MemoryImage::default();
        let create9 = runtime.alloc_host_thunk(HostThunk::Direct3DCreate9);
        let create9ex = runtime.alloc_host_thunk(HostThunk::Direct3DCreate9Ex);

        // Direct3DCreate9 returns an IDirect3D9 factory object pointer.
        let factory =
            dispatch_x86_thunk_regs(&mut runtime, &mut memory, create9, &[(Register::Rcx, 32)]);
        assert_ne!(factory, 0, "Direct3DCreate9 returns a factory object");
        assert_eq!(
            runtime.guest_object_kind(factory).expect("factory kind"),
            GuestObjectKind::D3d9Factory
        );

        // Direct3DCreate9Ex writes the factory pointer into the out slot.
        let out_ptr = 0x41_000;
        memory.map_bytes(out_ptr as u64, &[0; 8]);
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create9ex,
            &[(Register::Rcx, 32), (Register::Rdx, out_ptr as u64)],
        );
        assert_eq!(result, 0, "Direct3DCreate9Ex returns D3D_OK");
        let factory_ex = memory.read_u64(out_ptr as u64).expect("factory ex");
        assert_eq!(
            runtime
                .guest_object_kind(factory_ex)
                .expect("factory ex kind"),
            GuestObjectKind::D3d9Factory
        );

        // A NULL out pointer returns E_INVALIDARG.
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create9ex,
            &[(Register::Rcx, 32), (Register::Rdx, 0)],
        );
        assert_eq!(result, 0x8007_0057);
    })
}

#[test]
fn dxgi_create_factory2_writes_a_managed_factory_object() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("dxgi-factory2");
        runtime.d3d12_runtime = D3d12Runtime::from_backend(GraphicsBackend::with_host_profile(
            host_gpu_profile_from_name("NVIDIA GeForce RTX 4080"),
        ));
        let mut memory = MemoryImage::default();
        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory2);
        let out_ptr = 0x41_000;
        memory.map_bytes(out_ptr as u64, &[0; 8]);

        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create_factory,
            &[
                (Register::Rcx, 0),
                (Register::Rdx, 0),
                (Register::R8, out_ptr as u64),
            ],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, 0);
        let factory_object = memory.read_u64(out_ptr as u64).expect("factory");
        assert_ne!(factory_object, 0, "a DXGI factory object must be produced");
        assert_eq!(
            runtime.guest_object_kind(factory_object).expect("kind"),
            GuestObjectKind::DxgiFactory
        );

        // A NULL out pointer returns E_INVALIDARG.
        let result = dispatch_x86_thunk_regs(
            &mut runtime,
            &mut memory,
            create_factory,
            &[(Register::Rcx, 0), (Register::Rdx, 0), (Register::R8, 0)],
        );
        assert_eq!(result, 0x8007_0057);
    })
}

#[test]
fn evidence_gl_fixed_function_pipeline_renders_and_reads_back() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-gl");
        let mut memory = MemoryImage::default();
        let create_ctx: u64 = runtime.alloc_host_thunk(HostThunk::WglCreateContext);
        let make_current: u64 = runtime.alloc_host_thunk(HostThunk::WglMakeCurrent);
        let ctx = dispatch_x86_thunk(&mut runtime, &mut memory, create_ctx, &[0x1000]);
        assert_ne!(ctx, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                make_current,
                &[0x1000, ctx as u32]
            ),
            1
        );

        let viewport: u64 = runtime.alloc_host_thunk(HostThunk::GlViewport);
        let clear_color: u64 = runtime.alloc_host_thunk(HostThunk::GlClearColor);
        let clear: u64 = runtime.alloc_host_thunk(HostThunk::GlClear);
        let read: u64 = runtime.alloc_host_thunk(HostThunk::GlReadPixels);
        dispatch_x86_thunk(&mut runtime, &mut memory, viewport, &[0, 0, 16, 16]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            clear_color,
            &[
                0.25f32.to_bits(),
                0.5f32.to_bits(),
                0.75f32.to_bits(),
                1.0f32.to_bits(),
            ],
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, clear, &[0x0000_4000]);
        let pixels_out = 0x41_000_u64;
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read,
            &[0, 0, 1, 1, 0x1908, 0x1401, pixels_out as u32],
        );
        let px = memory.read_bytes(pixels_out, 4).unwrap();
        assert_eq!(&px[..3], &[64, 128, 191], "clear color readback got {px:?}");

        // Projection: glOrtho(-1, 1, -1, 1, -1, 1) — the doubles live on
        // the x86 stack at 8-byte offsets.
        let ortho: u64 = runtime.alloc_host_thunk(HostThunk::GlOrtho);
        let ortho_stack = 0x50_000_u64;
        memory.map_bytes(ortho_stack, &[0_u8; 0x200]);
        for (index, value) in [-1.0f64, 1.0, -1.0, 1.0, -1.0, 1.0].iter().enumerate() {
            for (b, byte) in value.to_le_bytes().iter().enumerate() {
                memory.write_u8(ortho_stack + 4 + (index as u64 * 8) + b as u64, *byte);
            }
        }
        let mut ortho_state = CpuState::new(GuestArch::X86);
        ortho_state.set(Register::Rsp, ortho_stack);
        runtime
            .dispatch_import(ortho, &mut ortho_state, &mut memory)
            .unwrap();

        // A red triangle in immediate mode.
        let begin: u64 = runtime.alloc_host_thunk(HostThunk::GlBegin);
        let end: u64 = runtime.alloc_host_thunk(HostThunk::GlEnd);
        let color3f: u64 = runtime.alloc_host_thunk(HostThunk::GlColor3f);
        let vertex3f: u64 = runtime.alloc_host_thunk(HostThunk::GlVertex3f);
        dispatch_x86_thunk(&mut runtime, &mut memory, begin, &[0x0004]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            color3f,
            &[1.0f32.to_bits(), 0.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vertex3f,
            &[0.0f32.to_bits(), 0.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vertex3f,
            &[1.0f32.to_bits(), 0.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vertex3f,
            &[0.5f32.to_bits(), 1.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, end, &[]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read,
            &[12, 10, 1, 1, 0x1908, 0x1401, pixels_out as u32],
        );
        let px = memory.read_bytes(pixels_out, 4).unwrap();
        assert_eq!(px[0], 255, "triangle interior is red got {px:?}");
        assert_eq!(px[1], 0);
        assert_eq!(px[2], 0);

        // Texture object + texel upload + textured draw.
        let gen_textures: u64 = runtime.alloc_host_thunk(HostThunk::GlGenTextures);
        let bind: u64 = runtime.alloc_host_thunk(HostThunk::GlBindTexture);
        let tex_image: u64 = runtime.alloc_host_thunk(HostThunk::GlTexImage2D);
        let enable: u64 = runtime.alloc_host_thunk(HostThunk::GlEnable);
        let texcoord2f: u64 = runtime.alloc_host_thunk(HostThunk::GlTexCoord2f);
        let name_out = 0x41_100_u64;
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            gen_textures,
            &[1, name_out as u32],
        );
        let tex_name = read_guest_u32(&memory, name_out).unwrap();
        assert_eq!(tex_name, 1);
        dispatch_x86_thunk(&mut runtime, &mut memory, bind, &[0x0DE1, tex_name]);
        let texel_out = 0x41_200_u64;
        let red_texels: Vec<u8> = vec![
            255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255,
        ];
        memory.map_bytes(texel_out, &red_texels);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            tex_image,
            &[0x0DE1, 0, 0x1908, 2, 2, 0, 0x1908, 0x1401, texel_out as u32],
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, enable, &[0x0DE1]);
        dispatch_x86_thunk(&mut runtime, &mut memory, begin, &[0x0004]);
        dispatch_x86_thunk(&mut runtime, &mut memory, color3f, &[1.0f32.to_bits(); 3]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            texcoord2f,
            &[0.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, vertex3f, &[0.0f32.to_bits(); 3]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            texcoord2f,
            &[1.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vertex3f,
            &[1.0f32.to_bits(), 0.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            texcoord2f,
            &[0.5f32.to_bits(), 1.0f32.to_bits()],
        );
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            vertex3f,
            &[0.5f32.to_bits(), 1.0f32.to_bits(), 0.0f32.to_bits()],
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, end, &[]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read,
            &[12, 10, 1, 1, 0x1908, 0x1401, pixels_out as u32],
        );
        let px = memory.read_bytes(pixels_out, 4).unwrap();
        assert_eq!(px[0], 255, "textured triangle samples the red texel");

        // GLU math on the same matrices.
        let perspective: u64 = runtime.alloc_host_thunk(HostThunk::GluPerspective);
        let look_at: u64 = runtime.alloc_host_thunk(HostThunk::GluLookAt);
        let doubles_stack = 0x51_000_u64;
        memory.map_bytes(doubles_stack, &[0_u8; 0x400]);
        let doubles = [45.0f64, 1.0, 0.1, 100.0];
        for (index, value) in doubles.iter().enumerate() {
            for (b, byte) in value.to_le_bytes().iter().enumerate() {
                memory.write_u8(doubles_stack + 4 + (index as u64 * 8) + b as u64, *byte);
            }
        }
        let mut gl_state = CpuState::new(GuestArch::X86);
        gl_state.set(Register::Rsp, doubles_stack);
        runtime
            .dispatch_import(perspective, &mut gl_state, &mut memory)
            .unwrap();
        let eye_doubles = [0.0f64, 0.0, 5.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0];
        let la_stack = 0x51_400_u64;
        memory.map_bytes(la_stack, &[0_u8; 0x400]);
        for (index, value) in eye_doubles.iter().enumerate() {
            for (b, byte) in value.to_le_bytes().iter().enumerate() {
                memory.write_u8(la_stack + 4 + (index as u64 * 8) + b as u64, *byte);
            }
        }
        let mut gl_state = CpuState::new(GuestArch::X86);
        gl_state.set(Register::Rsp, la_stack);
        runtime
            .dispatch_import(look_at, &mut gl_state, &mut memory)
            .unwrap();

        // WGL pixel format round trip.
        let choose: u64 = runtime.alloc_host_thunk(HostThunk::WglChoosePixelFormat);
        let set_format: u64 = runtime.alloc_host_thunk(HostThunk::WglSetPixelFormat);
        let get_format: u64 = runtime.alloc_host_thunk(HostThunk::WglGetPixelFormat);
        let format_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                choose,
                &[0x2000, 0, 1, format_out as u32]
            ),
            1
        );
        assert_eq!(read_guest_u32(&memory, format_out).unwrap(), 1);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_format, &[0x2000, 1, 0]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_format, &[0x2000]),
            1
        );

        // The whole sequence leaves no GL error pending.
        let get_error: u64 = runtime.alloc_host_thunk(HostThunk::GlGetError);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_error, &[]),
            0
        );
    })
}

#[test]
fn evidence_legacy_graphics_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-gfx");
        let mut memory = MemoryImage::default();
        let create_ex: u64 = runtime.alloc_host_thunk(HostThunk::DirectDrawCreateEx);
        let get_caps: u64 = runtime.alloc_host_thunk(HostThunk::DirectDrawGetCaps);
        let create_surface: u64 = runtime.alloc_host_thunk(HostThunk::DirectDrawCreateSurface);
        let surface_lock: u64 = runtime.alloc_host_thunk(HostThunk::DirectDrawSurfaceLock);
        let get_desc: u64 = runtime.alloc_host_thunk(HostThunk::DirectDrawSurfaceGetSurfaceDesc);
        let perf_status: u64 = runtime.alloc_host_thunk(HostThunk::D3dPerfGetStatus);
        let create_blob: u64 = runtime.alloc_host_thunk(HostThunk::D3dCreateBlob);
        let blob_size: u64 = runtime.alloc_host_thunk(HostThunk::D3dBlobGetBufferSize);
        let compile: u64 = runtime.alloc_host_thunk(HostThunk::D3dCompile);
        let get_info: u64 = runtime.alloc_host_thunk(HostThunk::D3dx11GetImageInfoFromFileW);
        let d3d10_create: u64 = runtime.alloc_host_thunk(HostThunk::D3d10CreateDevice);

        // DirectDrawCreateEx -> IDirectDraw7.
        let dd_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_ex,
                &[0, dd_out as u32, 0, 0]
            ),
            0
        );
        let dd = read_guest_pointer(&memory, dd_out, GuestArch::X86).unwrap();
        assert_ne!(dd, 0);

        // GetCaps writes the caps bitmasks.
        let hw_out = 0x41_100_u64;
        let sw_out = 0x41_110_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_caps,
                &[dd as u32, hw_out as u32, sw_out as u32]
            ),
            0
        );
        assert_ne!(read_guest_u32(&memory, hw_out).unwrap(), 0);
        assert_ne!(read_guest_u32(&memory, sw_out).unwrap(), 0);

        // CreateSurface with a DDSURFACEDESC2 (width/height at offsets
        // 24/20, caps at 4) -> a software surface.
        let desc = 0x41_200_u64;
        memory.map_bytes(desc, &[0_u8; 124]);
        write_guest_u32(&mut memory, desc + 20, 64).ok();
        write_guest_u32(&mut memory, desc + 24, 128).ok();
        write_guest_u32(&mut memory, desc + 4, 0x1000).ok();
        let surf_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_surface,
                &[dd as u32, desc as u32, surf_out as u32, 0]
            ),
            0
        );
        let surface = read_guest_pointer(&memory, surf_out, GuestArch::X86).unwrap();
        assert_ne!(surface, 0);
        assert_eq!(runtime.ddraw_surfaces.get(&surface).unwrap().width, 128);
        assert_eq!(runtime.ddraw_surfaces.get(&surface).unwrap().height, 64);

        // Lock fills the desc with the surface contract (the surface
        // pointer at offset 48).
        let lock_desc = 0x41_400_u64;
        memory.map_bytes(lock_desc, &[0_u8; 124]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                surface_lock,
                &[surface as u32, 0, lock_desc as u32, 0, 0]
            ),
            0
        );
        assert_eq!(
            read_guest_pointer(&memory, lock_desc + 48, GuestArch::X86).unwrap(),
            surface
        );
        assert_eq!(
            read_guest_u32(&memory, lock_desc + 40).unwrap(),
            128 * 4,
            "pitch"
        );

        // GetSurfaceDesc reports the same geometry.
        let desc_out = 0x41_500_u64;
        memory.map_bytes(desc_out, &[0_u8; 124]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_desc,
                &[surface as u32, desc_out as u32]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, desc_out + 20).unwrap(), 64);
        assert_eq!(read_guest_u32(&memory, desc_out + 24).unwrap(), 128);

        // D3DPERF is disabled.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, perf_status, &[]),
            0
        );

        // D3DCreateBlob allocates a real blob.
        let blob_out = 0x41_600_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_blob,
                &[256, blob_out as u32]
            ),
            0
        );
        let blob = read_guest_pointer(&memory, blob_out, GuestArch::X86).unwrap();
        assert_ne!(blob, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, blob_size, &[blob as u32]),
            256
        );

        // D3DCompile answers E_FAIL with an error blob (no compiler).
        let error_blob = 0x41_700_u64;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            compile,
            &[0, 0, 0, 0, 0, error_blob as u32],
        );
        assert_eq!(hr, 0x8000_4005);
        let error_blob_obj = read_guest_pointer(&memory, error_blob, GuestArch::X86).unwrap();
        assert_ne!(error_blob_obj, 0, "the error blob is produced");

        // D3D10CreateDevice builds the shared device machinery.
        let device_out = 0x41_800_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                d3d10_create,
                &[0, 0, 0, 0, 0xa000, device_out as u32]
            ),
            0
        );
        let device = read_guest_pointer(&memory, device_out, GuestArch::X86).unwrap();
        assert_ne!(device, 0);

        // D3DX11GetImageInfoFromFileW parses a real DDS header.
        let dds_path = std::env::temp_dir().join("casa1-evidence.dds");
        let mut dds = vec![0_u8; 128];
        dds[..4].copy_from_slice(b"DDS ");
        dds[12..16].copy_from_slice(&32_u32.to_le_bytes());
        dds[16..20].copy_from_slice(&64_u32.to_le_bytes());
        dds[28..32].copy_from_slice(&1_u32.to_le_bytes());
        std::fs::write(&dds_path, &dds).unwrap();
        let name_ptr = 0x41_900_u64;
        let wide: Vec<u16> = dds_path
            .to_string_lossy()
            .encode_utf16()
            .chain([0])
            .collect();
        for (i, unit) in wide.iter().enumerate() {
            write_guest_u16(&mut memory, name_ptr + (i as u64 * 2), *unit).ok();
        }
        let info_out = 0x41_a00_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_info,
                &[name_ptr as u32, 0, info_out as u32, 0]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, info_out).unwrap(), 64, "DDS width");
        assert_eq!(
            read_guest_u32(&memory, info_out + 4).unwrap(),
            32,
            "DDS height"
        );
        std::fs::remove_file(&dds_path).ok();
    })
}

#[test]
fn d3d12_dml_dll_imports_resolve_and_reject_unsupported_registry_export() {
    let import = |name: &str| ResolvedImport {
        requested_module: "dml.dll".to_string(),
        resolved_module: "dml.dll".to_string(),
        symbol: ImportSymbol::ByName {
            hint: 0,
            name: name.to_string(),
        },
        iat_rva: 0,
        export: ExportSymbol {
            ordinal: 0,
            name: Some(name.to_string()),
            target: ExportTarget::Rva(0),
        },
    };
    assert!(matches!(
        HostThunk::from_import(&import("DMLCreateDevice")),
        HostThunk::DMLCreateDevice
    ));
    assert!(matches!(
        HostThunk::from_import(&import("DMLCreateDevice1")),
        HostThunk::DMLCreateDevice1
    ));
    match HostThunk::from_import(&import("DMLCreateOperatorRegistry")) {
        HostThunk::Unsupported { dll, symbol } => {
            assert_eq!(dll, "dml.dll");
            assert_eq!(symbol, "DMLCreateOperatorRegistry");
        }
        other => panic!("unexpected DML registry thunk: {other:?}"),
    }
}

#[test]
fn d3d12_state_object_com_lifetime_add_and_query_interface() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-state-com",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x50_0000;
        memory.map_bytes(base, &vec![0u8; 0x20000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let device_vtable = memory.read_u64(device).expect("device vtable");
        let create_state_object = memory
            .read_u64(device_vtable + 61 * 8)
            .expect("CreateStateObject thunk");
        let add_to_state_object = memory
            .read_u64(device_vtable + 65 * 8)
            .expect("AddToStateObject thunk");
        assert_ne!(create_state_object, 0);
        assert_ne!(add_to_state_object, 0);

        // ID3D12Device5/7 must be reachable through QueryInterface.
        let device_qi = memory.read_u64(device_vtable).expect("device QI");
        let iid_device7 = base + 0x8600;
        memory.map_bytes(iid_device7, &[0u8; 16]);
        let device7_iid: [u8; 16] = [
            0x53, 0x4b, 0x01, 0x5c, 0xa1, 0x68, 0x9b, 0x4b, 0x8b, 0xd1, 0xdd, 0x60, 0x46, 0xb9,
            0x35, 0x8b,
        ];
        for (index, byte) in device7_iid.iter().enumerate() {
            memory.write_u8(iid_device7 + index as u64, *byte);
        }
        let device_qi_out = base + 0x8610;
        memory.map_bytes(device_qi_out, &[0u8; 8]);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, base + 0x600);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, iid_device7);
        state.set(Register::R8, device_qi_out);
        memory.write_u64(base + 0x600, 0x1000_0009);
        runtime
            .dispatch_import(device_qi, &mut state, &mut memory)
            .expect("device QI Device7");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            memory.read_u64(device_qi_out).expect("device QI ptr"),
            device
        );
        let bad_device_iid = base + 0x8620;
        memory.map_bytes(bad_device_iid, &[0xDD; 16]);
        state.set(Register::Rsp, base + 0x640);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, bad_device_iid);
        state.set(Register::R8, device_qi_out);
        memory.write_u64(base + 0x640, 0x1000_000a);
        runtime
            .dispatch_import(device_qi, &mut state, &mut memory)
            .expect("device bad QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);

        let desc = build_raytracing_state_object_desc(&mut memory, base + 0x1000, "raygen");
        let iid = base + 0x8800;
        let out = base + 0x8900;
        memory.map_bytes(iid, &[0u8; 16]);
        memory.map_bytes(out, &[0u8; 8]);
        let iid_bytes: [u8; 16] = [
            0x43, 0x69, 0x01, 0x47, 0xa8, 0xfc, 0x94, 0x45, 0x93, 0xea, 0xaf, 0x25, 0x8b, 0x55,
            0x34, 0x6d,
        ];
        for (index, byte) in iid_bytes.iter().enumerate() {
            memory.write_u8(iid + index as u64, *byte);
        }
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, base + 0x100);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, desc);
        state.set(Register::R8, iid);
        state.set(Register::R9, out);
        memory.write_u64(base + 0x100, 0x1000_0010);
        runtime
            .dispatch_import(create_state_object, &mut state, &mut memory)
            .expect("CreateStateObject");
        assert_eq!(state.get(Register::Rax), 0);
        let state_object = memory.read_u64(out).expect("state object");
        assert_eq!(
            runtime.guest_object_kind(state_object).expect("kind"),
            GuestObjectKind::D3d12StateObject
        );
        assert_eq!(runtime.d3d12_state_object_handles.len(), 1);
        assert_eq!(runtime.d3d12_runtime.state_objects().count(), 1);

        let vtable = memory.read_u64(state_object).expect("state object vtable");
        let query_interface = memory.read_u64(vtable).expect("QueryInterface");
        let release = memory.read_u64(vtable + 16).expect("Release");
        let out2 = base + 0x8100;
        memory.map_bytes(out2, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, state_object);
        state.set(Register::Rdx, iid);
        state.set(Register::R8, out2);
        memory.write_u64(base + 0x140, 0x1000_0011);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("state object QueryInterface");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            memory.read_u64(out2).expect("queried pointer"),
            state_object
        );

        let bad_iid = base + 0x8110;
        memory.map_bytes(bad_iid, &[0xAA; 16]);
        state.set(Register::Rsp, base + 0x180);
        state.set(Register::Rcx, state_object);
        state.set(Register::Rdx, bad_iid);
        state.set(Register::R8, out2);
        memory.write_u64(base + 0x180, 0x1000_0012);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("bad QueryInterface");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);
        assert_eq!(memory.read_u64(out2).expect("failed pointer"), 0);

        // QI added a reference; release it plus the creation reference.
        state.set(Register::Rsp, base + 0x1c0);
        state.set(Register::Rcx, state_object);
        memory.write_u64(base + 0x1c0, 0x1000_0013);
        runtime
            .dispatch_import(release, &mut state, &mut memory)
            .expect("release QI reference");
        assert_eq!(state.get(Register::Rax), 1);
        state.set(Register::Rsp, base + 0x200);
        state.set(Register::Rcx, state_object);
        memory.write_u64(base + 0x200, 0x1000_0014);
        runtime
            .dispatch_import(release, &mut state, &mut memory)
            .expect("release creation reference");
        assert_eq!(state.get(Register::Rax), 0);
        assert!(runtime.d3d12_state_object_handles.is_empty());
        assert_eq!(runtime.d3d12_runtime.state_objects().count(), 0);

        // Double release of a destroyed COM object is an exact error.
        state.set(Register::Rsp, base + 0x240);
        state.set(Register::Rcx, state_object);
        memory.write_u64(base + 0x240, 0x1000_0015);
        let error = runtime
            .dispatch_import(release, &mut state, &mut memory)
            .expect_err("double release must fail");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);

        // Recreate a parent, grow it with AddToStateObject, then release
        // both COM objects across the addition.
        let parent_out = base + 0x8200;
        memory.map_bytes(parent_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x280);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, desc);
        state.set(Register::R8, iid);
        state.set(Register::R9, parent_out);
        memory.write_u64(base + 0x280, 0x1000_0016);
        runtime
            .dispatch_import(create_state_object, &mut state, &mut memory)
            .expect("recreate parent");
        let parent = memory.read_u64(parent_out).expect("parent");
        let addition = build_raytracing_state_object_desc(&mut memory, base + 0x9000, "miss");
        let child_out = base + 0x8208;
        memory.map_bytes(child_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x2c0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, addition);
        state.set(Register::R8, parent);
        state.set(Register::R9, iid);
        memory.write_u64(base + 0x2c0, 0x1000_0017);
        memory.write_u64(base + 0x2c0 + 0x28, child_out);
        runtime
            .dispatch_import(add_to_state_object, &mut state, &mut memory)
            .expect("AddToStateObject");
        assert_eq!(state.get(Register::Rax), 0);
        let child = memory.read_u64(child_out).expect("child state object");
        assert_ne!(child, parent);
        assert_eq!(runtime.d3d12_state_object_handles.len(), 2);
        let child_vtable = memory.read_u64(child).expect("child vtable");
        let child_release = memory.read_u64(child_vtable + 16).expect("child Release");
        for (slot, object) in [(0x300u64, child), (0x340, parent)] {
            state.set(Register::Rsp, base + slot);
            state.set(Register::Rcx, object);
            memory.write_u64(base + slot, 0x1000_0020 + slot);
            runtime
                .dispatch_import(child_release, &mut state, &mut memory)
                .expect("release state object chain");
            assert_eq!(state.get(Register::Rax), 0);
        }
        assert!(runtime.d3d12_state_object_handles.is_empty());
        assert_eq!(runtime.d3d12_runtime.state_objects().count(), 0);

        // Null creation arguments fail before any object is produced.
        state.set(Register::Rsp, base + 0x380);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, iid);
        state.set(Register::R9, out);
        memory.write_u64(base + 0x380, 0x1000_0030);
        runtime
            .dispatch_import(create_state_object, &mut state, &mut memory)
            .expect("null desc");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        state.set(Register::Rsp, base + 0x3c0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, parent);
        state.set(Register::R9, iid);
        memory.write_u64(base + 0x3c0, 0x1000_0031);
        memory.write_u64(base + 0x3c0 + 0x28, child_out);
        runtime
            .dispatch_import(add_to_state_object, &mut state, &mut memory)
            .expect("null addition");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
    });
}

#[test]
fn d3d12_command_signature_com_lifetime_and_execute_indirect() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-signature-com",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x58_0000;
        memory.map_bytes(base, &vec![0u8; 0x20000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x1000, device);
        let device_vtable = memory.read_u64(device).expect("device vtable");
        let create_signature = memory
            .read_u64(device_vtable + 10 * 8)
            .expect("CreateCommandSignature");
        let signature_desc = base + 0x2000;
        let argument_desc = base + 0x2040;
        let signature_out = base + 0x3000;
        memory.map_bytes(signature_desc, &[0u8; 32]);
        memory.map_bytes(argument_desc, &[0u8; 16]);
        memory.map_bytes(signature_out, &[0u8; 8]);
        write_u32(&mut memory, signature_desc, 16);
        write_u32(&mut memory, signature_desc + 4, 1);
        write_u64(&mut memory, signature_desc + 8, argument_desc);
        write_u32(&mut memory, signature_desc + 16, 0);
        write_u32(&mut memory, argument_desc, 0); // DRAW
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, base + 0x100);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, signature_desc);
        state.set(Register::R8, signature_out);
        memory.write_u64(base + 0x100, 0x1000_0400);
        runtime
            .dispatch_import(create_signature, &mut state, &mut memory)
            .expect("CreateCommandSignature");
        assert_eq!(state.get(Register::Rax), 0);
        let signature = memory.read_u64(signature_out).expect("signature object");
        assert_eq!(
            runtime
                .guest_object_kind(signature)
                .expect("signature kind"),
            GuestObjectKind::D3d12CommandSignature
        );
        assert_eq!(runtime.d3d12_command_signature_handles.len(), 1);

        let vtable = memory.read_u64(signature).expect("signature vtable");
        let query_interface = memory.read_u64(vtable).expect("QI");
        let release = memory.read_u64(vtable + 16).expect("Release");
        let iid = base + 0x3100;
        memory.map_bytes(iid, &[0u8; 16]);
        let iid_bytes: [u8; 16] = [
            0x7c, 0x79, 0x6a, 0xc3, 0x80, 0xec, 0x0a, 0x4f, 0x89, 0x85, 0xa7, 0xb2, 0x47, 0x50,
            0x82, 0xd1,
        ];
        for (index, byte) in iid_bytes.iter().enumerate() {
            memory.write_u8(iid + index as u64, *byte);
        }
        let qi_out = base + 0x3110;
        memory.map_bytes(qi_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, signature);
        state.set(Register::Rdx, iid);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x140, 0x1000_0401);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("signature QI");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            memory.read_u64(qi_out).expect("signature QI ptr"),
            signature
        );
        let bad_iid = base + 0x3120;
        memory.map_bytes(bad_iid, &[0xBB; 16]);
        state.set(Register::Rsp, base + 0x180);
        state.set(Register::Rcx, signature);
        state.set(Register::Rdx, bad_iid);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x180, 0x1000_0402);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("signature bad QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);

        // Create an argument-buffer resource and write two DRAW records.
        let resource_desc = base + 0x3200;
        memory.map_bytes(resource_desc, &[0u8; 48]);
        write_u32(&mut memory, resource_desc, 28);
        write_u32(&mut memory, resource_desc + 4, 4); // BUFFER
        write_u64(&mut memory, resource_desc + 8, 32);
        write_u32(&mut memory, resource_desc + 16, 1);
        write_u16(&mut memory, resource_desc + 20, 1);
        write_u16(&mut memory, resource_desc + 24, 1);
        write_u32(&mut memory, resource_desc + 28, 1);
        let create_resource = memory
            .read_u64(device_vtable + 24 * 8)
            .expect("CreateCommittedResource");
        let resource_out = base + 0x3300;
        memory.map_bytes(resource_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x1c0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, resource_desc);
        memory.write_u64(base + 0x1c0, 0x1000_0403);
        write_u32(&mut memory, base + 0x1c0 + 0x28, 0);
        memory.write_u64(base + 0x1c0 + 0x30, 0);
        memory.write_u64(base + 0x1c0 + 0x38, resource_out);
        runtime
            .dispatch_import(create_resource, &mut state, &mut memory)
            .expect("CreateCommittedResource");
        assert_eq!(state.get(Register::Rax), 0);
        let resource = memory.read_u64(resource_out).expect("argument resource");
        let resource_id = runtime
            .d3d12_resource(resource)
            .expect("resource record")
            .resource_id;
        let mut arguments = Vec::new();
        for (vertices, instances) in [(3u32, 1u32), (6, 2)] {
            arguments.extend_from_slice(&vertices.to_le_bytes());
            arguments.extend_from_slice(&instances.to_le_bytes());
            arguments.extend_from_slice(&0u32.to_le_bytes());
            arguments.extend_from_slice(&0u32.to_le_bytes());
        }
        runtime
            .d3d12_runtime
            .overwrite_resource_bytes(resource_id, &arguments)
            .expect("write argument buffer");

        let list_vtable = memory.read_u64(list).expect("list vtable");
        let execute_indirect = memory
            .read_u64(list_vtable + 47 * 8)
            .expect("ExecuteIndirect");
        state.set(Register::Rsp, base + 0x200);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, signature);
        state.set(Register::R8, 2);
        state.set(Register::R9, resource);
        memory.write_u64(base + 0x200, 0x1000_0404);
        memory.write_u64(base + 0x200 + 0x28, 0);
        memory.write_u64(base + 0x200 + 0x30, 0);
        write_u32(&mut memory, base + 0x200 + 0x38, 0);
        runtime
            .dispatch_import(execute_indirect, &mut state, &mut memory)
            .expect("ExecuteIndirect");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        let command_list_id = runtime
            .d3d12_command_lists
            .get(&list)
            .and_then(|record| record.command_list_id)
            .expect("command list id");
        let stream = runtime
            .d3d12_runtime
            .close_command_list(command_list_id)
            .expect("close command list");
        assert_eq!(stream.commands.len(), 0);

        // ExecuteIndirect handler error matrix.
        let error_list =
            create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x1400, device);
        let count_resource = base + 0x3500;
        memory.map_bytes(count_resource, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x2e0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, resource_desc);
        memory.write_u64(base + 0x2e0, 0x1000_0408);
        write_u32(&mut memory, base + 0x2e0 + 0x28, 0);
        memory.write_u64(base + 0x2e0 + 0x30, 0);
        memory.write_u64(base + 0x2e0 + 0x38, count_resource);
        runtime
            .dispatch_import(create_resource, &mut state, &mut memory)
            .expect("count resource");
        assert_eq!(state.get(Register::Rax), 0);
        let count_guest = memory
            .read_u64(count_resource)
            .expect("count resource guest");
        let count_id = runtime
            .d3d12_resource(count_guest)
            .expect("count record")
            .resource_id;
        runtime
            .d3d12_runtime
            .overwrite_resource_bytes(count_id, &5u32.to_le_bytes())
            .expect("count bytes");
        let fake_resource = base + 0x3600;
        runtime.guest_objects.insert(
            fake_resource,
            super::state::GuestObjectMeta {
                kind: GuestObjectKind::D3d12Resource,
                refcount: 1,
            },
        );
        runtime.d3d12_resources.insert(
            fake_resource,
            super::state::GuestD3d12Resource {
                device_object: device,
                resource_id: 0xFFFF,
                format: crate::gfx::DxgiFormat::R8G8B8A8Unorm,
                swapchain_backbuffer: false,
                width: 4,
                height: 4,
            },
        );
        for (sig, args_obj, max_count, args_offset, count_obj, count_offset, expected) in [
            (0x9999u64, resource, 2u64, 0u64, 0u64, 0u32, E_INVALIDARG),
            (signature, 0x9999, 2, 0, 0, 0, E_INVALIDARG),
            (signature, resource, 2, 0, 0x9999, 0, E_INVALIDARG),
            (signature, resource, 2, 0, count_guest, 0x1000, E_INVALIDARG),
            (signature, resource, 1, 0, count_guest, 0, E_INVALIDARG),
            (signature, fake_resource, 1, 0, 0, 0, E_INVALIDARG),
            (signature, resource, 1, 0, fake_resource, 0, E_INVALIDARG),
        ] {
            state.set(Register::Rsp, base + 0x400);
            state.set(Register::Rcx, error_list);
            state.set(Register::Rdx, sig);
            state.set(Register::R8, max_count);
            state.set(Register::R9, args_obj);
            memory.write_u64(base + 0x400, 0x1000_0409);
            memory.write_u64(base + 0x400 + 0x28, args_offset);
            memory.write_u64(base + 0x400 + 0x30, count_obj);
            write_u32(&mut memory, base + 0x400 + 0x38, count_offset);
            runtime
                .dispatch_import(execute_indirect, &mut state, &mut memory)
                .expect("ExecuteIndirect error path");
            assert_eq!(state.get(Register::Rax), expected);
        }
        // Unsupported start location maps to E_NOTIMPL.
        let mut bad_draw = Vec::new();
        bad_draw.extend_from_slice(&3u32.to_le_bytes());
        bad_draw.extend_from_slice(&1u32.to_le_bytes());
        bad_draw.extend_from_slice(&7u32.to_le_bytes());
        bad_draw.extend_from_slice(&0u32.to_le_bytes());
        runtime
            .d3d12_runtime
            .overwrite_resource_bytes(resource_id, &bad_draw)
            .expect("bad draw args");
        state.set(Register::Rsp, base + 0x440);
        state.set(Register::Rcx, error_list);
        state.set(Register::Rdx, signature);
        state.set(Register::R8, 1);
        state.set(Register::R9, resource);
        memory.write_u64(base + 0x440, 0x1000_040a);
        memory.write_u64(base + 0x440 + 0x28, 0);
        memory.write_u64(base + 0x440 + 0x30, 0);
        write_u32(&mut memory, base + 0x440 + 0x38, 0);
        runtime
            .dispatch_import(execute_indirect, &mut state, &mut memory)
            .expect("ExecuteIndirect missing native pipeline");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        // QI added one reference; release it and the creation reference.
        state.set(Register::Rsp, base + 0x240);
        state.set(Register::Rcx, signature);
        memory.write_u64(base + 0x240, 0x1000_0405);
        runtime
            .dispatch_import(release, &mut state, &mut memory)
            .expect("signature release QI");
        assert_eq!(state.get(Register::Rax), 1);
        state.set(Register::Rsp, base + 0x280);
        state.set(Register::Rcx, signature);
        memory.write_u64(base + 0x280, 0x1000_0406);
        runtime
            .dispatch_import(release, &mut state, &mut memory)
            .expect("signature release creation");
        assert_eq!(state.get(Register::Rax), 0);
        assert!(runtime.d3d12_command_signature_handles.is_empty());
        state.set(Register::Rsp, base + 0x2c0);
        state.set(Register::Rcx, signature);
        memory.write_u64(base + 0x2c0, 0x1000_0407);
        let error = runtime
            .dispatch_import(release, &mut state, &mut memory)
            .expect_err("signature double release");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    });
}

#[test]
fn d3d12_auto_graphics_pso_rejects_manual_registration_and_draws_match_indirect() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-auto-pso",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x70_0000;
        memory.map_bytes(base, &vec![0u8; 0x40000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x1000, device);
        let vs = make_test_dxil_container(0);
        let ps = make_test_dxil_container(0);
        let vs_ptr = base + 0x8000;
        let ps_ptr = base + 0x9000;
        memory.map_bytes(vs_ptr, &vs);
        memory.map_bytes(ps_ptr, &ps);
        let desc = base + 0xa000;
        let out = base + 0xa100;
        memory.map_bytes(desc, &[0u8; 0x80]);
        memory.map_bytes(out, &[0u8; 8]);
        write_u64(&mut memory, desc + 8, vs_ptr);
        write_u64(&mut memory, desc + 16, vs.len() as u64);
        write_u64(&mut memory, desc + 24, ps_ptr);
        write_u64(&mut memory, desc + 32, ps.len() as u64);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, desc);
        state.set(Register::R9, out);
        runtime
            .dispatch_d3d12_create_graphics_pipeline_state(&mut memory, &mut state)
            .expect("auto PSO");
        assert_eq!(state.get(Register::Rax), 0);
        let pso = memory.read_u64(out).expect("pso handle") as crate::gfx::PipelineStateId;
        assert_ne!(pso, 0);
        let (vs_msl, ps_msl) = runtime
            .d3d12_runtime
            .native_pipeline_artifacts(pso)
            .expect("translated artifacts");
        assert_eq!(vs_msl.contains("vs_main"), true);
        assert_eq!(ps_msl.contains("fs_main"), true);
        assert_eq!(vs_msl.starts_with("#include <metal_stdlib>"), true);
        runtime
            .d3d12_runtime
            .compile_native_render_pipeline(pso)
            .expect("idempotent native compile");

        let target = runtime
            .d3d12_runtime
            .create_committed_resource(crate::gfx::ResourceDesc {
                name: "auto-pso-target".into(),
                format: crate::gfx::DxgiFormat::B8G8R8A8Unorm,
                heap: crate::gfx::HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: crate::gfx::ResourceState::Common,
                usage_hint: crate::gfx::ResourceUsageHint::Texture {
                    sampled: false,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("target");
        let vertex = runtime
            .d3d12_runtime
            .create_committed_resource(crate::gfx::ResourceDesc {
                name: "auto-pso-vertex".into(),
                format: crate::gfx::DxgiFormat::Unknown,
                heap: crate::gfx::HeapType::Default,
                size: 36,
                subresources: 1,
                initial_state: crate::gfx::ResourceState::Common,
                usage_hint: crate::gfx::ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("vertex");
        runtime
            .d3d12_runtime
            .write_resource_bytes(vertex, &[0u8; 36])
            .expect("vertices");
        let command_list_id = runtime
            .d3d12_command_lists
            .get(&list)
            .and_then(|record| record.command_list_id)
            .expect("list id");
        runtime
            .d3d12_runtime
            .bind_native_pipeline(command_list_id, pso)
            .expect("bind auto pipeline");
        runtime.d3d12_runtime.bind_native_render_target(
            command_list_id,
            target,
            4,
            4,
            crate::gfx::DxgiFormat::B8G8R8A8Unorm,
        );
        runtime
            .d3d12_runtime
            .bind_native_vertex_buffer(command_list_id, vertex, 0);
        assert_eq!(
            runtime
                .d3d12_runtime
                .execute_native_direct_draw(command_list_id, 3, 1)
                .expect("direct draw"),
            true
        );
        let direct = runtime
            .d3d12_runtime
            .resource_bytes(target)
            .expect("direct bytes")
            .to_vec();
        runtime
            .d3d12_runtime
            .write_resource_bytes(target, &[0u8; 64])
            .expect("clear");
        let draw_sig = runtime
            .d3d12_runtime
            .create_command_signature(crate::d3d12::D3D12CommandSignatureDesc {
                byte_stride: 16,
                node_mask: 0,
                arguments: vec![crate::d3d12::D3D12IndirectArgumentDesc {
                    ty: crate::d3d12::D3D12_INDIRECT_ARGUMENT_TYPE_DRAW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("draw signature");
        let args = [3u32, 1, 0, 0].map(|value| value.to_le_bytes()).concat();
        assert_eq!(
            runtime
                .d3d12_runtime
                .execute_indirect_gpu(
                    command_list_id,
                    draw_sig,
                    1,
                    &args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("indirect draw"),
            1
        );
        assert_eq!(
            runtime
                .d3d12_runtime
                .resource_bytes(target)
                .expect("indirect bytes"),
            &direct[..]
        );

        // Mutating the guest bytecode after creation must not affect the
        // retained translated artifacts.
        memory.map_bytes(vs_ptr, &[0xAA; 64]);
        let (vs_after, _) = runtime
            .d3d12_runtime
            .native_pipeline_artifacts(pso)
            .expect("retained artifacts");
        assert_eq!(vs_after, vs_msl);
    });
}

#[test]
fn d3d12_auto_graphics_pso_rejects_invalid_bytecode() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-auto-pso-errors",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x71_0000;
        memory.map_bytes(base, &vec![0u8; 0x20000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let desc = base + 0x8000;
        let out = base + 0x8100;
        memory.map_bytes(desc, &[0u8; 0x80]);
        memory.map_bytes(out, &[0u8; 8]);
        let mut state = CpuState::new(GuestArch::X64);
        let run = |runtime: &mut PeHostRuntime, memory: &mut MemoryImage, state: &mut CpuState| {
            state.set(Register::Rcx, device);
            state.set(Register::Rdx, desc);
            state.set(Register::R9, out);
            runtime
                .dispatch_d3d12_create_graphics_pipeline_state(memory, state)
                .expect("CreateGraphicsPipelineState");
            state.get(Register::Rax)
        };
        // Missing VS bytecode.
        write_u64(&mut memory, desc + 8, 0);
        write_u64(&mut memory, desc + 16, 0);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_INVALIDARG);
        // Bad container magic.
        let bad_ptr = base + 0x9000;
        memory.map_bytes(bad_ptr, b"NOPE");
        write_u64(&mut memory, desc + 8, bad_ptr);
        write_u64(&mut memory, desc + 16, 4);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_INVALIDARG);
        // DXBC shader model 5 has no DXIL chunk.
        let dxbc_ptr = base + 0x9100;
        let mut dxbc = vec![0u8; 32];
        dxbc[..4].copy_from_slice(b"DXBC");
        memory.map_bytes(dxbc_ptr, &dxbc);
        write_u64(&mut memory, desc + 8, dxbc_ptr);
        write_u64(&mut memory, desc + 16, dxbc.len() as u64);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_NOTIMPL);
        // Corrupt DXIL container.
        let bad_dxil = b"DXIL"
            .iter()
            .copied()
            .chain([1u8, 0, 0, 0])
            .chain([0u8; 4])
            .collect::<Vec<u8>>();
        let bad_dxil_ptr = base + 0x9200;
        memory.map_bytes(bad_dxil_ptr, &bad_dxil);
        write_u64(&mut memory, desc + 8, bad_dxil_ptr);
        write_u64(&mut memory, desc + 16, bad_dxil.len() as u64);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_INVALIDARG);
        // Missing PS bytecode with a valid VS.
        let good = make_test_dxil_container(0);
        let good_ptr = base + 0x9300;
        memory.map_bytes(good_ptr, &good);
        write_u64(&mut memory, desc + 8, good_ptr);
        write_u64(&mut memory, desc + 16, good.len() as u64);
        write_u64(&mut memory, desc + 24, 0);
        write_u64(&mut memory, desc + 32, 0);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_INVALIDARG);
        // Oversized bytecode is rejected before reading guest memory.
        write_u64(&mut memory, desc + 8, good_ptr);
        write_u64(&mut memory, desc + 16, 64 * 1024 * 1024 + 1);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_INVALIDARG);
        // PS DXBC without a DXIL chunk maps to E_NOTIMPL.
        write_u64(&mut memory, desc + 8, good_ptr);
        write_u64(&mut memory, desc + 16, good.len() as u64);
        write_u64(&mut memory, desc + 24, dxbc_ptr);
        write_u64(&mut memory, desc + 32, dxbc.len() as u64);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_NOTIMPL);
        // Compilation failure inside CreateGraphicsPipelineState surfaces
        // as E_INVALIDARG.
        write_u64(&mut memory, desc + 24, good_ptr);
        write_u64(&mut memory, desc + 32, good.len() as u64);
        crate::metal_backend::set_native_pipeline_creation_fault(true);
        assert_eq!(run(&mut runtime, &mut memory, &mut state), E_INVALIDARG);
        crate::metal_backend::set_native_pipeline_creation_fault(false);

        // Compiling a PSO without retained native artifacts is an exact
        // error, and a Metal compilation fault surfaces as an error.
        let root = runtime
            .d3d12_runtime
            .create_root_signature(crate::d3d12::RootSignatureDesc::default());
        let orphan = runtime.d3d12_runtime.create_pipeline_state(
            root,
            crate::d3d12::PipelineStateDesc {
                label: "auto-pso-orphan".into(),
                compute: false,
                render_target_formats: vec![crate::gfx::DxgiFormat::B8G8R8A8Unorm],
                depth_format: None,
            },
        );
        let error = runtime
            .d3d12_runtime
            .compile_native_render_pipeline(orphan)
            .expect_err("orphan native compile");
        assert_eq!(
            error.message,
            "pipeline state has no registered native pipeline"
        );
        runtime
            .d3d12_runtime
            .register_native_render_pipeline(
                orphan,
                "vertex void vs_main() {}".to_string(),
                "fragment float4 fs_main() { return float4(1.0); }".to_string(),
                crate::gfx::DxgiFormat::B8G8R8A8Unorm,
            )
            .expect("register fault pipeline");
        crate::metal_backend::set_native_pipeline_creation_fault(true);
        let error = runtime
            .d3d12_runtime
            .compile_native_render_pipeline(orphan)
            .expect_err("native compile fault");
        crate::metal_backend::set_native_pipeline_creation_fault(false);
        assert_eq!(error.message, "native render pipeline creation fault");
    });
}

#[test]
fn d3d12_native_indirect_shell_rejects_missing_state_and_binds_gpu_resources() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-native-shell",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x60_0000;
        memory.map_bytes(base, &vec![0u8; 0x30000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x1000, device);

        let target = runtime
            .d3d12_runtime
            .create_committed_resource(crate::gfx::ResourceDesc {
                name: "shell-target".into(),
                format: crate::gfx::DxgiFormat::B8G8R8A8Unorm,
                heap: crate::gfx::HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: crate::gfx::ResourceState::Common,
                usage_hint: crate::gfx::ResourceUsageHint::Texture {
                    sampled: false,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("target resource");
        let vertices: [f32; 9] = [-1.0, -1.0, 0.0, 3.0, -1.0, 0.0, -1.0, 3.0, 0.0];
        let vertex_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                vertices.as_ptr() as *const u8,
                std::mem::size_of_val(&vertices),
            )
        };
        let vertex = runtime
            .d3d12_runtime
            .create_committed_resource(crate::gfx::ResourceDesc {
                name: "shell-vertices".into(),
                format: crate::gfx::DxgiFormat::Unknown,
                heap: crate::gfx::HeapType::Default,
                size: 36,
                subresources: 1,
                initial_state: crate::gfx::ResourceState::Common,
                usage_hint: crate::gfx::ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("vertex resource");
        runtime
            .d3d12_runtime
            .write_resource_bytes(vertex, vertex_bytes)
            .expect("vertices");
        let index = runtime
            .d3d12_runtime
            .create_committed_resource(crate::gfx::ResourceDesc {
                name: "shell-indices".into(),
                format: crate::gfx::DxgiFormat::Unknown,
                heap: crate::gfx::HeapType::Default,
                size: 6,
                subresources: 1,
                initial_state: crate::gfx::ResourceState::Common,
                usage_hint: crate::gfx::ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Index,
                    cpu_write_frequent: true,
                },
            })
            .expect("index resource");
        runtime
            .d3d12_runtime
            .write_resource_bytes(index, &[0u8, 0, 1, 0, 2, 0])
            .expect("indices");

        let resource_object = |runtime: &mut PeHostRuntime,
                               memory: &mut MemoryImage,
                               resource_id: crate::gfx::ResourceId| {
            let object = runtime
                .alloc_guest_object(memory, GuestObjectKind::D3d12Resource, 0x7000_0000)
                .expect("resource object");
            runtime.d3d12_resources.insert(
                object,
                super::state::GuestD3d12Resource {
                    device_object: device,
                    resource_id,
                    format: crate::gfx::DxgiFormat::B8G8R8A8Unorm,
                    swapchain_backbuffer: false,
                    width: 4,
                    height: 4,
                },
            );
            object
        };
        let _target_object = resource_object(&mut runtime, &mut memory, target);
        let vertex_object = resource_object(&mut runtime, &mut memory, vertex);
        let index_object = resource_object(&mut runtime, &mut memory, index);

        let heap_id = runtime
            .d3d12_runtime
            .create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        runtime
            .d3d12_runtime
            .write_descriptor(
                heap_id,
                0,
                crate::gfx::ViewDescriptor::Rtv {
                    resource: target,
                    format: crate::gfx::DxgiFormat::B8G8R8A8Unorm,
                },
            )
            .expect("RTV descriptor");
        let heap_object = runtime
            .alloc_guest_object(
                &mut memory,
                GuestObjectKind::D3d12DescriptorHeap,
                0x7000_0100,
            )
            .expect("heap object");
        runtime.d3d12_descriptor_heaps.insert(
            heap_object,
            super::state::GuestD3d12DescriptorHeap {
                device_object: device,
                heap_id,
                ty: DescriptorHeapType::Rtv,
                cpu_handle_start: 0x7000_1000,
                descriptor_count: 1,
            },
        );
        let rtv_handle = 0x7000_1000u64;

        let root = runtime
            .d3d12_runtime
            .create_root_signature(crate::d3d12::RootSignatureDesc::default());
        let pso = runtime.d3d12_runtime.create_pipeline_state(
            root,
            crate::d3d12::PipelineStateDesc {
                label: "shell-pso".into(),
                compute: false,
                render_target_formats: vec![crate::gfx::DxgiFormat::B8G8R8A8Unorm],
                depth_format: None,
            },
        );
        runtime
            .d3d12_runtime
            .register_native_render_pipeline(
                pso,
                r#"#include <metal_stdlib>
using namespace metal;
struct VOut { float4 position [[position]]; };
vertex VOut vs_main(uint vid [[vertex_id]], device const float* vertices [[buffer(0)]]) {
    VOut out;
    uint index = vid * 3u;
    out.position = float4(vertices[index], vertices[index + 1u], vertices[index + 2u], 1.0);
    return out;
}"#
                .to_string(),
                r#"#include <metal_stdlib>
using namespace metal;
fragment float4 fs_main() { return float4(1.0, 0.0, 0.0, 1.0); }"#
                    .to_string(),
                crate::gfx::DxgiFormat::B8G8R8A8Unorm,
            )
            .expect("native pipeline");

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, pso as u64);
        runtime
            .dispatch_d3d12_graphics_command_list_set_pipeline_state(&mut memory, &mut state)
            .expect("SetPipelineState");
        assert_eq!(state.get(Register::Rax), 0);

        let vertex_view = base + 0x5000;
        write_u64(&mut memory, vertex_view, vertex_object);
        write_u64(&mut memory, vertex_view + 8, 0);
        write_u32(&mut memory, vertex_view + 16, 12);
        write_u32(&mut memory, vertex_view + 20, 36);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 1);
        state.set(Register::R9, vertex_view);
        runtime
            .dispatch_d3d12_graphics_command_list_ia_set_vertex_buffers(&mut memory, &mut state)
            .expect("IASetVertexBuffers");
        assert_eq!(state.get(Register::Rax), 0);

        let index_view = base + 0x5040;
        write_u64(&mut memory, index_view, index_object);
        write_u64(&mut memory, index_view + 8, 0);
        write_u32(&mut memory, index_view + 16, 6);
        write_u32(&mut memory, index_view + 20, 57);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, index_view);
        runtime
            .dispatch_d3d12_graphics_command_list_ia_set_index_buffer(&mut memory, &mut state)
            .expect("IASetIndexBuffer");
        assert_eq!(state.get(Register::Rax), 0);

        let rts = base + 0x5080;
        write_u64(&mut memory, rts, rtv_handle);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, rts);
        state.set(Register::R9, 0);
        state.set(Register::Rsp, base + 0x5100);
        write_u64(&mut memory, base + 0x5100, 0);
        runtime
            .dispatch_d3d12_graphics_command_list_om_set_render_targets(&mut memory, &mut state)
            .expect("OMSetRenderTargets");
        assert_eq!(state.get(Register::Rax), 0);

        state.set(Register::Rcx, list);
        state.set(Register::Rdx, 3);
        state.set(Register::R8, 1);
        state.set(Register::R9, 0);
        state.set(Register::Rsp, base + 0x5120);
        write_u64(&mut memory, base + 0x5120, 0);
        runtime
            .dispatch_d3d12_graphics_command_list_draw_instanced(&mut memory, &mut state)
            .expect("DrawInstanced");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            runtime
                .d3d12_runtime
                .resource_bytes(target)
                .expect("target readback")[0..4],
            [0, 0, 255, 255]
        );

        // Descriptor/heap shell paths: null rejects, valid succeeds.
        state.set(Register::Rcx, device);
        runtime
            .dispatch_d3d12_create_pipeline_library(&mut state)
            .expect("CreatePipelineLibrary");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R9, 0);
        runtime
            .dispatch_d3d12_create_heap(&mut memory, &mut state)
            .expect("CreateHeap null");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        let heap_desc = base + 0x5200;
        let heap_out = base + 0x5240;
        memory.map_bytes(heap_desc, &[0u8; 16]);
        memory.map_bytes(heap_out, &[0u8; 8]);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, heap_desc);
        state.set(Register::R9, heap_out);
        runtime
            .dispatch_d3d12_create_heap(&mut memory, &mut state)
            .expect("CreateHeap");
        assert_eq!(state.get(Register::Rax), 0);

        let placed_desc = base + 0x5300;
        let placed_out = base + 0x5340;
        memory.map_bytes(placed_desc, &[0u8; 32]);
        write_u32(&mut memory, placed_desc, 28);
        write_u32(&mut memory, placed_desc + 4, 3);
        write_u64(&mut memory, placed_desc + 8, 4);
        write_u32(&mut memory, placed_desc + 16, 4);
        memory.map_bytes(placed_out, &[0u8; 8]);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R9, placed_desc);
        state.set(Register::Rsp, base + 0x5360);
        write_u64(&mut memory, base + 0x5380, placed_out);
        runtime
            .dispatch_d3d12_create_placed_resource(&mut memory, &mut state)
            .expect("CreatePlacedResource");
        assert_eq!(state.get(Register::Rax), 0);

        let reserved_desc = base + 0x5400;
        let reserved_out = base + 0x5440;
        memory.map_bytes(reserved_desc, &[0u8; 32]);
        write_u32(&mut memory, reserved_desc, 28);
        write_u32(&mut memory, reserved_desc + 4, 3);
        write_u64(&mut memory, reserved_desc + 8, 4);
        write_u32(&mut memory, reserved_desc + 16, 4);
        memory.map_bytes(reserved_out, &[0u8; 8]);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R9, reserved_desc);
        state.set(Register::Rsp, base + 0x5460);
        write_u64(&mut memory, base + 0x5480, reserved_out);
        // Missing-pipeline draw keeps the typed fallback.
        let fallback_list =
            create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x6000, device);
        state.set(Register::Rcx, fallback_list);
        state.set(Register::Rdx, 3);
        state.set(Register::R8, 1);
        state.set(Register::R9, 0);
        state.set(Register::Rsp, base + 0x6200);
        write_u64(&mut memory, base + 0x6200, 0);
        runtime
            .dispatch_d3d12_graphics_command_list_draw_instanced(&mut memory, &mut state)
            .expect("fallback DrawInstanced");
        assert_eq!(state.get(Register::Rax), 0);

        // Unknown PSO is rejected before any native binding.
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, 0xDEAD);
        runtime
            .dispatch_d3d12_graphics_command_list_set_pipeline_state(&mut memory, &mut state)
            .expect("SetPipelineState unknown");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        // Non-device and null descriptors for placed/reserved resources.
        state.set(Register::Rcx, list);
        let error = runtime
            .dispatch_d3d12_create_placed_resource(&mut memory, &mut state.clone())
            .expect_err("placed non-device");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        state.set(Register::Rcx, device);
        state.set(Register::R9, 0);
        state.set(Register::Rsp, base + 0x6300);
        write_u64(&mut memory, base + 0x6300, 0);
        runtime
            .dispatch_d3d12_create_placed_resource(&mut memory, &mut state)
            .expect("placed null");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        state.set(Register::Rcx, list);
        let error = runtime
            .dispatch_d3d12_create_reserved_resource(&mut memory, &mut state)
            .expect_err("reserved non-device");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        state.set(Register::Rcx, device);
        state.set(Register::R9, 0);
        state.set(Register::Rsp, base + 0x6320);
        write_u64(&mut memory, base + 0x6320, 0);
        runtime
            .dispatch_d3d12_create_reserved_resource(&mut memory, &mut state)
            .expect("reserved null");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        // Graphics PSO creation writes a usable PSO handle.
        let pso_desc_ptr = base + 0x6400;
        let pso_out = base + 0x6440;
        memory.map_bytes(pso_desc_ptr, &[0u8; 16]);
        memory.map_bytes(pso_out, &[0u8; 8]);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, pso_desc_ptr);
        state.set(Register::R9, pso_out);
        runtime
            .dispatch_d3d12_create_graphics_pipeline_state(&mut memory, &mut state)
            .expect("CreateGraphicsPipelineState empty bytecode");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        assert_eq!(memory.read_u64(pso_out).expect("pso handle"), 0);

        // ExecuteIndirect success through the DISPATCH GPU path.
        let dispatch_sig = runtime
            .d3d12_runtime
            .create_command_signature(crate::d3d12::D3D12CommandSignatureDesc {
                byte_stride: 12,
                node_mask: 0,
                arguments: vec![crate::d3d12::D3D12IndirectArgumentDesc {
                    ty: crate::d3d12::D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("dispatch signature");
        let signature_object = runtime
            .alloc_guest_object(
                &mut memory,
                GuestObjectKind::D3d12CommandSignature,
                0x7000_0200,
            )
            .expect("signature object");
        runtime
            .d3d12_command_signature_handles
            .insert(signature_object, dispatch_sig);
        let args_resource = runtime
            .d3d12_runtime
            .create_committed_resource(crate::gfx::ResourceDesc {
                name: "shell-indirect-args".into(),
                format: crate::gfx::DxgiFormat::Unknown,
                heap: crate::gfx::HeapType::Default,
                size: 12,
                subresources: 1,
                initial_state: crate::gfx::ResourceState::Common,
                usage_hint: crate::gfx::ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("args resource");
        runtime
            .d3d12_runtime
            .write_resource_bytes(
                args_resource,
                &[2u32, 1, 1].map(|value| value.to_le_bytes()).concat(),
            )
            .expect("args bytes");
        let args_object = resource_object(&mut runtime, &mut memory, args_resource);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, signature_object);
        state.set(Register::R8, 1);
        state.set(Register::R9, args_object);
        state.set(Register::Rsp, base + 0x6500);
        write_u64(&mut memory, base + 0x6500, 0);
        write_u64(&mut memory, base + 0x6508, 0);
        write_u32(&mut memory, base + 0x6510, 0);
        runtime
            .dispatch_d3d12_graphics_command_list_execute_indirect(&mut memory, &mut state)
            .expect("ExecuteIndirect");
        assert_eq!(state.get(Register::Rax), 0);

        // Build-AS registration consumes mapped guest geometry bytes.
        let build_desc = base + 0x6600;
        let geom_desc = base + 0x6700;
        let vb = base + 0x6800;
        let ib = base + 0x6900;
        memory.map_bytes(build_desc, &[0u8; 64]);
        memory.map_bytes(geom_desc, &[0u8; 48]);
        memory.map_bytes(vb, vertex_bytes);
        memory.map_bytes(ib, &[0u8, 0, 1, 0, 2, 0]);
        write_u64(&mut memory, build_desc, 0x1000);
        write_u32(&mut memory, build_desc + 8, 0);
        write_u32(&mut memory, build_desc + 12, 0);
        write_u32(&mut memory, build_desc + 16, 1);
        write_u64(&mut memory, build_desc + 24, geom_desc);
        write_u64(&mut memory, build_desc + 40, 0x2000);
        write_u32(&mut memory, geom_desc, 0);
        write_u32(&mut memory, geom_desc + 4, 1);
        write_u64(&mut memory, geom_desc + 8, vb);
        write_u64(&mut memory, geom_desc + 16, ib);
        write_u32(&mut memory, geom_desc + 24, 0);
        write_u32(&mut memory, geom_desc + 28, 3);
        write_u32(&mut memory, geom_desc + 32, 57);
        write_u32(&mut memory, geom_desc + 36, 6);
        write_u32(&mut memory, geom_desc + 40, 12);
        write_u32(&mut memory, geom_desc + 44, 1);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, build_desc);
        runtime
            .dispatch_d3d12_graphics_command_list4_build_raytracing_acceleration_structure(
                &mut memory,
                &mut state,
            )
            .expect("BuildRaytracingAccelerationStructure");
        assert_eq!(state.get(Register::Rax), 0);

        // Non-indexed and alternate index-format builds cover every
        // geometry-format branch.
        let non_indexed_desc = base + 0x6e00;
        let non_indexed_geom = base + 0x6e40;
        memory.map_bytes(non_indexed_desc, &[0u8; 64]);
        memory.map_bytes(non_indexed_geom, &[0u8; 48]);
        write_u64(&mut memory, non_indexed_desc, 0x1200);
        write_u32(&mut memory, non_indexed_desc + 8, 0);
        write_u32(&mut memory, non_indexed_desc + 16, 1);
        write_u64(&mut memory, non_indexed_desc + 24, non_indexed_geom);
        write_u64(&mut memory, non_indexed_desc + 40, 0x2200);
        write_u32(&mut memory, non_indexed_geom, 0);
        write_u32(&mut memory, non_indexed_geom + 4, 1);
        write_u64(&mut memory, non_indexed_geom + 8, vb);
        write_u32(&mut memory, non_indexed_geom + 28, 3);
        write_u32(&mut memory, non_indexed_geom + 36, 6);
        write_u32(&mut memory, non_indexed_geom + 40, 12);
        write_u32(&mut memory, non_indexed_geom + 44, 1);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, non_indexed_desc);
        runtime
            .dispatch_d3d12_graphics_command_list4_build_raytracing_acceleration_structure(
                &mut memory,
                &mut state,
            )
            .expect("non-indexed build");
        assert_eq!(state.get(Register::Rax), 0);

        let uint32_desc = base + 0x6f00;
        let uint32_geom = base + 0x6f40;
        let uint32_ib = base + 0x6f80;
        memory.map_bytes(uint32_desc, &[0u8; 64]);
        memory.map_bytes(uint32_geom, &[0u8; 48]);
        memory.map_bytes(uint32_ib, &[0u8; 12]);
        write_u64(&mut memory, uint32_desc, 0x1300);
        write_u32(&mut memory, uint32_desc + 8, 0);
        write_u32(&mut memory, uint32_desc + 16, 1);
        write_u64(&mut memory, uint32_desc + 24, uint32_geom);
        write_u64(&mut memory, uint32_desc + 40, 0x2300);
        write_u32(&mut memory, uint32_geom, 0);
        write_u32(&mut memory, uint32_geom + 4, 1);
        write_u64(&mut memory, uint32_geom + 8, vb);
        write_u64(&mut memory, uint32_geom + 16, uint32_ib);
        write_u32(&mut memory, uint32_geom + 28, 3);
        write_u32(&mut memory, uint32_geom + 32, 42);
        write_u32(&mut memory, uint32_geom + 36, 6);
        write_u32(&mut memory, uint32_geom + 40, 12);
        write_u32(&mut memory, uint32_geom + 44, 1);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, uint32_desc);
        runtime
            .dispatch_d3d12_graphics_command_list4_build_raytracing_acceleration_structure(
                &mut memory,
                &mut state,
            )
            .expect("uint32 index build");
        assert_eq!(state.get(Register::Rax), 0);

        let unsupported_index_desc = base + 0x7000;
        let unsupported_index_geom = base + 0x7040;
        memory.map_bytes(unsupported_index_desc, &[0u8; 64]);
        memory.map_bytes(unsupported_index_geom, &[0u8; 48]);
        write_u64(&mut memory, unsupported_index_desc, 0x1400);
        write_u32(&mut memory, unsupported_index_desc + 8, 0);
        write_u32(&mut memory, unsupported_index_desc + 16, 1);
        write_u64(
            &mut memory,
            unsupported_index_desc + 24,
            unsupported_index_geom,
        );
        write_u64(&mut memory, unsupported_index_desc + 40, 0x2400);
        write_u32(&mut memory, unsupported_index_geom, 0);
        write_u32(&mut memory, unsupported_index_geom + 4, 1);
        write_u64(&mut memory, unsupported_index_geom + 8, vb);
        write_u64(&mut memory, unsupported_index_geom + 16, ib);
        write_u32(&mut memory, unsupported_index_geom + 28, 3);
        write_u32(&mut memory, unsupported_index_geom + 32, 0);
        write_u32(&mut memory, unsupported_index_geom + 36, 6);
        write_u32(&mut memory, unsupported_index_geom + 40, 12);
        write_u32(&mut memory, unsupported_index_geom + 44, 1);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, unsupported_index_desc);
        let error = runtime
            .dispatch_d3d12_graphics_command_list4_build_raytracing_acceleration_structure(
                &mut memory,
                &mut state,
            )
            .expect_err("unsupported index format");
        assert_eq!(
            error.message,
            "geometry 0 index format 0 is not supported for raytracing"
        );

        // TLAS registration consumes mapped instance descriptors.
        let tlas_desc = base + 0x7100;
        let instance_desc = base + 0x7140;
        memory.map_bytes(tlas_desc, &[0u8; 64]);
        memory.map_bytes(instance_desc, &[0u8; 64]);
        write_u64(&mut memory, tlas_desc, 0x3000);
        write_u32(&mut memory, tlas_desc + 8, 1);
        write_u32(&mut memory, tlas_desc + 12, 2);
        write_u32(&mut memory, tlas_desc + 16, 1);
        write_u64(&mut memory, tlas_desc + 24, instance_desc);
        write_u64(&mut memory, tlas_desc + 40, 0x4000);
        write_u32(&mut memory, instance_desc + 48, 0xFF00_0000);
        write_u64(&mut memory, instance_desc + 56, 0x1000);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, tlas_desc);
        runtime
            .dispatch_d3d12_graphics_command_list4_build_raytracing_acceleration_structure(
                &mut memory,
                &mut state,
            )
            .expect("TLAS build");
        assert_eq!(state.get(Register::Rax), 0);

        // DispatchRays registers mapped shader-table bytes before failing
        // on the missing top-level structure.
        let rays_desc = base + 0x6a00;
        let raygen = base + 0x6b00;
        let hit = base + 0x6c00;
        memory.map_bytes(rays_desc, &[0u8; 100]);
        memory.map_bytes(raygen, &[0u8; 40]);
        memory.map_bytes(hit, &[7u8, 0, 0, 0]);
        write_u64(&mut memory, rays_desc, raygen);
        write_u64(&mut memory, rays_desc + 8, 40);
        write_u64(&mut memory, rays_desc + 40, hit);
        write_u64(&mut memory, rays_desc + 48, 4);
        write_u64(&mut memory, rays_desc + 56, 4);
        write_u32(&mut memory, rays_desc + 88, 1);
        write_u32(&mut memory, rays_desc + 92, 1);
        write_u32(&mut memory, rays_desc + 96, 1);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, rays_desc);
        runtime
            .dispatch_d3d12_graphics_command_list4_dispatch_rays(&mut memory, &mut state)
            .expect("DispatchRays");
        assert_eq!(state.get(Register::Rax), 0);

        // Unsupported command-signature argument type maps to E_NOTIMPL.
        let bad_sig_desc = base + 0x6d00;
        let bad_arg = base + 0x6d40;
        let bad_out = base + 0x6d80;
        memory.map_bytes(bad_sig_desc, &[0u8; 32]);
        memory.map_bytes(bad_arg, &[0u8; 16]);
        memory.map_bytes(bad_out, &[0u8; 8]);
        write_u32(&mut memory, bad_sig_desc, 4);
        write_u32(&mut memory, bad_sig_desc + 4, 1);
        write_u64(&mut memory, bad_sig_desc + 8, bad_arg);
        write_u32(&mut memory, bad_arg, 99);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, bad_sig_desc);
        state.set(Register::R8, bad_out);
        runtime
            .dispatch_d3d12_create_command_signature(&mut memory, &mut state)
            .expect("CreateCommandSignature unsupported");
        assert_eq!(state.get(Register::Rax), E_NOTIMPL);

        // Swapchain backbuffer allocation retains guest dimensions.
        let swapchain_id = runtime
            .d3d12_runtime
            .create_swapchain(crate::gfx::SwapchainDesc {
                width: 8,
                height: 6,
                format: crate::gfx::DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("swapchain");
        let swapchain_object = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::DxgiSwapChain, 0x7000_0300)
            .expect("swapchain object");
        runtime.d3d12_swapchains.insert(
            swapchain_object,
            super::state::GuestD3d12SwapChain {
                device_object: device,
                swapchain_id,
                backbuffer_objects: std::collections::BTreeMap::new(),
            },
        );
        let backbuffer = runtime
            .ensure_d3d12_backbuffer_object(&mut memory, swapchain_object, 0)
            .expect("backbuffer object");
        let backbuffer_resource = runtime
            .d3d12_resource(backbuffer)
            .expect("backbuffer resource");
        assert_eq!(
            (backbuffer_resource.width, backbuffer_resource.height),
            (8, 6)
        );
    });
}

#[test]
fn d3d12_set_program_and_dispatch_graph_validate_real_vtables() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-workgraph-com",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x60_0000;
        memory.map_bytes(base, &vec![0u8; 0x20000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let device_vtable = memory.read_u64(device).expect("device vtable");
        let create_state_object = memory
            .read_u64(device_vtable + 61 * 8)
            .expect("CreateStateObject");
        let desc = build_work_graph_state_object_desc(&mut memory, base + 0x1000);
        let iid = base + 0x8800;
        memory.map_bytes(iid, &[0u8; 16]);
        let iid_bytes: [u8; 16] = [
            0x43, 0x69, 0x01, 0x47, 0xa8, 0xfc, 0x94, 0x45, 0x93, 0xea, 0xaf, 0x25, 0x8b, 0x55,
            0x34, 0x6d,
        ];
        for (index, byte) in iid_bytes.iter().enumerate() {
            memory.write_u8(iid + index as u64, *byte);
        }
        let out = base + 0x8900;
        memory.map_bytes(out, &[0u8; 8]);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, base + 0x100);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, desc);
        state.set(Register::R8, iid);
        state.set(Register::R9, out);
        memory.write_u64(base + 0x100, 0x1000_0100);
        runtime
            .dispatch_import(create_state_object, &mut state, &mut memory)
            .expect("create work graph state object");
        assert_eq!(state.get(Register::Rax), 0);
        let state_object = memory.read_u64(out).expect("state object");
        let handle = runtime.d3d12_state_object_handles[&state_object];
        let identifier = runtime
            .d3d12_runtime
            .work_graph_program_identifier(handle, "graph")
            .expect("program identifier");

        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x2000, device);
        let list_vtable = memory.read_u64(list).expect("list vtable");
        let set_program = memory.read_u64(list_vtable + 73 * 8).expect("SetProgram");
        let dispatch_graph = memory
            .read_u64(list_vtable + 74 * 8)
            .expect("DispatchGraph");
        assert_ne!(set_program, 0);
        assert_ne!(dispatch_graph, 0);

        // The COM object must answer QueryInterface for
        // ID3D12GraphicsCommandList10, and reject unrelated IIDs.
        let list_qi = memory.read_u64(list_vtable).expect("list QI");
        let iid_cl10 = base + 0x8700;
        memory.map_bytes(iid_cl10, &[0u8; 16]);
        let cl10_iid: [u8; 16] = [
            0x15, 0xc0, 0x13, 0x70, 0x61, 0xd1, 0x63, 0x4b, 0xa0, 0x8c, 0x23, 0x85, 0x52, 0xdd,
            0x8a, 0xcc,
        ];
        for (index, byte) in cl10_iid.iter().enumerate() {
            memory.write_u8(iid_cl10 + index as u64, *byte);
        }
        let cl_qi_out = base + 0x8710;
        memory.map_bytes(cl_qi_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x120);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, iid_cl10);
        state.set(Register::R8, cl_qi_out);
        memory.write_u64(base + 0x120, 0x1000_0100_1);
        runtime
            .dispatch_import(list_qi, &mut state, &mut memory)
            .expect("CL10 QI");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(memory.read_u64(cl_qi_out).expect("CL10 QI ptr"), list);
        let bad_cl_iid = base + 0x8720;
        memory.map_bytes(bad_cl_iid, &[0xCC; 16]);
        state.set(Register::Rsp, base + 0x130);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, bad_cl_iid);
        state.set(Register::R8, cl_qi_out);
        memory.write_u64(base + 0x130, 0x1000_0100_2);
        runtime
            .dispatch_import(list_qi, &mut state, &mut memory)
            .expect("CL10 bad QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);

        // DispatchGraph before SetProgram is an exact error.
        let graph_desc = base + 0x3000;
        memory.map_bytes(graph_desc, &[0u8; 0x100]);
        write_u32(&mut memory, graph_desc, 0); // NODE_CPU_INPUT
        write_u32(&mut memory, graph_desc + 8, 0);
        write_u32(&mut memory, graph_desc + 12, 1);
        write_u64(&mut memory, graph_desc + 16, base + 0x3100);
        write_u64(&mut memory, graph_desc + 24, 8);
        memory.map_bytes(base + 0x3100, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, graph_desc);
        memory.write_u64(base + 0x140, 0x1000_0101);
        runtime
            .dispatch_import(dispatch_graph, &mut state, &mut memory)
            .expect("dispatch before SetProgram");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        // Unknown program identifier is rejected.
        let set_desc = base + 0x3200;
        memory.map_bytes(set_desc, &[0u8; 0x80]);
        write_u32(&mut memory, set_desc, 5); // WORK_GRAPH
        for index in 0..32u64 {
            memory.write_u8(set_desc + 8 + index, 0xAB);
        }
        state.set(Register::Rsp, base + 0x180);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, set_desc);
        memory.write_u64(base + 0x180, 0x1000_0102);
        runtime
            .dispatch_import(set_program, &mut state, &mut memory)
            .expect("SetProgram unknown id");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        // Non-work-graph program type fails closed.
        write_u32(&mut memory, set_desc, 1);
        state.set(Register::Rsp, base + 0x1c0);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, set_desc);
        memory.write_u64(base + 0x1c0, 0x1000_0103);
        runtime
            .dispatch_import(set_program, &mut state, &mut memory)
            .expect("SetProgram unsupported type");
        assert_eq!(state.get(Register::Rax), E_NOTIMPL);

        // Valid SetProgram then DispatchGraph records a compute command.
        write_u32(&mut memory, set_desc, 5);
        for (index, byte) in identifier.iter().enumerate() {
            memory.write_u8(set_desc + 8 + index as u64, *byte);
        }
        write_u32(&mut memory, set_desc + 40, 0);
        write_u64(&mut memory, set_desc + 48, 0);
        write_u64(&mut memory, set_desc + 56, 0);
        state.set(Register::Rsp, base + 0x200);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, set_desc);
        memory.write_u64(base + 0x200, 0x1000_0104);
        runtime
            .dispatch_import(set_program, &mut state, &mut memory)
            .expect("SetProgram valid");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rsp, base + 0x240);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, graph_desc);
        memory.write_u64(base + 0x240, 0x1000_0105);
        runtime
            .dispatch_import(dispatch_graph, &mut state, &mut memory)
            .expect("DispatchGraph valid");
        assert_eq!(state.get(Register::Rax), 0);
        let command_list_id = runtime
            .d3d12_command_lists
            .get(&list)
            .and_then(|record| record.command_list_id)
            .expect("command list id");
        let stream = runtime
            .d3d12_runtime
            .close_command_list(command_list_id)
            .expect("close command list");
        assert_eq!(stream.commands.len(), 1);
        assert!(matches!(
            stream.commands[0],
            crate::gfx::Command::Dispatch { x: 1, y: 1, z: 1 }
        ));

        // GPU-record dispatch mode with zero records is a valid no-work
        // dispatch; the previous E_NOTIMPL gate is gone.
        let gpu_list =
            create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x4000, device);
        let gpu_vtable = memory.read_u64(gpu_list).expect("gpu list vtable");
        let gpu_set_program = memory.read_u64(gpu_vtable + 73 * 8).expect("SetProgram");
        let gpu_dispatch_graph = memory.read_u64(gpu_vtable + 74 * 8).expect("DispatchGraph");
        state.set(Register::Rsp, base + 0x280);
        state.set(Register::Rcx, gpu_list);
        state.set(Register::Rdx, set_desc);
        memory.write_u64(base + 0x280, 0x1000_0106);
        runtime
            .dispatch_import(gpu_set_program, &mut state, &mut memory)
            .expect("SetProgram for GPU mode test");
        assert_eq!(state.get(Register::Rax), 0);
        let gpu_desc = base + 0x3300;
        memory.map_bytes(gpu_desc, &[0u8; 0x80]);
        write_u32(&mut memory, gpu_desc, 1); // NODE_GPU_INPUT
        state.set(Register::Rsp, base + 0x2c0);
        state.set(Register::Rcx, gpu_list);
        state.set(Register::Rdx, gpu_desc);
        memory.write_u64(base + 0x2c0, 0x1000_0107);
        runtime
            .dispatch_import(gpu_dispatch_graph, &mut state, &mut memory)
            .expect("GPU DispatchGraph");
        assert_eq!(state.get(Register::Rax), 0);
    });
}

#[test]
fn d3d12_dml_com_surface_create_compile_bind_record_and_execute() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "dml-com", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x70_0000;
        memory.map_bytes(base, &vec![0u8; 0x30000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);

        let iid_device = base + 0x8000;
        memory.map_bytes(iid_device, &crate::d3d12::directml::IID_IDMLDEVICE.0);
        let dml_out = base + 0x8010;
        memory.map_bytes(dml_out, &[0u8; 8]);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, base + 0x100);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, iid_device);
        state.set(Register::R9, dml_out);
        memory.write_u64(base + 0x100, 0x1000_0200);
        let create_dml = runtime.alloc_host_thunk(HostThunk::DMLCreateDevice);
        runtime
            .dispatch_import(create_dml, &mut state, &mut memory)
            .expect("DMLCreateDevice");
        assert_eq!(state.get(Register::Rax), 0);
        let dml_device = memory.read_u64(dml_out).expect("DML device");
        assert_eq!(
            runtime.guest_object_kind(dml_device).expect("dml kind"),
            GuestObjectKind::DmlDevice
        );

        let dml_vtable = memory.read_u64(dml_device).expect("DML vtable");
        let query_interface = memory.read_u64(dml_vtable).expect("QI");
        let create_operator = memory.read_u64(dml_vtable + 8 * 8).expect("CreateOperator");
        let compile_operator = memory
            .read_u64(dml_vtable + 9 * 8)
            .expect("CompileOperator");
        let create_initializer = memory
            .read_u64(dml_vtable + 10 * 8)
            .expect("CreateOperatorInitializer");
        let create_recorder = memory
            .read_u64(dml_vtable + 11 * 8)
            .expect("CreateCommandRecorder");
        let create_binding_table = memory
            .read_u64(dml_vtable + 12 * 8)
            .expect("CreateBindingTable");

        // QueryInterface: DMLCreateDevice returns IDMLDevice, not
        // IDMLDevice1; the latter must fail with E_NOINTERFACE.
        let qi_out = base + 0x8030;
        memory.map_bytes(qi_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, iid_device);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x140, 0x1000_0201);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("DML QI");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(memory.read_u64(qi_out).expect("DML QI pointer"), dml_device);

        let iid_device1 = base + 0x8020;
        memory.map_bytes(iid_device1, &crate::d3d12::directml::IID_IDMLDEVICE1.0);
        state.set(Register::Rsp, base + 0x160);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, iid_device1);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x160, 0x1000_0201_1);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("DML Device1 QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);
        assert_eq!(memory.read_u64(qi_out).expect("DML Device1 pointer"), 0);
        let bad_iid = base + 0x8040;
        memory.map_bytes(bad_iid, &crate::d3d12::directml::IID_IDMLOPERATOR.0);
        state.set(Register::Rsp, base + 0x180);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, bad_iid);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x180, 0x1000_0202);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("DML bad QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);
        assert_eq!(memory.read_u64(qi_out).expect("failed QI"), 0);

        // Null IID is E_POINTER.
        state.set(Register::Rsp, base + 0x1a0);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x1a0, 0x1000_0202_1);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("DML null QI");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_POINTER as u64
        );

        // Release the QI reference.
        let dml_release = memory.read_u64(dml_vtable + 16).expect("Release");
        state.set(Register::Rsp, base + 0x1c0);
        state.set(Register::Rcx, dml_device);
        memory.write_u64(base + 0x1c0, 0x1000_0203);
        runtime
            .dispatch_import(dml_release, &mut state, &mut memory)
            .expect("DML release QI");

        // CreateOperator (real descriptor parsing), then CompileOperator.
        let iid_operator = base + 0x8050;
        memory.map_bytes(iid_operator, &crate::d3d12::directml::IID_IDMLOPERATOR.0);
        let operator_out = base + 0x8060;
        memory.map_bytes(operator_out, &[0u8; 8]);
        let operator_desc = build_dml_identity_operator(&mut memory, base + 0x1000);
        state.set(Register::Rsp, base + 0x200);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, operator_desc);
        state.set(Register::R8, iid_operator);
        state.set(Register::R9, operator_out);
        memory.write_u64(base + 0x200, 0x1000_0204);
        runtime
            .dispatch_import(create_operator, &mut state, &mut memory)
            .expect("CreateOperator");
        assert_eq!(state.get(Register::Rax), 0);
        let operator = memory.read_u64(operator_out).expect("operator");
        assert_eq!(
            runtime.guest_object_kind(operator).expect("operator kind"),
            GuestObjectKind::DmlOperator
        );

        // Unsupported operator type must return E_INVALIDARG.
        let bad_operator = base + 0x1200;
        write_u32(&mut memory, bad_operator, 9999);
        write_u64(&mut memory, bad_operator + 8, bad_operator + 0x40);
        state.set(Register::Rsp, base + 0x240);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, bad_operator);
        state.set(Register::R8, iid_operator);
        state.set(Register::R9, operator_out);
        memory.write_u64(base + 0x240, 0x1000_0205);
        runtime
            .dispatch_import(create_operator, &mut state, &mut memory)
            .expect("unsupported CreateOperator");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // Null operator descriptor is E_POINTER.
        state.set(Register::Rsp, base + 0x280);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, iid_operator);
        state.set(Register::R9, operator_out);
        memory.write_u64(base + 0x280, 0x1000_0206);
        runtime
            .dispatch_import(create_operator, &mut state, &mut memory)
            .expect("null CreateOperator");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_POINTER as u64
        );

        let iid_compiled = base + 0x8070;
        memory.map_bytes(
            iid_compiled,
            &crate::d3d12::directml::IID_IDMLCOMPILEDOPERATOR.0,
        );
        let compiled_out = base + 0x8080;
        memory.map_bytes(compiled_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x2c0);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, operator);
        state.set(Register::R8, 0);
        state.set(Register::R9, iid_compiled);
        memory.write_u64(base + 0x2c0, 0x1000_0207);
        memory.write_u64(base + 0x2c0 + 0x28, compiled_out);
        runtime
            .dispatch_import(compile_operator, &mut state, &mut memory)
            .expect("CompileOperator");
        assert_eq!(state.get(Register::Rax), 0);
        let compiled = memory.read_u64(compiled_out).expect("compiled");
        assert_eq!(
            runtime.guest_object_kind(compiled).expect("compiled kind"),
            GuestObjectKind::DmlCompiledOperator
        );

        // Compile failure for an object that is not an operator.
        state.set(Register::Rsp, base + 0x300);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, dml_device);
        state.set(Register::R8, 0);
        state.set(Register::R9, iid_compiled);
        memory.write_u64(base + 0x300, 0x1000_0208);
        memory.write_u64(base + 0x300 + 0x28, compiled_out);
        runtime
            .dispatch_import(compile_operator, &mut state, &mut memory)
            .expect("invalid CompileOperator");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // GetBindingProperties on the compiled operator.
        let compiled_vtable = memory.read_u64(compiled).expect("compiled vtable");
        let get_properties = memory
            .read_u64(compiled_vtable + 8 * 8)
            .expect("GetBindingProperties");
        let properties = base + 0x8090;
        memory.map_bytes(properties, &[0u8; 24]);
        state.set(Register::Rsp, base + 0x340);
        state.set(Register::Rcx, compiled);
        state.set(Register::Rdx, properties);
        memory.write_u64(base + 0x340, 0x1000_0209);
        runtime
            .dispatch_import(get_properties, &mut state, &mut memory)
            .expect("GetBindingProperties");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime_read_u32(&memory, properties), 2);

        // Initializer creation and reset.
        let iid_initializer = base + 0x80a0;
        memory.map_bytes(
            iid_initializer,
            &crate::d3d12::directml::IID_IDMLOPERATORINITIALIZER.0,
        );
        let initializer_out = base + 0x80b0;
        memory.map_bytes(initializer_out, &[0u8; 8]);
        let operator_array = base + 0x80c0;
        memory.map_bytes(operator_array, &[0u8; 8]);
        memory.write_u64(operator_array, compiled);
        state.set(Register::Rsp, base + 0x380);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, operator_array);
        state.set(Register::R9, iid_initializer);
        memory.write_u64(base + 0x380, 0x1000_020a);
        memory.write_u64(base + 0x380 + 0x28, initializer_out);
        runtime
            .dispatch_import(create_initializer, &mut state, &mut memory)
            .expect("CreateOperatorInitializer");
        assert_eq!(state.get(Register::Rax), 0);
        let initializer = memory.read_u64(initializer_out).expect("initializer");
        let initializer_vtable = memory.read_u64(initializer).expect("initializer vtable");
        let reset = memory
            .read_u64(initializer_vtable + 9 * 8)
            .expect("initializer Reset");
        state.set(Register::Rsp, base + 0x3c0);
        state.set(Register::Rcx, initializer);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, operator_array);
        memory.write_u64(base + 0x3c0, 0x1000_020b);
        runtime
            .dispatch_import(reset, &mut state, &mut memory)
            .expect("initializer Reset");
        assert_eq!(state.get(Register::Rax), 0);

        // Command recorder and binding table.
        let iid_recorder = base + 0x80d0;
        memory.map_bytes(
            iid_recorder,
            &crate::d3d12::directml::IID_IDMLCOMMANDRECORDER.0,
        );
        let recorder_out = base + 0x80e0;
        memory.map_bytes(recorder_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x400);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, iid_recorder);
        state.set(Register::R8, recorder_out);
        memory.write_u64(base + 0x400, 0x1000_020c);
        runtime
            .dispatch_import(create_recorder, &mut state, &mut memory)
            .expect("CreateCommandRecorder");
        assert_eq!(state.get(Register::Rax), 0);
        let recorder = memory.read_u64(recorder_out).expect("recorder");

        let iid_table = base + 0x80f0;
        memory.map_bytes(iid_table, &crate::d3d12::directml::IID_IDMLBINDINGTABLE.0);
        let table_desc = base + 0x9000;
        memory.map_bytes(table_desc, &[0u8; 32]);
        write_u64(&mut memory, table_desc, compiled);
        write_u32(&mut memory, table_desc + 24, 2);
        let table_out = base + 0x8100;
        memory.map_bytes(table_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x440);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, table_desc);
        state.set(Register::R8, iid_table);
        state.set(Register::R9, table_out);
        memory.write_u64(base + 0x440, 0x1000_020d);
        runtime
            .dispatch_import(create_binding_table, &mut state, &mut memory)
            .expect("CreateBindingTable");
        assert_eq!(state.get(Register::Rax), 0);
        let table = memory.read_u64(table_out).expect("binding table");

        // Null binding-table descriptor is rejected.
        state.set(Register::Rsp, base + 0x460);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, iid_table);
        state.set(Register::R9, table_out);
        memory.write_u64(base + 0x460, 0x1000_020e);
        runtime
            .dispatch_import(create_binding_table, &mut state, &mut memory)
            .expect("null CreateBindingTable");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // Create two D3D12 resources to bind.
        let resource_desc = base + 0x9200;
        memory.map_bytes(resource_desc, &[0u8; 48]);
        write_u32(&mut memory, resource_desc, 28); // DXGI_FORMAT_R8G8B8A8_UNORM
        write_u32(&mut memory, resource_desc + 4, 2); // TEXTURE2D
        write_u64(&mut memory, resource_desc + 8, 16);
        write_u32(&mut memory, resource_desc + 16, 1);
        write_u16(&mut memory, resource_desc + 20, 1);
        write_u16(&mut memory, resource_desc + 24, 1);
        write_u32(&mut memory, resource_desc + 28, 1);
        write_u32(&mut memory, resource_desc + 32, 0);
        let create_resource = memory
            .read_u64(memory.read_u64(device).expect("device vtable") + 24 * 8)
            .expect("CreateCommittedResource");
        let resource_a_out = base + 0x8110;
        let resource_b_out = base + 0x8118;
        memory.map_bytes(resource_a_out, &[0u8; 8]);
        memory.map_bytes(resource_b_out, &[0u8; 8]);
        for (slot, out) in [(0x480u64, resource_a_out), (0x4c0, resource_b_out)] {
            state.set(Register::Rsp, base + slot);
            state.set(Register::Rcx, device);
            state.set(Register::Rdx, 0);
            state.set(Register::R8, 0);
            state.set(Register::R9, resource_desc);
            memory.write_u64(base + slot, 0x1000_0210 + slot);
            write_u32(&mut memory, base + slot + 0x28, 0);
            memory.write_u64(base + slot + 0x30, 0);
            memory.write_u64(base + slot + 0x38, out);
            runtime
                .dispatch_import(create_resource, &mut state, &mut memory)
                .expect("CreateCommittedResource");
            assert_eq!(state.get(Register::Rax), 0);
        }
        let resource_a = memory.read_u64(resource_a_out).expect("resource A");
        let resource_b = memory.read_u64(resource_b_out).expect("resource B");

        let buffer_binding_a = base + 0x9300;
        let buffer_binding_b = base + 0x9320;
        let bindings_a = base + 0x9400;
        let bindings_b = base + 0x9420;
        for (binding, resource) in [
            (buffer_binding_a, resource_a),
            (buffer_binding_b, resource_b),
        ] {
            write_u64(&mut memory, binding, resource);
            write_u64(&mut memory, binding + 8, 0);
            write_u64(&mut memory, binding + 16, 8);
        }
        for (desc, binding) in [
            (bindings_a, buffer_binding_a),
            (bindings_b, buffer_binding_b),
        ] {
            write_u32(&mut memory, desc, 1); // DML_BINDING_TYPE_BUFFER
            write_u64(&mut memory, desc + 8, binding);
        }
        let table_vtable = memory.read_u64(table).expect("table vtable");
        let bind_inputs = memory.read_u64(table_vtable + 8 * 8).expect("BindInputs");
        let bind_outputs = memory.read_u64(table_vtable + 9 * 8).expect("BindOutputs");
        state.set(Register::Rsp, base + 0x500);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, bindings_a);
        memory.write_u64(base + 0x500, 0x1000_0220);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("BindInputs");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rsp, base + 0x540);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, bindings_b);
        memory.write_u64(base + 0x540, 0x1000_0221);
        runtime
            .dispatch_import(bind_outputs, &mut state, &mut memory)
            .expect("BindOutputs");
        assert_eq!(state.get(Register::Rax), 0);

        // Null binding array with a non-zero count is E_INVALIDARG.
        state.set(Register::Rsp, base + 0x560);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, 0);
        memory.write_u64(base + 0x560, 0x1000_0221_1);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("null BindInputs");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // Unsupported BUFFER_ARRAY binding fails closed.
        let bad_binding = base + 0x9500;
        write_u32(&mut memory, bad_binding, 2);
        write_u64(&mut memory, bad_binding + 8, buffer_binding_a);
        state.set(Register::Rsp, base + 0x580);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, bad_binding);
        memory.write_u64(base + 0x580, 0x1000_0222);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("unsupported BindInputs");
        assert_eq!(state.get(Register::Rax), E_NOTIMPL);

        // RecordDispatch through the real command recorder vtable.
        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x6000, device);
        let recorder_vtable = memory.read_u64(recorder).expect("recorder vtable");
        let record_dispatch = memory
            .read_u64(recorder_vtable + 8 * 8)
            .expect("RecordDispatch");
        state.set(Register::Rsp, base + 0x5c0);
        state.set(Register::Rcx, recorder);
        state.set(Register::Rdx, list);
        state.set(Register::R8, compiled);
        state.set(Register::R9, table);
        memory.write_u64(base + 0x5c0, 0x1000_0223);
        runtime
            .dispatch_import(record_dispatch, &mut state, &mut memory)
            .expect("RecordDispatch");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.d3d12_runtime.directml().dispatches().len(), 1);

        // Null binding table is rejected.
        state.set(Register::Rsp, base + 0x600);
        state.set(Register::Rcx, recorder);
        state.set(Register::Rdx, list);
        state.set(Register::R8, compiled);
        state.set(Register::R9, 0);
        memory.write_u64(base + 0x600, 0x1000_0224);
        runtime
            .dispatch_import(record_dispatch, &mut state, &mut memory)
            .expect("null RecordDispatch");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // One real Metal elementwise execution through the compiled
        // operator (identity on two FLOAT32 values).
        let compiled_handle = runtime.dml_object_handles[&compiled];
        let input = [1.5f32.to_le_bytes(), (-2.5f32).to_le_bytes()].concat();
        let mut output = [0u8; 8];
        runtime
            .d3d12_runtime
            .directml()
            .execute_elementwise(compiled_handle, &[&input], &mut output)
            .expect("real DirectML Metal execution");
        assert_eq!(output.as_slice(), input.as_slice());

        // Release the whole COM hierarchy; device refcounts must unwind.
        for object in [table, recorder, initializer, compiled, operator, dml_device] {
            let vtable = memory.read_u64(object).expect("object vtable");
            let release = memory.read_u64(vtable + 16).expect("Release");
            state.set(Register::Rsp, base + 0x640);
            state.set(Register::Rcx, object);
            memory.write_u64(base + 0x640, 0x1000_0230);
            runtime
                .dispatch_import(release, &mut state, &mut memory)
                .expect("release DML object");
        }
        assert!(runtime.dml_object_handles.is_empty());
    });
}

#[test]
fn d3d12_dml_create_device1_feature_level_and_device1_query_interface() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "dml-device1", GeArch::X64, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x70_0000;
        memory.map_bytes(base, &vec![0u8; 0x20000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let iid = base + 0x8000;
        memory.map_bytes(iid, &crate::d3d12::directml::IID_IDMLDEVICE.0);
        let out = base + 0x8010;
        memory.map_bytes(out, &[0u8; 8]);
        let create_dml1 = runtime.alloc_host_thunk(HostThunk::DMLCreateDevice1);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, base + 0x100);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(
            Register::R8,
            crate::d3d12::directml::DML_FEATURE_LEVEL_6_4 as u64,
        );
        state.set(Register::R9, iid);
        memory.write_u64(base + 0x100, 0x1000_0300);
        memory.write_u64(base + 0x100 + 0x28, out);
        runtime
            .dispatch_import(create_dml1, &mut state, &mut memory)
            .expect("DMLCreateDevice1 unsupported level");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::DXGI_ERROR_UNSUPPORTED as u64
        );
        state.set(Register::Rsp, base + 0x100);
        state.set(
            Register::R8,
            crate::d3d12::directml::DML_FEATURE_LEVEL_1_0 as u64,
        );
        state.set(Register::R9, iid);
        memory.write_u64(base + 0x100 + 0x28, out);
        runtime
            .dispatch_import(create_dml1, &mut state, &mut memory)
            .expect("DMLCreateDevice1");
        assert_eq!(state.get(Register::Rax), 0);
        let dml_device = memory.read_u64(out).expect("device1 object");
        assert!(runtime.dml_device1_objects.contains(&dml_device));
        let vtable = memory.read_u64(dml_device).expect("device1 vtable");
        let query_interface = memory.read_u64(vtable).expect("QI");
        let iid_device1 = base + 0x8020;
        memory.map_bytes(iid_device1, &crate::d3d12::directml::IID_IDMLDEVICE1.0);
        let qi_out = base + 0x8030;
        memory.map_bytes(qi_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, iid_device1);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x140, 0x1000_0301);
        runtime
            .dispatch_import(query_interface, &mut state, &mut memory)
            .expect("Device1 QI");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(memory.read_u64(qi_out).expect("Device1 QI ptr"), dml_device);
    });
}

#[test]
fn d3d12_dml_dispatch_error_paths_and_object_methods_are_pinned() {
    use crate::d3d12::directml;
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "dml-dispatch-errors",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x78_0000;
        memory.map_bytes(base, &vec![0u8; 0x30000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x1000, device);
        let mut state = CpuState::new(GuestArch::X64);
        let create_dml = runtime.alloc_host_thunk(HostThunk::DMLCreateDevice);
        let iid_device = base + 0x8000;
        memory.map_bytes(iid_device, &crate::d3d12::directml::IID_IDMLDEVICE.0);
        let dml_out = base + 0x8010;
        memory.map_bytes(dml_out, &[0u8; 8]);
        let bad_parent = 0x1234u64;
        for (parent, iid_ptr, flags, out_ptr, expected) in [
            (
                bad_parent,
                iid_device,
                0,
                dml_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                device,
                0,
                0,
                dml_out,
                crate::d3d12::directml::E_POINTER as u64,
            ),
            (device, base + 0x8020, 0, dml_out, E_NOINTERFACE),
            (
                device,
                iid_device,
                0x8,
                dml_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                device,
                iid_device,
                0,
                0,
                crate::d3d12::directml::E_POINTER as u64,
            ),
        ] {
            memory.map_bytes(base + 0x8020, &[0xAA; 16]);
            state.set(Register::Rsp, base + 0x100);
            state.set(Register::Rcx, parent);
            state.set(Register::Rdx, flags);
            state.set(Register::R8, iid_ptr);
            state.set(Register::R9, out_ptr);
            memory.write_u64(base + 0x100, 0x1000_0800);
            runtime
                .dispatch_import(create_dml, &mut state, &mut memory)
                .expect("DMLCreateDevice error path");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, iid_device);
        state.set(Register::R9, dml_out);
        memory.write_u64(base + 0x140, 0x1000_0801);
        runtime
            .dispatch_import(create_dml, &mut state, &mut memory)
            .expect("DMLCreateDevice success");
        assert_eq!(state.get(Register::Rax), 0);
        let dml_device = memory.read_u64(dml_out).expect("DML device");
        let dml_vtable = memory.read_u64(dml_device).expect("DML vtable");
        let _query_interface = memory.read_u64(dml_vtable).expect("QI");
        let create_operator = memory.read_u64(dml_vtable + 8 * 8).expect("CreateOperator");
        let compile_operator = memory
            .read_u64(dml_vtable + 9 * 8)
            .expect("CompileOperator");
        let create_initializer = memory
            .read_u64(dml_vtable + 10 * 8)
            .expect("CreateOperatorInitializer");
        let create_recorder = memory
            .read_u64(dml_vtable + 11 * 8)
            .expect("CreateCommandRecorder");
        let create_binding_table = memory
            .read_u64(dml_vtable + 12 * 8)
            .expect("CreateBindingTable");
        let get_parent_device = memory
            .read_u64(dml_vtable + 16 * 8)
            .expect("GetParentDevice");
        let check_feature = memory
            .read_u64(dml_vtable + 7 * 8)
            .expect("CheckFeatureSupport");
        let iid_operator = base + 0x8100;
        memory.map_bytes(iid_operator, &crate::d3d12::directml::IID_IDMLOPERATOR.0);
        let operator_desc = build_dml_identity_operator(&mut memory, base + 0x2000);
        let operator_out = base + 0x8110;
        memory.map_bytes(operator_out, &[0u8; 8]);
        for (device_obj, desc, iid_ptr, out_ptr, expected) in [
            (
                device,
                operator_desc,
                iid_operator,
                0,
                crate::d3d12::directml::E_POINTER as u64,
            ),
            (
                device,
                operator_desc,
                base + 0x8120,
                operator_out,
                E_NOINTERFACE,
            ),
            (dml_device, operator_desc, iid_operator, operator_out, 0),
        ] {
            memory.map_bytes(base + 0x8120, &[0xBB; 16]);
            state.set(Register::Rsp, base + 0x180);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, desc);
            state.set(Register::R8, iid_ptr);
            state.set(Register::R9, out_ptr);
            memory.write_u64(base + 0x180, 0x1000_0802);
            runtime
                .dispatch_import(create_operator, &mut state, &mut memory)
                .expect("CreateOperator");
            assert_eq!(state.get(Register::Rax), expected);
        }
        let operator = memory.read_u64(operator_out).expect("operator");
        // QI on every child object kind.
        let qi_out = base + 0x8130;
        memory.map_bytes(qi_out, &[0u8; 8]);
        let child_qi = memory.read_u64(operator).expect("operator vtable");
        let child_qi_fn = memory.read_u64(child_qi).expect("child QI");
        for (iid, expected) in [
            (crate::d3d12::directml::IID_IDMLOPERATOR.0, 0u64),
            (crate::d3d12::directml::IID_IDMLDEVICECHILD.0, 0u64),
            (
                crate::d3d12::directml::IID_IDMLCOMPILEDOPERATOR.0,
                E_NOINTERFACE,
            ),
        ] {
            memory.map_bytes(base + 0x8140, &iid);
            state.set(Register::Rsp, base + 0x1c0);
            state.set(Register::Rcx, operator);
            state.set(Register::Rdx, base + 0x8140);
            state.set(Register::R8, qi_out);
            memory.write_u64(base + 0x1c0, 0x1000_0803);
            runtime
                .dispatch_import(child_qi_fn, &mut state, &mut memory)
                .expect("operator QI");
            assert_eq!(state.get(Register::Rax), expected);
            if expected == 0 {
                // Balance each successful QI reference.
                let release = memory.read_u64(child_qi + 16).expect("child release");
                state.set(Register::Rsp, base + 0x200);
                state.set(Register::Rcx, operator);
                memory.write_u64(base + 0x200, 0x1000_0804);
                runtime
                    .dispatch_import(release, &mut state, &mut memory)
                    .expect("release QI reference");
            }
        }

        // Private data, names, and GetDevice on the operator.
        let get_private = memory.read_u64(child_qi + 24).expect("GetPrivateData");
        let set_private = memory.read_u64(child_qi + 32).expect("SetPrivateData");
        let set_interface = memory
            .read_u64(child_qi + 40)
            .expect("SetPrivateDataInterface");
        let set_name = memory.read_u64(child_qi + 48).expect("SetName");
        let get_device = memory.read_u64(child_qi + 56).expect("GetDevice");
        let guid = base + 0x8200;
        memory.map_bytes(guid, &[0x11; 16]);
        let size_ptr = base + 0x8210;
        let data_ptr = base + 0x8220;
        memory.map_bytes(size_ptr, &[0u8; 4]);
        memory.map_bytes(data_ptr, &[0u8; 16]);
        state.set(Register::Rsp, base + 0x240);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, size_ptr);
        state.set(Register::R9, 0);
        memory.write_u64(base + 0x240, 0x1000_0805);
        runtime
            .dispatch_import(get_private, &mut state, &mut memory)
            .expect("GetPrivateData missing");
        assert_eq!(state.get(Register::Rax), DXGI_ERROR_NOT_FOUND);
        state.set(Register::Rsp, base + 0x280);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 4);
        state.set(Register::R9, data_ptr);
        memory.write_u64(base + 0x280, 0x1000_0806);
        runtime
            .dispatch_import(set_private, &mut state, &mut memory)
            .expect("SetPrivateData");
        assert_eq!(state.get(Register::Rax), 0);
        write_u32(&mut memory, size_ptr, 16);
        state.set(Register::Rsp, base + 0x2c0);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, size_ptr);
        state.set(Register::R9, data_ptr);
        memory.write_u64(base + 0x2c0, 0x1000_0807);
        runtime
            .dispatch_import(get_private, &mut state, &mut memory)
            .expect("GetPrivateData success");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime_read_u32(&memory, size_ptr), 4);
        write_u32(&mut memory, size_ptr, 2);
        state.set(Register::Rsp, base + 0x300);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, size_ptr);
        state.set(Register::R9, data_ptr);
        memory.write_u64(base + 0x300, 0x1000_0808);
        runtime
            .dispatch_import(get_private, &mut state, &mut memory)
            .expect("GetPrivateData short buffer");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::DXGI_ERROR_MORE_DATA as u64
        );
        assert_eq!(runtime_read_u32(&memory, size_ptr), 4);
        state.set(Register::Rsp, base + 0x340);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 4);
        state.set(Register::R9, 0);
        memory.write_u64(base + 0x340, 0x1000_0809);
        runtime
            .dispatch_import(set_private, &mut state, &mut memory)
            .expect("SetPrivateData null data");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );
        state.set(Register::Rsp, base + 0x380);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        memory.write_u64(base + 0x380, 0x1000_080a);
        runtime
            .dispatch_import(set_private, &mut state, &mut memory)
            .expect("SetPrivateData clear");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rsp, base + 0x3c0);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, dml_device);
        memory.write_u64(base + 0x3c0, 0x1000_080b);
        runtime
            .dispatch_import(set_interface, &mut state, &mut memory)
            .expect("SetPrivateDataInterface set");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rsp, base + 0x400);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 0);
        memory.write_u64(base + 0x400, 0x1000_080c);
        runtime
            .dispatch_import(set_interface, &mut state, &mut memory)
            .expect("SetPrivateDataInterface clear");
        assert_eq!(state.get(Register::Rax), 0);
        let name_ptr = base + 0x8300;
        for (index, unit) in "operator".encode_utf16().enumerate() {
            memory.write_u16(name_ptr + index as u64 * 2, unit);
        }
        for name in [name_ptr, 0] {
            state.set(Register::Rsp, base + 0x440);
            state.set(Register::Rcx, operator);
            state.set(Register::Rdx, name);
            memory.write_u64(base + 0x440, 0x1000_080d);
            runtime
                .dispatch_import(set_name, &mut state, &mut memory)
                .expect("SetName");
            assert_eq!(state.get(Register::Rax), 0);
        }
        for (iid, expected) in [
            (crate::d3d12::directml::IID_IDMLDEVICE.0, 0u64),
            (crate::d3d12::directml::IID_IDMLDEVICE1.0, E_NOINTERFACE),
        ] {
            memory.map_bytes(base + 0x8340, &iid);
            state.set(Register::Rsp, base + 0x480);
            state.set(Register::Rcx, operator);
            state.set(Register::Rdx, base + 0x8340);
            state.set(Register::R8, qi_out);
            memory.write_u64(base + 0x480, 0x1000_080e);
            runtime
                .dispatch_import(get_device, &mut state, &mut memory)
                .expect("GetDevice");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x4c0);
        state.set(Register::Rcx, 0x9999);
        state.set(Register::Rdx, base + 0x8340);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x4c0, 0x1000_080f);
        runtime
            .dispatch_import(get_device, &mut state, &mut memory)
            .expect("GetDevice unknown");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // GetParentDevice.
        let device_iid: [u8; 16] = [
            0xf1, 0x19, 0x98, 0x18, 0xb6, 0x1d, 0x57, 0x4b, 0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b,
            0x85, 0xf7,
        ];
        for (iid, expected) in [(device_iid, 0u64), ([0xCCu8; 16], E_NOINTERFACE)] {
            memory.map_bytes(base + 0x8400, &iid);
            state.set(Register::Rsp, base + 0x500);
            state.set(Register::Rcx, dml_device);
            state.set(Register::Rdx, base + 0x8400);
            state.set(Register::R8, qi_out);
            memory.write_u64(base + 0x500, 0x1000_0810);
            runtime
                .dispatch_import(get_parent_device, &mut state, &mut memory)
                .expect("GetParentDevice");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x540);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, base + 0x8400);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x540, 0x1000_0811);
        runtime
            .dispatch_import(get_parent_device, &mut state, &mut memory)
            .expect("GetParentDevice unknown");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );

        // CheckFeatureSupport.
        let query = base + 0x8500;
        let feature_out = base + 0x8520;
        memory.map_bytes(query, &[0u8; 32]);
        memory.map_bytes(feature_out, &[0u8; 32]);
        for (feature, query_size, data_type, expected) in [
            (
                0u32,
                4u32,
                crate::d3d12::directml::DML_TENSOR_DATA_TYPE_FLOAT32,
                0u64,
            ),
            (0, 4, crate::d3d12::directml::DML_TENSOR_DATA_TYPE_UINT32, 0),
            (0, 2, 0, crate::d3d12::directml::E_INVALIDARG as u64),
            (2, 4, 0, crate::d3d12::directml::E_INVALIDARG as u64),
        ] {
            write_u32(&mut memory, query, data_type);
            state.set(Register::Rsp, base + 0x580);
            state.set(Register::Rcx, dml_device);
            state.set(Register::Rdx, feature as u64);
            state.set(Register::R8, query_size as u64);
            state.set(Register::R9, query);
            memory.write_u64(base + 0x580, 0x1000_0812);
            write_u32(&mut memory, base + 0x580 + 0x28, 4);
            memory.write_u64(base + 0x580 + 0x30, feature_out);
            runtime
                .dispatch_import(check_feature, &mut state, &mut memory)
                .expect("CheckFeatureSupport");
            assert_eq!(state.get(Register::Rax), expected);
        }
        write_u32(&mut memory, query, 2);
        write_u64(&mut memory, query + 8, base + 0x8540);
        write_u32(&mut memory, base + 0x8540, 0x1000);
        write_u32(&mut memory, base + 0x8544, 0x2000);
        state.set(Register::Rsp, base + 0x5c0);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, 16);
        state.set(Register::R9, query);
        memory.write_u64(base + 0x5c0, 0x1000_0813);
        write_u32(&mut memory, base + 0x5c0 + 0x28, 4);
        memory.write_u64(base + 0x5c0 + 0x30, feature_out);
        runtime
            .dispatch_import(check_feature, &mut state, &mut memory)
            .expect("CheckFeatureSupport levels");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            runtime_read_u32(&memory, feature_out),
            crate::d3d12::directml::DML_FEATURE_LEVEL_6_3
        );

        // Compile and create the rest of the object graph.
        let iid_compiled = base + 0x8600;
        memory.map_bytes(
            iid_compiled,
            &crate::d3d12::directml::IID_IDMLCOMPILEDOPERATOR.0,
        );
        let compiled_out = base + 0x8610;
        memory.map_bytes(compiled_out, &[0u8; 8]);
        for (device_obj, op, iid_ptr, out_ptr, expected) in [
            (
                device,
                0x9999,
                iid_compiled,
                compiled_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                dml_device,
                operator,
                base + 0x8620,
                compiled_out,
                E_NOINTERFACE,
            ),
            (
                dml_device,
                operator,
                iid_compiled,
                0,
                crate::d3d12::directml::E_POINTER as u64,
            ),
        ] {
            memory.map_bytes(base + 0x8620, &[0xDD; 16]);
            state.set(Register::Rsp, base + 0x600);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, op);
            state.set(Register::R8, 0);
            state.set(Register::R9, iid_ptr);
            memory.write_u64(base + 0x600, 0x1000_0814);
            memory.write_u64(base + 0x600 + 0x28, out_ptr);
            runtime
                .dispatch_import(compile_operator, &mut state, &mut memory)
                .expect("CompileOperator error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x640);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, operator);
        state.set(Register::R8, 0);
        state.set(Register::R9, iid_compiled);
        memory.write_u64(base + 0x640, 0x1000_0815);
        memory.write_u64(base + 0x640 + 0x28, compiled_out);
        runtime
            .dispatch_import(compile_operator, &mut state, &mut memory)
            .expect("CompileOperator");
        assert_eq!(state.get(Register::Rax), 0);
        let compiled = memory.read_u64(compiled_out).expect("compiled");
        let compiled_vtable = memory.read_u64(compiled).expect("compiled vtable");
        let compiled_qi = memory.read_u64(compiled_vtable).expect("compiled QI");
        let get_props = memory
            .read_u64(compiled_vtable + 8 * 8)
            .expect("GetBindingProperties");
        for iid in [
            crate::d3d12::directml::IID_IDMLCOMPILEDOPERATOR.0,
            crate::d3d12::directml::IID_IDMLDISPATCHABLE.0,
            crate::d3d12::directml::IID_IDMLPAGEABLE.0,
        ] {
            memory.map_bytes(base + 0x8640, &iid);
            state.set(Register::Rsp, base + 0x680);
            state.set(Register::Rcx, compiled);
            state.set(Register::Rdx, base + 0x8640);
            state.set(Register::R8, qi_out);
            memory.write_u64(base + 0x680, 0x1000_0816);
            runtime
                .dispatch_import(compiled_qi, &mut state, &mut memory)
                .expect("compiled QI");
            assert_eq!(state.get(Register::Rax), 0);
            let release = memory.read_u64(compiled_vtable + 16).expect("release");
            state.set(Register::Rsp, base + 0x6c0);
            state.set(Register::Rcx, compiled);
            memory.write_u64(base + 0x6c0, 0x1000_0817);
            runtime
                .dispatch_import(release, &mut state, &mut memory)
                .expect("release compiled QI");
        }
        let props = base + 0x8660;
        memory.map_bytes(props, &[0u8; 24]);
        state.set(Register::Rsp, base + 0x700);
        state.set(Register::Rcx, compiled);
        state.set(Register::Rdx, props);
        memory.write_u64(base + 0x700, 0x1000_0818);
        runtime
            .dispatch_import(get_props, &mut state, &mut memory)
            .expect("GetBindingProperties");
        assert_eq!(state.get(Register::Rax), 0);

        // Initializer, recorder and binding table errors plus auxiliary binds.
        let iid_initializer = base + 0x8700;
        memory.map_bytes(
            iid_initializer,
            &crate::d3d12::directml::IID_IDMLOPERATORINITIALIZER.0,
        );
        let initializer_out = base + 0x8710;
        memory.map_bytes(initializer_out, &[0u8; 8]);
        let operator_array = base + 0x8720;
        memory.map_bytes(operator_array, &[0u8; 8]);
        memory.write_u64(operator_array, compiled);
        for (device_obj, count, ptr, iid_ptr, out_ptr, expected) in [
            (
                device,
                1u32,
                operator_array,
                iid_initializer,
                initializer_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                dml_device,
                1,
                operator_array,
                base + 0x8730,
                initializer_out,
                E_NOINTERFACE,
            ),
            (
                dml_device,
                1,
                0,
                iid_initializer,
                initializer_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                dml_device,
                1,
                operator_array,
                iid_initializer,
                0,
                crate::d3d12::directml::E_POINTER as u64,
            ),
        ] {
            memory.map_bytes(base + 0x8730, &[0xEE; 16]);
            state.set(Register::Rsp, base + 0x740);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, count as u64);
            state.set(Register::R8, ptr);
            state.set(Register::R9, iid_ptr);
            memory.write_u64(base + 0x740, 0x1000_0819);
            memory.write_u64(base + 0x740 + 0x28, out_ptr);
            runtime
                .dispatch_import(create_initializer, &mut state, &mut memory)
                .expect("CreateOperatorInitializer error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x780);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, operator_array);
        state.set(Register::R9, iid_initializer);
        memory.write_u64(base + 0x780, 0x1000_081a);
        memory.write_u64(base + 0x780 + 0x28, initializer_out);
        runtime
            .dispatch_import(create_initializer, &mut state, &mut memory)
            .expect("CreateOperatorInitializer");
        assert_eq!(state.get(Register::Rax), 0);
        let initializer = memory.read_u64(initializer_out).expect("initializer");
        let initializer_vtable = memory.read_u64(initializer).expect("initializer vtable");
        let reset = memory
            .read_u64(initializer_vtable + 9 * 8)
            .expect("initializer Reset");
        let init_props = memory
            .read_u64(initializer_vtable + 8 * 8)
            .expect("initializer properties");
        memory.map_bytes(props, &[0u8; 24]);
        state.set(Register::Rsp, base + 0x7c0);
        state.set(Register::Rcx, initializer);
        state.set(Register::Rdx, props);
        memory.write_u64(base + 0x7c0, 0x1000_081b);
        runtime
            .dispatch_import(init_props, &mut state, &mut memory)
            .expect("initializer properties");
        assert_eq!(runtime_read_u32(&memory, props), 0);
        for (count, ptr, expected) in [
            (1u32, 0u64, crate::d3d12::directml::E_INVALIDARG as u64),
            (
                1,
                base + 0x8750,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
        ] {
            memory.map_bytes(base + 0x8750, &[0u8; 8]);
            state.set(Register::Rsp, base + 0x800);
            state.set(Register::Rcx, initializer);
            state.set(Register::Rdx, count as u64);
            state.set(Register::R8, ptr);
            memory.write_u64(base + 0x800, 0x1000_081c);
            runtime
                .dispatch_import(reset, &mut state, &mut memory)
                .expect("initializer Reset error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x840);
        state.set(Register::Rcx, initializer);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, operator_array);
        memory.write_u64(base + 0x840, 0x1000_081d);
        runtime
            .dispatch_import(reset, &mut state, &mut memory)
            .expect("initializer Reset");
        assert_eq!(state.get(Register::Rax), 0);
        let iid_recorder = base + 0x8800;
        memory.map_bytes(
            iid_recorder,
            &crate::d3d12::directml::IID_IDMLCOMMANDRECORDER.0,
        );
        let recorder_out = base + 0x8810;
        memory.map_bytes(recorder_out, &[0u8; 8]);
        for (device_obj, iid_ptr, out_ptr, expected) in [
            (
                device,
                iid_recorder,
                recorder_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (dml_device, base + 0x8820, recorder_out, E_NOINTERFACE),
            (
                dml_device,
                iid_recorder,
                0,
                crate::d3d12::directml::E_POINTER as u64,
            ),
        ] {
            memory.map_bytes(base + 0x8820, &[0x11; 16]);
            state.set(Register::Rsp, base + 0x880);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, iid_ptr);
            state.set(Register::R8, out_ptr);
            memory.write_u64(base + 0x880, 0x1000_081e);
            runtime
                .dispatch_import(create_recorder, &mut state, &mut memory)
                .expect("CreateCommandRecorder error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x8c0);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, iid_recorder);
        state.set(Register::R8, recorder_out);
        memory.write_u64(base + 0x8c0, 0x1000_081f);
        runtime
            .dispatch_import(create_recorder, &mut state, &mut memory)
            .expect("CreateCommandRecorder");
        let recorder = memory.read_u64(recorder_out).expect("recorder");
        let recorder_vtable = memory.read_u64(recorder).expect("recorder vtable");
        let record_dispatch = memory
            .read_u64(recorder_vtable + 8 * 8)
            .expect("RecordDispatch");
        // A same-device initializer is a valid dispatchable (covers the
        // success arm of the initializer branch).
        assert!(
            runtime
                .d3d12_runtime
                .directml_mut()
                .create_binding_table(
                    runtime.dml_object_handles[&dml_device],
                    runtime.dml_object_handles[&initializer],
                    1,
                )
                .is_ok()
        );
        let iid_table = base + 0x8900;
        memory.map_bytes(iid_table, &crate::d3d12::directml::IID_IDMLBINDINGTABLE.0);
        let table_desc = base + 0x8a00;
        memory.map_bytes(table_desc, &[0u8; 32]);
        let table_out = base + 0x8a20;
        memory.map_bytes(table_out, &[0u8; 8]);
        for (device_obj, desc, iid_ptr, out_ptr, expected) in [
            (
                device,
                table_desc,
                iid_table,
                table_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                dml_device,
                table_desc,
                base + 0x8a30,
                table_out,
                E_NOINTERFACE,
            ),
            (
                dml_device,
                0,
                iid_table,
                table_out,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
        ] {
            memory.map_bytes(base + 0x8a30, &[0x22; 16]);
            state.set(Register::Rsp, base + 0x900);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, desc);
            state.set(Register::R8, iid_ptr);
            state.set(Register::R9, out_ptr);
            memory.write_u64(base + 0x900, 0x1000_0820);
            runtime
                .dispatch_import(create_binding_table, &mut state, &mut memory)
                .expect("CreateBindingTable error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        write_u64(&mut memory, table_desc, compiled);
        write_u32(&mut memory, table_desc + 24, 2);
        state.set(Register::Rsp, base + 0x940);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, table_desc);
        state.set(Register::R8, iid_table);
        state.set(Register::R9, table_out);
        memory.write_u64(base + 0x940, 0x1000_0821);
        runtime
            .dispatch_import(create_binding_table, &mut state, &mut memory)
            .expect("CreateBindingTable");
        let table = memory.read_u64(table_out).expect("table");
        let table_vtable = memory.read_u64(table).expect("table vtable");
        let bind_inputs = memory.read_u64(table_vtable + 8 * 8).expect("BindInputs");
        let bind_outputs = memory.read_u64(table_vtable + 9 * 8).expect("BindOutputs");
        let bind_temp = memory
            .read_u64(table_vtable + 10 * 8)
            .expect("BindTemporaryResource");
        let bind_reset = memory.read_u64(table_vtable + 12 * 8).expect("BindReset");
        let binding = base + 0x8b00;
        let binding_desc = base + 0x8b20;
        write_u32(&mut memory, binding_desc, 1);
        write_u64(&mut memory, binding_desc + 8, binding);
        write_u64(&mut memory, binding, 0x1234);
        write_u64(&mut memory, binding + 8, 0);
        write_u64(&mut memory, binding + 16, 8);
        for (fn_ptr, count, ptr, expected) in [
            (
                bind_inputs,
                1u32,
                0u64,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                bind_inputs,
                65_536,
                binding_desc,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                bind_inputs,
                1,
                base + 0x8b40,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
        ] {
            write_u32(&mut memory, base + 0x8b40, 9);
            state.set(Register::Rsp, base + 0x980);
            state.set(Register::Rcx, table);
            state.set(Register::Rdx, count as u64);
            state.set(Register::R8, ptr);
            memory.write_u64(base + 0x980, 0x1000_0822);
            runtime
                .dispatch_import(fn_ptr, &mut state, &mut memory)
                .expect("Bind error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        // Null binding entry (type NONE) is accepted.
        write_u32(&mut memory, binding_desc, 0);
        state.set(Register::Rsp, base + 0x9c0);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, binding_desc);
        memory.write_u64(base + 0x9c0, 0x1000_0823);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("Bind NONE");
        assert_eq!(state.get(Register::Rax), 0);
        // Temporary/persistent binding validation.
        write_u32(&mut memory, binding_desc, 0);
        for (fn_ptr, ptr, expected) in [
            (bind_temp, binding_desc, 0u64),
            (bind_temp, 0, crate::d3d12::directml::E_INVALIDARG as u64),
        ] {
            state.set(Register::Rsp, base + 0xa00);
            state.set(Register::Rcx, table);
            state.set(Register::Rdx, ptr);
            memory.write_u64(base + 0xa00, 0x1000_0824);
            runtime
                .dispatch_import(fn_ptr, &mut state, &mut memory)
                .expect("Bind auxiliary");
            assert_eq!(state.get(Register::Rax), expected);
        }
        // Reset errors and success.
        state.set(Register::Rsp, base + 0xa40);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 0);
        memory.write_u64(base + 0xa40, 0x1000_0825);
        runtime
            .dispatch_import(bind_reset, &mut state, &mut memory)
            .expect("BindReset error");
        assert_eq!(
            state.get(Register::Rax),
            crate::d3d12::directml::E_INVALIDARG as u64
        );
        state.set(Register::Rsp, base + 0xa80);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, table_desc);
        memory.write_u64(base + 0xa80, 0x1000_0826);
        runtime
            .dispatch_import(bind_reset, &mut state, &mut memory)
            .expect("BindReset");
        assert_eq!(state.get(Register::Rax), 0);
        // RecordDispatch errors and initializer dispatch fail-closed.
        for (rec, list_arg, dispatchable, table_arg, expected) in [
            (
                recorder,
                0x9999,
                compiled,
                table,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                0x9999,
                list,
                compiled,
                table,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (
                recorder,
                list,
                0x9999,
                table,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
            (recorder, list, initializer, table, 0x8000_4001),
            (
                recorder,
                list,
                compiled,
                0x9999,
                crate::d3d12::directml::E_INVALIDARG as u64,
            ),
        ] {
            state.set(Register::Rsp, base + 0xac0);
            state.set(Register::Rcx, rec);
            state.set(Register::Rdx, list_arg);
            state.set(Register::R8, dispatchable);
            state.set(Register::R9, table_arg);
            memory.write_u64(base + 0xac0, 0x1000_0827);
            runtime
                .dispatch_import(record_dispatch, &mut state, &mut memory)
                .expect("RecordDispatch error");
            assert_eq!(state.get(Register::Rax), expected);
        }

        // QueryInterface for every child interface family.
        for (object, iids) in [
            (
                operator,
                vec![
                    crate::d3d12::directml::IID_IDMLOPERATOR.0,
                    crate::d3d12::directml::IID_IDMLDEVICECHILD.0,
                    crate::d3d12::directml::IID_IDMLOBJECT.0,
                ],
            ),
            (
                compiled,
                vec![
                    crate::d3d12::directml::IID_IDMLCOMPILEDOPERATOR.0,
                    crate::d3d12::directml::IID_IDMLDISPATCHABLE.0,
                    crate::d3d12::directml::IID_IDMLPAGEABLE.0,
                    crate::d3d12::directml::IID_IDMLDEVICECHILD.0,
                ],
            ),
            (
                initializer,
                vec![
                    crate::d3d12::directml::IID_IDMLOPERATORINITIALIZER.0,
                    crate::d3d12::directml::IID_IDMLDISPATCHABLE.0,
                    crate::d3d12::directml::IID_IDMLPAGEABLE.0,
                ],
            ),
            (
                recorder,
                vec![
                    crate::d3d12::directml::IID_IDMLCOMMANDRECORDER.0,
                    crate::d3d12::directml::IID_IDMLDEVICECHILD.0,
                ],
            ),
            (
                table,
                vec![
                    crate::d3d12::directml::IID_IDMLBINDINGTABLE.0,
                    crate::d3d12::directml::IID_IDMLOBJECT.0,
                ],
            ),
        ] {
            let vtable = memory.read_u64(object).expect("object vtable");
            let qi = memory.read_u64(vtable).expect("QI");
            let release = memory.read_u64(vtable + 16).expect("Release");
            for iid in iids {
                memory.map_bytes(base + 0x8c00, &iid);
                state.set(Register::Rsp, base + 0xb00);
                state.set(Register::Rcx, object);
                state.set(Register::Rdx, base + 0x8c00);
                state.set(Register::R8, qi_out);
                memory.write_u64(base + 0xb00, 0x1000_0828);
                runtime
                    .dispatch_import(qi, &mut state, &mut memory)
                    .expect("child QI");
                assert_eq!(state.get(Register::Rax), 0);
                state.set(Register::Rsp, base + 0xb40);
                state.set(Register::Rcx, object);
                memory.write_u64(base + 0xb40, 0x1000_0829);
                runtime
                    .dispatch_import(release, &mut state, &mut memory)
                    .expect("release child QI");
            }
            memory.map_bytes(base + 0x8c00, &[0xFE; 16]);
            state.set(Register::Rsp, base + 0xb80);
            state.set(Register::Rcx, object);
            state.set(Register::Rdx, base + 0x8c00);
            state.set(Register::R8, qi_out);
            memory.write_u64(base + 0xb80, 0x1000_082a);
            runtime
                .dispatch_import(qi, &mut state, &mut memory)
                .expect("child bad QI");
            assert_eq!(state.get(Register::Rax), E_NOINTERFACE);
        }
        // QI on a non-DML object returns E_NOINTERFACE.
        state.set(Register::Rsp, base + 0xbc0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, base + 0x8c00);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0xbc0, 0x1000_082b);
        runtime
            .dispatch_import(
                memory
                    .read_u64(memory.read_u64(device).expect("device vtable"))
                    .expect("device QI"),
                &mut state,
                &mut memory,
            )
            .expect("non-DML QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);

        // Malformed GUID pointers hit the E_INVALIDARG guards.
        for (fn_ptr, arg2, arg3) in [
            (get_private, 0u64, size_ptr),
            (set_private, 0u64, 0u64),
            (set_interface, 0u64, 0u64),
        ] {
            state.set(Register::Rsp, base + 0xc00);
            state.set(Register::Rcx, operator);
            state.set(Register::Rdx, arg2);
            state.set(Register::R8, arg3);
            state.set(Register::R9, 0);
            memory.write_u64(base + 0xc00, 0x1000_082c);
            runtime
                .dispatch_import(fn_ptr, &mut state, &mut memory)
                .expect("malformed GUID");
            assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        }
        // GetPrivateData with no size pointer uses the stored length.
        state.set(Register::Rsp, base + 0xc40);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 0);
        state.set(Register::R9, data_ptr);
        memory.write_u64(base + 0xc40, 0x1000_082d);
        runtime
            .dispatch_import(get_private, &mut state, &mut memory)
            .expect("GetPrivateData no size");
        assert_eq!(state.get(Register::Rax), DXGI_ERROR_NOT_FOUND);
        // Feature-level query with too-small query buffer.
        state.set(Register::Rsp, base + 0xc80);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, 4);
        state.set(Register::R9, query);
        memory.write_u64(base + 0xc80, 0x1000_082e);
        write_u32(&mut memory, base + 0xc80 + 0x28, 4);
        memory.write_u64(base + 0xc80 + 0x30, feature_out);
        runtime
            .dispatch_import(check_feature, &mut state, &mut memory)
            .expect("feature levels too small");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);

        // Unknown-device and unknown-object branches.
        memory.map_bytes(iid_operator, &crate::d3d12::directml::IID_IDMLOPERATOR.0);
        let unknown_cases: Vec<(u64, u64, u64, u64, u64, u64, u64)> = vec![
            (
                create_operator,
                operator,
                operator_desc,
                iid_operator,
                operator_out,
                0,
                directml::E_INVALIDARG as u64,
            ),
            (
                create_recorder,
                operator,
                iid_recorder,
                recorder_out,
                0,
                0,
                directml::E_INVALIDARG as u64,
            ),
            (
                create_binding_table,
                operator,
                table_desc,
                iid_table,
                table_out,
                0,
                directml::E_INVALIDARG as u64,
            ),
            (
                create_binding_table,
                dml_device,
                base + 0x9900,
                iid_table,
                table_out,
                0,
                directml::E_INVALIDARG as u64,
            ),
            (
                get_parent_device,
                operator,
                base + 0x8400,
                qi_out,
                0,
                0,
                directml::E_INVALIDARG as u64,
            ),
            (
                get_props,
                0x9999,
                props,
                0,
                0,
                0,
                directml::E_INVALIDARG as u64,
            ),
            (reset, 0x9999, 0, 0, 0, 0, directml::E_INVALIDARG as u64),
            (
                record_dispatch,
                0x9999,
                list,
                compiled,
                table,
                0,
                directml::E_INVALIDARG as u64,
            ),
        ];
        for (fn_ptr, a, b, c, d, _e, expected) in unknown_cases {
            state.set(Register::Rsp, base + 0xcc0);
            state.set(Register::Rcx, a);
            state.set(Register::Rdx, b);
            state.set(Register::R8, c);
            state.set(Register::R9, d);
            memory.write_u64(base + 0xcc0, 0x1000_082f);
            memory.write_u64(base + 0xcc0 + 0x28, c);
            runtime
                .dispatch_import(fn_ptr, &mut state, &mut memory)
                .expect("unknown object branch");
            assert_eq!(state.get(Register::Rax), expected);
        }

        // CompileOperator and CreateOperatorInitializer have stack-based
        // out parameters and are driven with their real ABI.
        for (device_obj, op, out_ptr, expected) in [
            (
                operator,
                operator,
                compiled_out,
                directml::E_INVALIDARG as u64,
            ),
            (
                dml_device,
                0x9999,
                compiled_out,
                directml::E_INVALIDARG as u64,
            ),
        ] {
            state.set(Register::Rsp, base + 0xcd0);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, op);
            state.set(Register::R8, 0);
            state.set(Register::R9, iid_compiled);
            memory.write_u64(base + 0xcd0, 0x1000_0833);
            memory.write_u64(base + 0xcd0 + 0x28, out_ptr);
            runtime
                .dispatch_import(compile_operator, &mut state, &mut memory)
                .expect("CompileOperator unknown");
            assert_eq!(state.get(Register::Rax), expected);
        }
        let unknown_compiled_array = base + 0x8d00;
        memory.map_bytes(unknown_compiled_array, &[0u8; 8]);
        memory.write_u64(unknown_compiled_array, 0x9999);
        for (device_obj, array, out_ptr, expected) in [
            (
                operator,
                operator_array,
                initializer_out,
                directml::E_INVALIDARG as u64,
            ),
            (
                dml_device,
                unknown_compiled_array,
                initializer_out,
                directml::E_INVALIDARG as u64,
            ),
        ] {
            state.set(Register::Rsp, base + 0xd10);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, 1);
            state.set(Register::R8, array);
            state.set(Register::R9, iid_initializer);
            memory.write_u64(base + 0xd10, 0x1000_0834);
            memory.write_u64(base + 0xd10 + 0x28, out_ptr);
            runtime
                .dispatch_import(create_initializer, &mut state, &mut memory)
                .expect("CreateOperatorInitializer unknown");
            assert_eq!(state.get(Register::Rax), expected);
        }

        // Binding-table error branches.
        for (fn_ptr, table_arg, count, ptr, expected) in [
            (
                bind_inputs,
                0x9999u64,
                1u64,
                binding_desc,
                directml::E_INVALIDARG as u64,
            ),
            (bind_inputs, table, 1, 0, directml::E_INVALIDARG as u64),
            (bind_inputs, table, 1, base + 0x8c80, 0x8000_4001),
        ] {
            write_u32(&mut memory, base + 0x8c80, 2);
            state.set(Register::Rsp, base + 0xd00);
            state.set(Register::Rcx, table_arg);
            state.set(Register::Rdx, count);
            state.set(Register::R8, ptr);
            memory.write_u64(base + 0xd00, 0x1000_0830);
            runtime
                .dispatch_import(fn_ptr, &mut state, &mut memory)
                .expect("BindInputs error");
            assert_eq!(state.get(Register::Rax), expected);
        }
        // BUFFER binding with a non-resource pointer is rejected.
        write_u32(&mut memory, binding_desc, 1);
        write_u64(&mut memory, binding, 0x1234);
        state.set(Register::Rsp, base + 0xd40);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, binding_desc);
        memory.write_u64(base + 0xd40, 0x1000_0831);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("BindInputs non-resource");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        // Reset with an unknown table and unknown dispatchable.
        for (table_arg, desc_ptr, expected) in [
            (0x9999u64, table_desc, directml::E_INVALIDARG as u64),
            (table, base + 0x9900, directml::E_INVALIDARG as u64),
        ] {
            state.set(Register::Rsp, base + 0xd80);
            state.set(Register::Rcx, table_arg);
            state.set(Register::Rdx, desc_ptr);
            memory.write_u64(base + 0xd80, 0x1000_0832);
            runtime
                .dispatch_import(bind_reset, &mut state, &mut memory)
                .expect("BindReset error");
            assert_eq!(state.get(Register::Rax), expected);
        }

        // Binding descriptor validation: null Desc and zero-size buffer.
        write_u32(&mut memory, binding_desc, 1);
        write_u64(&mut memory, binding_desc + 8, 0);
        state.set(Register::Rsp, base + 0xdc0);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, binding_desc);
        memory.write_u64(base + 0xdc0, 0x1000_0835);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("binding null desc");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        let fake_resource = base + 0x8e00;
        runtime.guest_objects.insert(
            fake_resource,
            super::state::GuestObjectMeta {
                kind: GuestObjectKind::D3d12Resource,
                refcount: 1,
            },
        );
        runtime.d3d12_resources.insert(
            fake_resource,
            super::state::GuestD3d12Resource {
                device_object: device,
                resource_id: 0xFFFF,
                format: crate::gfx::DxgiFormat::R8G8B8A8Unorm,
                swapchain_backbuffer: false,
                width: 4,
                height: 4,
            },
        );
        let fake_binding = base + 0x8e20;
        write_u64(&mut memory, binding + 8, 0);
        write_u64(&mut memory, binding + 16, 0);
        write_u64(&mut memory, binding, fake_resource);
        write_u64(&mut memory, binding_desc + 8, fake_binding);
        write_u64(&mut memory, fake_binding, fake_resource);
        write_u64(&mut memory, fake_binding + 8, 0);
        write_u64(&mut memory, fake_binding + 16, 0);
        state.set(Register::Rsp, base + 0xe00);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, binding_desc);
        memory.write_u64(base + 0xe00, 0x1000_0836);
        runtime
            .dispatch_import(bind_inputs, &mut state, &mut memory)
            .expect("binding zero size");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);

        // Private data with no size pointer after a successful set.
        write_u32(&mut memory, data_ptr, 0x1234_5678);
        state.set(Register::Rsp, base + 0xe40);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 4);
        state.set(Register::R9, data_ptr);
        memory.write_u64(base + 0xe40, 0x1000_0837);
        runtime
            .dispatch_import(set_private, &mut state, &mut memory)
            .expect("SetPrivateData again");
        state.set(Register::Rsp, base + 0xe80);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, 0);
        state.set(Register::R9, data_ptr);
        memory.write_u64(base + 0xe80, 0x1000_0838);
        runtime
            .dispatch_import(get_private, &mut state, &mut memory)
            .expect("GetPrivateData no size with data");
        assert_eq!(state.get(Register::Rax), 0);
        write_u32(&mut memory, size_ptr, 16);
        state.set(Register::Rsp, base + 0xea0);
        state.set(Register::Rcx, operator);
        state.set(Register::Rdx, guid);
        state.set(Register::R8, size_ptr);
        state.set(Register::R9, 0);
        memory.write_u64(base + 0xea0, 0x1000_0847);
        runtime
            .dispatch_import(get_private, &mut state, &mut memory)
            .expect("GetPrivateData size only");
        assert_eq!(state.get(Register::Rax), 0);

        // DML QueryInterface on a non-DML COM object returns E_NOINTERFACE.
        memory.map_bytes(base + 0x8c00, &crate::d3d12::directml::IID_IDMLDEVICE.0);
        state.set(Register::Rsp, base + 0xec0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, base + 0x8c00);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0xec0, 0x1000_0839);
        runtime
            .dispatch_dml_object_query_interface(&mut memory, &mut state)
            .expect("non-DML DML QI");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);

        // CreateOperator runtime error (valid device, invalid descriptor).
        let bad_op_desc = base + 0x8f00;
        write_u32(&mut memory, bad_op_desc, 9999);
        write_u64(&mut memory, bad_op_desc + 8, bad_op_desc + 0x40);
        state.set(Register::Rsp, base + 0xf00);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, bad_op_desc);
        state.set(Register::R8, iid_operator);
        state.set(Register::R9, operator_out);
        memory.write_u64(base + 0xf00, 0x1000_083a);
        runtime
            .dispatch_import(create_operator, &mut state, &mut memory)
            .expect("CreateOperator runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);

        // Second DML device for cross-device compile/initializer failures.
        let other_dml_out = base + 0x8f80;
        memory.map_bytes(other_dml_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0xf40);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, iid_device);
        state.set(Register::R9, other_dml_out);
        memory.write_u64(base + 0xf40, 0x1000_083b);
        runtime
            .dispatch_import(create_dml, &mut state, &mut memory)
            .expect("second DML device");
        let other_dml_device = memory.read_u64(other_dml_out).expect("other DML device");
        let other_operator_out = base + 0x8f90;
        memory.map_bytes(other_operator_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0xf80);
        state.set(Register::Rcx, other_dml_device);
        state.set(Register::Rdx, operator_desc);
        state.set(Register::R8, iid_operator);
        state.set(Register::R9, other_operator_out);
        memory.write_u64(base + 0xf80, 0x1000_083c);
        runtime
            .dispatch_import(create_operator, &mut state, &mut memory)
            .expect("operator on second device");
        assert_eq!(state.get(Register::Rax), 0);
        let other_operator = memory.read_u64(other_operator_out).expect("other operator");
        let other_compiled_out = base + 0x8fa0;
        memory.map_bytes(other_compiled_out, &[0u8; 8]);
        state.set(Register::Rsp, base + 0xfc0);
        state.set(Register::Rcx, other_dml_device);
        state.set(Register::Rdx, other_operator);
        state.set(Register::R8, 0);
        state.set(Register::R9, iid_compiled);
        memory.write_u64(base + 0xfc0, 0x1000_083d);
        memory.write_u64(base + 0xfc0 + 0x28, other_compiled_out);
        runtime
            .dispatch_import(compile_operator, &mut state, &mut memory)
            .expect("compile on second device");
        let other_compiled = memory.read_u64(other_compiled_out).expect("other compiled");
        state.set(Register::Rsp, base + 0x1000);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, other_operator);
        state.set(Register::R8, 0);
        state.set(Register::R9, iid_compiled);
        memory.write_u64(base + 0x1000, 0x1000_083e);
        memory.write_u64(base + 0x1000 + 0x28, compiled_out);
        runtime
            .dispatch_import(compile_operator, &mut state, &mut memory)
            .expect("cross-device compile");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        let other_compiled_array = base + 0x8fc0;
        memory.map_bytes(other_compiled_array, &[0u8; 8]);
        memory.write_u64(other_compiled_array, other_compiled);
        state.set(Register::Rsp, base + 0x1040);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, other_compiled_array);
        state.set(Register::R9, iid_initializer);
        memory.write_u64(base + 0x1040, 0x1000_083f);
        memory.write_u64(base + 0x1040 + 0x28, initializer_out);
        runtime
            .dispatch_import(create_initializer, &mut state, &mut memory)
            .expect("cross-device initializer");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);

        // A binding table whose dispatchable differs from the recorded
        // operator reaches the runtime and fails.
        let mismatch_table_out = base + 0x8fe0;
        memory.map_bytes(mismatch_table_out, &[0u8; 8]);
        write_u64(&mut memory, table_desc, initializer);
        write_u64(&mut memory, table_desc + 8, initializer);
        state.set(Register::Rsp, base + 0x1080);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, table_desc);
        state.set(Register::R8, iid_table);
        state.set(Register::R9, mismatch_table_out);
        memory.write_u64(base + 0x1080, 0x1000_0840);
        runtime
            .dispatch_import(create_binding_table, &mut state, &mut memory)
            .expect("mismatch binding table");
        assert_eq!(state.get(Register::Rax), 0);
        let mismatch_table = memory.read_u64(mismatch_table_out).expect("mismatch table");
        state.set(Register::Rsp, base + 0x10c0);
        state.set(Register::Rcx, recorder);
        state.set(Register::Rdx, list);
        state.set(Register::R8, compiled);
        state.set(Register::R9, mismatch_table);
        memory.write_u64(base + 0x10c0, 0x1000_0841);
        runtime
            .dispatch_import(record_dispatch, &mut state, &mut memory)
            .expect("RecordDispatch mismatch");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);

        // Remove runtime records while guest wrappers still exist to
        // exercise the remaining error branches.
        let dml_handle = runtime.dml_object_handles[&dml_device];
        let compiled_handle = runtime.dml_object_handles[&compiled];
        let initializer_handle = runtime.dml_object_handles[&initializer];
        let table_handle = runtime.dml_object_handles[&table];
        runtime
            .d3d12_runtime
            .directml_mut()
            .destroy_compiled(compiled_handle)
            .unwrap();
        state.set(Register::Rsp, base + 0x1100);
        state.set(Register::Rcx, compiled);
        state.set(Register::Rdx, props);
        memory.write_u64(base + 0x1100, 0x1000_0842);
        runtime
            .dispatch_import(get_props, &mut state, &mut memory)
            .expect("binding properties runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        runtime
            .d3d12_runtime
            .directml_mut()
            .destroy_operator_initializer(initializer_handle)
            .unwrap();
        state.set(Register::Rsp, base + 0x1140);
        state.set(Register::Rcx, initializer);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, operator_array);
        memory.write_u64(base + 0x1140, 0x1000_0843);
        runtime
            .dispatch_import(reset, &mut state, &mut memory)
            .expect("initializer reset runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        runtime
            .d3d12_runtime
            .directml_mut()
            .destroy_binding_table(table_handle)
            .unwrap();
        write_u32(&mut memory, binding_desc, 0);
        state.set(Register::Rsp, base + 0x1180);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, binding_desc);
        memory.write_u64(base + 0x1180, 0x1000_0844);
        runtime
            .dispatch_import(bind_outputs, &mut state, &mut memory)
            .expect("BindOutputs runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        state.set(Register::Rsp, base + 0x11c0);
        state.set(Register::Rcx, table);
        state.set(Register::Rdx, table_desc);
        memory.write_u64(base + 0x11c0, 0x1000_0845);
        runtime
            .dispatch_import(bind_reset, &mut state, &mut memory)
            .expect("BindReset runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        runtime
            .d3d12_runtime
            .directml_mut()
            .destroy_device(dml_handle)
            .unwrap();
        state.set(Register::Rsp, base + 0x1200);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, base + 0x8400);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x1200, 0x1000_0846);
        runtime
            .dispatch_import(get_parent_device, &mut state, &mut memory)
            .expect("GetParentDevice runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        state.set(Register::Rsp, base + 0x1240);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, iid_recorder);
        state.set(Register::R8, recorder_out);
        memory.write_u64(base + 0x1240, 0x1000_0848);
        runtime
            .dispatch_import(create_recorder, &mut state, &mut memory)
            .expect("CreateCommandRecorder runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
        write_u64(&mut memory, table_desc, initializer);
        write_u64(&mut memory, table_desc + 8, initializer);
        state.set(Register::Rsp, base + 0x1280);
        state.set(Register::Rcx, dml_device);
        state.set(Register::Rdx, table_desc);
        state.set(Register::R8, iid_table);
        state.set(Register::R9, table_out);
        memory.write_u64(base + 0x1280, 0x1000_0849);
        runtime
            .dispatch_import(create_binding_table, &mut state, &mut memory)
            .expect("CreateBindingTable runtime error");
        assert_eq!(state.get(Register::Rax), directml::E_INVALIDARG as u64);
    });
}

#[test]
fn d3d12_state_object_and_work_graph_dispatch_error_paths_are_pinned() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "d3d12-dispatch-errors",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let base = 0x68_0000;
        memory.map_bytes(base, &vec![0u8; 0x30000]);
        let device = create_test_d3d12_device(&mut runtime, &mut memory, base, base + 0x20);
        let list = create_test_d3d12_command_list(&mut runtime, &mut memory, base + 0x1000, device);
        let device_vtable = memory.read_u64(device).expect("device vtable");
        let create_state_object = memory
            .read_u64(device_vtable + 61 * 8)
            .expect("CreateStateObject");
        let add_to_state_object = memory
            .read_u64(device_vtable + 65 * 8)
            .expect("AddToStateObject");
        let iid = base + 0x8000;
        memory.map_bytes(iid, &[0u8; 16]);
        let iid_bytes: [u8; 16] = [
            0x43, 0x69, 0x01, 0x47, 0xa8, 0xfc, 0x94, 0x45, 0x93, 0xea, 0xaf, 0x25, 0x8b, 0x55,
            0x34, 0x6d,
        ];
        for (index, byte) in iid_bytes.iter().enumerate() {
            memory.write_u8(iid + index as u64, *byte);
        }
        let out = base + 0x8010;
        memory.map_bytes(out, &[0u8; 8]);
        let mut state = CpuState::new(GuestArch::X64);
        let desc = build_work_graph_state_object_desc(&mut memory, base + 0x2000);
        // CreateStateObject errors.
        for (device_obj, desc_ptr, iid_ptr, out_ptr, expected) in [
            (list, desc, iid, out, E_INVALIDARG),
            (device, 0, iid, out, E_INVALIDARG),
            (device, desc, base + 0x8020, out, E_NOINTERFACE),
            (device, 0x5000, iid, out, E_INVALIDARG),
        ] {
            memory.map_bytes(base + 0x8020, &[0xBB; 16]);
            state.set(Register::Rsp, base + 0x100);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, desc_ptr);
            state.set(Register::R8, iid_ptr);
            state.set(Register::R9, out_ptr);
            memory.write_u64(base + 0x100, 0x1000_0900);
            runtime
                .dispatch_import(create_state_object, &mut state, &mut memory)
                .expect("CreateStateObject error path");
            assert_eq!(state.get(Register::Rax), expected);
        }
        state.set(Register::Rsp, base + 0x140);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, desc);
        state.set(Register::R8, iid);
        state.set(Register::R9, out);
        memory.write_u64(base + 0x140, 0x1000_0901);
        runtime
            .dispatch_import(create_state_object, &mut state, &mut memory)
            .expect("CreateStateObject");
        assert_eq!(state.get(Register::Rax), 0);
        let state_object = memory.read_u64(out).expect("state object");
        let handle = runtime.d3d12_state_object_handles[&state_object];
        let identifier = runtime
            .d3d12_runtime
            .work_graph_program_identifier(handle, "graph")
            .expect("identifier");

        // SetPipelineState1 accepts the COM state object and the direct
        // DXIL reader extracts bytecode from a real state-object desc.
        let set_pipeline = memory
            .read_u64(memory.read_u64(list).expect("list vtable") + 64 * 8)
            .expect("SetPipelineState1");
        state.set(Register::Rsp, base + 0x1040);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, state_object);
        memory.write_u64(base + 0x1040, 0x1000_0900_1);
        runtime
            .dispatch_import(set_pipeline, &mut state, &mut memory)
            .expect("SetPipelineState1 COM");
        assert_eq!(state.get(Register::Rax), 0);
        let dxil_desc = build_raytracing_state_object_desc(&mut memory, base + 0x11000, "raygen");
        assert_eq!(
            runtime.read_dxil_from_state_object(&memory, dxil_desc),
            vec![0x44, 0x58, 0x42, 0x43]
        );
        assert!(
            runtime
                .read_dxil_from_state_object(&memory, desc)
                .is_empty()
        );

        // CreateCommandSignature handler error matrix.
        let create_signature = memory
            .read_u64(device_vtable + 10 * 8)
            .expect("CreateCommandSignature");
        let signature_desc = base + 0x1050;
        let signature_out = base + 0x1070;
        memory.map_bytes(signature_desc, &[0u8; 32]);
        memory.map_bytes(signature_out, &[0u8; 8]);
        let error = runtime
            .dispatch_import(
                create_signature,
                &mut {
                    let mut s = CpuState::new(GuestArch::X64);
                    s.set(Register::Rsp, base + 0x1080);
                    s.set(Register::Rcx, list);
                    s.set(Register::Rdx, signature_desc);
                    s.set(Register::R8, signature_out);
                    memory.write_u64(base + 0x1080, 0x1000_0901_1);
                    s
                },
                &mut memory,
            )
            .expect_err("non-device command signature");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        for (desc_ptr, expected) in [(0u64, E_INVALIDARG), (signature_desc, E_INVALIDARG)] {
            write_u32(&mut memory, signature_desc, 16);
            write_u32(&mut memory, signature_desc + 4, 5000);
            state.set(Register::Rsp, base + 0x10c0);
            state.set(Register::Rcx, device);
            state.set(Register::Rdx, desc_ptr);
            state.set(Register::R8, signature_out);
            memory.write_u64(base + 0x10c0, 0x1000_0902_1);
            runtime
                .dispatch_import(create_signature, &mut state, &mut memory)
                .expect("signature arg count");
            assert_eq!(state.get(Register::Rax), expected);
        }
        for (ty, stride, expected) in [(1u32, 20u32, 0u64), (0, 0, E_INVALIDARG)] {
            write_u32(&mut memory, signature_desc, stride);
            write_u32(&mut memory, signature_desc + 4, 1);
            let argument_desc = base + 0x10e0;
            write_u64(&mut memory, signature_desc + 8, argument_desc);
            write_u32(&mut memory, argument_desc, ty);
            state.set(Register::Rsp, base + 0x1100);
            state.set(Register::Rcx, device);
            state.set(Register::Rdx, signature_desc);
            state.set(Register::R8, signature_out);
            memory.write_u64(base + 0x1100, 0x1000_0903_1);
            runtime
                .dispatch_import(create_signature, &mut state, &mut memory)
                .expect("signature type/stride");
            assert_eq!(state.get(Register::Rax), expected);
        }
        write_u32(&mut memory, signature_desc, 16);
        write_u32(&mut memory, signature_desc + 4, 1);
        let argument_desc = base + 0x10e0;
        write_u64(&mut memory, signature_desc + 8, argument_desc);
        write_u32(&mut memory, argument_desc, 0);
        state.set(Register::Rsp, base + 0x1140);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, signature_desc);
        state.set(Register::R8, signature_out);
        memory.write_u64(base + 0x1140, 0x1000_0904_1);
        runtime
            .dispatch_import(create_signature, &mut state, &mut memory)
            .expect("signature valid");
        assert_eq!(state.get(Register::Rax), 0);

        // AddToStateObject errors.
        let addition = build_raytracing_state_object_desc(&mut memory, base + 0x9000, "miss");
        let child_out = base + 0x8030;
        memory.map_bytes(child_out, &[0u8; 8]);

        // AddToStateObject runtime rejection (parent did not opt in).
        let plain_desc = build_raytracing_state_object_desc(&mut memory, base + 0x12000, "plain");
        // Clear the ALLOW_STATE_OBJECT_ADDITIONS flag in the state config.
        write_u32(&mut memory, base + 0x12000 + 0x200, 0);
        state.set(Register::Rsp, base + 0x1180);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, plain_desc);
        state.set(Register::R8, iid);
        state.set(Register::R9, out);
        memory.write_u64(base + 0x1180, 0x1000_0905_1);
        runtime
            .dispatch_import(create_state_object, &mut state, &mut memory)
            .expect("plain state object");
        let plain = memory.read_u64(out).expect("plain state object ptr");
        state.set(Register::Rsp, base + 0x11c0);
        state.set(Register::Rcx, device);
        state.set(Register::Rdx, addition);
        state.set(Register::R8, plain);
        state.set(Register::R9, iid);
        memory.write_u64(base + 0x11c0, 0x1000_0906_1);
        memory.write_u64(base + 0x11c0 + 0x28, child_out);
        runtime
            .dispatch_import(add_to_state_object, &mut state, &mut memory)
            .expect("AddToStateObject runtime rejection");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        for (device_obj, addition_ptr, parent, iid_ptr, out_ptr, expected) in [
            (list, addition, state_object, iid, child_out, E_INVALIDARG),
            (device, 0, state_object, iid, child_out, E_INVALIDARG),
            (device, addition, 0x9999, iid, child_out, E_INVALIDARG),
            (
                device,
                addition,
                state_object,
                base + 0x8040,
                child_out,
                E_NOINTERFACE,
            ),
            (device, 0x5000, state_object, iid, child_out, E_INVALIDARG),
        ] {
            memory.map_bytes(base + 0x8040, &[0xCC; 16]);
            state.set(Register::Rsp, base + 0x180);
            state.set(Register::Rcx, device_obj);
            state.set(Register::Rdx, addition_ptr);
            state.set(Register::R8, parent);
            state.set(Register::R9, iid_ptr);
            memory.write_u64(base + 0x180, 0x1000_0902);
            memory.write_u64(base + 0x180 + 0x28, out_ptr);
            runtime
                .dispatch_import(add_to_state_object, &mut state, &mut memory)
                .expect("AddToStateObject error path");
            assert_eq!(state.get(Register::Rax), expected);
        }

        // Child GetDevice through the state-object vtable.
        let vtable = memory.read_u64(state_object).expect("state vtable");
        let get_device = memory.read_u64(vtable + 7 * 8).expect("GetDevice");
        let qi_out = base + 0x8050;
        memory.map_bytes(qi_out, &[0u8; 8]);
        memory.map_bytes(base + 0x8060, &[0xDD; 16]);
        state.set(Register::Rsp, base + 0x1c0);
        state.set(Register::Rcx, state_object);
        state.set(Register::Rdx, base + 0x8060);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x1c0, 0x1000_0903);
        runtime
            .dispatch_import(get_device, &mut state, &mut memory)
            .expect("GetDevice bad iid");
        assert_eq!(state.get(Register::Rax), E_NOINTERFACE);
        state.set(Register::Rsp, base + 0x200);
        state.set(Register::Rcx, state_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x200, 0x1000_0904);
        runtime
            .dispatch_import(get_device, &mut state, &mut memory)
            .expect("GetDevice null iid");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rsp, base + 0x240);
        state.set(Register::Rcx, 0x9999);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, qi_out);
        memory.write_u64(base + 0x240, 0x1000_0905);
        runtime
            .dispatch_import(get_device, &mut state, &mut memory)
            .expect("GetDevice unknown");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);

        // SetPipelineState1 fallback for a malformed description.
        let set_pipeline = memory
            .read_u64(memory.read_u64(list).expect("list vtable") + 64 * 8)
            .expect("SetPipelineState1");
        write_u32(&mut memory, base + 0x5000, 1);
        state.set(Register::Rsp, base + 0x280);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, base + 0x5000);
        memory.write_u64(base + 0x280, 0x1000_0906);
        runtime
            .dispatch_import(set_pipeline, &mut state, &mut memory)
            .expect("SetPipelineState1 fallback");
        assert_eq!(state.get(Register::Rax), 0);
        state.set(Register::Rsp, base + 0x2c0);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, 0);
        memory.write_u64(base + 0x2c0, 0x1000_0907);
        runtime
            .dispatch_import(set_pipeline, &mut state, &mut memory)
            .expect("SetPipelineState1 null");
        assert_eq!(state.get(Register::Rax), 0);

        // SetProgram / DispatchGraph error branches.
        let list_vtable = memory.read_u64(list).expect("list vtable");
        let set_program = memory.read_u64(list_vtable + 73 * 8).expect("SetProgram");
        let dispatch_graph = memory
            .read_u64(list_vtable + 74 * 8)
            .expect("DispatchGraph");
        let set_desc = base + 0x5100;
        memory.map_bytes(set_desc, &[0u8; 0x80]);
        for (desc_ptr, expected) in [(0u64, E_INVALIDARG), (set_desc, E_NOTIMPL)] {
            state.set(Register::Rsp, base + 0x300);
            state.set(Register::Rcx, list);
            state.set(Register::Rdx, desc_ptr);
            memory.write_u64(base + 0x300, 0x1000_0908);
            runtime
                .dispatch_import(set_program, &mut state, &mut memory)
                .expect("SetProgram null/type");
            assert_eq!(state.get(Register::Rax), expected);
        }
        write_u32(&mut memory, set_desc, 5);
        for (index, byte) in identifier.iter().enumerate() {
            memory.write_u8(set_desc + 8 + index as u64, *byte);
        }
        write_u32(&mut memory, set_desc + 40, 0x4);
        state.set(Register::Rsp, base + 0x340);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, set_desc);
        memory.write_u64(base + 0x340, 0x1000_0909);
        runtime
            .dispatch_import(set_program, &mut state, &mut memory)
            .expect("SetProgram bad flags");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        write_u32(&mut memory, set_desc + 40, 0);
        write_u64(&mut memory, set_desc + 48, 4);
        write_u64(&mut memory, set_desc + 56, 8);
        state.set(Register::Rsp, base + 0x380);
        state.set(Register::Rcx, list);
        state.set(Register::Rdx, set_desc);
        memory.write_u64(base + 0x380, 0x1000_090a);
        runtime
            .dispatch_import(set_program, &mut state, &mut memory)
            .expect("SetProgram misaligned backing");
        assert_eq!(state.get(Register::Rax), E_INVALIDARG);
        write_u64(&mut memory, set_desc + 48, 0);
        write_u64(&mut memory, set_desc + 56, 0);
        for (desc_ptr, expected) in [(0u64, E_INVALIDARG), (base + 0x5200, E_INVALIDARG)] {
            write_u32(&mut memory, base + 0x5200, 99);
            state.set(Register::Rsp, base + 0x3c0);
            state.set(Register::Rcx, list);
            state.set(Register::Rdx, desc_ptr);
            memory.write_u64(base + 0x3c0, 0x1000_090b);
            runtime
                .dispatch_import(dispatch_graph, &mut state, &mut memory)
                .expect("DispatchGraph error");
            assert_eq!(state.get(Register::Rax), expected);
        }
    });
}
