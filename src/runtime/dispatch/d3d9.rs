//! D3D9 COM object allocators and device gap-fill handlers, moved out of the
//! runtime monolith as inherent `PeHostRuntime` impls.

use super::super::*;

impl PeHostRuntime {
    // ── D3D9 COM object allocators (Phase 1.5) ──────────────────────────────

    pub(crate) fn alloc_d3d9_factory_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        // IDirect3D9 has ~20 methods. Fill with unsupported defaults, then
        // wire up the ones we implement.
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IDirect3D9::QueryInterface"); 20];
        methods[0] = unsupported_method(&self.telemetry, "IDirect3D9::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[3] = HostThunk::D3d9FactoryCreateDevice;
        methods[4] = HostThunk::D3d9FactoryGetAdapterCount;
        methods[5] = HostThunk::D3d9FactoryGetAdapterIdentifier;
        methods[6] = HostThunk::D3d9FactoryGetAdapterModeCount;
        methods[7] = HostThunk::D3d9FactoryGetAdapterDisplayMode;
        methods[8] = HostThunk::D3d9FactoryGetDeviceCaps;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d9Factory, vtable)?;
        self.d3d9_factories.insert(object);
        Ok(object)
    }

    pub(crate) fn alloc_d3d9_device_object(
        &mut self,
        memory: &mut MemoryImage,
        device_id: D3d9DeviceId,
        present_params: D3dPresentParameters,
    ) -> AppResult<u64> {
        // IDirect3DDevice9 has 105 vtable slots. Fill with unsupported, wire up
        // the methods we handle for basic fixed-function rendering.
        let mut methods = vec![unsupported_method(&self.telemetry, "IDirect3DDevice9::?"); 105];

        // Standard COM (slots 0-2)
        methods[0] = unsupported_method(&self.telemetry, "IDirect3DDevice9::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;

        // State queries (slot 3)
        methods[3] = HostThunk::D3d9DeviceTestCooperativeLevel;

        // Capabilities (slot 7)
        methods[7] = HostThunk::D3d9DeviceGetDeviceCaps;

        // Reset / Present (slots 16-17)
        methods[16] = HostThunk::D3d9DeviceReset;
        methods[17] = HostThunk::D3d9DevicePresent;

        // Back buffer / render target (slots 18-22)
        methods[18] = HostThunk::D3d9DeviceGetBackBuffer;
        methods[19] = HostThunk::D3d9DeviceGetRenderTarget;
        methods[20] = HostThunk::D3d9DeviceSetRenderTarget;
        methods[21] = HostThunk::D3d9DeviceGetDepthStencilSurface;
        methods[22] = HostThunk::D3d9DeviceSetDepthStencilSurface;

        // Scene management (slots 23-24)
        methods[23] = HostThunk::D3d9DeviceBeginScene;
        methods[24] = HostThunk::D3d9DeviceEndScene;

        // Clear (slot 25)
        methods[25] = HostThunk::D3d9DeviceClear;

        // Transform (slots 26-28)
        methods[26] = HostThunk::D3d9DeviceSetTransform;
        methods[27] = HostThunk::D3d9DeviceGetTransform;

        // Viewport (slots 29-30)
        methods[29] = HostThunk::D3d9DeviceSetViewport;
        methods[30] = HostThunk::D3d9DeviceGetViewport;

        // Material (slots 31-32)
        methods[31] = HostThunk::D3d9DeviceSetMaterial;

        // Light (slots 33-36)
        methods[33] = HostThunk::D3d9DeviceSetLight;
        methods[35] = HostThunk::D3d9DeviceLightEnable;

        // Clip plane (slots 37-38)
        methods[37] = HostThunk::D3d9DeviceSetClipPlane;

        // Render states (slots 39-40)
        methods[39] = HostThunk::D3d9DeviceSetRenderState;
        methods[40] = HostThunk::D3d9DeviceGetRenderState;

        // Texture (slots 46-49)
        methods[46] = HostThunk::D3d9DeviceGetTexture;
        methods[47] = HostThunk::D3d9DeviceSetTexture;
        methods[49] = HostThunk::D3d9DeviceSetTextureStageState;

        // Sampler state (slots 50-51)
        methods[51] = HostThunk::D3d9DeviceSetSamplerState;

        // Scissor rect (slots 57-58)
        methods[57] = HostThunk::D3d9DeviceSetScissorRect;

        // Draw (slots 63-66)
        methods[63] = HostThunk::D3d9DeviceDrawPrimitive;
        methods[64] = HostThunk::D3d9DeviceDrawIndexedPrimitive;
        methods[65] = HostThunk::D3d9DeviceDrawPrimitiveUP;
        methods[66] = HostThunk::D3d9DeviceDrawIndexedPrimitiveUP;

        // Vertex/pixel shader (slots 71-76)
        methods[72] = HostThunk::D3d9DeviceSetVertexShader;
        methods[75] = HostThunk::D3d9DeviceSetPixelShader;

        // Resource creation (slots 77-82)
        methods[77] = HostThunk::D3d9DeviceCreateVertexBuffer;
        methods[78] = HostThunk::D3d9DeviceCreateIndexBuffer;
        methods[79] = HostThunk::D3d9DeviceCreateTexture;

        // Shader constants (slots 84-87)
        methods[84] = HostThunk::D3d9DeviceSetVertexShaderConstantF;
        methods[86] = HostThunk::D3d9DeviceSetPixelShaderConstantF;

        // Stream source / indices (slots 88-93)
        methods[88] = HostThunk::D3d9DeviceSetStreamSource;
        methods[89] = HostThunk::D3d9DeviceGetStreamSource;
        methods[90] = unsupported_method(&self.telemetry, "IDirect3DDevice9::SetStreamSourceFreq");
        methods[92] = HostThunk::D3d9DeviceSetIndices;
        methods[93] = HostThunk::D3d9DeviceGetIndices;

        // Render target / depth-stencil creation (slots 94-95)
        methods[94] = HostThunk::D3d9DeviceCreateRenderTarget;
        methods[95] = HostThunk::D3d9DeviceCreateDepthStencilSurface;

        // Query creation (slot 82)
        methods[82] = HostThunk::D3d9DeviceCreateQuery;

        // Swap chain (slots 13-15)
        methods[13] = HostThunk::D3d9DeviceGetSwapChain;
        methods[14] =
            unsupported_method(&self.telemetry, "IDirect3DDevice9::GetNumberOfSwapChains");

        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d9Device, vtable)?;

        // Create a Direct3D9Device for state tracking, indexed by device_id
        // (device_id comes from the shim's create_device call)
        let swapchain_width = present_params.back_buffer_width.max(1);
        let swapchain_height = present_params.back_buffer_height.max(1);
        let shim_device = crate::d3d11::Direct3D9Device {
            id: device_id,
            state: D3d9StateBlock::new(),
            present_params,
            swapchain_width,
            swapchain_height,
        };
        self.d3d9_devices.insert(object, shim_device);

        Ok(object)
    }

    pub(crate) fn alloc_d3d9_vertex_buffer_object(
        &mut self,
        memory: &mut MemoryImage,
        size: usize,
        fvf: u32,
        stride: u32,
    ) -> AppResult<u64> {
        let methods = vec![
            unsupported_method(&self.telemetry, "IDirect3DVertexBuffer9::QueryInterface"),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::D3d9VertexBufferLock,
            HostThunk::D3d9VertexBufferUnlock,
            unsupported_method(&self.telemetry, "IDirect3DVertexBuffer9::GetDesc"),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d9VertexBuffer, vtable)?;
        let vb = crate::d3d11::VertexBuffer9 {
            id: 0, // unused for guest-managed
            size,
            data: vec![0u8; size],
            fvf,
            stride,
        };
        self.d3d9_vertex_buffers.insert(object, vb);
        Ok(object)
    }

    pub(crate) fn alloc_d3d9_index_buffer_object(
        &mut self,
        memory: &mut MemoryImage,
        size: usize,
        format: bool,
    ) -> AppResult<u64> {
        let methods = vec![
            unsupported_method(&self.telemetry, "IDirect3DIndexBuffer9::QueryInterface"),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::D3d9IndexBufferLock,
            HostThunk::D3d9IndexBufferUnlock,
            unsupported_method(&self.telemetry, "IDirect3DIndexBuffer9::GetDesc"),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d9IndexBuffer, vtable)?;
        let ib = crate::d3d11::IndexBuffer9 {
            id: 0,
            size,
            format,
            data: vec![0u8; size],
        };
        self.d3d9_index_buffers.insert(object, ib);
        Ok(object)
    }

    pub(crate) fn alloc_d3d9_texture_object(
        &mut self,
        memory: &mut MemoryImage,
        width: u32,
        height: u32,
        levels: u32,
        format: u32,
    ) -> AppResult<u64> {
        let methods = vec![
            unsupported_method(&self.telemetry, "IDirect3DTexture9::QueryInterface"),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            unsupported_method(&self.telemetry, "IDirect3DTexture9::GetLevelDesc"),
            unsupported_method(&self.telemetry, "IDirect3DTexture9::GetSurfaceLevel"),
            HostThunk::D3d9TextureLockRect,
            HostThunk::D3d9TextureUnlockRect,
            unsupported_method(&self.telemetry, "IDirect3DTexture9::AddDirtyRect"),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d9Texture, vtable)?;
        let mut mip_levels = Vec::new();
        let mut mw = width;
        let mut mh = height;
        for _ in 0..levels {
            let pixel_count = (mw * mh * 4) as usize;
            mip_levels.push(vec![0u8; pixel_count]);
            mw = (mw / 2).max(1);
            mh = (mh / 2).max(1);
        }
        let tex = crate::d3d11::D3d9Texture {
            id: 0,
            width,
            height,
            levels: mip_levels,
            format,
        };
        self.d3d9_textures.insert(object, tex);
        Ok(object)
    }
    // ── D3D9 Device gap-fill dispatch handlers (Phase 3.3) ─────────────

    pub(crate) fn dispatch_d3d9_device_create_render_target(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _width = state.get(Register::Rdx) as u32;
        let _height = state.get(Register::R8) as u32;
        let _format = state.get(Register::R9) as u32;
        let sp = state.get(Register::Rsp);
        let _multi_sample = memory.read_u32(sp + 0x20)?;
        let _multi_quality = memory.read_u32(sp + 0x24)?;
        let _lockable = memory.read_u32(sp + 0x28)?;
        let surface_ptr = memory.read_u64(sp + 0x30)?;
        let _shared_handle = memory.read_u64(sp + 0x38)?;
        if surface_ptr != 0 {
            // IDirect3DSurface9 vtable: 13 methods (IUnknown[3] + IDirect3DResource9[5] + IDirect3DSurface9[5])
            let methods = vec![
                HostThunk::D3d9StubReturnOk,      // 0: QueryInterface
                HostThunk::GuestObjectAddRef,     // 1: AddRef
                HostThunk::GuestObjectRelease,    // 2: Release
                HostThunk::D3d9StubReturnOk,      // 3: GetDevice
                HostThunk::D3d9SetPrivateData,    // 4: SetPrivateData
                HostThunk::D3d9GetPrivateData,    // 5: GetPrivateData
                HostThunk::D3d9FreePrivateData,   // 6: FreePrivateData
                HostThunk::D3d9StubReturnOk,      // 7: GetContainer
                HostThunk::D3d9SurfaceGetDesc,    // 8: GetDesc
                HostThunk::D3d9SurfaceLockRect,   // 9: LockRect
                HostThunk::D3d9SurfaceUnlockRect, // 10: UnlockRect
                HostThunk::D3d9SurfaceGetDC,      // 11: GetDC
                HostThunk::D3d9SurfaceReleaseDC,  // 12: ReleaseDC
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let surface_object =
                self.alloc_guest_object(memory, GuestObjectKind::D3d9Surface, vtable)?;
            write_u64(memory, surface_ptr, surface_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::CreateRenderTarget",
            BTreeMap::from([
                ("width".to_string(), json!(_width)),
                ("height".to_string(), json!(_height)),
                ("format".to_string(), json!(_format)),
            ]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_create_depth_stencil_surface(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _width = state.get(Register::Rdx) as u32;
        let _height = state.get(Register::R8) as u32;
        let _format = state.get(Register::R9) as u32;
        let sp = state.get(Register::Rsp);
        let _multi_sample = memory.read_u32(sp + 0x20)?;
        let _multi_quality = memory.read_u32(sp + 0x24)?;
        let _discard = memory.read_u32(sp + 0x28)?;
        let surface_ptr = memory.read_u64(sp + 0x30)?;
        let _shared_handle = memory.read_u64(sp + 0x38)?;
        if surface_ptr != 0 {
            // IDirect3DSurface9 vtable: 13 methods (IUnknown[3] + IDirect3DResource9[5] + IDirect3DSurface9[5])
            let methods = vec![
                HostThunk::D3d9StubReturnOk,      // 0: QueryInterface
                HostThunk::GuestObjectAddRef,     // 1: AddRef
                HostThunk::GuestObjectRelease,    // 2: Release
                HostThunk::D3d9StubReturnOk,      // 3: GetDevice
                HostThunk::D3d9SetPrivateData,    // 4: SetPrivateData
                HostThunk::D3d9GetPrivateData,    // 5: GetPrivateData
                HostThunk::D3d9FreePrivateData,   // 6: FreePrivateData
                HostThunk::D3d9StubReturnOk,      // 7: GetContainer
                HostThunk::D3d9SurfaceGetDesc,    // 8: GetDesc
                HostThunk::D3d9SurfaceLockRect,   // 9: LockRect
                HostThunk::D3d9SurfaceUnlockRect, // 10: UnlockRect
                HostThunk::D3d9SurfaceGetDC,      // 11: GetDC
                HostThunk::D3d9SurfaceReleaseDC,  // 12: ReleaseDC
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let surface_object =
                self.alloc_guest_object(memory, GuestObjectKind::D3d9Surface, vtable)?;
            write_u64(memory, surface_ptr, surface_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::CreateDepthStencilSurface",
            BTreeMap::from([
                ("width".to_string(), json!(_width)),
                ("height".to_string(), json!(_height)),
                ("format".to_string(), json!(_format)),
            ]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_create_offscreen_plain_surface(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _width = state.get(Register::Rdx) as u32;
        let _height = state.get(Register::R8) as u32;
        let _format = state.get(Register::R9) as u32;
        let sp = state.get(Register::Rsp);
        let _pool = memory.read_u32(sp + 0x20)?;
        let surface_ptr = memory.read_u64(sp + 0x28)?;
        let _shared_handle = memory.read_u64(sp + 0x30)?;
        if surface_ptr != 0 {
            // IDirect3DSurface9 vtable: 13 methods (IUnknown[3] + IDirect3DResource9[5] + IDirect3DSurface9[5])
            let methods = vec![
                HostThunk::D3d9StubReturnOk,      // 0: QueryInterface
                HostThunk::GuestObjectAddRef,     // 1: AddRef
                HostThunk::GuestObjectRelease,    // 2: Release
                HostThunk::D3d9StubReturnOk,      // 3: GetDevice
                HostThunk::D3d9SetPrivateData,    // 4: SetPrivateData
                HostThunk::D3d9GetPrivateData,    // 5: GetPrivateData
                HostThunk::D3d9FreePrivateData,   // 6: FreePrivateData
                HostThunk::D3d9StubReturnOk,      // 7: GetContainer
                HostThunk::D3d9SurfaceGetDesc,    // 8: GetDesc
                HostThunk::D3d9SurfaceLockRect,   // 9: LockRect
                HostThunk::D3d9SurfaceUnlockRect, // 10: UnlockRect
                HostThunk::D3d9SurfaceGetDC,      // 11: GetDC
                HostThunk::D3d9SurfaceReleaseDC,  // 12: ReleaseDC
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let surface_object =
                self.alloc_guest_object(memory, GuestObjectKind::D3d9Surface, vtable)?;
            write_u64(memory, surface_ptr, surface_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::CreateOffscreenPlainSurface",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_get_render_target_data(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _src = state.get(Register::Rdx);
        let _dst = state.get(Register::R8);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::GetRenderTargetData",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_stretch_rect(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _src = state.get(Register::Rdx);
        let _dst = state.get(Register::R8);
        let _filter = state.get(Register::R9) as u32;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::StretchRect",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_get_front_buffer_data(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _index = state.get(Register::Rdx) as u32;
        let _buffer = state.get(Register::R8);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::GetFrontBufferData",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_update_surface(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _src = state.get(Register::Rdx);
        let _src_rect = state.get(Register::R8);
        let _dst = state.get(Register::R9);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::UpdateSurface",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_color_fill(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _surface = state.get(Register::Rdx);
        let _rect = state.get(Register::R8);
        let _color = state.get(Register::R9) as u32;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::ColorFill",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_create_vertex_declaration(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _decl_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if out_ptr != 0 {
            // IDirect3DVertexDeclaration9 vtable (IUnknown[3] + IDirect3DResource9[5] + GetDeclaration)
            let methods = vec![
                HostThunk::D3d9StubReturnOk,    // 0: QueryInterface
                HostThunk::GuestObjectAddRef,   // 1: AddRef
                HostThunk::GuestObjectRelease,  // 2: Release
                HostThunk::D3d9StubReturnOk,    // 3: GetDevice
                HostThunk::D3d9SetPrivateData,  // 4: SetPrivateData
                HostThunk::D3d9GetPrivateData,  // 5: GetPrivateData
                HostThunk::D3d9FreePrivateData, // 6: FreePrivateData
                HostThunk::D3d9StubReturnOk,    // 7: GetContainer
                HostThunk::D3d9StubReturnOk,    // 8: GetDeclaration
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let decl_object =
                self.alloc_guest_object(memory, GuestObjectKind::D3d9VertexDeclaration, vtable)?;
            write_u64(memory, out_ptr, decl_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::CreateVertexDeclaration",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_create_vertex_shader(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _func_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if out_ptr != 0 {
            // IDirect3DVertexShader9 vtable (IUnknown[3] + IDirect3DResource9[5] + GetFunction)
            let methods = vec![
                HostThunk::D3d9StubReturnOk,    // 0: QueryInterface
                HostThunk::GuestObjectAddRef,   // 1: AddRef
                HostThunk::GuestObjectRelease,  // 2: Release
                HostThunk::D3d9StubReturnOk,    // 3: GetDevice
                HostThunk::D3d9SetPrivateData,  // 4: SetPrivateData
                HostThunk::D3d9GetPrivateData,  // 5: GetPrivateData
                HostThunk::D3d9FreePrivateData, // 6: FreePrivateData
                HostThunk::D3d9StubReturnOk,    // 7: GetContainer
                HostThunk::D3d9StubReturnOk,    // 8: GetFunction
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let shader_object =
                self.alloc_guest_object(memory, GuestObjectKind::D3d9VertexShader, vtable)?;
            write_u64(memory, out_ptr, shader_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::CreateVertexShader",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_create_pixel_shader(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _func_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if out_ptr != 0 {
            // IDirect3DPixelShader9 vtable (IUnknown[3] + IDirect3DResource9[5] + GetFunction)
            let methods = vec![
                HostThunk::D3d9StubReturnOk,    // 0: QueryInterface
                HostThunk::GuestObjectAddRef,   // 1: AddRef
                HostThunk::GuestObjectRelease,  // 2: Release
                HostThunk::D3d9StubReturnOk,    // 3: GetDevice
                HostThunk::D3d9SetPrivateData,  // 4: SetPrivateData
                HostThunk::D3d9GetPrivateData,  // 5: GetPrivateData
                HostThunk::D3d9FreePrivateData, // 6: FreePrivateData
                HostThunk::D3d9StubReturnOk,    // 7: GetContainer
                HostThunk::D3d9StubReturnOk,    // 8: GetFunction
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let shader_object =
                self.alloc_guest_object(memory, GuestObjectKind::D3d9PixelShader, vtable)?;
            write_u64(memory, out_ptr, shader_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::CreatePixelShader",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_set_vertex_declaration(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _decl = state.get(Register::Rdx);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::SetVertexDeclaration",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d9_device_get_vertex_declaration(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _device_object = state.get(Register::Rcx);
        let _decl_out = state.get(Register::Rdx);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d9",
            "IDirect3DDevice9::GetVertexDeclaration",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }
}
