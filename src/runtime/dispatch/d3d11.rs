//! D3D11 object allocators, accessors and the Query/Predicate handler tail.
//! The methods are inherent `PeHostRuntime` impls moved out of the runtime
//! monolith; the dispatch match arms keep calling the same methods.

use super::super::*;

impl PeHostRuntime {
    pub(crate) fn alloc_d3d11_device_object(
        &mut self,
        memory: &mut MemoryImage,
        device: D3d11Device,
    ) -> AppResult<u64> {
        let mut device_methods =
            vec![unsupported_method(&self.telemetry, "ID3D11Device::unsupported"); 43];
        device_methods[0] = HostThunk::GraphicsObjectQueryInterface;
        device_methods[1] = HostThunk::GuestObjectAddRef;
        device_methods[2] = HostThunk::GuestObjectRelease;
        device_methods[3] = HostThunk::D3D11DeviceCreateBuffer;
        device_methods[4] = HostThunk::D3D11DeviceCreateTexture1D;
        device_methods[5] = HostThunk::D3D11DeviceCreateTexture2D;
        device_methods[6] = HostThunk::D3D11DeviceCreateTexture3D;
        device_methods[7] = HostThunk::D3D11DeviceCreateShaderResourceView;
        device_methods[8] = HostThunk::D3D11DeviceCreateUnorderedAccessView;
        device_methods[9] = HostThunk::D3D11DeviceCreateRenderTargetView;
        device_methods[10] = HostThunk::D3D11DeviceCreateDepthStencilView;
        device_methods[11] = HostThunk::D3D11DeviceCreateInputLayout;
        device_methods[12] = HostThunk::D3D11DeviceCreateVertexShader;
        device_methods[13] = HostThunk::D3D11DeviceCreateGeometryShader;
        device_methods[14] = HostThunk::D3D11DeviceCreateGeometryShaderWithStreamOutput;
        device_methods[15] = HostThunk::D3D11DeviceCreatePixelShader;
        device_methods[16] = HostThunk::D3D11DeviceCreateHullShader;
        device_methods[17] = HostThunk::D3D11DeviceCreateDomainShader;
        device_methods[18] = HostThunk::D3D11DeviceCreateComputeShader;
        device_methods[19] = HostThunk::D3D11DeviceCreateClassLinkage;
        device_methods[20] = HostThunk::D3D11DeviceCreateBlendState;
        device_methods[21] = HostThunk::D3D11DeviceCreateDepthStencilState;
        device_methods[22] = HostThunk::D3D11DeviceCreateRasterizerState;
        device_methods[23] = HostThunk::D3D11DeviceCreateSamplerState;
        device_methods[24] = HostThunk::D3D11DeviceCreateQuery;
        device_methods[25] = HostThunk::D3D11DeviceCreatePredicate;
        device_methods[26] = HostThunk::D3D11DeviceCreateCounter;
        device_methods[27] = HostThunk::D3D11DeviceCreateDeferredContext;
        device_methods[28] = HostThunk::D3D11DeviceOpenSharedResource;
        device_methods[29] = HostThunk::D3D11DeviceCheckFormatSupport;
        device_methods[30] = HostThunk::D3D11DeviceCheckMultisampleQualityLevels;
        device_methods[31] = HostThunk::D3D11DeviceCheckCounterInfo;
        device_methods[32] = HostThunk::D3D11DeviceCheckCounter;
        device_methods[33] = HostThunk::D3D11DeviceCheckFeatureSupport;
        device_methods[34] = HostThunk::DXGIFactoryGetPrivateData; // GetPrivateData
        device_methods[35] = HostThunk::DXGIFactorySetPrivateData; // SetPrivateData
        device_methods[36] = HostThunk::D3D11DeviceGetDeviceRemovedReason;
        device_methods[37] = HostThunk::DXGIFactorySetPrivateDataInterface;
        device_methods[38] = HostThunk::D3D11DeviceGetFeatureLevel;
        device_methods[39] = HostThunk::D3D11DeviceGetImmediateContext_Base; // ID3D11Device::GetImmediateContext (base)
        device_methods[40] = HostThunk::D3D11DeviceGetImmediateContext; // ID3D11Device1::GetImmediateContext1
        device_methods[41] = HostThunk::D3D11DeviceCreateDeferredContext1;
        device_methods[42] = HostThunk::D3D11DeviceGetImmediateContext2;

        let mut context_methods =
            vec![unsupported_method(&self.telemetry, "ID3D11DeviceContext::unsupported"); 70];
        context_methods[0] = HostThunk::GraphicsObjectQueryInterface;
        context_methods[1] = HostThunk::GuestObjectAddRef;
        context_methods[2] = HostThunk::GuestObjectRelease;
        // ID3D11DeviceChild methods (slots 3-6)
        context_methods[3] = HostThunk::D3D11DeviceContextGetDevice;
        context_methods[4] = HostThunk::DXGIFactoryGetPrivateData; // GetPrivateData
        context_methods[5] = HostThunk::DXGIFactorySetPrivateData; // SetPrivateData
        context_methods[6] = HostThunk::DXGIFactorySetPrivateDataInterface; // SetPrivateDataInterface
        context_methods[7] = HostThunk::D3D11DeviceContextVSSetConstantBuffers;
        context_methods[8] = HostThunk::D3D11DeviceContextPSSetShaderResources;
        context_methods[9] = HostThunk::D3D11DeviceContextPSSetShader;
        context_methods[10] = HostThunk::D3D11DeviceContextPSSetSamplers;
        context_methods[11] = HostThunk::D3D11DeviceContextVSSetShader;
        context_methods[12] = HostThunk::D3D11DeviceContextDrawIndexed;
        context_methods[13] = HostThunk::D3D11DeviceContextDraw;
        context_methods[14] = HostThunk::D3D11DeviceContextDrawAuto;
        context_methods[15] = HostThunk::D3D11DeviceContextClearRenderTargetView;
        context_methods[16] = HostThunk::D3D11DeviceContextClearDepthStencilView;
        context_methods[17] = HostThunk::D3D11DeviceContextIASetInputLayout;
        context_methods[18] = HostThunk::D3D11DeviceContextIASetVertexBuffers;
        context_methods[19] = HostThunk::D3D11DeviceContextIASetIndexBuffer;
        context_methods[20] = HostThunk::D3D11DeviceContextDrawIndexedInstanced;
        context_methods[21] = HostThunk::D3D11DeviceContextDrawInstanced;
        context_methods[22] = HostThunk::D3D11DeviceContextGSSetShader;
        context_methods[23] = HostThunk::D3D11DeviceContextGSSetConstantBuffers;
        context_methods[24] = HostThunk::D3D11DeviceContextIASetPrimitiveTopology;
        context_methods[25] = HostThunk::D3D11DeviceContextGSSetShaderResources;
        context_methods[26] = HostThunk::D3D11DeviceContextGSSetSamplers;
        context_methods[27] = HostThunk::D3D11DeviceContextHSSetShader;
        context_methods[28] = HostThunk::D3D11DeviceContextHSSetConstantBuffers;
        context_methods[29] = HostThunk::D3D11DeviceContextHSSetShaderResources;
        context_methods[30] = HostThunk::D3D11DeviceContextHSSetSamplers;
        context_methods[31] = HostThunk::D3D11DeviceContextDSSetShader;
        context_methods[32] = HostThunk::D3D11DeviceContextDSSetConstantBuffers;
        context_methods[33] = HostThunk::D3D11DeviceContextOMSetRenderTargets;
        context_methods[34] = HostThunk::D3D11DeviceContextDSSetShaderResources;
        context_methods[35] = HostThunk::D3D11DeviceContextOMSetBlendState;
        context_methods[36] = HostThunk::D3D11DeviceContextOMSetDepthStencilState;
        context_methods[37] = HostThunk::D3D11DeviceContextDSSetSamplers;
        context_methods[38] = HostThunk::D3D11DeviceContextVSSetShaderResources;
        context_methods[39] = HostThunk::D3D11DeviceContextVSSetSamplers;
        context_methods[40] = HostThunk::D3D11DeviceContextCSSetShaderResources;
        context_methods[41] = HostThunk::D3D11DeviceContextCSSetUnorderedAccessViews;
        context_methods[42] = HostThunk::D3D11DeviceContextCSSetSamplers;
        context_methods[43] = HostThunk::D3D11DeviceContextRSSetState;
        context_methods[44] = HostThunk::D3D11DeviceContextRSSetViewports;
        context_methods[45] = HostThunk::D3D11DeviceContextRSSetScissorRects;
        context_methods[46] = HostThunk::D3D11DeviceContextCSSetConstantBuffers;
        context_methods[47] = HostThunk::D3D11DeviceContextCopySubresourceRegion;
        context_methods[48] = HostThunk::D3D11DeviceContextUpdateSubresource;
        context_methods[49] = HostThunk::D3D11DeviceContextCopyResource;
        context_methods[50] = HostThunk::D3D11DeviceContextCopyStructureCount;
        context_methods[51] = HostThunk::D3D11DeviceContextBegin;
        context_methods[52] = HostThunk::D3D11DeviceContextEnd;
        context_methods[53] = HostThunk::D3D11DeviceContextGetData;
        context_methods[54] = HostThunk::D3D11DeviceContextResolveSubresource;
        context_methods[55] = HostThunk::D3D11DeviceContextSetPredication;
        context_methods[56] = HostThunk::D3D11DeviceContextGetPredication;
        context_methods[57] = HostThunk::D3D11DeviceContextMap;
        context_methods[58] = HostThunk::D3D11DeviceContextUnmap;
        context_methods[59] = HostThunk::D3D11DeviceContextGenerateMips;
        context_methods[60] = HostThunk::D3D11DeviceContextSetResourceMinLOD;
        context_methods[61] = HostThunk::D3D11DeviceContextGetResourceMinLOD;
        context_methods[62] = HostThunk::D3D11DeviceContextResolveSubresourceFlag;
        context_methods[63] = HostThunk::D3D11DeviceContextFinishCommandList;
        context_methods[64] = HostThunk::D3D11DeviceContextFlush;
        context_methods[65] = HostThunk::D3D11DeviceContextExecuteCommandList;
        context_methods[66] = HostThunk::D3D11DeviceContextClearState;
        context_methods[67] = HostThunk::D3D11DeviceContextClearUnorderedAccessViewUint;
        context_methods[68] = HostThunk::D3D11DeviceContextClearUnorderedAccessViewFloat;
        context_methods[69] = HostThunk::D3D11DeviceContextCSSetShader;

        let mut swapchain_methods =
            vec![unsupported_method(&self.telemetry, "IDXGISwapChain::unsupported"); 14];
        swapchain_methods[0] = HostThunk::GraphicsObjectQueryInterface;
        swapchain_methods[1] = HostThunk::GuestObjectAddRef;
        swapchain_methods[2] = HostThunk::GuestObjectRelease;
        swapchain_methods[8] = HostThunk::DXGISwapChainPresent;
        swapchain_methods[9] = HostThunk::DXGISwapChainGetBuffer;

        let device_vtable = self.alloc_guest_vtable(memory, device_methods)?;
        let context_vtable = self.alloc_guest_vtable(memory, context_methods)?;
        let swapchain_vtable = if device.swapchain_state().is_some() {
            Some(self.alloc_guest_vtable(memory, swapchain_methods)?)
        } else {
            None
        };

        let device_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11Device, device_vtable)?;
        let context_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11DeviceContext, context_vtable)?;
        let swapchain_object = if let Some(vtable) = swapchain_vtable {
            Some(self.alloc_guest_object(memory, GuestObjectKind::DxgiSwapChain, vtable)?)
        } else {
            None
        };
        if let Some(context_meta) = self.guest_objects.get_mut(&context_object) {
            context_meta.refcount = 0;
        }
        if let Some(swapchain_object) = swapchain_object
            && let Some(swapchain_meta) = self.guest_objects.get_mut(&swapchain_object)
        {
            swapchain_meta.refcount = 0;
        }

        self.add_ref_guest_object(device_object)?;
        if swapchain_object.is_some() {
            self.add_ref_guest_object(device_object)?;
        }

        self.d3d11_contexts
            .insert(context_object, GuestD3d11Context { device_object });
        if let Some(swapchain_object) = swapchain_object {
            self.d3d11_swapchains
                .insert(swapchain_object, GuestDxgiSwapChain { device_object });
        }
        self.d3d11_devices.insert(
            device_object,
            GuestD3d11Device {
                device,
                context_object,
                swapchain_object,
                backbuffer_objects: BTreeMap::new(),
            },
        );
        Ok(device_object)
    }

    pub(crate) fn alloc_d3d11_texture_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        resource_id: D3d11ResourceId,
    ) -> AppResult<u64> {
        let texture_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11Texture2D::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ],
        )?;
        let texture_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11Texture2D, texture_vtable)?;
        if let Some(texture_meta) = self.guest_objects.get_mut(&texture_object) {
            texture_meta.refcount = 0;
        }
        self.add_ref_guest_object(device_object)?;
        self.d3d11_textures.insert(
            texture_object,
            GuestD3d11Texture2D {
                device_object,
                resource_id,
            },
        );
        Ok(texture_object)
    }

    pub(crate) fn alloc_d3d11_buffer_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        resource_id: D3d11ResourceId,
    ) -> AppResult<u64> {
        let buffer_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11Buffer::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let buffer_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11Buffer, buffer_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_buffers.insert(
            buffer_object,
            GuestD3d11Buffer {
                device_object,
                resource_id,
            },
        );
        Ok(buffer_object)
    }

    pub(crate) fn alloc_d3d11_view_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        view_id: D3d11ViewId,
        kind: ViewKind,
    ) -> AppResult<u64> {
        let view_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11View::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let view_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11View, view_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_views.insert(
            view_object,
            GuestD3d11View {
                device_object,
                view_id,
                kind,
            },
        );
        Ok(view_object)
    }

    pub(crate) fn alloc_d3d11_input_layout_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        layout_id: InputLayoutId,
    ) -> AppResult<u64> {
        let layout_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11InputLayout::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let layout_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11InputLayout, layout_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_input_layouts.insert(
            layout_object,
            GuestD3d11InputLayout {
                device_object,
                layout_id,
            },
        );
        Ok(layout_object)
    }

    pub(crate) fn alloc_d3d11_shader_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        shader_id: u64,
        stage: D3d11ShaderStage,
    ) -> AppResult<u64> {
        let shader_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let shader_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11Shader, shader_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_shaders.insert(
            shader_object,
            GuestD3d11Shader {
                device_object,
                shader_id,
                stage,
            },
        );
        Ok(shader_object)
    }

    pub(crate) fn alloc_d3d11_blend_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11BlendState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let state_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11BlendState, state_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_blend_states.insert(
            state_object,
            GuestD3d11BlendState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }

    pub(crate) fn alloc_d3d11_rasterizer_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11RasterizerState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let state_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11RasterizerState, state_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_rasterizer_states.insert(
            state_object,
            GuestD3d11RasterizerState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }

    pub(crate) fn alloc_d3d11_depth_stencil_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11DepthStencilState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let state_object = self.alloc_guest_object(
            memory,
            GuestObjectKind::D3d11DepthStencilState,
            state_vtable,
        )?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_depth_stencil_states.insert(
            state_object,
            GuestD3d11DepthStencilState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }

    pub(crate) fn alloc_d3d11_sampler_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "ID3D11SamplerState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetDevice"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::GetPrivateData"),
                unsupported_method(&self.telemetry, "ID3D11DeviceChild::SetPrivateData"),
                unsupported_method(
                    &self.telemetry,
                    "ID3D11DeviceChild::SetPrivateDataInterface",
                ),
            ],
        )?;
        let state_object =
            self.alloc_guest_object(memory, GuestObjectKind::D3d11SamplerState, state_vtable)?;
        self.add_ref_guest_object(device_object)?;
        self.d3d11_sampler_states.insert(
            state_object,
            GuestD3d11SamplerState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }
    pub(crate) fn destroy_d3d11_device_object(&mut self, address: u64) -> AppResult<()> {
        let device = self.d3d11_devices.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 device {address:#x}"),
            )
        })?;
        for texture_object in device.backbuffer_objects.into_values() {
            let _ = self.destroy_d3d11_texture_object(texture_object);
        }
        self.d3d11_contexts.remove(&device.context_object);
        self.guest_objects.remove(&device.context_object);
        if let Some(swapchain_object) = device.swapchain_object {
            self.d3d11_swapchains.remove(&swapchain_object);
            self.guest_objects.remove(&swapchain_object);
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    pub(crate) fn destroy_d3d11_texture_object(&mut self, address: u64) -> AppResult<()> {
        let texture = self.d3d11_textures.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 texture {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(texture.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_buffer_object(&mut self, address: u64) -> AppResult<()> {
        let buffer = self.d3d11_buffers.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 buffer {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(buffer.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_view_object(&mut self, address: u64) -> AppResult<()> {
        let view = self.d3d11_views.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 view {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(view.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_input_layout_object(&mut self, address: u64) -> AppResult<()> {
        let input_layout = self.d3d11_input_layouts.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 input layout {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(input_layout.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_shader_object(&mut self, address: u64) -> AppResult<()> {
        let shader = self.d3d11_shaders.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 shader {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(shader.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_blend_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self.d3d11_blend_states.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 blend state {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(state.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_rasterizer_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self
            .d3d11_rasterizer_states
            .remove(&address)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 rasterizer state {address:#x}"),
                )
            })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(state.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_depth_stencil_state_object(
        &mut self,
        address: u64,
    ) -> AppResult<()> {
        let state = self
            .d3d11_depth_stencil_states
            .remove(&address)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 depth stencil state {address:#x}"),
                )
            })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(state.device_object)?;
        Ok(())
    }

    pub(crate) fn destroy_d3d11_sampler_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self.d3d11_sampler_states.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 sampler state {address:#x}"),
            )
        })?;
        self.guest_objects.remove(&address);
        self.release_guest_object(state.device_object)?;
        Ok(())
    }

    pub(crate) fn d3d11_device(&self, address: u64) -> AppResult<&GuestD3d11Device> {
        self.d3d11_devices.get(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 device {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_device_mut(&mut self, address: u64) -> AppResult<&mut GuestD3d11Device> {
        self.d3d11_devices.get_mut(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 device {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_context(&self, address: u64) -> AppResult<GuestD3d11Context> {
        self.d3d11_contexts.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 context {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_deferred_context(
        &self,
        address: u64,
    ) -> AppResult<&GuestD3d11DeferredContext> {
        self.d3d11_deferred_contexts.get(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 deferred context {address:#x}"),
            )
        })
    }

    #[allow(dead_code)] // D3D11 deferred-context accessor; used by tests
    pub(crate) fn d3d11_deferred_context_mut(
        &mut self,
        address: u64,
    ) -> AppResult<&mut GuestD3d11DeferredContext> {
        self.d3d11_deferred_contexts
            .get_mut(&address)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 deferred context {address:#x}"),
                )
            })
    }

    /// Resolves a D3D11 context object (immediate or deferred) to its
    /// underlying device. Returns `None` if the context is invalid.
    pub(crate) fn d3d11_device_for_context(
        &self,
        context_object: u64,
    ) -> Option<&GuestD3d11Device> {
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            self.d3d11_device(deferred.device_object).ok()
        } else if let Ok(context) = self.d3d11_context(context_object) {
            self.d3d11_device(context.device_object).ok()
        } else {
            None
        }
    }

    pub(crate) fn d3d11_swapchain(&self, address: u64) -> AppResult<GuestDxgiSwapChain> {
        self.d3d11_swapchains.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown DXGI swapchain {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_texture(&self, address: u64) -> AppResult<GuestD3d11Texture2D> {
        self.d3d11_textures.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 texture {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_buffer(&self, address: u64) -> AppResult<GuestD3d11Buffer> {
        self.d3d11_buffers.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 buffer {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_view(&self, address: u64) -> AppResult<GuestD3d11View> {
        self.d3d11_views.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 view {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_input_layout(&self, address: u64) -> AppResult<GuestD3d11InputLayout> {
        self.d3d11_input_layouts
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 input layout {address:#x}"),
                )
            })
    }

    pub(crate) fn d3d11_shader(&self, address: u64) -> AppResult<GuestD3d11Shader> {
        self.d3d11_shaders.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D11 shader {address:#x}"),
            )
        })
    }

    pub(crate) fn d3d11_blend_state(&self, address: u64) -> AppResult<GuestD3d11BlendState> {
        self.d3d11_blend_states
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 blend state {address:#x}"),
                )
            })
    }

    pub(crate) fn d3d11_rasterizer_state(
        &self,
        address: u64,
    ) -> AppResult<GuestD3d11RasterizerState> {
        self.d3d11_rasterizer_states
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 rasterizer state {address:#x}"),
                )
            })
    }

    pub(crate) fn d3d11_depth_stencil_state(
        &self,
        address: u64,
    ) -> AppResult<GuestD3d11DepthStencilState> {
        self.d3d11_depth_stencil_states
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 depth stencil state {address:#x}"),
                )
            })
    }

    pub(crate) fn d3d11_sampler_state(&self, address: u64) -> AppResult<GuestD3d11SamplerState> {
        self.d3d11_sampler_states
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown D3D11 sampler state {address:#x}"),
                )
            })
    }

    pub(crate) fn d3d11_resource_owner_and_id(
        &self,
        address: u64,
    ) -> AppResult<(u64, D3d11ResourceId)> {
        match self.guest_object_kind(address)? {
            GuestObjectKind::D3d11Buffer => {
                let buffer = self.d3d11_buffer(address)?;
                Ok((buffer.device_object, buffer.resource_id))
            }
            GuestObjectKind::D3d11Texture2D => {
                let texture = self.d3d11_texture(address)?;
                Ok((texture.device_object, texture.resource_id))
            }
            kind => Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "unsupported D3D11 resource object kind {:?} for object {address:#x}",
                    kind
                ),
            )),
        }
    }

    pub(crate) fn dispatch_d3d11_create_buffer(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateBuffer on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let initial_data_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let byte_width = read_d3d11_buffer_byte_width(memory, desc_ptr)?;
        let (label, usage_hint) = read_d3d11_buffer_usage(memory, desc_ptr)?;
        let resource_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_buffer(&label, byte_width, usage_hint)
        {
            Ok(resource_id) => resource_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        if initial_data_ptr != 0 {
            let src_ptr = read_guest_u64(memory, initial_data_ptr)?;
            if src_ptr != 0 {
                let bytes = read_guest_bytes(memory, src_ptr, byte_width)?;
                self.d3d11_device_mut(device_object)?
                    .device
                    .update_subresource(resource_id, &bytes)?;
            }
        }
        let buffer_object = self.alloc_d3d11_buffer_object(memory, device_object, resource_id)?;
        write_u64(memory, out_ptr, buffer_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateBuffer",
            BTreeMap::from([
                ("byte_width".to_string(), json!(byte_width)),
                ("initialized".to_string(), json!(initial_data_ptr != 0)),
                ("label".to_string(), json!(label)),
                (
                    "usage_hint".to_string(),
                    json!(match usage_hint {
                        ResourceUsageHint::Buffer {
                            role,
                            cpu_write_frequent,
                        } => format!("{:?}:{}", role, cpu_write_frequent),
                        other => format!("{:?}", other),
                    }),
                ),
            ]),
            json!(buffer_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_texture2d(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateTexture2D on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let initial_data_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_texture2d_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let resource_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_texture_2d_with_usage(
                &desc.label,
                desc.width,
                desc.height,
                desc.format,
                desc.usage_hint,
            ) {
            Ok(resource_id) => resource_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        if initial_data_ptr != 0 {
            let src_ptr = read_guest_u64(memory, initial_data_ptr)?;
            if src_ptr != 0 {
                let bytes = read_guest_bytes(memory, src_ptr, desc.byte_width)?;
                self.d3d11_device_mut(device_object)?
                    .device
                    .update_subresource(resource_id, &bytes)?;
            }
        }
        let texture_object = self.alloc_d3d11_texture_object(memory, device_object, resource_id)?;
        write_u64(memory, out_ptr, texture_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateTexture2D",
            BTreeMap::from([
                ("width".to_string(), json!(desc.width)),
                ("height".to_string(), json!(desc.height)),
                ("format".to_string(), json!(format!("{:?}", desc.format))),
                ("label".to_string(), json!(desc.label)),
            ]),
            json!(texture_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_shader_resource_view(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "ID3D11Device::CreateShaderResourceView on non-device object {device_object:#x}"
                ),
            ));
        }
        let resource_object = state.get(Register::Rdx);
        let desc_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if resource_object == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (resource_device_object, resource_id) =
            self.d3d11_resource_owner_and_id(resource_object)?;
        if resource_device_object != device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let default_format = self
            .d3d11_device(device_object)?
            .device
            .resource_desc(resource_id)?
            .format;
        let format = if desc_ptr == 0 {
            default_format
        } else {
            read_d3d11_view_format(memory, desc_ptr, default_format)?
        };
        let view_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_shader_resource_view(resource_id, format)
        {
            Ok(view_id) => view_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let view_object =
            self.alloc_d3d11_view_object(memory, device_object, view_id, ViewKind::Srv)?;
        write_u64(memory, out_ptr, view_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateShaderResourceView",
            BTreeMap::from([("format".to_string(), json!(format!("{:?}", format)))]),
            json!(view_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_depth_stencil_view(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "ID3D11Device::CreateDepthStencilView on non-device object {device_object:#x}"
                ),
            ));
        }
        let resource_object = state.get(Register::Rdx);
        let desc_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if resource_object == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (resource_device_object, resource_id) =
            self.d3d11_resource_owner_and_id(resource_object)?;
        if resource_device_object != device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let default_format = self
            .d3d11_device(device_object)?
            .device
            .resource_desc(resource_id)?
            .format;
        let format = if desc_ptr == 0 {
            default_format
        } else {
            read_d3d11_view_format(memory, desc_ptr, default_format)?
        };
        let view_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_depth_stencil_view(resource_id, format)
        {
            Ok(view_id) => view_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let view_object =
            self.alloc_d3d11_view_object(memory, device_object, view_id, ViewKind::Dsv)?;
        write_u64(memory, out_ptr, view_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateDepthStencilView",
            BTreeMap::from([("format".to_string(), json!(format!("{:?}", format)))]),
            json!(view_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_render_target_view(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "ID3D11Device::CreateRenderTargetView on non-device object {device_object:#x}"
                ),
            ));
        }
        let resource_object = state.get(Register::Rdx);
        let desc_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if resource_object == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (resource_device_object, resource_id) =
            self.d3d11_resource_owner_and_id(resource_object)?;
        if resource_device_object != device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let default_format = self
            .d3d11_device(device_object)?
            .device
            .resource_desc(resource_id)?
            .format;
        let format = if desc_ptr == 0 {
            default_format
        } else {
            read_d3d11_view_format(memory, desc_ptr, default_format)?
        };
        let view_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_render_target_view(resource_id, format)
        {
            Ok(view_id) => view_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let view_object =
            self.alloc_d3d11_view_object(memory, device_object, view_id, ViewKind::Rtv)?;
        write_u64(memory, out_ptr, view_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateRenderTargetView",
            BTreeMap::from([("format".to_string(), json!(format!("{:?}", format)))]),
            json!(view_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_blend_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateBlendState on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_blend_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_blend_state(desc.clone());
        let state_object = self.alloc_d3d11_blend_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateBlendState",
            BTreeMap::from([
                (
                    "alpha_to_coverage_enable".to_string(),
                    json!(desc.alpha_to_coverage_enable),
                ),
                (
                    "independent_blend_enable".to_string(),
                    json!(desc.independent_blend_enable),
                ),
                (
                    "rt0_blend_enable".to_string(),
                    json!(desc.render_target[0].blend_enable),
                ),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_depth_stencil_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "ID3D11Device::CreateDepthStencilState on non-device object {device_object:#x}"
                ),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_depth_stencil_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_depth_stencil_state(desc.clone());
        let state_object =
            self.alloc_d3d11_depth_stencil_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateDepthStencilState",
            BTreeMap::from([
                ("depth_enable".to_string(), json!(desc.depth_enable)),
                ("depth_write_mask".to_string(), json!(desc.depth_write_mask)),
                ("depth_func".to_string(), json!(desc.depth_func)),
                ("stencil_enable".to_string(), json!(desc.stencil_enable)),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_rasterizer_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "ID3D11Device::CreateRasterizerState on non-device object {device_object:#x}"
                ),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_rasterizer_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_rasterizer_state(desc.clone());
        let state_object =
            self.alloc_d3d11_rasterizer_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateRasterizerState",
            BTreeMap::from([
                ("fill_mode".to_string(), json!(desc.fill_mode)),
                ("cull_mode".to_string(), json!(desc.cull_mode)),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_sampler_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateSamplerState on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_sampler_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_sampler_state(desc.clone());
        let state_object =
            self.alloc_d3d11_sampler_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateSamplerState",
            BTreeMap::from([
                ("filter".to_string(), json!(format!("{:?}", desc.filter))),
                ("address_u".to_string(), json!(desc.address_u)),
                ("address_v".to_string(), json!(desc.address_v)),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_input_layout(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateInputLayout on non-device object {device_object:#x}"),
            ));
        }
        let stack = state.get(Register::Rsp);
        let desc_ptr = state.get(Register::Rdx);
        let num_elements = state.get(Register::R8) as u32;
        let bytecode_ptr = state.get(Register::R9);
        let bytecode_len = memory.read_u64(stack + 0x20)? as usize;
        let out_ptr = memory.read_u64(stack + 0x28)?;
        if desc_ptr == 0
            || num_elements == 0
            || bytecode_ptr == 0
            || bytecode_len == 0
            || out_ptr == 0
        {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = read_d3d11_input_layout_desc(memory, desc_ptr, num_elements)?;
        let layout_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_input_layout(desc);
        let layout_object =
            self.alloc_d3d11_input_layout_object(memory, device_object, layout_id)?;
        write_u64(memory, out_ptr, layout_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateInputLayout",
            BTreeMap::from([
                ("elements".to_string(), json!(num_elements)),
                ("bytecode_len".to_string(), json!(bytecode_len)),
            ]),
            json!(layout_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_vs_set_constant_buffers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let start_slot = state.get(Register::Rdx) as u32;
        let num_buffers = state.get(Register::R8) as usize;
        let buffers_ptr = state.get(Register::R9);
        if start_slot != 0 || (num_buffers != 0 && buffers_ptr == 0) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut buffers = Vec::new();
        if num_buffers != 0 {
            let objects = read_guest_pointer_array(memory, buffers_ptr, num_buffers)?;
            if !objects.iter().all(|object| *object == 0) {
                buffers.reserve(objects.len());
                // Resolve device object for validation
                let device_object =
                    if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                        deferred.device_object
                    } else {
                        let context = self.d3d11_context(context_object)?;
                        context.device_object
                    };
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let buffer = self.d3d11_buffer(object)?;
                    if buffer.device_object != device_object {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    buffers.push(buffer.resource_id);
                }
            }
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .vs_set_constant_buffers(buffers.clone())?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .vs_set_constant_buffers(buffers.clone());
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::VSSetConstantBuffers",
            BTreeMap::from([("count".to_string(), json!(buffers.len()))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_ps_set_shader_resources(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let start_slot = state.get(Register::Rdx) as u32;
        let num_views = state.get(Register::R8) as usize;
        let views_ptr = state.get(Register::R9);
        if start_slot != 0 || (num_views != 0 && views_ptr == 0) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut views = Vec::new();
        if num_views != 0 {
            let objects = read_guest_pointer_array(memory, views_ptr, num_views)?;
            if !objects.iter().all(|object| *object == 0) {
                views.reserve(objects.len());
                // Resolve device object for validation
                let device_object =
                    if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                        deferred.device_object
                    } else {
                        let context = self.d3d11_context(context_object)?;
                        context.device_object
                    };
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let view = self.d3d11_view(object)?;
                    if view.device_object != device_object || view.kind != ViewKind::Srv {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    views.push(view.view_id);
                }
            }
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .ps_set_shader_resources(views.clone())?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .ps_set_shader_resources(views.clone());
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::PSSetShaderResources",
            BTreeMap::from([("count".to_string(), json!(views.len()))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_ps_set_samplers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let start_slot = state.get(Register::Rdx) as u32;
        let num_samplers = state.get(Register::R8) as usize;
        let samplers_ptr = state.get(Register::R9);
        if start_slot != 0 || (num_samplers != 0 && samplers_ptr == 0) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut samplers = Vec::new();
        if num_samplers != 0 {
            let objects = read_guest_pointer_array(memory, samplers_ptr, num_samplers)?;
            if !objects.iter().all(|object| *object == 0) {
                samplers.reserve(objects.len());
                // Resolve device object for validation
                let device_object =
                    if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                        deferred.device_object
                    } else {
                        let context = self.d3d11_context(context_object)?;
                        context.device_object
                    };
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let sampler = self.d3d11_sampler_state(object)?;
                    if sampler.device_object != device_object {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    samplers.push(sampler.state_id);
                }
            }
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .ps_set_samplers(samplers.clone())?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .ps_set_samplers(samplers.clone());
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::PSSetSamplers",
            BTreeMap::from([("count".to_string(), json!(samplers.len()))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_ia_set_input_layout(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let layout_object = state.get(Register::Rdx);
        if layout_object == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.ia_clear_input_layout()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .ia_clear_input_layout();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::IASetInputLayout",
                BTreeMap::new(),
                json!(0),
            );
            return Ok(());
        }
        let input_layout = self.d3d11_input_layout(layout_object)?;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if input_layout.device_object != deferred.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            deferred
                .deferred_context
                .ia_set_input_layout(input_layout.layout_id)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            if input_layout.device_object != context.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            self.d3d11_device_mut(context.device_object)?
                .device
                .ia_set_input_layout(input_layout.layout_id);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetInputLayout",
            BTreeMap::new(),
            json!(layout_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_ia_set_vertex_buffers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let start_slot = state.get(Register::Rdx) as u32;
        let num_buffers = state.get(Register::R8) as usize;
        let buffers_ptr = state.get(Register::R9);
        let stack = state.get(Register::Rsp);
        let strides_ptr = memory.read_u64(stack + 0x20)?;
        let offsets_ptr = memory.read_u64(stack + 0x28)?;
        if start_slot != 0
            || (num_buffers != 0 && (buffers_ptr == 0 || strides_ptr == 0 || offsets_ptr == 0))
        {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut buffers = Vec::new();
        if num_buffers != 0 {
            let objects = read_guest_pointer_array(memory, buffers_ptr, num_buffers)?;
            for index in 0..num_buffers as u64 {
                read_guest_u32(memory, strides_ptr + index * 4)?;
                read_guest_u32(memory, offsets_ptr + index * 4)?;
            }
            if !objects.iter().all(|object| *object == 0) {
                buffers.reserve(objects.len());
                // Resolve device object for validation
                let device_object =
                    if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                        deferred.device_object
                    } else {
                        let context = self.d3d11_context(context_object)?;
                        context.device_object
                    };
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let buffer = self.d3d11_buffer(object)?;
                    if buffer.device_object != device_object {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    buffers.push(buffer.resource_id);
                }
            }
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .ia_set_vertex_buffers(buffers.clone())?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .ia_set_vertex_buffers(buffers.clone());
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetVertexBuffers",
            BTreeMap::from([("count".to_string(), json!(buffers.len()))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_ia_set_index_buffer(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let buffer_object = state.get(Register::Rdx);
        let format = state.get(Register::R8) as u32;
        let offset = state.get(Register::R9) as u32;
        if buffer_object == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.ia_clear_index_buffer()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .ia_clear_index_buffer();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::IASetIndexBuffer",
                BTreeMap::new(),
                json!(0),
            );
            return Ok(());
        }
        if format != 42 && format != 57 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let buffer = self.d3d11_buffer(buffer_object)?;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if buffer.device_object != deferred.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            deferred
                .deferred_context
                .ia_set_index_buffer(buffer.resource_id)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            if buffer.device_object != context.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            self.d3d11_device_mut(context.device_object)?
                .device
                .ia_set_index_buffer(buffer.resource_id);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetIndexBuffer",
            BTreeMap::from([
                ("format".to_string(), json!(format)),
                ("offset".to_string(), json!(offset)),
            ]),
            json!(buffer_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_ia_set_primitive_topology(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let topology = state.get(Register::Rdx) as u32;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .ia_set_primitive_topology(topology)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .ia_set_primitive_topology(topology);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetPrimitiveTopology",
            BTreeMap::from([("topology".to_string(), json!(topology))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_om_set_render_targets(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let count = state.get(Register::Rdx) as usize;
        let render_targets_ptr = state.get(Register::R8);
        let depth_view_object = state.get(Register::R9);
        if count != 0 && render_targets_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        // Resolve device object for validation
        let device_object = if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred.device_object
        } else {
            let context = self.d3d11_context(context_object)?;
            context.device_object
        };
        let mut render_targets = Vec::new();
        if count != 0 {
            let objects = read_guest_pointer_array(memory, render_targets_ptr, count)?;
            if !objects.iter().all(|object| *object == 0) {
                render_targets.reserve(objects.len());
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let view = self.d3d11_view(object)?;
                    if view.device_object != device_object || view.kind != ViewKind::Rtv {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    render_targets.push(view.view_id);
                }
            }
        }
        let depth_target = if depth_view_object == 0 {
            None
        } else {
            let view = self.d3d11_view(depth_view_object)?;
            if view.device_object != device_object || view.kind != ViewKind::Dsv {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            Some(view.view_id)
        };
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .om_set_render_targets(render_targets.clone(), depth_target)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .om_set_render_targets(render_targets.clone(), depth_target);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::OMSetRenderTargets",
            BTreeMap::from([
                ("count".to_string(), json!(render_targets.len())),
                ("depth_bound".to_string(), json!(depth_target.is_some())),
            ]),
            json!(depth_view_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_om_set_blend_state(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let blend_state_object = state.get(Register::Rdx);
        if blend_state_object == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.om_clear_blend_state()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .om_clear_blend_state();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::OMSetBlendState",
                BTreeMap::new(),
                json!(0),
            );
            return Ok(());
        }
        let blend_state = self.d3d11_blend_state(blend_state_object)?;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if blend_state.device_object != deferred.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            deferred
                .deferred_context
                .om_set_blend_state(blend_state.state_id)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            if blend_state.device_object != context.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            self.d3d11_device_mut(context.device_object)?
                .device
                .om_set_blend_state(blend_state.state_id);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::OMSetBlendState",
            BTreeMap::new(),
            json!(blend_state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_om_set_depth_stencil_state(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let depth_stencil_state_object = state.get(Register::Rdx);
        let stencil_ref = state.get(Register::R8) as u32;
        if depth_stencil_state_object == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.om_clear_depth_stencil_state()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .om_clear_depth_stencil_state();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::OMSetDepthStencilState",
                BTreeMap::from([("stencil_ref".to_string(), json!(stencil_ref))]),
                json!(0),
            );
            return Ok(());
        }
        let depth_stencil_state = self.d3d11_depth_stencil_state(depth_stencil_state_object)?;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if depth_stencil_state.device_object != deferred.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            deferred
                .deferred_context
                .om_set_depth_stencil_state(depth_stencil_state.state_id)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            if depth_stencil_state.device_object != context.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            self.d3d11_device_mut(context.device_object)?
                .device
                .om_set_depth_stencil_state(depth_stencil_state.state_id);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::OMSetDepthStencilState",
            BTreeMap::from([("stencil_ref".to_string(), json!(stencil_ref))]),
            json!(depth_stencil_state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_rs_set_state(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let rasterizer_state_object = state.get(Register::Rdx);
        if rasterizer_state_object == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.rs_clear_state()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .rs_clear_state();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::RSSetState",
                BTreeMap::new(),
                json!(0),
            );
            return Ok(());
        }
        let rasterizer_state = self.d3d11_rasterizer_state(rasterizer_state_object)?;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if rasterizer_state.device_object != deferred.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            deferred
                .deferred_context
                .rs_set_state(rasterizer_state.state_id)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            if rasterizer_state.device_object != context.device_object {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            self.d3d11_device_mut(context.device_object)?
                .device
                .rs_set_state(rasterizer_state.state_id);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::RSSetState",
            BTreeMap::new(),
            json!(rasterizer_state_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_rs_set_viewports(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let count = state.get(Register::Rdx) as usize;
        let viewports_ptr = state.get(Register::R8);
        if count == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.rs_clear_viewports()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .rs_clear_viewports();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::RSSetViewports",
                BTreeMap::new(),
                json!(0),
            );
            return Ok(());
        }
        if count != 1 || viewports_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let viewport = match read_d3d11_viewport(memory, viewports_ptr) {
            Ok(viewport) => viewport,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .rs_set_viewports(viewport.clone())?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .rs_set_viewports(viewport.clone());
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::RSSetViewports",
            BTreeMap::from([
                ("width".to_string(), json!(viewport.width)),
                ("height".to_string(), json!(viewport.height)),
            ]),
            json!(count),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_rs_set_scissor_rects(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let count = state.get(Register::Rdx) as usize;
        let rects_ptr = state.get(Register::R8);
        if count == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                deferred.deferred_context.rs_clear_scissor_rects()?;
            } else {
                let context = self.d3d11_context(context_object)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .rs_clear_scissor_rects();
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::RSSetScissorRects",
                BTreeMap::new(),
                json!(0),
            );
            return Ok(());
        }
        if count != 1 || rects_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let rect = match read_d3d11_scissor_rect(memory, rects_ptr) {
            Ok(rect) => rect,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .rs_set_scissor_rects(rect.clone())?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .rs_set_scissor_rects(rect.clone());
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::RSSetScissorRects",
            BTreeMap::from([
                ("left".to_string(), json!(rect.left)),
                ("top".to_string(), json!(rect.top)),
                ("right".to_string(), json!(rect.right)),
                ("bottom".to_string(), json!(rect.bottom)),
            ]),
            json!(count),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_draw(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let vertex_count = state.get(Register::Rdx) as u32;
        let start_vertex_location = state.get(Register::R8) as u32;
        if start_vertex_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred.deferred_context.draw(vertex_count)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .draw(vertex_count);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::Draw",
            BTreeMap::from([("vertices".to_string(), json!(vertex_count))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_draw_instanced(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let vertex_count_per_instance = state.get(Register::Rdx) as u32;
        let instance_count = state.get(Register::R8) as u32;
        let start_vertex_location = state.get(Register::R9) as u32;
        let start_instance_location = read_guest_u32(memory, state.get(Register::Rsp) + 0x20)?;
        if start_vertex_location != 0 || start_instance_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .draw_instanced(vertex_count_per_instance, instance_count)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .draw_instanced(vertex_count_per_instance, instance_count);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::DrawInstanced",
            BTreeMap::from([
                (
                    "vertices_per_instance".to_string(),
                    json!(vertex_count_per_instance),
                ),
                ("instances".to_string(), json!(instance_count)),
            ]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_draw_indexed(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let index_count = state.get(Register::Rdx) as u32;
        let start_index_location = state.get(Register::R8) as u32;
        let base_vertex_location = state.get(Register::R9) as i32;
        if start_index_location != 0 || base_vertex_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred.deferred_context.draw_indexed(index_count)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .draw_indexed(index_count);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::DrawIndexed",
            BTreeMap::from([("indices".to_string(), json!(index_count))]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_draw_indexed_instanced(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let index_count_per_instance = state.get(Register::Rdx) as u32;
        let instance_count = state.get(Register::R8) as u32;
        let start_index_location = state.get(Register::R9) as u32;
        let stack = state.get(Register::Rsp);
        let base_vertex_location = read_guest_u32(memory, stack + 0x20)? as i32;
        let start_instance_location = read_guest_u32(memory, stack + 0x28)?;
        if start_index_location != 0 || base_vertex_location != 0 || start_instance_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            deferred
                .deferred_context
                .draw_indexed_instanced(index_count_per_instance, instance_count)?;
        } else {
            let context = self.d3d11_context(context_object)?;
            self.d3d11_device_mut(context.device_object)?
                .device
                .draw_indexed_instanced(index_count_per_instance, instance_count);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::DrawIndexedInstanced",
            BTreeMap::from([
                (
                    "indices_per_instance".to_string(),
                    json!(index_count_per_instance),
                ),
                ("instances".to_string(), json!(instance_count)),
            ]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_resolve_subresource(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        // ID3D11DeviceContext::ResolveSubresource calling convention (x64):
        //   RCX = this (context object)
        //   RDX = pDstResource
        //   R8  = DstSubresource
        //   R9  = pSrcResource
        //   [RSP+0x20] = SrcSubresource
        //   [RSP+0x28] = Format (DXGI_FORMAT)
        let context_object = state.get(Register::Rcx);
        let dst_texture = self.d3d11_texture(state.get(Register::Rdx))?;
        let dst_subresource = state.get(Register::R8) as u32;
        let src_texture = self.d3d11_texture(state.get(Register::R9))?;
        let stack = state.get(Register::Rsp);
        let src_subresource = memory.read_u64(stack + 0x20)? as u32;
        let format = memory.read_u64(stack + 0x28)? as u32;

        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if dst_texture.device_object != deferred.device_object
                || src_texture.device_object != deferred.device_object
            {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "ResolveSubresource requires resources owned by the same device",
                ));
            }
            deferred.deferred_context.resolve_subresource(
                dst_texture.resource_id,
                dst_subresource,
                src_texture.resource_id,
                src_subresource,
                format,
            )?;
        } else {
            let context = self.d3d11_context(context_object)?;
            if dst_texture.device_object != context.device_object
                || src_texture.device_object != context.device_object
            {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "ResolveSubresource requires resources owned by the same device",
                ));
            }
            self.d3d11_device_mut(context.device_object)?
                .device
                .resolve_subresource(
                    dst_texture.resource_id,
                    dst_subresource,
                    src_texture.resource_id,
                    src_subresource,
                    format,
                )?;
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::ResolveSubresource",
            BTreeMap::from([
                ("dst_subresource".to_string(), json!(dst_subresource)),
                ("src_subresource".to_string(), json!(src_subresource)),
                ("format".to_string(), json!(format)),
            ]),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_create_shader(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        stage: D3d11ShaderStage,
        trace_name: &str,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("{trace_name} on non-device object {device_object:#x}"),
            ));
        }
        let stack = state.get(Register::Rsp);
        let bytecode_ptr = state.get(Register::Rdx);
        let bytecode_len = state.get(Register::R8) as usize;
        let class_linkage = state.get(Register::R9);
        let out_ptr = memory.read_u64(stack + 0x20)?;
        if bytecode_ptr == 0 || bytecode_len == 0 || out_ptr == 0 || class_linkage != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let bytecode = read_guest_bytes(memory, bytecode_ptr, bytecode_len)?;
        let parsed = match parse_dxil_container(&bytecode) {
            Ok(parsed) => parsed,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let Some(root_signature) = parsed.root_signature_part.clone() else {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        };
        let entry_name = parsed.entry_name.clone();
        let shader_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_shader_from_dxil(
                crate::d3d11::ShaderModuleDesc {
                    stage,
                    entry: entry_name.clone(),
                },
                bytecode,
                root_signature,
            ) {
            Ok(shader_id) => shader_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let shader_object =
            self.alloc_d3d11_shader_object(memory, device_object, shader_id, stage)?;
        write_u64(memory, out_ptr, shader_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        let cache_key = self
            .d3d11_device(device_object)?
            .device
            .shader_translation_cache_key(shader_id)?
            .unwrap_or_default();
        self.push_trace(
            "d3d12",
            trace_name,
            BTreeMap::from([
                ("bytes".to_string(), json!(bytecode_len)),
                ("entry".to_string(), json!(entry_name)),
                ("cache_key".to_string(), json!(cache_key)),
            ]),
            json!(shader_object),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_set_shader(
        &mut self,
        state: &mut CpuState,
        stage: D3d11ShaderStage,
        trace_name: &str,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let shader_object = state.get(Register::Rdx);
        let class_instances = state.get(Register::R8);
        let class_instance_count = state.get(Register::R9);
        if class_instances != 0 || class_instance_count != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if shader_object == 0 {
            if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
                match stage {
                    D3d11ShaderStage::Vs => deferred.deferred_context.vs_clear_shader()?,
                    D3d11ShaderStage::Ps => deferred.deferred_context.ps_clear_shader()?,
                    D3d11ShaderStage::Cs => deferred.deferred_context.cs_clear_shader()?,
                    D3d11ShaderStage::Gs => deferred.deferred_context.gs_clear_shader()?,
                    D3d11ShaderStage::Hs => deferred.deferred_context.hs_clear_shader()?,
                    D3d11ShaderStage::Ds => deferred.deferred_context.ds_clear_shader()?,
                }
            } else {
                let context = self.d3d11_context(context_object)?;
                let device = &mut self.d3d11_device_mut(context.device_object)?.device;
                match stage {
                    D3d11ShaderStage::Vs => device.vs_clear_shader(),
                    D3d11ShaderStage::Ps => device.ps_clear_shader(),
                    D3d11ShaderStage::Cs => device.cs_clear_shader(),
                    D3d11ShaderStage::Gs => device.gs_clear_shader(),
                    D3d11ShaderStage::Hs => device.hs_clear_shader(),
                    D3d11ShaderStage::Ds => device.ds_clear_shader(),
                }
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", trace_name, BTreeMap::new(), json!(0));
            return Ok(());
        }
        let shader = self.d3d11_shader(shader_object)?;
        if let Ok(deferred) = self.d3d11_deferred_context(context_object) {
            if shader.device_object != deferred.device_object || shader.stage != stage {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            match stage {
                D3d11ShaderStage::Vs => {
                    deferred.deferred_context.vs_set_shader(shader.shader_id)?
                }
                D3d11ShaderStage::Ps => {
                    deferred.deferred_context.ps_set_shader(shader.shader_id)?
                }
                D3d11ShaderStage::Cs => {
                    deferred.deferred_context.cs_set_shader(shader.shader_id)?
                }
                D3d11ShaderStage::Gs => {
                    deferred.deferred_context.gs_set_shader(shader.shader_id)?
                }
                D3d11ShaderStage::Hs => {
                    deferred.deferred_context.hs_set_shader(shader.shader_id)?
                }
                D3d11ShaderStage::Ds => {
                    deferred.deferred_context.ds_set_shader(shader.shader_id)?
                }
            }
            let cache_key = String::new();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                trace_name,
                BTreeMap::from([("cache_key".to_string(), json!(cache_key))]),
                json!(shader_object),
            );
            Ok(())
        } else {
            let context = self.d3d11_context(context_object)?;
            if shader.device_object != context.device_object || shader.stage != stage {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            let cache_key = {
                let device = &mut self.d3d11_device_mut(context.device_object)?.device;
                match stage {
                    D3d11ShaderStage::Vs => device.vs_set_shader(shader.shader_id),
                    D3d11ShaderStage::Ps => device.ps_set_shader(shader.shader_id),
                    D3d11ShaderStage::Cs => device.cs_set_shader(shader.shader_id),
                    D3d11ShaderStage::Gs => device.gs_set_shader(shader.shader_id),
                    D3d11ShaderStage::Hs => device.hs_set_shader(shader.shader_id),
                    D3d11ShaderStage::Ds => device.ds_set_shader(shader.shader_id),
                }
                device
                    .shader_translation_cache_key(shader.shader_id)?
                    .unwrap_or_default()
            };
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                trace_name,
                BTreeMap::from([("cache_key".to_string(), json!(cache_key))]),
                json!(shader_object),
            );
            Ok(())
        }
    }

    pub(crate) fn ensure_d3d11_backbuffer_object(
        &mut self,
        memory: &mut MemoryImage,
        swapchain_object: u64,
        index: u32,
    ) -> AppResult<u64> {
        let device_object = self.d3d11_swapchain(swapchain_object)?.device_object;
        if let Some(existing) = self
            .d3d11_device(device_object)?
            .backbuffer_objects
            .get(&index)
            .copied()
        {
            return Ok(existing);
        }
        let resource_id = self
            .d3d11_device(device_object)?
            .device
            .swapchain_backbuffer(index)?;
        let texture_object = self.alloc_d3d11_texture_object(memory, device_object, resource_id)?;
        self.d3d11_device_mut(device_object)?
            .backbuffer_objects
            .insert(index, texture_object);
        Ok(texture_object)
    }
    // ── D3D11 Query dispatch handlers (Phase 3.5) ─────────────────────

    pub(crate) fn dispatch_d3d11_asynchronous_get_data(
        &mut self,
        _memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _query_object = state.get(Register::Rcx);
        let _data_ptr = state.get(Register::Rdx);
        let _data_size = state.get(Register::R8) as u32;
        let _flags = state.get(Register::R9) as u32;
        // Return S_OK with no data — signals that the query data is not available yet
        state.set(Register::Rax, 1); // S_FALSE = data not ready
        self.last_error = 0;
        self.push_trace(
            "d3d11",
            "ID3D11Asynchronous::GetData",
            BTreeMap::new(),
            json!(1),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_asynchronous_get_data_size(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _query_object = state.get(Register::Rcx);
        // Return 0 as the data size (no data available)
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d11",
            "ID3D11Asynchronous::GetDataSize",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_query_get_desc(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _query_object = state.get(Register::Rcx);
        let desc_ptr = state.get(Register::Rdx);
        if desc_ptr != 0 {
            // Write a default D3D11_QUERY_DESC { Query = 0 (D3D11_QUERY_EVENT), MiscFlags = 0 }
            memory.write_u32(desc_ptr, 0);
            memory.write_u32(desc_ptr + 4, 0);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace("d3d11", "ID3D11Query::GetDesc", BTreeMap::new(), json!(0));
        Ok(())
    }

    pub(crate) fn dispatch_d3d11_predicate_get_desc(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _predicate_object = state.get(Register::Rcx);
        let desc_ptr = state.get(Register::Rdx);
        if desc_ptr != 0 {
            // Write a default D3D11_QUERY_DESC { Query = 0 (D3D11_QUERY_EVENT), MiscFlags = 0 }
            memory.write_u32(desc_ptr, 0);
            memory.write_u32(desc_ptr + 4, 0);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d11",
            "ID3D11Predicate::GetDesc",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }
}
