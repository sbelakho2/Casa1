//! Guest object, TLS, and thunk-address helpers (runtime methods).

use super::*;

impl PeHostRuntime {
    pub(crate) fn alloc_host_thunk(&mut self, thunk: HostThunk) -> u64 {
        let address = self.next_thunk_address;
        self.next_thunk_address += 0x10;
        if let Some(api) = crate::jit::InlineApi::from_thunk(&thunk) {
            crate::jit::register_inline_api_target(address, api);
        }
        self.host_thunks.insert(address, thunk);
        // Register a fast-thunk ARM64 trampoline so JIT-compiled code and
        // the dispatch hot path can call the host function directly without
        // the overhead of the full dispatch_import match statement.
        self.register_fast_thunk(address);
        address
    }

    pub(crate) fn alloc_guest_vtable(
        &mut self,
        memory: &mut MemoryImage,
        methods: Vec<HostThunk>,
    ) -> AppResult<u64> {
        let entries = methods
            .into_iter()
            .map(|method| self.alloc_host_thunk(method))
            .collect::<Vec<_>>();
        self.alloc_pointer_array(memory, &entries)
    }

    pub(crate) fn sync_guest_tls_slot(
        &self,
        memory: &mut MemoryImage,
        slot: u32,
        value: u64,
    ) -> AppResult<()> {
        if self.tls_vector_ptr != 0 {
            let slot_address = self
                .tls_vector_ptr
                .wrapping_add(slot as u64 * self.guest_arch.pointer_bytes() as u64);
            write_guest_pointer(memory, slot_address, value, self.guest_arch)?;
        }
        Ok(())
    }

    /// Read a TLS slot value from the guest-visible TLS array.
    ///
    /// The array is the truth for in-range indices: freed and never-allocated
    /// slots read as zero (the array is zeroed at allocation and on TlsFree).
    /// x86 guests carry the array at `tls_vector_ptr`; x64 guests have no
    /// modelled array, so the host map (values of allocated slots) is used.
    pub(crate) fn read_guest_tls_value(&self, memory: &MemoryImage, slot: u32) -> AppResult<u64> {
        if self.tls_vector_ptr != 0 {
            let slot_address = self
                .tls_vector_ptr
                .wrapping_add(slot as u64 * self.guest_arch.pointer_bytes() as u64);
            read_guest_pointer(memory, slot_address, self.guest_arch)
        } else {
            Ok(self.tls_slots.get(&slot).copied().unwrap_or(0))
        }
    }

    /// Write a TLS slot value into the guest-visible TLS array.
    ///
    /// Any in-range index is writable. For x86 the guest array is written
    /// directly; the map mirror of *allocated* slots is kept in sync so the
    /// thread-switch machinery round-trips values. x64 guests have no array,
    /// so the map itself is the store (a never-allocated in-range slot is
    /// recorded there; the slot remains allocatable on x86 where TlsAlloc
    /// bookkeeping is independent of stored values).
    pub(crate) fn write_guest_tls_value(
        &mut self,
        memory: &mut MemoryImage,
        slot: u32,
        value: u64,
    ) -> AppResult<()> {
        if self.tls_vector_ptr != 0 {
            let slot_address = self
                .tls_vector_ptr
                .wrapping_add(slot as u64 * self.guest_arch.pointer_bytes() as u64);
            write_guest_pointer(memory, slot_address, value, self.guest_arch)?;
            if let Some(entry) = self.tls_slots.get_mut(&slot) {
                *entry = value;
            }
        } else {
            self.tls_slots.insert(slot, value);
        }
        Ok(())
    }

    pub(crate) fn sync_guest_critical_section(
        &self,
        memory: &mut MemoryImage,
        address: u64,
        depth: usize,
        owner_thread_id: u32,
        spin_count: Option<u32>,
    ) {
        if self.guest_arch != GuestArch::X86 || address == 0 {
            return;
        }
        let spin_count = spin_count
            .or_else(|| read_u32(memory, address + 20).ok())
            .unwrap_or(0);
        write_u32(memory, address, 0);
        write_u32(
            memory,
            address + 4,
            if depth == 0 {
                u32::MAX
            } else {
                depth.saturating_sub(1) as u32
            },
        );
        write_u32(memory, address + 8, depth as u32);
        write_u32(
            memory,
            address + 12,
            if depth == 0 { 0 } else { owner_thread_id },
        );
        write_u32(memory, address + 16, 0);
        write_u32(memory, address + 20, spin_count);
    }

    pub(crate) fn alloc_guest_object(
        &mut self,
        memory: &mut MemoryImage,
        kind: GuestObjectKind,
        vtable: u64,
    ) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, address, vtable);
        self.guest_objects
            .insert(address, GuestObjectMeta { kind, refcount: 1 });
        Ok(address)
    }

    pub(crate) fn guest_object_kind(&self, address: u64) -> AppResult<GuestObjectKind> {
        self.guest_objects
            .get(&address)
            .map(|object| object.kind)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown guest object {address:#x}"),
                )
            })
    }

    pub(crate) fn add_ref_guest_object(&mut self, address: u64) -> AppResult<u32> {
        let object = self.guest_objects.get_mut(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown guest object {address:#x}"),
            )
        })?;
        object.refcount = object.refcount.saturating_add(1);
        Ok(object.refcount)
    }

    pub(crate) fn release_guest_object(&mut self, address: u64) -> AppResult<u32> {
        let refcount = {
            let object = self.guest_objects.get_mut(&address).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown guest object {address:#x}"),
                )
            })?;
            object.refcount = object.refcount.saturating_sub(1);
            object.refcount
        };
        if refcount != 0 {
            return Ok(refcount);
        }
        match self.guest_object_kind(address)? {
            GuestObjectKind::XAudio2Engine => self.destroy_xaudio2_engine_object(address)?,
            GuestObjectKind::XAudio2MasteringVoice | GuestObjectKind::XAudio2SourceVoice => {
                self.destroy_xaudio2_voice_object(address)?
            }
            kind @ (GuestObjectKind::ComStream
            | GuestObjectKind::ComStorage
            | GuestObjectKind::ComStorageObject
            | GuestObjectKind::ComDataObject
            | GuestObjectKind::ComOleObject
            | GuestObjectKind::ComOleInPlaceObject
            | GuestObjectKind::ComObjectWithSite
            | GuestObjectKind::ComServiceProvider
            | GuestObjectKind::ComBindCtx
            | GuestObjectKind::ComFileMoniker
            | GuestObjectKind::ComEnumVariant
            | GuestObjectKind::ComConnectionPoint
            | GuestObjectKind::ComStdDispatch
            | GuestObjectKind::ComTypeInfo
            | GuestObjectKind::ComPropertyBag) => {
                // COM object teardown: the per-object state maps are keyed by
                // the guest pointer, so dropping the last reference forgets
                // the state alongside the object.
                self.com_streams.remove(&address);
                self.com_storages.remove(&address);
                self.com_data_objects.remove(&address);
                self.com_ole_sites.remove(&address);
                self.com_object_sites.remove(&address);
                self.com_connection_points.remove(&address);
                self.com_enum_variants.remove(&address);
                self.com_bind_ctx_params.remove(&address);
                self.com_moniker_names.remove(&address);
                self.com_monikers.remove(&address);
                self.com_type_infos.remove(&address);
                self.guest_objects.remove(&address);
                let _ = kind;
            }
            GuestObjectKind::ImfByteStream
            | GuestObjectKind::ImfPresentationDescriptor
            | GuestObjectKind::ImfStreamDescriptor
            | GuestObjectKind::ImfMediaTypeHandler
            | GuestObjectKind::ImfMetadata
            | GuestObjectKind::ImfMediaSource
            | GuestObjectKind::ImfSourceReader
            | GuestObjectKind::ImfMediaEvent => self.destroy_mf_object_state(address)?,
            kind @ (GuestObjectKind::ImfAttributes
            | GuestObjectKind::ImfMediaType
            | GuestObjectKind::ImfMediaBuffer
            | GuestObjectKind::ImfSample
            | GuestObjectKind::ImfMediaEventQueue
            | GuestObjectKind::ImfMediaSession
            | GuestObjectKind::ImfPresentationClock
            | GuestObjectKind::ImfSinkWriter
            | GuestObjectKind::ImfSourceResolver
            | GuestObjectKind::ImfTopology
            | GuestObjectKind::ImfMediaSink
            | GuestObjectKind::ImfAsyncResult
            | GuestObjectKind::ImfTopologyNode
            | GuestObjectKind::ImfDxgiDeviceManager
            | GuestObjectKind::DshowClassFactory
            | GuestObjectKind::DshowFilterGraph
            | GuestObjectKind::WicFactory
            | GuestObjectKind::WicBitmap
            | GuestObjectKind::WicPalette
            | GuestObjectKind::WicScaler
            | GuestObjectKind::WicClipper
            | GuestObjectKind::WicFlipRotator
            | GuestObjectKind::WicFormatConverter
            | GuestObjectKind::WicStream
            | GuestObjectKind::WicColorContext
            | GuestObjectKind::WicComponentInfo
            | GuestObjectKind::DirectDraw7
            | GuestObjectKind::DirectDrawSurface
            | GuestObjectKind::D3dBlob
            | GuestObjectKind::Theme
            | GuestObjectKind::MsiDatabase
            | GuestObjectKind::MsiView
            | GuestObjectKind::MsiRecord) => {
                self.guest_objects.remove(&address);
                let _ = kind;
            }
            GuestObjectKind::ImfRateControlService => {
                // The rate-control service objects are per-session service
                // objects: dropping the last guest reference forgets the
                // owner-session registration alongside the object.
                self.mf_rate_services.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::DxgiFactory => self.destroy_dxgi_factory_object(address)?,
            GuestObjectKind::DxgiAdapter => self.destroy_dxgi_adapter_object(address)?,
            GuestObjectKind::D3d11Device => self.destroy_d3d11_device_object(address)?,
            GuestObjectKind::D3d11DeviceContext => {
                if let Some(context) = self.d3d11_contexts.remove(&address) {
                    self.release_guest_object(context.device_object)?;
                }
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d11DeferredContext => {
                if let Some(deferred) = self.d3d11_deferred_contexts.remove(&address) {
                    self.release_guest_object(deferred.device_object)?;
                }
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::DxgiSwapChain => self.destroy_dxgi_swapchain_object(address)?,
            GuestObjectKind::D3d12Device => self.destroy_d3d12_device_object(address)?,
            GuestObjectKind::D3d12CommandQueue => {
                self.destroy_d3d12_command_queue_object(address)?
            }
            GuestObjectKind::D3d12CommandAllocator => {
                self.destroy_d3d12_command_allocator_object(address)?
            }
            GuestObjectKind::D3d12DescriptorHeap => {
                self.destroy_d3d12_descriptor_heap_object(address)?
            }
            GuestObjectKind::D3d12GraphicsCommandList | GuestObjectKind::D3d12CommandList => {
                self.destroy_d3d12_command_list_object(address)?
            }
            GuestObjectKind::D3d12Fence => self.destroy_d3d12_fence_object(address)?,
            GuestObjectKind::D3d12Resource => self.destroy_d3d12_resource_object(address)?,
            GuestObjectKind::D3d12StateObject => {
                self.guest_objects.remove(&address);
                self.d3d12_object_names.remove(&address);
                self.d3d12_private_data.remove(&address);
                if let Some(handle) = self.d3d12_state_object_handles.remove(&address) {
                    self.d3d12_runtime.release_state_object(handle)?;
                }
                if let Some(device) = self.d3d12_child_object_devices.remove(&address) {
                    self.release_guest_object(device)?;
                }
            }
            GuestObjectKind::D3d12CommandSignature => {
                self.guest_objects.remove(&address);
                self.d3d12_object_names.remove(&address);
                self.d3d12_private_data.remove(&address);
                if let Some(handle) = self.d3d12_command_signature_handles.remove(&address) {
                    self.d3d12_runtime.destroy_command_signature(handle)?;
                }
                if let Some(device) = self.d3d12_child_object_devices.remove(&address) {
                    self.release_guest_object(device)?;
                }
            }
            GuestObjectKind::DmlDevice => {
                self.guest_objects.remove(&address);
                self.dml_private_data.remove(&address);
                self.dml_object_names.remove(&address);
                let private_interfaces = self.dml_private_interfaces.remove(&address);
                if let Some(handle) = self.dml_object_handles.remove(&address) {
                    self.dml_device_objects.remove(&handle);
                    let parent_device = self
                        .d3d12_runtime
                        .directml()
                        .devices()
                        .get(&handle)
                        .map(|record| record.parent_device);
                    self.d3d12_runtime
                        .directml_mut()
                        .destroy_device(handle)
                        .map_err(|error| error.to_app_error())?;
                    if let Some(parent_device) = parent_device {
                        self.release_guest_object(parent_device)?;
                    }
                }
                if let Some(private_interfaces) = private_interfaces {
                    for interface in private_interfaces.into_values() {
                        self.release_guest_object(interface)?;
                    }
                }
            }
            kind @ (GuestObjectKind::DmlOperator
            | GuestObjectKind::DmlCompiledOperator
            | GuestObjectKind::DmlOperatorInitializer
            | GuestObjectKind::DmlCommandRecorder
            | GuestObjectKind::DmlBindingTable) => {
                self.guest_objects.remove(&address);
                self.dml_private_data.remove(&address);
                self.dml_object_names.remove(&address);
                let private_interfaces = self.dml_private_interfaces.remove(&address);
                let handle = self.dml_object_handles.remove(&address);
                let device_object = self.dml_object_devices.remove(&address);
                if let Some(handle) = handle {
                    let directml = self.d3d12_runtime.directml_mut();
                    match kind {
                        GuestObjectKind::DmlOperator => directml
                            .destroy_operator(handle)
                            .map_err(|e| e.to_app_error())?,
                        GuestObjectKind::DmlCompiledOperator => directml
                            .destroy_compiled(handle)
                            .map_err(|e| e.to_app_error())?,
                        GuestObjectKind::DmlOperatorInitializer => directml
                            .destroy_operator_initializer(handle)
                            .map_err(|e| e.to_app_error())?,
                        GuestObjectKind::DmlCommandRecorder => directml
                            .destroy_command_recorder(handle)
                            .map_err(|e| e.to_app_error())?,
                        GuestObjectKind::DmlBindingTable => directml
                            .destroy_binding_table(handle)
                            .map_err(|e| e.to_app_error())?,
                        _ => unreachable!("DML child kind arm"),
                    }
                }
                if let Some(device_object) = device_object {
                    self.release_guest_object(device_object)?;
                }
                if let Some(private_interfaces) = private_interfaces {
                    for interface in private_interfaces.into_values() {
                        self.release_guest_object(interface)?;
                    }
                }
            }
            GuestObjectKind::D3d11Buffer => self.destroy_d3d11_buffer_object(address)?,
            GuestObjectKind::D3d11Texture2D => self.destroy_d3d11_texture_object(address)?,
            GuestObjectKind::D3d11View => self.destroy_d3d11_view_object(address)?,
            GuestObjectKind::D3d11InputLayout => self.destroy_d3d11_input_layout_object(address)?,
            GuestObjectKind::D3d11Shader => self.destroy_d3d11_shader_object(address)?,
            GuestObjectKind::D3d11BlendState => self.destroy_d3d11_blend_state_object(address)?,
            GuestObjectKind::D3d11RasterizerState => {
                self.destroy_d3d11_rasterizer_state_object(address)?
            }
            GuestObjectKind::D3d11DepthStencilState => {
                self.destroy_d3d11_depth_stencil_state_object(address)?
            }
            GuestObjectKind::D3d11SamplerState => {
                self.destroy_d3d11_sampler_state_object(address)?
            }
            GuestObjectKind::D3d11Query => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::DirectInput8 => self.destroy_directinput8_object(address)?,
            GuestObjectKind::DirectInput8Device => {
                self.destroy_directinput8_device_object(address)?
            }
            GuestObjectKind::ShellLinkInterface => {
                self.destroy_shell_link_interface_object(address)?
            }
            GuestObjectKind::DirectSound8 => {
                // Stateless for DirectSound objects — but an activated audio
                // endpoint (or its IAudioRenderClient service object) owns
                // real per-endpoint client state that drops with its last
                // guest reference.
                crate::audio_activation::release_audio_object(self.guest_pid, address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::FileDialog => {
                // Stateless COM wrapper — no associated state to tear down.
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::SteamVRHmd
            | GuestObjectKind::SteamVRCompositor
            | GuestObjectKind::SteamVRChaperone
            | GuestObjectKind::SteamVRController
            | GuestObjectKind::SteamVRInput
            | GuestObjectKind::SteamVRRenderModels => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::ComClassFactory => {
                self.com_factory_clsids.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::ComDispatch => {
                self.com_servers.remove(&address);
                self.com_type_infos.remove(&address);
                self.com_connection_points.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::XapoEffect => {
                self.destroy_xapo_effect_object(address)?;
            }
            // ── WMI (Windows Management Instrumentation) ──────────────────────────
            GuestObjectKind::WbemLocator => {
                self.wmi_services.remove(&address);
                self.wmi_class_objects.remove(&address);
                self.wmi_enums.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WbemServices => {
                self.wmi_services.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WbemClassObject => {
                self.wmi_class_objects.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::EnumWbemObjects => {
                self.wmi_enums.remove(&address);
                self.guest_objects.remove(&address);
            }
            // ── WebView2 ────────────────────────────────────────────────
            GuestObjectKind::WebView2Environment => {
                self.webview2_runtime.environments.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WebView2Controller => {
                self.webview2_runtime.controllers.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WebView2WebView => {
                self.webview2_runtime.webviews.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WebView2Settings => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WebView2WebResourceResponse => {
                // Stateless COM wrapper — no associated state to tear down.
                self.guest_objects.remove(&address);
            }
            // ── D3D9 Basic Rendering ──────────────────────────────────
            GuestObjectKind::D3d9Factory => {
                self.d3d9_factories.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9Device => {
                self.d3d9_devices.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9VertexBuffer => {
                self.d3d9_vertex_buffers.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9IndexBuffer => {
                self.d3d9_index_buffers.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9Texture => {
                self.d3d9_textures.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9Query => {
                self.d3d9_queries.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9SwapChain => {
                self.d3d9_swapchains.remove(&address);
                self.guest_objects.remove(&address);
            }
            // ── Phase L: COM objects ───────────────────────────────────────────
            GuestObjectKind::ShellFolder => {
                self.shell_folder_paths.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::ContextMenu => {
                self.context_menu_paths.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::WebBrowser => {
                self.web_browsers.remove(&address);
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::PropertyStore
            | GuestObjectKind::XmlDomDocument
            | GuestObjectKind::UrlMoniker => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::ShellItem => {
                self.shell_item_paths.remove(&address);
                self.guest_objects.remove(&address);
            }
            // ── IEnumIDList ──────────────────────────────────────────
            GuestObjectKind::EnumIdList => {
                // State tracking removed; individual PIDL strings are
                // allocated on the guest heap and freed by the guest.
                self.enum_id_lists.remove(&address);
                self.guest_objects.remove(&address);
            }
            // ── D3D9 Surface & Shader Objects ──────────────────────────
            GuestObjectKind::D3d9Surface => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9VertexDeclaration => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9VertexShader => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d9PixelShader => {
                self.guest_objects.remove(&address);
            }
            // ── D2D1 Objects ─────────────────────────────────────────
            GuestObjectKind::D2d1Brush => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D2d1StrokeStyle => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D2d1DrawingStateBlock => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D2d1Bitmap => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D2d1RenderTarget => {
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::ShMalloc => {
                // The standard allocator is stateless apart from the COM
                // refcount (tracked in guest_objects).
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::NcryptProvider
            | GuestObjectKind::NcryptKey
            | GuestObjectKind::RpcBinding
            | GuestObjectKind::TsfThreadManager
            | GuestObjectKind::TsfCategoryManager
            | GuestObjectKind::TsfDisplayAttributeManager
            | GuestObjectKind::LdapSession
            | GuestObjectKind::HttpRequestQueue
            | GuestObjectKind::PdhQuery
            | GuestObjectKind::EvtSession
            | GuestObjectKind::EvtLog
            | GuestObjectKind::EvtQuery
            | GuestObjectKind::EvtSubscription
            | GuestObjectKind::EvtBookmark
            | GuestObjectKind::WlanClient
            | GuestObjectKind::D3dkmtDevice
            | GuestObjectKind::D3dkmtContext
            | GuestObjectKind::D3dkmtSyncObject
            | GuestObjectKind::EsentDatabase
            | GuestObjectKind::WinInetRequest
            | GuestObjectKind::DirectInput
            | GuestObjectKind::WmCodec
            | GuestObjectKind::WmEditor
            | GuestObjectKind::WmIndexer
            | GuestObjectKind::WmProfileManager
            | GuestObjectKind::WmReader
            | GuestObjectKind::WmSyncReader
            | GuestObjectKind::WmWriter
            | GuestObjectKind::EvrVideoMediaType
            | GuestObjectKind::EvrVideoMixer
            | GuestObjectKind::EvrVideoPresenter
            | GuestObjectKind::EvrVideoRenderer
            | GuestObjectKind::EvrSampleAllocator
            | GuestObjectKind::ComErrorInfo
            | GuestObjectKind::Dxva2VideoService
            | GuestObjectKind::CspContext
            | GuestObjectKind::CspKey
            | GuestObjectKind::VssBackup
            | GuestObjectKind::GdiPlusGraphics
            | GuestObjectKind::MftActivate
            | GuestObjectKind::MftTransform => {
                self.guest_objects.remove(&address);
            }
        }
        Ok(0)
    }
}
