use crate::error::{AppError, AppResult};
use crate::gfx::{
    CommandAllocatorId, CommandQueueId, DescriptorHeapId, DescriptorHeapType, DxgiFormat,
    FilterMode, GraphicsBackend, PipelineStateDesc, RenderPassPlan, ResourceDesc,
    ResourceId as GfxResourceId, ResourceState,
    RootSignatureDesc, SwapchainDesc, SwapchainId, SwapchainState, ViewDescriptor,
};
use crate::reason::ReasonCode;
use crate::shader::{
    build_cache_entry, shader_cache_key, translate_shader, CompileFlags as ShaderCompileFlags,
    ShaderCache, ShaderStage as TranslationShaderStage, ShaderTranslationInput,
    ShaderTranslationOutput,
};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type D3d11ResourceId = u64;
pub type D3d11ViewId = u64;
pub type BlendStateId = u64;
pub type RasterizerStateId = u64;
pub type DepthStencilStateId = u64;
pub type SamplerStateId = u64;
pub type InputLayoutId = u64;
pub type ShaderId = u64;
pub type D3d9DeviceId = u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FeatureLevel {
    Level10_1,
    Level11_0,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureCaps {
    pub geometry_shader: bool,
    pub hull_shader: bool,
    pub domain_shader: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCreationRequest {
    pub requested_feature_levels: Vec<FeatureLevel>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDimension {
    Buffer,
    Texture1D,
    Texture2D,
    Texture3D,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d11ResourceDesc {
    pub label: String,
    pub dimension: ResourceDimension,
    pub format: DxgiFormat,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub byte_width: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Srv,
    Rtv,
    Dsv,
    Uav,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ViewInfo {
    pub resource: D3d11ResourceId,
    pub kind: ViewKind,
    pub format: DxgiFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlendStateDesc {
    pub blend_enable: bool,
    pub alpha_to_coverage: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RasterizerStateDesc {
    pub fill_mode: String,
    pub cull_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepthStencilStateDesc {
    pub depth_enable: bool,
    pub depth_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamplerStateDesc {
    pub filter: FilterMode,
    pub address_u: String,
    pub address_v: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputElementDesc {
    pub semantic: String,
    pub format: DxgiFormat,
    pub slot: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputLayoutDesc {
    pub elements: Vec<InputElementDesc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ShaderStage {
    Vs,
    Ps,
    Cs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShaderModuleDesc {
    pub stage: ShaderStage,
    pub entry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Viewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionResult {
    pub feature_level: FeatureLevel,
    pub draw_calls: u32,
    pub indexed_draw_calls: u32,
    pub dispatch_calls: u32,
    pub executed_command_lists: usize,
    pub resource_digests: BTreeMap<String, String>,
    pub signature: String,
    pub hash: String,
    pub backend_plan: crate::gfx::MetalCommandBufferPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d11CommandList {
    pub binding_signature: String,
    pub commands: Vec<RecordedCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixedFunctionScene {
    pub texture_factor: u32,
    pub diffuse_color: [u8; 4],
    pub fog_enable: bool,
    pub alpha_blend_enable: bool,
    pub primitive_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d9Frame {
    pub signature: String,
    pub hash: String,
}

#[derive(Debug, Clone)]
struct ResourceRecord {
    desc: D3d11ResourceDesc,
    backend_id: GfxResourceId,
    bytes: Vec<u8>,
    mapped: bool,
    include_in_digests: bool,
}

#[derive(Debug, Clone)]
struct ViewRecord {
    info: ViewInfo,
    heap: Option<DescriptorHeapId>,
}

#[derive(Debug, Clone)]
struct ShaderArtifact {
    cache_key: String,
    metal_entry: String,
    output: ShaderTranslationOutput,
}

#[derive(Debug, Clone)]
struct ShaderRecord {
    desc: ShaderModuleDesc,
    artifact: Option<ShaderArtifact>,
}

#[derive(Debug, Clone, Default)]
struct ContextBindings {
    render_targets: Vec<D3d11ViewId>,
    depth_target: Option<D3d11ViewId>,
    viewport: Option<Viewport>,
    vertex_buffers: Vec<D3d11ResourceId>,
    index_buffer: Option<D3d11ResourceId>,
    input_layout: Option<InputLayoutId>,
    blend_state: Option<BlendStateId>,
    rasterizer_state: Option<RasterizerStateId>,
    depth_stencil_state: Option<DepthStencilStateId>,
    shaders: BTreeMap<ShaderStage, ShaderId>,
    constant_buffers: BTreeMap<ShaderStage, Vec<D3d11ResourceId>>,
    shader_resources: BTreeMap<ShaderStage, Vec<D3d11ViewId>>,
    samplers: BTreeMap<ShaderStage, Vec<SamplerStateId>>,
}

#[derive(Debug, Clone, Default)]
struct ImmediateContext {
    bindings: ContextBindings,
    commands: Vec<RecordedCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordedCommand {
    UpdateSubresource {
        resource: D3d11ResourceId,
        bytes: Vec<u8>,
    },
    CopyResource {
        src: D3d11ResourceId,
        dst: D3d11ResourceId,
    },
    CopySubresourceRegion {
        src: D3d11ResourceId,
        dst: D3d11ResourceId,
        src_offset: usize,
        dst_offset: usize,
        size: usize,
    },
    ClearRenderTargetView {
        view: D3d11ViewId,
        color: [u8; 4],
    },
    ClearDepthStencilView {
        view: D3d11ViewId,
        depth: u32,
        stencil: u8,
    },
    Draw {
        vertices: u32,
    },
    DrawIndexed {
        indices: u32,
    },
    Dispatch {
        x: u32,
        y: u32,
        z: u32,
    },
}

#[derive(Debug, Clone, Default)]
struct DeferredRecording {
    bindings: ContextBindings,
    commands: Vec<RecordedCommand>,
}

#[derive(Debug, Clone, Default)]
pub struct DeferredContext {
    recording: Arc<Mutex<DeferredRecording>>,
}

#[derive(Debug, Clone)]
pub struct Direct3D9Shim {
    enabled: bool,
    next_id: D3d9DeviceId,
}

#[derive(Debug, Clone)]
pub struct Direct3D9Device {
    id: D3d9DeviceId,
}

#[derive(Debug, Clone)]
pub struct D3d11Device {
    next_id: u64,
    backend: GraphicsBackend,
    feature_level: FeatureLevel,
    caps: FeatureCaps,
    swapchain: Option<SwapchainId>,
    queue: CommandQueueId,
    graphics_allocator: CommandAllocatorId,
    graphics_pipeline: u64,
    fence: u64,
    next_fence_value: u64,
    resources: BTreeMap<D3d11ResourceId, ResourceRecord>,
    views: BTreeMap<D3d11ViewId, ViewRecord>,
    blend_states: BTreeMap<BlendStateId, BlendStateDesc>,
    rasterizer_states: BTreeMap<RasterizerStateId, RasterizerStateDesc>,
    depth_stencil_states: BTreeMap<DepthStencilStateId, DepthStencilStateDesc>,
    sampler_states: BTreeMap<SamplerStateId, SamplerStateDesc>,
    input_layouts: BTreeMap<InputLayoutId, InputLayoutDesc>,
    shaders: BTreeMap<ShaderId, ShaderRecord>,
    shader_cache: ShaderCache,
    translated_shaders: BTreeMap<String, ShaderTranslationOutput>,
    immediate: ImmediateContext,
}

impl D3d11Device {
    pub fn feature_level(&self) -> FeatureLevel {
        self.feature_level
    }

    pub fn caps(&self) -> &FeatureCaps {
        &self.caps
    }

    pub fn swapchain_state(&self) -> Option<SwapchainState> {
        self.swapchain
            .and_then(|swapchain| self.backend.swapchain_state(swapchain).ok())
    }

    pub fn swapchain_backbuffer(&self, index: u32) -> AppResult<D3d11ResourceId> {
        let state = self.swapchain_state().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain backbuffer",
            )
        })?;
        state
            .backbuffers
            .get(index as usize)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "swapchain buffer index out of range"))
    }

    pub fn create_buffer(&mut self, label: &str, byte_width: usize) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Buffer,
            format: DxgiFormat::R32Float,
            width: byte_width as u32,
            height: 1,
            depth: 1,
            byte_width,
        })
    }

    pub fn create_texture_1d(&mut self, label: &str, width: u32, format: DxgiFormat) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Texture1D,
            format,
            width,
            height: 1,
            depth: 1,
            byte_width: width as usize * 4,
        })
    }

    pub fn create_texture_2d(
        &mut self,
        label: &str,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Texture2D,
            format,
            width,
            height,
            depth: 1,
            byte_width: width as usize * height as usize * 4,
        })
    }

    pub fn create_texture_3d(
        &mut self,
        label: &str,
        width: u32,
        height: u32,
        depth: u32,
        format: DxgiFormat,
    ) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Texture3D,
            format,
            width,
            height,
            depth,
            byte_width: width as usize * height as usize * depth as usize * 4,
        })
    }

    pub fn resource_desc(&self, resource: D3d11ResourceId) -> AppResult<D3d11ResourceDesc> {
        Ok(self.resource(resource)?.desc.clone())
    }

    pub fn create_shader_resource_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Srv, format)
    }

    pub fn create_render_target_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Rtv, format)
    }

    pub fn create_depth_stencil_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Dsv, format)
    }

    pub fn create_unordered_access_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Uav, format)
    }

    pub fn view_info(&self, view: D3d11ViewId) -> AppResult<ViewInfo> {
        Ok(self.view(view)?.info.clone())
    }

    pub fn create_blend_state(&mut self, desc: BlendStateDesc) -> BlendStateId {
        let id = self.alloc_id();
        self.blend_states.insert(id, desc);
        id
    }

    pub fn create_rasterizer_state(&mut self, desc: RasterizerStateDesc) -> RasterizerStateId {
        let id = self.alloc_id();
        self.rasterizer_states.insert(id, desc);
        id
    }

    pub fn create_depth_stencil_state(&mut self, desc: DepthStencilStateDesc) -> DepthStencilStateId {
        let id = self.alloc_id();
        self.depth_stencil_states.insert(id, desc);
        id
    }

    pub fn create_sampler_state(&mut self, desc: SamplerStateDesc) -> SamplerStateId {
        let id = self.alloc_id();
        self.sampler_states.insert(id, desc);
        id
    }

    pub fn create_input_layout(&mut self, desc: InputLayoutDesc) -> InputLayoutId {
        let id = self.alloc_id();
        self.input_layouts.insert(id, desc);
        id
    }

    pub fn create_shader(&mut self, desc: ShaderModuleDesc) -> ShaderId {
        let id = self.alloc_id();
        self.shaders.insert(
            id,
            ShaderRecord {
                desc,
                artifact: None,
            },
        );
        id
    }

    pub fn create_shader_from_dxil(
        &mut self,
        desc: ShaderModuleDesc,
        dxil: Vec<u8>,
        root_signature: Vec<u8>,
    ) -> AppResult<ShaderId> {
        let artifact = self.translate_shader_artifact(&desc, dxil, root_signature)?;
        let id = self.alloc_id();
        self.shaders.insert(
            id,
            ShaderRecord {
                desc,
                artifact: Some(artifact),
            },
        );
        Ok(id)
    }

    pub fn shader_translation_cache_key(&self, shader: ShaderId) -> AppResult<Option<String>> {
        Ok(self.shader(shader)?.artifact.as_ref().map(|artifact| artifact.cache_key.clone()))
    }

    pub fn shader_translation_output(&self, shader: ShaderId) -> AppResult<Option<ShaderTranslationOutput>> {
        Ok(self.shader(shader)?.artifact.as_ref().map(|artifact| artifact.output.clone()))
    }

    pub fn om_set_render_targets(&mut self, render_targets: Vec<D3d11ViewId>, depth_target: Option<D3d11ViewId>) {
        self.immediate.bindings.render_targets = render_targets;
        self.immediate.bindings.depth_target = depth_target;
    }

    pub fn om_set_blend_state(&mut self, state: BlendStateId) {
        self.immediate.bindings.blend_state = Some(state);
    }

    pub fn om_set_depth_stencil_state(&mut self, state: DepthStencilStateId) {
        self.immediate.bindings.depth_stencil_state = Some(state);
    }

    pub fn rs_set_state(&mut self, state: RasterizerStateId) {
        self.immediate.bindings.rasterizer_state = Some(state);
    }

    pub fn rs_set_viewports(&mut self, viewport: Viewport) {
        self.immediate.bindings.viewport = Some(viewport);
    }

    pub fn ia_set_vertex_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate.bindings.vertex_buffers = buffers;
    }

    pub fn ia_set_index_buffer(&mut self, buffer: D3d11ResourceId) {
        self.immediate.bindings.index_buffer = Some(buffer);
    }

    pub fn ia_set_input_layout(&mut self, layout: InputLayoutId) {
        self.immediate.bindings.input_layout = Some(layout);
    }

    pub fn ia_clear_input_layout(&mut self) {
        self.immediate.bindings.input_layout = None;
    }

    pub fn vs_set_shader(&mut self, shader: ShaderId) {
        self.immediate.bindings.shaders.insert(ShaderStage::Vs, shader);
    }

    pub fn vs_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Vs);
    }

    pub fn ps_set_shader(&mut self, shader: ShaderId) {
        self.immediate.bindings.shaders.insert(ShaderStage::Ps, shader);
    }

    pub fn ps_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Ps);
    }

    pub fn cs_set_shader(&mut self, shader: ShaderId) {
        self.immediate.bindings.shaders.insert(ShaderStage::Cs, shader);
    }

    pub fn cs_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Cs);
    }

    pub fn vs_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate.bindings.constant_buffers.insert(ShaderStage::Vs, buffers);
    }

    pub fn ps_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate.bindings.constant_buffers.insert(ShaderStage::Ps, buffers);
    }

    pub fn ps_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate.bindings.shader_resources.insert(ShaderStage::Ps, resources);
    }

    pub fn cs_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate.bindings.shader_resources.insert(ShaderStage::Cs, resources);
    }

    pub fn ps_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate.bindings.samplers.insert(ShaderStage::Ps, samplers);
    }

    pub fn update_subresource(&mut self, resource: D3d11ResourceId, bytes: &[u8]) -> AppResult<()> {
        self.validate_resource_write(resource, bytes.len())?;
        self.immediate.commands.push(RecordedCommand::UpdateSubresource {
            resource,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    pub fn map(&mut self, resource: D3d11ResourceId) -> AppResult<Vec<u8>> {
        let record = self.resource_mut(resource)?;
        record.mapped = true;
        Ok(record.bytes.clone())
    }

    pub fn unmap(&mut self, resource: D3d11ResourceId, bytes: &[u8]) -> AppResult<()> {
        let backend_id = {
            let record = self.resource_mut(resource)?;
            if !record.mapped {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("resource {} is not mapped", record.desc.label),
                ));
            }
            if bytes.len() > record.bytes.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unmap payload exceeds resource {}", record.desc.label),
                ));
            }
            record.bytes[..bytes.len()].copy_from_slice(bytes);
            record.mapped = false;
            record.backend_id
        };
        self.backend.overwrite_resource_bytes(backend_id, bytes)?;
        Ok(())
    }

    pub fn copy_resource(&mut self, src: D3d11ResourceId, dst: D3d11ResourceId) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.immediate.commands.push(RecordedCommand::CopyResource { src, dst });
        Ok(())
    }

    pub fn copy_subresource_region(
        &mut self,
        src: D3d11ResourceId,
        dst: D3d11ResourceId,
        src_offset: usize,
        dst_offset: usize,
        size: usize,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.immediate.commands.push(RecordedCommand::CopySubresourceRegion {
            src,
            dst,
            src_offset,
            dst_offset,
            size,
        });
        Ok(())
    }

    pub fn clear_render_target_view(&mut self, view: D3d11ViewId, color: [u8; 4]) -> AppResult<()> {
        self.expect_view_kind(view, ViewKind::Rtv)?;
        self.immediate.commands.push(RecordedCommand::ClearRenderTargetView { view, color });
        Ok(())
    }

    pub fn clear_depth_stencil_view(&mut self, view: D3d11ViewId, depth: u32, stencil: u8) -> AppResult<()> {
        self.expect_view_kind(view, ViewKind::Dsv)?;
        self.immediate.commands.push(RecordedCommand::ClearDepthStencilView { view, depth, stencil });
        Ok(())
    }

    pub fn draw(&mut self, vertices: u32) {
        self.immediate.commands.push(RecordedCommand::Draw { vertices });
    }

    pub fn draw_indexed(&mut self, indices: u32) {
        self.immediate.commands.push(RecordedCommand::DrawIndexed { indices });
    }

    pub fn dispatch(&mut self, x: u32, y: u32, z: u32) {
        self.immediate.commands.push(RecordedCommand::Dispatch { x, y, z });
    }

    pub fn create_deferred_context(&self) -> DeferredContext {
        DeferredContext {
            recording: Arc::new(Mutex::new(DeferredRecording::default())),
        }
    }

    pub fn submit_immediate(&mut self) -> AppResult<SubmissionResult> {
        let bindings = self.immediate.bindings.clone();
        let commands = self.immediate.commands.clone();
        self.immediate.commands.clear();
        self.submit_sequences(vec![(bindings, commands)])
    }

    fn submit_immediate_without_digests(&mut self) -> AppResult<()> {
        let bindings = self.immediate.bindings.clone();
        let commands = self.immediate.commands.clone();
        self.immediate.commands.clear();
        self.submit_sequences_without_digests(vec![(bindings, commands)])
    }

    pub fn present_swapchain(
        &mut self,
        sync_interval: u32,
        allow_tearing: bool,
        capture_submission: bool,
    ) -> AppResult<(Option<SubmissionResult>, crate::gfx::PresentResult)> {
        let submission = if capture_submission {
            Some(self.submit_immediate()?)
        } else {
            self.submit_immediate_without_digests()?;
            None
        };
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to present",
            )
        })?;
        let present = self.backend.present(swapchain, sync_interval, allow_tearing)?;
        Ok((submission, present))
    }

    pub fn export_presented_frame_ppm(&self, path: &Path) -> AppResult<()> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to export",
            )
        })?;
        self.backend.export_presented_frame_ppm(swapchain, path)
    }

    pub fn presented_frame(&self) -> AppResult<crate::gfx::PresentedFrame> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to export",
            )
        })?;
        self.backend.presented_frame(swapchain)
    }

    pub fn open_presented_frame(&self) -> AppResult<()> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to preview",
            )
        })?;
        self.backend.open_presented_frame(swapchain)
    }

    pub fn execute_deferred_command_lists(&mut self, lists: &[D3d11CommandList]) -> AppResult<SubmissionResult> {
        let sequences = lists
            .iter()
            .map(|list| (ContextBindings::default(), list.commands.clone()))
            .collect::<Vec<_>>();
        self.submit_sequences_with_signatures(
            sequences,
            lists.iter().map(|list| list.binding_signature.clone()).collect(),
            true,
        )
    }

    pub fn resource_digest(&self, resource: D3d11ResourceId) -> AppResult<String> {
        Ok(util::sha256_bytes(&self.resource(resource)?.bytes))
    }

    fn create_resource(&mut self, desc: D3d11ResourceDesc) -> AppResult<D3d11ResourceId> {
        let id = self.alloc_id();
        let backend_id = self.backend.create_resource(ResourceDesc {
            name: desc.label.clone(),
            format: desc.format,
            heap: crate::gfx::HeapType::Default,
            size: desc.byte_width,
            subresources: 1,
            initial_state: ResourceState::Common,
        })?;
        self.resources.insert(
            id,
            ResourceRecord {
                bytes: vec![0; desc.byte_width],
                mapped: false,
                backend_id,
                include_in_digests: true,
                desc,
            },
        );
        Ok(id)
    }

    fn create_view(&mut self, resource: D3d11ResourceId, kind: ViewKind, format: DxgiFormat) -> AppResult<D3d11ViewId> {
        let backend_resource = self.resource(resource)?.backend_id;
        let heap = match kind {
            ViewKind::Rtv => {
                let heap = self.backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
                self.backend.write_descriptor(
                    heap,
                    0,
                    ViewDescriptor::Rtv {
                        resource: backend_resource,
                        format,
                    },
                )?;
                Some(heap)
            }
            ViewKind::Dsv => {
                let heap = self.backend.create_descriptor_heap(DescriptorHeapType::Dsv, 1);
                self.backend.write_descriptor(
                    heap,
                    0,
                    ViewDescriptor::Dsv {
                        resource: backend_resource,
                        format,
                    },
                )?;
                Some(heap)
            }
            ViewKind::Srv | ViewKind::Uav => None,
        };
        let id = self.alloc_id();
        self.views.insert(
            id,
            ViewRecord {
                info: ViewInfo {
                    resource,
                    kind,
                    format,
                },
                heap,
            },
        );
        Ok(id)
    }

    fn submit_sequences(&mut self, sequences: Vec<(ContextBindings, Vec<RecordedCommand>)>) -> AppResult<SubmissionResult> {
        let binding_signatures = sequences
            .iter()
            .map(|(bindings, _)| self.binding_signature(bindings))
            .collect::<AppResult<Vec<_>>>()?;
        self.submit_sequences_with_signatures(sequences, binding_signatures, true)
    }

    fn submit_sequences_without_digests(
        &mut self,
        sequences: Vec<(ContextBindings, Vec<RecordedCommand>)>,
    ) -> AppResult<()> {
        self.submit_sequences_with_signatures(sequences, Vec::new(), false)?;
        Ok(())
    }

    fn submit_sequences_with_signatures(
        &mut self,
        sequences: Vec<(ContextBindings, Vec<RecordedCommand>)>,
        binding_signatures: Vec<String>,
        capture_submission: bool,
    ) -> AppResult<SubmissionResult> {
        let mut immutable_streams = Vec::new();
        let mut draw_calls = 0;
        let mut indexed_draw_calls = 0;
        let mut dispatch_calls = 0;

        for (_bindings, commands) in &sequences {
            let list = self
                .backend
                .create_graphics_command_list(self.graphics_allocator, self.graphics_pipeline);
            for command in commands {
                match command {
                    RecordedCommand::UpdateSubresource { resource, bytes } => {
                        let backend_id = {
                            let record = self.resource_mut(*resource)?;
                            record.bytes[..bytes.len()].copy_from_slice(bytes);
                            record.backend_id
                        };
                        self.backend.overwrite_resource_bytes(backend_id, bytes)?;
                    }
                    RecordedCommand::CopyResource { src, dst } => {
                        let source_bytes = self.resource(*src)?.bytes.clone();
                        let src_backend = self.resource(*src)?.backend_id;
                        let dst_backend = self.resource(*dst)?.backend_id;
                        let destination = self.resource_mut(*dst)?;
                        destination.bytes = source_bytes;
                        self.backend.record_copy_resource(list, src_backend, dst_backend)?;
                    }
                    RecordedCommand::CopySubresourceRegion {
                        src,
                        dst,
                        src_offset,
                        dst_offset,
                        size,
                    } => {
                        let source = self.resource(*src)?.bytes.clone();
                        let destination = self.resource_mut(*dst)?;
                        let src_end = src_offset + size;
                        let dst_end = dst_offset + size;
                        if src_end > source.len() || dst_end > destination.bytes.len() {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                "copy subresource region out of bounds",
                            ));
                        }
                        destination.bytes[*dst_offset..dst_end].copy_from_slice(&source[*src_offset..src_end]);
                    }
                    RecordedCommand::ClearRenderTargetView { view, color } => {
                        let (resource_id, heap) = {
                            let view = self.view(*view)?;
                            (view.info.resource, view.heap.expect("RTV heap"))
                        };
                        let resource = self.resource_mut(resource_id)?;
                        for chunk in resource.bytes.chunks_mut(4) {
                            chunk.copy_from_slice(color);
                        }
                        self.backend.record_clear_rtv(list, heap, 0)?;
                    }
                    RecordedCommand::ClearDepthStencilView { view, depth, stencil } => {
                        let depth_bytes = [
                            (*depth & 0xff) as u8,
                            ((*depth >> 8) & 0xff) as u8,
                            ((*depth >> 16) & 0xff) as u8,
                            ((*depth >> 24) & 0xff) as u8,
                        ];
                        let (resource_id, heap) = {
                            let view = self.view(*view)?;
                            (view.info.resource, view.heap.expect("DSV heap"))
                        };
                        let resource = self.resource_mut(resource_id)?;
                        for chunk in resource.bytes.chunks_mut(5) {
                            if chunk.len() >= 4 {
                                chunk[..4].copy_from_slice(&depth_bytes);
                            }
                            if chunk.len() == 5 {
                                chunk[4] = *stencil;
                            }
                        }
                        self.backend.record_clear_dsv(list, heap, 0)?;
                    }
                    RecordedCommand::Draw { vertices } => {
                        draw_calls += 1;
                        self.backend.record_draw(list, *vertices)?;
                    }
                    RecordedCommand::DrawIndexed { indices } => {
                        indexed_draw_calls += 1;
                        self.backend.record_draw(list, *indices)?;
                    }
                    RecordedCommand::Dispatch { x, y, z } => {
                        dispatch_calls += 1;
                        self.backend.record_dispatch(list, *x, *y, *z)?;
                    }
                }
            }
            immutable_streams.push(self.backend.close_command_list(list)?);
        }

        self.next_fence_value += 1;
        let backend_plan = self.backend.execute_command_lists(
            self.queue,
            &immutable_streams,
            Some((self.fence, self.next_fence_value)),
        )?;
        let (resource_digests, signature, hash) = if capture_submission {
            let resource_digests = self.collect_resource_digests();
            let gpu_profile = self.pipeline_profile_signature();
            let signature = build_submission_signature(
                &gpu_profile,
                self.feature_level,
                draw_calls,
                indexed_draw_calls,
                dispatch_calls,
                sequences.len(),
                &binding_signatures,
                &resource_digests,
                &backend_plan,
            );
            let hash = util::sha256_bytes(signature.as_bytes());
            (resource_digests, signature, hash)
        } else {
            (BTreeMap::new(), String::new(), String::new())
        };
        Ok(SubmissionResult {
            feature_level: self.feature_level,
            draw_calls,
            indexed_draw_calls,
            dispatch_calls,
            executed_command_lists: sequences.len(),
            resource_digests,
            hash,
            signature,
            backend_plan,
        })
    }

    fn collect_resource_digests(&self) -> BTreeMap<String, String> {
        self.resources
            .values()
            .filter(|resource| resource.include_in_digests)
            .map(|resource| {
                (
                    resource.desc.label.clone(),
                    util::sha256_bytes(&resource.bytes),
                )
            })
            .collect()
    }

    fn pipeline_profile_signature(&self) -> String {
        let adapter = self.backend.adapter();
        let caps = self.backend.capabilities();
        format!(
            "adapter={}|family={}|argbuf={}|unified={}|memoryless={}|timestamps={}|mesh={}",
            adapter.name,
            adapter.metal_family,
            caps.argument_buffers,
            caps.unified_memory,
            caps.memoryless_render_targets,
            caps.timestamp_queries,
            caps.mesh_shaders,
        )
    }

    fn translate_shader_artifact(
        &mut self,
        desc: &ShaderModuleDesc,
        dxil: Vec<u8>,
        root_signature: Vec<u8>,
    ) -> AppResult<ShaderArtifact> {
        let input = ShaderTranslationInput {
            dxil,
            stage: translate_shader_stage(desc.stage),
            root_signature,
            compile_flags: runtime_shader_compile_flags(),
            gpu_family: self.backend.adapter().metal_family.clone(),
            os_build: runtime_os_build(),
            macwin_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let cache_key = shader_cache_key(&input)?;
        let output = if let Some(output) = self.translated_shaders.get(&cache_key) {
            output.clone()
        } else {
            let output = translate_shader(&input).map_err(shader_error_to_app_error)?;
            let entry = build_cache_entry(&cache_key, &output, 0, None)?;
            self.shader_cache.insert(entry);
            self.translated_shaders.insert(cache_key.clone(), output.clone());
            output
        };
        let metal_entry = output
            .function_mapping
            .get(&desc.entry)
            .cloned()
            .or_else(|| output.function_mapping.values().next().cloned())
            .unwrap_or_else(|| desc.entry.clone());
        Ok(ShaderArtifact {
            cache_key,
            metal_entry,
            output,
        })
    }

    fn binding_signature(&self, bindings: &ContextBindings) -> AppResult<String> {
        let gpu_profile = self.pipeline_profile_signature();
        let render_targets = bindings
            .render_targets
            .iter()
            .map(|view| {
                let view = self.view(*view)?;
                Ok(format!("{:?}:{}", view.info.kind, self.resource(view.info.resource)?.desc.label))
            })
            .collect::<AppResult<Vec<_>>>()?;
        let depth_target = bindings.depth_target.map(|view| {
            self.view(view)
                .and_then(|view| Ok(self.resource(view.info.resource)?.desc.label.clone()))
        }).transpose()?;
        let viewport = bindings.viewport.as_ref().map(|viewport| {
            format!("{:.1},{:.1},{:.1},{:.1}", viewport.x, viewport.y, viewport.width, viewport.height)
        }).unwrap_or_else(|| "none".to_string());
        let vertex_buffers = bindings
            .vertex_buffers
            .iter()
            .map(|resource| self.resource(*resource).map(|record| record.desc.label.clone()))
            .collect::<AppResult<Vec<_>>>()?;
        let index_buffer = bindings.index_buffer.map(|resource| {
            self.resource(resource).map(|record| record.desc.label.clone())
        }).transpose()?;
        let input_layout = bindings.input_layout.map(|layout| {
            self.input_layouts
                .get(&layout)
                .map(|layout| {
                    layout
                        .elements
                        .iter()
                        .map(|element| format!("{}:{:?}:{}", element.semantic, element.format, element.slot))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown input layout {layout}")))
        }).transpose()?.unwrap_or_else(|| "none".to_string());
        let blend = bindings.blend_state.map(|id| {
            self.blend_states
                .get(&id)
                .map(|state| format!("{}:{}", state.blend_enable, state.alpha_to_coverage))
                .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown blend state {id}")))
        }).transpose()?.unwrap_or_else(|| "none".to_string());
        let rasterizer = bindings.rasterizer_state.map(|id| {
            self.rasterizer_states
                .get(&id)
                .map(|state| format!("{}:{}", state.fill_mode, state.cull_mode))
                .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown rasterizer state {id}")))
        }).transpose()?.unwrap_or_else(|| "none".to_string());
        let depth = bindings.depth_stencil_state.map(|id| {
            self.depth_stencil_states
                .get(&id)
                .map(|state| format!("{}:{}", state.depth_enable, state.depth_write))
                .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown depth state {id}")))
        }).transpose()?.unwrap_or_else(|| "none".to_string());
        let shaders = [ShaderStage::Vs, ShaderStage::Ps, ShaderStage::Cs]
            .iter()
            .map(|stage| {
                bindings.shaders.get(stage).map(|id| {
                    self.shader(*id).map(|shader| {
                        if let Some(artifact) = &shader.artifact {
                            format!(
                                "{:?}:{}:{}",
                                stage, artifact.metal_entry, artifact.cache_key
                            )
                        } else {
                            format!("{:?}:{}", stage, shader.desc.entry)
                        }
                    })
                }).transpose().map(|value| value.unwrap_or_else(|| format!("{:?}:none", stage)))
            })
            .collect::<AppResult<Vec<_>>>()?;
        let constant_buffers = stage_binding_labels(&bindings.constant_buffers, |resource| {
            self.resource(resource).map(|record| record.desc.label.clone())
        })?;
        let shader_resources = stage_binding_labels(&bindings.shader_resources, |view| {
            self.view(view)
                .and_then(|record| self.resource(record.info.resource).map(|resource| resource.desc.label.clone()))
        })?;
        let samplers = stage_binding_labels(&bindings.samplers, |id| {
            self.sampler_states
                .get(&id)
                .map(|state| format!("{:?}:{}:{}", state.filter, state.address_u, state.address_v))
                .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown sampler {id}")))
        })?;
        Ok(format!(
            "gpu={}|rtv=[{}]|dsv={}|vp={}|vb=[{}]|ib={}|il={}|blend={}|rast={}|depth={}|shaders=[{}]|cb=[{}]|srv=[{}]|samp=[{}]",
            gpu_profile,
            render_targets.join(","),
            depth_target.unwrap_or_else(|| "none".to_string()),
            viewport,
            vertex_buffers.join(","),
            index_buffer.unwrap_or_else(|| "none".to_string()),
            input_layout,
            blend,
            rasterizer,
            depth,
            shaders.join(","),
            constant_buffers,
            shader_resources,
            samplers,
        ))
    }

    fn validate_resource_write(&self, resource: D3d11ResourceId, length: usize) -> AppResult<()> {
        let record = self.resource(resource)?;
        if length > record.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("write exceeds resource {}", record.desc.label),
            ));
        }
        Ok(())
    }

    fn expect_view_kind(&self, view: D3d11ViewId, kind: ViewKind) -> AppResult<()> {
        let actual = self.view(view)?;
        if actual.info.kind != kind {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("expected {:?} view, found {:?}", kind, actual.info.kind),
            ));
        }
        Ok(())
    }

    fn resource(&self, resource: D3d11ResourceId) -> AppResult<&ResourceRecord> {
        self.resources.get(&resource).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown D3D11 resource {resource}"))
        })
    }

    fn shader(&self, shader: ShaderId) -> AppResult<&ShaderRecord> {
        self.shaders.get(&shader).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown shader {shader}"))
        })
    }

    fn resource_mut(&mut self, resource: D3d11ResourceId) -> AppResult<&mut ResourceRecord> {
        self.resources.get_mut(&resource).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown D3D11 resource {resource}"))
        })
    }

    fn view(&self, view: D3d11ViewId) -> AppResult<&ViewRecord> {
        self.views.get(&view).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown D3D11 view {view}"))
        })
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl DeferredContext {
    pub fn om_set_render_targets(&self, render_targets: Vec<D3d11ViewId>, depth_target: Option<D3d11ViewId>) -> AppResult<()> {
        let mut recording = self.lock()?;
        recording.bindings.render_targets = render_targets;
        recording.bindings.depth_target = depth_target;
        Ok(())
    }

    pub fn rs_set_viewports(&self, viewport: Viewport) -> AppResult<()> {
        self.lock()?.bindings.viewport = Some(viewport);
        Ok(())
    }

    pub fn ia_set_vertex_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock()?.bindings.vertex_buffers = buffers;
        Ok(())
    }

    pub fn ia_set_index_buffer(&self, buffer: D3d11ResourceId) -> AppResult<()> {
        self.lock()?.bindings.index_buffer = Some(buffer);
        Ok(())
    }

    pub fn ia_set_input_layout(&self, layout: InputLayoutId) -> AppResult<()> {
        self.lock()?.bindings.input_layout = Some(layout);
        Ok(())
    }

    pub fn ia_clear_input_layout(&self) -> AppResult<()> {
        self.lock()?.bindings.input_layout = None;
        Ok(())
    }

    pub fn om_set_blend_state(&self, state: BlendStateId) -> AppResult<()> {
        self.lock()?.bindings.blend_state = Some(state);
        Ok(())
    }

    pub fn rs_set_state(&self, state: RasterizerStateId) -> AppResult<()> {
        self.lock()?.bindings.rasterizer_state = Some(state);
        Ok(())
    }

    pub fn om_set_depth_stencil_state(&self, state: DepthStencilStateId) -> AppResult<()> {
        self.lock()?.bindings.depth_stencil_state = Some(state);
        Ok(())
    }

    pub fn vs_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock()?.bindings.shaders.insert(ShaderStage::Vs, shader);
        Ok(())
    }

    pub fn vs_clear_shader(&self) -> AppResult<()> {
        self.lock()?.bindings.shaders.remove(&ShaderStage::Vs);
        Ok(())
    }

    pub fn ps_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock()?.bindings.shaders.insert(ShaderStage::Ps, shader);
        Ok(())
    }

    pub fn ps_clear_shader(&self) -> AppResult<()> {
        self.lock()?.bindings.shaders.remove(&ShaderStage::Ps);
        Ok(())
    }

    pub fn cs_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock()?.bindings.shaders.insert(ShaderStage::Cs, shader);
        Ok(())
    }

    pub fn cs_clear_shader(&self) -> AppResult<()> {
        self.lock()?.bindings.shaders.remove(&ShaderStage::Cs);
        Ok(())
    }

    pub fn vs_set_constant_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock()?.bindings.constant_buffers.insert(ShaderStage::Vs, buffers);
        Ok(())
    }

    pub fn ps_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock()?.bindings.shader_resources.insert(ShaderStage::Ps, resources);
        Ok(())
    }

    pub fn ps_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock()?.bindings.samplers.insert(ShaderStage::Ps, samplers);
        Ok(())
    }

    pub fn update_subresource(&self, resource: D3d11ResourceId, bytes: &[u8]) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::UpdateSubresource {
            resource,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    pub fn clear_render_target_view(&self, view: D3d11ViewId, color: [u8; 4]) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::ClearRenderTargetView { view, color });
        Ok(())
    }

    pub fn clear_depth_stencil_view(&self, view: D3d11ViewId, depth: u32, stencil: u8) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::ClearDepthStencilView { view, depth, stencil });
        Ok(())
    }

    pub fn copy_resource(&self, src: D3d11ResourceId, dst: D3d11ResourceId) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::CopyResource { src, dst });
        Ok(())
    }

    pub fn draw(&self, vertices: u32) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::Draw { vertices });
        Ok(())
    }

    pub fn draw_indexed(&self, indices: u32) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::DrawIndexed { indices });
        Ok(())
    }

    pub fn dispatch(&self, x: u32, y: u32, z: u32) -> AppResult<()> {
        self.lock()?.commands.push(RecordedCommand::Dispatch { x, y, z });
        Ok(())
    }

    pub fn finish_command_list(&self, device: &D3d11Device) -> AppResult<D3d11CommandList> {
        let recording = self.lock()?;
        Ok(D3d11CommandList {
            binding_signature: device.binding_signature(&recording.bindings)?,
            commands: recording.commands.clone(),
        })
    }

    fn lock(&self) -> AppResult<std::sync::MutexGuard<'_, DeferredRecording>> {
        self.recording.lock().map_err(|_| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "deferred context mutex poisoned",
            )
        })
    }
}

impl Direct3D9Shim {
    pub fn create_device(&mut self) -> AppResult<Direct3D9Device> {
        if !self.enabled {
            return Err(AppError::new(
                ReasonCode::RcD3d9NotSupported,
                "d3d9 is disabled for this GE",
            )
            .with_hint("enable the Direct3D9 compatibility shim for legacy fixed-function titles"));
        }
        let id = self.next_id;
        self.next_id += 1;
        Ok(Direct3D9Device { id })
    }
}

impl Direct3D9Device {
    pub fn render_fixed_function_scene(&self, scene: &FixedFunctionScene) -> AppResult<D3d9Frame> {
        let signature = format!(
            "d3d9:id={}|tf={:08x}|diff={:02x}{:02x}{:02x}{:02x}|fog={}|blend={}|prim={}",
            self.id,
            scene.texture_factor,
            scene.diffuse_color[0],
            scene.diffuse_color[1],
            scene.diffuse_color[2],
            scene.diffuse_color[3],
            scene.fog_enable,
            scene.alpha_blend_enable,
            scene.primitive_count,
        );
        Ok(D3d9Frame {
            hash: util::sha256_bytes(signature.as_bytes()),
            signature,
        })
    }
}

pub fn d3d11_create_device(request: DeviceCreationRequest) -> AppResult<D3d11Device> {
    create_device_internal(request, None)
}

pub fn d3d11_create_device_and_swapchain(
    request: DeviceCreationRequest,
    swapchain_desc: SwapchainDesc,
) -> AppResult<D3d11Device> {
    create_device_internal(request, Some(swapchain_desc))
}

pub fn direct3d_create9(enabled: bool) -> Direct3D9Shim {
    Direct3D9Shim { enabled, next_id: 1 }
}

fn create_device_internal(
    request: DeviceCreationRequest,
    swapchain_desc: Option<SwapchainDesc>,
) -> AppResult<D3d11Device> {
    create_device_internal_with_backend(request, swapchain_desc, GraphicsBackend::new())
}

fn create_device_internal_with_backend(
    request: DeviceCreationRequest,
    swapchain_desc: Option<SwapchainDesc>,
    mut backend: GraphicsBackend,
) -> AppResult<D3d11Device> {
    let requested = if request.requested_feature_levels.is_empty() {
        vec![FeatureLevel::Level11_0, FeatureLevel::Level10_1]
    } else {
        request.requested_feature_levels
    };
    let feature_level = requested
        .iter()
        .copied()
        .find(|level| *level == FeatureLevel::Level10_1)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                "requested D3D11 feature levels are not supported by the Metal planner",
            )
            .with_hint("request feature level 10_1 when geometry or tessellation shaders are unavailable")
        })?;
    let swapchain = match swapchain_desc {
        Some(desc) => Some(backend.create_swapchain(desc)?),
        None => None,
    };
    let mut resources = BTreeMap::new();
    let mut next_id = 1_u64;
    if let Some(swapchain_id) = swapchain {
        let state = backend.swapchain_state(swapchain_id)?;
        for (index, backbuffer) in state.backbuffers.iter().copied().enumerate() {
            resources.insert(
                backbuffer,
                ResourceRecord {
                    bytes: vec![0; state.desc.width as usize * state.desc.height as usize * 4],
                    mapped: false,
                    backend_id: backbuffer,
                    include_in_digests: false,
                    desc: D3d11ResourceDesc {
                        label: format!("swapchain-backbuffer-{index}"),
                        dimension: ResourceDimension::Texture2D,
                        format: state.desc.format,
                        width: state.desc.width,
                        height: state.desc.height,
                        depth: 1,
                        byte_width: state.desc.width as usize * state.desc.height as usize * 4,
                    },
                },
            );
            next_id = next_id.max(backbuffer.saturating_add(1));
        }
    }
    let queue = backend.create_command_queue();
    let allocator = backend.create_command_allocator();
    let root_signature = backend.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
    });
    let pipeline_label = format!(
        "d3d11-immediate-{}-mesh{}-argbuf{}",
        backend.adapter().metal_family,
        u8::from(backend.capabilities().mesh_shaders),
        u8::from(backend.capabilities().argument_buffers),
    );
    let pipeline = backend.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: pipeline_label,
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );
    let fence = backend.create_fence(0);
    Ok(D3d11Device {
        next_id,
        backend,
        feature_level,
        caps: FeatureCaps {
            geometry_shader: false,
            hull_shader: false,
            domain_shader: false,
        },
        swapchain,
        queue,
        graphics_allocator: allocator,
        graphics_pipeline: pipeline,
        fence,
        next_fence_value: 0,
        resources,
        views: BTreeMap::new(),
        blend_states: BTreeMap::new(),
        rasterizer_states: BTreeMap::new(),
        depth_stencil_states: BTreeMap::new(),
        sampler_states: BTreeMap::new(),
        input_layouts: BTreeMap::new(),
        shaders: BTreeMap::new(),
        shader_cache: ShaderCache::new(1 << 20),
        translated_shaders: BTreeMap::new(),
        immediate: ImmediateContext::default(),
    })
}

fn translate_shader_stage(stage: ShaderStage) -> TranslationShaderStage {
    match stage {
        ShaderStage::Vs => TranslationShaderStage::Vs,
        ShaderStage::Ps => TranslationShaderStage::Ps,
        ShaderStage::Cs => TranslationShaderStage::Cs,
    }
}

fn runtime_shader_compile_flags() -> ShaderCompileFlags {
    ShaderCompileFlags {
        fast_math: true,
        denorm_mode: "preserve".to_string(),
        debug: false,
        optimization_level: 3,
    }
}

fn runtime_os_build() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn shader_error_to_app_error(error: crate::shader::ShaderError) -> AppError {
    AppError::new(error.reason_code, error.message).with_hint(format!(
        "dxil_hash={}; stage={:?}; pass={}",
        error.dxil_hash, error.stage, error.failing_pass
    ))
}

fn stage_binding_labels<T, F>(
    bindings: &BTreeMap<ShaderStage, Vec<T>>,
    mut formatter: F,
) -> AppResult<String>
where
    T: Copy,
    F: FnMut(T) -> AppResult<String>,
{
    let mut parts = Vec::new();
    for stage in [ShaderStage::Vs, ShaderStage::Ps, ShaderStage::Cs] {
        let labels = bindings
            .get(&stage)
            .map(|values| values.iter().copied().map(&mut formatter).collect::<AppResult<Vec<_>>>())
            .transpose()?
            .unwrap_or_default();
        parts.push(format!("{:?}=[{}]", stage, labels.join(",")));
    }
    Ok(parts.join(";"))
}

fn build_submission_signature(
    gpu_profile: &str,
    feature_level: FeatureLevel,
    draw_calls: u32,
    indexed_draw_calls: u32,
    dispatch_calls: u32,
    executed_command_lists: usize,
    binding_signatures: &[String],
    resource_digests: &BTreeMap<String, String>,
    backend_plan: &crate::gfx::MetalCommandBufferPlan,
) -> String {
    let mut signature = format!(
        "gpu={}|fl={:?}|lists={}|draw={}|draw_indexed={}|dispatch={}|render_passes={}|compute_passes={}|blit_passes={}|validation={}",
        gpu_profile,
        feature_level,
        executed_command_lists,
        draw_calls,
        indexed_draw_calls,
        dispatch_calls,
        backend_plan.render_passes.len(),
        backend_plan.compute_passes,
        backend_plan.blit_passes,
        backend_plan.validation_errors.len(),
    );
    for (index, binding_signature) in binding_signatures.iter().enumerate() {
        signature.push_str(&format!("|bind[{index}]={binding_signature}"));
    }
    for RenderPassPlan {
        color_formats,
        depth_format,
        draw_calls,
        load_action,
        store_action,
    } in &backend_plan.render_passes
    {
        signature.push_str(&format!(
            "|rp={:?}:{:?}:{}:{}:{}",
            color_formats, depth_format, draw_calls, load_action, store_action
        ));
    }
    for (label, digest) in resource_digests {
        signature.push_str(&format!("|res[{label}]={digest}"));
    }
    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gfx::{host_gpu_profile_from_name, HostGpuProfile};

    fn build_root_signature(root_constants: u32, descriptors: &[(u8, u8, u8, u8, u8, u8)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&(descriptors.len() as u32).to_le_bytes());
        bytes.extend(&root_constants.to_le_bytes());
        for descriptor in descriptors {
            bytes.extend([
                descriptor.0,
                descriptor.1,
                descriptor.2,
                descriptor.3,
                descriptor.4,
                descriptor.5,
            ]);
        }
        bytes
    }

    fn build_program_part(
        instruction_count: u32,
        ir_size: u32,
        threadgroup_size: (u32, u32, u32),
        uses: &[(u8, u8, u8, u8, u8, u16)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&instruction_count.to_le_bytes());
        bytes.extend(&ir_size.to_le_bytes());
        bytes.extend(&threadgroup_size.0.to_le_bytes());
        bytes.extend(&threadgroup_size.1.to_le_bytes());
        bytes.extend(&threadgroup_size.2.to_le_bytes());
        bytes.extend(&(uses.len() as u32).to_le_bytes());
        for entry in uses {
            bytes.extend([
                entry.0,
                entry.1,
                entry.2,
                entry.3,
                entry.4,
                entry.5 as u8,
                (entry.5 >> 8) as u8,
                0,
            ]);
        }
        bytes
    }

    fn build_reflection_part(
        resources: &[(u8, u8, u8, u8, u8, u8, u8)],
        cbuffers: &[(u8, u8, u16, u32)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&(resources.len() as u32).to_le_bytes());
        for resource in resources {
            bytes.extend([
                resource.0,
                resource.1,
                resource.2,
                resource.3,
                resource.4,
                resource.5,
                resource.6,
            ]);
        }
        bytes.extend(&(cbuffers.len() as u32).to_le_bytes());
        for cbuffer in cbuffers {
            bytes.extend([
                cbuffer.0,
                cbuffer.1,
                cbuffer.2 as u8,
                (cbuffer.2 >> 8) as u8,
                cbuffer.3 as u8,
                (cbuffer.3 >> 8) as u8,
                (cbuffer.3 >> 16) as u8,
                (cbuffer.3 >> 24) as u8,
            ]);
        }
        bytes
    }

    fn build_container(entry_name: &str, parts: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
        let header_size = 12 + parts.len() * 12;
        let mut offset = header_size as u32;
        let descriptors = parts
            .iter()
            .map(|(kind, payload)| {
                let descriptor = (*kind, offset, payload.len() as u32);
                offset += payload.len() as u32;
                descriptor
            })
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        bytes.extend(b"DXIL");
        bytes.extend(&1_u32.to_le_bytes());
        bytes.extend(&(parts.len() as u32).to_le_bytes());
        for (kind, offset, size) in &descriptors {
            bytes.extend(kind);
            bytes.extend(&offset.to_le_bytes());
            bytes.extend(&size.to_le_bytes());
        }
        for (_, payload) in parts {
            bytes.extend(payload);
        }
        let mut meta = vec![entry_name.len() as u8];
        meta.extend(entry_name.as_bytes());
        let parts_without_meta = bytes[12 + descriptors.len() * 12..].to_vec();
        let mut rewritten = Vec::new();
        rewritten.extend(b"DXIL");
        rewritten.extend(&1_u32.to_le_bytes());
        rewritten.extend(&((descriptors.len() + 1) as u32).to_le_bytes());
        let mut running_offset = (12 + (descriptors.len() + 1) * 12) as u32;
        for (kind, _, size) in descriptors {
            rewritten.extend(kind);
            rewritten.extend(&running_offset.to_le_bytes());
            rewritten.extend(&size.to_le_bytes());
            running_offset += size;
        }
        rewritten.extend(*b"META");
        rewritten.extend(&running_offset.to_le_bytes());
        rewritten.extend(&(meta.len() as u32).to_le_bytes());
        rewritten.extend(parts_without_meta);
        rewritten.extend(meta);
        rewritten
    }

    fn reflected_dxil_fixture(entry_name: &str) -> (Vec<u8>, Vec<u8>) {
        let root_signature = build_root_signature(8, &[(1, 0, 0, 1, 0, 0), (2, 0, 0, 1, 1, 0), (3, 0, 0, 1, 2, 0)]);
        let dxil = build_container(
            entry_name,
            vec![
                (
                    *b"PROG",
                    build_program_part(
                        32,
                        512,
                        (8, 8, 1),
                        &[(1, 0, 0, 0, 1, 0), (2, 0, 0, 0, 3, 0), (3, 0, 0, 0, 0, 64)],
                    ),
                ),
                (*b"SIGN", b"input-signature-output-signature".to_vec()),
                (
                    *b"RFLX",
                    build_reflection_part(
                        &[(1, 0, 0, 0, 0, 0, 1), (2, 0, 0, 1, 0, 0, 3)],
                        &[(0, 0, 64, 0x0102_0304)],
                    ),
                ),
            ],
        );
        (dxil, root_signature)
    }

    fn test_backend(profile: HostGpuProfile) -> GraphicsBackend {
        GraphicsBackend::with_host_profile(profile)
    }

    #[test]
    fn update_subresource_reaches_presented_swapchain_frame() {
        let mut device = d3d11_create_device_and_swapchain(
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
        .expect("create device and swapchain");

        let backbuffer = device.swapchain_backbuffer(0).expect("swapchain backbuffer");
        let uploaded = [0x30, 0x20, 0x10, 0xff, 0x60, 0x50, 0x40, 0xff];

        device
            .update_subresource(backbuffer, &uploaded)
            .expect("update subresource");
        device
            .present_swapchain(1, false, true)
            .expect("present swapchain");

        let frame = device.presented_frame().expect("presented frame");
        assert_eq!(frame.width, 2);
        assert_eq!(frame.height, 1);
        assert_eq!(&frame.bytes[..uploaded.len()], &uploaded);
    }

    #[test]
    fn repeated_presents_keep_showing_updated_backbuffer_zero() {
        let mut device = d3d11_create_device_and_swapchain(
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
        .expect("create device and swapchain");

        let backbuffer = device.swapchain_backbuffer(0).expect("swapchain backbuffer");
        let first = [0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff];
        let second = [0xa0, 0xb0, 0xc0, 0xff, 0xd0, 0xe0, 0xf0, 0xff];

        device
            .update_subresource(backbuffer, &first)
            .expect("update first frame");
        device
            .present_swapchain(1, false, true)
            .expect("present first frame");
        let first_frame = device.presented_frame().expect("first presented frame");
        assert_eq!(&first_frame.bytes[..first.len()], &first);

        device
            .update_subresource(backbuffer, &second)
            .expect("update second frame");
        device
            .present_swapchain(1, false, true)
            .expect("present second frame");
        let second_frame = device.presented_frame().expect("second presented frame");
        assert_eq!(&second_frame.bytes[..second.len()], &second);
    }

    #[test]
    fn submission_signature_changes_with_detected_gpu_family_profile() {
        let mut apple7 = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create apple7 device");
        let apple7_shader = apple7.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Ps,
            entry: "main_ps".to_string(),
        });
        apple7.ps_set_shader(apple7_shader);
        let apple7_submission = apple7.submit_immediate().expect("submit apple7 workload");

        let mut apple11 = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M5 Pro")),
        )
        .expect("create apple11 device");
        let apple11_shader = apple11.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Ps,
            entry: "main_ps".to_string(),
        });
        apple11.ps_set_shader(apple11_shader);
        let apple11_submission = apple11.submit_immediate().expect("submit apple11 workload");

        assert!(apple7_submission.signature.contains("family=apple7"));
        assert!(apple11_submission.signature.contains("family=apple11"));
        assert!(apple7_submission.signature.contains("mesh=false"));
        assert!(apple11_submission.signature.contains("mesh=true"));
        assert_ne!(apple7_submission.signature, apple11_submission.signature);
        assert_ne!(apple7_submission.hash, apple11_submission.hash);
    }

    #[test]
    fn dxil_shader_creation_uses_gpu_family_in_cache_key_and_reuses_device_cache() {
        let (dxil, root_signature) = reflected_dxil_fixture("main_ps");
        let mut apple7 = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create apple7 device");
        let shader_a = apple7
            .create_shader_from_dxil(
                ShaderModuleDesc {
                    stage: ShaderStage::Ps,
                    entry: "main_ps".to_string(),
                },
                dxil.clone(),
                root_signature.clone(),
            )
            .expect("compile first apple7 shader");
        let shader_b = apple7
            .create_shader_from_dxil(
                ShaderModuleDesc {
                    stage: ShaderStage::Ps,
                    entry: "main_ps".to_string(),
                },
                dxil.clone(),
                root_signature.clone(),
            )
            .expect("compile second apple7 shader");
        let apple7_key_a = apple7
            .shader_translation_cache_key(shader_a)
            .expect("apple7 key a")
            .expect("apple7 shader should have cache key");
        let apple7_key_b = apple7
            .shader_translation_cache_key(shader_b)
            .expect("apple7 key b")
            .expect("apple7 shader should have cache key");
        assert_eq!(apple7_key_a, apple7_key_b);
        assert_eq!(apple7.shader_cache.len(), 1);
        assert_eq!(apple7.translated_shaders.len(), 1);

        apple7.ps_set_shader(shader_a);
        let apple7_binding = apple7
            .binding_signature(&apple7.immediate.bindings)
            .expect("apple7 binding signature");
        assert!(apple7_binding.contains(&apple7_key_a));
        assert!(apple7_binding.contains("msl_ps_"));

        let mut apple11 = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M5 Pro")),
        )
        .expect("create apple11 device");
        let shader_c = apple11
            .create_shader_from_dxil(
                ShaderModuleDesc {
                    stage: ShaderStage::Ps,
                    entry: "main_ps".to_string(),
                },
                dxil,
                root_signature,
            )
            .expect("compile apple11 shader");
        let apple11_key = apple11
            .shader_translation_cache_key(shader_c)
            .expect("apple11 key")
            .expect("apple11 shader should have cache key");
        assert_ne!(apple7_key_a, apple11_key);

        let translation = apple11
            .shader_translation_output(shader_c)
            .expect("apple11 translation output")
            .expect("translation output should exist");
        assert_eq!(translation.cache_key, apple11_key);
        assert_eq!(apple11.shader_cache.len(), 1);
        assert_eq!(apple11.translated_shaders.len(), 1);
    }
}