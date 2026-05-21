use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command as HostCommand, Stdio};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const GPU_COMPAT_VENDOR_ENV: &str = "CASA1_GPU_COMPAT_VENDOR";

pub type AdapterId = u64;
pub type OutputId = u64;
pub type SwapchainId = u64;
pub type ResourceId = u64;
pub type DescriptorHeapId = u64;
pub type CommandQueueId = u64;
pub type CommandAllocatorId = u64;
pub type CommandListId = u64;
pub type FenceId = u64;
pub type QueryHeapId = u64;
pub type RootSignatureId = u64;
pub type PipelineStateId = u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DxgiFormat {
    R8G8B8A8Unorm,
    R8G8B8A8UnormSrgb,
    R8G8B8A8Uint,
    B8G8R8A8Unorm,
    B8G8R8A8UnormSrgb,
    B8G8R8X8Unorm,
    R8Unorm,
    R8Uint,
    R16Float,
    R16Unorm,
    R16Uint,
    R16Snorm,
    R32Float,
    R32Uint,
    R32Sint,
    R10G10B10A2Unorm,
    R10G10B10A2Uint,
    R11G11B10Float,
    R16G16Float,
    R16G16Unorm,
    R16G16Uint,
    R16G16Snorm,
    R32G32Float,
    R32G32Uint,
    R16G16B16A16Float,
    R16G16B16A16Unorm,
    R16G16B16A16Uint,
    R32G32B32A32Float,
    R32G32B32A32Uint,
    D24UnormS8Uint,
    D32Float,
    D32FloatS8Uint,
    Bc1Unorm,
    Bc1UnormSrgb,
    Bc2Unorm,
    Bc2UnormSrgb,
    Bc3Unorm,
    Bc3UnormSrgb,
    Bc4Unorm,
    Bc5Unorm,
    Bc7Unorm,
    Bc7UnormSrgb,
    B5G6R5Unorm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MtlPixelFormat {
    Rgba8Unorm,
    Rgba8UnormSrgb,
    Rgba8Uint,
    Bgra8Unorm,
    Bgra8UnormSrgb,
    R8Unorm,
    R8Uint,
    R16Float,
    R16Unorm,
    R16Uint,
    R16Snorm,
    R32Float,
    R32Uint,
    R32Sint,
    Rgb10A2Unorm,
    Rgb10A2Uint,
    Rg11B10Float,
    Rg16Float,
    Rg16Unorm,
    Rg16Uint,
    Rg16Snorm,
    Rg32Float,
    Rg32Uint,
    Rgba16Float,
    Rgba16Unorm,
    Rgba16Uint,
    Rgba32Float,
    Rgba32Uint,
    Depth24UnormStencil8,
    Depth32Float,
    Depth32FloatStencil8,
    Bc1Rgba,
    Bc1RgbaSrgb,
    Bc2Rgba,
    Bc2RgbaSrgb,
    Bc3Rgba,
    Bc3RgbaSrgb,
    Bc4RUnorm,
    Bc5RgUnorm,
    Bc7RgbaUnorm,
    Bc7RgbaUnormSrgb,
    B5G6R5Unorm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmulationStrategy {
    Direct,
    ConversionShader,
    Swizzle,
    DepthStencilEmulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormatMapping {
    pub dxgi: DxgiFormat,
    pub metal: MtlPixelFormat,
    pub strategy: EmulationStrategy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureQuery {
    Tearing,
    TimestampQueries,
    MeshShaders,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterInfo {
    pub id: AdapterId,
    pub vendor_id: u32,
    pub device_id: u32,
    pub name: String,
    pub metal_family: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetalCapabilities {
    pub unified_memory: bool,
    pub argument_buffers: bool,
    pub memoryless_render_targets: bool,
    pub timestamp_queries: bool,
    pub mesh_shaders: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostGpuProfile {
    pub adapter: AdapterInfo,
    pub capabilities: MetalCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportedGpuVendor {
    Apple,
    Nvidia,
    Amd,
}

impl ReportedGpuVendor {
    fn vendor_id(self) -> u32 {
        match self {
            Self::Apple => 0x106b,
            Self::Nvidia => 0x10de,
            Self::Amd => 0x1002,
        }
    }

    fn synthetic_device_id(self, family: u8) -> u32 {
        match self {
            Self::Apple => 0x1000 + family as u32,
            Self::Nvidia => 0x2000 + family as u32,
            Self::Amd => 0x7000 + family as u32,
        }
    }

    fn compatibility_adapter_name(self, original: &str) -> String {
        match self {
            Self::Apple => original.to_string(),
            Self::Nvidia => format!("NVIDIA Compatibility Adapter ({original})"),
            Self::Amd => format!("AMD Compatibility Adapter ({original})"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_numerator: u32,
    pub refresh_denominator: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputInfo {
    pub id: OutputId,
    pub name: String,
    pub dpi_x: u32,
    pub dpi_y: u32,
    pub modes: Vec<DisplayMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapchainDesc {
    pub width: u32,
    pub height: u32,
    pub format: DxgiFormat,
    pub buffer_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapchainState {
    pub id: SwapchainId,
    pub desc: SwapchainDesc,
    pub backbuffers: Vec<ResourceId>,
    pub queued_frames: u32,
    pub max_frame_latency: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentResult {
    pub queued_frames: u32,
    pub effective_sync_interval: u32,
    pub tearing_allowed: bool,
    pub displayed_frame_index: u64,
    pub frame_time_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentedFrame {
    pub width: u32,
    pub height: u32,
    pub format: DxgiFormat,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeapType {
    Default,
    Upload,
    Readback,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetalStorageMode {
    Shared,
    Private,
    Memoryless,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    Common,
    Present,
    RenderTarget,
    CopySource,
    CopyDest,
    PixelShaderResource,
    UnorderedAccess,
    DepthWrite,
    GenericRead,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BufferRole {
    Generic,
    Constant,
    Vertex,
    Index,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUsageHint {
    Generic,
    SwapchainBackbuffer,
    DepthStencil,
    Buffer {
        role: BufferRole,
        cpu_write_frequent: bool,
    },
    Texture {
        sampled: bool,
        render_target: bool,
        depth_stencil: bool,
        cpu_write_frequent: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceDesc {
    pub name: String,
    pub format: DxgiFormat,
    pub heap: HeapType,
    pub size: usize,
    pub subresources: u32,
    pub initial_state: ResourceState,
    pub usage_hint: ResourceUsageHint,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorHeapType {
    CbvSrvUav,
    Sampler,
    Rtv,
    Dsv,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterMode {
    Point,
    Linear,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ViewDescriptor {
    Cbv { resource: ResourceId, size: usize },
    Srv { resource: ResourceId, format: DxgiFormat },
    Uav { resource: ResourceId, format: DxgiFormat },
    Sampler { filter: FilterMode },
    Rtv { resource: ResourceId, format: DxgiFormat },
    Dsv { resource: ResourceId, format: DxgiFormat },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetalBinding {
    pub slot: u32,
    pub kind: String,
    pub resource: Option<ResourceId>,
    pub metal_format: Option<MtlPixelFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootSignatureDesc {
    pub descriptor_tables: Vec<u32>,
    pub root_constants: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineStateDesc {
    pub label: String,
    pub compute: bool,
    pub render_target_formats: Vec<DxgiFormat>,
    pub depth_format: Option<DxgiFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryResolveResult {
    pub values: Vec<u64>,
    pub emulated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    Timestamp,
    Occlusion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Command {
    Transition {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    UavBarrier {
        resource: ResourceId,
    },
    AliasingBarrier {
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    },
    SetRootConstants {
        values: Vec<u32>,
    },
    BeginRenderPass {
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: String,
        store_action: String,
    },
    ClearRtv {
        heap: DescriptorHeapId,
        index: usize,
    },
    ClearDsv {
        heap: DescriptorHeapId,
        index: usize,
    },
    Draw {
        vertices: u32,
    },
    DrawInstanced {
        vertices: u32,
        instances: u32,
    },
    Dispatch {
        x: u32,
        y: u32,
        z: u32,
    },
    CopyResource {
        src: ResourceId,
        dst: ResourceId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImmutableCommandStream {
    pub id: CommandListId,
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderPassPlan {
    pub color_formats: Vec<MtlPixelFormat>,
    pub depth_format: Option<MtlPixelFormat>,
    pub draw_calls: u32,
    pub load_action: String,
    pub store_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetalCommandBufferPlan {
    pub render_passes: Vec<RenderPassPlan>,
    pub compute_passes: u32,
    pub blit_passes: u32,
    pub validation_errors: Vec<String>,
    pub root_constants_log: Vec<Vec<u32>>,
    pub signaled_fences: Vec<(FenceId, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SceneSpec {
    pub name: String,
    pub format: DxgiFormat,
    pub clear_color: [u8; 4],
    pub draw_calls: u32,
    pub compute_dispatches: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrameArtifact {
    pub hash: String,
    pub ssim: f32,
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct ResourceRecord {
    desc: ResourceDesc,
    states: Vec<ResourceState>,
    bytes: Vec<u8>,
    storage_mode: MetalStorageMode,
    live: bool,
}

#[derive(Debug, Clone)]
struct DescriptorHeapRecord {
    ty: DescriptorHeapType,
    descriptors: Vec<Option<ViewDescriptor>>,
}

#[derive(Debug, Clone)]
struct SwapchainRecord {
    state: SwapchainState,
    next_present_index: u64,
    presented_backbuffer_index: usize,
}

#[derive(Debug, Clone)]
struct QueryHeapRecord {
    ty: QueryType,
    values: Vec<u64>,
    emulated: bool,
}

#[derive(Debug, Clone)]
struct CommandListRecord {
    pipeline_state: PipelineStateId,
    commands: Vec<Command>,
    closed: bool,
}

#[derive(Debug, Clone)]
struct FenceRecord {
    value: u64,
}

#[derive(Debug, Clone)]
pub struct GraphicsBackend {
    next_id: u64,
    adapter: AdapterInfo,
    capabilities: MetalCapabilities,
    outputs: Vec<OutputInfo>,
    swapchains: BTreeMap<SwapchainId, SwapchainRecord>,
    resources: BTreeMap<ResourceId, ResourceRecord>,
    descriptor_heaps: BTreeMap<DescriptorHeapId, DescriptorHeapRecord>,
    command_lists: BTreeMap<CommandListId, CommandListRecord>,
    fences: BTreeMap<FenceId, FenceRecord>,
    query_heaps: BTreeMap<QueryHeapId, QueryHeapRecord>,
    root_signatures: BTreeMap<RootSignatureId, RootSignatureDesc>,
    pipeline_states: BTreeMap<PipelineStateId, PipelineStateDesc>,
    timestamps: u64,
}

impl Default for GraphicsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphicsBackend {
    pub fn new() -> Self {
        Self::with_host_profile(detected_host_gpu_profile())
    }

    pub(crate) fn with_host_profile(profile: HostGpuProfile) -> Self {
        Self {
            next_id: 1,
            adapter: profile.adapter,
            capabilities: profile.capabilities,
            outputs: vec![
                OutputInfo {
                    id: 1,
                    name: "Built-in Display".to_string(),
                    dpi_x: 144,
                    dpi_y: 144,
                    modes: vec![
                        DisplayMode {
                            width: 2560,
                            height: 1600,
                            refresh_numerator: 60000,
                            refresh_denominator: 1000,
                        },
                        DisplayMode {
                            width: 1920,
                            height: 1200,
                            refresh_numerator: 60000,
                            refresh_denominator: 1000,
                        },
                    ],
                },
                OutputInfo {
                    id: 2,
                    name: "External Display".to_string(),
                    dpi_x: 110,
                    dpi_y: 110,
                    modes: vec![
                        DisplayMode {
                            width: 3840,
                            height: 2160,
                            refresh_numerator: 120000,
                            refresh_denominator: 1000,
                        },
                        DisplayMode {
                            width: 2560,
                            height: 1440,
                            refresh_numerator: 60000,
                            refresh_denominator: 1000,
                        },
                    ],
                },
            ],
            swapchains: BTreeMap::new(),
            resources: BTreeMap::new(),
            descriptor_heaps: BTreeMap::new(),
            command_lists: BTreeMap::new(),
            fences: BTreeMap::new(),
            query_heaps: BTreeMap::new(),
            root_signatures: BTreeMap::new(),
            pipeline_states: BTreeMap::new(),
            timestamps: 1,
        }
    }

    pub fn adapter(&self) -> &AdapterInfo {
        &self.adapter
    }

    pub fn capabilities(&self) -> &MetalCapabilities {
        &self.capabilities
    }

    pub fn outputs(&self) -> &[OutputInfo] {
        &self.outputs
    }

    pub fn query_feature(&self, query: FeatureQuery) -> bool {
        match query {
            FeatureQuery::Tearing => true,
            FeatureQuery::TimestampQueries => self.capabilities.timestamp_queries,
            FeatureQuery::MeshShaders => self.capabilities.mesh_shaders,
        }
    }

    pub fn query_format_support(&self, format: DxgiFormat) -> AppResult<FormatMapping> {
        format_mapping(format)
    }

    pub fn create_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        if desc.buffer_count < 2 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "swapchain buffer count must be at least 2",
            ));
        }
        let id = self.alloc_id();
        let max_frame_latency = if self.capabilities.unified_memory { 1 } else { 3 };
        let backbuffers = (0..desc.buffer_count)
            .map(|index| {
                self.create_resource(ResourceDesc {
                    name: format!("swapchain-{id}-buffer-{index}"),
                    format: desc.format,
                    heap: HeapType::Default,
                    size: (desc.width as usize) * (desc.height as usize) * 4,
                    subresources: 1,
                    initial_state: ResourceState::Present,
                    usage_hint: ResourceUsageHint::SwapchainBackbuffer,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        self.swapchains.insert(
            id,
            SwapchainRecord {
                state: SwapchainState {
                    id,
                    desc,
                    backbuffers,
                    queued_frames: 0,
                    max_frame_latency,
                },
                next_present_index: 0,
                presented_backbuffer_index: 0,
            },
        );
        Ok(id)
    }

    pub fn set_maximum_frame_latency(&mut self, swapchain: SwapchainId, latency: u32) -> AppResult<()> {
        let record = self.swapchain_mut(swapchain)?;
        record.state.max_frame_latency = latency.max(1);
        Ok(())
    }

    pub fn swapchain_state(&self, swapchain: SwapchainId) -> AppResult<SwapchainState> {
        Ok(self.swapchain(swapchain)?.state.clone())
    }

    pub fn present(&mut self, swapchain: SwapchainId, sync_interval: u32, allow_tearing: bool) -> AppResult<PresentResult> {
        if sync_interval > 4 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported sync interval {sync_interval}"),
            ));
        }
        let tearing_allowed = allow_tearing && sync_interval == 0 && self.query_feature(FeatureQuery::Tearing);
        let record = self.swapchain_mut(swapchain)?;
        record.next_present_index += 1;
        record.presented_backbuffer_index = 0;
        record.state.queued_frames = (record.state.queued_frames + 1).min(record.state.max_frame_latency);
        Ok(PresentResult {
            queued_frames: record.state.queued_frames,
            effective_sync_interval: sync_interval,
            tearing_allowed,
            displayed_frame_index: record.next_present_index,
            frame_time_us: match sync_interval {
                0 => 5_000,
                value => 16_666 * value as u64,
            },
        })
    }

    pub fn export_presented_frame_ppm(&self, swapchain: SwapchainId, path: &Path) -> AppResult<()> {
        let bytes = self.presented_frame_ppm_bytes(swapchain)?;
        fs::write(path, bytes).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to write presented frame {}", path.display()),
                &error,
            )
        })
    }

    pub fn presented_frame(&self, swapchain: SwapchainId) -> AppResult<PresentedFrame> {
        let record = self.swapchain(swapchain)?;
        if record.state.backbuffers.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "swapchain has no backbuffers to export",
            ));
        }
        let index = record
            .presented_backbuffer_index
            .min(record.state.backbuffers.len().saturating_sub(1));
        let resource = self.resource(record.state.backbuffers[index])?;
        Ok(PresentedFrame {
            width: record.state.desc.width,
            height: record.state.desc.height,
            format: record.state.desc.format,
            bytes: resource.bytes.clone(),
        })
    }

    pub fn open_presented_frame(&self, swapchain: SwapchainId) -> AppResult<()> {
        let temp_path = std::env::temp_dir().join(format!(
            "casa1-frame-{}-{}.ppm",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        self.export_presented_frame_ppm(swapchain, &temp_path)?;
        let status = HostCommand::new("open")
            .arg(&temp_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| AppError::from_io(ReasonCode::RcIo, "failed to launch open for presented frame", &error))?;
        if !status.success() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("open failed while previewing presented frame: {status}"),
            ));
        }
        Ok(())
    }

    pub fn resize_buffers(
        &mut self,
        swapchain: SwapchainId,
        buffer_count: u32,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) -> AppResult<()> {
        let old_backbuffers = self.swapchain(swapchain)?.state.backbuffers.clone();
        for resource in old_backbuffers {
            self.destroy_resource(resource)?;
        }
        let backbuffers = (0..buffer_count)
            .map(|index| {
                self.create_resource(ResourceDesc {
                    name: format!("swapchain-{swapchain}-buffer-resized-{index}"),
                    format,
                    heap: HeapType::Default,
                    size: (width as usize) * (height as usize) * 4,
                    subresources: 1,
                    initial_state: ResourceState::Present,
                    usage_hint: ResourceUsageHint::SwapchainBackbuffer,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        let record = self.swapchain_mut(swapchain)?;
        record.state.desc = SwapchainDesc {
            width,
            height,
            format,
            buffer_count,
        };
        record.state.backbuffers = backbuffers;
        record.state.queued_frames = 0;
        record.presented_backbuffer_index = 0;
        Ok(())
    }

    pub fn create_resource(&mut self, desc: ResourceDesc) -> AppResult<ResourceId> {
        let id = self.alloc_id();
        let storage_mode = self.storage_mode_for_resource(&desc);
        self.resources.insert(
            id,
            ResourceRecord {
                states: vec![desc.initial_state; desc.subresources as usize],
                bytes: vec![0; desc.size],
                storage_mode,
                desc,
                live: true,
            },
        );
        Ok(id)
    }

    pub fn destroy_resource(&mut self, resource: ResourceId) -> AppResult<()> {
        self.resources
            .remove(&resource)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown resource"))
    }

    pub fn live_resource_count(&self) -> usize {
        self.resources.values().filter(|resource| resource.live).count()
    }

    pub fn resource_state(&self, resource: ResourceId, subresource: u32) -> AppResult<ResourceState> {
        let resource = self.resource(resource)?;
        resource
            .states
            .get(subresource as usize)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "invalid subresource index"))
    }

    pub fn transition_resource(
        &mut self,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        let resource = self.resource_mut(resource)?;
        let state = resource
            .states
            .get_mut(subresource as usize)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "invalid subresource index"))?;
        if *state != from {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("resource state mismatch: expected {from:?}, found {state:?}"),
            ));
        }
        *state = to;
        Ok(())
    }

    pub fn create_descriptor_heap(&mut self, ty: DescriptorHeapType, count: usize) -> DescriptorHeapId {
        let id = self.alloc_id();
        self.descriptor_heaps.insert(
            id,
            DescriptorHeapRecord {
                ty,
                descriptors: vec![None; count],
            },
        );
        id
    }

    pub fn write_descriptor(
        &mut self,
        heap: DescriptorHeapId,
        index: usize,
        descriptor: ViewDescriptor,
    ) -> AppResult<()> {
        self.validate_descriptor(&descriptor)?;
        let heap_record = self.descriptor_heap_mut(heap)?;
        let slot = heap_record
            .descriptors
            .get_mut(index)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "descriptor index out of range"))?;
        *slot = Some(descriptor);
        Ok(())
    }

    pub fn copy_descriptors(
        &mut self,
        src_heap: DescriptorHeapId,
        src_index: usize,
        dst_heap: DescriptorHeapId,
        dst_index: usize,
        count: usize,
    ) -> AppResult<()> {
        let source = self
            .descriptor_heap(src_heap)?
            .descriptors
            .get(src_index..src_index + count)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "source descriptor range out of bounds"))?
            .to_vec();
        let destination = self.descriptor_heap_mut(dst_heap)?;
        let slice = destination
            .descriptors
            .get_mut(dst_index..dst_index + count)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "destination descriptor range out of bounds"))?;
        slice.clone_from_slice(&source);
        Ok(())
    }

    pub fn copy_descriptors_simple(
        &mut self,
        src_heap: DescriptorHeapId,
        src_index: usize,
        dst_heap: DescriptorHeapId,
        dst_index: usize,
        count: usize,
    ) -> AppResult<()> {
        self.copy_descriptors(src_heap, src_index, dst_heap, dst_index, count)
    }

    pub fn descriptor_heap_snapshot(&self, heap: DescriptorHeapId) -> AppResult<Vec<Option<ViewDescriptor>>> {
        Ok(self.descriptor_heap(heap)?.descriptors.clone())
    }

    pub fn descriptor_heap_type(&self, heap: DescriptorHeapId) -> AppResult<DescriptorHeapType> {
        Ok(self.descriptor_heap(heap)?.ty)
    }

    pub fn translate_descriptor_heap(&self, heap: DescriptorHeapId) -> AppResult<Vec<MetalBinding>> {
        let heap_record = self.descriptor_heap(heap)?;
        Ok(heap_record
            .descriptors
            .iter()
            .enumerate()
            .filter_map(|(slot, descriptor)| descriptor.as_ref().map(|descriptor| metal_binding(slot as u32, descriptor)))
            .collect())
    }

    pub fn create_root_signature(&mut self, desc: RootSignatureDesc) -> RootSignatureId {
        let id = self.alloc_id();
        self.root_signatures.insert(id, desc);
        id
    }

    pub fn create_pipeline_state(&mut self, _root_signature: RootSignatureId, desc: PipelineStateDesc) -> PipelineStateId {
        let id = self.alloc_id();
        self.pipeline_states.insert(id, desc);
        id
    }

    pub fn create_command_queue(&mut self) -> CommandQueueId {
        self.alloc_id()
    }

    pub fn create_command_allocator(&mut self) -> CommandAllocatorId {
        self.alloc_id()
    }

    pub fn create_graphics_command_list(
        &mut self,
        _allocator: CommandAllocatorId,
        pipeline_state: PipelineStateId,
    ) -> CommandListId {
        let id = self.alloc_id();
        self.command_lists.insert(
            id,
            CommandListRecord {
                pipeline_state,
                commands: Vec::new(),
                closed: false,
            },
        );
        id
    }

    pub fn record_transition(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        self.transition_resource(resource, subresource, from, to)?;
        self.command_list_mut(list)?.commands.push(Command::Transition {
            resource,
            subresource,
            from,
            to,
        });
        Ok(())
    }

    pub fn record_uav_barrier(&mut self, list: CommandListId, resource: ResourceId) -> AppResult<()> {
        self.resource(resource)?;
        self.command_list_mut(list)?.commands.push(Command::UavBarrier { resource });
        Ok(())
    }

    pub fn record_aliasing_barrier(
        &mut self,
        list: CommandListId,
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    ) -> AppResult<()> {
        if let Some(before) = before {
            self.resource(before)?;
        }
        if let Some(after) = after {
            self.resource(after)?;
        }
        self.command_list_mut(list)?.commands.push(Command::AliasingBarrier { before, after });
        Ok(())
    }

    pub fn record_set_root_constants(&mut self, list: CommandListId, values: Vec<u32>) -> AppResult<()> {
        self.command_list_mut(list)?.commands.push(Command::SetRootConstants { values });
        Ok(())
    }

    pub fn record_begin_render_pass(
        &mut self,
        list: CommandListId,
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: &str,
        store_action: &str,
    ) -> AppResult<()> {
        self.command_list_mut(list)?.commands.push(Command::BeginRenderPass {
            color_formats,
            depth_format,
            load_action: load_action.to_string(),
            store_action: store_action.to_string(),
        });
        Ok(())
    }

    pub fn record_clear_rtv(&mut self, list: CommandListId, heap: DescriptorHeapId, index: usize) -> AppResult<()> {
        self.validate_rtv_descriptor(heap, index)?;
        self.command_list_mut(list)?.commands.push(Command::ClearRtv { heap, index });
        Ok(())
    }

    pub fn record_clear_dsv(&mut self, list: CommandListId, heap: DescriptorHeapId, index: usize) -> AppResult<()> {
        self.validate_dsv_descriptor(heap, index)?;
        self.command_list_mut(list)?.commands.push(Command::ClearDsv { heap, index });
        Ok(())
    }

    pub fn record_draw(&mut self, list: CommandListId, vertices: u32) -> AppResult<()> {
        self.command_list_mut(list)?.commands.push(Command::Draw { vertices });
        Ok(())
    }

    pub fn record_draw_instanced(
        &mut self,
        list: CommandListId,
        vertices: u32,
        instances: u32,
    ) -> AppResult<()> {
        self.command_list_mut(list)?.commands.push(Command::DrawInstanced { vertices, instances });
        Ok(())
    }

    pub fn record_dispatch(&mut self, list: CommandListId, x: u32, y: u32, z: u32) -> AppResult<()> {
        self.command_list_mut(list)?.commands.push(Command::Dispatch { x, y, z });
        Ok(())
    }

    pub fn record_copy_resource(&mut self, list: CommandListId, src: ResourceId, dst: ResourceId) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.command_list_mut(list)?.commands.push(Command::CopyResource { src, dst });
        Ok(())
    }

    pub fn close_command_list(&mut self, list: CommandListId) -> AppResult<ImmutableCommandStream> {
        let record = self.command_list_mut(list)?;
        record.closed = true;
        Ok(ImmutableCommandStream {
            id: list,
            commands: record.commands.clone(),
        })
    }

    pub fn execute_command_lists(
        &mut self,
        _queue: CommandQueueId,
        lists: &[ImmutableCommandStream],
        signal_fence: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        let mut render_passes = Vec::new();
        let mut compute_passes = 0;
        let mut blit_passes = 0;
        let mut validation_errors = Vec::new();
        let mut root_constants_log = Vec::new();
        let mut active_pass: Option<RenderPassPlan> = None;

        for stream in lists {
            let pipeline = self
                .pipeline_states
                .get(&self.command_lists.get(&stream.id).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown command list {}", stream.id))
                })?.pipeline_state)
                .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown pipeline state"))?
                .clone();
            for command in &stream.commands {
                match command {
                    Command::Transition { .. } | Command::UavBarrier { .. } | Command::AliasingBarrier { .. } => {
                        if let Some(pass) = active_pass.take() {
                            render_passes.push(pass);
                        }
                    }
                    Command::SetRootConstants { values } => {
                        if let Some(pass) = active_pass.take() {
                            render_passes.push(pass);
                        }
                        root_constants_log.push(values.clone());
                    }
                    Command::BeginRenderPass {
                        color_formats,
                        depth_format,
                        load_action,
                        store_action,
                    } => {
                        let mapped_color_formats = color_formats
                            .iter()
                            .map(|format| format_mapping(*format).map(|mapping| mapping.metal))
                            .collect::<AppResult<Vec<_>>>()?;
                        let mapped_depth_format = depth_format
                            .map(|format| format_mapping(format).map(|mapping| mapping.metal))
                            .transpose()?;
                        match &mut active_pass {
                            Some(pass)
                                if pass.color_formats == mapped_color_formats
                                    && pass.depth_format == mapped_depth_format
                                    && self.capabilities.mesh_shaders =>
                            {
                                pass.store_action = store_action.clone();
                            }
                            Some(_) => {
                                render_passes.push(active_pass.take().expect("active pass"));
                                active_pass = Some(RenderPassPlan {
                                    color_formats: mapped_color_formats,
                                    depth_format: mapped_depth_format,
                                    draw_calls: 0,
                                    load_action: load_action.clone(),
                                    store_action: store_action.clone(),
                                });
                            }
                            None => {
                                active_pass = Some(RenderPassPlan {
                                    color_formats: mapped_color_formats,
                                    depth_format: mapped_depth_format,
                                    draw_calls: 0,
                                    load_action: load_action.clone(),
                                    store_action: store_action.clone(),
                                });
                            }
                        }
                    }
                    Command::ClearRtv { heap, index } => {
                        let descriptor = self.descriptor_at(*heap, *index)?;
                        let ViewDescriptor::Rtv { format, .. } = descriptor else {
                            validation_errors.push("invalid RTV attachment".to_string());
                            continue;
                        };
                        let mapping = format_mapping(format)?;
                        let depth_format = pipeline.depth_format.map(format_mapping).transpose()?.map(|mapping| mapping.metal);
                        match &mut active_pass {
                            Some(pass) => {
                                if pass.color_formats != vec![mapping.metal] || pass.depth_format != depth_format {
                                    render_passes.push(active_pass.take().expect("active pass"));
                                    active_pass = Some(RenderPassPlan {
                                        color_formats: vec![mapping.metal],
                                        depth_format,
                                        draw_calls: 0,
                                        load_action: "clear".to_string(),
                                        store_action: "store".to_string(),
                                    });
                                } else {
                                    pass.load_action = "clear".to_string();
                                }
                            }
                            None => {
                                active_pass = Some(RenderPassPlan {
                                    color_formats: vec![mapping.metal],
                                    depth_format,
                                    draw_calls: 0,
                                    load_action: "clear".to_string(),
                                    store_action: "store".to_string(),
                                });
                            }
                        }
                    }
                    Command::ClearDsv { .. } => {}
                    Command::Draw { .. } | Command::DrawInstanced { .. } => {
                        if let Some(pass) = &mut active_pass {
                            pass.draw_calls += 1;
                        } else {
                            validation_errors.push("draw without active render pass".to_string());
                        }
                    }
                    Command::Dispatch { .. } => {
                        if let Some(pass) = active_pass.take() {
                            render_passes.push(pass);
                        }
                        compute_passes += 1;
                    }
                    Command::CopyResource { src, dst } => {
                        if let Some(pass) = active_pass.take() {
                            render_passes.push(pass);
                        }
                        blit_passes += 1;
                        let src_bytes = self.resource(*src)?.bytes.clone();
                        self.resource_mut(*dst)?.bytes = src_bytes;
                    }
                }
            }
        }
        if let Some(pass) = active_pass.take() {
            render_passes.push(pass);
        }

        let mut signaled_fences = Vec::new();
        if let Some((fence, value)) = signal_fence {
            self.signal_fence(fence, value)?;
            signaled_fences.push((fence, value));
        }

        Ok(MetalCommandBufferPlan {
            render_passes,
            compute_passes,
            blit_passes,
            validation_errors,
            root_constants_log,
            signaled_fences,
        })
    }

    pub fn create_fence(&mut self, initial_value: u64) -> FenceId {
        let id = self.alloc_id();
        self.fences.insert(id, FenceRecord { value: initial_value });
        id
    }

    pub fn signal_fence(&mut self, fence: FenceId, value: u64) -> AppResult<()> {
        self.fence_mut(fence)?.value = value;
        Ok(())
    }

    pub fn fence_value(&self, fence: FenceId) -> AppResult<u64> {
        Ok(self.fence(fence)?.value)
    }

    pub fn upload_write(&mut self, resource: ResourceId, offset: usize, bytes: &[u8]) -> AppResult<()> {
        let resource = self.resource_mut(resource)?;
        if resource.desc.heap != HeapType::Upload {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource is not in an upload heap",
            ));
        }
        let end = offset + bytes.len();
        if end > resource.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "upload write out of bounds",
            ));
        }
        resource.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn overwrite_resource_bytes(&mut self, resource: ResourceId, bytes: &[u8]) -> AppResult<()> {
        let resource = self.resource_mut(resource)?;
        if bytes.len() > resource.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource write out of bounds",
            ));
        }
        resource.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn readback(&self, resource: ResourceId, fence: FenceId, required_value: u64) -> AppResult<Vec<u8>> {
        let resource = self.resource(resource)?;
        if resource.desc.heap != HeapType::Readback {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource is not in a readback heap",
            ));
        }
        if self.fence(fence)?.value < required_value {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "readback requires a completed fence",
            ));
        }
        Ok(resource.bytes.clone())
    }

    pub fn resource_storage_mode(&self, resource: ResourceId) -> AppResult<MetalStorageMode> {
        Ok(self.resource(resource)?.storage_mode)
    }

    pub fn set_resource_usage_hint(
        &mut self,
        resource: ResourceId,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<()> {
        let mut desc = self.resource(resource)?.desc.clone();
        desc.usage_hint = usage_hint;
        let storage_mode = self.storage_mode_for_resource(&desc);
        let record = self.resource_mut(resource)?;
        record.desc = desc;
        record.storage_mode = storage_mode;
        Ok(())
    }

    pub fn create_query_heap(&mut self, ty: QueryType, count: usize) -> QueryHeapId {
        let id = self.alloc_id();
        self.query_heaps.insert(
            id,
            QueryHeapRecord {
                ty,
                values: vec![0; count],
                emulated: ty == QueryType::Timestamp,
            },
        );
        id
    }

    pub fn write_timestamp(&mut self, heap: QueryHeapId, index: usize) -> AppResult<u64> {
        let value = self.timestamps * 1_000;
        self.timestamps += 1;
        let query_heap = self.query_heap_mut(heap)?;
        if query_heap.ty != QueryType::Timestamp {
            return Err(AppError::new(ReasonCode::RcD3dInvalidState, "query heap is not a timestamp heap"));
        }
        let slot = query_heap
            .values
            .get_mut(index)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "query index out of bounds"))?;
        *slot = value;
        Ok(value)
    }

    pub fn write_occlusion(&mut self, heap: QueryHeapId, index: usize, samples: u64) -> AppResult<()> {
        let query_heap = self.query_heap_mut(heap)?;
        if query_heap.ty != QueryType::Occlusion {
            return Err(AppError::new(ReasonCode::RcD3dInvalidState, "query heap is not an occlusion heap"));
        }
        let slot = query_heap
            .values
            .get_mut(index)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "query index out of bounds"))?;
        *slot = samples;
        Ok(())
    }

    pub fn resolve_query_data(&self, heap: QueryHeapId) -> AppResult<QueryResolveResult> {
        let query_heap = self.query_heap(heap)?;
        Ok(QueryResolveResult {
            values: query_heap.values.clone(),
            emulated: query_heap.emulated,
        })
    }

    pub fn render_scene(&self, scene: &SceneSpec) -> AppResult<FrameArtifact> {
        let mapping = format_mapping(scene.format)?;
        let signature = format!(
            "{}|{:?}|{:02x}{:02x}{:02x}{:02x}|{}|{}|{:?}",
            scene.name,
            scene.format,
            scene.clear_color[0],
            scene.clear_color[1],
            scene.clear_color[2],
            scene.clear_color[3],
            scene.draw_calls,
            scene.compute_dispatches,
            mapping.strategy,
        );
        Ok(FrameArtifact {
            hash: util::sha256_bytes(signature.as_bytes()),
            ssim: 1.0,
            validation_errors: Vec::new(),
        })
    }

    fn validate_descriptor(&self, descriptor: &ViewDescriptor) -> AppResult<()> {
        match descriptor {
            ViewDescriptor::Cbv { resource, .. } => {
                self.resource(*resource)?;
            }
            ViewDescriptor::Srv { resource, format }
            | ViewDescriptor::Uav { resource, format }
            | ViewDescriptor::Rtv { resource, format }
            | ViewDescriptor::Dsv { resource, format } => {
                let resource = self.resource(*resource)?;
                validate_view_format(resource.desc.format, *format, descriptor)?;
            }
            ViewDescriptor::Sampler { .. } => {}
        }
        Ok(())
    }

    fn validate_rtv_descriptor(&self, heap: DescriptorHeapId, index: usize) -> AppResult<()> {
        match self.descriptor_at(heap, index)? {
            ViewDescriptor::Rtv { .. } => Ok(()),
            _ => Err(AppError::new(ReasonCode::RcD3dInvalidState, "descriptor is not an RTV")),
        }
    }

    fn validate_dsv_descriptor(&self, heap: DescriptorHeapId, index: usize) -> AppResult<()> {
        match self.descriptor_at(heap, index)? {
            ViewDescriptor::Dsv { .. } => Ok(()),
            _ => Err(AppError::new(ReasonCode::RcD3dInvalidState, "descriptor is not a DSV")),
        }
    }

    fn descriptor_at(&self, heap: DescriptorHeapId, index: usize) -> AppResult<ViewDescriptor> {
        self.descriptor_heap(heap)?
            .descriptors
            .get(index)
            .and_then(Clone::clone)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "descriptor slot is empty"))
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn storage_mode_for_resource(&self, desc: &ResourceDesc) -> MetalStorageMode {
        if self.capabilities.memoryless_render_targets
            && desc.heap == HeapType::Default
            && desc.format == DxgiFormat::D24UnormS8Uint
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::DepthStencil
                    | ResourceUsageHint::Texture {
                        depth_stencil: true,
                        ..
                    }
            )
        {
            return MetalStorageMode::Memoryless;
        }

        if self.capabilities.unified_memory
            && desc.heap == HeapType::Default
            && desc.format == DxgiFormat::R32Float
            && desc.subresources == 1
            && desc.size <= 64 * 1024
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::Buffer {
                    cpu_write_frequent: true,
                    ..
                }
            )
        {
            return MetalStorageMode::Shared;
        }

        if self.capabilities.unified_memory
            && desc.heap == HeapType::Default
            && desc.subresources == 1
            && desc.size <= 256 * 1024
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: false,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                }
            )
        {
            return MetalStorageMode::Shared;
        }

        match desc.heap {
            HeapType::Upload | HeapType::Readback => MetalStorageMode::Shared,
            HeapType::Default => MetalStorageMode::Private,
        }
    }

    fn swapchain(&self, swapchain: SwapchainId) -> AppResult<&SwapchainRecord> {
        self.swapchains.get(&swapchain).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown swapchain {swapchain}"))
        })
    }

    fn swapchain_mut(&mut self, swapchain: SwapchainId) -> AppResult<&mut SwapchainRecord> {
        self.swapchains.get_mut(&swapchain).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown swapchain {swapchain}"))
        })
    }

    fn resource(&self, resource: ResourceId) -> AppResult<&ResourceRecord> {
        self.resources.get(&resource).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown resource {resource}"))
        })
    }

    fn resource_mut(&mut self, resource: ResourceId) -> AppResult<&mut ResourceRecord> {
        self.resources.get_mut(&resource).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown resource {resource}"))
        })
    }

    fn descriptor_heap(&self, heap: DescriptorHeapId) -> AppResult<&DescriptorHeapRecord> {
        self.descriptor_heaps.get(&heap).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown descriptor heap {heap}"))
        })
    }

    fn descriptor_heap_mut(&mut self, heap: DescriptorHeapId) -> AppResult<&mut DescriptorHeapRecord> {
        self.descriptor_heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown descriptor heap {heap}"))
        })
    }

    fn command_list_mut(&mut self, list: CommandListId) -> AppResult<&mut CommandListRecord> {
        self.command_lists.get_mut(&list).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown command list {list}"))
        })
    }

    fn fence(&self, fence: FenceId) -> AppResult<&FenceRecord> {
        self.fences.get(&fence).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown fence {fence}"))
        })
    }

    fn fence_mut(&mut self, fence: FenceId) -> AppResult<&mut FenceRecord> {
        self.fences.get_mut(&fence).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown fence {fence}"))
        })
    }

    fn query_heap(&self, heap: QueryHeapId) -> AppResult<&QueryHeapRecord> {
        self.query_heaps.get(&heap).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown query heap {heap}"))
        })
    }

    fn query_heap_mut(&mut self, heap: QueryHeapId) -> AppResult<&mut QueryHeapRecord> {
        self.query_heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown query heap {heap}"))
        })
    }

    fn presented_frame_ppm_bytes(&self, swapchain: SwapchainId) -> AppResult<Vec<u8>> {
        let frame = self.presented_frame(swapchain)?;
        encode_ppm(frame.width, frame.height, frame.format, &frame.bytes)
    }
}

fn encode_ppm(width: u32, height: u32, format: DxgiFormat, bytes: &[u8]) -> AppResult<Vec<u8>> {
    let pixel_count = width as usize * height as usize;
    let expected_bytes = pixel_count.checked_mul(4).ok_or_else(|| {
        AppError::new(ReasonCode::RcD3dInvalidState, "frame dimensions overflow")
    })?;
    if bytes.len() < expected_bytes {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("frame buffer is too small for {width}x{height} {format:?}"),
        ));
    }
    let mut ppm = format!("P6\n{width} {height}\n255\n").into_bytes();
    ppm.reserve(pixel_count * 3);
    match format {
        DxgiFormat::R8G8B8A8Unorm | DxgiFormat::R8G8B8A8UnormSrgb => {
            for chunk in bytes[..expected_bytes].chunks_exact(4) {
                ppm.extend_from_slice(&chunk[..3]);
            }
        }
        DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm => {
            for chunk in bytes[..expected_bytes].chunks_exact(4) {
                ppm.extend_from_slice(&[chunk[2], chunk[1], chunk[0]]);
            }
        }
        other => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("frame export does not support {other:?}"),
            ))
        }
    }
    Ok(ppm)
}

pub fn format_mapping(format: DxgiFormat) -> AppResult<FormatMapping> {
    Ok(match format {
        DxgiFormat::R8G8B8A8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8G8B8A8UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba8UnormSrgb,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8G8B8A8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba8Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::B8G8R8A8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bgra8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::B8G8R8A8UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bgra8UnormSrgb,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::B8G8R8X8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bgra8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R8Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Snorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Snorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R32Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32Sint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R32Sint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R10G10B10A2Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgb10A2Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R10G10B10A2Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgb10A2Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R11G11B10Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg11B10Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Snorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Snorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg32Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16B16A16Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba16Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16B16A16Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba16Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16B16A16Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba16Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32B32A32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32B32A32Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba32Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::D24UnormS8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Depth24UnormStencil8,
            strategy: EmulationStrategy::DepthStencilEmulation,
        },
        DxgiFormat::D32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Depth32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::D32FloatS8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Depth32FloatStencil8,
            strategy: EmulationStrategy::DepthStencilEmulation,
        },
        DxgiFormat::Bc1Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc1Rgba,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc1UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc1RgbaSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc2Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc2Rgba,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc2UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc2RgbaSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc3Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc3Rgba,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc3UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc3RgbaSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc4Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc4RUnorm,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc5Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc5RgUnorm,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc7Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc7RgbaUnorm,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc7UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc7RgbaUnormSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::B5G6R5Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::B5G6R5Unorm,
            strategy: EmulationStrategy::Swizzle,
        },
    })
}

fn metal_binding(slot: u32, descriptor: &ViewDescriptor) -> MetalBinding {
    match descriptor {
        ViewDescriptor::Cbv { resource, .. } => MetalBinding {
            slot,
            kind: "cbv".to_string(),
            resource: Some(*resource),
            metal_format: None,
        },
        ViewDescriptor::Srv { resource, format } => MetalBinding {
            slot,
            kind: "srv".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
        ViewDescriptor::Uav { resource, format } => MetalBinding {
            slot,
            kind: "uav".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
        ViewDescriptor::Sampler { .. } => MetalBinding {
            slot,
            kind: "sampler".to_string(),
            resource: None,
            metal_format: None,
        },
        ViewDescriptor::Rtv { resource, format } => MetalBinding {
            slot,
            kind: "rtv".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
        ViewDescriptor::Dsv { resource, format } => MetalBinding {
            slot,
            kind: "dsv".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
    }
}

fn validate_view_format(resource_format: DxgiFormat, requested_format: DxgiFormat, descriptor: &ViewDescriptor) -> AppResult<()> {
    match descriptor {
        ViewDescriptor::Dsv { .. } => {
            if !matches!(resource_format, DxgiFormat::D24UnormS8Uint) || requested_format != resource_format {
                return Err(AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    "invalid depth/stencil view reinterpretation",
                ));
            }
        }
        ViewDescriptor::Rtv { .. } => {
            if resource_format == DxgiFormat::D24UnormS8Uint || requested_format != resource_format {
                return Err(AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    "invalid render-target view reinterpretation",
                ));
            }
        }
        ViewDescriptor::Srv { .. } | ViewDescriptor::Uav { .. } => {
            if requested_format != resource_format && resource_format != DxgiFormat::B5G6R5Unorm {
                return Err(AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    "invalid shader-resource/UAV view reinterpretation",
                ));
            }
        }
        ViewDescriptor::Cbv { .. } | ViewDescriptor::Sampler { .. } => {}
    }
    Ok(())
}

pub fn detected_host_gpu_profile() -> HostGpuProfile {
    static HOST_GPU_PROFILE: OnceLock<HostGpuProfile> = OnceLock::new();
    HOST_GPU_PROFILE.get_or_init(detect_host_gpu_profile).clone()
}

fn detect_host_gpu_profile() -> HostGpuProfile {
    let profile = {
    #[cfg(target_os = "macos")]
    {
        if let Some(chip_name) = detect_macos_apple_chip_name() {
            host_gpu_profile_from_name(&chip_name)
        } else {
            host_gpu_profile_from_name("Apple GPU")
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        host_gpu_profile_from_name("Apple GPU")
    }
    };
    match reported_gpu_vendor_override() {
        Some(vendor) => apply_reported_gpu_vendor_compatibility(profile, vendor),
        None => profile,
    }
}

pub(crate) fn host_gpu_profile_from_name(name: &str) -> HostGpuProfile {
    let normalized = normalize_gpu_name(name);
    let family = metal_family_for_gpu_name(&normalized).unwrap_or(8);
    let vendor = reported_gpu_vendor_for_name(&normalized);
    HostGpuProfile {
        adapter: AdapterInfo {
            id: 1,
            vendor_id: vendor.vendor_id(),
            device_id: vendor.synthetic_device_id(family),
            name: normalized.clone(),
            metal_family: format!("apple{family}"),
        },
        capabilities: MetalCapabilities {
            unified_memory: normalized.starts_with("Apple "),
            argument_buffers: true,
            memoryless_render_targets: normalized.starts_with("Apple "),
            timestamp_queries: true,
            mesh_shaders: family >= 9,
        },
    }
}

fn reported_gpu_vendor_for_name(name: &str) -> ReportedGpuVendor {
    let upper = name.to_ascii_uppercase();
    if upper.contains("NVIDIA") || upper.contains("GEFORCE") || upper.contains("QUADRO") || upper.contains("RTX") || upper.contains("GTX") {
        ReportedGpuVendor::Nvidia
    } else if upper.starts_with("AMD ") || upper.contains("RADEON") {
        ReportedGpuVendor::Amd
    } else {
        ReportedGpuVendor::Apple
    }
}

fn reported_gpu_vendor_override() -> Option<ReportedGpuVendor> {
    let value = std::env::var(GPU_COMPAT_VENDOR_ENV).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" | "" => None,
        "apple" => Some(ReportedGpuVendor::Apple),
        "nvidia" | "geforce" => Some(ReportedGpuVendor::Nvidia),
        "amd" | "radeon" => Some(ReportedGpuVendor::Amd),
        _ => None,
    }
}

fn apply_reported_gpu_vendor_compatibility(
    mut profile: HostGpuProfile,
    vendor: ReportedGpuVendor,
) -> HostGpuProfile {
    let family = profile
        .adapter
        .metal_family
        .strip_prefix("apple")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(8);
    profile.adapter.vendor_id = vendor.vendor_id();
    profile.adapter.device_id = vendor.synthetic_device_id(family);
    if vendor != ReportedGpuVendor::Apple && profile.adapter.name.starts_with("Apple ") {
        profile.adapter.name = vendor.compatibility_adapter_name(&profile.adapter.name);
    }
    profile
}

fn normalize_gpu_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        "Apple GPU".to_string()
    } else {
        trimmed.to_string()
    }
}

fn metal_family_for_gpu_name(name: &str) -> Option<u8> {
    let upper = name.to_ascii_uppercase();
    if !upper.starts_with("APPLE ") {
        return None;
    }
    let generation = upper
        .split_whitespace()
        .find_map(|part| part.strip_prefix('M'))
        .and_then(|digits| digits.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>().parse::<u8>().ok());
    generation.map(|generation| generation.saturating_add(6)).or(Some(8))
}

#[cfg(target_os = "macos")]
fn detect_macos_apple_chip_name() -> Option<String> {
    read_command_output("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])
        .filter(|value| value.starts_with("Apple "))
        .or_else(|| system_profiler_value("SPHardwareDataType", &["chip_type"]))
        .or_else(|| system_profiler_value("SPDisplaysDataType", &["sppci_model", "chipset_model"]))
        .filter(|value| value.starts_with("Apple "))
}

#[cfg(target_os = "macos")]
fn system_profiler_value(data_type: &str, keys: &[&str]) -> Option<String> {
    let output = HostCommand::new("/usr/sbin/system_profiler")
        .arg(data_type)
        .arg("-json")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let json = serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()?;
    let entries = json.get(data_type)?.as_array()?;
    for entry in entries {
        for key in keys {
            let value = entry.get(*key)?.as_str()?.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = HostCommand::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_m_series_profiles_map_to_expected_metal_families() {
        let m1 = host_gpu_profile_from_name("Apple M1 Max");
        assert_eq!(m1.adapter.name, "Apple M1 Max");
        assert_eq!(m1.adapter.vendor_id, 0x106b);
        assert_eq!(m1.adapter.metal_family, "apple7");
        assert!(m1.capabilities.unified_memory);
        assert!(m1.capabilities.argument_buffers);
        assert!(m1.capabilities.memoryless_render_targets);
        assert!(!m1.capabilities.mesh_shaders);

        let m3 = host_gpu_profile_from_name("Apple M3 Pro");
        assert_eq!(m3.adapter.metal_family, "apple9");
        assert!(m3.capabilities.mesh_shaders);

        let m4 = host_gpu_profile_from_name("Apple M4 Max");
        assert_eq!(m4.adapter.metal_family, "apple10");
        assert!(m4.capabilities.mesh_shaders);

        let m5 = host_gpu_profile_from_name("Apple M5 Pro");
        assert_eq!(m5.adapter.metal_family, "apple11");
        assert!(m5.capabilities.mesh_shaders);
    }

    #[test]
    fn nvidia_and_amd_profiles_report_vendor_compatible_adapter_ids() {
        let nvidia = host_gpu_profile_from_name("NVIDIA GeForce RTX 4080");
        assert_eq!(nvidia.adapter.vendor_id, 0x10de);
        assert_eq!(nvidia.adapter.device_id, 0x2008);
        assert_eq!(nvidia.adapter.name, "NVIDIA GeForce RTX 4080");
        assert_eq!(nvidia.adapter.metal_family, "apple8");
        assert!(!nvidia.capabilities.unified_memory);
        assert!(!nvidia.capabilities.memoryless_render_targets);

        let amd = host_gpu_profile_from_name("AMD Radeon RX 7900 XTX");
        assert_eq!(amd.adapter.vendor_id, 0x1002);
        assert_eq!(amd.adapter.device_id, 0x7008);
        assert_eq!(amd.adapter.name, "AMD Radeon RX 7900 XTX");
        assert_eq!(amd.adapter.metal_family, "apple8");
        assert!(!amd.capabilities.unified_memory);
        assert!(!amd.capabilities.memoryless_render_targets);
    }

    #[test]
    fn reported_vendor_compatibility_override_preserves_underlying_metal_capabilities() {
        let apple = host_gpu_profile_from_name("Apple M3 Pro");
        let nvidia = apply_reported_gpu_vendor_compatibility(apple.clone(), ReportedGpuVendor::Nvidia);
        let amd = apply_reported_gpu_vendor_compatibility(apple.clone(), ReportedGpuVendor::Amd);

        assert_eq!(nvidia.adapter.vendor_id, 0x10de);
        assert_eq!(nvidia.adapter.device_id, 0x2009);
        assert_eq!(nvidia.adapter.name, "NVIDIA Compatibility Adapter (Apple M3 Pro)");
        assert_eq!(nvidia.adapter.metal_family, "apple9");
        assert_eq!(nvidia.capabilities, apple.capabilities);

        assert_eq!(amd.adapter.vendor_id, 0x1002);
        assert_eq!(amd.adapter.device_id, 0x7009);
        assert_eq!(amd.adapter.name, "AMD Compatibility Adapter (Apple M3 Pro)");
        assert_eq!(amd.adapter.metal_family, "apple9");
        assert_eq!(amd.capabilities, apple.capabilities);
    }

    #[test]
    fn graphics_backend_uses_capability_profile_for_features_and_storage_modes() {
        let mut backend = GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Ultra"));

        assert_eq!(backend.adapter().name, "Apple M3 Ultra");
        assert_eq!(backend.adapter().metal_family, "apple9");
        assert!(backend.query_feature(FeatureQuery::TimestampQueries));
        assert!(backend.query_feature(FeatureQuery::MeshShaders));

        let upload = backend
            .create_resource(ResourceDesc {
                name: "upload".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Upload,
                size: 256,
                subresources: 1,
                initial_state: ResourceState::GenericRead,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create upload resource");
        assert_eq!(
            backend.resource_storage_mode(upload).expect("upload storage mode"),
            MetalStorageMode::Shared
        );

        let depth = backend
            .create_resource(ResourceDesc {
                name: "depth".to_string(),
                format: DxgiFormat::D24UnormS8Uint,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::DepthWrite,
                usage_hint: ResourceUsageHint::DepthStencil,
            })
            .expect("create depth resource");
        assert_eq!(
            backend.resource_storage_mode(depth).expect("depth storage mode"),
            MetalStorageMode::Memoryless
        );
    }

    #[test]
    fn graphics_backend_prefers_shared_storage_for_small_dynamic_buffers_on_unified_memory_apple_gpus() {
        let mut backend = GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M5 Pro"));

        let small_dynamic_buffer = backend
            .create_resource(ResourceDesc {
                name: "small-dynamic-vertex-buffer".to_string(),
                format: DxgiFormat::R32Float,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("create small dynamic vertex buffer");
        assert_eq!(
            backend
                .resource_storage_mode(small_dynamic_buffer)
                .expect("small dynamic buffer storage mode"),
            MetalStorageMode::Shared
        );

        let small_static_buffer = backend
            .create_resource(ResourceDesc {
                name: "small-static-vertex-buffer".to_string(),
                format: DxgiFormat::R32Float,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: false,
                },
            })
            .expect("create small static vertex buffer");
        assert_eq!(
            backend
                .resource_storage_mode(small_static_buffer)
                .expect("small static buffer storage mode"),
            MetalStorageMode::Private
        );

        let large_dynamic_buffer = backend
            .create_resource(ResourceDesc {
                name: "large-dynamic-vertex-buffer".to_string(),
                format: DxgiFormat::R32Float,
                heap: HeapType::Default,
                size: 256 * 1024,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("create large dynamic vertex buffer");
        assert_eq!(
            backend
                .resource_storage_mode(large_dynamic_buffer)
                .expect("large dynamic buffer storage mode"),
            MetalStorageMode::Private
        );

        let streamed_texture = backend
            .create_resource(ResourceDesc {
                name: "streamed-texture".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 128 * 128 * 4,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: false,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("create streamed texture");
        assert_eq!(
            backend
                .resource_storage_mode(streamed_texture)
                .expect("streamed texture storage mode"),
            MetalStorageMode::Shared
        );

        let render_target_texture = backend
            .create_resource(ResourceDesc {
                name: "render-target-texture".to_string(),
                format: DxgiFormat::B8G8R8A8Unorm,
                heap: HeapType::Default,
                size: 128 * 128 * 4,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: false,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("create render target texture");
        assert_eq!(
            backend
                .resource_storage_mode(render_target_texture)
                .expect("render target texture storage mode"),
            MetalStorageMode::Private
        );
    }

    #[test]
    fn graphics_backend_uses_low_latency_swapchain_defaults_on_apple_silicon() {
        let mut backend = GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M5 Pro"));

        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 1920,
                height: 1080,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");

        let state = backend.swapchain_state(swapchain).expect("swapchain state");

        assert_eq!(state.max_frame_latency, 1);
    }

    #[test]
    fn graphics_backend_preserves_deeper_swapchain_latency_for_non_unified_profiles() {
        let mut backend = GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Generic Discrete GPU"));

        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 1280,
                height: 720,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");

        let state = backend.swapchain_state(swapchain).expect("swapchain state");

        assert_eq!(state.max_frame_latency, 3);
    }
}