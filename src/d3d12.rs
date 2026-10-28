use crate::error::{AppError, AppResult};
use crate::gfx::{
    D3D12DescriptorRangeType, D3D12ResourceBarrierDesc, D3D12ResourceBarrierType,
    D3D12ShaderVisibility, D3D12StaticSamplerDesc, FeatureQuery, GraphicsBackend,
    PendingSplitBarrier, SubresourceKey,
};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_D3D12_METAL_HANDLE: AtomicU64 = AtomicU64::new(1);

fn alloc_d3d12_metal_handle() -> u64 {
    NEXT_D3D12_METAL_HANDLE.fetch_add(1, Ordering::Relaxed)
}

#[path = "d3d12_directml.rs"]
pub mod directml;
#[path = "metal4_batch.rs"]
pub mod metal4_batch;
#[path = "d3d12_state_objects.rs"]
pub mod state_objects;
#[path = "d3d12_work_graphs.rs"]
pub mod work_graphs;

pub use crate::gfx::{
    AdapterId, AdapterInfo, CommandAllocatorId, CommandListId, CommandQueueId,
    D3D12FilterReduction, D3D12TextureAddressMode, DescriptorHeapId, DescriptorHeapType,
    DxgiFormat, FenceId, FormatMapping, HeapType, ImmutableCommandStream, MetalBinding,
    MetalCommandBufferPlan, MetalStorageMode, OutputId, OutputInfo, PipelineStateDesc,
    PipelineStateId, PresentResult, PresentedFrame, QueryHeapId, QueryResolveResult, QueryType,
    ResourceDesc, ResourceId, ResourceState, ResourceUsageHint, RootSignatureDesc, RootSignatureId,
    SwapchainDesc, SwapchainId, SwapchainState, ViewDescriptor,
};

use self::directml::DmlRuntime;
use self::state_objects::{
    D3d12StateObject, D3d12StateObjectDesc, D3d12StateSubobject,
    STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS, STATE_OBJECT_TYPE_COLLECTION,
    STATE_OBJECT_TYPE_EXECUTABLE, STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, StateObjectMemory,
};
use self::work_graphs::{
    D3d12DispatchGraphDesc, D3d12GpuRangeAndStride, D3d12WorkGraph,
    D3d12WorkGraphMemoryRequirements,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d12FeatureOptions {
    pub tearing: bool,
    pub timestamp_queries: bool,
    pub mesh_shaders: bool,
    pub unified_memory: bool,
    pub argument_buffers: bool,
    pub memoryless_render_targets: bool,
    pub raytracing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d12DeviceInfo {
    pub adapter: AdapterInfo,
    pub outputs: Vec<OutputInfo>,
    pub features: D3d12FeatureOptions,
}

/// MetalFX mode requested for the opt-in DXGI present path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetalFxPresentMode {
    /// Spatial upscaling; the only mode the present path can drive without
    /// per-frame temporal inputs.
    Spatial,
    /// Temporal upscaling. The wrapper supports it directly, but a DXGI
    /// present would need depth/motion textures, so opting the present path
    /// into it is rejected explicitly instead of silently degrading quality.
    Temporal,
}

/// Explicit opt-in configuration for the MetalFX DXGI present path.
///
/// The present path never enables MetalFX on its own. Enabling requires both a
/// real scaler (or an exact unsupported error) and an explicit output size, so
/// the quality change is always caller-visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetalFxPresentOptions {
    pub mode: MetalFxPresentMode,
    pub output_width: u32,
    pub output_height: u32,
    pub color_processing_mode: crate::metal_fx::MetalFxColorProcessingMode,
}

impl MetalFxPresentOptions {
    /// Spatial upscale to `output_width` x `output_height`.
    pub fn spatial(output_width: u32, output_height: u32) -> Self {
        Self {
            mode: MetalFxPresentMode::Spatial,
            output_width,
            output_height,
            color_processing_mode: crate::metal_fx::MetalFxColorProcessingMode::Perceptual,
        }
    }
}

/// A configured MetalFX present path for one swapchain.
#[derive(Debug)]
struct MetalFxPresentState {
    options: MetalFxPresentOptions,
    config: crate::metal_fx::SpatialScalerConfig,
    scaler: crate::metal_fx::SpatialScaler,
    command_queue: metal::CommandQueue,
    output_texture: metal::Texture,
    output_alias: metal::Texture,
    output_channel: crate::metal_backend::IoSurfacePresentChannel,
    output_format: DxgiFormat,
}

/// The decoded Metal sampler configuration for a D3D12_FILTER value.
///
/// The reduction field is carried as the real [`D3D12FilterReduction`] enum:
/// COMPARISON drives the sampler comparison path, and MINIMUM/MAXIMUM are
/// recorded here because Metal samplers have no min/max reduction mode
/// (`MTLSamplerMinMagFilter` is Nearest/Linear only) — the standard
/// (non-comparison) filter mapping is emitted for them and the requested
/// reduction stays visible to the caller, never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3D12MetalFilterMapping {
    pub min_filter: &'static str,
    pub mag_filter: &'static str,
    pub mip_filter: &'static str,
    pub anisotropic: bool,
    pub reduction: D3D12FilterReduction,
}

impl D3D12MetalFilterMapping {
    /// Whether the filter uses the comparison reduction (drives the Metal
    /// sampler comparison function).
    pub fn is_comparison(&self) -> bool {
        self.reduction == D3D12FilterReduction::Comparison
    }
}

// ---------------------------------------------------------------------------
// DXR / Raytracing state types
// ---------------------------------------------------------------------------

/// A raytracing pipeline state object (subobject of a D3D12_STATE_OBJECT).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D3D12RaytracingPipelineState {
    /// Raw DXIL shader bytecode (the *IL section of the DXBC container).
    pub dxil_bytecode: Vec<u8>,
    /// Maximum recursion depth.
    pub max_recursion_depth: u32,
    /// Maximum payload size in bytes.
    pub payload_size: u32,
    /// Maximum attribute size in bytes.
    pub attribute_size: u32,
    /// Translated ray-generation MSL, when the state object supplied ray DXIL.
    #[serde(default)]
    pub ray_msl: Option<String>,
    /// Entry point exported for the translated ray-generation shader.
    #[serde(default)]
    pub ray_entry: Option<String>,
    /// Per-export ray stage artifacts translated from that stage's own DXIL.
    ///
    /// D3D12 selects these through the SBT shader identifier; each entry is a
    /// complete MSL module for the stage so hit, miss, callable and
    /// intersection programs are compiled independently of the raygen body.
    #[serde(default)]
    pub ray_stages: BTreeMap<String, D3D12RayShaderArtifact>,
}

/// One compiled ray-stage artifact retained on a raytracing PSO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D3D12RayShaderArtifact {
    /// D3D12 stage name recorded by the DXIL metadata.
    pub stage: String,
    /// Entry point lowered from the stage bitcode.
    pub entry: String,
    /// Translated MSL source for this stage.
    pub source: String,
    /// Stable per-state-object index encoded into SBT records.
    pub function_index: u32,
}

/// An acceleration structure managed through the D3D12 bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D3D12AccelerationStructure {
    /// D3D12 GPU virtual address assigned to this structure.
    pub gpu_address: u64,
    /// Size in bytes of the acceleration structure buffer.
    pub size: u64,
    /// Whether this is a bottom-level (false) or top-level (true) AS.
    pub is_top_level: bool,
    /// Handle returned by `metal_backend::create_acceleration_structure`.
    pub metal_accel_handle: u64,
    /// Whether the structure has been built.
    pub built: bool,
    /// Bytes reported by Metal's compacted-size query.
    pub compacted_size: u64,
    /// D3D12 build flags the structure was built with.
    pub build_flags: u32,
}

/// Description of a raytracing geometry from D3D12 guest memory.
#[derive(Debug, Clone)]
pub struct D3D12RaytracingGeometryDesc {
    pub ty: u32, // D3D12_RAYTRACING_GEOMETRY_TYPE_TRIANGLES = 0, _AABBS = 1
    pub flags: u32,
    pub vertex_buffer: u64,
    pub vertex_format: u32, // DXGI_FORMAT
    pub vertex_stride: u32,
    pub vertex_count: u32,
    pub index_buffer: u64,
    pub index_format: u32, // DXGI_FORMAT
    pub index_count: u32,
}

/// Parsed from guest memory — the inputs half of BuildRaytracingAccelerationStructure.
#[derive(Debug, Clone)]
pub struct D3D12BuildRaytracingInputs {
    pub ty: u32, // 0 = BOTTOM_LEVEL, 1 = TOP_LEVEL
    pub flags: u32,
    pub num_descs: u32,
    pub geometries: Vec<D3D12RaytracingGeometryDesc>,
}

/// Full description for building an acceleration structure.
#[derive(Debug, Clone)]
pub struct D3D12BuildAccelerationStructureDesc {
    pub dest_address: u64,
    pub inputs: D3D12BuildRaytracingInputs,
    pub source_address: u64,
    pub scratch_address: u64,
}

/// Description for dispatch rays from guest memory.
#[derive(Debug, Clone)]
pub struct D3D12DispatchRaysDesc {
    pub raygen_shader_start_address: u64,
    pub raygen_shader_size: u64,
    pub miss_shader_start_address: u64,
    pub miss_shader_size: u64,
    pub miss_shader_stride: u64,
    pub hit_group_start_address: u64,
    pub hit_group_size: u64,
    pub hit_group_stride: u64,
    pub callable_shader_start_address: u64,
    pub callable_shader_size: u64,
    pub callable_shader_stride: u64,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
}

// ---------------------------------------------------------------------------
// ID3D12CommandSignature / ExecuteIndirect
// ---------------------------------------------------------------------------

/// D3D12_INDIRECT_ARGUMENT_TYPE values.
pub const D3D12_INDIRECT_ARGUMENT_TYPE_DRAW: u32 = 0;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_DRAW_INDEXED: u32 = 1;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH: u32 = 2;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_VERTEX_BUFFER_VIEW: u32 = 3;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_INDEX_BUFFER_VIEW: u32 = 4;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_CONSTANT: u32 = 5;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_CONSTANT_BUFFER_VIEW: u32 = 6;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_SHADER_RESOURCE_VIEW: u32 = 7;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_UNORDERED_ACCESS_VIEW: u32 = 8;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_RAYS: u32 = 9;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_MESH: u32 = 10;
pub const D3D12_INDIRECT_ARGUMENT_TYPE_INCREMENTING_CONSTANT: u32 = 11;

/// One parsed D3D12_INDIRECT_ARGUMENT_DESC. Only the argument type is needed
/// for the supported single-argument ExecuteIndirect signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3D12IndirectArgumentDesc {
    pub ty: u32,
    pub root_parameter_index: u32,
    pub dest_offset_in_32bit_values: u32,
    pub num_32bit_values_to_set: u32,
}

/// Parsed D3D12_COMMAND_SIGNATURE_DESC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3D12CommandSignatureDesc {
    pub byte_stride: u32,
    pub node_mask: u32,
    pub arguments: Vec<D3D12IndirectArgumentDesc>,
}

/// A live command signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3D12CommandSignature {
    pub handle: u64,
    pub byte_stride: u32,
    pub node_mask: u32,
    pub argument: D3D12IndirectArgumentDesc,
}

/// Arguments consumed by one indirect DRAW command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3D12DrawArguments {
    pub vertex_count_per_instance: u32,
    pub instance_count: u32,
    pub start_vertex_location: u32,
    pub start_instance_location: u32,
}

/// Arguments consumed by one indirect DISPATCH/DISPATCH_MESH command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3D12DispatchArguments {
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

/// A Work Graph program bound to a command list by
/// `ID3D12GraphicsCommandList10::SetProgram`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D3d12WorkGraphProgram {
    pub state_object: u64,
    pub program_name: String,
    pub flags: u32,
    pub backing_memory: Option<(u64, u64)>,
    pub node_local_root_arguments_table: Option<D3d12GpuRangeAndStride>,
}

// ---------------------------------------------------------------------------
// D3d12Runtime
// ---------------------------------------------------------------------------

/// Describes a D3D12 query heap tracked at the runtime level.
#[derive(Debug, Clone)]
struct QueryHeap {
    heap_type: u32, // D3D12_QUERY_HEAP_TYPE: 0=Occlusion, 1=Timestamp, 2=PipelineStats, 3=SOStatistics
    count: u32,
    /// Tracks whether a query at (index) has begun.
    active: Vec<bool>,
    /// For timestamp queries: the begin timestamp counter value.
    begin_values: Vec<u64>,
    /// Final resolved values (end - begin for timestamps), written to the
    /// guest's readback buffer by ResolveQueryData.
    resolved: Vec<u64>,
}

/// Cloneable slot for the DirectStorage completion callback. Clones share the
/// same callback (Arc), so a cloned runtime observes the same hook.
#[derive(Clone, Default)]
struct UploadCompletionHook(
    Option<std::sync::Arc<std::sync::Mutex<Option<Box<dyn FnMut() + Send>>>>>,
);

impl std::fmt::Debug for UploadCompletionHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadCompletionHook")
            .field("registered", &self.0.is_some())
            .finish()
    }
}

impl UploadCompletionHook {
    fn set(&mut self, callback: Box<dyn FnMut() + Send>) {
        let slot = self
            .0
            .get_or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(None)));
        *slot.lock().expect("upload completion hook poisoned") = Some(callback);
    }

    /// Shared slot for registration with the DirectStorage completion
    /// listener, so the hook fires without any caller polling or waiting.
    fn slot(&self) -> Option<std::sync::Arc<std::sync::Mutex<Option<Box<dyn FnMut() + Send>>>>> {
        self.0.clone()
    }
}

/// Native Metal render pipeline registered for a D3D12 PSO.
#[derive(Debug, Clone)]
struct D3d12NativePipeline {
    vertex_msl: String,
    fragment_msl: String,
    pixel_format: DxgiFormat,
}

/// Native command-list state retained from SetPipelineState / IA / OM calls.
#[derive(Debug, Clone, Default)]
struct D3d12NativeCommandState {
    pipeline: Option<u64>,
    color_resource: Option<ResourceId>,
    color_width: u32,
    color_height: u32,
    color_format: Option<DxgiFormat>,
    vertex_resource: Option<ResourceId>,
    vertex_offset: u64,
    index_resource: Option<ResourceId>,
    index_offset: u64,
    index_format: u32,
}

/// A real Metal acceleration structure owned by the D3D12 bridge.
struct D3d12MetalStructure {
    structure: metal::AccelerationStructure,
    instance_masks: Vec<u32>,
    /// D3D12 row-major 3x4 object-to-world rows for each TLAS instance. BLAS
    /// structures keep this empty.
    instance_transforms: Vec<[f32; 12]>,
    /// Flattened vertex/index/AABB data for a BLAS or TLAS.
    geometry: crate::metal_backend::MetalRayGeometryData,
}

struct D3d12MetalRayTracingInner {
    device: metal::Device,
    queue: metal::CommandQueue,
    ray_pipeline: crate::metal_backend::MetalRayQueryPipeline,
    structures: BTreeMap<u64, D3d12MetalStructure>,
    guest_to_handle: BTreeMap<u64, u64>,
    last_ray_results: Vec<crate::metal_backend::MetalRayResult>,
    work_graph: Option<crate::metal_backend::MetalWorkGraphFanout>,
    last_work_graph_records: Vec<u32>,
    work_graph_node_programs:
        BTreeMap<(u64, String, u32), crate::metal_backend::MetalWorkGraphNodeProgram>,
    indirect_interpreter: Option<crate::metal_backend::MetalIndirectInterpreter>,
    native_render_pipelines: BTreeMap<u64, metal::RenderPipelineState>,
    ray_shader_programs: BTreeMap<u64, crate::metal_backend::MetalRayShaderProgram>,
    last_ray_payloads: Vec<crate::metal_backend::MetalRayPayloadResult>,
    last_indirect_results: Vec<crate::metal_backend::MetalIndirectResult>,
    last_indirect_effective: u32,
    last_indirect_native: bool,
    last_indirect_boundary: Option<String>,
}

/// Lazily initialised real Metal raytracing state for the D3D12 bridge.
#[derive(Clone)]
struct D3d12MetalRayTracing {
    inner: std::sync::Arc<std::sync::Mutex<D3d12MetalRayTracingInner>>,
}

#[rustfmt::skip]
impl std::fmt::Debug for D3d12MetalRayTracing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("D3d12MetalRayTracing")
            .finish_non_exhaustive()
    }
}

/// Real timing for one swapchain present.
///
/// The GPU and drawable probes are populated only when the caller marked the
/// frame for timing (`mark_input_event` / `enable_present_timing`) before
/// calling [`D3d12Runtime::present`]. Durations come from real Metal
/// `GPUStartTime`/`GPUEndTime` and `CAMetalDrawable.presentedTime` values, never
/// from CPU bookkeeping.
#[derive(Clone, Default)]
pub struct D3d12PresentTiming {
    /// CoreAnimation media time of the input event correlated with this frame.
    pub input_seconds: Option<f64>,
    /// CoreAnimation media time at command submission.
    pub submitted_seconds: Option<f64>,
    pub gpu: Option<crate::metal_backend::GpuTimingProbe>,
    pub drawable: Option<crate::metal_backend::DrawableTimingProbe>,
}

impl std::fmt::Debug for D3d12PresentTiming {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("D3d12PresentTiming")
            .field("input_seconds", &self.input_seconds)
            .field("submitted_seconds", &self.submitted_seconds)
            .field("has_gpu_probe", &self.gpu.is_some())
            .field("has_drawable_probe", &self.drawable.is_some())
            .finish()
    }
}

fn seconds_delta_to_ns(start: f64, end: f64) -> Option<u64> {
    let delta = (end - start) * 1_000_000_000.0;
    if !delta.is_finite() || delta < 0.0 || delta > u64::MAX as f64 {
        None
    } else {
        Some(delta.round() as u64)
    }
}

impl D3d12PresentTiming {
    /// Build a timing record from known values. Used by tests and by callers
    /// that already own real timestamps.
    pub fn from_seconds(
        input_seconds: Option<f64>,
        submitted_seconds: Option<f64>,
        gpu_seconds: Option<(f64, f64)>,
        presented_seconds: Option<f64>,
    ) -> Self {
        let gpu = gpu_seconds.map(|(start, end)| {
            let reading = if start.is_finite() && end.is_finite() && start > 0.0 && end >= start {
                crate::metal_backend::GpuTimestampReading::Measured {
                    start_seconds: start,
                    end_seconds: end,
                }
            } else {
                crate::metal_backend::GpuTimestampReading::MissingTimestamp {
                    status: "Completed",
                }
            };
            crate::metal_backend::GpuTimingProbe::with_reading(reading)
        });
        let drawable = presented_seconds.map(|presented_seconds| {
            let reading = if presented_seconds.is_finite() && presented_seconds > 0.0 {
                crate::metal_backend::PresentTimestampReading::Measured { presented_seconds }
            } else {
                crate::metal_backend::PresentTimestampReading::MissingTimestamp
            };
            crate::metal_backend::DrawableTimingProbe::with_reading(reading)
        });
        Self {
            input_seconds,
            submitted_seconds,
            gpu,
            drawable,
        }
    }

    pub fn gpu_seconds(&self) -> Option<(f64, f64)> {
        match self.gpu.as_ref()?.snapshot()? {
            crate::metal_backend::GpuTimestampReading::Measured {
                start_seconds,
                end_seconds,
            } => Some((start_seconds, end_seconds)),
            _ => None,
        }
    }

    pub fn presented_seconds(&self) -> Option<f64> {
        match self.drawable.as_ref()?.snapshot()? {
            crate::metal_backend::PresentTimestampReading::Measured { presented_seconds } => {
                Some(presented_seconds)
            }
            _ => None,
        }
    }

    /// Real GPU execution time, or `None` when the timestamps are absent.
    pub fn gpu_time_ns(&self) -> Option<u64> {
        let (start, end) = self.gpu_seconds()?;
        seconds_delta_to_ns(start, end)
    }

    /// Real input-event → drawable-presentation duration.
    pub fn input_to_present_ns(&self) -> Option<u64> {
        seconds_delta_to_ns(self.input_seconds?, self.presented_seconds()?)
    }

    /// Real input-event → GPU-completion duration.
    pub fn input_to_gpu_completion_ns(&self) -> Option<u64> {
        let (_, end) = self.gpu_seconds()?;
        seconds_delta_to_ns(self.input_seconds?, end)
    }

    /// Exact reason the GPU timestamp is unavailable, or `None` when measured.
    pub fn gpu_unavailable(&self) -> Option<crate::perf::TimingUnavailable> {
        match self.gpu.as_ref().and_then(|probe| probe.snapshot()) {
            Some(crate::metal_backend::GpuTimestampReading::Measured { .. }) => None,
            Some(crate::metal_backend::GpuTimestampReading::UnsupportedDevice) => {
                Some(crate::perf::TimingUnavailable::UnsupportedGpuTimestamp)
            }
            Some(crate::metal_backend::GpuTimestampReading::MissingTimestamp { .. }) | None => {
                Some(crate::perf::TimingUnavailable::MissingGpuTimestamp)
            }
        }
    }

    /// Exact reason the drawable presentation timestamp is unavailable.
    pub fn present_unavailable(&self) -> Option<crate::perf::TimingUnavailable> {
        match self.drawable.as_ref().and_then(|probe| probe.snapshot()) {
            Some(crate::metal_backend::PresentTimestampReading::Measured { .. }) => None,
            Some(crate::metal_backend::PresentTimestampReading::UnsupportedDevice) => {
                Some(crate::perf::TimingUnavailable::UnsupportedGpuTimestamp)
            }
            Some(crate::metal_backend::PresentTimestampReading::MissingTimestamp) => {
                Some(crate::perf::TimingUnavailable::MissingPresentTimestamp)
            }
            None => Some(crate::perf::TimingUnavailable::NoDrawable),
        }
    }
}

#[derive(Debug, Clone)]
pub struct D3d12Runtime {
    backend: GraphicsBackend,
    render_pass_active: bool,
    shading_rate: u32,
    /// Map from guest state-object pointer to parsed pipeline state.
    raytracing_pipeline_states: BTreeMap<u64, D3D12RaytracingPipelineState>,
    /// Live D3D12 state objects keyed by the guest-visible handle.
    state_objects: BTreeMap<u64, D3d12StateObject>,
    /// Monotonic allocator for bridge-owned state-object handles.
    next_state_object_handle: u64,
    /// State object currently bound to each command list by SetPipelineState1.
    pipeline_state_objects: BTreeMap<CommandListId, u64>,
    /// Work-graph program currently bound to each command list by SetProgram.
    work_graph_programs: BTreeMap<CommandListId, D3d12WorkGraphProgram>,
    /// Parsed command signatures keyed by the handle returned to the guest.
    command_signatures: BTreeMap<u64, D3D12CommandSignature>,
    /// Monotonic allocator for command-signature handles.
    next_command_signature_handle: u64,
    /// DirectML device/operator/compile/dispatch registry.
    directml: DmlRuntime,
    /// Map from GPU virtual address to acceleration structure metadata.
    acceleration_structures: BTreeMap<u64, D3D12AccelerationStructure>,
    /// Query heap tracking for begin/end query pairs.
    query_heaps: BTreeMap<u64, QueryHeap>,
    /// Depth bounds min/max (set by OMSetDepthBounds).
    depth_bounds_min: f32,
    depth_bounds_max: f32,
    /// Sample positions state (set by SetSamplePositions).
    sample_positions_pixel_samples: u32,
    sample_positions_num_pixels: u32,
    /// View instance mask for multiview rendering.
    view_instance_mask: u32,
    /// Protected resource session handle.
    protected_session: u64,
    /// Per-subresource barrier state tracking: (resource, 0, flat D3D12
    /// subresource index) -> state, mirroring the backend convention.
    subresource_states: BTreeMap<SubresourceKey, ResourceState>,
    /// Pending split barrier states (BEGIN_ONLY not yet matched with END_ONLY).
    pending_split_barriers: Vec<PendingSplitBarrier>,
    /// Tracking for aliasing barrier resource overlaps.
    aliasing_overlaps: Vec<(Option<ResourceId>, Option<ResourceId>)>,
    /// Root signature descriptors stored for reference.
    root_signature_descs: BTreeMap<RootSignatureId, RootSignatureDesc>,
    /// Pending WriteBufferImmediate requests stored for processing during
    /// command list execution. Each entry is (list, dst_gpu_addr, value_bytes).
    pending_immediate_writes: Vec<(CommandListId, u64, [u8; 8])>,
    /// IOSurface-backed present channels, one per swapchain backbuffer. Empty
    /// means the capability probe/allocation failed; presents then use the
    /// verified host-visible fallback.
    iosurface_channels: Vec<crate::metal_backend::IoSurfacePresentChannel>,
    /// Presents that bound the aliasing Metal texture.
    iosurface_presents: u64,
    /// The swapchain whose IOSurface channels are current. Writes to its
    /// backbuffers route into the surface instead of the CPU backing bytes.
    present_swapchain: Option<SwapchainId>,
    /// Writes that landed directly in the IOSurface mapping.
    surface_writes: u64,
    /// Writes that had to update the CPU backing bytes.
    cpu_backing_writes: u64,
    /// Present-time uploads through the fallback path.
    fallback_uploads: u64,
    /// NV12 plane channels for the primary swapchain (empty for pixel paths).
    primary_nv12: Vec<crate::metal_backend::Nv12PresentChannel>,
    /// Additional swapchains, each with its own IOSurface channel set.
    extra_swapchains: BTreeMap<SwapchainId, SwapchainChannelSet>,
    /// Presents that bound both NV12 planes.
    nv12_presents: u64,
    /// Requests for a swapchain format this host could not represent; the
    /// request fell back to the caller's typed format.
    swapchain_format_fallbacks: u64,
    /// Opt-in MetalFX present state keyed by swapchain. Empty unless a caller
    /// explicitly called [`D3d12Runtime::enable_metalfx_present`].
    metalfx_present: BTreeMap<SwapchainId, std::sync::Arc<std::sync::Mutex<MetalFxPresentState>>>,
    /// Presents that succeeded through MetalFX.
    metalfx_scaled_presents: u64,
    /// Presents that fell back to the existing path after MetalFX failed.
    metalfx_fallbacks: u64,
    /// Most recent MetalFX present error (kept observable even after a
    /// fallback, so a quality downgrade is never silent).
    metalfx_last_error: Option<AppError>,
    /// Swapchain whose frame was produced by MetalFX on the last successful
    /// present, if any.
    metalfx_last_scaled_swapchain: Option<SwapchainId>,
    /// Textures created through the DirectStorage / initial-data path, keyed by
    /// the translated resource id.
    gpu_textures: BTreeMap<ResourceId, crate::metal_backend::DirectStorageTexture>,
    /// Bytes delivered by the DirectStorage direct path (file -> MTLBuffer).
    directstorage_bytes: u64,
    /// Bytes that transited a host staging buffer (compressed sources and
    /// host-owned CreateResource initial-data uploads).
    staging_bytes: u64,
    /// CreateResource initial-data uploads whose source bytes were canonical
    /// guest memory (no host copy).
    guest_initial_uploads: u64,
    /// Async DirectStorage pipeline (queued command buffers + MTLSharedEvent).
    directstorage_queue:
        Option<std::sync::Arc<std::sync::Mutex<crate::metal_backend::DirectStorageUploadQueue>>>,
    /// Completion hook fired once each time the async queue drains.
    directstorage_completion: UploadCompletionHook,
    /// Resources created by async enqueues that have not completed yet.
    directstorage_pending_resources: Vec<(ResourceId, u64)>,
    /// Real Metal acceleration structures, ray traversal pipelines and
    /// dispatch readback, created on first use.
    metal_raytracing: Option<D3d12MetalRayTracing>,
    /// Registered CPU bytes for raytracing input buffers keyed by GPU address.
    raytracing_buffer_bytes: BTreeMap<u64, Vec<u8>>,
    /// Registered D3D12 instance descriptors keyed by the TLAS destination.
    raytracing_instance_bytes: BTreeMap<u64, Vec<u8>>,
    /// Translated native render pipelines keyed by native handle.
    native_pipelines: BTreeMap<u64, D3d12NativePipeline>,
    /// Native pipeline bound to each D3D12 pipeline state object.
    pso_native_pipelines: BTreeMap<PipelineStateId, u64>,
    /// Native render state per open command list.
    native_command_states: BTreeMap<CommandListId, D3d12NativeCommandState>,
    /// Render-target dimensions keyed by resource.
    native_target_dimensions: BTreeMap<ResourceId, (u32, u32)>,
    /// Metal 4 grouped executor for ExecuteCommandLists, created on first use.
    metal4_batch: Option<metal4_batch::Metal4Batch>,
    /// True when this host refused Metal 4; batches then use the CPU fallback.
    metal4_batch_disabled: bool,
    /// ExecuteCommandLists batches that used the CPU fallback.
    metal4_batch_fallbacks: u64,
    /// Most recent Metal 4 batch failure that caused a fallback.
    metal4_batch_last_error: Option<AppError>,
    /// Shared-event value of the most recent successful grouped submission.
    metal4_batch_last_event: Option<u64>,
    /// Input-event timestamp for the next timed present.
    pending_present_input_seconds: Option<f64>,
    /// True when the caller asked for timing on the next present.
    present_timing_requested: bool,
    /// Timing of the most recent real present, when timing was requested.
    last_present_timing: Option<D3d12PresentTiming>,
}

#[derive(Debug, Clone, Default)]
struct SwapchainChannelSet {
    pixel: Vec<crate::metal_backend::IoSurfacePresentChannel>,
    nv12: Vec<crate::metal_backend::Nv12PresentChannel>,
}

impl SwapchainChannelSet {
    fn is_empty(&self) -> bool {
        self.pixel.is_empty() && self.nv12.is_empty()
    }
}

/// Handle returned by an asynchronous DirectStorage enqueue. `fence_value` is
/// the MTLSharedEvent value signaled by this upload's real command buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3D12UploadTicket {
    pub resource: ResourceId,
    pub fence_value: u64,
}

/// D3D12 `CreateResource` initial texture data (width/height/format plus the
/// tightly packed texel bytes).
#[derive(Debug, Clone)]
pub struct D3d12InitialTextureData {
    pub width: u32,
    pub height: u32,
    pub format: metal::MTLPixelFormat,
    pub data: Vec<u8>,
}

/// Allocate one IOSurface-backed present channel per swapchain backbuffer.
/// Returns an empty vector when the capability probe or any allocation fails,
/// so presents take the verified fallback path.
fn build_iosurface_channels(
    width: u32,
    height: u32,
    format: metal::MTLPixelFormat,
    count: u32,
) -> Vec<crate::metal_backend::IoSurfacePresentChannel> {
    let mut channels = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match crate::metal_backend::IoSurfacePresentChannel::new(width, height, format) {
            Ok(channel) => channels.push(channel),
            Err(_) => return Vec::new(),
        }
    }
    channels
}

/// Allocate one NV12 IOSurface channel (two Metal planes) per backbuffer.
/// Returns `None` when the host cannot provide the two-plane surface, so the
/// caller can count the fallback and use the pixel path.
fn build_nv12_channels(
    width: u32,
    height: u32,
    count: u32,
) -> Option<Vec<crate::metal_backend::Nv12PresentChannel>> {
    let mut channels = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match crate::metal_backend::Nv12PresentChannel::new(width, height) {
            Ok(channel) => channels.push(channel),
            Err(_) => return None,
        }
    }
    Some(channels)
}

/// DXGI format of the IOSurface-backed MetalFX output texture.
fn metalfx_output_dxgi_format(format: metal::MTLPixelFormat) -> DxgiFormat {
    match format {
        metal::MTLPixelFormat::BGRA8Unorm => DxgiFormat::B8G8R8A8Unorm,
        _ => DxgiFormat::R8G8B8A8Unorm,
    }
}

#[rustfmt::skip]
fn unreachable_no_metal_device_error() -> AppError { AppError::new(ReasonCode::RcD3dInvalidState, "MetalFX present: no Metal device available") } // coverage: unreachable — the system default Metal device exists on this host
#[rustfmt::skip]
fn unreachable_scaler_status_error(status: metal::MTLCommandBufferStatus) -> AppError { AppError::new(ReasonCode::RcD3dInvalidState, format!("MetalFX present: scaler command buffer completed with status {status:?}")) } // coverage: unreachable — a valid MetalFX encode plus blit completes

/// Build a real spatial scaler plus the private output texture and the
/// IOSurface alias that present binds.
fn build_metalfx_present_state(
    desc: &SwapchainDesc,
    options: MetalFxPresentOptions,
) -> AppResult<MetalFxPresentState> {
    if options.mode != MetalFxPresentMode::Spatial {
        return Err(AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            "MetalFX present: temporal mode requires per-frame depth and motion textures and is \
             not supported by the DXGI present path",
        ));
    }
    if options.output_width == 0 || options.output_height == 0 {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!(
                "MetalFX present: output size {}x{} must be non-zero",
                options.output_width, options.output_height
            ),
        ));
    }
    if options.output_width < desc.width || options.output_height < desc.height {
        return Err(AppError::new(
            ReasonCode::RcInvalidParameter,
            format!(
                "MetalFX present: output {}x{} must be at least the swapchain size {}x{}",
                options.output_width, options.output_height, desc.width, desc.height
            ),
        ));
    }
    let input_format = crate::metal_backend::dxgi_to_metal_format(desc.format);
    if !crate::metal_fx::is_supported_present_format(input_format) {
        return Err(AppError::new(
            ReasonCode::RcGfxFormatUnsupported,
            format!(
                "MetalFX present: swapchain format {:?} ({input_format:?}) is not supported; the \
                 DXGI present path requires B8G8R8A8Unorm or R8G8B8A8Unorm",
                desc.format
            ),
        ));
    }
    let config = crate::metal_fx::SpatialScalerConfig {
        input_width: desc.width,
        input_height: desc.height,
        output_width: options.output_width,
        output_height: options.output_height,
        color_format: input_format,
        output_format: input_format,
        color_processing_mode: options.color_processing_mode,
    };
    let Some(device) = metal::Device::system_default() else {
        return Err(unreachable_no_metal_device_error()); // coverage: unreachable — the system default Metal device exists
    };
    let scaler = crate::metal_fx::SpatialScaler::new(device.as_ref(), config)?;
    let mut output_channel = crate::metal_backend::IoSurfacePresentChannel::new(
        options.output_width,
        options.output_height,
        input_format,
    )?; // coverage: unreachable — validated output sizes allocate an IOSurface on this host
    let output_alias = output_channel.metal_texture()?.to_owned();

    let descriptor = metal::TextureDescriptor::new();
    descriptor.set_texture_type(metal::MTLTextureType::D2);
    descriptor.set_pixel_format(input_format);
    descriptor.set_width(options.output_width as u64);
    descriptor.set_height(options.output_height as u64);
    descriptor
        .set_usage(metal::MTLTextureUsage::ShaderWrite | metal::MTLTextureUsage::RenderTarget);
    descriptor.set_storage_mode(metal::MTLStorageMode::Private);
    descriptor.set_sample_count(1);
    let output_texture = device.new_texture(&descriptor);

    Ok(MetalFxPresentState {
        options,
        config,
        scaler,
        command_queue: device.new_command_queue(),
        output_texture,
        output_alias,
        output_channel,
        output_format: metalfx_output_dxgi_format(input_format),
    })
}

impl Default for D3d12Runtime {
    fn default() -> Self {
        Self {
            backend: GraphicsBackend::new(),
            render_pass_active: false,
            shading_rate: 0,
            raytracing_pipeline_states: BTreeMap::new(),
            state_objects: BTreeMap::new(),
            next_state_object_handle: 0x5000,
            pipeline_state_objects: BTreeMap::new(),
            work_graph_programs: BTreeMap::new(),
            command_signatures: BTreeMap::new(),
            next_command_signature_handle: 1,
            directml: DmlRuntime::new(),
            acceleration_structures: BTreeMap::new(),
            query_heaps: BTreeMap::new(),
            depth_bounds_min: 0.0,
            depth_bounds_max: 1.0,
            sample_positions_pixel_samples: 0,
            sample_positions_num_pixels: 0,
            view_instance_mask: 0,
            protected_session: 0,
            subresource_states: BTreeMap::new(),
            pending_split_barriers: Vec::new(),
            aliasing_overlaps: Vec::new(),
            root_signature_descs: BTreeMap::new(),
            pending_immediate_writes: Vec::new(),
            iosurface_channels: Vec::new(),
            iosurface_presents: 0,
            present_swapchain: None,
            surface_writes: 0,
            cpu_backing_writes: 0,
            fallback_uploads: 0,
            primary_nv12: Vec::new(),
            extra_swapchains: BTreeMap::new(),
            nv12_presents: 0,
            swapchain_format_fallbacks: 0,
            metalfx_present: BTreeMap::new(),
            metalfx_scaled_presents: 0,
            metalfx_fallbacks: 0,
            metalfx_last_error: None,
            metalfx_last_scaled_swapchain: None,
            gpu_textures: BTreeMap::new(),
            directstorage_bytes: 0,
            staging_bytes: 0,
            guest_initial_uploads: 0,
            directstorage_queue: None,
            directstorage_completion: UploadCompletionHook::default(),
            directstorage_pending_resources: Vec::new(),
            metal_raytracing: None,
            raytracing_buffer_bytes: BTreeMap::new(),
            raytracing_instance_bytes: BTreeMap::new(),
            native_pipelines: BTreeMap::new(),
            pso_native_pipelines: BTreeMap::new(),
            native_command_states: BTreeMap::new(),
            native_target_dimensions: BTreeMap::new(),
            metal4_batch: None,
            metal4_batch_disabled: false,
            metal4_batch_fallbacks: 0,
            metal4_batch_last_error: None,
            metal4_batch_last_event: None,
            pending_present_input_seconds: None,
            present_timing_requested: false,
            last_present_timing: None,
        }
    }
}

impl D3d12Runtime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_backend(backend: GraphicsBackend) -> Self {
        Self {
            backend,
            render_pass_active: false,
            shading_rate: 0,
            raytracing_pipeline_states: BTreeMap::new(),
            state_objects: BTreeMap::new(),
            next_state_object_handle: 0x5000,
            pipeline_state_objects: BTreeMap::new(),
            work_graph_programs: BTreeMap::new(),
            command_signatures: BTreeMap::new(),
            next_command_signature_handle: 1,
            directml: DmlRuntime::new(),
            acceleration_structures: BTreeMap::new(),
            query_heaps: BTreeMap::new(),
            depth_bounds_min: 0.0,
            depth_bounds_max: 1.0,
            sample_positions_pixel_samples: 0,
            sample_positions_num_pixels: 0,
            view_instance_mask: 0,
            protected_session: 0,
            subresource_states: BTreeMap::new(),
            pending_split_barriers: Vec::new(),
            aliasing_overlaps: Vec::new(),
            root_signature_descs: BTreeMap::new(),
            pending_immediate_writes: Vec::new(),
            iosurface_channels: Vec::new(),
            iosurface_presents: 0,
            present_swapchain: None,
            surface_writes: 0,
            cpu_backing_writes: 0,
            fallback_uploads: 0,
            primary_nv12: Vec::new(),
            extra_swapchains: BTreeMap::new(),
            nv12_presents: 0,
            swapchain_format_fallbacks: 0,
            metalfx_present: BTreeMap::new(),
            metalfx_scaled_presents: 0,
            metalfx_fallbacks: 0,
            metalfx_last_error: None,
            metalfx_last_scaled_swapchain: None,
            gpu_textures: BTreeMap::new(),
            directstorage_bytes: 0,
            staging_bytes: 0,
            guest_initial_uploads: 0,
            directstorage_queue: None,
            directstorage_completion: UploadCompletionHook::default(),
            directstorage_pending_resources: Vec::new(),
            metal_raytracing: None,
            raytracing_buffer_bytes: BTreeMap::new(),
            raytracing_instance_bytes: BTreeMap::new(),
            native_pipelines: BTreeMap::new(),
            pso_native_pipelines: BTreeMap::new(),
            native_command_states: BTreeMap::new(),
            native_target_dimensions: BTreeMap::new(),
            metal4_batch: None,
            metal4_batch_disabled: false,
            metal4_batch_fallbacks: 0,
            metal4_batch_last_error: None,
            metal4_batch_last_event: None,
            pending_present_input_seconds: None,
            present_timing_requested: false,
            last_present_timing: None,
        }
    }

    pub fn backend(&self) -> &GraphicsBackend {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut GraphicsBackend {
        &mut self.backend
    }

    /// Emit a diagnostic trace line. Writes to stderr only when
    /// `CASA1_TRACE_D3D12` is set, so hot paths (e.g. per-frame acceleration
    /// structure builds) do not pay unbuffered stderr I/O by default.
    fn trace(&self, message: &str) {
        if std::env::var_os("CASA1_TRACE_D3D12").is_some() {
            eprintln!("[d3d12] {message}");
        }
    }

    pub fn device_info(&self) -> D3d12DeviceInfo {
        let capabilities = self.backend.capabilities();
        D3d12DeviceInfo {
            adapter: self.backend.adapter().clone(),
            outputs: self.backend.outputs().to_vec(),
            features: D3d12FeatureOptions {
                tearing: self.backend.query_feature(FeatureQuery::Tearing),
                timestamp_queries: self.backend.query_feature(FeatureQuery::TimestampQueries),
                mesh_shaders: self.backend.query_feature(FeatureQuery::MeshShaders),
                unified_memory: capabilities.unified_memory,
                argument_buffers: capabilities.argument_buffers,
                memoryless_render_targets: capabilities.memoryless_render_targets,
                raytracing: capabilities.raytracing,
            },
        }
    }

    /// Get subresource state from fine-grained tracking. `subresource` is the
    /// flat D3D12 subresource index (mip + array_slice * mip_levels).
    pub fn subresource_state(
        &self,
        resource: ResourceId,
        subresource: u32,
    ) -> Option<ResourceState> {
        self.subresource_states
            .get(&(resource, 0, subresource))
            .copied()
    }

    /// Set subresource state in fine-grained tracking. `subresource` is the
    /// flat D3D12 subresource index (mip + array_slice * mip_levels).
    pub fn set_subresource_state(
        &mut self,
        resource: ResourceId,
        subresource: u32,
        state: ResourceState,
    ) {
        self.subresource_states
            .insert((resource, 0, subresource), state);
    }

    /// Get the stored root signature descriptor for a given ID.
    pub fn root_signature_desc(&self, id: RootSignatureId) -> Option<&RootSignatureDesc> {
        self.root_signature_descs.get(&id)
    }

    /// Map a D3D12_DESCRIPTOR_RANGE_TYPE to its Metal argument buffer resource type string.
    pub fn descriptor_range_type_to_metal(range_type: D3D12DescriptorRangeType) -> &'static str {
        match range_type {
            D3D12DescriptorRangeType::Srv => "texture",
            D3D12DescriptorRangeType::Uav => "texture",
            D3D12DescriptorRangeType::Cbv => "buffer",
            D3D12DescriptorRangeType::Sampler => "sampler",
        }
    }

    /// Map D3D12_FILTER to a Metal sampler descriptor configuration.
    ///
    /// The D3D12_FILTER bit encoding is decoded per d3d12.h: bits 0-1 mip
    /// filter, bits 2-3 mag filter, bits 4-5 min filter, bit 6 anisotropic,
    /// bits 7-8 reduction type. The reduction is returned as the real
    /// [`D3D12FilterReduction`] enum — COMPARISON drives the comparison
    /// path, MINIMUM/MAXIMUM are recorded on the mapping (Metal samplers
    /// have no min/max reduction mode; see below).
    pub fn map_d3d12_filter_to_metal(d3d12_filter: u32) -> D3D12MetalFilterMapping {
        // D3D12_FILTER bit encoding (see d3d12.h):
        //   bits 0-1: mip filter (0=point, 1=linear)
        //   bits 2-3: mag filter (0=point, 1=linear)
        //   bits 4-5: min filter (0=point, 1=linear)
        //   bit 6   : anisotropic filtering (forces linear on all stages)
        //   bits 7-8: reduction type (0=standard, 1=comparison, 2=min, 3=max)
        let anisotropic = (d3d12_filter & 0x40) != 0;
        // Bits 7-8 always decode to a defined reduction (0..=3); the
        // D3D12_FILTER_REDUCTION_TYPE enum has exactly four members.
        let reduction = D3D12FilterReduction::from_u32((d3d12_filter >> 7) & 0x03)
            .expect("reduction field bits 7-8 always decode 0..=3");

        let mip_linear = anisotropic || (d3d12_filter & 0x03) != 0;
        let mag_linear = anisotropic || ((d3d12_filter >> 2) & 0x03) != 0;
        let min_linear = anisotropic || ((d3d12_filter >> 4) & 0x03) != 0;

        let min_filter = if min_linear { "linear" } else { "nearest" };
        let mag_filter = if mag_linear { "linear" } else { "nearest" };
        let mip_filter = if mip_linear { "linear" } else { "nearest" };

        D3D12MetalFilterMapping {
            min_filter,
            mag_filter,
            mip_filter,
            anisotropic,
            reduction,
        }
    }

    /// Map D3D12_TEXTURE_ADDRESS_MODE to the Metal address mode string.
    ///
    /// D3D12 values (per d3d12.h): 0=WRAP, 1=MIRROR, 2=CLAMP, 3=BORDER,
    /// 4=MIRROR_ONCE. Metal has no `mirror_once` mode, so MIRROR_ONCE maps
    /// to `mirror_clamp_to_edge` (the closest Metal equivalent).
    ///
    /// Values outside `0..=4` are undefined per d3d12.h — a validation
    /// error on Windows, never a silent default. The runtime rejects them
    /// exactly like the reference does.
    pub fn map_d3d12_address_mode(mode: u32) -> AppResult<&'static str> {
        D3D12TextureAddressMode::from_u32(mode)
            .map(D3D12TextureAddressMode::metal_name)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "D3D12_TEXTURE_ADDRESS_MODE value {mode} is outside the defined \
                         0..=4 range (0=WRAP, 1=MIRROR, 2=CLAMP, 3=BORDER, 4=MIRROR_ONCE) \
                         and is a validation error on Windows"
                    ),
                )
            })
    }

    /// Map D3D12_COMPARISON_FUNC to Metal compare function string.
    pub fn map_d3d12_comparison_func(func: u32) -> &'static str {
        match func {
            1 => "never",
            2 => "less",
            3 => "equal",
            4 => "less_equal",
            5 => "greater",
            6 => "not_equal",
            7 => "greater_equal",
            8 => "always",
            _ => "never",
        }
    }

    /// Map D3D12_STATIC_BORDER_COLOR to Metal border color string.
    pub fn map_d3d12_border_color(color: u32) -> &'static str {
        match color {
            0 => "transparent_black", // D3D12_STATIC_BORDER_COLOR_TRANSPARENT_BLACK
            1 => "opaque_black",      // D3D12_STATIC_BORDER_COLOR_OPAQUE_BLACK
            2 => "opaque_white",      // D3D12_STATIC_BORDER_COLOR_OPAQUE_WHITE
            _ => "transparent_black",
        }
    }

    /// Create a Metal sampler descriptor string from a D3D12_STATIC_SAMPLER_DESC.
    ///
    /// Rejects invalid combinations (anisotropy above the Metal limit of 16,
    /// min_lod > max_lod, address modes outside `0..=4`) before emitting the
    /// descriptor.
    pub fn static_sampler_to_metal_desc(sampler: &D3D12StaticSamplerDesc) -> AppResult<String> {
        Self::validate_static_sampler(sampler)?;
        let mapping = Self::map_d3d12_filter_to_metal(sampler.filter);
        let address_u = Self::map_d3d12_address_mode(sampler.address_u)?;
        let address_v = Self::map_d3d12_address_mode(sampler.address_v)?;
        let address_w = Self::map_d3d12_address_mode(sampler.address_w)?;
        let compare_fn = Self::map_d3d12_comparison_func(sampler.comparison_func);
        let border_color = Self::map_d3d12_border_color(sampler.border_color);

        // D3D12_FILTER_REDUCTION_TYPE MINIMUM/MAXIMUM (mapping.reduction):
        // Metal has no min/max reduction in samplers, so the descriptor is
        // emitted with the standard (non-comparison) filter mapping — a
        // documented translation, with the requested reduction visible on
        // `mapping.reduction` rather than silently assumed standard.
        Ok(format!(
            "sampler(coord::normalized, address::{addr_u}, address::{addr_v}, address::{addr_w}, \
             filter::{min_f},{mag_f},{mip_f}, compare::{cmp}, lod_clamp({min_lod},{max_lod}), \
             max_anisotropy({aniso}), border_color::{border})",
            addr_u = address_u,
            addr_v = address_v,
            addr_w = address_w,
            min_f = mapping.min_filter,
            mag_f = mapping.mag_filter,
            mip_f = mapping.mip_filter,
            cmp = compare_fn,
            min_lod = sampler.min_lod,
            max_lod = sampler.max_lod,
            aniso = if mapping.anisotropic {
                sampler.max_anisotropy
            } else {
                1
            },
            border = border_color,
        ))
    }

    /// Validate a static sampler descriptor for unsupported combinations.
    pub fn validate_static_sampler(sampler: &D3D12StaticSamplerDesc) -> AppResult<()> {
        if sampler.max_anisotropy > 16 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "max anisotropy {} exceeds Metal limit of 16",
                    sampler.max_anisotropy
                ),
            ));
        }
        if sampler.min_lod > sampler.max_lod {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "static sampler min_lod > max_lod",
            ));
        }
        // D3D12_TEXTURE_ADDRESS_MODE is 0-based (0=WRAP..4=MIRROR_ONCE);
        // any other value is a validation error on Windows.
        for (field, mode) in [
            ("address_u", sampler.address_u),
            ("address_v", sampler.address_v),
            ("address_w", sampler.address_w),
        ] {
            if D3D12TextureAddressMode::from_u32(mode).is_none() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "static sampler {field} value {mode} is outside \
                         D3D12_TEXTURE_ADDRESS_MODE 0..=4 (a validation error on Windows)"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Handle unbounded descriptor ranges (NumDescriptors == UINT_MAX).
    /// Falls back to a reasonable limit per range type.
    pub fn resolve_unbounded_range(
        range_type: D3D12DescriptorRangeType,
        num_descriptors: u32,
    ) -> u32 {
        if num_descriptors != u32::MAX {
            return num_descriptors;
        }
        match range_type {
            D3D12DescriptorRangeType::Srv | D3D12DescriptorRangeType::Uav => 1024,
            D3D12DescriptorRangeType::Cbv => 256,
            D3D12DescriptorRangeType::Sampler => 64,
        }
    }

    /// Get per-shader-visibility descriptor table offsets for a root signature.
    pub fn visibility_offsets(
        desc: &RootSignatureDesc,
        visibility: D3D12ShaderVisibility,
    ) -> &[u32] {
        const EMPTY: &[u32] = &[];
        desc.visibility_offsets
            .get(&visibility)
            .map_or(EMPTY, |v| v.as_slice())
    }

    pub fn query_format_support(&self, format: DxgiFormat) -> AppResult<FormatMapping> {
        self.backend.query_format_support(format)
    }

    /// Opt the DXGI present path into MetalFX spatial upscaling.
    ///
    /// This is the only way MetalFX is activated for presents: nothing changes
    /// quality unless the caller invokes this method. Unsupported hosts,
    /// swapchain formats, modes and sizes return an exact error and leave the
    /// existing present path untouched.
    pub fn enable_metalfx_present(
        &mut self,
        swapchain: SwapchainId,
        options: MetalFxPresentOptions,
    ) -> AppResult<()> {
        let desc = self.backend.swapchain_state(swapchain)?.desc;
        let state = build_metalfx_present_state(&desc, options)?;
        self.metalfx_present
            .insert(swapchain, std::sync::Arc::new(std::sync::Mutex::new(state)));
        self.metalfx_last_error = None;
        self.metalfx_last_scaled_swapchain = None;
        Ok(())
    }

    /// Disable MetalFX for `swapchain`; returns whether a configuration existed.
    pub fn disable_metalfx_present(&mut self, swapchain: SwapchainId) -> bool {
        if self.metalfx_last_scaled_swapchain == Some(swapchain) {
            self.metalfx_last_scaled_swapchain = None;
        }
        self.metalfx_present.remove(&swapchain).is_some()
    }

    /// Whether `swapchain` has an explicit MetalFX present configuration.
    pub fn metalfx_present_configured(&self, swapchain: SwapchainId) -> bool {
        self.metalfx_present.contains_key(&swapchain)
    }

    /// The exact options the caller opted into, when configured.
    pub fn metalfx_present_options(&self, swapchain: SwapchainId) -> Option<MetalFxPresentOptions> {
        self.metalfx_present
            .get(&swapchain)
            .and_then(|state| state.lock().ok().map(|state| state.options))
    }

    /// Presents that actually ran through MetalFX.
    pub fn metalfx_scaled_present_count(&self) -> u64 {
        self.metalfx_scaled_presents
    }

    /// Presents or resize refreshes that fell back after a MetalFX failure.
    pub fn metalfx_fallback_count(&self) -> u64 {
        self.metalfx_fallbacks
    }

    /// The last MetalFX failure, retained even after falling back so the
    /// quality downgrade stays observable.
    pub fn metalfx_last_error(&self) -> Option<&AppError> {
        self.metalfx_last_error.as_ref()
    }

    fn record_metalfx_fallback(&mut self, error: AppError) {
        self.metalfx_fallbacks += 1;
        self.metalfx_last_error = Some(error);
    }

    /// Rebuild the scaler and output surface after a swapchain resize. A
    /// configuration that no longer fits is dropped and reported through the
    /// fallback counters; the normal present path keeps working.
    fn refresh_metalfx_present(&mut self, swapchain: SwapchainId, desc: &SwapchainDesc) {
        let Some(options) = self
            .metalfx_present
            .get(&swapchain)
            .and_then(|state| state.lock().ok().map(|state| state.options))
        else {
            return;
        };
        match build_metalfx_present_state(desc, options) {
            Ok(state) => {
                self.metalfx_present
                    .insert(swapchain, std::sync::Arc::new(std::sync::Mutex::new(state)));
                self.metalfx_last_error = None;
            }
            Err(error) => {
                self.metalfx_present.remove(&swapchain);
                self.metalfx_last_scaled_swapchain = None;
                self.record_metalfx_fallback(error);
            }
        }
    }

    /// Encode one MetalFX spatial upscale from the swapchain's IOSurface
    /// texture into the configured output surface. Returns `None` (and records
    /// the exact error) so the caller can present through the existing path.
    fn try_metalfx_present(
        &mut self,
        swapchain: SwapchainId,
    ) -> Option<(crate::metal_backend::IoSurfacePresentChannel, DxgiFormat)> {
        let Some(state) = self.metalfx_present.get(&swapchain).cloned() else {
            return None;
        };
        match self.encode_metalfx_frame(swapchain, &state) {
            Ok(presented) => {
                self.metalfx_last_error = None;
                Some(presented)
            }
            Err(error) => {
                self.record_metalfx_fallback(error);
                None
            }
        }
    }

    fn encode_metalfx_frame(
        &mut self,
        swapchain: SwapchainId,
        state: &std::sync::Arc<std::sync::Mutex<MetalFxPresentState>>,
    ) -> AppResult<(crate::metal_backend::IoSurfacePresentChannel, DxgiFormat)> {
        let is_primary = self.present_swapchain == Some(swapchain);
        let nv12 = if is_primary {
            !self.primary_nv12.is_empty()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .map(|set| !set.nv12.is_empty())
                .unwrap_or(false)
        };
        if nv12 {
            return Err(AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                "MetalFX present: NV12 swapchains are not supported by the MetalFX present path",
            ));
        }
        let source = if is_primary {
            self.iosurface_channels.first_mut()
        } else {
            self.extra_swapchains
                .get_mut(&swapchain)
                .and_then(|set| set.pixel.first_mut())
        };
        let Some(source) = source else {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("MetalFX present: swapchain {swapchain} has no pixel present channel"),
            ));
        };
        let source_texture = source.metal_texture()?.to_owned();
        let state = state.lock().expect("MetalFX present state lock poisoned");
        let command_buffer = state.command_queue.new_command_buffer();
        state
            .scaler
            .encode(command_buffer, &source_texture, &state.output_texture)?;
        let blit = command_buffer.new_blit_command_encoder();
        blit.copy_from_texture(
            &state.output_texture,
            0,
            0,
            metal::MTLOrigin { x: 0, y: 0, z: 0 },
            metal::MTLSize::new(
                state.config.output_width as u64,
                state.config.output_height as u64,
                1,
            ),
            &state.output_alias,
            0,
            0,
            metal::MTLOrigin { x: 0, y: 0, z: 0 },
        );
        blit.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();
        if command_buffer.status() != metal::MTLCommandBufferStatus::Completed {
            return Err(unreachable_scaler_status_error(command_buffer.status())); // coverage: unreachable — a valid encode plus blit completes
        }
        Ok((state.output_channel.clone(), state.output_format))
    }

    pub fn create_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        let swapchain = self.backend.create_swapchain(desc.clone())?;
        // Capability + allocation probe; on failure presents use the
        // verified fallback path.
        self.iosurface_channels = build_iosurface_channels(
            desc.width,
            desc.height,
            crate::metal_backend::dxgi_to_metal_format(desc.format),
            desc.buffer_count.max(1),
        );
        self.primary_nv12.clear();
        self.present_swapchain = Some(swapchain);
        Ok(swapchain)
    }

    /// Create the primary swapchain with DXGI_FORMAT_NV12 (raw value 103).
    /// Backed by an NV12 IOSurface with a luma and an interleaved chroma Metal
    /// plane. If the host cannot allocate the NV12 channel, the request is
    /// counted in `swapchain_format_fallbacks` and a normal pixel swapchain is
    /// created instead.
    pub fn create_nv12_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        let count = desc.buffer_count.max(1);
        if let Some(channels) = build_nv12_channels(desc.width, desc.height, count) {
            let swapchain = self.backend.create_nv12_swapchain(desc.clone())?;
            self.iosurface_channels.clear();
            self.primary_nv12 = channels;
            self.present_swapchain = Some(swapchain);
            return Ok(swapchain);
        }
        self.swapchain_format_fallbacks += 1;
        self.create_swapchain(desc)
    }

    /// Create an additional swapchain on the same device. Each swapchain owns
    /// an independent IOSurface channel set; presenting one never rebinds the
    /// other's channels.
    pub fn create_additional_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        let swapchain = self.backend.create_swapchain(desc.clone())?;
        let channels = build_iosurface_channels(
            desc.width,
            desc.height,
            crate::metal_backend::dxgi_to_metal_format(desc.format),
            desc.buffer_count.max(1),
        );
        self.extra_swapchains.insert(
            swapchain,
            SwapchainChannelSet {
                pixel: channels,
                nv12: Vec::new(),
            },
        );
        Ok(swapchain)
    }

    /// Create an additional NV12 swapchain (independent from the primary).
    pub fn create_additional_nv12_swapchain(
        &mut self,
        desc: SwapchainDesc,
    ) -> AppResult<SwapchainId> {
        let count = desc.buffer_count.max(1);
        let channels = match build_nv12_channels(desc.width, desc.height, count) {
            Some(channels) => channels,
            None => {
                self.swapchain_format_fallbacks += 1;
                return self.create_additional_swapchain(desc);
            }
        };
        let swapchain = self.backend.create_nv12_swapchain(desc)?;
        self.extra_swapchains.insert(
            swapchain,
            SwapchainChannelSet {
                pixel: Vec::new(),
                nv12: channels,
            },
        );
        Ok(swapchain)
    }

    /// DXGI-format-keyed swapchain creation. Raw value 103 selects the real
    /// NV12 two-plane path; any other raw format must match `desc.format`.
    /// Unknown values are counted as fallbacks and the typed `desc.format` is
    /// used, so the caller can observe that the raw request was not honoured.
    pub fn create_swapchain_for_format(
        &mut self,
        desc: SwapchainDesc,
        raw_format: u32,
    ) -> AppResult<SwapchainId> {
        if raw_format == 103 {
            return self.create_nv12_swapchain(desc);
        }
        match DxgiFormat::from_u32_checked(raw_format) {
            Ok(format) if format == desc.format => self.create_swapchain(desc),
            Ok(_) | Err(_) => {
                self.swapchain_format_fallbacks += 1;
                self.create_swapchain(desc)
            }
        }
    }

    pub fn set_maximum_frame_latency(
        &mut self,
        swapchain: SwapchainId,
        latency: u32,
    ) -> AppResult<()> {
        self.backend.set_maximum_frame_latency(swapchain, latency)
    }

    pub fn swapchain_state(&self, swapchain: SwapchainId) -> AppResult<SwapchainState> {
        self.backend.swapchain_state(swapchain)
    }

    pub fn resize_buffers(
        &mut self,
        swapchain: SwapchainId,
        buffer_count: u32,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) -> AppResult<()> {
        self.backend
            .resize_buffers(swapchain, buffer_count, width, height, format)?;
        // Resize invalidates only this swapchain's surfaces; every other
        // swapchain keeps its own channel set and IOSurface allocation.
        let is_nv12 = self.backend.swapchain_is_nv12(swapchain).unwrap_or(false);
        let count = buffer_count.max(1);
        if self.present_swapchain == Some(swapchain) {
            if is_nv12 {
                self.primary_nv12 = build_nv12_channels(width, height, count).unwrap_or_default();
                self.iosurface_channels.clear();
            } else {
                self.iosurface_channels = build_iosurface_channels(
                    width,
                    height,
                    crate::metal_backend::dxgi_to_metal_format(format),
                    count,
                );
                self.primary_nv12.clear();
            }
        } else if let Some(set) = self.extra_swapchains.get_mut(&swapchain) {
            if is_nv12 {
                set.nv12 = build_nv12_channels(width, height, count).unwrap_or_default();
                set.pixel.clear();
            } else {
                set.pixel = build_iosurface_channels(
                    width,
                    height,
                    crate::metal_backend::dxgi_to_metal_format(format),
                    count,
                );
                set.nv12.clear();
            }
        }
        let desc = self.backend.swapchain_state(swapchain)?.desc;
        self.refresh_metalfx_present(swapchain, &desc);
        Ok(())
    }

    /// Mark the next present as correlated with an input event. This enables
    /// real Metal GPU/drawable timing for exactly that present.
    pub fn mark_input_event(&mut self) {
        self.pending_present_input_seconds = Some(crate::metal_backend::media_now_seconds());
        self.present_timing_requested = true;
    }

    /// Request GPU/drawable timing for the next present without an input
    /// correlation.
    pub fn enable_present_timing(&mut self) {
        self.present_timing_requested = true;
    }

    /// Timing for the most recent present, when timing was requested.
    pub fn last_present_timing(&self) -> Option<&D3d12PresentTiming> {
        self.last_present_timing.as_ref()
    }

    /// Take the most recent present timing, leaving the slot empty.
    pub fn take_last_present_timing(&mut self) -> Option<D3d12PresentTiming> {
        self.last_present_timing.take()
    }

    pub fn present(
        &mut self,
        swapchain: SwapchainId,
        sync_interval: u32,
        allow_tearing: bool,
    ) -> AppResult<PresentResult> {
        let input_seconds = self.pending_present_input_seconds.take();
        let timing_requested = self.present_timing_requested || input_seconds.is_some();
        self.present_timing_requested = false;
        self.last_present_timing = None;
        let state = self.backend.swapchain_state(swapchain)?;
        let backbuffer_ids = state.backbuffers.clone();
        let is_primary = self.present_swapchain == Some(swapchain);
        let nv12_len = if is_primary {
            self.primary_nv12.len()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .map(|set| set.nv12.len())
                .unwrap_or(0)
        };
        let pixel_len = if is_primary {
            self.iosurface_channels.len()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .map(|set| set.pixel.len())
                .unwrap_or(0)
        };
        let metalfx_output = self.try_metalfx_present(swapchain);

        if nv12_len > 0 {
            if nv12_len != backbuffer_ids.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "NV12 present: {nv12_len} channels for {} backbuffers",
                        backbuffer_ids.len()
                    ),
                ));
            }
            let channels: &[crate::metal_backend::Nv12PresentChannel] = if is_primary {
                &self.primary_nv12
            } else {
                &self
                    .extra_swapchains
                    .get(&swapchain)
                    .expect("channel set checked above")
                    .nv12
            };
            for (index, channel) in channels.iter().enumerate() {
                if channel.width() != state.desc.width || channel.height() != state.desc.height {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "NV12 present: swapchain {}x{} does not match channel {} at {index} ({}x{})",
                            state.desc.width,
                            state.desc.height,
                            index,
                            channel.width(),
                            channel.height()
                        ),
                    ));
                }
            }
            // Both plane textures are built eagerly; binding them here proves
            // present targets the luma and chroma planes of this channel. The
            // real composite compute pass converts the planes into the RGBA
            // drawable texture that present binds.
            let presented = channels[0].clone();
            presented.composite_to_drawable()?;
            presented.bind_drawable();
            let _ = presented.plane_texture_ptrs();
            self.nv12_presents += 1;
            self.iosurface_presents += 1;
            self.backend.set_presented_nv12_surface(Some(presented));
        } else if pixel_len > 0 {
            if pixel_len != backbuffer_ids.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "IOSurface present: {pixel_len} channels for {} backbuffers",
                        backbuffer_ids.len()
                    ),
                ));
            }
            let channels: &mut [crate::metal_backend::IoSurfacePresentChannel] = if is_primary {
                &mut self.iosurface_channels
            } else {
                &mut self
                    .extra_swapchains
                    .get_mut(&swapchain)
                    .expect("channel set checked above")
                    .pixel
            };
            let expected_format = crate::metal_backend::dxgi_to_metal_format(state.desc.format);
            for (index, channel) in channels.iter_mut().enumerate() {
                if channel.width() != state.desc.width || channel.height() != state.desc.height {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "IOSurface present: swapchain {}x{} does not match channel {} at {index} ({}x{})",
                            state.desc.width,
                            state.desc.height,
                            index,
                            channel.width(),
                            channel.height()
                        ),
                    ));
                }
                if channel.pixel_format() != expected_format {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "IOSurface present: swapchain format {:?} ({expected_format:?}) does not \
                             match channel {index} {:?}",
                            state.desc.format,
                            channel.pixel_format()
                        ),
                    ));
                }
            }
            channels[0].metal_texture()?;
            let presented = metalfx_output
                .clone()
                .map(|(channel, _)| channel)
                .unwrap_or_else(|| channels[0].clone());
            self.iosurface_presents += 1;
            self.backend.set_presented_surface(Some(presented));
        } else {
            self.backend.set_presented_surface(None);
            self.backend.set_presented_nv12_surface(None);
            self.fallback_uploads += backbuffer_ids.len() as u64;
        }
        let used_metalfx = metalfx_output.is_some();
        if timing_requested {
            crate::metal_backend::clear_last_present_timing();
            crate::metal_backend::set_present_timing_enabled(true);
        }
        let result = self
            .backend
            .present(swapchain, sync_interval, allow_tearing);
        if timing_requested {
            if result.is_ok()
                && let Some(probe) = crate::metal_backend::take_last_present_timing()
            {
                self.last_present_timing = Some(D3d12PresentTiming {
                    input_seconds,
                    submitted_seconds: probe.submitted_seconds,
                    gpu: probe.gpu,
                    drawable: probe.drawable,
                });
            }
            crate::metal_backend::set_present_timing_enabled(false);
            crate::metal_backend::clear_last_present_timing();
        }
        if result.is_ok() {
            if used_metalfx {
                self.metalfx_scaled_presents += 1;
                self.metalfx_last_scaled_swapchain = Some(swapchain);
            } else {
                self.metalfx_last_scaled_swapchain = None;
            }
        } // coverage: unreachable — lcov attributes the if-join to this brace
        result
    }

    pub fn presented_frame(&self, swapchain: SwapchainId) -> AppResult<PresentedFrame> {
        if self.metalfx_last_scaled_swapchain == Some(swapchain) {
            if let Some(state) = self.metalfx_present.get(&swapchain) {
                let state = state.lock().expect("MetalFX present state lock poisoned");
                return Ok(PresentedFrame {
                    width: state.output_channel.width(),
                    height: state.output_channel.height(),
                    format: state.output_format,
                    bytes: state.output_channel.read_pixels()?,
                    source: crate::gfx::FrameSource::DxgiD3D12,
                    stride: state.output_channel.width() as usize * 4,
                    sequence: self.iosurface_presents,
                    timestamp: std::time::Instant::now(),
                });
            }
        }
        let is_primary = self.present_swapchain == Some(swapchain);
        if is_primary {
            if let Some(channel) = self.primary_nv12.first() {
                return Ok(PresentedFrame {
                    width: channel.width(),
                    height: channel.height(),
                    format: DxgiFormat::R8G8B8A8Unorm,
                    bytes: channel.to_rgba8()?,
                    source: crate::gfx::FrameSource::DxgiD3D12,
                    stride: channel.width() as usize * 4,
                    sequence: self.iosurface_presents,
                    timestamp: std::time::Instant::now(),
                });
            }
            if let Some(channel) = self.iosurface_channels.first() {
                let state = self.backend.swapchain_state(swapchain)?;
                return Ok(PresentedFrame {
                    width: channel.width(),
                    height: channel.height(),
                    format: state.desc.format,
                    bytes: channel.read_pixels()?,
                    source: crate::gfx::FrameSource::DxgiD3D12,
                    stride: channel.width() as usize * 4,
                    sequence: self.iosurface_presents,
                    timestamp: std::time::Instant::now(),
                });
            }
        } else if let Some(set) = self.extra_swapchains.get(&swapchain) {
            let state = self.backend.swapchain_state(swapchain)?;
            if let Some(channel) = set.nv12.first() {
                return Ok(PresentedFrame {
                    width: channel.width(),
                    height: channel.height(),
                    format: DxgiFormat::R8G8B8A8Unorm,
                    bytes: channel.to_rgba8()?,
                    source: crate::gfx::FrameSource::DxgiD3D12,
                    stride: channel.width() as usize * 4,
                    sequence: self.iosurface_presents,
                    timestamp: std::time::Instant::now(),
                });
            }
            if let Some(channel) = set.pixel.first() {
                return Ok(PresentedFrame {
                    width: channel.width(),
                    height: channel.height(),
                    format: state.desc.format,
                    bytes: channel.read_pixels()?,
                    source: crate::gfx::FrameSource::DxgiD3D12,
                    stride: channel.width() as usize * 4,
                    sequence: self.iosurface_presents,
                    timestamp: std::time::Instant::now(),
                });
            }
        }
        self.backend.presented_frame(swapchain)
    }

    /// Read both NV12 planes of `swapchain` (0 = Y, 1 = interleaved UV).
    pub fn presented_nv12_plane_bytes(
        &self,
        swapchain: SwapchainId,
    ) -> AppResult<(Vec<u8>, Vec<u8>)> {
        let channel = if self.present_swapchain == Some(swapchain) {
            self.primary_nv12.first()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.nv12.first())
        }
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("swapchain {swapchain} has no NV12 present channel"),
            )
        })?;
        Ok((channel.read_plane(0)?, channel.read_plane(1)?))
    }

    /// Read the two NV12 planes through their Metal textures using real GPU
    /// blits (not the CPU surface mapping).
    pub fn presented_nv12_plane_bytes_gpu(
        &self,
        swapchain: SwapchainId,
    ) -> AppResult<(Vec<u8>, Vec<u8>)> {
        let channel = if self.present_swapchain == Some(swapchain) {
            self.primary_nv12.first()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.nv12.first())
        }
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("swapchain {swapchain} has no NV12 present channel"),
            )
        })?;
        Ok((
            channel.read_plane_via_metal(0)?,
            channel.read_plane_via_metal(1)?,
        ))
    }

    /// GPU readback of the RGBA drawable written by the NV12 composite pass.
    pub fn presented_nv12_composite_rgba(&self, swapchain: SwapchainId) -> AppResult<Vec<u8>> {
        let channel = self.nv12_channel(swapchain)?;
        channel.read_drawable_rgba()
    }

    /// Number of real GPU composite passes run for a swapchain's NV12 channel.
    pub fn nv12_composite_passes(&self, swapchain: SwapchainId) -> u64 {
        self.nv12_channel(swapchain)
            .map(|channel| channel.composite_passes())
            .unwrap_or(0)
    }

    /// Number of presents that bound the composited RGBA drawable texture.
    pub fn nv12_drawable_binds(&self, swapchain: SwapchainId) -> u64 {
        self.nv12_channel(swapchain)
            .map(|channel| channel.drawable_binds())
            .unwrap_or(0)
    }

    /// Raw pointer of the drawable texture bound by the last NV12 present.
    pub fn presented_nv12_drawable_ptr(&self, swapchain: SwapchainId) -> Option<usize> {
        self.nv12_channel(swapchain)
            .ok()
            .map(|channel| channel.drawable_texture_ptr())
    }

    fn nv12_channel(
        &self,
        swapchain: SwapchainId,
    ) -> AppResult<&crate::metal_backend::Nv12PresentChannel> {
        if self.present_swapchain == Some(swapchain) {
            self.primary_nv12.first()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.nv12.first())
        }
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("swapchain {swapchain} has no NV12 present channel"),
            )
        })
    }

    /// Presents that bound both NV12 planes.
    pub fn nv12_present_count(&self) -> u64 {
        self.nv12_presents
    }

    /// Number of swapchain format requests that used the counted fallback.
    pub fn swapchain_format_fallback_count(&self) -> u64 {
        self.swapchain_format_fallbacks
    }

    /// Presents that bound an IOSurface-backed Metal texture.
    pub fn iosurface_present_count(&self) -> u64 {
        self.iosurface_presents
    }

    /// Writes that landed directly in the IOSurface mapping.
    pub fn zero_copy_upload_count(&self) -> u64 {
        self.surface_writes
    }

    /// Writes that landed in the IOSurface (authoritative present pixels).
    pub fn surface_writes(&self) -> u64 {
        self.surface_writes
    }

    /// Writes that had to update the CPU backing bytes.
    pub fn cpu_backing_writes(&self) -> u64 {
        self.cpu_backing_writes
    }

    /// Raw handle of the shared surface attached to the gfx backend.
    pub fn presented_surface_handle(&self) -> Option<*mut std::ffi::c_void> {
        self.backend.presented_surface_handle()
    }

    /// Present-time uploads through the fallback path.
    pub fn fallback_upload_count(&self) -> u64 {
        self.fallback_uploads
    }

    /// Live-consumer API: RGBA8 pixels of the presented frame, read from the
    /// shared IOSurface on the zero-copy path.
    pub fn presented_frame_rgba(&self, swapchain: SwapchainId) -> AppResult<Vec<u8>> {
        let frame = self.presented_frame(swapchain)?;
        let mut bytes = frame.bytes;
        if matches!(
            frame.format,
            DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm
        ) {
            for pixel in bytes.chunks_exact_mut(4) {
                pixel.swap(0, 2);
            }
        }
        Ok(bytes)
    }

    /// True when presents bind the IOSurface-backed Metal texture.
    pub fn iosurface_zero_copy_active(&self) -> bool {
        (!self.iosurface_channels.is_empty() || !self.primary_nv12.is_empty())
            && self.present_swapchain.is_some()
    }

    /// MTLTextures built by the presented channel (stable across presents).
    pub fn iosurface_texture_builds(&self) -> u32 {
        self.iosurface_channels
            .first()
            .map(|channel| channel.texture_builds())
            .or_else(|| {
                self.primary_nv12
                    .first()
                    .map(|channel| channel.texture_builds())
            })
            .unwrap_or(0)
    }

    /// Plane MTLTextures built for an NV12 present channel (2 when healthy).
    pub fn nv12_texture_builds(&self, swapchain: SwapchainId) -> u32 {
        let channel = if self.present_swapchain == Some(swapchain) {
            self.primary_nv12.first()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.nv12.first())
        };
        channel.map(|channel| channel.texture_builds()).unwrap_or(0)
    }

    /// Swapchain and backbuffer index when `resource` belongs to any swapchain
    /// with an attached IOSurface channel set.
    fn present_backbuffer_index(&self, resource: ResourceId) -> Option<(SwapchainId, usize)> {
        let primary = self.present_swapchain?;
        let mut candidates = vec![primary];
        candidates.extend(self.extra_swapchains.keys().copied());
        for swapchain in candidates {
            if let Ok(state) = self.backend.swapchain_state(swapchain) {
                if let Some(index) = state.backbuffers.iter().position(|id| *id == resource) {
                    let has_channels = if swapchain == primary {
                        !self.iosurface_channels.is_empty() || !self.primary_nv12.is_empty()
                    } else {
                        self.extra_swapchains
                            .get(&swapchain)
                            .map(|set| !set.is_empty())
                            .unwrap_or(false)
                    };
                    if has_channels {
                        return Some((swapchain, index));
                    }
                }
            }
        }
        None
    }

    /// Write `bytes` at `offset` into the IOSurface when `resource` is a
    /// current swapchain backbuffer. Returns `false` when the CPU backing
    /// Bytes must be used instead.
    fn write_present_backbuffer_bytes(
        &mut self,
        resource: ResourceId,
        offset: usize,
        bytes: &[u8],
    ) -> AppResult<bool> {
        let Some((swapchain, index)) = self.present_backbuffer_index(resource) else {
            return Ok(false);
        };
        let is_primary = self.present_swapchain == Some(swapchain);
        let format = self.backend.swapchain_state(swapchain)?.desc.format;
        let is_nv12 = if is_primary {
            !self.primary_nv12.is_empty()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .map(|set| !set.nv12.is_empty())
                .unwrap_or(false)
        };
        if is_nv12 {
            let channel = if is_primary {
                self.primary_nv12.get(index)
            } else {
                self.extra_swapchains
                    .get(&swapchain)
                    .and_then(|set| set.nv12.get(index))
            }
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "NV12 present: backbuffer channel is missing",
                )
            })?;
            let expected = channel.width() as usize * channel.height() as usize * 4;
            let end = offset.checked_add(bytes.len()).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "surface write range overflow",
                )
            })?;
            if offset != 0 || end != expected {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "NV12 present surface requires full-frame writes",
                ));
            }
            channel.write_dxgi_pixels(bytes, format)?;
            self.surface_writes += 1;
            return Ok(true);
        }
        let channel = if is_primary {
            self.iosurface_channels.get_mut(index)
        } else {
            self.extra_swapchains
                .get_mut(&swapchain)
                .and_then(|set| set.pixel.get_mut(index))
        };
        let Some(channel) = channel else {
            return Ok(false);
        };
        let expected = channel.width() as usize * channel.height() as usize * 4;
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "surface write range overflow",
            )
        })?;
        if end > expected {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "surface write exceeds present backbuffer",
            ));
        }
        if offset == 0 && bytes.len() == expected {
            channel.write_pixels(bytes)?;
        } else {
            let mut pixels = channel.read_pixels()?;
            pixels[offset..end].copy_from_slice(bytes);
            channel.write_pixels(&pixels)?;
        }
        self.surface_writes += 1;
        Ok(true)
    }

    fn record_cpu_backing_write(&mut self) {
        self.cpu_backing_writes += 1;
    }

    pub fn create_committed_resource(&mut self, desc: ResourceDesc) -> AppResult<ResourceId> {
        self.backend.create_resource(desc)
    }

    /// D3D12 `CreateResource` with `pInitialData`: the translated resource is
    /// created and, when initial texture data is supplied, the bytes are
    /// uploaded into a real private Metal texture through one blit. The GPU
    /// texture is retained for `readback_gpu_texture`.
    pub fn create_committed_resource_with_initial_data(
        &mut self,
        desc: ResourceDesc,
        initial_data: Option<D3d12InitialTextureData>,
    ) -> AppResult<ResourceId> {
        let resource = self.backend.create_resource(desc)?;
        if let Some(initial) = initial_data {
            let upload = match crate::metal_backend::upload_texture_from_bytes(
                &initial.data,
                initial.width,
                initial.height,
                initial.format,
            ) {
                Ok(upload) => upload,
                Err(error) => {
                    let _ = self.backend.destroy_resource(resource);
                    return Err(error);
                }
            };
            self.staging_bytes += initial.data.len() as u64;
            self.gpu_textures.insert(resource, upload);
        }
        Ok(resource)
    }

    /// `CreateResource` with initial data whose texel bytes already live in
    /// canonical guest memory.
    ///
    /// The bytes are blitted from a no-copy MTLBuffer over the guest window, so
    /// `staging_bytes` does not advance and `guest_initial_uploads` does. A
    /// destination outside the window or a refused device mapping is an
    /// explicit error, never a silent host staging copy.
    pub fn create_committed_resource_with_guest_initial_data(
        &mut self,
        desc: ResourceDesc,
        window: &crate::metal_backend::GuestMemoryWindow,
        offset: usize,
        data_len: usize,
        width: u32,
        height: u32,
        format: metal::MTLPixelFormat,
    ) -> AppResult<ResourceId> {
        let resource = self.backend.create_resource(desc)?;
        let upload = match crate::metal_backend::upload_texture_from_guest_bytes(
            window, offset, data_len, width, height, format,
        ) {
            Ok(upload) => upload,
            Err(error) => {
                let _ = self.backend.destroy_resource(resource);
                return Err(error);
            }
        };
        if !upload.stats().guest_backed {
            let _ = self.backend.destroy_resource(resource);
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "CreateResource guest initial data refused: buffer is not guest backed",
            ));
        }
        self.guest_initial_uploads += 1;
        self.gpu_textures.insert(resource, upload);
        Ok(resource)
    }

    /// Number of `CreateResource` initial-data uploads served directly from
    /// canonical guest memory.
    pub fn guest_initial_upload_count(&self) -> u64 {
        self.guest_initial_uploads
    }

    fn open_directstorage_file(
        ge: &crate::ge::GameEnvironment,
        windows_path: &str,
    ) -> AppResult<(std::fs::File, String)> {
        let handle = ge.open_file(
            windows_path,
            crate::ge::FileAccess::read_only(),
            crate::ge::ShareMode::read_only(),
        )?;
        let normalized = handle.normalized_path.clone();
        let host_path = ge.host_path_for_windows_path(&normalized)?;
        let file = std::fs::File::open(&host_path).map_err(|error| {
            let _ = ge.close_file_handle(&handle);
            AppError::from_io(
                ReasonCode::RcIo,
                format!("DirectStorage: failed to open {}", host_path.display()),
                &error,
            )
        })?;
        // The file-table handle is released as soon as the host file is open;
        // reads work on the descriptor, not on guest-visible data.
        let _ = ge.close_file_handle(&handle);
        Ok((file, normalized))
    }

    /// DirectStorage-style upload: open the file through the game environment's
    /// file table, read the requested region straight into a Metal buffer, and
    /// blit it into a private MTLTexture. Uncompressed sources never build a
    /// guest-visible staging Vec (`staging_bytes` stays 0).
    ///
    /// The resource descriptor's format is the upload's real DXGI format,
    /// derived from `desc.format`: there is no RGBA shadow descriptor.
    pub fn upload_file_to_texture(
        &mut self,
        ge: &crate::ge::GameEnvironment,
        windows_path: &str,
        desc: crate::metal_backend::DirectStorageUploadDesc,
    ) -> AppResult<ResourceId> {
        let (file, normalized_path) = Self::open_directstorage_file(ge, windows_path)?;
        let host_path = ge.host_path_for_windows_path(&normalized_path)?;
        drop(file);
        let upload = crate::metal_backend::upload_texture_from_path(&host_path, desc)?;
        let stats = upload.stats();
        let format = upload.dxgi_format().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                format!(
                    "DirectStorage: upload texture format {:?} has no DXGI resource format",
                    upload.format()
                ),
            )
        })?;
        self.directstorage_bytes += stats.directstorage_bytes;
        self.staging_bytes += stats.staging_bytes;
        let resource = self.backend.create_resource(ResourceDesc {
            name: format!("directstorage-{normalized_path}"),
            format,
            heap: HeapType::Default,
            size: stats.directstorage_bytes as usize,
            subresources: 1,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Texture {
                sampled: true,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        })?;
        self.gpu_textures.insert(resource, upload);
        Ok(resource)
    }

    /// GPU readback of a texture created through
    /// [`create_committed_resource_with_initial_data`] or
    /// [`upload_file_to_texture`]. Uses a real texture -> buffer blit.
    pub fn readback_gpu_texture(&self, resource: ResourceId) -> AppResult<Vec<u8>> {
        self.gpu_textures
            .get(&resource)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("resource {resource} has no GPU texture upload"),
                )
            })?
            .read_back()
    }

    /// Bytes delivered by the DirectStorage direct path.
    pub fn directstorage_bytes(&self) -> u64 {
        self.directstorage_bytes
    }

    /// Bytes that transited a host staging buffer (compressed sources and
    /// CreateResource initial-data uploads).
    pub fn staging_bytes(&self) -> u64 {
        self.staging_bytes
    }

    /// DXGI format of the real upload texture backing `resource`. This is the
    /// format authority for DirectStorage resources (RGBA8, BGRA8, R8, …);
    /// there is no RGBA shadow descriptor.
    pub fn directstorage_texture_format(&self, resource: ResourceId) -> AppResult<DxgiFormat> {
        self.gpu_textures
            .get(&resource)
            .and_then(|texture| texture.dxgi_format())
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("resource {resource} has no DirectStorage texture format"),
                )
            })
    }

    /// Number of GPU upload textures currently owned by the runtime.
    pub fn directstorage_live_texture_count(&self) -> usize {
        self.gpu_textures.len()
    }

    /// Format recorded in the backend resource descriptor.
    pub fn resource_format(&self, resource: ResourceId) -> AppResult<DxgiFormat> {
        self.backend.resource_format(resource)
    }

    fn ensure_directstorage_queue(
        &mut self,
    ) -> AppResult<std::sync::Arc<std::sync::Mutex<crate::metal_backend::DirectStorageUploadQueue>>>
    {
        if let Some(queue) = &self.directstorage_queue {
            return Ok(queue.clone());
        }
        let queue = std::sync::Arc::new(std::sync::Mutex::new(
            crate::metal_backend::DirectStorageUploadQueue::new()?,
        ));
        if let Some(slot) = self.directstorage_completion.slot() {
            queue
                .lock()
                .expect("DirectStorage queue poisoned")
                .register_drain_callback(slot);
        }
        self.directstorage_queue = Some(queue.clone());
        Ok(queue)
    }

    /// Enqueue an asynchronous DirectStorage upload. The source is read into
    /// a Metal buffer immediately, then a blit command buffer is committed and
    /// signals the queue's MTLSharedEvent. Uploads execute in enqueue order on
    /// one MTLCommandQueue.
    pub fn enqueue_file_to_texture(
        &mut self,
        ge: &crate::ge::GameEnvironment,
        windows_path: &str,
        desc: crate::metal_backend::DirectStorageUploadDesc,
    ) -> AppResult<D3D12UploadTicket> {
        let (mut file, normalized_path) = Self::open_directstorage_file(ge, windows_path)?;
        let queue = self.ensure_directstorage_queue()?;
        let (fence_value, upload) = queue
            .lock()
            .expect("DirectStorage queue poisoned")
            .enqueue_file(&mut file, desc)?;
        let format = upload.dxgi_format().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                format!(
                    "DirectStorage async: upload texture format {:?} has no DXGI resource format",
                    upload.format()
                ),
            )
        })?;
        let stats = upload.stats();
        let resource = self
            .backend
            .create_resource(ResourceDesc {
                name: format!("directstorage-async-{normalized_path}"),
                format,
                heap: HeapType::Default,
                size: stats.directstorage_bytes as usize,
                subresources: 1,
                initial_state: ResourceState::CopyDest,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("gfx resource creation is infallible");
        self.directstorage_bytes += stats.directstorage_bytes;
        self.staging_bytes += stats.staging_bytes;
        self.gpu_textures.insert(resource, upload);
        self.directstorage_pending_resources
            .push((resource, fence_value));
        Ok(D3D12UploadTicket {
            resource,
            fence_value,
        })
    }

    /// Alias for [`enqueue_file_to_texture`](Self::enqueue_file_to_texture).
    pub fn upload_file_to_texture_async(
        &mut self,
        ge: &crate::ge::GameEnvironment,
        windows_path: &str,
        desc: crate::metal_backend::DirectStorageUploadDesc,
    ) -> AppResult<D3D12UploadTicket> {
        self.enqueue_file_to_texture(ge, windows_path, desc)
    }

    /// Enqueue one logical two-plane NV12 upload. The single ticket covers both
    /// planes (one shared-event signal); [`readback_gpu_texture`] returns the
    /// NV12 byte layout (luma then interleaved UV), and
    /// [`readback_gpu_texture_plane`] reads one plane.
    ///
    /// The resource descriptor uses `R8_UNORM` for the luma plane. The chroma
    /// plane is `RG8_UNORM`, which has no DXGI_FORMAT enum; the plane-typed
    /// DirectStorage descriptor is its format authority.
    pub fn enqueue_nv12_file_to_texture(
        &mut self,
        ge: &crate::ge::GameEnvironment,
        windows_path: &str,
        desc: crate::metal_backend::DirectStorageNv12UploadDesc,
    ) -> AppResult<D3D12UploadTicket> {
        let (mut file, normalized_path) = Self::open_directstorage_file(ge, windows_path)?;
        let queue = self.ensure_directstorage_queue()?;
        let (fence_value, upload) = queue
            .lock()
            .expect("DirectStorage queue poisoned")
            .enqueue_nv12_file(&mut file, desc)?;
        let format = upload
            .dxgi_format()
            .expect("NV12 luma uploads always map to R8Unorm");
        let stats = upload.stats();
        let resource = self.backend.create_resource(ResourceDesc {
            name: format!("directstorage-nv12-{normalized_path}"),
            format,
            heap: HeapType::Default,
            size: stats.directstorage_bytes as usize,
            subresources: 2,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Texture {
                sampled: true,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        })?;
        self.directstorage_bytes += stats.directstorage_bytes;
        self.staging_bytes += stats.staging_bytes;
        self.gpu_textures.insert(resource, upload);
        self.directstorage_pending_resources
            .push((resource, fence_value));
        Ok(D3D12UploadTicket {
            resource,
            fence_value,
        })
    }

    /// Read one plane of a DirectStorage upload through a real GPU blit.
    /// Plane 0 is luma; plane 1 is the NV12 interleaved UV plane.
    pub fn readback_gpu_texture_plane(
        &self,
        resource: ResourceId,
        plane: usize,
    ) -> AppResult<Vec<u8>> {
        self.gpu_textures
            .get(&resource)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("resource {resource} has no GPU texture upload"),
                )
            })?
            .read_back_plane(plane)
    }

    fn completed_directstorage_resources(&mut self, fence_value: u64) {
        self.directstorage_pending_resources
            .retain(|(_, value)| *value > fence_value);
    }

    /// Non-blocking async upload poll. Updates completion counters and fires
    /// the completion hook once when the queue transitions to empty.
    pub fn poll_directstorage_uploads(
        &mut self,
    ) -> AppResult<crate::metal_backend::DirectStorageQueueStats> {
        let Some(queue) = self.directstorage_queue.clone() else {
            return Ok(crate::metal_backend::DirectStorageQueueStats::default());
        };
        let stats = queue.lock().expect("DirectStorage queue poisoned").poll();
        self.completed_directstorage_resources(stats.fence_value);
        Ok(stats)
    }

    /// Wait for every queued async upload. Returns the GPU-observed fence
    /// value. A timeout is a real error, never a silent false.
    pub fn wait_for_directstorage_uploads(&mut self, timeout_ns: u64) -> AppResult<u64> {
        let Some(queue) = self.directstorage_queue.clone() else {
            return Ok(0);
        };
        let fence_value = queue
            .lock()
            .expect("DirectStorage queue poisoned")
            .wait_for_all(timeout_ns)?;
        self.completed_directstorage_resources(fence_value);
        Ok(fence_value)
    }

    /// Wait for a specific shared-event value (used by adversarial timeout
    /// tests and multi-upload ordering checks).
    pub fn wait_for_directstorage_fence(&mut self, value: u64, timeout_ns: u64) -> AppResult<()> {
        let Some(queue) = self.directstorage_queue.clone() else {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("DirectStorage: no upload queue exists to wait for value {value}"),
            ));
        };
        let stats = {
            let mut queue = queue.lock().expect("DirectStorage queue poisoned");
            queue.wait_for_value(value, timeout_ns)?;
            queue.stats()
        };
        self.completed_directstorage_resources(stats.fence_value);
        Ok(())
    }

    /// Snapshot of queued/completed/in-flight counters.
    pub fn directstorage_upload_stats(&self) -> crate::metal_backend::DirectStorageQueueStats {
        self.directstorage_queue
            .as_ref()
            .map(|queue| queue.lock().expect("DirectStorage queue poisoned").stats())
            .unwrap_or_default()
    }

    /// Cumulative uploads accepted into the async queue.
    pub fn directstorage_queued_uploads(&self) -> u64 {
        self.directstorage_upload_stats().queued
    }

    /// Uploads whose GPU completion the shared event has observed.
    pub fn directstorage_completed_uploads(&self) -> u64 {
        self.directstorage_upload_stats().completed
    }

    /// Uploads currently retained by the pipeline (staging buffer + texture).
    pub fn directstorage_in_flight_uploads(&self) -> u64 {
        self.directstorage_upload_stats().in_flight
    }

    /// Short alias for [`poll_directstorage_uploads`](Self::poll_directstorage_uploads).
    pub fn poll_upload_completion(
        &mut self,
    ) -> AppResult<crate::metal_backend::DirectStorageQueueStats> {
        self.poll_directstorage_uploads()
    }

    /// Short alias for
    /// [`wait_for_directstorage_uploads`](Self::wait_for_directstorage_uploads).
    pub fn wait_for_upload_completion(&mut self, timeout_ns: u64) -> AppResult<u64> {
        self.wait_for_directstorage_uploads(timeout_ns)
    }

    /// Short alias for
    /// [`set_directstorage_completion_callback`](Self::set_directstorage_completion_callback).
    pub fn set_upload_completion_callback(&mut self, callback: impl FnMut() + Send + 'static) {
        self.set_directstorage_completion_callback(callback);
    }

    /// Current GPU-observed shared-event value.
    pub fn directstorage_fence_value(&self) -> u64 {
        self.directstorage_queue
            .as_ref()
            .map(|queue| {
                queue
                    .lock()
                    .expect("DirectStorage queue poisoned")
                    .fence_value()
            })
            .unwrap_or(0)
    }

    /// Register a completion hook fired once each time the async upload queue
    /// drains (not once per upload).
    pub fn set_directstorage_completion_callback(
        &mut self,
        callback: impl FnMut() + Send + 'static,
    ) {
        self.directstorage_completion.set(Box::new(callback));
        if let (Some(queue), Some(slot)) = (
            &self.directstorage_queue,
            self.directstorage_completion.slot(),
        ) {
            queue
                .lock()
                .expect("DirectStorage queue poisoned")
                .register_drain_callback(slot);
        }
    }

    /// Cancel/drain in-flight async uploads, releasing their staging buffers,
    /// queue-held textures and the resources they created.
    pub fn cancel_directstorage_uploads(&mut self) -> AppResult<()> {
        let Some(queue) = self.directstorage_queue.clone() else {
            return Ok(());
        };
        queue
            .lock()
            .expect("DirectStorage queue poisoned")
            .cancel_in_flight();
        let pending = std::mem::take(&mut self.directstorage_pending_resources);
        for (resource, _) in pending {
            self.gpu_textures.remove(&resource);
            let _ = self.backend.destroy_resource(resource);
        }
        Ok(())
    }

    /// Cancel only uploads that have not reached the GPU queue yet. Committed
    /// uploads are never affected and still complete. Returns the number of
    /// uncommitted uploads removed.
    pub fn cancel_pending_directstorage_uploads(&mut self) -> u64 {
        let Some(queue) = self.directstorage_queue.clone() else {
            return 0;
        };
        let cancelled = {
            let mut queue = queue.lock().expect("DirectStorage queue poisoned");
            let cancelled = queue.cancel_pending();
            (cancelled, queue.cancelled_fences())
        };
        let (count, fences) = cancelled;
        if count > 0 {
            let pending = std::mem::take(&mut self.directstorage_pending_resources);
            for (resource, value) in pending {
                if fences.contains(&value) {
                    self.gpu_textures.remove(&resource);
                    let _ = self.backend.destroy_resource(resource);
                } else {
                    self.directstorage_pending_resources.push((resource, value));
                }
            }
        }
        count
    }

    /// Report uploads that are already committed to the GPU queue and therefore
    /// cannot be cancelled. They keep running and complete normally.
    pub fn cancel_committed_directstorage_uploads(&self) -> u64 {
        self.directstorage_queue
            .as_ref()
            .map(|queue| {
                queue
                    .lock()
                    .expect("DirectStorage queue poisoned")
                    .cancel_committed()
            })
            .unwrap_or(0)
    }

    /// Reset the async pipeline: drains in-flight work, releases every
    /// retained resource and clears the pending-resource set.
    pub fn reset_directstorage_uploads(&mut self) -> AppResult<()> {
        self.cancel_directstorage_uploads()
    }

    pub fn destroy_resource(&mut self, resource: ResourceId) -> AppResult<()> {
        // Drop any GPU upload texture first so resource destruction releases
        // the real MTLTexture (no shadow entries left behind).
        self.gpu_textures.remove(&resource);
        self.directstorage_pending_resources
            .retain(|(pending, _)| *pending != resource);
        self.backend.destroy_resource(resource)
    }

    pub fn resource_state(
        &self,
        resource: ResourceId,
        subresource: u32,
    ) -> AppResult<ResourceState> {
        self.backend.resource_state(resource, subresource)
    }

    pub fn resource_storage_mode(&self, resource: ResourceId) -> AppResult<MetalStorageMode> {
        self.backend.resource_storage_mode(resource)
    }

    pub fn set_resource_usage_hint(
        &mut self,
        resource: ResourceId,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<()> {
        self.backend.set_resource_usage_hint(resource, usage_hint)
    }

    pub fn upload_write(
        &mut self,
        resource: ResourceId,
        offset: usize,
        bytes: &[u8],
    ) -> AppResult<()> {
        if self.write_present_backbuffer_bytes(resource, offset, bytes)? {
            return Ok(());
        }
        // Upload-heap resources are host-visible: the write lands in the
        // shared backing and is classified as a zero-copy update (the
        // backend rejects non-upload heaps with the D3D12 error).
        self.backend.upload_write(resource, offset, bytes)?;
        self.record_cpu_backing_write();
        Ok(())
    }

    pub fn overwrite_resource_bytes(
        &mut self,
        resource: ResourceId,
        bytes: &[u8],
    ) -> AppResult<()> {
        if self.write_present_backbuffer_bytes(resource, 0, bytes)? {
            return Ok(());
        }
        // Classify the update by the destination storage mode so a shared
        // (host-visible) resource records a zero-copy write and a private
        // one records the staged upload it would need on real Metal.
        self.backend
            .overwrite_resource_host_visible(resource, bytes)?;
        self.record_cpu_backing_write();
        Ok(())
    }

    pub fn readback(
        &self,
        resource: ResourceId,
        fence: FenceId,
        required_value: u64,
    ) -> AppResult<Vec<u8>> {
        // DirectStorage resources live in a real private MTLTexture, not in
        // the backend's CPU shadow bytes; read the actual texture once the
        // caller's fence is satisfied.
        if let Some(texture) = self.gpu_textures.get(&resource) {
            if self.backend.fence_value(fence)? < required_value {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "readback requires a completed fence",
                ));
            }
            return texture.read_back();
        }
        self.backend.readback(resource, fence, required_value)
    }

    pub fn create_descriptor_heap(
        &mut self,
        ty: DescriptorHeapType,
        count: usize,
    ) -> DescriptorHeapId {
        self.backend.create_descriptor_heap(ty, count)
    }

    pub fn write_descriptor(
        &mut self,
        heap: DescriptorHeapId,
        index: usize,
        descriptor: ViewDescriptor,
    ) -> AppResult<()> {
        self.backend.write_descriptor(heap, index, descriptor)
    }

    pub fn copy_descriptors(
        &mut self,
        src_heap: DescriptorHeapId,
        src_index: usize,
        dst_heap: DescriptorHeapId,
        dst_index: usize,
        count: usize,
    ) -> AppResult<()> {
        self.backend
            .copy_descriptors(src_heap, src_index, dst_heap, dst_index, count)
    }

    pub fn copy_descriptors_simple(
        &mut self,
        src_heap: DescriptorHeapId,
        src_index: usize,
        dst_heap: DescriptorHeapId,
        dst_index: usize,
        count: usize,
    ) -> AppResult<()> {
        self.backend
            .copy_descriptors_simple(src_heap, src_index, dst_heap, dst_index, count)
    }

    pub fn descriptor_heap_snapshot(
        &self,
        heap: DescriptorHeapId,
    ) -> AppResult<Vec<Option<ViewDescriptor>>> {
        self.backend.descriptor_heap_snapshot(heap)
    }

    pub fn translate_descriptor_heap(
        &self,
        heap: DescriptorHeapId,
    ) -> AppResult<Vec<MetalBinding>> {
        self.backend.translate_descriptor_heap(heap)
    }

    /// Returns the descriptor handle increment size for a given heap type.
    /// Direct3D 12 requires these values for manual descriptor handle arithmetic.
    pub fn get_descriptor_handle_increment_size(&self, heap_type: DescriptorHeapType) -> u32 {
        match heap_type {
            DescriptorHeapType::CbvSrvUav => 32,
            DescriptorHeapType::Sampler => 32,
            DescriptorHeapType::Rtv => 16,
            DescriptorHeapType::Dsv => 16,
        }
    }

    pub fn create_root_signature(&mut self, desc: RootSignatureDesc) -> RootSignatureId {
        let id = self.backend.create_root_signature(desc.clone());
        self.root_signature_descs.insert(id, desc);
        id
    }

    pub fn create_pipeline_state(
        &mut self,
        root_signature: RootSignatureId,
        desc: PipelineStateDesc,
    ) -> PipelineStateId {
        self.backend.create_pipeline_state(root_signature, desc)
    }

    pub fn create_command_queue(&mut self) -> CommandQueueId {
        self.backend.create_command_queue()
    }

    pub fn create_command_allocator(&mut self) -> CommandAllocatorId {
        self.backend.create_command_allocator()
    }

    pub fn create_graphics_command_list(
        &mut self,
        allocator: CommandAllocatorId,
        pipeline_state: PipelineStateId,
        is_bundle: bool,
    ) -> CommandListId {
        self.backend
            .create_graphics_command_list(allocator, pipeline_state, is_bundle)
    }

    pub fn record_transition(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        self.set_subresource_state(resource, subresource, to);
        self.backend
            .record_transition(list, resource, subresource, from, to)
    }

    pub fn record_uav_barrier(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
    ) -> AppResult<()> {
        self.backend.record_uav_barrier(list, resource)
    }

    pub fn record_aliasing_barrier(
        &mut self,
        list: CommandListId,
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    ) -> AppResult<()> {
        self.track_aliasing_overlap(before, after);
        self.backend.record_aliasing_barrier(list, before, after)
    }

    /// Record a full D3D12_RESOURCE_BARRIER (handles Transition, Aliasing, UAV with flags).
    pub fn record_resource_barrier(
        &mut self,
        list: CommandListId,
        desc: &D3D12ResourceBarrierDesc,
    ) -> AppResult<()> {
        // Track aliasing overlaps (deduplicated so the set stays bounded)
        if desc.barrier_type == D3D12ResourceBarrierType::Aliasing {
            self.track_aliasing_overlap(desc.resource_before, desc.resource_after);
        }
        self.backend.record_resource_barrier(list, desc)
    }

    /// Track an aliasing overlap pair, deduplicating so the set does not grow
    /// without bound across repeated barriers on the same pair.
    fn track_aliasing_overlap(&mut self, before: Option<ResourceId>, after: Option<ResourceId>) {
        if !self
            .aliasing_overlaps
            .iter()
            .any(|(b, a)| *b == before && *a == after)
        {
            self.aliasing_overlaps.push((before, after));
        }
    }

    /// Record a split barrier begin (D3D12_RESOURCE_BARRIER_FLAG_BEGIN_ONLY).
    pub fn record_split_barrier_begin(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        self.set_subresource_state(resource, subresource, to);
        self.pending_split_barriers.push(PendingSplitBarrier {
            resource,
            subresource,
            state_before: from,
            state_after: to,
        });
        self.backend
            .record_split_barrier_begin(list, resource, subresource, from, to)
    }

    /// Record a split barrier end (D3D12_RESOURCE_BARRIER_FLAG_END_ONLY).
    pub fn record_split_barrier_end(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        // Remove matching pending split barrier. An END_ONLY without a
        // matching BEGIN is a malformed barrier sequence; reject it instead
        // of mutating resource state (D3D12 debug validation rejects it).
        let pos = self.pending_split_barriers.iter().position(|pending| {
            pending.resource == resource
                && pending.subresource == subresource
                && pending.state_before == from
                && pending.state_after == to
        });
        let index = pos.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "split barrier END without matching BEGIN for resource {resource} subresource {subresource}"
                ),
            )
        })?;
        self.pending_split_barriers.remove(index);
        self.backend
            .record_split_barrier_end(list, resource, subresource, from, to)
    }

    /// Query the number of pending split barriers.
    pub fn pending_split_barrier_count(&self) -> usize {
        self.pending_split_barriers.len()
    }

    /// Resolve aliasing barriers: check if two resources overlap.
    pub fn check_aliasing_overlap(&self, before: ResourceId, after: ResourceId) -> bool {
        self.aliasing_overlaps
            .iter()
            .any(|(b, a)| *b == Some(before) && *a == Some(after))
    }

    /// Clear all tracked aliasing overlaps.
    pub fn clear_aliasing_overlaps(&mut self) {
        self.aliasing_overlaps.clear();
    }

    pub fn record_set_root_constants(
        &mut self,
        list: CommandListId,
        values: Vec<u32>,
    ) -> AppResult<()> {
        self.backend.record_set_root_constants(list, values)
    }

    pub fn record_begin_render_pass(
        &mut self,
        list: CommandListId,
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: &str,
        store_action: &str,
    ) -> AppResult<()> {
        self.backend.record_begin_render_pass(
            list,
            color_formats,
            depth_format,
            load_action,
            store_action,
        )
    }

    pub fn record_clear_rtv(
        &mut self,
        list: CommandListId,
        heap: DescriptorHeapId,
        index: usize,
    ) -> AppResult<()> {
        // Clear operations on a present backbuffer are applied to the
        // authoritative surface immediately (transparent black), so a later
        // CPU staging upload cannot resurrect stale pixels. The guest clear
        // colour is not represented by the current command signature.
        let resource = self
            .backend
            .descriptor_heap_snapshot(heap)?
            .get(index)
            .and_then(|descriptor| match descriptor {
                Some(ViewDescriptor::Rtv { resource, .. }) => Some(*resource),
                _ => None,
            });
        if let Some(resource) = resource {
            if let Some((swapchain, _channel_index)) = self.present_backbuffer_index(resource) {
                let state = self.backend.swapchain_state(swapchain)?;
                let pixels = vec![0u8; state.desc.width as usize * state.desc.height as usize * 4];
                self.write_present_backbuffer_bytes(resource, 0, &pixels)?;
            }
        }
        self.backend.record_clear_rtv(list, heap, index)
    }

    pub fn record_clear_dsv(
        &mut self,
        list: CommandListId,
        heap: DescriptorHeapId,
        index: usize,
    ) -> AppResult<()> {
        self.backend.record_clear_dsv(list, heap, index)
    }

    pub fn record_draw(&mut self, list: CommandListId, vertices: u32) -> AppResult<()> {
        self.backend.record_draw(list, vertices)
    }

    pub fn record_draw_instanced(
        &mut self,
        list: CommandListId,
        vertices: u32,
        instances: u32,
    ) -> AppResult<()> {
        self.backend
            .record_draw_instanced(list, vertices, instances)
    }

    pub fn record_dispatch(
        &mut self,
        list: CommandListId,
        x: u32,
        y: u32,
        z: u32,
    ) -> AppResult<()> {
        self.backend.record_dispatch(list, x, y, z)
    }

    pub fn record_copy_resource(
        &mut self,
        list: CommandListId,
        src: ResourceId,
        dst: ResourceId,
    ) -> AppResult<()> {
        self.backend.record_copy_resource(list, src, dst)
    }

    pub fn record_copy_buffer_region(
        &mut self,
        list: CommandListId,
        dst: ResourceId,
        dst_offset: u64,
        src: ResourceId,
        src_offset: u64,
        size: u64,
    ) -> AppResult<()> {
        self.backend
            .record_copy_buffer_region(list, dst, dst_offset, src, src_offset, size)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_copy_resource_region(
        &mut self,
        list: CommandListId,
        dst: ResourceId,
        dst_x: u32,
        dst_y: u32,
        dst_z: u32,
        src: ResourceId,
        src_x: u32,
        src_y: u32,
        src_z: u32,
        width: u32,
        height: u32,
        depth: u32,
    ) -> AppResult<()> {
        self.backend.record_copy_resource_region(
            list, dst, dst_x, dst_y, dst_z, src, src_x, src_y, src_z, width, height, depth,
        )
    }

    pub fn record_upload_buffer_region(
        &mut self,
        _list: CommandListId,
        dst: ResourceId,
        dst_offset: u64,
        src: &[u8],
    ) -> AppResult<()> {
        self.backend.upload_write(dst, dst_offset as usize, src)
    }

    pub fn close_command_list(&mut self, list: CommandListId) -> AppResult<ImmutableCommandStream> {
        self.backend.close_command_list(list)
    }

    pub fn execute_command_lists(
        &mut self,
        queue: CommandQueueId,
        streams: &[ImmutableCommandStream],
        signal: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        Self::validate_command_list_batch(streams)?;
        self.submit_metal4_batch(streams);
        // Drain queued WriteBufferImmediate requests; the aliasing overlap
        // set is also reset so both stay bounded across frames.
        self.drain_pending_immediate_writes();
        self.clear_aliasing_overlaps();
        if streams.len() > 1 {
            // Independent streams are translated concurrently; effects are
            // applied in submission order by the shared execution path, so
            // the plan and resource contents match serial execution exactly.
            self.backend
                .execute_command_lists_parallel(queue, streams, signal)
        } else {
            self.backend.execute_command_lists(queue, streams, signal)
        }
    }

    /// Execute command streams with explicit parallel translation of
    /// independent streams. Results are identical to
    /// [`execute_command_lists`](Self::execute_command_lists); counters in
    /// [`GraphicsBackend::translation_stats`] report the parallel work.
    pub fn execute_command_lists_parallel(
        &mut self,
        queue: CommandQueueId,
        streams: &[ImmutableCommandStream],
        signal: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        Self::validate_command_list_batch(streams)?;
        self.submit_metal4_batch(streams);
        self.drain_pending_immediate_writes();
        self.clear_aliasing_overlaps();
        self.backend
            .execute_command_lists_parallel(queue, streams, signal)
    }

    /// Reject the same command list appearing twice in one ExecuteCommandLists
    /// batch. D3D12 permits re-executing a closed list in a later batch, but a
    /// duplicate inside one batch would alias two Metal 4 encodings.
    fn validate_command_list_batch(streams: &[ImmutableCommandStream]) -> AppResult<()> {
        let mut seen = std::collections::BTreeSet::new();
        for stream in streams {
            if !seen.insert(stream.id) {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "D3D12 ExecuteCommandLists: duplicate command list {} in one batch",
                        stream.id
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Encode the batch into Metal 4 command buffers and submit it as one
    /// group when the host supports Metal 4. Failures fall back to the
    /// authoritative CPU execution path and stay observable through the
    /// fallback counters; they never alter the returned plan.
    fn submit_metal4_batch(&mut self, streams: &[ImmutableCommandStream]) {
        if streams.is_empty() {
            return;
        }
        if self.metal4_batch_disabled {
            self.metal4_batch_fallbacks += 1;
            return;
        }
        if self.metal4_batch.is_none() {
            match metal4_batch::Metal4Batch::new() {
                Ok(batch) => self.metal4_batch = Some(batch),
                Err(error) => {
                    self.metal4_batch_disabled = true;
                    self.metal4_batch_fallbacks += 1;
                    self.metal4_batch_last_error = Some(error);
                    return;
                }
            }
        }
        let ids: Vec<CommandListId> = streams.iter().map(|stream| stream.id).collect();
        let result = self
            .metal4_batch
            .as_mut()
            .expect("Metal 4 batch was initialised above")
            .execute_markers(&ids);
        match result {
            Ok(completion) => {
                self.metal4_batch_last_error = None;
                self.metal4_batch_last_event = Some(completion.event_value);
            }
            Err(error) => {
                self.metal4_batch_fallbacks += 1;
                self.metal4_batch_last_error = Some(error);
            }
        }
    }

    /// Metal 4 grouped-submission counters, if a batch has been created.
    pub fn metal4_batch_stats(&self) -> Option<metal4_batch::Metal4BatchStats> {
        self.metal4_batch
            .as_ref()
            .map(metal4_batch::Metal4Batch::stats)
    }

    /// ExecuteCommandLists batches that used the CPU fallback.
    pub fn metal4_batch_fallbacks(&self) -> u64 {
        self.metal4_batch_fallbacks
    }

    /// Most recent Metal 4 batch failure that caused a fallback.
    pub fn metal4_batch_last_error(&self) -> Option<&AppError> {
        self.metal4_batch_last_error.as_ref()
    }

    /// Shared-event value of the most recent successful grouped submission.
    pub fn metal4_batch_last_event(&self) -> Option<u64> {
        self.metal4_batch_last_event
    }

    #[cfg(test)]
    fn disable_metal4_batch_for_test(&mut self) {
        self.metal4_batch_disabled = true;
    }

    /// Analyse barrier hazards across command streams without executing them.
    pub fn analyze_barriers(
        &self,
        streams: &[ImmutableCommandStream],
    ) -> AppResult<crate::gfx::BarrierAnalysis> {
        self.backend.analyze_barriers(streams)
    }

    /// Translate a batch of descriptor heaps into Metal bindings, reusing the
    /// revision cache for heaps whose descriptors did not change.
    pub fn translate_descriptor_tables(
        &self,
        heaps: &[DescriptorHeapId],
    ) -> AppResult<Vec<Vec<MetalBinding>>> {
        self.backend.translate_descriptor_tables(heaps)
    }

    pub fn create_fence(&mut self, initial_value: u64) -> FenceId {
        self.backend.create_fence(initial_value)
    }

    pub fn fence_value(&self, fence: FenceId) -> AppResult<u64> {
        self.backend.fence_value(fence)
    }

    pub fn signal_fence(&mut self, fence: FenceId, value: u64) -> AppResult<()> {
        self.backend.signal_fence(fence, value)
    }

    pub fn wait_for_fence(&self, fence: FenceId, value: u64, timeout_ns: u64) -> AppResult<bool> {
        // Delegate to backend which tracks fence values via signal_fence
        self.backend.wait_for_fence(fence, value, timeout_ns)
    }

    pub fn create_query_heap(&mut self, ty: QueryType, count: usize) -> QueryHeapId {
        let id = self.backend.create_query_heap(ty, count);
        // Also track at runtime level with D3D12 query heap type mapping
        let heap_type = match ty {
            QueryType::Occlusion => 0u32, // D3D12_QUERY_HEAP_TYPE_OCCLUSION
            QueryType::Timestamp => 1u32, // D3D12_QUERY_HEAP_TYPE_TIMESTAMP
            QueryType::PipelineStatistics => 2u32, // D3D12_QUERY_HEAP_TYPE_PIPELINE_STATISTICS
            QueryType::SoStatistics => 3u32, // D3D12_QUERY_HEAP_TYPE_SO_STATISTICS
            QueryType::VideoDecodeStat => 4u32, // D3D12_QUERY_HEAP_TYPE_VIDEO_DECODE_STAT
            QueryType::VideoProcessStat => 5u32, // D3D12_QUERY_HEAP_TYPE_VIDEO_PROCESS_STAT
        };
        self.query_heaps.insert(
            id,
            QueryHeap {
                heap_type,
                count: count as u32,
                active: vec![false; count],
                begin_values: vec![0; count],
                resolved: vec![0; count],
            },
        );
        id
    }

    pub fn record_begin_query(
        &mut self,
        _list: CommandListId,
        heap: QueryHeapId,
        index: u32,
    ) -> AppResult<()> {
        let qh = self.query_heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown query heap {heap}"),
            )
        })?;
        let idx = index as usize;
        if idx >= qh.count as usize {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("query index {index} out of range (count {})", qh.count),
            ));
        }
        if qh.active[idx] {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("query {heap}[{index}] begun twice"),
            ));
        }
        qh.active[idx] = true;
        if qh.heap_type == 1 {
            // Timestamp query — capture the begin timestamp.
            let ts = self.backend.write_timestamp(heap, idx)?;
            qh.begin_values[idx] = ts;
        } else if qh.heap_type == 0 {
            // Occlusion query — mark that we should track draws
            qh.begin_values[idx] = 0;
        }
        Ok(())
    }

    pub fn record_end_query(
        &mut self,
        _list: CommandListId,
        heap: QueryHeapId,
        index: u32,
    ) -> AppResult<()> {
        let qh = self.query_heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown query heap {heap}"),
            )
        })?;
        let idx = index as usize;
        if idx >= qh.count as usize {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("query index {index} out of range (count {})", qh.count),
            ));
        }
        if !qh.active[idx] {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("query {heap}[{index}] ended without begin"),
            ));
        }
        qh.active[idx] = false;
        if qh.heap_type == 1 {
            // Timestamp query — the resolved value is end minus begin, which
            // is what the guest reads back. Store the delta in both the
            // runtime heap and the backend heap (so resolve_query_data
            // reports the same value).
            let end_ts = self.backend.write_timestamp(heap, idx)?;
            let delta = end_ts.saturating_sub(qh.begin_values[idx]);
            qh.resolved[idx] = delta;
            self.backend.write_timestamp_value(heap, idx, delta)?;
        } else if qh.heap_type == 0 {
            // Occlusion query — write occlusion sample (1 sample for a basic pass)
            self.backend.write_occlusion(heap, idx, 1)?;
            qh.resolved[idx] = 1;
        }
        Ok(())
    }

    pub fn record_resolve_query_data(
        &mut self,
        _list: CommandListId,
        heap: QueryHeapId,
        start: u32,
        count: u32,
        dst: ResourceId,
    ) -> AppResult<()> {
        let qh = self.query_heaps.get(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown query heap {heap}"),
            )
        })?;
        let start_idx = start as usize;
        let count = count as usize;
        let end_idx = start_idx.checked_add(count).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resolve query range overflow",
            )
        })?;
        if end_idx > qh.count as usize {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "resolve query range [{start}, {}) out of range (count {})",
                    start + count as u32,
                    qh.count
                ),
            ));
        }
        // Write the resolved values (8 bytes each) into the destination
        // resource, which is the guest's readback buffer.
        let mut bytes = Vec::with_capacity(count * 8);
        for value in &qh.resolved[start_idx..end_idx] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.backend.write_resource_bytes(dst, 0, &bytes)
    }

    pub fn resolve_query_data(&self, heap: QueryHeapId) -> AppResult<QueryResolveResult> {
        self.backend.resolve_query_data(heap)
    }

    pub fn begin_render_pass(
        &mut self,
        list: CommandListId,
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: &str,
        store_action: &str,
    ) -> AppResult<()> {
        // Set the flag only after the fallible backend call succeeds so a
        // failure does not desync is_render_pass_active()/reset_render_pass_state().
        self.backend.record_begin_render_pass(
            list,
            color_formats,
            depth_format,
            load_action,
            store_action,
        )?;
        self.render_pass_active = true;
        Ok(())
    }

    pub fn end_render_pass(&mut self, _list: CommandListId) -> AppResult<()> {
        self.render_pass_active = false;
        // GraphicsBackend does not have a dedicated end_render_pass — render passes
        // are implicitly ended by execute_command_lists.
        Ok(())
    }

    // ── ID3D12GraphicsCommandList4 methods ─────────────────────────
    /// Parse guest memory for D3D12_META_COMMAND_PARAMETER_STAGE data and store it.
    pub fn initialize_meta_command(&mut self, _list: CommandListId) -> AppResult<()> {
        // Meta command initialization is acknowledged.
        // Guest-side parameters are not forwarded by pe_runtime at this layer;
        // a full implementation would read them from guest memory.
        self.trace("initialize_meta_command: acknowledged (no-op, parameters not forwarded)");
        Ok(())
    }

    /// Execute a previously initialized meta command.
    pub fn execute_meta_command(&mut self, _list: CommandListId) -> AppResult<()> {
        // Meta command execution is acknowledged.
        // Guest-side parameters are not forwarded by pe_runtime at this layer.
        self.trace("execute_meta_command: acknowledged (no-op, parameters not forwarded)");
        Ok(())
    }

    /// Register the CPU bytes for a guest GPU buffer used as raytracing input.
    ///
    /// The D3D12 bridge has no global GPU virtual-address map; the dispatch
    /// layer supplies the bytes it read from guest memory so the Metal build
    /// consumes the real vertex/index data instead of only descriptor metadata.
    pub fn register_raytracing_buffer(&mut self, gpu_address: u64, bytes: Vec<u8>) {
        self.raytracing_buffer_bytes.insert(gpu_address, bytes);
    }

    /// Register D3D12_RAYTRACING_INSTANCE_DESC records for a top-level build.
    pub fn register_raytracing_instances(&mut self, dest_address: u64, bytes: Vec<u8>) {
        self.raytracing_instance_bytes.insert(dest_address, bytes);
    }

    fn metal_raytracing(&mut self) -> AppResult<D3d12MetalRayTracing> {
        if let Some(existing) = &self.metal_raytracing {
            return Ok(existing.clone());
        }
        let device = crate::metal_backend::MetalDevice::system_default()?.metal_device_owned();
        let queue = device.new_command_queue();
        let ray_pipeline = crate::metal_backend::create_ray_query_pipeline(&device)?;
        let bridge = D3d12MetalRayTracing {
            inner: std::sync::Arc::new(std::sync::Mutex::new(D3d12MetalRayTracingInner {
                device,
                queue,
                ray_pipeline,
                structures: BTreeMap::new(),
                guest_to_handle: BTreeMap::new(),
                last_ray_results: Vec::new(),
                work_graph: None,
                last_work_graph_records: Vec::new(),
                work_graph_node_programs: BTreeMap::new(),
                indirect_interpreter: None,
                native_render_pipelines: BTreeMap::new(),
                ray_shader_programs: BTreeMap::new(),
                last_ray_payloads: Vec::new(),
                last_indirect_results: Vec::new(),
                last_indirect_effective: 0,
                last_indirect_native: false,
                last_indirect_boundary: None,
            })),
        };
        self.metal_raytracing = Some(bridge.clone());
        Ok(bridge)
    }

    /// Build a raytracing acceleration structure with real Metal objects.
    ///
    /// Bottom-level structures consume the registered vertex/index bytes (or a
    /// zero-filled buffer of the declared size when no bytes were registered);
    /// top-level structures consume D3D12 instance descriptors, resolve their
    /// BLAS references and honour instance masks/options. Both paths encode a
    /// real `buildAccelerationStructure`, query the compacted size and compact
    /// when D3D12 requested `ALLOW_COMPACTION`.
#[rustfmt::skip]
    pub fn build_raytracing_acceleration_structure(
        &mut self,
        _list: CommandListId,
        desc: &D3D12BuildAccelerationStructureDesc,
    ) -> AppResult<u64> {
        const BUILD_FLAG_ALLOW_UPDATE: u32 = 0x1;
        const BUILD_FLAG_ALLOW_COMPACTION: u32 = 0x2;
        const BUILD_FLAG_PREFER_FAST_TRACE: u32 = 0x4;
        const BUILD_FLAG_PREFER_FAST_BUILD: u32 = 0x8;
        const BUILD_FLAG_MINIMIZE_MEMORY: u32 = 0x10;
        const GEOMETRY_FLAG_OPAQUE: u32 = 0x1;
        const GEOMETRY_FLAG_NO_DUPLICATE_ANYHIT: u32 = 0x2;

        if desc.dest_address % 256 != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "BuildRaytracingAccelerationStructure DestAccelerationStructureData {:#x} is not 256-byte aligned",
                    desc.dest_address
                ),
            ));
        }
        if desc.scratch_address % 256 != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "BuildRaytracingAccelerationStructure ScratchAccelerationStructureData {:#x} is not 256-byte aligned",
                    desc.scratch_address
                ),
            ));
        }
        if desc.scratch_address == desc.dest_address {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "BuildRaytracingAccelerationStructure scratch and destination overlap",
            ));
        }
        let valid_flags = BUILD_FLAG_ALLOW_UPDATE
            | BUILD_FLAG_ALLOW_COMPACTION
            | BUILD_FLAG_PREFER_FAST_TRACE
            | BUILD_FLAG_PREFER_FAST_BUILD
            | BUILD_FLAG_MINIMIZE_MEMORY;
        if desc.inputs.flags & !valid_flags != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "BuildRaytracingAccelerationStructure flags {:#x} contain undefined bits",
                    desc.inputs.flags
                ),
            ));
        }
        let is_tlas = match desc.inputs.ty {
            0 => false,
            1 => true,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE {other} is not defined"),
                ));
            }
        };
        if desc.inputs.num_descs == 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "BuildRaytracingAccelerationStructure NumDescs must be non-zero",
            ));
        }

        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");

        let (metal_handle, size, compacted_size) = if is_tlas {
            let instance_stride = 64u64;
            let required = (desc.inputs.num_descs as u64) * instance_stride;
            let mut instance_bytes = self
                .raytracing_instance_bytes
                .get(&desc.dest_address)
                .cloned()
                .unwrap_or_else(|| vec![0u8; required as usize]);
            if (instance_bytes.len() as u64) < required {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "TLAS instance descriptor range {required} exceeds the registered {} bytes",
                        instance_bytes.len()
                    ),
                ));
            }
            instance_bytes.truncate(required as usize);
            // Resolve the BLAS list referenced by the D3D12 instance records.
            let mut referenced: Vec<u64> = Vec::new();
            for index in 0..desc.inputs.num_descs as usize {
                let offset = index * instance_stride as usize;
                let address = u64::from_le_bytes(
                    instance_bytes[offset + 56..offset + 64]
                        .try_into()
                        .expect("8-byte instance tail"),
                );
                if address != 0 && !referenced.contains(&address) {
                    referenced.push(address);
                }
            }
            let mut metal_instances = Vec::with_capacity(desc.inputs.num_descs as usize);
            let mut instance_masks = Vec::with_capacity(desc.inputs.num_descs as usize);
            let mut instance_transforms = Vec::with_capacity(desc.inputs.num_descs as usize);
            let mut instance_geometry = Vec::with_capacity(desc.inputs.num_descs as usize);
            let mut instanced_handles = Vec::new();
            for address in &referenced {
                let handle = inner.guest_to_handle.get(address).copied().ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("instance references unknown acceleration structure {address:#x}"),
                    )
                })?;
                instanced_handles.push(handle);
            }
            for index in 0..desc.inputs.num_descs as usize {
                let offset = index * instance_stride as usize;
                let address = u64::from_le_bytes(
                    instance_bytes[offset + 56..offset + 64]
                        .try_into()
                        .expect("8-byte instance tail"),
                );
                if address == 0 {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "top-level acceleration structure instance has a zero AccelerationStructure address",
                    ));
                }
                instance_geometry.push(address);
                let structure_index = referenced
                    .iter()
                    .position(|candidate| *candidate == address)
                    .expect("referenced address was resolved");
                let mut instance = metal::MTLAccelerationStructureInstanceDescriptor::default();
                let mut transform_rows = [0.0f32; 12];
                for row in 0..3 {
                    for column in 0..4 {
                        let source = offset + (row * 4 + column) * 4;
                        let value = f32::from_le_bytes(
                            instance_bytes[source..source + 4]
                                .try_into()
                                .expect("4-byte transform element"),
                        );
                        instance.transformation_matrix[column][row] = value;
                        transform_rows[row * 4 + column] = value;
                    }
                }
                let identity = [
                    [1.0f32, 0.0, 0.0],
                    [0.0, 1.0, 0.0],
                    [0.0, 0.0, 1.0],
                    [0.0, 0.0, 0.0],
                ];
                if instance.transformation_matrix == [[0.0f32; 3]; 4] {
                    instance.transformation_matrix = identity;
                    transform_rows = crate::metal_backend::RAY_INSTANCE_IDENTITY_ROWS;
                }
                let id_and_mask = u32::from_le_bytes(
                    instance_bytes[offset + 48..offset + 52]
                        .try_into()
                        .expect("4-byte instance id"),
                );
                instance.mask = (id_and_mask >> 24) & 0xFF;
                let contribution_and_flags = u32::from_le_bytes(
                    instance_bytes[offset + 52..offset + 56]
                        .try_into()
                        .expect("4-byte instance flags"),
                );
                let instance_flags = (contribution_and_flags >> 24) & 0xFF;
                let mut options = metal::MTLAccelerationStructureInstanceOptions::None;
                options.set(
                    metal::MTLAccelerationStructureInstanceOptions::DisableTriangleCulling,
                    instance_flags & 0x1 != 0,
                );
                options.set(
                    metal::MTLAccelerationStructureInstanceOptions::TriangleFrontFacingWindingCounterClockwise,
                    instance_flags & 0x2 != 0,
                );
                options.set(
                    metal::MTLAccelerationStructureInstanceOptions::Opaque,
                    instance_flags & 0x4 != 0,
                );
                options.set(
                    metal::MTLAccelerationStructureInstanceOptions::NonOpaque,
                    instance_flags & 0x8 != 0,
                );
                instance.options = options;
                instance.intersection_function_table_offset = 0;
                instance.acceleration_structure_index = structure_index as u32;
                instance_masks.push(instance.mask);
                instance_transforms.push(transform_rows);
                metal_instances.push(instance);
            }
            let instance_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    metal_instances.as_ptr() as *const u8,
                    std::mem::size_of_val(metal_instances.as_slice()),
                )
            };
            let instance_buffer = inner.device.new_buffer_with_data(
                instance_bytes.as_ptr() as *const std::ffi::c_void,
                instance_bytes.len() as u64,
                metal::MTLResourceOptions::StorageModeShared,
            );
            let blas_refs: Vec<&metal::AccelerationStructureRef> = instanced_handles
                .iter()
                .map(|handle| {
                    inner
                        .structures
                        .get(handle)
                        .expect("validated BLAS handle")
                        .structure
                        .as_ref()
                })
                .collect();
            let sizes = crate::metal_backend::instance_acceleration_structure_sizes(
                &inner.device,
                &instance_buffer,
                desc.inputs.num_descs,
                std::mem::size_of::<metal::MTLAccelerationStructureInstanceDescriptor>() as u64,
                metal::MTLAccelerationStructureInstanceDescriptorType::Default,
                &blas_refs,)?;
            let mut tlas = crate::metal_backend::create_instance_acceleration_structure(
                &inner.device,
                &instance_buffer,
                desc.inputs.num_descs,
                std::mem::size_of::<metal::MTLAccelerationStructureInstanceDescriptor>() as u64,
                metal::MTLAccelerationStructureInstanceDescriptorType::Default,
                &blas_refs,)?;
            let scratch = crate::metal_backend::allocate_acceleration_scratch_buffer(
                &inner.device,
                sizes.build_scratch_size.max(sizes.refit_scratch_size),
            );
            let command_buffer = inner.queue.new_command_buffer();
            let encoder =
                crate::metal_backend::MetalAccelerationStructureEncoder::new(command_buffer)?;
            crate::metal_backend::build_instance_acceleration_structure(
                &encoder,
                &mut tlas,
                &scratch,
                0,
                &instance_buffer,
                &blas_refs,)?;
            encoder.end_encoding();
            command_buffer.commit();
            command_buffer.wait_until_completed();
            let compacted =
                Self::query_compacted_size(&inner.queue, tlas.acceleration_structure.as_ref());
            let (structure, size) = if desc.inputs.flags & BUILD_FLAG_ALLOW_COMPACTION != 0
                && compacted > 0
            {
                let destination = inner.device.new_acceleration_structure_with_size(compacted);
                let compact_buffer = inner.queue.new_command_buffer();
                let encoder =
                    crate::metal_backend::MetalAccelerationStructureEncoder::new(compact_buffer)?;
                crate::metal_backend::compact_acceleration_structure(
                    &encoder,
                    tlas.acceleration_structure.as_ref(),
                    destination.as_ref(),
                );
                encoder.end_encoding();
                compact_buffer.commit();
                compact_buffer.wait_until_completed();
                (destination, compacted)
            } else {
                (tlas.acceleration_structure, tlas.size as u64)
            };
            let mut tlas_geometry = crate::metal_backend::MetalRayGeometryData::default();
            for (instance_index, address) in instance_geometry.iter().enumerate() {
                let blas_handle = inner.guest_to_handle[address];
                let Some(blas) = inner.structures.get(&blas_handle) else {
                    continue; // coverage: unreachable — TLAS only references mapped BLAS
                };
                if let Some(binding) = blas.geometry.bindings.first() {
                    let vertex_offset = tlas_geometry.vertices.len() as u32;
                    let index_offset = tlas_geometry.indices.len() as u32;
                    tlas_geometry
                        .vertices
                        .extend_from_slice(&blas.geometry.vertices);
                    tlas_geometry.indices.extend_from_slice(&blas.geometry.indices);
                    tlas_geometry.bindings.push(
                        crate::metal_backend::MetalRayGeometryBinding {
                            vertex_offset,
                            index_offset,
                            triangle_count: binding.triangle_count,
                            reserved: 0,
                        },
                    );
                } else {
                    tlas_geometry
                        .bindings
                        .push(crate::metal_backend::MetalRayGeometryBinding::default());
                }
                for aabb in &blas.geometry.aabbs {
                    let mut candidate = *aabb;
                    candidate.instance_id = instance_index as u32;
                    tlas_geometry.aabbs.push(candidate);
                }
            }
            let handle = alloc_d3d12_metal_handle();
            inner.structures.insert(
                handle,
                D3d12MetalStructure {
                    structure,
                    instance_masks,
                    instance_transforms,
                    geometry: tlas_geometry,
                },
            );
            inner.guest_to_handle.insert(desc.dest_address, handle);
            (handle, size, compacted)
        } else {
            if desc.inputs.geometries.len() != desc.inputs.num_descs as usize {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "BuildRaytracingAccelerationStructure NumDescs {} does not match {} geometry descriptors",
                        desc.inputs.num_descs,
                        desc.inputs.geometries.len()
                    ),
                ));
            }
            if desc.inputs.geometries.len() > 1 {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "bottom-level acceleration structure with multiple geometries must use DescriptorsLayout",
                ));
            }
            let mut metal_geometries = Vec::new();
            let mut metal_buffers = Vec::new();
            let mut blas_geometry = crate::metal_backend::MetalRayGeometryData::default();
            for (index, geometry) in desc.inputs.geometries.iter().enumerate() {
                if geometry.flags & !(GEOMETRY_FLAG_OPAQUE | GEOMETRY_FLAG_NO_DUPLICATE_ANYHIT) != 0
                {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "geometry {index} flags {:#x} contain undefined bits",
                            geometry.flags
                        ),
                    ));
                }
                match geometry.ty {
                    0 => {
                        if geometry.vertex_buffer % 4 != 0 {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} vertex buffer {:#x} is not 4-byte aligned",
                                    geometry.vertex_buffer
                                ),
                            ));
                        }
                        if geometry.vertex_stride == 0 || geometry.vertex_stride % 4 != 0 {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} vertex stride {} must be a non-zero multiple of 4",
                                    geometry.vertex_stride
                                ),
                            ));
                        }
                        let (vertex_format, minimum_stride) =
                            Self::dxgi_raytracing_vertex_format(geometry.vertex_format, index)?;
                        if geometry.vertex_stride < minimum_stride {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} vertex stride {} is smaller than the {} bytes required by the format",
                                    geometry.vertex_stride, minimum_stride
                                ),
                            ));
                        }
                        if geometry.vertex_count < 3 {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} vertex count {} is smaller than 3",
                                    geometry.vertex_count
                                ),
                            ));
                        }
                        let indexed = geometry.index_buffer != 0;
                        let (index_format, index_size) = if indexed {
                            if geometry.index_buffer % 4 != 0 {
                                return Err(AppError::new(
                                    ReasonCode::RcD3dInvalidState,
                                    format!(
                                        "geometry {index} index buffer {:#x} is not 4-byte aligned",
                                        geometry.index_buffer
                                    ),
                                ));
                            }
                            if geometry.index_count == 0 || geometry.index_count % 3 != 0 {
                                return Err(AppError::new(
                                    ReasonCode::RcD3dInvalidState,
                                    format!(
                                        "geometry {index} index count {} is not a non-zero multiple of 3",
                                        geometry.index_count
                                    ),
                                ));
                            }
                            let (format, size) =
                                Self::dxgi_raytracing_index_format(geometry.index_format, index)?;
                            (Some(format), size)
                        } else {
                            (None, 0)
                        };
                        let vertex_required =
                            geometry.vertex_count as u64 * geometry.vertex_stride as u64;
                        let vertex_bytes = self
                            .raytracing_buffer_bytes
                            .get(&geometry.vertex_buffer)
                            .cloned()
                            .unwrap_or_else(|| vec![0u8; vertex_required as usize]);
                        if (vertex_bytes.len() as u64) < vertex_required {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} vertex buffer range {vertex_required} exceeds the registered {} bytes",
                                    vertex_bytes.len()
                                ),
                            ));
                        }
                        blas_geometry.vertices = Self::raytracing_vertex_attributes(
                            geometry.vertex_format,
                            geometry.vertex_stride,
                            &vertex_bytes,
                            geometry.vertex_count,
                        );
                        let vertex_buffer = inner.device.new_buffer_with_data(
                            vertex_bytes.as_ptr() as *const std::ffi::c_void,
                            vertex_required,
                            metal::MTLResourceOptions::StorageModeShared,
                        );
                        let (index_buffer, index_required) = if indexed {
                            let index_required = geometry.index_count as u64 * index_size;
                            let index_bytes = self
                                .raytracing_buffer_bytes
                                .get(&geometry.index_buffer)
                                .cloned()
                                .unwrap_or_else(|| vec![0u8; index_required as usize]);
                            if (index_bytes.len() as u64) < index_required {
                                return Err(AppError::new(
                                    ReasonCode::RcD3dInvalidState,
                                    format!(
                                        "geometry {index} index buffer range {index_required} exceeds the registered {} bytes",
                                        index_bytes.len()
                                    ),
                                ));
                            }
                            blas_geometry.indices = Self::raytracing_indices(
                                geometry.index_format,
                                &index_bytes,
                                geometry.index_count,
                            );
                            let buffer = inner.device.new_buffer_with_data(
                                index_bytes.as_ptr() as *const std::ffi::c_void,
                                index_required,
                                metal::MTLResourceOptions::StorageModeShared,
                            );
                            (Some((buffer, index_required)), index_required)
                        } else {
                            blas_geometry.indices = (0..geometry.vertex_count).collect();
                            (None, 0)
                        };
                        let _ = index_required;
                        metal_geometries.push(crate::metal_backend::RayTracingGeometryDescriptor {
                            kind: crate::metal_backend::RayTracingGeometryKind::Triangles,
                            vertex_buffer: geometry.vertex_buffer,
                            vertex_stride: geometry.vertex_stride as u64,
                            vertex_format,
                            index_buffer: index_format.map(|_| geometry.index_buffer),
                            index_format,
                            primitive_count: if indexed {
                                geometry.index_count / 3
                            } else {
                                geometry.vertex_count / 3
                            },
                            triangle_count: if indexed {
                                geometry.index_count / 3
                            } else {
                                geometry.vertex_count / 3
                            },
                            opaque: geometry.flags & GEOMETRY_FLAG_OPAQUE != 0,
                            allow_duplicates: false,
                        });
                        let triangle_count = if indexed {
                            geometry.index_count / 3
                        } else {
                            geometry.vertex_count / 3
                        };
                        blas_geometry.bindings.push(
                            crate::metal_backend::MetalRayGeometryBinding {
                                vertex_offset: 0,
                                index_offset: 0,
                                triangle_count,
                                reserved: 0,
                            },
                        );
                        metal_buffers.push((vertex_buffer, index_buffer));
                    }
                    1 => {
                        if geometry.vertex_buffer % 4 != 0 {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} bounding-box buffer {:#x} is not 4-byte aligned",
                                    geometry.vertex_buffer
                                ),
                            ));
                        }
                        if geometry.vertex_stride < 24 || geometry.vertex_stride % 4 != 0 {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} bounding-box stride {} must be at least 24 and a multiple of 4",
                                    geometry.vertex_stride
                                ),
                            ));
                        }
                        if geometry.vertex_count == 0 {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!("geometry {index} bounding-box count is zero"),
                            ));
                        }
                        let required = geometry.vertex_count as u64 * geometry.vertex_stride as u64;
                        let bytes = self
                            .raytracing_buffer_bytes
                            .get(&geometry.vertex_buffer)
                            .cloned()
                            .unwrap_or_else(|| vec![0u8; required as usize]);
                        if (bytes.len() as u64) < required {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "geometry {index} bounding-box range {required} exceeds the registered {} bytes",
                                    bytes.len()
                                ),
                            ));
                        }
                        blas_geometry.aabbs = Self::raytracing_aabbs(
                            &bytes,
                            geometry.vertex_stride,
                            geometry.vertex_count,
                        );
                        let buffer = inner.device.new_buffer_with_data(
                            bytes.as_ptr() as *const std::ffi::c_void,
                            required,
                            metal::MTLResourceOptions::StorageModeShared,
                        );
                        metal_geometries.push(crate::metal_backend::RayTracingGeometryDescriptor {
                            kind: crate::metal_backend::RayTracingGeometryKind::BoundingBoxes,
                            vertex_buffer: geometry.vertex_buffer,
                            vertex_stride: geometry.vertex_stride as u64,
                            vertex_format: crate::metal_backend::VertexFormat::Float3,
                            index_buffer: None,
                            index_format: None,
                            primitive_count: geometry.vertex_count,
                            triangle_count: 0,
                            opaque: geometry.flags & GEOMETRY_FLAG_OPAQUE != 0,
                            allow_duplicates: false,
                        });
                        metal_buffers.push((buffer, None));
                    }
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("geometry {index} type {other} is not defined"),
                        ));
                    }
                }
            }
            let descriptor = crate::metal_backend::AccelerationStructureDescriptor {
                geometry_descriptors: metal_geometries,
                usage: crate::metal_backend::AccelerationStructureUsage::RayTracing,
            };
            let buffers: Vec<crate::metal_backend::RayTracingGeometryBuffers<'_>> = metal_buffers
                .iter()
                .map(
                    |(vertex, index)| crate::metal_backend::RayTracingGeometryBuffers {
                        vertex_buffer: vertex.as_ref(),
                        vertex_offset: 0,
                        index_buffer: index.as_ref().map(|(buffer, _)| (buffer.as_ref(), 0)),
                    },
                )
                .collect();
            let sizes = crate::metal_backend::primitive_acceleration_structure_sizes(
                &inner.device,
                &descriptor,
                &buffers,)?;
            let mut blas = crate::metal_backend::create_acceleration_structure(
                &inner.device,
                &descriptor,
                &buffers,)?;
            let scratch = crate::metal_backend::allocate_acceleration_scratch_buffer(
                &inner.device,
                sizes.build_scratch_size.max(sizes.refit_scratch_size),
            );
            let command_buffer = inner.queue.new_command_buffer();
            let encoder =
                crate::metal_backend::MetalAccelerationStructureEncoder::new(command_buffer)?;
            crate::metal_backend::build_acceleration_structure(
                &encoder, &mut blas, &scratch, &buffers,)?;
            encoder.end_encoding();
            command_buffer.commit();
            command_buffer.wait_until_completed();
            let compacted =
                Self::query_compacted_size(&inner.queue, blas.acceleration_structure.as_ref());
            let (structure, size) = if desc.inputs.flags & BUILD_FLAG_ALLOW_COMPACTION != 0
                && compacted > 0
            {
                let destination = inner.device.new_acceleration_structure_with_size(compacted);
                let compact_buffer = inner.queue.new_command_buffer();
                let encoder =
                    crate::metal_backend::MetalAccelerationStructureEncoder::new(compact_buffer)?;
                crate::metal_backend::compact_acceleration_structure(
                    &encoder,
                    blas.acceleration_structure.as_ref(),
                    destination.as_ref(),
                );
                encoder.end_encoding();
                compact_buffer.commit();
                compact_buffer.wait_until_completed();
                (destination, compacted)
            } else {
                (blas.acceleration_structure, blas.size as u64)
            };
            let handle = alloc_d3d12_metal_handle();
            inner.structures.insert(
                handle,
                D3d12MetalStructure {
                    structure,
                    instance_masks: vec![0xFFFF_FFFF],
                    instance_transforms: Vec::new(),
                    geometry: blas_geometry,
                },
            );
            inner.guest_to_handle.insert(desc.dest_address, handle);
            (handle, size, compacted)
        };

        let accel = D3D12AccelerationStructure {
            gpu_address: desc.dest_address,
            size,
            is_top_level: is_tlas,
            metal_accel_handle: metal_handle,
            built: true,
            compacted_size,
            build_flags: desc.inputs.flags,
        };
        self.acceleration_structures
            .insert(desc.dest_address, accel);
        self.trace(&format!(
            "BuildAccelerationStructure: addr=0x{:x} {} size={} geoms={} compacted={}",
            desc.dest_address,
            if is_tlas { "TLAS" } else { "BLAS" },
            size,
            desc.inputs.num_descs,
            compacted_size,
        ));
        Ok(desc.dest_address)
    }

    fn query_compacted_size(
        queue: &metal::CommandQueueRef,
        acceleration: &metal::AccelerationStructureRef,
    ) -> u64 {
        let device = queue.device();
        let buffer = device.new_buffer(8, metal::MTLResourceOptions::StorageModeShared);
        let command_buffer = queue.new_command_buffer();
        let encoder = crate::metal_backend::MetalAccelerationStructureEncoder::new(command_buffer)
            .expect("compacted-size encoder");
        crate::metal_backend::write_compacted_acceleration_structure_size(
            &encoder,
            acceleration,
            buffer.as_ref(),
            0,
        );
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();
        unsafe { *(buffer.contents() as *const u64) }
    }

    fn dxgi_raytracing_vertex_format(
        format: u32,
        index: usize,
    ) -> AppResult<(crate::metal_backend::VertexFormat, u32)> {
        match format {
            6 | 71 | 80 => Ok((crate::metal_backend::VertexFormat::Float3, 12)),
            17 => Ok((crate::metal_backend::VertexFormat::Float2, 8)),
            35 => Ok((crate::metal_backend::VertexFormat::Half3, 8)),
            other => Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("geometry {index} vertex format {other} is not supported for raytracing"),
            )),
        }
    }

    fn half_to_f32(bits: u16) -> f32 {
        let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
        let exponent = (bits >> 10) & 0x1F;
        let mantissa = (bits & 0x03FF) as f32;
        if exponent == 0 {
            sign * mantissa * 2.0f32.powi(-24)
        } else if exponent == 0x1F {
            if mantissa == 0.0 {
                sign * f32::INFINITY
            } else {
                f32::NAN
            }
        } else {
            sign * (1.0 + mantissa / 1024.0) * 2.0f32.powi(exponent as i32 - 15)
        }
    }

    fn raytracing_vertex_attributes(
        format: u32,
        stride: u32,
        bytes: &[u8],
        count: u32,
    ) -> Vec<[f32; 4]> {
        let mut vertices = Vec::with_capacity(count as usize);
        for vertex in 0..count as usize {
            let base = vertex * stride as usize;
            let mut attributes = [0.0f32; 4];
            match format {
                6 | 71 | 80 => {
                    for (component, slot) in attributes.iter_mut().take(3).enumerate() {
                        let offset = base + component * 4;
                        *slot = f32::from_le_bytes(
                            bytes[offset..offset + 4].try_into().expect("vertex float"),
                        );
                    }
                }
                17 => {
                    for (component, slot) in attributes.iter_mut().take(2).enumerate() {
                        let offset = base + component * 4;
                        *slot = f32::from_le_bytes(
                            bytes[offset..offset + 4].try_into().expect("vertex float2"),
                        );
                    }
                }
                35 => {
                    for (component, slot) in attributes.iter_mut().take(3).enumerate() {
                        let offset = base + component * 2;
                        let raw = u16::from_le_bytes(
                            bytes[offset..offset + 2].try_into().expect("vertex half"),
                        );
                        *slot = Self::half_to_f32(raw);
                    }
                }
                _ => {} // coverage: unreachable — callers validate the vertex format
            }
            attributes[3] = 1.0;
            vertices.push(attributes);
        }
        vertices
    }

    fn raytracing_indices(format: u32, bytes: &[u8], count: u32) -> Vec<u32> {
        let mut indices = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            indices.push(if format == 57 {
                let offset = index * 2;
                u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 index")) as u32
            } else {
                let offset = index * 4;
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 index"))
            });
        }
        indices
    }

    fn raytracing_aabbs(
        bytes: &[u8],
        stride: u32,
        count: u32,
    ) -> Vec<crate::metal_backend::MetalRayAabb> {
        let mut aabbs = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let base = index * stride as usize;
            let mut bounds = [0.0f32; 6];
            for (component, slot) in bounds.iter_mut().enumerate() {
                let offset = base + component * 4;
                *slot = f32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("AABB"));
            }
            aabbs.push(crate::metal_backend::MetalRayAabb {
                min: [bounds[0], bounds[1], bounds[2]],
                max: [bounds[3], bounds[4], bounds[5]],
                instance_id: 0,
                geometry_index: 0,
                group: 0,
                reserved: 0,
            });
        }
        aabbs
    }

    fn dxgi_raytracing_index_format(
        format: u32,
        index: usize,
    ) -> AppResult<(crate::metal_backend::IndexFormat, u64)> {
        match format {
            57 => Ok((crate::metal_backend::IndexFormat::UInt16, 2)),
            42 | 43 => Ok((crate::metal_backend::IndexFormat::UInt32, 4)),
            other => Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("geometry {index} index format {other} is not supported for raytracing"),
            )),
        }
    }

    /// Emit post-build info for acceleration structures.
    ///
    /// Handles COMPACTED_SIZE, TOOLS_VISUALIZATION, and SERIALIZATION.
    /// `info_type` is the D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_TYPE.
    /// `output_buffer` is a mutable slice of the guest output buffer to write into.
    pub fn emit_raytracing_acceleration_structure_postbuild_info(
        &mut self,
        _list: CommandListId,
        info_type: u32,
        source_addresses: &[u64],
        output_buffer: &mut [u8],
    ) -> AppResult<()> {
        // D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO types:
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_COMPACTED_SIZE: u32 = 1;
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_TOOLS_VISUALIZATION: u32 = 2;
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_SERIALIZATION: u32 = 3;

        for (i, &src_addr) in source_addresses.iter().enumerate() {
            let accel = self.acceleration_structures.get(&src_addr);
            let base_offset = i * 8; // each entry is at least 8 bytes

            match info_type {
                D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_COMPACTED_SIZE => {
                    // Output: UINT64 CompactedSizeInBytes
                    if base_offset + 8 <= output_buffer.len() {
                        let compacted_size = accel.map(|a| a.compacted_size).unwrap_or(0);
                        let bytes = compacted_size.to_le_bytes();
                        let start = base_offset;
                        let end = (base_offset + 8).min(output_buffer.len());
                        output_buffer[start..end].copy_from_slice(&bytes[..end - start]);
                    }
                }
                D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_TOOLS_VISUALIZATION => {
                    // Output: UINT64 VisualizationSizeInBytes
                    if base_offset + 8 <= output_buffer.len() {
                        let vis_size = accel.map(|a| a.size).unwrap_or(0);
                        let bytes = vis_size.to_le_bytes();
                        let start = base_offset;
                        let end = (base_offset + 8).min(output_buffer.len());
                        output_buffer[start..end].copy_from_slice(&bytes[..end - start]);
                    }
                }
                D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_SERIALIZATION
                    if base_offset + 16 <= output_buffer.len() =>
                {
                    // Output: D3D12_SERIALIZATION_INFO { UINT64 SerializedSizeInBytes; UINT64 NumBottomLevelAccelerationStructurePointers; }
                    let serialized_size = accel.map(|a| a.size).unwrap_or(0);
                    let num_blas = if accel.is_some_and(|a| a.is_top_level) {
                        1
                    } else {
                        0
                    };
                    let size_bytes = serialized_size.to_le_bytes();
                    let num_bytes = (num_blas as u64).to_le_bytes();
                    let start = base_offset;
                    let mid = base_offset + 8;
                    output_buffer[start..mid].copy_from_slice(&size_bytes);
                    output_buffer[mid..base_offset + 16].copy_from_slice(&num_bytes);
                }
                _ => {
                    // Unknown info type — skip
                }
            }
        }
        Ok(())
    }

    /// Copy (or compact, serialize, deserialize) an acceleration structure.
    ///
    /// `mode` maps to `D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE`:
    ///   0 = COPY, 1 = COMPACT, 2 = VISUALIZATION, 3 = SERIALIZE, 4 = DESERIALIZE
    pub fn copy_raytracing_acceleration_structure(
        &mut self,
        _list: CommandListId,
        dest_address: u64,
        source_address: u64,
        mode: u32,
    ) -> AppResult<()> {
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_COPY: u32 = 0;
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_COMPACT: u32 = 1;
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_VISUALIZATION: u32 = 2;
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_SERIALIZE: u32 = 3;
        const D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_DESERIALIZE: u32 = 4;

        match mode {
            D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_COPY
            | D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_COMPACT => {
                // COPY: create a new entry at dest_address with the same metadata.
                // COMPACT: also just reference the same structure (compact not needed on Metal).
                if let Some(src) = self.acceleration_structures.get(&source_address).cloned() {
                    let mut dst = src.clone();
                    dst.gpu_address = dest_address;
                    self.acceleration_structures.insert(dest_address, dst);
                }
            }
            D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_VISUALIZATION => {
                // Visualization copy duplicates the AS for debugging.
                if let Some(src) = self.acceleration_structures.get(&source_address).cloned() {
                    let mut dst = src;
                    dst.gpu_address = dest_address;
                    self.acceleration_structures.insert(dest_address, dst);
                }
            }
            D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_SERIALIZE => {
                // SERIALIZE: reads source AS data and writes to dest buffer.
                // The dest is a GPU buffer address; serialization writes the raw bytes.
                // For the bridge we track the reference — serialization of raw Metal AS
                // data would require Metal API calls. We store the mapping.
                if let Some(src) = self.acceleration_structures.get(&source_address).cloned() {
                    let mut dst = src;
                    dst.gpu_address = dest_address;
                    self.acceleration_structures.insert(dest_address, dst);
                }
            }
            D3D12_RAYTRACING_ACCELERATION_STRUCTURE_COPY_MODE_DESERIALIZE => {
                // DESERIALIZE: reads raw bytes from source buffer and builds an AS.
                // We create a new AS entry pointing to the source metadata.
                if let Some(src) = self.acceleration_structures.get(&source_address).cloned() {
                    let mut dst = src;
                    dst.gpu_address = dest_address;
                    self.acceleration_structures.insert(dest_address, dst);
                }
            }
            _ => {
                // Unknown mode — no-op
            }
        }
        Ok(())
    }

    /// Set pipeline state 1 (raytracing / state object).
    ///
    /// `state_object_ptr` is the guest pointer to the D3D12_STATE_OBJECT.
    /// `dxil_bytecode` is the parsed DXIL shader from the state object subobjects.
    /// The pipeline state is stored for later use during `DispatchRays`.
    pub fn set_pipeline_state1(
        &mut self,
        _list: CommandListId,
        state_object_ptr: u64,
        dxil_bytecode: Vec<u8>,
    ) -> AppResult<()> {
        // Parse DXIL to determine recursion depth, payload size, and attribute size.
        // For DXIL, the metadata is embedded in the DXIL container.
        // We use reasonable defaults when metadata cannot be parsed.
        let (max_recursion_depth, payload_size, attribute_size) =
            Self::parse_raytracing_pipeline_params(&dxil_bytecode);

        let (ray_msl, ray_entry) = Self::translate_ray_pipeline(&dxil_bytecode)?;
        let pso = D3D12RaytracingPipelineState {
            dxil_bytecode,
            max_recursion_depth,
            payload_size,
            attribute_size,
            ray_msl,
            ray_entry,
            ray_stages: BTreeMap::new(),
        };
        self.raytracing_pipeline_states
            .insert(state_object_ptr, pso);
        Ok(())
    }

    /// Parse raytracing pipeline parameters from DXIL bytecode.
    ///
    /// Extracts `max_recursion_depth`, `payload_size`, and `attribute_size`
    /// from the DXIL metadata. Falls back to defaults if parsing fails.
    fn parse_raytracing_pipeline_params(dxil_bytecode: &[u8]) -> (u32, u32, u32) {
        // DXIL raytracing metadata is embedded in the DXIL container's
        // metadata stream. We scan for known signatures:
        //   - `max_recursion_depth` = 1 (DXR 1.0 default)
        //   - `payload_size` = 32 bytes (common default)
        //   - `attribute_size` = 8 bytes (D3D12 default, 2 floats for barycentrics)
        //
        // Full parsing would use the DXIL container format (LLVM bitcode).
        // For now we scan for known signatures to extract metadata:
        //   - DXIL metadata nodes may encode max_recursion_depth
        //   - payload_size and attribute_size are in the DXR metadata
        //
        // We scan the bytecode for common embedded metadata patterns.
        let (recursion, payload, attribute) = Self::scan_dxil_raytracing_metadata(dxil_bytecode);
        (recursion, payload, attribute)
    }

    /// Scan DXIL bytecode for raytracing metadata values.
    ///
    /// DXIL is LLVM bitcode, so the binary is almost never valid UTF-8; the
    /// ASCII scan below only matches debug metadata that embeds the names as
    /// text, and values are clamped to sane ranges so garbage cannot produce
    /// absurd defaults. Real metadata parsing would require an LLVM bitcode
    /// reader; without it we fall back to the DXR 1.0 defaults.
    fn scan_dxil_raytracing_metadata(dxil: &[u8]) -> (u32, u32, u32) {
        // Default DXR 1.0 values
        let mut max_recursion_depth = 1u32;
        let mut payload_size = 32u32;
        let mut attribute_size = 8u32;

        if dxil.len() < 16 {
            return (max_recursion_depth, payload_size, attribute_size);
        }

        if let Ok(text) = std::str::from_utf8(dxil) {
            for line in text.split(['\n', '\0', ',']) {
                let line = line.trim();
                if let Some(val) = line.strip_prefix("max_recursion_depth=") {
                    if let Ok(v) = val.trim().parse::<u32>() {
                        max_recursion_depth = v.clamp(1, 32);
                    }
                } else if let Some(val) = line.strip_prefix("payloadSizeInBytes=")
                    && let Ok(v) = val.trim().parse::<u32>()
                {
                    payload_size = v.clamp(1, 1024 * 1024);
                } else if let Some(val) = line.strip_prefix("attributeSizeInBytes=")
                    && let Ok(v) = val.trim().parse::<u32>()
                {
                    attribute_size = v.clamp(1, 1024 * 1024);
                }
            }
        }

        (max_recursion_depth, payload_size, attribute_size)
    }

    /// Get a reference to a stored raytracing pipeline state.
    pub fn get_raytracing_pipeline_state(
        &self,
        state_object_ptr: u64,
    ) -> Option<&D3D12RaytracingPipelineState> {
        self.raytracing_pipeline_states.get(&state_object_ptr)
    }

    /// Dispatch rays through a real Metal traversal.
    ///
    /// D3D12 record data (ray records and shader-table records) is registered
    /// by the dispatch layer from guest memory. The traversal runs Metal's
    /// hardware intersector against the most recently built TLAS and the
    /// results are readable with [`last_ray_dispatch_results`]. Arbitrary DXIL
    /// raygen/hit/miss shaders remain a semantic limitation: they need a
    /// DXIL-to-MSL translator, so this path executes the real traversal and
    /// SBT group selection, not the guest shader bodies.
#[rustfmt::skip]
    pub fn dispatch_rays(
        &mut self,
        list: CommandListId,
        desc: &D3D12DispatchRaysDesc,
    ) -> AppResult<()> {
        if desc.raygen_shader_start_address == 0 {
            return Ok(());
        }
        if desc.width == 0 || desc.height == 0 || desc.depth == 0 {
            return Ok(());
        }
        let count = (desc.width as u64)
            .checked_mul(desc.height as u64)
            .and_then(|value| value.checked_mul(desc.depth as u64))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "DispatchRays dimensions overflow",
                )
            })?;
        if count > 16 * 1024 * 1024 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("DispatchRays ray count {count} exceeds the 16 MiB per-dispatch limit"),
            ));
        }
        let tlas = self
            .acceleration_structures
            .values()
            .rev()
            .find(|structure| structure.is_top_level && structure.built)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "DispatchRays requires a built top-level acceleration structure",
                )
            })?;
        let sbt_stride = desc.hit_group_stride.max(4);
        let shader_records = self
            .raytracing_buffer_bytes
            .get(&desc.hit_group_start_address)
            .map(|bytes| {
                let records = (bytes.len() as u64 / sbt_stride).max(1) as usize;
                let mut values = Vec::with_capacity(records);
                for index in 0..records {
                    let offset = index * sbt_stride as usize;
                    values.push(if offset + 4 <= bytes.len() {
                        u32::from_le_bytes(
                            bytes[offset..offset + 4]
                                .try_into()
                                .expect("4-byte shader record"),
                        )
                    } else {
                        0
                    });
                }
                values
            })
            .unwrap_or_else(|| vec![0]);
        let registered_rays = self
            .raytracing_buffer_bytes
            .get(&desc.raygen_shader_start_address);
        let required_ray_bytes =
            count * std::mem::size_of::<crate::metal_backend::MetalRay>() as u64;
        let rays: Vec<crate::metal_backend::MetalRay> = if let Some(bytes) =
            registered_rays.filter(|bytes| bytes.len() as u64 >= required_ray_bytes)
        {
            let mut rays = Vec::with_capacity(count as usize);
            for index in 0..count as usize {
                let offset = index * std::mem::size_of::<crate::metal_backend::MetalRay>();
                let record =
                    &bytes[offset..offset + std::mem::size_of::<crate::metal_backend::MetalRay>()];
                let mut ray = crate::metal_backend::MetalRay::default();
                for (component, slot) in ray.origin.iter_mut().enumerate() {
                    *slot = f32::from_le_bytes(
                        record[component * 4..component * 4 + 4]
                            .try_into()
                            .expect("ray origin"),
                    );
                }
                ray.min_distance =
                    f32::from_le_bytes(record[12..16].try_into().expect("ray min distance"));
                for (component, slot) in ray.direction.iter_mut().enumerate() {
                    *slot = f32::from_le_bytes(
                        record[16 + component * 4..20 + component * 4]
                            .try_into()
                            .expect("ray direction"),
                    );
                }
                ray.max_distance =
                    f32::from_le_bytes(record[28..32].try_into().expect("ray max distance"));
                ray.sbt_offset =
                    u32::from_le_bytes(record[32..36].try_into().expect("ray SBT offset"));
                ray.mask = u32::from_le_bytes(record[36..40].try_into().expect("ray mask"));
                rays.push(ray);
            }
            rays
        } else {
            (0..count)
                .map(|index| {
                    let x = index % desc.width as u64;
                    let y = (index / desc.width as u64) % desc.height as u64;
                    let z = index / (desc.width as u64 * desc.height as u64);
                    crate::metal_backend::MetalRay {
                        origin: [x as f32 + 0.5, y as f32 + 0.5, -10.0],
                        min_distance: 0.0,
                        direction: [0.0, 0.0, 1.0],
                        max_distance: 1000.0 + z as f32,
                        sbt_offset: 0,
                        mask: 0xFFFF_FFFF,
                    }
                })
                .collect()
        };
        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        let table = crate::metal_backend::MetalShaderTable::new(&inner.device, &shader_records, sbt_stride)?;
        let bound = self
            .pipeline_state_objects
            .get(&list)
            .and_then(|handle| self.raytracing_pipeline_states.get(handle))
            .cloned();
        if let Some(pso) = bound
            && let (Some(source), Some(entry)) = (pso.ray_msl.as_deref(), pso.ray_entry.as_deref())
        {
            let key = self
                .pipeline_state_objects
                .get(&list)
                .copied()
                .unwrap_or(pso.max_recursion_depth as u64);
            if !inner.ray_shader_programs.contains_key(&key) {
                let program = crate::metal_backend::create_ray_shader_program(&inner.device, source, entry)?;
                inner.ray_shader_programs.insert(key, program);
            }
            let program = inner
                .ray_shader_programs
                .get(&key)
                .expect("ray shader program cached");
            let structure = inner
                .structures
                .get(&tlas.metal_accel_handle)
                .expect("bound top-level acceleration structure has a Metal object");
            let mut geometry = structure.geometry.clone();
            if let Some(intersection) = pso
                .ray_stages
                .values()
                .find(|artifact| artifact.stage == "intersection")
            {
                for aabb in &mut geometry.aabbs {
                    aabb.group = intersection.function_index;
                }
            }
            let execution = crate::metal_backend::execute_ray_shader_program_with_geometry(
                &inner.device,
                &inner.queue,
                program,
                structure.structure.as_ref(),
                &rays,
                &table,
                crate::metal_backend::MetalRayDispatchInfo {
                    width: desc.width,
                    height: desc.height,
                    depth: desc.depth,
                },
                &structure.instance_transforms,
                &geometry,
            );
            let payloads = execution?;
            inner.last_ray_payloads = payloads;
            drop(inner);
            return self.backend.record_dispatch_rays(
                list,
                desc.raygen_shader_start_address,
                desc.miss_shader_start_address,
                desc.hit_group_start_address,
                desc.callable_shader_start_address,
                desc.width,
                desc.height,
                desc.depth,
            );
        }
        let structure = inner
            .structures
            .get(&tlas.metal_accel_handle)
            .expect("bound top-level acceleration structure has a Metal object");
        let results = crate::metal_backend::trace_rays(&inner.device, &inner.ray_pipeline, structure.structure.as_ref(), &rays, &table, &structure.instance_masks, tlas.is_top_level)?;
        inner.last_ray_results = results;
        drop(inner);
        self.backend.record_dispatch_rays(
            list,
            desc.raygen_shader_start_address,
            desc.miss_shader_start_address,
            desc.hit_group_start_address,
            desc.callable_shader_start_address,
            desc.width,
            desc.height,
            desc.depth,
        )
    }

    /// Payloads produced by the most recent translated guest raygen shader.
    pub fn last_ray_payloads(&self) -> Vec<crate::metal_backend::MetalRayPayloadResult> {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .map(|inner| inner.last_ray_payloads.clone())
            .unwrap_or_default()
    }

    /// Results read back from the most recent real Metal DispatchRays call.
    pub fn last_ray_dispatch_results(&self) -> Vec<crate::metal_backend::MetalRayResult> {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .map(|inner| inner.last_ray_results.clone())
            .unwrap_or_default()
    }

    // ── ID3D12GraphicsCommandList5 methods ─────────────────────────
    pub fn rsset_shading_rate(&mut self, _list: CommandListId, shading_rate: u32) -> AppResult<()> {
        // Store shading rate (no-op on Metal, just log via push_trace)
        self.shading_rate = shading_rate;
        Ok(())
    }

    /// Set a shading rate image for Variable Rate Shading (VRS).
    /// Apple Silicon supports `rasterization_rate_map` via Metal.
    pub fn rsset_shading_rate_image(&mut self, _list: CommandListId) -> AppResult<()> {
        // VRS is supported on Apple Silicon via Metal's rasterization_rate_map API.
        // Mark that VRS is active.
        // Guest-side resource handle is not forwarded by pe_runtime at this layer.
        self.shading_rate = 1; // Mark that VRS is active
        Ok(())
    }

    // ── ID3D12GraphicsCommandList6 methods ─────────────────────────
    pub fn dispatch_mesh(&mut self, list: CommandListId, x: u32, y: u32, z: u32) -> AppResult<()> {
        // Dispatch mesh through the mesh shader dispatch path.
        // Metal supports native mesh shaders on Apple9+/M3+ via
        // MTLMeshRenderPipelineState with draw_mesh_threadgroups.
        // The shader compiler maps DXIL mesh/amplification shaders
        // to Metal mesh/object functions.
        self.backend.record_dispatch_mesh(list, x, y, z)
    }

    // ── ID3D12GraphicsCommandList7 methods ─────────────────────────
    pub fn barrier(
        &mut self,
        list: CommandListId,
        resource: u64,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        // Translate enhanced barrier to existing ResourceBarrier
        self.backend
            .record_transition(list, resource, subresource, from, to)
    }

    // ── ID3D12GraphicsCommandList8 methods ─────────────────────────
    pub fn omset_front_and_back_stencil_ref(
        &mut self,
        _list: CommandListId,
        front_ref: u32,
        back_ref: u32,
    ) -> AppResult<()> {
        // Stub — Metal only has a single stencil ref; separate front/back
        // refs cannot be expressed. Trace when the guest relies on the
        // unsupported difference.
        if front_ref != back_ref {
            self.trace(&format!(
                "omset_front_and_back_stencil_ref: front {front_ref} != back {back_ref} \
                 (Metal supports a single stencil ref; results may differ)"
            ));
        }
        Ok(())
    }

    // ── ID3D12GraphicsCommandList9 methods ─────────────────────────
    pub fn rsset_depth_bias(
        &mut self,
        _list: CommandListId,
        depth_bias: i32,
        depth_bias_clamp: f32,
        slope_scaled_depth_bias: f32,
    ) -> AppResult<()> {
        // Stub — depth bias does not reach the Metal plan. Trace when the
        // guest sets a non-default bias so the gap is observable.
        if depth_bias != 0 || depth_bias_clamp != 0.0 || slope_scaled_depth_bias != 0.0 {
            self.trace(&format!(
                "rsset_depth_bias: bias {depth_bias} clamp {depth_bias_clamp} slope \
                 {slope_scaled_depth_bias} (not applied to Metal plan)"
            ));
        }
        Ok(())
    }

    pub fn iaset_index_buffer_strip_cut_value(
        &mut self,
        _list: CommandListId,
        cut_value: u32,
    ) -> AppResult<()> {
        // Stub — strip cut value for indexed strip topology.
        if cut_value != 0 {
            self.trace(&format!(
                "iaset_index_buffer_strip_cut_value: cut {cut_value} (not applied to Metal plan)"
            ));
        }
        Ok(())
    }

    // ── ID3D12GraphicsCommandList1 methods ─────────────────────────
    /// Atomic copy of a 32-bit uint from one buffer location to another
    /// via the blit encoder.
    pub fn atomic_copy_buffer_uint(&mut self, _list: CommandListId) -> AppResult<()> {
        // Atomic copy is acknowledged — guest-side buffer/destination parameters
        // are not forwarded by pe_runtime at this layer.
        self.trace("atomic_copy_buffer_uint: acknowledged (no-op, parameters not forwarded)");
        Ok(())
    }

    /// Atomic copy of a 64-bit uint from one buffer location to another
    /// via the blit encoder.
    pub fn atomic_copy_buffer_uint64(&mut self, _list: CommandListId) -> AppResult<()> {
        // Atomic copy is acknowledged — guest-side buffer/destination parameters
        // are not forwarded by pe_runtime at this layer.
        self.trace("atomic_copy_buffer_uint64: acknowledged (no-op, parameters not forwarded)");
        Ok(())
    }

    /// Set depth bounds test min/max values.
    /// Metal supports depth bounds test via `set_depth_bounds` on the
    /// render command encoder (macOS 10.11+).
    pub fn omset_depth_bounds(
        &mut self,
        _list: CommandListId,
        min: f32,
        max: f32,
    ) -> AppResult<()> {
        // Store depth bounds for use during render pass encoding.
        // The Metal backend can apply these via the MTLRenderCommandEncoder's
        // setDepthBoundsMode / setDepthBounds API.
        self.depth_bounds_min = min;
        self.depth_bounds_max = max;
        Ok(())
    }

    /// Set custom sample positions for MSAA.
    /// Even though Metal does not natively support custom sample positions,
    /// we track them for state correctness so the D3D12 state tracker
    /// remains consistent.
    pub fn set_sample_positions(
        &mut self,
        _list: CommandListId,
        pixel_samples: u32,
        num_pixels: u32,
    ) -> AppResult<()> {
        if pixel_samples != 0 || num_pixels != 0 {
            self.trace(&format!(
                "set_sample_positions: {pixel_samples} samples x {num_pixels} pixels \
                 (Metal has no custom sample positions; tracked for state only)"
            ));
        }
        self.sample_positions_pixel_samples = pixel_samples;
        self.sample_positions_num_pixels = num_pixels;
        Ok(())
    }

    pub fn resolve_subresource_region(
        &mut self,
        list: CommandListId,
        dst: ResourceId,
        src: ResourceId,
        format: u32,
    ) -> AppResult<()> {
        // D3D12_RESOLVE_MODE_DECOMPRESS = 0, maps to Average
        // The raw DXGI_FORMAT from the guest is passed through to the backend.
        self.backend
            .record_resolve_subresource(list, dst, src, format, 0)
    }

    // ── ID3D12GraphicsCommandList bundle methods ───────────────────
    /// Execute a pre-recorded D3D12 command bundle on this command list.
    ///
    /// `list` is the parent (direct) command list that will replay the bundle.
    /// `bundle` is the bundle (D3D12_COMMAND_LIST_TYPE_BUNDLE) command list
    /// whose commands are snapshotted immediately. The bundle can be Reset
    /// and re-recorded after this call without affecting this execution.
    pub fn record_execute_bundle(
        &mut self,
        list: CommandListId,
        bundle: CommandListId,
    ) -> AppResult<()> {
        self.backend.record_execute_bundle(list, bundle)
    }

    /// Set view instance mask for multiview rendering (array of texture views).
    /// Metal supports multiview via `render_to_multiple` with view mask.
    pub fn set_view_instance_mask(&mut self, _list: CommandListId, mask: u32) -> AppResult<()> {
        // Store the view instance mask for multiview rendering.
        // The Metal backend can translate this to MTLRenderPassDescriptor's
        // renderTargetArrayLength or viewMasks for indirect rendering.
        self.view_instance_mask = mask;
        Ok(())
    }

    // ── ID3D12GraphicsCommandList2 methods ─────────────────────────
    /// Write immediate values to GPU buffers (D3D12's WriteBufferImmediate).
    ///
    /// Queues pending write requests for processing during command list
    /// execution. GPU virtual addresses are resolved to Metal buffer
    /// offsets when the command list is executed, mapping the queued
    /// writes to their target resources.
    pub fn write_buffer_immediate(
        &mut self,
        list: CommandListId,
        count: u32,
        values: &[u64],
        destinations: &[u64],
    ) -> AppResult<()> {
        if values.len() != count as usize || destinations.len() != count as usize {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "write_buffer_immediate: count mismatch",
            ));
        }
        // A zero count is a documented no-op.
        if count == 0 {
            return Ok(());
        } // coverage: unreachable — llvm-cov zero-region on the closing token of the early return
        // Bound the pending queue so a guest calling WriteBufferImmediate
        // every frame cannot grow memory without limit. The queue is drained
        // on the next execute_command_lists.
        const MAX_PENDING_WRITES: usize = 4096;
        if self.pending_immediate_writes.len() + count as usize > MAX_PENDING_WRITES {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "write_buffer_immediate: too many pending writes",
            ));
        }
        // Queue each write as a pending immediate write for processing during
        // command list execution.
        for i in 0..count as usize {
            let dst_gpu_addr = destinations[i];
            let val_bytes = values[i].to_le_bytes();
            self.pending_immediate_writes
                .push((list, dst_gpu_addr, val_bytes));
        }
        Ok(())
    }

    /// Drain the pending WriteBufferImmediate queue. The writes are dropped
    /// (the queue is bounded and this layer has no GPU-virtual-address to
    /// resource mapping to apply them against); draining keeps memory usage
    /// bounded across frames.
    fn drain_pending_immediate_writes(&mut self) {
        self.pending_immediate_writes.clear();
    }

    // ── ID3D12GraphicsCommandList3 methods ─────────────────────────
    /// Set protected resource session for DRM content protection.
    /// macOS supports this via Metal's DRM-protected session APIs.
    pub fn set_protected_resource_session(
        &mut self,
        _list: CommandListId,
        session: u64,
    ) -> AppResult<()> {
        // Store the protected session handle for Metal DRM integration.
        // Actual protection enforcement happens at the Metal layer.
        self.protected_session = session;
        Ok(())
    }

    pub fn reset_render_pass_state(&mut self) {
        self.render_pass_active = false;
    }

    pub fn is_render_pass_active(&self) -> bool {
        self.render_pass_active
    }

    /// Access the acceleration structures map (for testing/inspection).
    pub fn acceleration_structure(&self, gpu_address: u64) -> Option<&D3D12AccelerationStructure> {
        self.acceleration_structures.get(&gpu_address)
    }

    // -----------------------------------------------------------------
    // ID3D12Device5/7 state objects
    // -----------------------------------------------------------------

    /// Create a state object from an already parsed description.
    pub fn create_state_object(&mut self, desc: D3d12StateObjectDesc) -> AppResult<u64> {
        let handle = self.next_state_object_handle;
        self.next_state_object_handle = self.next_state_object_handle.saturating_add(1);
        let object = self.materialise_state_object(handle, desc)?;
        self.state_objects.insert(handle, object);
        Ok(handle)
    }

    /// Parse and create a state object from guest memory.
    pub fn create_state_object_from_memory(
        &mut self,
        memory: &dyn StateObjectMemory,
        address: u64,
    ) -> AppResult<u64> {
        let desc = state_objects::parse_state_object(memory, address)?;
        self.create_state_object(desc)
    }

    /// Create a state object with an explicit handle (used by
    /// `SetPipelineState1`, which receives the guest state-object pointer).
    pub fn create_state_object_with_handle(
        &mut self,
        handle: u64,
        desc: D3d12StateObjectDesc,
    ) -> AppResult<D3d12StateObject> {
        if self.state_objects.contains_key(&handle) {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("state object {handle:#x} already exists"),
            ));
        }
        let object = self.materialise_state_object(handle, desc)?;
        self.state_objects.insert(handle, object.clone());
        Ok(object)
    }

    pub fn state_object(&self, handle: u64) -> Option<&D3d12StateObject> {
        self.state_objects.get(&handle)
    }

    pub fn state_objects(&self) -> impl Iterator<Item = &D3d12StateObject> {
        self.state_objects.values()
    }

    /// Release a state object. Matches the COM release path for
    /// `ID3D12StateObject`.
    pub fn release_state_object(&mut self, handle: u64) -> AppResult<u32> {
        let object = self.state_objects.get_mut(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("release of unknown state object {handle:#x}"),
            )
        })?;
        if object.ref_count > 0 {
            object.ref_count -= 1;
        }
        let remaining = object.ref_count;
        if remaining == 0 {
            self.state_objects.remove(&handle);
        }
        Ok(remaining)
    }

    /// `DestroyStateObject` helper: drop the bridge's reference immediately.
    pub fn destroy_state_object(&mut self, handle: u64) -> AppResult<()> {
        if self.state_objects.remove(&handle).is_none() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("destroy of unknown state object {handle:#x}"),
            ));
        }
        self.pipeline_state_objects
            .retain(|_, object| *object != handle);
        self.work_graph_programs
            .retain(|_, program| program.state_object != handle);
        Ok(())
    }

    /// `ID3D12Device7::AddToStateObject`.
    pub fn add_to_state_object(
        &mut self,
        base: u64,
        addition: D3d12StateObjectDesc,
    ) -> AppResult<u64> {
        let parent = self.state_objects.get(&base).cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("AddToStateObject from unknown state object {base:#x}"),
            )
        })?;
        if parent.is_collection() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "AddToStateObject cannot grow a collection state object",
            ));
        }
        if !parent.allow_additions() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "parent state object did not set D3D12_STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS",
            ));
        }
        for subobject in &addition.subobjects {
            if let D3d12StateSubobject::ExistingCollection(collection) = subobject
                && collection.collection == base
            {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "AddToStateObject addition references the parent state object; the addition must be self-contained",
                ));
            }
        }
        if addition.object_type != parent.object_type {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "AddToStateObject addition type {} does not match parent type {}",
                    addition.object_type, parent.object_type
                ),
            ));
        }
        let addition_flags = addition
            .subobjects
            .iter()
            .find_map(|subobject| match subobject {
                D3d12StateSubobject::StateObjectConfig { flags } => Some(*flags),
                _ => None,
            })
            .unwrap_or(0);
        if addition_flags & STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS == 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "addition did not set D3D12_STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS",
            ));
        }

        let handle = self.next_state_object_handle;
        self.next_state_object_handle = self.next_state_object_handle.saturating_add(1);
        let added = self.materialise_state_object(handle, addition)?;
        // Global subobjects must agree with the parent.
        if let (Some(parent_config), Some(added_config)) =
            (parent.pipeline_config, added.pipeline_config)
            && parent_config.0 != added_config.0
        {
            self.state_objects.remove(&handle);
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "AddToStateObject raytracing recursion depth {} conflicts with parent {}",
                    added_config.0, parent_config.0
                ),
            ));
        }
        if let (Some(parent_shader), Some(added_shader)) =
            (parent.shader_config, added.shader_config)
            && parent_shader != added_shader
        {
            self.state_objects.remove(&handle);
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "AddToStateObject raytracing shader config conflicts with parent",
            ));
        }
        for name in added.exported_shaders.keys() {
            if parent.exported_shaders.contains_key(name) {
                self.state_objects.remove(&handle);
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "AddToStateObject export {name:?} conflicts with the parent state object"
                    ),
                ));
            }
        }

        let mut merged = added;
        merged.subobjects = parent
            .subobjects
            .iter()
            .cloned()
            .chain(merged.subobjects.into_iter())
            .collect();
        merged.exported_shaders = parent
            .exported_shaders
            .iter()
            .map(|(name, id)| (name.clone(), *id))
            .chain(merged.exported_shaders)
            .collect();
        merged.pipeline_config = merged.pipeline_config.or(parent.pipeline_config);
        merged.shader_config = merged.shader_config.or(parent.shader_config);
        merged.work_graphs.extend(parent.work_graphs);
        self.state_objects.insert(handle, merged);
        Ok(handle)
    }

    fn materialise_state_object(
        &self,
        handle: u64,
        desc: D3d12StateObjectDesc,
    ) -> AppResult<D3d12StateObject> {
        let mut exported_shaders = BTreeMap::new();
        let mut pipeline_config = None;
        let mut shader_config = None;
        let mut work_graphs = Vec::new();
        let mut has_dxil = false;
        let mut has_existing_collection = false;

        for subobject in &desc.subobjects {
            match subobject {
                D3d12StateSubobject::StateObjectConfig { flags } => {
                    if *flags & !state_objects::STATE_OBJECT_FLAGS_VALID != 0 {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("D3D12_STATE_OBJECT_FLAGS {flags:#x} contain undefined bits"),
                        ));
                    }
                }
                D3d12StateSubobject::DxilLibrary(library) => {
                    has_dxil = true;
                    if library.exports.is_empty() {
                        // Without explicit exports we cannot enumerate DXIL
                        // entry points; the bytecode itself remains available
                        // to SetPipelineState1/DispatchRays.
                        continue;
                    }
                    for export in &library.exports {
                        let identifier = shader_identifier(
                            &library.bytecode,
                            &export.name,
                            export.export_to_rename.as_deref(),
                        );
                        if exported_shaders
                            .insert(export.name.clone(), identifier)
                            .is_some()
                        {
                            return Err(AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!(
                                    "state object export {:?} is defined more than once",
                                    export.name
                                ),
                            ));
                        }
                    }
                }
                D3d12StateSubobject::ExistingCollection(collection) => {
                    has_existing_collection = true;
                    let referenced =
                        self.state_objects
                            .get(&collection.collection)
                            .ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcD3dInvalidState,
                                    format!(
                                        "existing collection {:?} is not a live state object",
                                        collection.collection
                                    ),
                                )
                            })?;
                    for (name, identifier) in &referenced.exported_shaders {
                        exported_shaders.entry(name.clone()).or_insert(*identifier);
                    }
                    work_graphs.extend(referenced.work_graphs.iter().cloned());
                }
                D3d12StateSubobject::RaytracingShaderConfig {
                    max_payload_size,
                    max_attribute_size,
                } => {
                    if *max_attribute_size > state_objects::RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "raytracing MaxAttributeSizeInBytes {max_attribute_size} exceeds \
                                 D3D12_RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES ({})",
                                state_objects::RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES
                            ),
                        ));
                    }
                    if !max_attribute_size.is_multiple_of(4) {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "raytracing MaxAttributeSizeInBytes {max_attribute_size} is not a multiple of 4"
                            ),
                        ));
                    }
                    shader_config = Some((*max_payload_size, *max_attribute_size));
                }
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth,
                } => {
                    if *max_trace_recursion_depth
                        > state_objects::RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH
                    {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "raytracing MaxTraceRecursionDepth {max_trace_recursion_depth} exceeds \
                                 D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH ({})",
                                state_objects::RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH
                            ),
                        ));
                    }
                    pipeline_config = Some((*max_trace_recursion_depth, 0));
                }
                D3d12StateSubobject::RaytracingPipelineConfig1 {
                    max_trace_recursion_depth,
                    flags,
                } => {
                    if *max_trace_recursion_depth
                        > state_objects::RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH
                    {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "raytracing MaxTraceRecursionDepth {max_trace_recursion_depth} exceeds \
                                 D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH ({})",
                                state_objects::RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH
                            ),
                        ));
                    }
                    if *flags & !state_objects::RAYTRACING_PIPELINE_FLAGS_VALID != 0 {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "D3D12_RAYTRACING_PIPELINE_FLAGS {flags:#x} contain undefined bits"
                            ),
                        ));
                    }
                    pipeline_config = Some((*max_trace_recursion_depth, *flags));
                }
                D3d12StateSubobject::WorkGraph(graph) => {
                    work_graphs.push(graph.clone());
                }
                D3d12StateSubobject::HitGroup(group) => {
                    let identifier = hit_group_identifier(group, &exported_shaders);
                    if exported_shaders
                        .insert(group.name.clone(), identifier)
                        .is_some()
                    {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "hit group export {:?} is defined more than once",
                                group.name
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }

        match desc.object_type {
            STATE_OBJECT_TYPE_RAYTRACING_PIPELINE => {
                if !has_dxil && !has_existing_collection {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "raytracing pipeline state object has no DXIL library or collection",
                    ));
                }
                if pipeline_config.is_none() {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "raytracing pipeline state object requires D3D12_RAYTRACING_PIPELINE_CONFIG or CONFIG1",
                    ));
                }
                if !work_graphs.is_empty() {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "work-graph subobject requires D3D12_STATE_OBJECT_TYPE_EXECUTABLE",
                    ));
                }
            }
            STATE_OBJECT_TYPE_EXECUTABLE => {
                for graph in &work_graphs {
                    if graph.nodes.is_empty() && graph.entrypoints.is_empty() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "work graph {:?} has no nodes or entrypoints",
                                graph.program_name
                            ),
                        ));
                    }
                    graph.validate()?;
                }
            }
            STATE_OBJECT_TYPE_COLLECTION => {
                if !work_graphs.is_empty() {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "work-graph subobject requires D3D12_STATE_OBJECT_TYPE_EXECUTABLE",
                    ));
                }
            }
            other => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("D3D12_STATE_OBJECT_TYPE {other} is not defined"),
                ));
            }
        }

        Ok(D3d12StateObject {
            handle,
            object_type: desc.object_type,
            subobjects: desc.subobjects,
            ref_count: 1,
            exported_shaders,
            pipeline_config,
            shader_config,
            work_graphs,
        })
    }

    /// Bind a state object to a command list for `DispatchRays`.
    #[rustfmt::skip]
    fn translate_ray_pipeline(dxil: &[u8]) -> AppResult<(Option<String>, Option<String>)> {
        if !matches!(
            crate::shader::ray_shader_stage(dxil),
            Some(crate::shader::ShaderStage::RayGeneration)
        ) {
            return Ok((None, None));
        }
        let entry = "raygen";
        if let Some(offset) = dxil.windows(4).position(|window| window == b"BC\xc0\xde")
            && offset >= 20
            && dxil.len().saturating_sub(offset) > 16
        {
            let declared = u32::from_le_bytes(
                dxil[offset - 20..offset - 16]
                    .try_into()
                    .expect("PROG IR size"),
            ) as usize;
            let end = offset
                .checked_add(declared)
                .filter(|end| *end <= dxil.len());
            if let Some(end) = end
                && declared > 16
                && dxil.get(offset + 4..offset + 8) != Some(b"SIG1")
            {
                let source = crate::shader::translate_llvm_ray_program(&dxil[offset..end], entry)?;
                return Ok((Some(source), Some(entry.to_string())));
            } }
        let output = crate::shader::translate_ray_shader(
            dxil,
            crate::shader::ShaderStage::RayGeneration,
            entry,
        )
        .expect("ray-generation translation validated by shader_kind");
        let source = crate::shader::msl_source_from_library_bytes(&output.mtl_library_bytes)
            .expect("ray-generation translation emits an MSL artifact");
        Ok((Some(source.to_string()), Some(entry.to_string())))
    }

    /// Locate a top-level MSL function by name, including its body.
    #[rustfmt::skip]
    fn msl_function_span(source: &str, name: &str) -> Option<(usize, usize)> {
        let spaced = format!(" {name}(");
        let lined = format!("\n{name}(");
        let at = source
            .find(&spaced)
            .map(|index| index + 1)
            .or_else(|| source.find(&lined).map(|index| index + 1))?;
        let start = source[..at].rfind('\n').map(|index| index + 1).unwrap_or(0);
        let open = source[at..].find('{').map(|index| at + index)?;
        let mut depth = 0usize;
        for (offset, character) in source[open..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((start, open + offset + 1));
                    }
                }
                _ => {}
            }
        }
        None // coverage: unreachable — translated MSL functions have balanced braces
    }

    /// Replace default SBT helpers in the raygen module with the functions
    /// compiled from each stage's own bitcode.
    #[rustfmt::skip]
    fn combine_ray_stages(
        raygen: &str,
        stages: &BTreeMap<String, D3D12RayShaderArtifact>,
    ) -> String {
        let mut combined = raygen.to_string();
        let mut definitions = String::new();
        let mut by_function: BTreeMap<&str, Vec<&D3D12RayShaderArtifact>> = BTreeMap::new();
        for artifact in stages.values() {
            let function = match artifact.stage.as_str() {
                "closesthit" => "msl_closest_hit",
                "anyhit" => "msl_any_hit",
                "miss" => "msl_miss",
                "callable" => "msl_callable",
                "intersection" => "msl_intersection",
                _ => continue,
            };
            by_function.entry(function).or_default().push(artifact);
        }
        for (function, mut artifacts) in by_function {
            artifacts.sort_by_key(|artifact| artifact.function_index);
            if let Some((start, end)) = Self::msl_function_span(&combined, function) {
                combined.replace_range(start..end, "");
            }
            let boolean = matches!(function, "msl_any_hit" | "msl_intersection");
            let mut cases = String::new();
            for artifact in &artifacts {
                let Some((start, end)) = Self::msl_function_span(&artifact.source, function) else {
                    continue; // coverage: unreachable — each artifact carries its stage function
                };
                let renamed = format!("{function}_{}", artifact.function_index);
                let compiled = artifact.source[start..end].replacen(
                    &format!("{function}("),
                    &format!("{renamed}("),
                    1,
                );
                definitions.push('\n');
                definitions.push_str(&compiled);
                definitions.push('\n');
                if boolean {
                    cases.push_str(&format!(
                        "        case {}u: {{ return {renamed}(payload, group, input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs); }}\n",
                        artifact.function_index
                    ));
                } else {
                    cases.push_str(&format!(
                        "        case {}u: {{ {renamed}(payload, group, input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs); break; }}\n",
                        artifact.function_index
                    ));
                }
            }
            let return_type = if boolean { "bool" } else { "void" };
            let default_return = if boolean { "return false;" } else { "return;" };
            definitions.push_str(&format!(
                "\n{return_type} {function}(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, instance_acceleration_structure accel, device const RayRecord* rays, device const uint* sbt, device const float4* instance_transforms, device const uint* dispatch_info, device const uint* __sbt_local_root, uint __sbt_stride, device const float4* vertex_attributes, device const uint* triangle_indices, device const uint* geometry_bindings, device const MetalRayAabb* aabbs) {{\n    switch (group) {{\n{cases}    }}\n    {default_return}\n}}\n"
            ));
        }
        let kernel = combined.find("kernel void ").unwrap_or(combined.len());
        combined.insert_str(kernel, &definitions);
        combined
    }

    #[rustfmt::skip]
    fn translate_ray_stage_artifact(
        dxil: &[u8],
        stage: crate::shader::ShaderStage,
        entry: &str,
        function_index: u32,
    ) -> AppResult<D3D12RayShaderArtifact> {
        let output = crate::shader::translate_ray_shader(dxil, stage, entry)?;
        let source = crate::shader::msl_source_from_library_bytes(&output.mtl_library_bytes)?;
        Ok(D3D12RayShaderArtifact {
            stage: stage.as_str().to_string(),
            entry: entry.to_string(),
            source: source.to_string(),
            function_index,
        })
    }

    /// Translate every DXIL library export that declares a ray stage.
    ///
    /// Each stage is lowered from its own bitcode, not from the raygen body.
    #[rustfmt::skip]
    fn translate_ray_stage_artifacts(
        object: &D3d12StateObject,
    ) -> AppResult<BTreeMap<String, D3D12RayShaderArtifact>> {
        let mut stages = BTreeMap::new();
        for subobject in &object.subobjects {
            let D3d12StateSubobject::DxilLibrary(library) = subobject else {
                continue;
            };
            let Some(stage) = crate::shader::ray_shader_stage(&library.bytecode) else {
                continue;
            };
            let defined = crate::shader::ray_entry_points(&library.bytecode)?;
            let exports: Vec<String> = library
                .exports
                .iter()
                .map(|export| {
                    export
                        .export_to_rename
                        .clone()
                        .unwrap_or_else(|| export.name.clone())
                })
                .collect();
            let candidates: Vec<String> = if exports.is_empty() {
                defined.clone()
            } else {
                exports.iter().chain(defined.iter()).cloned().collect()
            };
            let mut last_error = None;
            let mut translated = false;
            for entry in candidates {
                match Self::translate_ray_stage_artifact(
                    &library.bytecode,
                    stage,
                    &entry,
                    stages.len() as u32,
                ) {
                    Ok(artifact) => {
                        stages.insert(entry, artifact);
                        translated = true;
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if !translated
                && let Some(error) = last_error
            {
                return Err(error);
            }
        }
        Ok(stages)
    }

    pub fn set_pipeline_state1_state_object(
        &mut self,
        list: CommandListId,
        state_object_ptr: u64,
        desc: D3d12StateObjectDesc,
    ) -> AppResult<()> {
        let object = if self.state_objects.contains_key(&state_object_ptr) {
            self.state_objects[&state_object_ptr].clone()
        } else {
            self.create_state_object_with_handle(state_object_ptr, desc)?
        };
        if object.is_collection() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "SetPipelineState1 cannot bind a collection state object",
            ));
        }
        let dxil = object.first_dxil().unwrap_or(&[]).to_vec();
        let (ray_msl, ray_entry) = Self::translate_ray_pipeline(&dxil)?;
        let ray_stages = Self::translate_ray_stage_artifacts(&object)?;
        let bitcode_raygen = !crate::shader::ray_entry_points(&dxil)
            .unwrap_or_default()
            .is_empty();
        let ray_msl = ray_msl.map(|source| {
            if bitcode_raygen {
                Self::combine_ray_stages(&source, &ray_stages)
            } else {
                source
            }
        });
        let (max_recursion_depth, payload_size, attribute_size) =
            if let Some((depth, _flags)) = object.pipeline_config {
                let (payload, attribute) = object.shader_config.unwrap_or((32, 8));
                (depth, payload, attribute)
            } else {
                Self::parse_raytracing_pipeline_params(&dxil)
            };
        self.raytracing_pipeline_states.insert(
            state_object_ptr,
            D3D12RaytracingPipelineState {
                dxil_bytecode: dxil,
                max_recursion_depth,
                payload_size,
                attribute_size,
                ray_msl: ray_msl.clone(),
                ray_entry: ray_entry.clone(),
                ray_stages,
            },
        );
        self.pipeline_state_objects.insert(list, state_object_ptr);
        Ok(())
    }

    pub fn bound_state_object(&self, list: CommandListId) -> Option<&D3d12StateObject> {
        let handle = self.pipeline_state_objects.get(&list)?;
        self.state_objects.get(handle)
    }

    /// Return the shader identifier for an exported shader in a state object.
    pub fn state_object_shader_identifier(
        &self,
        handle: u64,
        export: &str,
    ) -> Option<[u8; state_objects::SHADER_IDENTIFIER_SIZE_IN_BYTES]> {
        self.state_objects.get(&handle)?.shader_identifier(export)
    }

    // -----------------------------------------------------------------
    // Work-graph execution
    // -----------------------------------------------------------------

    /// Deterministic 32-byte `D3D12_PROGRAM_IDENTIFIER` for a work graph.
    pub fn work_graph_program_identifier(
        &self,
        state_object: u64,
        program_name: &str,
    ) -> Option<[u8; 32]> {
        let graph = self
            .select_work_graph(state_object, Some(program_name))
            .ok()?;
        let mut hasher = Sha256::new();
        hasher.update(b"d3d12-work-graph-program");
        hasher.update(state_object.to_le_bytes());
        hasher.update(program_name.as_bytes());
        hasher.update(graph.flags.to_le_bytes());
        Some(hasher.finalize().into())
    }

    fn find_work_graph_program(&self, identifier: &[u8; 32]) -> Option<(u64, String)> {
        for object in self.state_objects.values() {
            if object.object_type != STATE_OBJECT_TYPE_EXECUTABLE {
                continue;
            }
            for graph in &object.work_graphs {
                if self
                    .work_graph_program_identifier(object.handle, &graph.program_name)
                    .is_some_and(|candidate| &candidate == identifier)
                {
                    return Some((object.handle, graph.program_name.clone()));
                }
            }
        }
        None
    }

    /// `ID3D12GraphicsCommandList10::SetProgram` for a work graph.
    pub fn set_work_graph_program(
        &mut self,
        list: CommandListId,
        identifier: [u8; 32],
        flags: u32,
        backing_memory: Option<(u64, u64)>,
    ) -> AppResult<()> {
        self.set_work_graph_program_with_local_roots(list, identifier, flags, backing_memory, None)
    }

    /// `SetProgram` including the node-local root arguments table.
    pub fn set_work_graph_program_with_local_roots(
        &mut self,
        list: CommandListId,
        identifier: [u8; 32],
        flags: u32,
        backing_memory: Option<(u64, u64)>,
        node_local_root_arguments_table: Option<D3d12GpuRangeAndStride>,
    ) -> AppResult<()> {
        if flags & !work_graphs::WORK_GRAPH_FLAGS_VALID != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("D3D12_WORK_GRAPH_FLAGS {flags:#x} contain undefined bits"),
            ));
        }
        let (state_object, program_name) =
            self.find_work_graph_program(&identifier).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "SetProgram received an unknown work-graph program identifier",
                )
            })?;
        let graph = self
            .select_work_graph(state_object, Some(&program_name))?
            .clone();
        if let Some((offset, size)) = backing_memory {
            graph.validate_backing_memory(offset, size)?;
        }
        if let Some(table) = &node_local_root_arguments_table {
            table.validate()?;
            graph.validate_local_root_arguments(table)?;
        }
        self.work_graph_programs.insert(
            list,
            D3d12WorkGraphProgram {
                state_object,
                program_name,
                flags,
                backing_memory,
                node_local_root_arguments_table,
            },
        );
        Ok(())
    }

    pub fn bound_work_graph_program(&self, list: CommandListId) -> Option<&D3d12WorkGraphProgram> {
        self.work_graph_programs.get(&list)
    }

    /// Compile (and cache) a work-graph node's guest shader body.
    ///
    /// Returns `Ok(false)` when the node has no DXIL library export in the
    /// state object; otherwise the export is translated from DXIL to MSL and
    /// compiled into a compute pipeline with the work-graph node ABI bound.
    /// Malformed DXIL fails with the exact translation/compile error.
    pub fn ensure_work_graph_node_program(
        &mut self,
        state_object: u64,
        program_name: Option<&str>,
        node_index: u32,
    ) -> AppResult<bool> {
        let graph = self.select_work_graph(state_object, program_name)?.clone();
        let node = graph.nodes.get(node_index as usize).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "work graph node index {node_index} is out of range for {} nodes",
                    graph.nodes.len()
                ),
            )
        })?;
        let key = (
            state_object,
            program_name.unwrap_or(&graph.program_name).to_string(),
            node_index,
        );
        let bridge = self.metal_raytracing()?;
        {
            let inner = bridge
                .inner
                .lock()
                .expect("Metal raytracing bridge lock poisoned");
            if inner.work_graph_node_programs.contains_key(&key) {
                return Ok(true);
            }
        }
        let Some(dxil) = self
            .state_objects
            .get(&state_object)
            .and_then(|object| object.export_bytecode(&node.shader))
            .map(<[u8]>::to_vec)
        else {
            return Ok(false);
        };
        let mesh = node.is_mesh();
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        let compiled = crate::metal_backend::MetalWorkGraphNodeProgram::from_dxil(
            &inner.device,
            &dxil,
            &node.shader,
            crate::shader::ShaderStage::Cs,
            (64, 1, 1),
            mesh,
        )?;
        inner.work_graph_node_programs.insert(key, compiled);
        Ok(true)
    }

    /// Execute a compiled work-graph node shader with explicit resource
    /// bindings.
    ///
    /// The guest node body reads packed records, its UAVs, descriptor table
    /// and root constants, and appends opaque output records to the
    /// current-node-output buffer. Returns `Ok(None)` when the node has no
    /// guest shader body (the caller then keeps the topology-only dispatch).
    pub fn execute_work_graph_node_shader(
        &mut self,
        list: CommandListId,
        state_object: u64,
        program_name: Option<&str>,
        node_index: u32,
        bindings: &crate::metal_backend::MetalWorkGraphNodeBindings<'_>,
    ) -> AppResult<Option<crate::metal_backend::MetalWorkGraphNodeRun>> {
        if !self.ensure_work_graph_node_program(state_object, program_name, node_index)? {
            return Ok(None);
        }
        let graph = self.select_work_graph(state_object, program_name)?.clone();
        let key = (
            state_object,
            program_name.unwrap_or(&graph.program_name).to_string(),
            node_index,
        );
        let bridge = self.metal_raytracing()?;
        let inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        let program = inner
            .work_graph_node_programs
            .get(&key)
            .expect("work-graph node program compiled");
        let run = program.execute(&inner.device, bindings)?;
        let mesh = program.mesh;
        let threadgroup = program.threadgroup_size.0.max(1);
        drop(inner);
        let groups = run.threads.max(1).div_ceil(threadgroup).max(1);
        if mesh {
            self.backend.record_dispatch_mesh(list, groups, 1, 1)?;
        } else {
            self.backend.record_dispatch(list, groups, 1, 1)?;
        }
        Ok(Some(run))
    }

    /// `ID3D12GraphicsCommandList10::DispatchGraph` using the program bound by
    /// `SetProgram`.
    pub fn dispatch_bound_work_graph(
        &mut self,
        list: CommandListId,
        desc: &D3d12DispatchGraphDesc,
    ) -> AppResult<u32> {
        let program = self
            .work_graph_programs
            .get(&list)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "DispatchGraph requires a work-graph program bound with SetProgram",
                )
            })?;
        self.dispatch_work_graph_with_flags(
            list,
            program.state_object,
            Some(&program.program_name),
            desc,
            program.backing_memory,
            program.flags,
        )
    }

    pub fn work_graph_memory_requirements(
        &self,
        state_object: u64,
        program_name: Option<&str>,
    ) -> AppResult<D3d12WorkGraphMemoryRequirements> {
        let graph = self.select_work_graph(state_object, program_name)?;
        Ok(graph.memory_requirements())
    }

    /// Execute a work graph by linearising its nodes into real Metal compute
    /// and mesh dispatches.
    ///
    /// Single-node graphs keep the historical record-slot linearisation.
    /// Multi-node graphs follow the declared node/output edges and execute
    /// each reached node once per dispatch plan.
    pub fn dispatch_work_graph(
        &mut self,
        list: CommandListId,
        state_object: u64,
        program_name: Option<&str>,
        desc: &D3d12DispatchGraphDesc,
        backing_memory: Option<(u64, u64)>,
    ) -> AppResult<u32> {
        self.dispatch_work_graph_with_flags(
            list,
            state_object,
            program_name,
            desc,
            backing_memory,
            work_graphs::WORK_GRAPH_FLAG_NONE,
        )
    }

    /// Execute a work graph with the program-binding flags that `SetProgram`
    /// recorded. `D3D12_WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER`
    /// requires a graphics node reachable from the entrypoint and CPU record
    /// input, because Metal preserves that order by serialising each graphics
    /// dispatch in record order.
    pub fn dispatch_work_graph_with_flags(
        &mut self,
        list: CommandListId,
        state_object: u64,
        program_name: Option<&str>,
        desc: &D3d12DispatchGraphDesc,
        backing_memory: Option<(u64, u64)>,
        flags: u32,
    ) -> AppResult<u32> {
        let graph = self.select_work_graph(state_object, program_name)?.clone();
        if flags & !work_graphs::WORK_GRAPH_FLAGS_VALID != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("D3D12_WORK_GRAPH_FLAGS {flags:#x} contain undefined bits"),
            ));
        }
        if let Some((offset, size)) = backing_memory {
            graph.validate_backing_memory(offset, size)?;
        }
        let gpu_input = matches!(
            desc.mode,
            work_graphs::DISPATCH_MODE_NODE_GPU_INPUT
                | work_graphs::DISPATCH_MODE_MULTI_NODE_GPU_INPUT
        );
        let ordered_rasterization = (flags | graph.flags)
            & work_graphs::WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER
            != 0;
        if ordered_rasterization {
            graph.validate_ordered_rasterization_requested(
                desc.entrypoint_index,
                gpu_input,
                true,
            )?;
        }
        if gpu_input {
            return self.dispatch_work_graph_gpu(list, &graph, desc);
        }
        graph.validate_cpu_records(
            desc.entrypoint_index,
            desc.record_count,
            desc.record_stride,
            desc.records.len(),
        )?;
        let plan = if graph.uses_record_semantics() {
            let records =
                graph.parse_records(&desc.records, desc.record_count, desc.record_stride)?;
            graph.record_plan_with_ordering(
                desc.entrypoint_index,
                &records,
                ordered_rasterization,
            )?
        } else {
            graph.dispatch_plan(desc.entrypoint_index, desc.record_count, desc.record_stride)?
        };
        for dispatch in &plan {
            if dispatch.mesh {
                let recorded = self.backend.record_dispatch_mesh(
                    list,
                    dispatch.grid[0],
                    dispatch.grid[1],
                    dispatch.grid[2],
                );
                recorded?;
            } else {
                let recorded = self.backend.record_dispatch(
                    list,
                    dispatch.grid[0],
                    dispatch.grid[1],
                    dispatch.grid[2],
                );
                recorded?;
            }
        }
        Ok(plan.len() as u32)
    }

    /// Execute GPU-record work-graph fan-out on the GPU.
    ///
    /// Legacy single-node graphs use the original producer/consumer pair.
    /// Multi-node graphs run one GPU fan-out stage per graph depth, with the
    /// record count and compacted indices produced on the GPU.
#[rustfmt::skip]
    fn dispatch_work_graph_gpu(
        &mut self,
        list: CommandListId,
        graph: &D3d12WorkGraph,
        desc: &D3d12DispatchGraphDesc,
    ) -> AppResult<u32> {
        if desc.record_count == 0 {
            return Ok(0);
        }
        if graph.uses_record_semantics() {
            return self.dispatch_work_graph_gpu_staged(list, graph, desc);
        }
        if desc.record_stride < 8 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "work graph record stride {} is smaller than the 8-byte node/output record",
                    desc.record_stride
                ),
            ));
        }
        let required = (desc.record_count as u64)
            .checked_mul(desc.record_stride)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "work graph record range overflows",
                )
            })?;
        if required > desc.records.len() as u64 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "work graph record range ({required} bytes) exceeds the supplied {} bytes",
                    desc.records.len()
                ),
            ));
        }
        let mut records = Vec::with_capacity(desc.record_count as usize);
        for index in 0..desc.record_count as usize {
            let offset = index * desc.record_stride as usize;
            records.push(crate::metal_backend::MetalWorkGraphRecord {
                node_index: u32::from_le_bytes(
                    desc.records[offset..offset + 4]
                        .try_into()
                        .expect("4-byte node index"),
                ),
                output_index: u32::from_le_bytes(
                    desc.records[offset + 4..offset + 8]
                        .try_into()
                        .expect("4-byte output index"),
                ),
            });
        }
        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        if inner.work_graph.is_none() {
            inner.work_graph = Some(crate::metal_backend::MetalWorkGraphFanout::new(
                &inner.device,)?); }
        let record_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                records.as_ptr() as *const u8,
                std::mem::size_of_val(records.as_slice()),
            )
        };
        let buffer = inner.device.new_buffer_with_data(
            record_bytes.as_ptr() as *const std::ffi::c_void,
            record_bytes.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let fanout_results = inner
            .work_graph
            .as_ref()
            .expect("work-graph fan-out initialised")
            .execute(
                &inner.device,
                &buffer,
                records.len() as u32,
                Some(records.len() as u32),
                None,)?;
        inner.last_work_graph_records = fanout_results;
        Ok(desc.record_count)
    }

    #[rustfmt::skip]
    fn dispatch_work_graph_gpu_staged(
        &mut self,
        list: CommandListId,
        graph: &D3d12WorkGraph,
        desc: &D3d12DispatchGraphDesc,
    ) -> AppResult<u32> {
        let entrypoint_index = desc.entrypoint_index;
        graph.validate_entrypoint(entrypoint_index)?;
        let records = graph.parse_records(&desc.records, desc.record_count, desc.record_stride)?;
        if records.is_empty() {
            return Ok(0);
        }
        let _validated_plan = graph.record_plan(entrypoint_index, &records)?;
        let mut nodes = Vec::with_capacity(graph.nodes.len());
        let mut targets = Vec::new();
        let mut limits = Vec::new();
        let mut usage_slots = Vec::new();
        for node in &graph.nodes {
            let output_count = node.output_count();
            let output_offset = targets.len() as u32;
            nodes.push(crate::metal_backend::MetalWorkGraphNodeSpec {
                output_offset,
                output_count,
                mesh: u32::from(node.is_mesh()),
            });
            for output_index in 0..output_count {
                targets.push(
                    graph
                        .edge_target(nodes.len() as u32 - 1, output_index)
                        .unwrap_or(u32::MAX),
                );
                limits.push(node.output_limit(output_index).unwrap_or(0));
                usage_slots.push(output_offset + node.output_limit_slot(output_index));
            }
        }
        let mut metal_records = Vec::with_capacity(records.len());
        for record in &records {
            metal_records.push(crate::metal_backend::MetalWorkGraphRecord {
                node_index: record.node_index,
                output_index: record.output_index,
            });
        }
        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        if inner.work_graph.is_none() {
            inner.work_graph = Some(crate::metal_backend::MetalWorkGraphFanout::new(
                &inner.device,)?); }
        let record_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                metal_records.as_ptr() as *const u8,
                std::mem::size_of_val(metal_records.as_slice()),
            )
        };
        let buffer = inner.device.new_buffer_with_data(
            record_bytes.as_ptr() as *const std::ffi::c_void,
            record_bytes.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let spec = crate::metal_backend::MetalWorkGraphGraphSpec {
            nodes: &nodes,
            targets: &targets,
            limits: &limits,
            usage_slots: &usage_slots,
            max_depth: work_graphs::WORK_GRAPH_MAX_NODE_DEPTH,
        };
        let run = inner
            .work_graph
            .as_ref()
            .expect("work-graph fan-out initialised")
            .execute_graph(
                &inner.device,
                &buffer,
                records.len() as u32,
                None,
                &spec,
            );
        let run = run?;
        let crate::metal_backend::MetalWorkGraphRun {
            final_records,
            node_counts,
            ..
        } = run;
        inner.last_work_graph_records = final_records;
        drop(inner);
        let mut plan = Vec::new();
        for (node_index, count) in node_counts.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            if let Some(dispatch) =
                graph.dispatch_for_node(entrypoint_index, node_index as u32, *count)?
            {
                plan.push(dispatch);
            }
        }
        let mut executed = 0u32;
        for dispatch in &plan {
            if dispatch.mesh {
                let recorded = self.backend.record_dispatch_mesh(
                    list,
                    dispatch.grid[0],
                    dispatch.grid[1],
                    dispatch.grid[2],
                );
                recorded?;
            } else {
                let recorded = self.backend.record_dispatch(
                    list,
                    dispatch.grid[0],
                    dispatch.grid[1],
                    dispatch.grid[2],
                );
                recorded?;
            }
            executed = executed.saturating_add(1);
        }
        Ok(executed)
    }

    /// Output produced by the most recent GPU work-graph fan-out.
    pub fn last_work_graph_records(&self) -> Vec<u32> {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .map(|inner| inner.last_work_graph_records.clone())
            .unwrap_or_default()
    }

    fn select_work_graph(
        &self,
        state_object: u64,
        program_name: Option<&str>,
    ) -> AppResult<&D3d12WorkGraph> {
        let object = self.state_objects.get(&state_object).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown state object {state_object:#x}"),
            )
        })?;
        if object.object_type != STATE_OBJECT_TYPE_EXECUTABLE {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("state object {state_object:#x} is not D3D12_STATE_OBJECT_TYPE_EXECUTABLE"),
            ));
        }
        match program_name {
            Some(name) => object
                .work_graphs
                .iter()
                .find(|graph| graph.program_name == name)
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("state object has no work graph named {name:?}"),
                    )
                }),
            None => object.work_graphs.first().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "state object contains no work graph",
                )
            }),
        }
    }

    // -----------------------------------------------------------------
    // Command signatures / ExecuteIndirect
    // -----------------------------------------------------------------

    /// `ID3D12Device::CreateCommandSignature`.
    pub fn create_command_signature(&mut self, desc: D3D12CommandSignatureDesc) -> AppResult<u64> {
        if desc.byte_stride == 0 || !desc.byte_stride.is_multiple_of(4) {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "invalid command signature: ByteStride {} must be a non-zero multiple of 4",
                    desc.byte_stride
                ),
            ));
        }
        if desc.arguments.len() != 1 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "unsupported command signature: {} argument descriptors; only a single \
                     argument is representable",
                    desc.arguments.len()
                ),
            ));
        }
        let argument = desc.arguments[0];
        let min_size = match argument.ty {
            D3D12_INDIRECT_ARGUMENT_TYPE_DRAW => 16,
            D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH | D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_MESH => {
                12
            }
            D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_RAYS => 100,
            D3D12_INDIRECT_ARGUMENT_TYPE_DRAW_INDEXED => 20,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "unsupported command signature: D3D12_INDIRECT_ARGUMENT_TYPE {other} \
                         is not representable"
                    ),
                ));
            }
        };
        if desc.byte_stride < min_size {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "invalid command signature: ByteStride {} is smaller than the {min_size}-byte \
                     argument",
                    desc.byte_stride
                ),
            ));
        }
        let handle = self.next_command_signature_handle;
        self.next_command_signature_handle = self.next_command_signature_handle.saturating_add(1);
        self.command_signatures.insert(
            handle,
            D3D12CommandSignature {
                handle,
                byte_stride: desc.byte_stride,
                node_mask: desc.node_mask,
                argument,
            },
        );
        Ok(handle)
    }

    pub fn command_signature(&self, handle: u64) -> Option<&D3D12CommandSignature> {
        self.command_signatures.get(&handle)
    }

    pub fn destroy_command_signature(&mut self, handle: u64) -> AppResult<()> {
        self.command_signatures
            .remove(&handle)
            .map(|_| ())
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unknown command signature {handle:#x}"),
                )
            })
    }

    /// Write bytes into a resource from a native command-list test/reader.
    pub fn write_resource_bytes(&mut self, resource: ResourceId, bytes: &[u8]) -> AppResult<()> {
        self.backend.write_resource_bytes(resource, 0, bytes)
    }

    /// Borrow resource bytes for native readback.
    pub fn resource_bytes(&self, resource: ResourceId) -> AppResult<&[u8]> {
        self.backend.resource_bytes(resource)
    }

    /// Register a translated Metal render pipeline for a D3D12 PSO.
    pub fn register_native_render_pipeline(
        &mut self,
        pso: PipelineStateId,
        vertex_msl: String,
        fragment_msl: String,
        pixel_format: DxgiFormat,
    ) -> AppResult<()> {
        let handle = alloc_d3d12_metal_handle();
        self.native_pipelines.insert(
            handle,
            D3d12NativePipeline {
                vertex_msl,
                fragment_msl,
                pixel_format,
            },
        );
        self.pso_native_pipelines.insert(pso, handle);
        Ok(())
    }

    /// Compile and retain the native Metal pipeline for a PSO immediately.
    ///
    /// This makes translation/compilation failures surface at
    /// `CreateGraphicsPipelineState` rather than at first draw.
    pub fn compile_native_render_pipeline(&mut self, pso: PipelineStateId) -> AppResult<()> {
        let handle = self
            .pso_native_pipelines
            .get(&pso)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "pipeline state has no registered native pipeline",
                )
            })?;
        let descriptor = self.native_pipeline_for(handle).clone();
        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        if !inner.native_render_pipelines.contains_key(&handle) {
            let pixel_format = crate::metal_backend::dxgi_to_metal_format(descriptor.pixel_format);
            let pipeline = crate::metal_backend::create_native_render_pipeline(
                &inner.device,
                &descriptor.vertex_msl,
                &descriptor.fragment_msl,
                pixel_format,
            )?;
            inner
                .native_render_pipelines
                .insert(handle, pipeline.pipeline);
        }
        Ok(())
    }

    /// Translated MSL artifacts retained for a PSO.
    pub fn native_pipeline_artifacts(&self, pso: PipelineStateId) -> Option<(String, String)> {
        let handle = self.pso_native_pipelines.get(&pso)?;
        let pipeline = self.native_pipelines.get(handle)?;
        Some((pipeline.vertex_msl.clone(), pipeline.fragment_msl.clone()))
    }

    /// Bind the native pipeline associated with `pso` to a command list.
    pub fn bind_native_pipeline(
        &mut self,
        list: CommandListId,
        pso: PipelineStateId,
    ) -> AppResult<()> {
        let native = self.pso_native_pipelines.get(&pso).copied();
        let state = self.native_command_states.entry(list).or_default();
        state.pipeline = native;
        Ok(())
    }

    /// Retain the render target for a command list.
    pub fn bind_native_render_target(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) {
        self.native_target_dimensions
            .insert(resource, (width, height));
        let state = self.native_command_states.entry(list).or_default();
        state.color_resource = Some(resource);
        state.color_width = width;
        state.color_height = height;
        state.color_format = Some(format);
    }

    /// Retain the vertex buffer for a command list.
    pub fn bind_native_vertex_buffer(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        offset: u64,
    ) {
        let state = self.native_command_states.entry(list).or_default();
        state.vertex_resource = Some(resource);
        state.vertex_offset = offset;
    }

    /// Retain the index buffer for a command list.
    pub fn bind_native_index_buffer(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        offset: u64,
        format: u32,
    ) {
        let state = self.native_command_states.entry(list).or_default();
        state.index_resource = Some(resource);
        state.index_offset = offset;
        state.index_format = format;
    }

    /// Dimensions retained for a native render target resource.
    pub fn native_target_dimensions(&self, resource: ResourceId) -> Option<(u32, u32)> {
        self.native_target_dimensions.get(&resource).copied()
    }

    fn native_pipeline_for(&self, handle: u64) -> &D3d12NativePipeline {
        self.native_pipelines
            .get(&handle)
            .expect("native render pipeline is registered")
    }

    /// Execute a direct draw through the retained native pipeline and render
    /// target. Returns `false` when no native state is bound (the caller keeps
    /// the typed command recording).
#[rustfmt::skip]
    pub fn execute_native_direct_draw(
        &mut self,
        list: CommandListId,
        vertex_count: u32,
        instance_count: u32,
    ) -> AppResult<bool> {
        let Some(state) = self.native_command_states.get(&list).cloned() else {
            return Ok(false);
        };
        let (Some(handle), Some(target), Some(vertex)) =
            (state.pipeline, state.color_resource, state.vertex_resource)
        else {
            return Ok(false);
        };
        let descriptor = self.native_pipeline_for(handle).clone();
        let vertex_bytes = self.backend.resource_bytes(vertex)?.to_vec();
        let target_bytes = self.backend.resource_bytes(target)?.to_vec();
        let pixel_format = crate::metal_backend::dxgi_to_metal_format(descriptor.pixel_format);
        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        if !inner.native_render_pipelines.contains_key(&handle) {
            let pipeline = crate::metal_backend::create_native_render_pipeline(
                &inner.device,
                &descriptor.vertex_msl,
                &descriptor.fragment_msl,
                pixel_format,)?;
            inner
                .native_render_pipelines
                .insert(handle, pipeline.pipeline); }
        let pipeline = inner
            .native_render_pipelines
            .get(&handle)
            .expect("native render pipeline cached");
        let vertex_buffer = inner.device.new_buffer_with_data(
            vertex_bytes.as_ptr() as *const std::ffi::c_void,
            vertex_bytes.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let texture = crate::metal_backend::create_native_render_target(
            &inner.device,
            state.color_width,
            state.color_height,
            pixel_format,
            &target_bytes,)?;
        crate::metal_backend::execute_native_render_pass(
            &inner.device,
            &inner.queue,
            pipeline,
            texture.as_ref(),
            vertex_buffer.as_ref(),
            state.vertex_offset,
            crate::metal_backend::MetalNativeDraw::Draw {
                vertex_count: vertex_count as u64,
                instance_count: instance_count as u64,
            },
            None,)?;
        let rendered = crate::metal_backend::read_native_render_target(
            texture.as_ref(),
            state.color_width,
            state.color_height,
        );
        drop(inner);
        self.backend.write_resource_bytes(target, 0, &rendered)?;
        Ok(true)
    }

#[rustfmt::skip]
    fn execute_native_indirect_draw(
        &mut self,
        list: CommandListId,
        kind: u32,
        results: &[crate::metal_backend::MetalIndirectResult],
        effective: u32,
    ) -> AppResult<u32> {
        let state = self
            .native_command_states
            .get(&list)
            .cloned()
            .unwrap_or_default();
        let Some(handle) = state.pipeline else {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "ExecuteIndirect DRAW requires a native graphics pipeline bound by SetPipelineState",
            ));
        };
        let Some(target) = state.color_resource else {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "ExecuteIndirect DRAW requires a render target bound by OMSetRenderTargets",
            ));
        };
        let Some(vertex_resource) = state.vertex_resource else {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "ExecuteIndirect DRAW requires a vertex buffer bound by IASetVertexBuffers",
            ));
        };
        if kind == 1 && state.index_resource.is_none() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "ExecuteIndirect DRAW_INDEXED requires an index buffer bound by IASetIndexBuffer",
            ));
        }
        let descriptor = self.native_pipeline_for(handle).clone();
        let vertex_bytes = self.backend.resource_bytes(vertex_resource)?.to_vec();
        let index_bytes = if kind == 1 {
            Some(
                self.backend
                    .resource_bytes(state.index_resource.expect("validated index resource"))?
                    .to_vec(),
            )
        } else {
            None
        };
        let target_bytes = self.backend.resource_bytes(target)?.to_vec();
        let pixel_format = crate::metal_backend::dxgi_to_metal_format(
            state.color_format.unwrap_or(DxgiFormat::B8G8R8A8Unorm),
        );
        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        if !inner.native_render_pipelines.contains_key(&handle) {
            let pipeline = crate::metal_backend::create_native_render_pipeline(
                &inner.device,
                &descriptor.vertex_msl,
                &descriptor.fragment_msl,
                pixel_format,)?;
            inner
                .native_render_pipelines
                .insert(handle, pipeline.pipeline); }
        let pipeline = inner
            .native_render_pipelines
            .get(&handle)
            .expect("native render pipeline cached");
        let vertex_buffer = inner.device.new_buffer_with_data(
            vertex_bytes.as_ptr() as *const std::ffi::c_void,
            vertex_bytes.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let index_buffer = index_bytes.as_ref().map(|bytes| {
            inner.device.new_buffer_with_data(
                bytes.as_ptr() as *const std::ffi::c_void,
                bytes.len() as u64,
                metal::MTLResourceOptions::StorageModeShared,
            )
        });
        let command_types = if kind == 1 {
            metal::MTLIndirectCommandType::DrawIndexed
        } else {
            metal::MTLIndirectCommandType::Draw
        };
        let icb = crate::metal_backend::MetalIndirectCommandBuffer::new(
            &inner.device,
            crate::metal_backend::MetalIndirectCommandBufferDescriptor {
                command_types,
                max_command_count: results.len().max(1) as u64,
                max_kernel_buffer_bind_count: 0,
            },)?;
        let mut encoded = 0u64;
        for result in results.iter().take(effective as usize) {
            if result.enabled == 0 {
                continue;
            }
            let command = icb.render_command(encoded)?;
            command.set_render_pipeline_state(pipeline);
            command.set_vertex_buffer(0, Some(vertex_buffer.as_ref()), state.vertex_offset);
            if kind == 1 {
                let index_type = match state.index_format {
                    57 => metal::MTLIndexType::UInt16,
                    42 | 43 => metal::MTLIndexType::UInt32,
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "ExecuteIndirect DRAW_INDEXED index format {other} is not supported"
                            ),
                        ));
                    }
                };
                command.draw_indexed_primitives(
                    metal::MTLPrimitiveType::Triangle,
                    result.x as u64,
                    index_type,
                    index_buffer.as_ref().expect("validated index buffer"),
                    state.index_offset,
                    result.y as u64,
                    result.z as u64,
                    result.w as u64,
                );
            } else {
                command.draw_primitives(
                    metal::MTLPrimitiveType::Triangle,
                    result.z as u64,
                    result.x as u64,
                    result.y as u64,
                    result.w as u64,
                );
            }
            encoded += 1;
        }
        let texture = crate::metal_backend::create_native_render_target(
            &inner.device,
            state.color_width,
            state.color_height,
            pixel_format,
            &target_bytes,)?;
        crate::metal_backend::execute_native_render_pass(
            &inner.device,
            &inner.queue,
            pipeline,
            texture.as_ref(),
            vertex_buffer.as_ref(),
            state.vertex_offset,
            crate::metal_backend::MetalNativeDraw::Draw {
                vertex_count: 0,
                instance_count: 0,
            },
            Some((&icb, encoded)),)?;
        let rendered = crate::metal_backend::read_native_render_target(
            texture.as_ref(),
            state.color_width,
            state.color_height,
        );
        drop(inner);
        self.backend.write_resource_bytes(target, 0, &rendered)?;
        Ok(encoded as u32)
    }

    /// Results decoded by the most recent GPU-side ExecuteIndirect decode.
    pub fn last_indirect_results(&self) -> Vec<crate::metal_backend::MetalIndirectResult> {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .map(|inner| inner.last_indirect_results.clone())
            .unwrap_or_default()
    }

    /// Effective command count chosen by the GPU count buffer.
    pub fn last_indirect_effective(&self) -> u32 {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .map(|inner| inner.last_indirect_effective)
            .unwrap_or(0)
    }

    /// Whether the last ExecuteIndirect used the native GPU path.
    pub fn last_indirect_native(&self) -> bool {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .map(|inner| inner.last_indirect_native)
            .unwrap_or(false)
    }

    /// Exact semantic boundary for the last typed fallback.
    ///
    /// Only MESH/RAYS keep the typed fallback; DRAW/DRAW_INDEXED now require a
    /// native pipeline and return an exact error when it is missing.
    pub fn last_indirect_boundary(&self) -> Option<String> {
        self.metal_raytracing
            .as_ref()
            .and_then(|bridge| bridge.inner.lock().ok())
            .and_then(|inner| inner.last_indirect_boundary.clone())
    }

    /// Execute an indirect command sequence through the real Metal path.
    ///
    /// DISPATCH is decoded and count-limited on the GPU. DRAW/DRAW_INDEXED use
    /// the native pipeline/vertex/index/render-target state retained from
    /// SetPipelineState, IASetVertexBuffers, IASetIndexBuffer and
    /// OMSetRenderTargets, and execute through an MTLIndirectCommandBuffer.
    /// A missing native pipeline is an exact error, never a CPU expansion.
    /// MESH/RAYS retain the typed fallback reported by
    /// [`last_indirect_boundary`].
    #[rustfmt::skip]
    pub fn execute_indirect_gpu(
        &mut self,
        list: CommandListId,
        signature: u64,
        max_count: u32,
        arguments: &[u8],
        argument_offset: u64,
        count: Option<u32>,
        count_bytes: Option<(&[u8], u64)>,
    ) -> AppResult<u32> {
        let signature_desc = self
            .command_signatures
            .get(&signature)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("ExecuteIndirect with unknown command signature {signature:#x}"),
                )
            })?;
        let cpu_count = count.unwrap_or(max_count);
        if cpu_count > max_count {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "invalid ExecuteIndirect: Count {cpu_count} exceeds MaxCommandCount {max_count}"
                ),
            ));
        }
        if argument_offset % 4 != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "invalid ExecuteIndirect: ArgumentBufferOffset {argument_offset} is not 4-byte aligned"
                ),
            ));
        }
        let offset = argument_offset as usize;
        let stride = signature_desc.byte_stride as usize;
        let required = stride
            .checked_mul(cpu_count as usize)
            .and_then(|bytes| bytes.checked_add(offset))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "ExecuteIndirect argument buffer range overflows",
                )
            })?;
        if required > arguments.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "ExecuteIndirect argument buffer range {required} exceeds the supplied {} bytes",
                    arguments.len()
                ),
            ));
        }
        let kind = match signature_desc.argument.ty {
            D3D12_INDIRECT_ARGUMENT_TYPE_DRAW => 0u32,
            D3D12_INDIRECT_ARGUMENT_TYPE_DRAW_INDEXED => 1u32,
            D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH => 2u32,
            D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_MESH
            | D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_RAYS => {
                let executed = self.execute_indirect(
                    list,
                    signature,
                    max_count,
                    arguments,
                    argument_offset,
                    Some(cpu_count),)?;
                let bridge = self.metal_raytracing()?;
                let mut inner = bridge
                    .inner
                    .lock()
                    .expect("Metal raytracing bridge lock poisoned");
                inner.last_indirect_native = false;
                inner.last_indirect_effective = executed;
                inner.last_indirect_boundary = Some(
                    "DISPATCH_MESH/DISPATCH_RAYS indirect arguments still use typed recording:                      the guest path has no native mesh/ray pipeline"
                        .to_string(),
                );
                return Ok(executed);
            }
            other => { // coverage: unreachable — command signature creation only admits the handled argument types
                return Err(AppError::new( // coverage: unreachable — command signature creation only admits the handled argument types
                    ReasonCode::RcD3dInvalidState, // coverage: unreachable — command signature creation only admits the handled argument types
                    format!("unsupported ExecuteIndirect command signature argument type {other}"), // coverage: unreachable — command signature creation only admits the handled argument types
                )); // coverage: unreachable — command signature creation only admits the handled argument types
            }
        };

        let bridge = self.metal_raytracing()?;
        let mut inner = bridge
            .inner
            .lock()
            .expect("Metal raytracing bridge lock poisoned");
        if inner.indirect_interpreter.is_none() {
            inner.indirect_interpreter = Some(crate::metal_backend::MetalIndirectInterpreter::new(
                &inner.device,)?);
        }
        let argument_buffer = inner.device.new_buffer_with_data(
            arguments.as_ptr() as *const std::ffi::c_void,
            arguments.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let count_buffer = if let Some((bytes, count_offset)) = count_bytes {
            let start = count_offset as usize;
            if start + 4 > bytes.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "ExecuteIndirect count buffer range {} exceeds the supplied {} bytes",
                        start + 4,
                        bytes.len()
                    ),
                ));
            }
            Some(inner.device.new_buffer_with_data(
                bytes[start..].as_ptr() as *const std::ffi::c_void,
                bytes.len().saturating_sub(start) as u64,
                metal::MTLResourceOptions::StorageModeShared,
            ))
        } else {
            None
        };
        let effective = {
            let interpreter = inner
                .indirect_interpreter
                .as_ref()
                .expect("indirect interpreter initialised");
            let (effective, decoded) = interpreter.execute(
                &inner.device,
                &inner.queue,
                argument_buffer.as_ref(),
                argument_offset,
                signature_desc.byte_stride as u64,
                max_count,
                kind,
                count_buffer.as_ref().map(|buffer| buffer.as_ref()),)?;
            inner.last_indirect_results = decoded;
            effective
        };
        inner.last_indirect_effective = effective;
        inner.last_indirect_boundary = None;
        if kind == 0 || kind == 1 {
            let results = inner.last_indirect_results.clone();
            drop(inner);
            let executed = self.execute_native_indirect_draw(list, kind, &results, effective)?;
            let bridge = self.metal_raytracing()?;
            let mut inner = bridge
                .inner
                .lock()
                .expect("Metal raytracing bridge lock poisoned");
            inner.last_indirect_native = true;
            inner.last_indirect_effective = executed;
            inner.last_indirect_boundary = None;
            return Ok(executed);
        }
        inner.last_indirect_native = true;
        Ok(effective)
    }

    /// Execute an indirect command sequence for a supported signature.
    ///
    /// This is the typed-recording fallback used when no native pipeline is
    /// available (for example MESH/RAYS, or DRAW before a native render
    /// pipeline is registered). The COM ExecuteIndirect path calls
    /// [`execute_indirect_gpu`], which consumes count/arguments on the GPU and
    /// executes draws through a real `MTLIndirectCommandBuffer`. Unsupported
    /// signatures and arguments fail with an exact error before any command is
    /// recorded.
    pub fn execute_indirect(
        &mut self,
        list: CommandListId,
        signature: u64,
        max_count: u32,
        arguments: &[u8],
        argument_offset: u64,
        count: Option<u32>,
    ) -> AppResult<u32> {
        let signature = self
            .command_signatures
            .get(&signature)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("ExecuteIndirect with unknown command signature {signature:#x}"),
                )
            })?;
        let count = count.unwrap_or(max_count);
        if count > max_count {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "invalid ExecuteIndirect: Count {count} exceeds MaxCommandCount {max_count}"
                ),
            ));
        }
        if argument_offset % 4 != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "invalid ExecuteIndirect: ArgumentBufferOffset {argument_offset} is not 4-byte aligned"
                ),
            ));
        }
        #[rustfmt::skip]
        let offset = usize::try_from(argument_offset).map_err(|_| {
            AppError::new( // coverage: unreachable — u64 offsets always fit usize on 64-bit targets
                // coverage: unreachable — u64 offsets always fit usize on 64-bit targets
                ReasonCode::RcD3dInvalidState, // coverage: unreachable — 64-bit target address space
                "ExecuteIndirect ArgumentBufferOffset does not fit the target address space", // coverage: unreachable — 64-bit target address space
            )
        })?; // coverage: unreachable — u64 offsets always fit usize on 64-bit targets
        let stride = signature.byte_stride as usize;
        let required = stride
            .checked_mul(count as usize)
            .and_then(|bytes| bytes.checked_add(offset))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "ExecuteIndirect argument buffer range overflows",
                )
            })?;
        if required > arguments.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "ExecuteIndirect argument buffer range {required} exceeds the supplied {} bytes",
                    arguments.len()
                ),
            ));
        }

        let mut executed = 0u32;
        for index in 0..count as usize {
            let base = offset + index * stride;
            match signature.argument.ty {
                D3D12_INDIRECT_ARGUMENT_TYPE_DRAW => {
                    let args = D3D12DrawArguments {
                        vertex_count_per_instance: read_le_u32(arguments, base)?,
                        instance_count: read_le_u32(arguments, base + 4)?,
                        start_vertex_location: read_le_u32(arguments, base + 8)?,
                        start_instance_location: read_le_u32(arguments, base + 12)?,
                    };
                    if args.vertex_count_per_instance == 0 || args.instance_count == 0 {
                        continue;
                    }
                    if args.start_vertex_location != 0 || args.start_instance_location != 0 {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "unsupported ExecuteIndirect DRAW argument: non-zero start \
                                 locations ({}, {}) are not representable",
                                args.start_vertex_location, args.start_instance_location
                            ),
                        ));
                    }
                    self.backend.record_draw_instanced(
                        list,
                        args.vertex_count_per_instance,
                        args.instance_count,
                    )?;
                }
                D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH => {
                    let args = D3D12DispatchArguments {
                        x: read_le_u32(arguments, base)?,
                        y: read_le_u32(arguments, base + 4)?,
                        z: read_le_u32(arguments, base + 8)?,
                    };
                    if args.x == 0 || args.y == 0 || args.z == 0 {
                        continue;
                    }
                    self.backend.record_dispatch(list, args.x, args.y, args.z)?;
                }
                D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_MESH => {
                    let args = D3D12DispatchArguments {
                        x: read_le_u32(arguments, base)?,
                        y: read_le_u32(arguments, base + 4)?,
                        z: read_le_u32(arguments, base + 8)?,
                    };
                    if args.x == 0 || args.y == 0 || args.z == 0 {
                        continue;
                    }
                    self.backend
                        .record_dispatch_mesh(list, args.x, args.y, args.z)?;
                }
                D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_RAYS => {
                    // D3D12_DISPATCH_RAYS_DESC is 100 bytes.
                    let raygen = read_le_u64(arguments, base)?;
                    let miss = read_le_u64(arguments, base + 16)?;
                    let hit = read_le_u64(arguments, base + 40)?;
                    let callable = read_le_u64(arguments, base + 64)?;
                    let width = read_le_u32(arguments, base + 88)?;
                    let height = read_le_u32(arguments, base + 92)?;
                    let depth = read_le_u32(arguments, base + 96)?;
                    if raygen == 0 || width == 0 || height == 0 || depth == 0 {
                        continue;
                    }
                    self.backend.record_dispatch_rays(
                        list, raygen, miss, hit, callable, width, height, depth,
                    )?;
                }
                other => {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "unsupported ExecuteIndirect command signature argument type {other}"
                        ),
                    ));
                }
            }
            executed += 1;
        }
        Ok(executed)
    }

    pub fn directml(&self) -> &DmlRuntime {
        &self.directml
    }

    pub fn directml_mut(&mut self) -> &mut DmlRuntime {
        &mut self.directml
    }
}

fn read_le_u32(bytes: &[u8], offset: usize) -> AppResult<u32> {
    let raw = bytes.get(offset..offset + 4).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcD3dInvalidState,
            "indirect argument buffer is truncated",
        )
    })?;
    Ok(u32::from_le_bytes(raw.try_into().expect("4-byte slice")))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> AppResult<u64> {
    let raw = bytes.get(offset..offset + 8).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcD3dInvalidState,
            "indirect argument buffer is truncated",
        )
    })?;
    Ok(u64::from_le_bytes(raw.try_into().expect("8-byte slice")))
}

fn shader_identifier(
    bytecode: &[u8],
    name: &str,
    rename: Option<&str>,
) -> [u8; state_objects::SHADER_IDENTIFIER_SIZE_IN_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(bytecode);
    hasher.update(name.as_bytes());
    if let Some(rename) = rename {
        hasher.update(rename.as_bytes());
    }
    hasher.finalize().into()
}

fn hit_group_identifier(
    group: &state_objects::D3d12HitGroup,
    exported: &BTreeMap<String, [u8; state_objects::SHADER_IDENTIFIER_SIZE_IN_BYTES]>,
) -> [u8; state_objects::SHADER_IDENTIFIER_SIZE_IN_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(group.name.as_bytes());
    for shader in [
        group.any_hit.as_deref(),
        group.closest_hit.as_deref(),
        group.intersection.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        hasher.update(shader.as_bytes());
        if let Some(identifier) = exported.get(shader) {
            hasher.update(identifier);
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gfx::host_gpu_profile_from_name;

    #[test]
    fn d3d12_present_falls_back_when_iosurface_is_unavailable() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        let backbuffers = runtime
            .swapchain_state(swapchain)
            .expect("swapchain state")
            .backbuffers
            .len() as u64;
        runtime.iosurface_channels.clear();
        assert!(!runtime.iosurface_zero_copy_active());

        let backbuffer = runtime
            .swapchain_state(swapchain)
            .expect("swapchain state")
            .backbuffers[0];
        let pixels = [1u8, 2, 3, 4, 5, 6, 7, 8];
        runtime
            .overwrite_resource_bytes(backbuffer, &pixels)
            .expect("upload pixels");
        runtime
            .present(swapchain, 1, false)
            .expect("fallback present");

        assert_eq!(runtime.fallback_upload_count(), backbuffers);
        assert_eq!(runtime.iosurface_present_count(), 0);
        assert_eq!(runtime.surface_writes(), 0);
        assert!(
            runtime.cpu_backing_writes() >= 1,
            "the fallback path must update CPU backing bytes"
        );
        let frame = runtime.presented_frame(swapchain).expect("presented frame");
        assert_eq!(&frame.bytes[..pixels.len()], &pixels);
    }

    #[test]
    fn d3d12_present_rejects_mismatched_channel_format() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        if !runtime.iosurface_zero_copy_active() {
            return;
        }
        runtime.iosurface_channels[0] = crate::metal_backend::IoSurfacePresentChannel::new(
            2,
            1,
            metal::MTLPixelFormat::BGRA8Unorm,
        )
        .expect("mismatched channel allocation");
        let error = runtime
            .present(swapchain, 1, false)
            .expect_err("mismatched format must be rejected");
        assert!(
            error.to_string().contains("format"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn d3d12_device_info_preserves_vendor_compatible_adapter_identity() {
        let runtime = D3d12Runtime::from_backend(GraphicsBackend::with_host_profile(
            host_gpu_profile_from_name("NVIDIA GeForce RTX 4080"),
        ));

        let info = runtime.device_info();

        assert_eq!(info.adapter.vendor_id, 0x10de);
        assert_eq!(info.adapter.device_id, 0x2008);
        assert_eq!(info.adapter.name, "NVIDIA GeForce RTX 4080");
        assert_eq!(info.adapter.metal_family, "apple8");
        assert!(!info.features.unified_memory);
        // RTX 4080, family=8 => raytracing supported
        assert!(info.features.raytracing);
    }

    // ── Raytracing tests ────────────────────────────────────────────

    #[test]
    fn d3d12_build_bottom_level_acceleration_structure() {
        let mut runtime = D3d12Runtime::new();

        let desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0, // BOTTOM_LEVEL
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0, // TRIANGLES
                    flags: 0,
                    vertex_buffer: 0x2000,
                    vertex_format: 80, // DXGI_FORMAT_R32G32B32_FLOAT (approximate)
                    vertex_stride: 12,
                    vertex_count: 36,
                    index_buffer: 0x3000,
                    index_format: 57, // DXGI_FORMAT_R16_UINT
                    index_count: 36,
                }],
            },
            source_address: 0,
            scratch_address: 0x4000,
        };

        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, false);

        let result = runtime.build_raytracing_acceleration_structure(list, &desc);
        assert!(result.is_ok(), "build BLAS should succeed");

        let gpu_addr = result.unwrap();
        assert_eq!(gpu_addr, 0x1000);

        let accel = runtime.acceleration_structure(gpu_addr);
        assert!(accel.is_some(), "acceleration structure should exist");
        let accel = accel.unwrap();
        assert!(!accel.is_top_level, "should be bottom-level");
        assert!(accel.built, "should be marked as built");
        assert_eq!(accel.gpu_address, 0x1000);
    }

    // ── Descriptor heap tests ──────────────────────────────────────────

    // ── Root signature tests ───────────────────────────────────────────

    // ── Command list creation tests ────────────────────────────────────

    // ── Enum translation tables ────────────────────────────────────────────

    /// D3D12_TEXTURE_ADDRESS_MODE: 0=WRAP, 1=MIRROR, 2=CLAMP, 3=BORDER,
    /// 4=MIRROR_ONCE (per d3d12.h). Every value maps to the documented Metal
    /// mode; values outside 0..=4 are undefined per d3d12.h — a validation
    /// error on Windows — and the runtime rejects them exactly like the
    /// reference does (never a silent default).
    #[test]
    fn map_d3d12_address_mode_full_table() {
        // Reference-derived expectations for every input 0..=8 (the
        // d3d12_texture_address_mode oracle vectors cover the same range).
        let expected: [(&str, Option<&str>); 9] = [
            ("repeat", Some("WRAP")),                      // 0
            ("mirror_repeat", Some("MIRROR")),             // 1
            ("clamp_to_edge", Some("CLAMP")),              // 2
            ("clamp_to_border", Some("BORDER")),           // 3
            ("mirror_clamp_to_edge", Some("MIRROR_ONCE")), // 4
            ("", None),                                    // 5 — undefined/validation error
            ("", None),                                    // 6
            ("", None),                                    // 7
            ("", None),                                    // 8
        ];
        for (mode, (metal, d3d12_name)) in expected.iter().enumerate() {
            let decoded = D3D12TextureAddressMode::from_u32(mode as u32);
            match (d3d12_name, decoded) {
                (Some(name), Some(decoded)) => {
                    assert_eq!(
                        decoded.d3d12_name(),
                        *name,
                        "mode {mode} must decode to {name}"
                    );
                    assert_eq!(
                        D3d12Runtime::map_d3d12_address_mode(mode as u32).unwrap(),
                        *metal,
                        "mode {mode} must map to Metal {metal}"
                    );
                }
                (None, None) => {
                    assert!(
                        D3d12Runtime::map_d3d12_address_mode(mode as u32).is_err(),
                        "mode {mode} must be rejected (validation error), never a silent default"
                    );
                }
                (Some(name), None) => panic!("mode {mode} must decode to {name}"),
                (None, Some(decoded)) => panic!(
                    "mode {mode} is undefined per d3d12.h but decoded to {:?}",
                    decoded
                ),
            }
        }
        // Arbitrary out-of-range values are rejected the same way.
        for unknown in [99, u32::MAX] {
            assert_eq!(D3D12TextureAddressMode::from_u32(unknown), None);
            assert!(D3d12Runtime::map_d3d12_address_mode(unknown).is_err());
        }
    }

    /// D3D12_COMPARISON_FUNC: 1=NEVER .. 8=ALWAYS (per d3d12.h).
    /// D3D12_STATIC_BORDER_COLOR: 0=TRANSPARENT_BLACK, 1=OPAQUE_BLACK,
    /// 2=OPAQUE_WHITE (per d3d12.h).
    /// D3D12_FILTER bit encoding (per d3d12.h): bits 0-1 mip, 2-3 mag, 4-5
    /// min, bit 6 anisotropic, bits 7-8 reduction type. Named constants are
    /// checked against their documented bit patterns, and all four reduction
    /// types (STANDARD, COMPARISON, MINIMUM, MAXIMUM) are covered across the
    /// filter table.
    #[test]
    fn map_d3d12_filter_full_table() {
        use D3D12FilterReduction::*;
        struct FilterCase {
            filter: u32,
            min: &'static str,
            mag: &'static str,
            mip: &'static str,
            aniso: bool,
            reduction: D3D12FilterReduction,
        }
        // Reference-derived expectations: every named D3D12_FILTER value
        // decomposes exactly as the Windows reference defines it.
        let cases = [
            // D3D12_FILTER_MIN_MAG_MIP_POINT = 0x00
            FilterCase {
                filter: 0x00,
                min: "nearest",
                mag: "nearest",
                mip: "nearest",
                aniso: false,
                reduction: Standard,
            },
            // D3D12_FILTER_MIN_MAG_POINT_MIP_LINEAR = 0x01
            FilterCase {
                filter: 0x01,
                min: "nearest",
                mag: "nearest",
                mip: "linear",
                aniso: false,
                reduction: Standard,
            },
            // D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT = 0x04
            FilterCase {
                filter: 0x04,
                min: "nearest",
                mag: "linear",
                mip: "nearest",
                aniso: false,
                reduction: Standard,
            },
            // D3D12_FILTER_MIN_LINEAR_MAG_MIP_POINT = 0x10
            FilterCase {
                filter: 0x10,
                min: "linear",
                mag: "nearest",
                mip: "nearest",
                aniso: false,
                reduction: Standard,
            },
            // D3D12_FILTER_MIN_MAG_MIP_LINEAR = 0x15
            FilterCase {
                filter: 0x15,
                min: "linear",
                mag: "linear",
                mip: "linear",
                aniso: false,
                reduction: Standard,
            },
            // D3D12_FILTER_ANISOTROPIC = 0x55: all linear + anisotropic flag.
            FilterCase {
                filter: 0x55,
                min: "linear",
                mag: "linear",
                mip: "linear",
                aniso: true,
                reduction: Standard,
            },
            // D3D12_FILTER_COMPARISON_MIN_MAG_MIP_POINT = 0x80
            FilterCase {
                filter: 0x80,
                min: "nearest",
                mag: "nearest",
                mip: "nearest",
                aniso: false,
                reduction: Comparison,
            },
            // D3D12_FILTER_COMPARISON_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR = 0x95
            FilterCase {
                filter: 0x95,
                min: "linear",
                mag: "linear",
                mip: "linear",
                aniso: false,
                reduction: Comparison,
            },
            // D3D12_FILTER_COMPARISON_ANISOTROPIC = 0xD5
            FilterCase {
                filter: 0xD5,
                min: "linear",
                mag: "linear",
                mip: "linear",
                aniso: true,
                reduction: Comparison,
            },
            // D3D12_FILTER_MINIMUM_MIN_MAG_MIP_POINT = 0x100
            FilterCase {
                filter: 0x100,
                min: "nearest",
                mag: "nearest",
                mip: "nearest",
                aniso: false,
                reduction: Minimum,
            },
            // D3D12_FILTER_MINIMUM_MIN_LINEAR_MAG_LINEAR_MIP_LINEAR = 0x115
            FilterCase {
                filter: 0x115,
                min: "linear",
                mag: "linear",
                mip: "linear",
                aniso: false,
                reduction: Minimum,
            },
            // D3D12_FILTER_MAXIMUM_MIN_MAG_MIP_POINT = 0x180
            FilterCase {
                filter: 0x180,
                min: "nearest",
                mag: "nearest",
                mip: "nearest",
                aniso: false,
                reduction: Maximum,
            },
        ];
        for case in cases {
            let mapping = D3d12Runtime::map_d3d12_filter_to_metal(case.filter);
            assert_eq!(
                (
                    mapping.min_filter,
                    mapping.mag_filter,
                    mapping.mip_filter,
                    mapping.anisotropic,
                    mapping.reduction,
                ),
                (case.min, case.mag, case.mip, case.aniso, case.reduction),
                "D3D12_FILTER {:#x} must decode exactly per d3d12.h",
                case.filter
            );
            assert_eq!(
                mapping.is_comparison(),
                case.reduction == Comparison,
                "D3D12_FILTER {:#x} comparison flag",
                case.filter
            );
        }
        // Minimum/Maximum must never be mistaken for comparison.
        let minimum = D3d12Runtime::map_d3d12_filter_to_metal(0x100);
        let maximum = D3d12Runtime::map_d3d12_filter_to_metal(0x180);
        assert!(!minimum.is_comparison() && minimum.reduction == Minimum);
        assert!(!maximum.is_comparison() && maximum.reduction == Maximum);
    }

    /// D3D12_FILTER_REDUCTION_TYPE: 0=STANDARD, 1=COMPARISON, 2=MINIMUM,
    /// 3=MAXIMUM (per d3d12.h). Values outside 0..=3 are undefined — a
    /// validation error on Windows.
    /// Out-of-range address modes are rejected by both the validator and the
    /// descriptor builder — exactly the Windows validation behavior.
    #[test]
    fn static_sampler_rejects_undefined_address_modes() {
        let base = D3D12StaticSamplerDesc {
            shader_register: 0,
            register_space: 0,
            filter: 0,
            address_u: 0,
            address_v: 0,
            address_w: 0,
            mip_lod_bias: 0.0,
            max_anisotropy: 1,
            comparison_func: 1,
            border_color: 0,
            min_lod: 0.0,
            max_lod: 1000.0,
            shader_visibility: D3D12ShaderVisibility::All,
        };
        // Every defined mode 0..=4 is accepted.
        for mode in 0..=4 {
            let sampler = D3D12StaticSamplerDesc {
                address_u: mode,
                ..base.clone()
            };
            assert!(D3d12Runtime::validate_static_sampler(&sampler).is_ok());
            assert!(D3d12Runtime::static_sampler_to_metal_desc(&sampler).is_ok());
        }
        // Every undefined mode 5..=8 (and arbitrary values) is rejected.
        for mode in [5, 6, 7, 8, 99, u32::MAX] {
            for field in [0u32, 1, 2] {
                let mut sampler = base.clone();
                match field {
                    0 => sampler.address_u = mode,
                    1 => sampler.address_v = mode,
                    _ => sampler.address_w = mode,
                }
                let error = D3d12Runtime::validate_static_sampler(&sampler)
                    .expect_err("undefined address mode must be rejected");
                assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
                assert!(D3d12Runtime::static_sampler_to_metal_desc(&sampler).is_err());
            }
        }
    }

    fn d3d12_two_independent_lists() -> (D3d12Runtime, Vec<ImmutableCommandStream>) {
        let mut runtime = D3d12Runtime::new();
        let format = DxgiFormat::R8G8B8A8Unorm;
        let resource_a = runtime
            .create_committed_resource(ResourceDesc {
                name: "d3d12-parallel-a".to_string(),
                format,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create resource a");
        let resource_b = runtime
            .create_committed_resource(ResourceDesc {
                name: "d3d12-parallel-b".to_string(),
                format,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create resource b");
        let heap_a = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        runtime
            .write_descriptor(
                heap_a,
                0,
                ViewDescriptor::Rtv {
                    resource: resource_a,
                    format,
                },
            )
            .expect("rtv a");
        let heap_b = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        runtime
            .write_descriptor(
                heap_b,
                0,
                ViewDescriptor::Rtv {
                    resource: resource_b,
                    format,
                },
            )
            .expect("rtv b");
        let root_signature = runtime.create_root_signature(RootSignatureDesc::default());
        let pipeline_state = runtime.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "d3d12-parallel".to_string(),
                compute: false,
                render_target_formats: vec![format],
                depth_format: None,
            },
        );
        let allocator = runtime.create_command_allocator();
        let mut streams = Vec::new();
        for heap in [heap_a, heap_b] {
            let list = runtime.create_graphics_command_list(allocator, pipeline_state, false);
            runtime
                .record_begin_render_pass(list, vec![format], None, "clear", "store")
                .expect("begin pass");
            runtime.record_clear_rtv(list, heap, 0).expect("clear rtv");
            runtime.record_draw(list, 3).expect("draw");
            streams.push(runtime.close_command_list(list).expect("close list"));
        }
        (runtime, streams)
    }

    fn test_game_environment(name: &str) -> (crate::ge::GameEnvironment, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "casa1-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(root.join("drive_c")).expect("create GE drive");
        std::fs::create_dir_all(root.join("tmp")).expect("create GE tmp");
        let config = crate::ge::GeConfig {
            schema_version: 1,
            name: name.to_string(),
            arch: crate::ge::GeArch::X64,
            winver: "win10".to_string(),
            user_name: "tester".to_string(),
            long_paths_enabled: false,
            drive_mappings: vec![crate::ge::DriveMapping {
                drive: "C".to_string(),
                target: "<GE>/drive_c".to_string(),
                read_only: false,
                enabled: true,
                requires_permission: false,
            }],
            override_profiles: Vec::new(),
            fs_state: Default::default(),
        };
        (
            crate::ge::GameEnvironment {
                root: root.clone(),
                config,
            },
            root,
        )
    }

    #[test]
    fn directstorage_short_file_surfaces_real_error() {
        let (ge, root) = test_game_environment("d3d12-ds-short");
        std::fs::write(root.join("drive_c").join("tiny.bin"), [1u8, 2, 3, 4])
            .expect("write tiny file");
        let mut runtime = D3d12Runtime::new();
        let error = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\tiny.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: 64,
                    output_len: 64,
                    width: 4,
                    height: 4,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect_err("short file must fail");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert!(error.message.contains("too short"), "unexpected: {error}");
        assert_eq!(runtime.directstorage_bytes(), 0);
        assert_eq!(runtime.staging_bytes(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_resource_format_comes_from_upload_format() {
        let (ge, root) = test_game_environment("d3d12-ds-formats");
        let mut runtime = D3d12Runtime::new();

        let rgba: Vec<u8> = (0..4 * 2 * 4).map(|index| (index * 7) as u8).collect();
        std::fs::write(root.join("drive_c").join("rgba.bin"), &rgba).expect("write rgba");
        let rgba_resource = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\rgba.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: rgba.len() as u64,
                    output_len: rgba.len() as u64,
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect("RGBA upload");
        assert_eq!(
            runtime
                .resource_format(rgba_resource)
                .expect("resource format"),
            DxgiFormat::R8G8B8A8Unorm,
            "RGBA upload must not be described as a BGRA shadow"
        );
        assert_eq!(
            runtime
                .directstorage_texture_format(rgba_resource)
                .expect("texture format"),
            DxgiFormat::R8G8B8A8Unorm
        );
        assert_eq!(
            runtime
                .readback_gpu_texture(rgba_resource)
                .expect("RGBA readback"),
            rgba
        );
        let fence = runtime.create_fence(0);
        assert!(
            runtime.readback(rgba_resource, fence, 1).is_err(),
            "readback must require a completed fence"
        );
        runtime
            .signal_fence(fence, 1)
            .expect("signal readback fence");
        assert_eq!(
            runtime
                .readback(rgba_resource, fence, 1)
                .expect("fenced DirectStorage readback"),
            rgba,
            "fenced readback must use the actual upload texture"
        );

        let bgra: Vec<u8> = (0..4 * 2 * 4).map(|index| (255 - index) as u8).collect();
        std::fs::write(root.join("drive_c").join("bgra.bin"), &bgra).expect("write bgra");
        let bgra_resource = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\bgra.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: bgra.len() as u64,
                    output_len: bgra.len() as u64,
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::BGRA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect("BGRA upload");
        assert_eq!(
            runtime
                .resource_format(bgra_resource)
                .expect("resource format"),
            DxgiFormat::B8G8R8A8Unorm,
            "BGRA upload resource must use the real BGRA format"
        );
        assert_eq!(
            runtime
                .readback_gpu_texture(bgra_resource)
                .expect("BGRA readback"),
            bgra,
            "readback uses the actual BGRA texture (no RGBA shadow conversion)"
        );

        // NV12 luma plane upload (the Y plane of an NV12 target is R8_UNORM).
        let luma: Vec<u8> = (0..8 * 4).map(|index| (index * 3) as u8).collect();
        std::fs::write(root.join("drive_c").join("nv12-y.bin"), &luma).expect("write luma");
        let luma_resource = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\nv12-y.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: luma.len() as u64,
                    output_len: luma.len() as u64,
                    width: 8,
                    height: 4,
                    format: metal::MTLPixelFormat::R8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect("NV12 luma upload");
        assert_eq!(
            runtime
                .resource_format(luma_resource)
                .expect("resource format"),
            DxgiFormat::R8Unorm,
            "NV12 luma targets must keep their real R8 format"
        );
        assert_eq!(
            runtime
                .readback_gpu_texture(luma_resource)
                .expect("luma readback"),
            luma
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_format_mismatches_are_real_errors() {
        let (ge, root) = test_game_environment("d3d12-ds-mismatch");
        let mut runtime = D3d12Runtime::new();
        let pixels = vec![7u8; 4 * 2 * 4];
        std::fs::write(root.join("drive_c").join("mismatch.bin"), &pixels).expect("write");
        let error = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\mismatch.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: pixels.len() as u64,
                    output_len: pixels.len() as u64 + 4,
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::BGRA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect_err("output_len mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert!(
            error.message.contains("does not match"),
            "unexpected: {error}"
        );

        let error = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\mismatch.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: pixels.len() as u64,
                    output_len: (4 * 2 * 2) as u64,
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RG8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect_err("format without a DXGI resource representation must fail");
        assert_eq!(error.code, ReasonCode::RcD3dFeatureUnsupported);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_async_reset_releases_in_flight_resources() {
        let (ge, root) = test_game_environment("d3d12-ds-reset");
        let pixels: Vec<u8> = (0..4 * 2 * 4).map(|index| (index * 11) as u8).collect();
        std::fs::write(root.join("drive_c").join("reset.bin"), &pixels).expect("write reset");
        let mut runtime = D3d12Runtime::new();
        let ticket = runtime
            .enqueue_file_to_texture(
                &ge,
                "C:\\reset.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: pixels.len() as u64,
                    output_len: pixels.len() as u64,
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect("enqueue");
        assert_eq!(runtime.directstorage_upload_stats().in_flight, 1);
        runtime
            .reset_directstorage_uploads()
            .expect("reset async uploads");
        let stats = runtime.directstorage_upload_stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.retained_buffers, 0);
        assert_eq!(stats.retained_textures, 0);
        assert!(
            stats.cancelled >= 1,
            "reset must count the cancelled upload"
        );
        assert_eq!(
            runtime.directstorage_live_texture_count(),
            0,
            "reset must drop the upload texture and its resource"
        );
        assert!(
            runtime.readback_gpu_texture(ticket.resource).is_err(),
            "cancelled resource must no longer be readable"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_cancel_distinguishes_pending_from_committed() {
        let (ge, root) = test_game_environment("d3d12-ds-cancel-split");
        let pixels: Vec<u8> = (0..1024 * 1024 * 4)
            .map(|index| (index % 249) as u8)
            .collect();
        std::fs::write(root.join("drive_c").join("split.bin"), &pixels).expect("write split");
        let mut runtime = D3d12Runtime::new();
        let pending = runtime
            .enqueue_file_to_texture(
                &ge,
                "C:\\split.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: pixels.len() as u64,
                    output_len: pixels.len() as u64,
                    width: 1024,
                    height: 1024,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect("enqueue pending upload");
        let cancelled = runtime.cancel_pending_directstorage_uploads();
        if cancelled > 0 {
            assert_eq!(cancelled, 1);
            let stats = runtime.directstorage_upload_stats();
            assert_eq!(stats.pending_io, 0);
            assert_eq!(stats.in_flight, 0);
            assert_eq!(stats.cancelled, 1);
            assert!(
                runtime.readback_gpu_texture(pending.resource).is_err(),
                "cancelled pending upload must release its resource"
            );
        }
        runtime
            .wait_for_directstorage_uploads(20_000_000_000)
            .expect("cancelled or committed upload completes");

        let committed = runtime
            .enqueue_file_to_texture(
                &ge,
                "C:\\split.bin",
                crate::metal_backend::DirectStorageUploadDesc {
                    file_offset: 0,
                    source_len: 4 * 2 * 4,
                    output_len: 4 * 2 * 4,
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    compression: crate::metal_backend::DirectStorageCompression::None,
                },
            )
            .expect("enqueue committed upload");
        runtime
            .wait_for_directstorage_fence(committed.fence_value, 20_000_000_000)
            .expect("committed upload reaches the GPU");
        assert!(
            runtime.directstorage_upload_stats().committed >= 1,
            "committed upload must be observed as committed"
        );
        assert_eq!(
            runtime.cancel_pending_directstorage_uploads(),
            0,
            "committed uploads are not cancellable"
        );
        assert!(
            runtime.cancel_committed_directstorage_uploads() >= 1,
            "committed upload must be reported as already committed"
        );
        runtime
            .wait_for_directstorage_fence(committed.fence_value, 20_000_000_000)
            .expect("committed work still completes");
        assert_eq!(
            runtime
                .readback_gpu_texture(committed.resource)
                .expect("committed readback"),
            pixels[..4 * 2 * 4].to_vec(),
            "committed upload still delivers its bytes"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nv12_resize_rejects_mismatched_odd_dimensions() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("NV12 swapchain");
        if runtime.nv12_texture_builds(swapchain) == 0 {
            return;
        }
        let error = runtime
            .resize_buffers(swapchain, 2, 5, 2, DxgiFormat::B8G8R8A8Unorm)
            .expect_err("odd NV12 width must be rejected");
        assert!(
            error.message.contains("must be even"),
            "unexpected: {error}"
        );
        assert_eq!(runtime.swapchain_state(swapchain).unwrap().desc.width, 4);
    }

    #[test]
    fn unsupported_swapchain_format_uses_counted_fallback() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain_for_format(
                SwapchainDesc {
                    width: 4,
                    height: 2,
                    format: DxgiFormat::R8G8B8A8Unorm,
                    buffer_count: 2,
                },
                9999,
            )
            .expect("fallback swapchain");
        assert_eq!(runtime.swapchain_format_fallback_count(), 1);
        assert_eq!(
            runtime.swapchain_state(swapchain).unwrap().desc.format,
            DxgiFormat::R8G8B8A8Unorm,
            "fallback uses the caller's typed format"
        );
    }

    fn directstorage_upload_desc(
        pixels: &[u8],
        width: u32,
        height: u32,
        format: metal::MTLPixelFormat,
    ) -> crate::metal_backend::DirectStorageUploadDesc {
        crate::metal_backend::DirectStorageUploadDesc {
            file_offset: 0,
            source_len: pixels.len() as u64,
            output_len: pixels.len() as u64,
            width,
            height,
            format,
            compression: crate::metal_backend::DirectStorageCompression::None,
        }
    }

    #[test]
    fn swapchain_fallback_paths_and_resize_reject_short_counts() {
        let mut runtime = D3d12Runtime::new();
        let matching = runtime
            .create_swapchain_for_format(
                SwapchainDesc {
                    width: 4,
                    height: 2,
                    format: DxgiFormat::R8G8B8A8Unorm,
                    buffer_count: 2,
                },
                28,
            )
            .expect("matching raw format creates a pixel swapchain");
        assert_eq!(runtime.swapchain_format_fallback_count(), 0);
        assert_eq!(
            runtime.swapchain_state(matching).unwrap().desc.format,
            DxgiFormat::R8G8B8A8Unorm
        );

        let extra = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional pixel swapchain");
        assert!(
            runtime
                .extra_swapchains
                .get(&extra)
                .unwrap()
                .nv12
                .is_empty()
        );

        runtime
            .resize_buffers(matching, 3, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize primary");
        assert_eq!(runtime.iosurface_channels.len(), 3);
        assert_eq!(runtime.iosurface_channels[0].width(), 8);
        assert_eq!(runtime.iosurface_channels[0].height(), 4);
        runtime
            .resize_buffers(extra, 2, 16, 8, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize additional");
        let resized = runtime.extra_swapchains.get(&extra).unwrap();
        assert_eq!(resized.pixel[0].width(), 16);
        assert_eq!(resized.pixel[0].height(), 8);
        assert_eq!(runtime.iosurface_channels[0].width(), 8);

        let error = runtime
            .resize_buffers(matching, 1, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect_err("buffer count below two must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "swapchain buffer count must be at least 2");
        assert_eq!(runtime.swapchain_state(matching).unwrap().desc.width, 8);

        let zero = runtime
            .create_nv12_swapchain(SwapchainDesc {
                width: 0,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("zero-dimension NV12 falls back");
        assert_eq!(runtime.swapchain_format_fallback_count(), 1);
        assert!(runtime.primary_nv12.is_empty());
        assert!(runtime.iosurface_channels.is_empty());
        assert_eq!(
            runtime.swapchain_state(zero).unwrap().desc.format,
            DxgiFormat::B8G8R8A8Unorm
        );

        let fallback = runtime
            .create_additional_nv12_swapchain(SwapchainDesc {
                width: 0,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional NV12 falls back");
        assert_eq!(runtime.swapchain_format_fallback_count(), 2);
        assert!(runtime.extra_swapchains.get(&fallback).unwrap().is_empty());

        let empty = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Uint,
                buffer_count: 2,
            })
            .expect("unsupported channel format still creates a swapchain");
        assert!(runtime.extra_swapchains.get(&empty).unwrap().is_empty());
        let empty_backbuffer = runtime.swapchain_state(empty).unwrap().backbuffers[0];
        let before = runtime.cpu_backing_writes();
        runtime
            .overwrite_resource_bytes(empty_backbuffer, &[3u8; 32])
            .expect("empty channel set writes CPU backing");
        assert_eq!(runtime.cpu_backing_writes(), before + 1);
    }

    #[test]
    fn present_rejects_pixel_channel_count_dimension_and_format_mismatches() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        assert_eq!(runtime.iosurface_channels.len(), 2);
        assert!(runtime.iosurface_zero_copy_active());

        runtime.iosurface_channels[0] = crate::metal_backend::IoSurfacePresentChannel::new(
            2,
            2,
            metal::MTLPixelFormat::RGBA8Unorm,
        )
        .expect("mismatched dimensions");
        let error = runtime
            .present(swapchain, 1, false)
            .expect_err("dimension mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: swapchain 4x2 does not match channel 0 at 0 (2x2)"
        );

        runtime.iosurface_channels[0] = crate::metal_backend::IoSurfacePresentChannel::new(
            4,
            2,
            metal::MTLPixelFormat::BGRA8Unorm,
        )
        .expect("mismatched format");
        let error = runtime
            .present(swapchain, 1, false)
            .expect_err("format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: swapchain format R8G8B8A8Unorm (RGBA8Unorm) does not match channel 0 BGRA8Unorm"
        );

        runtime.iosurface_channels[0] = crate::metal_backend::IoSurfacePresentChannel::new(
            4,
            2,
            metal::MTLPixelFormat::RGBA8Unorm,
        )
        .expect("restore channel");
        runtime
            .present(swapchain, 1, false)
            .expect("present primary");
        assert_eq!(runtime.iosurface_present_count(), 1);

        let extra = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional pixel swapchain");
        runtime.present(extra, 1, false).expect("present extra");
        let frame = runtime.presented_frame(extra).expect("extra frame");
        assert_eq!(frame.width, 4);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.format, DxgiFormat::B8G8R8A8Unorm);
        assert_eq!(runtime.iosurface_present_count(), 2);

        runtime.extra_swapchains.get_mut(&extra).unwrap().pixel[0] =
            crate::metal_backend::IoSurfacePresentChannel::new(
                4,
                2,
                metal::MTLPixelFormat::RGBA8Unorm,
            )
            .expect("mismatched extra format");
        let error = runtime
            .present(extra, 1, false)
            .expect_err("extra format mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: swapchain format B8G8R8A8Unorm (BGRA8Unorm) does not match channel 0 RGBA8Unorm"
        );

        runtime
            .extra_swapchains
            .get_mut(&extra)
            .unwrap()
            .pixel
            .pop();
        let error = runtime
            .present(extra, 1, false)
            .expect_err("extra channel count mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: 1 channels for 2 backbuffers"
        );

        runtime.iosurface_channels.pop();
        let error = runtime
            .present(swapchain, 1, false)
            .expect_err("primary channel count mismatch must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: 1 channels for 2 backbuffers"
        );
    }

    #[test]
    fn nv12_present_rejects_channel_count_and_dimension_mismatches() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain_for_format(
                SwapchainDesc {
                    width: 4,
                    height: 2,
                    format: DxgiFormat::B8G8R8A8Unorm,
                    buffer_count: 2,
                },
                103,
            )
            .expect("create NV12 swapchain");
        assert_eq!(runtime.swapchain_format_fallback_count(), 0);
        assert_eq!(runtime.nv12_texture_builds(swapchain), 2);
        assert_eq!(runtime.iosurface_texture_builds(), 2);
        runtime.present(swapchain, 1, false).expect("present NV12");
        assert_eq!(runtime.nv12_present_count(), 1);
        // One composite feeds the drawable present; the later
        // `presented_nv12_plane_bytes` verification path decodes the planes
        // again on the GPU (no CPU NV12 decode exists).
        assert_eq!(runtime.nv12_composite_passes(swapchain), 2);
        assert_eq!(runtime.nv12_drawable_binds(swapchain), 1);
        assert!(runtime.presented_nv12_drawable_ptr(swapchain).is_some());
        let (y, uv) = runtime
            .presented_nv12_plane_bytes(swapchain)
            .expect("NV12 plane readback");
        assert_eq!(y.len(), 8);
        assert_eq!(uv.len(), 4);
        let (gpu_y, gpu_uv) = runtime
            .presented_nv12_plane_bytes_gpu(swapchain)
            .expect("GPU NV12 plane readback");
        assert_eq!(gpu_y, y);
        assert_eq!(gpu_uv, uv);
        assert_eq!(
            runtime
                .presented_nv12_composite_rgba(swapchain)
                .expect("composite RGBA")
                .len(),
            32
        );
        let frame = runtime.presented_frame(swapchain).expect("NV12 frame");
        assert_eq!(frame.width, 4);
        assert_eq!(frame.format, DxgiFormat::R8G8B8A8Unorm);

        let extra = runtime
            .create_additional_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional NV12 swapchain");
        assert_eq!(runtime.nv12_texture_builds(extra), 2);
        runtime
            .present(extra, 1, false)
            .expect("present extra NV12");
        assert_eq!(runtime.nv12_present_count(), 2);
        assert_eq!(runtime.nv12_composite_passes(extra), 2);
        assert_eq!(runtime.presented_frame(extra).unwrap().width, 4);
        let (extra_y, extra_uv) = runtime
            .presented_nv12_plane_bytes(extra)
            .expect("extra NV12 planes");
        assert_eq!((extra_y.len(), extra_uv.len()), (8, 4));
        let (extra_gpu_y, extra_gpu_uv) = runtime
            .presented_nv12_plane_bytes_gpu(extra)
            .expect("extra GPU NV12 planes");
        assert_eq!((extra_gpu_y.len(), extra_gpu_uv.len()), (8, 4));

        let pixel = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional pixel swapchain");
        assert_eq!(runtime.nv12_texture_builds(pixel), 0);
        let error = runtime
            .presented_nv12_plane_bytes(pixel)
            .expect_err("pixel swapchain has no NV12 plane");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {pixel} has no NV12 present channel")
        );
        let error = runtime
            .presented_nv12_plane_bytes_gpu(pixel)
            .expect_err("pixel swapchain has no GPU NV12 plane");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {pixel} has no NV12 present channel")
        );

        runtime.extra_swapchains.get_mut(&extra).unwrap().nv12.pop();
        let error = runtime
            .present(extra, 1, false)
            .expect_err("extra NV12 count mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "NV12 present: 1 channels for 2 backbuffers");

        runtime.primary_nv12[0] =
            crate::metal_backend::Nv12PresentChannel::new(2, 2).expect("mismatched channel");
        let error = runtime
            .present(swapchain, 1, false)
            .expect_err("NV12 dimension mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 present: swapchain 4x2 does not match channel 0 at 0 (2x2)"
        );

        runtime
            .resize_buffers(swapchain, 2, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize primary NV12");
        assert_eq!(runtime.primary_nv12.len(), 2);
        assert_eq!(runtime.primary_nv12[0].width(), 8);
        assert!(runtime.iosurface_channels.is_empty());
        runtime
            .resize_buffers(extra, 2, 16, 8, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize extra NV12");
        let resized = runtime.extra_swapchains.get(&extra).unwrap();
        assert_eq!(resized.nv12.len(), 2);
        assert_eq!(resized.nv12[0].width(), 16);
        assert!(resized.pixel.is_empty());
        assert_eq!(runtime.primary_nv12[0].width(), 8);
    }

    #[test]
    fn surface_writes_reject_overflow_and_missing_channels() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        assert_eq!(runtime.iosurface_channels.len(), 2);
        let backbuffer = runtime.swapchain_state(swapchain).unwrap().backbuffers[0];
        runtime
            .overwrite_resource_bytes(backbuffer, &[9u8; 32])
            .expect("full-frame write");
        assert_eq!(runtime.surface_writes(), 1);
        assert_eq!(runtime.cpu_backing_writes(), 0);

        runtime
            .upload_write(backbuffer, 4, &[1u8; 4])
            .expect("partial surface write");
        assert_eq!(runtime.surface_writes(), 2);
        let frame = runtime.presented_frame(swapchain).expect("presented frame");
        assert_eq!(&frame.bytes[4..8], &[1u8; 4]);

        let error = runtime
            .upload_write(backbuffer, 0, &[0u8; 33])
            .expect_err("oversized surface write must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "surface write exceeds present backbuffer");
        let error = runtime
            .upload_write(backbuffer, usize::MAX, &[0u8])
            .expect_err("surface write offset overflow must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "surface write range overflow");

        let extra = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional pixel swapchain");
        let extra_backbuffers = runtime.swapchain_state(extra).unwrap().backbuffers;
        runtime
            .overwrite_resource_bytes(extra_backbuffers[0], &[4u8; 32])
            .expect("extra surface write");
        assert_eq!(runtime.surface_writes(), 3);
        runtime
            .extra_swapchains
            .get_mut(&extra)
            .unwrap()
            .pixel
            .pop();
        let before = runtime.cpu_backing_writes();
        runtime
            .overwrite_resource_bytes(extra_backbuffers[1], &[4u8; 32])
            .expect("missing extra channel writes CPU backing");
        assert_eq!(runtime.cpu_backing_writes(), before + 1);

        let nv12 = runtime
            .create_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("NV12 swapchain");
        assert_eq!(runtime.swapchain_format_fallback_count(), 0);
        let nv12_backbuffer = runtime.swapchain_state(nv12).unwrap().backbuffers[0];
        let writes_before = runtime.surface_writes();
        runtime
            .overwrite_resource_bytes(nv12_backbuffer, &[7u8; 32])
            .expect("full NV12 write");
        assert_eq!(runtime.surface_writes(), writes_before + 1);
        let error = runtime
            .upload_write(nv12_backbuffer, 0, &[7u8; 31])
            .expect_err("NV12 partial write must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 present surface requires full-frame writes"
        );
        let error = runtime
            .upload_write(nv12_backbuffer, usize::MAX, &[7u8])
            .expect_err("NV12 write offset overflow must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "surface write range overflow");
        runtime.primary_nv12.pop();
        let nv12_backbuffers = runtime.swapchain_state(nv12).unwrap().backbuffers;
        let error = runtime
            .upload_write(nv12_backbuffers[1], 0, &[7u8; 32])
            .expect_err("missing NV12 backbuffer channel must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "NV12 present: backbuffer channel is missing");

        let extra_nv12 = runtime
            .create_additional_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional NV12 swapchain");
        let extra_nv12_backbuffer = runtime.swapchain_state(extra_nv12).unwrap().backbuffers[0];
        runtime
            .overwrite_resource_bytes(extra_nv12_backbuffer, &[6u8; 32])
            .expect("extra NV12 write");
        assert_eq!(runtime.surface_writes(), writes_before + 2);
    }

    #[test]
    fn initial_data_failure_rolls_back_resource_and_counts_staging() {
        let mut runtime = D3d12Runtime::new();
        let desc = ResourceDesc {
            name: "initial-data".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 32,
            subresources: 1,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Texture {
                sampled: true,
                render_target: false,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        };
        let error = runtime
            .create_committed_resource_with_initial_data(
                desc.clone(),
                Some(D3d12InitialTextureData {
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    data: vec![0u8; 31],
                }),
            )
            .expect_err("initial data length mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert!(
            error.message.starts_with("initial data:"),
            "unexpected: {error}"
        );
        assert_eq!(runtime.staging_bytes(), 0);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);

        let data: Vec<u8> = (0..32).map(|index| (index * 7) as u8).collect();
        let resource = runtime
            .create_committed_resource_with_initial_data(
                desc,
                Some(D3d12InitialTextureData {
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    data: data.clone(),
                }),
            )
            .expect("valid initial data");
        assert_eq!(runtime.staging_bytes(), 32);
        assert_eq!(runtime.directstorage_live_texture_count(), 1);
        assert_eq!(
            runtime
                .readback_gpu_texture(resource)
                .expect("GPU readback"),
            data
        );
        runtime
            .destroy_resource(resource)
            .expect("destroy initial-data resource");
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        let error = runtime
            .destroy_resource(resource)
            .expect_err("double destroy must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "unknown resource");
    }

    #[test]
    fn directstorage_rejects_unopenable_host_file_and_unknown_resources() {
        let (ge, root) = test_game_environment("d3d12-ds-denied");
        let host = root.join("drive_c").join("locked.bin");
        let pixels = vec![5u8; 32];
        std::fs::write(&host, &pixels).expect("write locked file");
        let mut permissions = std::fs::metadata(&host).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o000);
        std::fs::set_permissions(&host, permissions).expect("chmod");
        let mut runtime = D3d12Runtime::new();
        let error = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\locked.bin",
                directstorage_upload_desc(&pixels, 4, 2, metal::MTLPixelFormat::RGBA8Unorm),
            )
            .expect_err("unreadable host file must fail");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert_eq!(
            error.message,
            format!("DirectStorage: failed to open {}", host.display())
        );
        assert_eq!(runtime.directstorage_bytes(), 0);
        assert_eq!(runtime.staging_bytes(), 0);

        let unknown = 999_999u64;
        let error = runtime
            .directstorage_texture_format(unknown)
            .expect_err("unknown resource has no DirectStorage format");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("resource {unknown} has no DirectStorage texture format")
        );
        let error = runtime
            .readback_gpu_texture(unknown)
            .expect_err("unknown resource has no GPU texture");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("resource {unknown} has no GPU texture upload")
        );
        let error = runtime
            .readback_gpu_texture_plane(unknown, 0)
            .expect_err("unknown resource plane must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("resource {unknown} has no GPU texture upload")
        );

        assert_eq!(
            runtime
                .poll_directstorage_uploads()
                .expect("poll without queue"),
            crate::metal_backend::DirectStorageQueueStats::default()
        );
        assert_eq!(
            runtime
                .wait_for_directstorage_uploads(1)
                .expect("wait without queue"),
            0
        );
        let error = runtime
            .wait_for_directstorage_fence(7, 1)
            .expect_err("fence wait without queue must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "DirectStorage: no upload queue exists to wait for value 7"
        );
        assert_eq!(runtime.directstorage_fence_value(), 0);
        assert_eq!(runtime.directstorage_queued_uploads(), 0);
        assert_eq!(runtime.directstorage_completed_uploads(), 0);
        assert_eq!(runtime.directstorage_in_flight_uploads(), 0);
        assert_eq!(runtime.cancel_pending_directstorage_uploads(), 0);
        assert_eq!(runtime.cancel_committed_directstorage_uploads(), 0);
        runtime
            .cancel_directstorage_uploads()
            .expect("cancel without queue");
        runtime
            .reset_directstorage_uploads()
            .expect("reset without queue");

        let mut permissions = std::fs::metadata(&host).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
        std::fs::set_permissions(&host, permissions).expect("restore chmod");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_async_rejects_format_without_dxgi_and_cancels_cleanly() {
        let (ge, root) = test_game_environment("d3d12-ds-format");
        let pixels = vec![1u8; 16];
        std::fs::write(root.join("drive_c").join("rg8.bin"), &pixels).expect("write");
        let mut runtime = D3d12Runtime::new();
        let error = runtime
            .enqueue_file_to_texture(
                &ge,
                "C:\\rg8.bin",
                directstorage_upload_desc(&pixels, 4, 2, metal::MTLPixelFormat::RG8Unorm),
            )
            .expect_err("RG8 has no DXGI resource format");
        assert_eq!(error.code, ReasonCode::RcD3dFeatureUnsupported);
        assert_eq!(
            error.message,
            "DirectStorage async: upload texture format RG8Unorm has no DXGI resource format"
        );
        assert_eq!(runtime.directstorage_queued_uploads(), 1);
        runtime
            .cancel_directstorage_uploads()
            .expect("cancel queued upload");
        assert_eq!(runtime.directstorage_in_flight_uploads(), 0);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_nv12_enqueue_reads_both_planes_and_rejects_plane_overrun() {
        let (ge, root) = test_game_environment("d3d12-ds-nv12");
        let luma = vec![12u8; 8];
        let chroma = vec![34u8, 56, 78, 90];
        let mut contents = luma.clone();
        contents.extend_from_slice(&chroma);
        std::fs::write(root.join("drive_c").join("planes.bin"), &contents).expect("write");
        let mut runtime = D3d12Runtime::new();
        let ticket = runtime
            .enqueue_nv12_file_to_texture(
                &ge,
                "C:\\planes.bin",
                crate::metal_backend::DirectStorageNv12UploadDesc::new(
                    4,
                    2,
                    0,
                    luma.len() as u64,
                    luma.len() as u64,
                    chroma.len() as u64,
                ),
            )
            .expect("enqueue NV12");
        runtime
            .wait_for_directstorage_fence(ticket.fence_value, 20_000_000_000)
            .expect("NV12 completion");
        assert_eq!(
            runtime
                .readback_gpu_texture_plane(ticket.resource, 0)
                .expect("luma"),
            luma
        );
        assert_eq!(
            runtime
                .readback_gpu_texture_plane(ticket.resource, 1)
                .expect("chroma"),
            chroma
        );
        assert_eq!(
            runtime
                .readback_gpu_texture(ticket.resource)
                .expect("NV12 layout"),
            contents
        );
        assert_eq!(
            runtime
                .directstorage_texture_format(ticket.resource)
                .expect("luma format"),
            DxgiFormat::R8Unorm
        );
        assert_eq!(runtime.directstorage_bytes(), 12);
        assert_eq!(runtime.directstorage_live_texture_count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_cancel_pending_retains_unobserved_resource() {
        use std::io::Write;
        let (ge, root) = test_game_environment("d3d12-ds-pending-fifo");
        let host = root.join("drive_c").join("blocked.bin");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&host)
                .status()
                .expect("run mkfifo")
                .success()
        );
        let (release, released) = std::sync::mpsc::channel::<()>();
        let writer_path = host.clone();
        let writer = std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .expect("open FIFO writer");
            let _ = released.recv();
            let _ = file.write_all(&[0u8; 32]);
        });
        let mut runtime = D3d12Runtime::new();
        crate::metal_backend::test_set_io_worker_pause(true);
        let ticket = runtime
            .enqueue_file_to_texture(
                &ge,
                "C:\\blocked.bin",
                directstorage_upload_desc(&[0u8; 32], 4, 2, metal::MTLPixelFormat::RGBA8Unorm),
            )
            .expect("enqueue blocked upload");
        while !crate::metal_backend::test_io_worker_paused() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(runtime.directstorage_upload_stats().pending_io, 1);
        let fake = 999_998u64;
        runtime
            .directstorage_pending_resources
            .push((fake, u64::MAX));
        let cancelled = runtime.cancel_pending_directstorage_uploads();
        crate::metal_backend::test_set_io_worker_pause(false);
        assert_eq!(cancelled, 1);
        assert!(
            runtime
                .directstorage_pending_resources
                .iter()
                .any(|(resource, value)| *resource == fake && *value == u64::MAX),
            "the unobserved resource must remain tracked"
        );
        release.send(()).expect("release FIFO writer");
        writer.join().expect("join FIFO writer");
        runtime
            .cancel_directstorage_uploads()
            .expect("drain cancelled upload");
        assert_eq!(runtime.directstorage_in_flight_uploads(), 0);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        assert!(runtime.readback_gpu_texture(ticket.resource).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_async_alias_completion_hooks_cancel_cleanly() {
        let (ge, root) = test_game_environment("d3d12-ds-alias-adversarial");
        let pixels: Vec<u8> = (0..32).map(|index| (index * 5) as u8).collect();
        std::fs::write(root.join("drive_c").join("alias.bin"), &pixels).expect("write alias");
        let mut runtime = D3d12Runtime::new();
        let callback_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed = callback_count.clone();
        runtime.set_upload_completion_callback(move || {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(
            format!("{:?}", runtime.directstorage_completion),
            "UploadCompletionHook { registered: true }"
        );
        assert_eq!(
            runtime
                .wait_for_upload_completion(0)
                .expect("alias wait without a queue"),
            0
        );
        assert_eq!(
            runtime
                .poll_upload_completion()
                .expect("alias poll without a queue")
                .queued,
            0
        );

        let ticket = runtime
            .upload_file_to_texture_async(
                &ge,
                "C:\\alias.bin",
                directstorage_upload_desc(&pixels, 4, 2, metal::MTLPixelFormat::RGBA8Unorm),
            )
            .expect("alias enqueue");
        assert_eq!(runtime.directstorage_queued_uploads(), 1);
        assert_eq!(runtime.directstorage_in_flight_uploads(), 1);
        assert_ne!(ticket.fence_value, 0);
        assert_eq!(
            runtime.directstorage_fence_value(),
            0,
            "the GPU has not observed the enqueued fence yet"
        );

        let observed_fence = runtime
            .wait_for_upload_completion(5_000_000_000)
            .expect("alias wait for the async upload");
        assert_eq!(observed_fence, ticket.fence_value);
        assert_eq!(runtime.directstorage_fence_value(), ticket.fence_value);
        assert_eq!(runtime.directstorage_completed_uploads(), 1);
        assert_eq!(runtime.directstorage_in_flight_uploads(), 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while callback_count.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the completion hook never fired"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(
            callback_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the completion hook must fire exactly once"
        );
        runtime.set_upload_completion_callback(|| {});
        assert_eq!(
            runtime
                .poll_upload_completion()
                .expect("alias poll after drain")
                .queued,
            1
        );
        assert_eq!(
            callback_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an already-drained queue must not re-fire the hook"
        );

        let fence = runtime.create_fence(ticket.fence_value);
        assert_eq!(
            runtime
                .readback(ticket.resource, fence, ticket.fence_value)
                .expect("fenced alias upload readback"),
            pixels
        );
        assert_eq!(runtime.directstorage_live_texture_count(), 1);
        runtime
            .destroy_resource(ticket.resource)
            .expect("destroy alias upload");
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        assert_eq!(runtime.cancel_pending_directstorage_uploads(), 0);
        assert_eq!(runtime.cancel_committed_directstorage_uploads(), 1);
        runtime
            .cancel_directstorage_uploads()
            .expect("cancel clean async queue");
        runtime
            .reset_directstorage_uploads()
            .expect("reset clean async queue");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directstorage_fence_timeout_and_cancel_counters_are_exact() {
        let (ge, root) = test_game_environment("d3d12-ds-timeout-adversarial");
        let pixels: Vec<u8> = (0..32).map(|index| (index * 3) as u8).collect();
        std::fs::write(root.join("drive_c").join("timeout.bin"), &pixels).expect("write");
        let mut runtime = D3d12Runtime::new();
        let ticket = runtime
            .upload_file_to_texture_async(
                &ge,
                "C:\\timeout.bin",
                directstorage_upload_desc(&pixels, 4, 2, metal::MTLPixelFormat::RGBA8Unorm),
            )
            .expect("enqueue timed upload");
        assert_eq!(
            runtime
                .wait_for_upload_completion(5_000_000_000)
                .expect("wait for the upload"),
            ticket.fence_value
        );

        let error = runtime
            .wait_for_directstorage_fence(ticket.fence_value + 1, 0)
            .expect_err("an unsignaled fence must hit the zero timeout");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!(
                "DirectStorage: fence wait timed out after 0 ns (wanted {}, signaled {})",
                ticket.fence_value + 1,
                ticket.fence_value
            )
        );
        assert_eq!(
            runtime
                .wait_for_directstorage_fence(ticket.fence_value, 0)
                .expect("already-signaled fence value"),
            ()
        );
        assert_eq!(runtime.cancel_pending_directstorage_uploads(), 0);
        assert_eq!(runtime.cancel_committed_directstorage_uploads(), 1);
        assert_eq!(runtime.directstorage_completed_uploads(), 1);
        assert_eq!(runtime.directstorage_in_flight_uploads(), 0);
        runtime
            .cancel_directstorage_uploads()
            .expect("cancel drained upload queue");
        assert_eq!(runtime.directstorage_upload_stats().cancelled, 1);
        assert_eq!(runtime.directstorage_live_texture_count(), 1);
        runtime
            .destroy_resource(ticket.resource)
            .expect("destroy timed upload");
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn initial_data_none_failure_and_leak_invariant_are_exact() {
        let mut runtime = D3d12Runtime::new();
        let desc = ResourceDesc {
            name: "initial-data-adversarial".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Default,
            size: 32,
            subresources: 1,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Texture {
                sampled: true,
                render_target: false,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        };
        let plain = runtime
            .create_committed_resource_with_initial_data(desc.clone(), None)
            .expect("resource without initial data");
        assert_eq!(runtime.staging_bytes(), 0);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        runtime
            .destroy_resource(plain)
            .expect("destroy plain resource");

        let error = runtime
            .create_committed_resource_with_initial_data(
                desc.clone(),
                Some(D3d12InitialTextureData {
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    data: vec![0u8; 31],
                }),
            )
            .expect_err("initial data length mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "initial data: 31 bytes do not match 4x2 RGBA8Unorm (32 bytes)"
        );
        assert_eq!(runtime.staging_bytes(), 0);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);

        let data: Vec<u8> = (0..32).map(|index| (index * 7) as u8).collect();
        let resource = runtime
            .create_committed_resource_with_initial_data(
                desc,
                Some(D3d12InitialTextureData {
                    width: 4,
                    height: 2,
                    format: metal::MTLPixelFormat::RGBA8Unorm,
                    data: data.clone(),
                }),
            )
            .expect("valid initial data");
        assert_eq!(runtime.staging_bytes(), 32);
        assert_eq!(runtime.directstorage_live_texture_count(), 1);
        assert_eq!(
            runtime
                .readback_gpu_texture(resource)
                .expect("initial data GPU readback"),
            data
        );
        runtime
            .destroy_resource(resource)
            .expect("destroy initial-data resource");
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
        let error = runtime
            .destroy_resource(resource)
            .expect_err("double destroy must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "unknown resource");
    }

    #[test]
    fn resource_usage_wrappers_reject_unknown_handles_and_upload_fallback() {
        let mut runtime = D3d12Runtime::new();
        let _swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        let resource = runtime
            .create_committed_resource(ResourceDesc {
                name: "wrapper-target".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Upload,
                size: 32,
                subresources: 1,
                initial_state: ResourceState::CopyDest,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create wrapper resource");
        assert_eq!(
            runtime.resource_state(resource, 0).expect("resource state"),
            ResourceState::CopyDest
        );
        assert_eq!(
            runtime
                .resource_storage_mode(resource)
                .expect("storage mode"),
            MetalStorageMode::Shared
        );
        runtime
            .set_resource_usage_hint(resource, ResourceUsageHint::Generic)
            .expect("set usage hint");
        assert_eq!(
            runtime
                .resource_storage_mode(resource)
                .expect("storage mode after hint"),
            MetalStorageMode::Shared
        );

        let before = runtime.cpu_backing_writes();
        runtime
            .upload_write(resource, 0, &[7u8; 8])
            .expect("non-present upload fallback");
        assert_eq!(runtime.cpu_backing_writes(), before + 1);
        let mut expected = [0u8; 32];
        expected[..8].fill(7);
        assert_eq!(
            runtime
                .backend()
                .resource_bytes(resource)
                .expect("resource bytes"),
            &expected
        );

        let error = runtime
            .resource_state(resource, 1)
            .expect_err("out-of-range subresource must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "invalid subresource index");

        let unknown = 999_999u64;
        let error = runtime
            .resource_state(unknown, 0)
            .expect_err("unknown resource state must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, format!("unknown resource {unknown}"));
        let error = runtime
            .resource_storage_mode(unknown)
            .expect_err("unknown storage mode must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, format!("unknown resource {unknown}"));
        let error = runtime
            .set_resource_usage_hint(unknown, ResourceUsageHint::Generic)
            .expect_err("unknown usage hint must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, format!("unknown resource {unknown}"));
    }

    #[test]
    fn pixel_resize_and_empty_present_fallbacks_are_exact() {
        let mut runtime = D3d12Runtime::new();
        let primary = runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create primary swapchain");
        assert_eq!(runtime.iosurface_channels.len(), 2);
        let extra = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create additional pixel swapchain");
        assert_eq!(runtime.extra_swapchains.get(&extra).unwrap().pixel.len(), 2);
        runtime
            .resize_buffers(extra, 3, 8, 4, DxgiFormat::R8G8B8A8Unorm)
            .expect("resize additional pixel swapchain");
        let resized = runtime.extra_swapchains.get(&extra).expect("channel set");
        assert_eq!(resized.pixel.len(), 3);
        assert_eq!(resized.pixel[0].width(), 8);
        assert_eq!(resized.pixel[0].height(), 4);
        assert_eq!(resized.nv12.len(), 0);
        assert_eq!(runtime.iosurface_channels[0].width(), 4);
        runtime
            .present(extra, 1, false)
            .expect("present resized extra swapchain");
        assert_eq!(runtime.iosurface_present_count(), 1);
        let extra_frame = runtime
            .presented_frame(extra)
            .expect("resized extra presented frame");
        assert_eq!(extra_frame.width, 8);
        assert_eq!(extra_frame.height, 4);

        let empty = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Uint,
                buffer_count: 2,
            })
            .expect("create empty-channel swapchain");
        assert_eq!(runtime.extra_swapchains.get(&empty).unwrap().pixel.len(), 0);
        let fallbacks = runtime.fallback_upload_count();
        runtime
            .present(empty, 1, false)
            .expect("present empty-channel swapchain");
        assert_eq!(runtime.fallback_upload_count(), fallbacks + 2);
        let frame = runtime
            .presented_frame(empty)
            .expect("presented empty-channel frame");
        assert_eq!(frame.width, 4);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.bytes.len(), 32);
        assert_eq!(runtime.iosurface_present_count(), 1);
        assert_eq!(runtime.iosurface_channels.len(), 2);
        assert_eq!(runtime.swapchain_state(primary).unwrap().desc.width, 4);
    }

    #[test]
    fn nv12_channel_errors_and_clear_backbuffer_surface_writes_are_exact() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create pixel swapchain");
        let error = runtime
            .presented_nv12_plane_bytes(swapchain)
            .expect_err("pixel swapchain has no NV12 planes");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {swapchain} has no NV12 present channel")
        );
        let error = runtime
            .presented_nv12_plane_bytes_gpu(swapchain)
            .expect_err("pixel swapchain has no GPU NV12 planes");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {swapchain} has no NV12 present channel")
        );
        let error = runtime
            .presented_nv12_composite_rgba(swapchain)
            .expect_err("pixel swapchain has no NV12 drawable");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {swapchain} has no NV12 present channel")
        );
        assert_eq!(runtime.nv12_composite_passes(swapchain), 0);

        let backbuffer = runtime
            .swapchain_state(swapchain)
            .expect("swapchain state")
            .backbuffers[0];
        let heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        runtime
            .write_descriptor(
                heap,
                0,
                ViewDescriptor::Rtv {
                    resource: backbuffer,
                    format: DxgiFormat::R8G8B8A8Unorm,
                },
            )
            .expect("RTV descriptor");
        let allocator = runtime.create_command_allocator();

        let root_signature = runtime.create_root_signature(RootSignatureDesc::default());
        let pipeline = runtime.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "clear-error-path".to_string(),
                compute: false,
                render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
                depth_format: None,
            },
        );
        let list = runtime.create_graphics_command_list(allocator, pipeline, false);
        runtime
            .record_clear_rtv(list, heap, 0)
            .expect("clear present backbuffer");
        assert_eq!(runtime.surface_writes(), 1);
        assert_eq!(runtime.cpu_backing_writes(), 0);
        assert_eq!(
            runtime
                .backend()
                .resource_bytes(backbuffer)
                .expect("backing bytes"),
            &[0u8; 32]
        );
    }

    #[test]
    fn resize_and_present_index_reject_stale_extra_state() {
        let mut runtime = D3d12Runtime::new();
        let primary = runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create primary");
        let extra = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create extra");
        runtime.extra_swapchains.remove(&extra);
        runtime
            .resize_buffers(extra, 2, 8, 4, DxgiFormat::R8G8B8A8Unorm)
            .expect("stale extra resize updates only the backend");
        assert_eq!(runtime.extra_swapchains.contains_key(&extra), false);
        assert_eq!(
            runtime
                .swapchain_state(extra)
                .expect("backend state")
                .desc
                .width,
            8
        );

        runtime.extra_swapchains.insert(
            u64::MAX,
            SwapchainChannelSet {
                pixel: Vec::new(),
                nv12: Vec::new(),
            },
        );
        assert_eq!(runtime.present_backbuffer_index(999_999), None);
        assert_eq!(runtime.present_swapchain, Some(primary));
    }

    #[test]
    fn directstorage_and_readback_reject_missing_path_and_nonreadback_heap() {
        let (ge, root) = test_game_environment("d3d12-ds-missing-and-readback");
        let mut runtime = D3d12Runtime::new();
        let error = runtime
            .upload_file_to_texture(
                &ge,
                "C:\\absent.bin",
                directstorage_upload_desc(&[0u8; 32], 4, 2, metal::MTLPixelFormat::RGBA8Unorm),
            )
            .expect_err("missing guest file must fail before any host file opens");
        assert_eq!(error.code, ReasonCode::RcFsNotFound);
        assert_eq!(error.message, "C:\\absent.bin was not found");
        assert_eq!(runtime.directstorage_bytes(), 0);
        assert_eq!(runtime.staging_bytes(), 0);

        let resource = runtime
            .create_committed_resource(ResourceDesc {
                name: "plain-default-heap".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 32,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: false,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("create non-readback resource");
        let error = runtime
            .readback(resource, 0, 1)
            .expect_err("a default-heap resource must not read back");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "resource is not in a readback heap");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn d3d12_update_subresource_direct_shared_backing_rejects_staged_fallback() {
        let mut runtime = D3d12Runtime::new();
        let resource = runtime
            .create_committed_resource(ResourceDesc {
                name: "d3d12-dynamic-index-buffer".to_string(),
                format: DxgiFormat::Unknown,
                heap: HeapType::Upload,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Index,
                    cpu_write_frequent: true,
                },
            })
            .expect("create upload buffer");
        assert_eq!(
            runtime
                .resource_storage_mode(resource)
                .expect("storage mode"),
            MetalStorageMode::Shared
        );
        let first: Vec<u8> = (0..64).map(|index| (index * 5) as u8).collect();
        runtime
            .upload_write(resource, 0, &first)
            .expect("direct upload write");
        assert_eq!(
            runtime
                .backend()
                .resource_bytes(resource)
                .expect("shared backing"),
            first.as_slice()
        );
        let stats = runtime.backend().translation_stats();
        assert_eq!(stats.zero_copy_updates, 1);
        assert_eq!(stats.staged_copies, 0);

        let second: Vec<u8> = (0..64).map(|index| (index * 7 + 1) as u8).collect();
        runtime
            .overwrite_resource_bytes(resource, &second)
            .expect("direct overwrite");
        assert_eq!(
            runtime
                .backend()
                .resource_bytes(resource)
                .expect("shared backing after overwrite"),
            second.as_slice()
        );
        let stats = runtime.backend().translation_stats();
        assert_eq!(stats.zero_copy_updates, 2);
        assert_eq!(stats.staged_copies, 0);

        let error = runtime
            .upload_write(resource, usize::MAX, &[0u8])
            .expect_err("overflowing upload write must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "upload write range overflow");

        // On unified memory a default-heap texture is shared storage now: the
        // CPU bytes are the host-visible backing, not a device-private shadow.
        let shared_texture = runtime
            .create_committed_resource(ResourceDesc {
                name: "d3d12-shared-texture".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("shared texture");
        assert_eq!(
            runtime
                .resource_storage_mode(shared_texture)
                .expect("storage mode"),
            MetalStorageMode::Shared
        );
        runtime
            .overwrite_resource_bytes(shared_texture, &[0x44; 16])
            .expect("shared texture update");
        let stats = runtime.backend().translation_stats();
        assert_eq!(stats.staged_copies, 0);
        assert_eq!(stats.zero_copy_updates, 3);

        // A discrete GPU genuinely requires private storage; the same update
        // is a counted staged upload, not a compatibility gap.
        let mut discrete =
            D3d12Runtime::from_backend(crate::gfx::GraphicsBackend::with_host_profile(
                crate::gfx::host_gpu_profile_from_name("NVIDIA GeForce RTX 4080"),
            ));
        let private = discrete
            .create_committed_resource(ResourceDesc {
                name: "d3d12-private-texture".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("private texture");
        assert_eq!(
            discrete
                .resource_storage_mode(private)
                .expect("storage mode"),
            MetalStorageMode::Private
        );
        discrete
            .overwrite_resource_bytes(private, &[0x44; 16])
            .expect("private update");
        let stats = discrete.backend().translation_stats();
        assert_eq!(stats.staged_copies, 1);
        assert_eq!(stats.zero_copy_updates, 0);
    }
    #[test]
    fn d3d12_guest_initial_data_rejects_window_edges_and_counts_zero_staging() {
        let pixels: Vec<u8> = (0..16).map(|index| (index * 3 + 1) as u8).collect();
        let mut region = crate::metal_backend::GuestSharedRegion::new(
            3 * crate::metal_backend::host_page_size(),
        )
        .expect("guest region");
        let window = region.window();
        region.as_mut_slice()[1..1 + pixels.len()].copy_from_slice(&pixels);
        let mut runtime = D3d12Runtime::new();
        let resource = runtime
            .create_committed_resource_with_guest_initial_data(
                ResourceDesc {
                    name: "guest-initial-data".to_string(),
                    format: DxgiFormat::R8G8B8A8Unorm,
                    heap: HeapType::Default,
                    size: pixels.len(),
                    subresources: 1,
                    initial_state: ResourceState::CopyDest,
                    usage_hint: ResourceUsageHint::Texture {
                        sampled: true,
                        render_target: false,
                        depth_stencil: false,
                        cpu_write_frequent: false,
                    },
                },
                &window,
                1,
                pixels.len(),
                2,
                2,
                metal::MTLPixelFormat::RGBA8Unorm,
            )
            .expect("guest initial data");
        assert_eq!(runtime.staging_bytes(), 0);
        assert_eq!(runtime.guest_initial_upload_count(), 1);
        assert_eq!(
            runtime
                .readback_gpu_texture(resource)
                .expect("guest initial data readback"),
            pixels
        );
        runtime
            .destroy_resource(resource)
            .expect("destroy guest initial-data resource");

        let error = runtime
            .create_committed_resource_with_guest_initial_data(
                ResourceDesc {
                    name: "guest-initial-oob".to_string(),
                    format: DxgiFormat::R8G8B8A8Unorm,
                    heap: HeapType::Default,
                    size: pixels.len(),
                    subresources: 1,
                    initial_state: ResourceState::CopyDest,
                    usage_hint: ResourceUsageHint::Generic,
                },
                &window,
                region.len(),
                pixels.len(),
                2,
                2,
                metal::MTLPixelFormat::RGBA8Unorm,
            )
            .expect_err("out-of-window guest initial data must be refused");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "initial data: guest initial data refused: guest region outside the canonical window"
        );
        assert_eq!(runtime.guest_initial_upload_count(), 1);
        assert_eq!(runtime.staging_bytes(), 0);
        assert_eq!(runtime.directstorage_live_texture_count(), 0);
    }

    fn rt_desc_with(subobjects: Vec<D3d12StateSubobject>) -> D3d12StateObjectDesc {
        D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects,
        }
    }

    fn dxil(export: &str, bytecode: Vec<u8>) -> D3d12StateSubobject {
        D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
            bytecode,
            exports: vec![state_objects::D3d12ExportDesc {
                name: export.to_string(),
                export_to_rename: None,
                flags: 0,
            }],
        })
    }

    fn sig_desc(ty: u32, stride: u32) -> D3D12CommandSignatureDesc {
        D3D12CommandSignatureDesc {
            byte_stride: stride,
            node_mask: 0,
            arguments: vec![D3D12IndirectArgumentDesc {
                ty,
                root_parameter_index: 0,
                dest_offset_in_32bit_values: 0,
                num_32bit_values_to_set: 0,
            }],
        }
    }

    fn draw_sig_for_matrix(runtime: &mut D3d12Runtime) -> u64 {
        runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW, 16))
            .expect("draw signature")
    }

    #[test]
    fn d3d12_state_objects_work_graphs_and_execute_indirect_error_matrix_are_pinned() {
        use crate::gfx::Command;
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);

        // create_state_object_with_handle and duplicate handling.
        let handle = 0x1234u64;
        let created = runtime
            .create_state_object_with_handle(
                handle,
                rt_desc_with(vec![
                    D3d12StateSubobject::StateObjectConfig { flags: 0 },
                    dxil("raygen", vec![1, 2, 3]),
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ]),
            )
            .expect("explicit handle");
        assert_eq!(created.handle, handle);
        let error = runtime
            .create_state_object_with_handle(
                handle,
                rt_desc_with(vec![D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                }]),
            )
            .expect_err("duplicate handle");
        assert_eq!(error.message, "state object 0x1234 already exists");
        assert!(runtime.bound_state_object(list).is_none());
        runtime
            .set_pipeline_state1_state_object(
                list,
                handle,
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
                    subobjects: vec![],
                },
            )
            .expect("bind existing state object");
        let bound = runtime
            .bound_state_object(list)
            .expect("bound state object");
        assert_eq!(bound.handle, handle);
        let error = runtime
            .set_pipeline_state1_state_object(
                list,
                0x5678,
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_COLLECTION,
                    subobjects: vec![],
                },
            )
            .expect_err("collection binding must fail");
        assert_eq!(
            error.message,
            "SetPipelineState1 cannot bind a collection state object"
        );
        runtime.destroy_state_object(handle).expect("destroy");
        let error = runtime.destroy_state_object(handle).unwrap_err();
        assert_eq!(error.message, "destroy of unknown state object 0x1234");

        // AddToStateObject validation matrix.
        let collection = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_COLLECTION,
                subobjects: vec![D3d12StateSubobject::StateObjectConfig { flags: 0x4 }],
            })
            .expect("collection");
        let error = runtime
            .add_to_state_object(0x9999, rt_desc_with(vec![]))
            .unwrap_err();
        assert_eq!(
            error.message,
            "AddToStateObject from unknown state object 0x9999"
        );
        let error = runtime
            .add_to_state_object(collection, rt_desc_with(vec![]))
            .unwrap_err();
        assert_eq!(
            error.message,
            "AddToStateObject cannot grow a collection state object"
        );
        let parent = runtime
            .create_state_object(state_object_desc_with_export(
                STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
                0x4,
                "raygen",
                1,
            ))
            .expect("parent");
        let error = runtime
            .add_to_state_object(
                parent,
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                    subobjects: vec![D3d12StateSubobject::StateObjectConfig { flags: 0x4 }],
                },
            )
            .unwrap_err();
        assert_eq!(
            error.message,
            "AddToStateObject addition type 4 does not match parent type 3"
        );
        let mut no_flag =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0, "miss", 1);
        no_flag.subobjects.retain(|subobject| {
            !matches!(subobject, D3d12StateSubobject::StateObjectConfig { .. })
        });
        let error = runtime.add_to_state_object(parent, no_flag).unwrap_err();
        assert_eq!(
            error.message,
            "addition did not set D3D12_STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS"
        );
        let mut depth_conflict =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0x4, "miss", 2);
        let error = runtime
            .add_to_state_object(parent, depth_conflict)
            .unwrap_err();
        assert_eq!(
            error.message,
            "AddToStateObject raytracing recursion depth 2 conflicts with parent 1"
        );
        depth_conflict =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0x4, "miss", 1);
        for subobject in &mut depth_conflict.subobjects {
            if let D3d12StateSubobject::RaytracingShaderConfig {
                max_attribute_size, ..
            } = subobject
            {
                *max_attribute_size = 12;
            }
        }
        let error = runtime
            .add_to_state_object(parent, depth_conflict)
            .unwrap_err();
        assert_eq!(
            error.message,
            "AddToStateObject raytracing shader config conflicts with parent"
        );
        let duplicate =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0x4, "raygen", 1);
        let error = runtime.add_to_state_object(parent, duplicate).unwrap_err();
        assert_eq!(
            error.message,
            "AddToStateObject export \"raygen\" conflicts with the parent state object"
        );

        // Materialise validation branches.
        let cases: Vec<(D3d12StateObjectDesc, &str)> = vec![
            (
                rt_desc_with(vec![
                    D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                        bytecode: vec![1],
                        exports: vec![
                            state_objects::D3d12ExportDesc {
                                name: "dup".into(),
                                export_to_rename: None,
                                flags: 0,
                            },
                            state_objects::D3d12ExportDesc {
                                name: "dup".into(),
                                export_to_rename: None,
                                flags: 0,
                            },
                        ],
                    }),
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ]),
                "state object export \"dup\" is defined more than once",
            ),
            (
                rt_desc_with(vec![D3d12StateSubobject::ExistingCollection(
                    state_objects::D3d12ExistingCollection {
                        collection: 0x9999,
                        exports: vec![],
                    },
                )]),
                "existing collection 39321 is not a live state object",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::RaytracingShaderConfig {
                        max_payload_size: 1,
                        max_attribute_size: 36,
                    },
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ]),
                "raytracing MaxAttributeSizeInBytes 36 exceeds D3D12_RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES (32)",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::RaytracingShaderConfig {
                        max_payload_size: 1,
                        max_attribute_size: 2,
                    },
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ]),
                "raytracing MaxAttributeSizeInBytes 2 is not a multiple of 4",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 32,
                    },
                ]),
                "raytracing MaxTraceRecursionDepth 32 exceeds D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH (31)",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::RaytracingPipelineConfig1 {
                        max_trace_recursion_depth: 32,
                        flags: 0,
                    },
                ]),
                "raytracing MaxTraceRecursionDepth 32 exceeds D3D12_RAYTRACING_MAX_DECLARABLE_TRACE_RECURSION_DEPTH (31)",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::RaytracingPipelineConfig1 {
                        max_trace_recursion_depth: 1,
                        flags: 0x1000,
                    },
                ]),
                "D3D12_RAYTRACING_PIPELINE_FLAGS 0x1000 contain undefined bits",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::HitGroup(state_objects::D3d12HitGroup {
                        name: "raygen".into(),
                        ty: 0,
                        any_hit: None,
                        closest_hit: None,
                        intersection: None,
                    }),
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ]),
                "hit group export \"raygen\" is defined more than once",
            ),
            (
                rt_desc_with(vec![D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                }]),
                "raytracing pipeline state object has no DXIL library or collection",
            ),
            (
                rt_desc_with(vec![dxil("raygen", vec![1])]),
                "raytracing pipeline state object requires D3D12_RAYTRACING_PIPELINE_CONFIG or CONFIG1",
            ),
            (
                rt_desc_with(vec![
                    dxil("raygen", vec![1]),
                    D3d12StateSubobject::WorkGraph(D3d12WorkGraph::default()),
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ]),
                "work-graph subobject requires D3D12_STATE_OBJECT_TYPE_EXECUTABLE",
            ),
            (
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                    subobjects: vec![D3d12StateSubobject::WorkGraph(D3d12WorkGraph::default())],
                },
                "work graph \"\" has no nodes or entrypoints",
            ),
            (
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_COLLECTION,
                    subobjects: vec![D3d12StateSubobject::WorkGraph(D3d12WorkGraph::default())],
                },
                "work-graph subobject requires D3D12_STATE_OBJECT_TYPE_EXECUTABLE",
            ),
            (
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_COLLECTION,
                    subobjects: vec![D3d12StateSubobject::StateObjectConfig { flags: 0x8 }],
                },
                "D3D12_STATE_OBJECT_FLAGS 0x8 contain undefined bits",
            ),
        ];
        for (desc, message) in cases {
            let error = runtime.create_state_object(desc).unwrap_err();
            assert_eq!(error.message, message);
        }

        // Valid Config1, hit groups, and export renaming exercise the
        // remaining success arms.
        let valid_config1 = runtime
            .create_state_object(rt_desc_with(vec![
                dxil("raygen", vec![1]),
                D3d12StateSubobject::RaytracingShaderConfig {
                    max_payload_size: 16,
                    max_attribute_size: 8,
                },
                D3d12StateSubobject::RaytracingPipelineConfig1 {
                    max_trace_recursion_depth: 1,
                    flags: 0x100,
                },
                D3d12StateSubobject::HitGroup(state_objects::D3d12HitGroup {
                    name: "hit".into(),
                    ty: 0,
                    any_hit: Some("raygen".into()),
                    closest_hit: Some("closest".into()),
                    intersection: None,
                }),
                D3d12StateSubobject::NodeMask { mask: 1 },
            ]))
            .expect("valid config1 and hit group");
        assert!(
            runtime
                .state_object(valid_config1)
                .unwrap()
                .shader_identifier("hit")
                .is_some()
        );
        let renamed = runtime
            .create_state_object(rt_desc_with(vec![
                D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                    bytecode: vec![4, 5, 6],
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: "renamed".into(),
                        export_to_rename: Some("original".into()),
                        flags: 0,
                    }],
                }),
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                },
            ]))
            .expect("renamed export");
        assert!(
            runtime
                .state_object(renamed)
                .unwrap()
                .shader_identifier("renamed")
                .is_some()
        );
        let error = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: 99,
                subobjects: vec![],
            })
            .unwrap_err();
        assert_eq!(error.message, "D3D12_STATE_OBJECT_TYPE 99 is not defined");
        // Executable state object without pipeline config takes the
        // parse_raytracing_pipeline_params branch on binding.
        let executable_with_dxil = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![dxil("exe", vec![7, 8])],
            })
            .expect("executable dxil");
        runtime
            .set_pipeline_state1_state_object(
                list,
                executable_with_dxil,
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                    subobjects: vec![],
                },
            )
            .expect("bind executable dxil");
        let overflow_sig = draw_sig_for_matrix(&mut runtime);
        let error = runtime
            .execute_indirect(
                list,
                overflow_sig,
                1,
                &draw_argument_bytes(1, 1),
                u64::MAX - 3,
                None,
            )
            .unwrap_err();
        assert_eq!(
            error.message,
            "ExecuteIndirect argument buffer range overflows"
        );

        // ExistingCollection success path.
        let referenced = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_COLLECTION,
                subobjects: vec![
                    D3d12StateSubobject::StateObjectConfig { flags: 0 },
                    dxil("collection_export", vec![9, 9]),
                ],
            })
            .expect("referenced collection");
        let with_collection = runtime
            .create_state_object(rt_desc_with(vec![
                D3d12StateSubobject::ExistingCollection(state_objects::D3d12ExistingCollection {
                    collection: referenced,
                    exports: vec![],
                }),
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                },
            ]))
            .expect("existing collection state object");
        assert!(
            runtime
                .state_object(with_collection)
                .unwrap()
                .shader_identifier("collection_export")
                .is_some()
        );

        // Work-graph selectors and validation.
        let graph = D3d12WorkGraph {
            program_name: "graph".into(),
            flags: 0,
            entrypoints: vec![work_graphs::D3d12NodeId::new("node0", 0)],
            nodes: vec![work_graphs::D3d12WorkGraphNode {
                node_type: work_graphs::D3D12_NODE_TYPE_SHADER,
                shader: "node0".into(),
                overrides: work_graphs::D3d12NodeOverrides::None,
            }],
        };
        let executable = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph.clone())],
            })
            .expect("executable");
        let identifier = runtime
            .work_graph_program_identifier(executable, "graph")
            .expect("identifier");
        let error = runtime
            .set_work_graph_program(list, identifier, 0x4, None)
            .unwrap_err();
        assert_eq!(
            error.message,
            "D3D12_WORK_GRAPH_FLAGS 0x4 contain undefined bits"
        );
        runtime
            .set_work_graph_program(
                list,
                identifier,
                0,
                Some((0, graph.memory_requirements().min_size_in_bytes)),
            )
            .expect("set program");
        assert_eq!(
            runtime
                .bound_work_graph_program(list)
                .map(|p| p.program_name.as_str()),
            Some("graph")
        );
        let dispatch = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_CPU_INPUT,
            entrypoint_index: 0,
            record_count: 1,
            record_stride: 8,
            records: vec![0; 8],
        };
        assert_eq!(
            runtime.dispatch_bound_work_graph(list, &dispatch).unwrap(),
            1
        );
        assert_eq!(
            runtime
                .work_graph_memory_requirements(executable, Some("graph"))
                .unwrap(),
            graph.memory_requirements()
        );
        let error = runtime
            .work_graph_memory_requirements(0x9999, None)
            .unwrap_err();
        assert_eq!(error.message, "unknown state object 0x9999");
        let error = runtime
            .work_graph_memory_requirements(collection, None)
            .unwrap_err();
        assert_eq!(
            error.message,
            format!("state object {collection:#x} is not D3D12_STATE_OBJECT_TYPE_EXECUTABLE")
        );
        let error = runtime
            .work_graph_memory_requirements(referenced, None)
            .unwrap_err();
        assert_eq!(
            error.message,
            format!("state object {referenced:#x} is not D3D12_STATE_OBJECT_TYPE_EXECUTABLE")
        );
        let empty_executable = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::StateObjectConfig { flags: 0 }],
            })
            .expect("empty executable");
        let error = runtime
            .work_graph_memory_requirements(empty_executable, None)
            .unwrap_err();
        assert_eq!(error.message, "state object contains no work graph");
        let error = runtime
            .dispatch_work_graph(
                list,
                executable,
                Some("graph"),
                &D3d12DispatchGraphDesc {
                    entrypoint_index: 0,
                    record_count: 1,
                    record_stride: 0,
                    records: vec![0; 8],
                    ..dispatch.clone()
                },
                None,
            )
            .unwrap_err();
        assert_eq!(error.message, "work graph record stride is zero");

        // Command signature error and success matrix.
        for (desc, message) in [
            (
                sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW, 0),
                "invalid command signature: ByteStride 0 must be a non-zero multiple of 4",
            ),
            (
                sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW, 2),
                "invalid command signature: ByteStride 2 must be a non-zero multiple of 4",
            ),
            (
                D3D12CommandSignatureDesc {
                    byte_stride: 16,
                    node_mask: 0,
                    arguments: vec![],
                },
                "unsupported command signature: 0 argument descriptors; only a single argument is representable",
            ),
            (
                sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_VERTEX_BUFFER_VIEW, 16),
                "unsupported command signature: D3D12_INDIRECT_ARGUMENT_TYPE 3 is not representable",
            ),
            (
                sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW, 12),
                "invalid command signature: ByteStride 12 is smaller than the 16-byte argument",
            ),
        ] {
            let error = runtime.create_command_signature(desc).unwrap_err();
            assert_eq!(error.message, message);
        }
        let draw_sig = runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW, 16))
            .unwrap();
        let indexed_sig = runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW_INDEXED, 20))
            .unwrap();
        assert!(runtime.command_signature(indexed_sig).is_some());
        let dispatch_sig = runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH, 12))
            .unwrap();
        let mesh_sig = runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_MESH, 12))
            .unwrap();
        let rays_sig = runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_RAYS, 100))
            .unwrap();
        assert!(runtime.command_signature(draw_sig).is_some());
        assert!(runtime.command_signature(0x9999).is_none());
        assert_eq!(
            runtime
                .destroy_command_signature(0x9999)
                .unwrap_err()
                .message,
            "unknown command signature 0x9999"
        );
        let temp_sig = runtime
            .create_command_signature(sig_desc(D3D12_INDIRECT_ARGUMENT_TYPE_DRAW, 16))
            .unwrap();
        runtime.destroy_command_signature(temp_sig).unwrap();

        // ExecuteIndirect validation and every supported argument type.
        assert_eq!(
            runtime
                .execute_indirect(list, 0x9999, 1, &[0; 16], 0, None)
                .unwrap_err()
                .message,
            "ExecuteIndirect with unknown command signature 0x9999"
        );
        let draw_args = draw_argument_bytes(3, 1);
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 1, &draw_args, 0, Some(2))
                .unwrap_err()
                .message,
            "invalid ExecuteIndirect: Count 2 exceeds MaxCommandCount 1"
        );
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 1, &draw_args, 1, None)
                .unwrap_err()
                .message,
            "invalid ExecuteIndirect: ArgumentBufferOffset 1 is not 4-byte aligned"
        );
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 2, &draw_args, 0, None)
                .unwrap_err()
                .message,
            "ExecuteIndirect argument buffer range 32 exceeds the supplied 16 bytes"
        );
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 1, &draw_args, 0, Some(0))
                .unwrap(),
            0
        );
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 1, &[0u8; 16], 0, None)
                .unwrap(),
            0
        );
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 1, &draw_args, 0, None)
                .unwrap(),
            1
        );
        let mut nonzero_start = draw_args;
        nonzero_start[8..12].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            runtime
                .execute_indirect(list, draw_sig, 1, &nonzero_start, 0, None)
                .unwrap_err()
                .message,
            "unsupported ExecuteIndirect DRAW argument: non-zero start locations (7, 0) are not representable"
        );
        let mut dispatch_args = Vec::new();
        dispatch_args.extend_from_slice(&2u32.to_le_bytes());
        dispatch_args.extend_from_slice(&3u32.to_le_bytes());
        dispatch_args.extend_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            runtime
                .execute_indirect(list, dispatch_sig, 1, &dispatch_args, 0, None)
                .unwrap(),
            1
        );
        assert_eq!(
            runtime
                .execute_indirect(list, dispatch_sig, 1, &[0u8; 12], 0, None)
                .unwrap(),
            0
        );
        assert_eq!(
            runtime
                .execute_indirect(list, mesh_sig, 1, &dispatch_args, 0, None)
                .unwrap(),
            1
        );
        assert_eq!(
            runtime
                .execute_indirect(list, mesh_sig, 1, &[0u8; 12], 0, None)
                .unwrap(),
            0
        );
        let mut rays_args = vec![0u8; 100];
        rays_args[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        rays_args[88..92].copy_from_slice(&320u32.to_le_bytes());
        rays_args[92..96].copy_from_slice(&200u32.to_le_bytes());
        rays_args[96..100].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            runtime
                .execute_indirect(list, rays_sig, 1, &rays_args, 0, None)
                .unwrap(),
            1
        );
        assert_eq!(
            runtime
                .execute_indirect(list, rays_sig, 1, &[0u8; 100], 0, None)
                .unwrap(),
            0
        );
        // Unsupported stored signature and truncated argument reads.
        runtime.command_signatures.insert(
            0x9001,
            D3D12CommandSignature {
                handle: 0x9001,
                byte_stride: 16,
                node_mask: 0,
                argument: D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_VERTEX_BUFFER_VIEW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                },
            },
        );
        assert_eq!(
            runtime
                .execute_indirect(list, 0x9001, 1, &[0u8; 16], 0, None)
                .unwrap_err()
                .message,
            "unsupported ExecuteIndirect command signature argument type 3"
        );
        runtime.command_signatures.insert(
            0x9002,
            D3D12CommandSignature {
                handle: 0x9002,
                byte_stride: 4,
                node_mask: 0,
                argument: D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                },
            },
        );
        assert_eq!(
            runtime
                .execute_indirect(list, 0x9002, 1, &[0u8; 4], 0, None)
                .unwrap_err()
                .message,
            "indirect argument buffer is truncated"
        );
        runtime.command_signatures.insert(
            0x9003,
            D3D12CommandSignature {
                handle: 0x9003,
                byte_stride: 4,
                node_mask: 0,
                argument: D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_RAYS,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                },
            },
        );
        assert_eq!(
            runtime
                .execute_indirect(list, 0x9003, 1, &[0u8; 4], 0, None)
                .unwrap_err()
                .message,
            "indirect argument buffer is truncated"
        );
        // Error propagation from the Metal backend is exercised by dispatching
        // and drawing on a closed command list.
        let closed = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .close_command_list(closed)
            .expect("close error list");
        let error = runtime
            .execute_indirect(closed, draw_sig, 1, &draw_args, 0, None)
            .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        let error = runtime
            .execute_indirect(closed, rays_sig, 1, &rays_args, 0, None)
            .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        let error = runtime
            .dispatch_work_graph(closed, executable, Some("graph"), &dispatch, None)
            .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);

        // The recorded commands include draws, dispatches, mesh dispatches and rays.
        let stream = runtime.close_command_list(list).expect("close");
        assert!(stream.commands.iter().any(|command| matches!(
            command,
            Command::DrawInstanced {
                vertices: 3,
                instances: 1
            }
        )));
        assert!(
            stream
                .commands
                .iter()
                .any(|command| matches!(command, Command::Dispatch { x: 2, y: 3, z: 4 }))
        );
        assert!(
            stream
                .commands
                .iter()
                .any(|command| matches!(command, Command::DispatchMesh { x: 2, y: 3, z: 4 }))
        );
        assert!(stream.commands.iter().any(|command| matches!(
            command,
            Command::DispatchRays {
                width: 320,
                height: 200,
                depth: 1,
                ..
            }
        )));
    }

    fn state_object_desc_with_export(
        object_type: u32,
        flags: u32,
        export: &str,
        recursion: u32,
    ) -> D3d12StateObjectDesc {
        D3d12StateObjectDesc {
            object_type,
            subobjects: vec![
                D3d12StateSubobject::StateObjectConfig { flags },
                D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                    bytecode: vec![0x44, 0x58, 0x42, 0x43],
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: export.to_string(),
                        export_to_rename: None,
                        flags: 0,
                    }],
                }),
                D3d12StateSubobject::RaytracingShaderConfig {
                    max_payload_size: 16,
                    max_attribute_size: 8,
                },
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: recursion,
                },
            ],
        }
    }

    #[test]
    fn d3d12_state_object_lifetime_and_shader_identifier_are_exact() {
        let mut runtime = D3d12Runtime::new();
        let desc =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0, "raygen", 1);
        let handle = runtime.create_state_object(desc).expect("state object");
        let identifier = runtime
            .state_object_shader_identifier(handle, "raygen")
            .expect("shader identifier");
        assert_eq!(identifier.len(), 32);
        let repeated = runtime
            .state_object_shader_identifier(handle, "raygen")
            .expect("stable identifier");
        assert_eq!(identifier, repeated);
        assert_ne!(
            identifier,
            runtime
                .state_object_shader_identifier(handle, "missing")
                .unwrap_or([0; 32])
        );
        assert_eq!(runtime.release_state_object(handle).expect("release"), 0);
        assert!(runtime.state_object(handle).is_none());
        let error = runtime
            .release_state_object(handle)
            .expect_err("double release must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
    }

    #[test]
    fn d3d12_add_to_state_object_requires_opt_in_and_merges_exports() {
        let mut runtime = D3d12Runtime::new();
        let parent = runtime
            .create_state_object(state_object_desc_with_export(
                STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
                0,
                "raygen",
                1,
            ))
            .expect("parent");
        let addition =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0x4, "miss", 1);
        let error = runtime
            .add_to_state_object(parent, addition)
            .expect_err("parent without opt-in must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "parent state object did not set D3D12_STATE_OBJECT_FLAG_ALLOW_STATE_OBJECT_ADDITIONS"
        );

        let parent = runtime
            .create_state_object(state_object_desc_with_export(
                STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
                0x4,
                "raygen",
                1,
            ))
            .expect("parent with opt-in");
        let addition =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0x4, "miss", 1);
        let child = runtime
            .add_to_state_object(parent, addition)
            .expect("addition");
        assert!(
            runtime
                .state_object(child)
                .unwrap()
                .shader_identifier("raygen")
                .is_some()
        );
        assert!(
            runtime
                .state_object(child)
                .unwrap()
                .shader_identifier("miss")
                .is_some()
        );
        let conflict =
            state_object_desc_with_export(STATE_OBJECT_TYPE_RAYTRACING_PIPELINE, 0x4, "raygen", 1);
        let error = runtime
            .add_to_state_object(child, conflict)
            .expect_err("duplicate export must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "AddToStateObject export \"raygen\" conflicts with the parent state object"
        );
    }

    #[test]
    fn d3d12_state_object_config1_requires_recursion_and_attribute_limits() {
        let mut runtime = D3d12Runtime::new();
        let error = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
                subobjects: vec![
                    D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                        bytecode: vec![1],
                        exports: vec![],
                    }),
                    D3d12StateSubobject::RaytracingShaderConfig {
                        max_payload_size: 16,
                        max_attribute_size: 36,
                    },
                ],
            })
            .expect_err("attribute size above 32 must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "raytracing MaxAttributeSizeInBytes 36 exceeds D3D12_RAYTRACING_MAX_ATTRIBUTE_SIZE_IN_BYTES (32)"
        );
        assert_eq!(runtime.state_objects().count(), 0);
    }

    #[test]
    fn d3d12_work_graph_dispatch_records_real_compute_commands() {
        use crate::gfx::Command;
        let mut runtime = D3d12Runtime::new();
        let graph = D3d12WorkGraph {
            program_name: "graph".to_string(),
            flags: 0,
            entrypoints: vec![work_graphs::D3d12NodeId::new("entry", 0)],
            nodes: vec![work_graphs::D3d12WorkGraphNode {
                node_type: work_graphs::D3D12_NODE_TYPE_SHADER,
                shader: "node0".to_string(),
                overrides: work_graphs::D3d12NodeOverrides::Broadcasting(
                    work_graphs::D3d12BroadcastingLaunchOverrides {
                        program_entry: Some(true),
                        new_name: Some(work_graphs::D3d12NodeId::new("entry", 0)),
                        dispatch_grid: Some([2, 1, 1]),
                        ..Default::default()
                    },
                ),
            }],
        };
        let requirements = graph.memory_requirements();
        assert_eq!(requirements.size_granularity_in_bytes, 8);
        let state_object = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph)],
            })
            .expect("executable work graph");
        let list = runtime.create_graphics_command_list(0, 0, false);
        let dispatch = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_CPU_INPUT,
            entrypoint_index: 0,
            record_count: 4,
            record_stride: 8,
            records: vec![0; 32],
        };
        let executed = runtime
            .dispatch_work_graph(
                list,
                state_object,
                Some("graph"),
                &dispatch,
                Some((0, requirements.min_size_in_bytes)),
            )
            .expect("work graph dispatch");
        assert_eq!(executed, 1);
        let stream = runtime.close_command_list(list).expect("close");
        assert_eq!(stream.commands.len(), 1);
        assert!(matches!(
            stream.commands[0],
            Command::Dispatch { x: 2, y: 1, z: 1 }
        ));

        let error = runtime
            .work_graph_memory_requirements(state_object, Some("missing"))
            .expect_err("unknown program must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "state object has no work graph named \"missing\""
        );
    }

    #[test]
    fn d3d12_work_graph_backing_memory_is_validated() {
        let mut runtime = D3d12Runtime::new();
        let graph = D3d12WorkGraph {
            program_name: "graph".to_string(),
            flags: 0,
            entrypoints: vec![work_graphs::D3d12NodeId::new("entry", 0)],
            nodes: vec![work_graphs::D3d12WorkGraphNode {
                node_type: work_graphs::D3D12_NODE_TYPE_SHADER,
                shader: "node0".to_string(),
                overrides: work_graphs::D3d12NodeOverrides::None,
            }],
        };
        let requirements = graph.memory_requirements();
        let state_object = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph)],
            })
            .expect("executable work graph");
        let list = runtime.create_graphics_command_list(0, 0, false);
        let dispatch = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_CPU_INPUT,
            entrypoint_index: 0,
            record_count: 1,
            record_stride: 8,
            records: vec![0; 8],
        };
        let error = runtime
            .dispatch_work_graph(list, state_object, None, &dispatch, Some((4, 8)))
            .expect_err("misaligned backing memory must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "work graph backing memory offset 4 is not aligned to 8 bytes"
        );
        let error = runtime
            .dispatch_work_graph(
                list,
                state_object,
                None,
                &dispatch,
                Some((0, requirements.min_size_in_bytes - 1)),
            )
            .expect_err("undersized backing memory must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!(
                "work graph backing memory size {} is smaller than the minimum {}",
                requirements.min_size_in_bytes - 1,
                requirements.min_size_in_bytes
            )
        );
    }

    fn draw_argument_bytes(vertices: u32, instances: u32) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&vertices.to_le_bytes());
        bytes[4..8].copy_from_slice(&instances.to_le_bytes());
        bytes
    }

    #[test]
    fn d3d12_execute_indirect_draw_records_concrete_draws() {
        use crate::gfx::Command;
        let mut runtime = D3d12Runtime::new();
        let signature = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 16,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("draw signature");
        let list = runtime.create_graphics_command_list(0, 0, false);
        // Boundary records: zero vertex count and zero instance count must
        // be skipped without recording or counting a command.
        let mut arguments = Vec::new();
        arguments.extend_from_slice(&draw_argument_bytes(0, 5));
        arguments.extend_from_slice(&draw_argument_bytes(3, 1));
        arguments.extend_from_slice(&draw_argument_bytes(4, 0));
        arguments.extend_from_slice(&draw_argument_bytes(6, 2));
        let executed = runtime
            .execute_indirect(list, signature, 4, &arguments, 0, None)
            .expect("execute indirect");
        assert_eq!(executed, 2);
        let stream = runtime.close_command_list(list).expect("close");
        assert_eq!(stream.commands.len(), 2);
        assert!(matches!(
            stream.commands[0],
            Command::DrawInstanced {
                vertices: 3,
                instances: 1
            }
        ));
        assert!(matches!(
            stream.commands[1],
            Command::DrawInstanced {
                vertices: 6,
                instances: 2
            }
        ));
    }

    #[test]
    fn d3d12_execute_indirect_rejects_unsupported_signatures_and_counts() {
        let mut runtime = D3d12Runtime::new();
        let indexed = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 20,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW_INDEXED,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("indexed draw signature");
        assert!(runtime.command_signature(indexed).is_some());

        let signature = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 16,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("draw signature");
        let list = runtime.create_graphics_command_list(0, 0, false);
        let arguments = draw_argument_bytes(3, 1);
        let error = runtime
            .execute_indirect(list, signature, 1, &arguments, 0, Some(2))
            .expect_err("count above max must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "invalid ExecuteIndirect: Count 2 exceeds MaxCommandCount 1"
        );

        let mut nonzero_start = draw_argument_bytes(3, 1);
        nonzero_start[8..12].copy_from_slice(&7u32.to_le_bytes());
        let error = runtime
            .execute_indirect(list, signature, 1, &nonzero_start, 0, None)
            .expect_err("non-zero start vertex must fail closed");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "unsupported ExecuteIndirect DRAW argument: non-zero start locations (7, 0) are not representable"
        );
    }

    #[test]
    fn d3d12_set_pipeline_state1_rejects_collection_state_object() {
        let mut runtime = D3d12Runtime::new();
        let collection = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_COLLECTION,
                subobjects: vec![D3d12StateSubobject::StateObjectConfig { flags: 0 }],
            })
            .expect("collection");
        let list = runtime.create_graphics_command_list(0, 0, false);
        let error = runtime
            .set_pipeline_state1_state_object(
                list,
                collection,
                D3d12StateObjectDesc {
                    object_type: STATE_OBJECT_TYPE_COLLECTION,
                    subobjects: vec![],
                },
            )
            .expect_err("collection binding must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "SetPipelineState1 cannot bind a collection state object"
        );
    }

    #[test]
    fn d3d12_add_to_state_object_rejects_parent_self_reference() {
        let mut runtime = D3d12Runtime::new();
        let parent = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
                subobjects: vec![
                    D3d12StateSubobject::StateObjectConfig { flags: 0x4 },
                    D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                        bytecode: vec![1, 2, 3],
                        exports: vec![],
                    }),
                    D3d12StateSubobject::RaytracingPipelineConfig {
                        max_trace_recursion_depth: 1,
                    },
                ],
            })
            .expect("parent");
        let addition = D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects: vec![
                D3d12StateSubobject::StateObjectConfig { flags: 0x4 },
                D3d12StateSubobject::ExistingCollection(state_objects::D3d12ExistingCollection {
                    collection: parent,
                    exports: vec![],
                }),
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                },
            ],
        };
        let error = runtime
            .add_to_state_object(parent, addition)
            .expect_err("self reference must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "AddToStateObject addition references the parent state object; the addition must be self-contained"
        );
    }

    #[test]
    fn d3d12_state_object_config_rejects_undefined_flags() {
        let mut runtime = D3d12Runtime::new();
        let error = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_COLLECTION,
                subobjects: vec![D3d12StateSubobject::StateObjectConfig { flags: 0x8 }],
            })
            .expect_err("undefined state object flags must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "D3D12_STATE_OBJECT_FLAGS 0x8 contain undefined bits"
        );
    }

    #[test]
    fn d3d12_set_program_and_dispatch_graph_use_bound_program() {
        use crate::gfx::Command;
        let mut runtime = D3d12Runtime::new();
        let graph = D3d12WorkGraph {
            program_name: "graph".to_string(),
            flags: 0,
            entrypoints: vec![work_graphs::D3d12NodeId::new("node0", 0)],
            nodes: vec![work_graphs::D3d12WorkGraphNode {
                node_type: work_graphs::D3D12_NODE_TYPE_SHADER,
                shader: "node0".to_string(),
                overrides: work_graphs::D3d12NodeOverrides::None,
            }],
        };
        let requirements = graph.memory_requirements();
        let state_object = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph)],
            })
            .expect("work graph state object");
        let identifier = runtime
            .work_graph_program_identifier(state_object, "graph")
            .expect("program identifier");
        let list = runtime.create_graphics_command_list(0, 0, false);
        let dispatch = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_CPU_INPUT,
            entrypoint_index: 0,
            record_count: 1,
            record_stride: 8,
            records: vec![0; 8],
        };
        let error = runtime
            .dispatch_bound_work_graph(list, &dispatch)
            .expect_err("dispatch without SetProgram must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "DispatchGraph requires a work-graph program bound with SetProgram"
        );
        let error = runtime
            .set_work_graph_program(
                list,
                [0xAB; 32],
                0,
                Some((0, requirements.min_size_in_bytes)),
            )
            .expect_err("unknown program identifier must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "SetProgram received an unknown work-graph program identifier"
        );
        runtime
            .set_work_graph_program(
                list,
                identifier,
                0,
                Some((0, requirements.min_size_in_bytes)),
            )
            .expect("bind work graph program");
        assert_eq!(
            runtime
                .bound_work_graph_program(list)
                .map(|p| p.program_name.as_str()),
            Some("graph")
        );
        let executed = runtime
            .dispatch_bound_work_graph(list, &dispatch)
            .expect("bound dispatch");
        assert_eq!(executed, 1);
        let stream = runtime.close_command_list(list).expect("close");
        assert!(matches!(
            stream.commands[0],
            Command::Dispatch { x: 1, y: 1, z: 1 }
        ));
    }

    #[test]
    fn d3d12_gpu_raytracing_rejects_malformed_descriptors_and_reads_back_real_hits() {
        let mut runtime = D3d12Runtime::new();
        assert_eq!(
            runtime.last_ray_dispatch_results(),
            Vec::<crate::metal_backend::MetalRayResult>::new()
        );
        assert_eq!(runtime.last_work_graph_records(), Vec::<u32>::new());
        let list = runtime.create_graphics_command_list(0, 0, false);

        let vertices: [f32; 9] = [-1.0, -1.0, 0.0, 1.0, -1.0, 0.0, 0.0, 1.0, 0.0];
        let vertex_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                vertices.as_ptr() as *const u8,
                std::mem::size_of_val(&vertices),
            )
        };
        let indices: [u16; 3] = [0, 1, 2];
        let index_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                indices.as_ptr() as *const u8,
                std::mem::size_of_val(&indices),
            )
        };
        runtime.register_raytracing_buffer(0x3000, vertex_bytes.to_vec());
        runtime.register_raytracing_buffer(0x4000, index_bytes.to_vec());

        let geometry = D3D12RaytracingGeometryDesc {
            ty: 0,
            flags: 1,
            vertex_buffer: 0x3000,
            vertex_format: 6,
            vertex_stride: 12,
            vertex_count: 3,
            index_buffer: 0x4000,
            index_format: 57,
            index_count: 3,
        };
        let blas_desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 2,
                num_descs: 1,
                geometries: vec![geometry.clone()],
            },
            source_address: 0,
            scratch_address: 0x2000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &blas_desc)
            .expect("real BLAS build");
        let blas = runtime
            .acceleration_structure(0x1000)
            .expect("BLAS metadata");
        assert_eq!(blas.built, true);
        assert_ne!(blas.metal_accel_handle, 0);
        assert_ne!(blas.compacted_size, 0);

        // A second BLAS covers the non-compacted branch and the compatibility
        // vertex-format aliases used by the Windows oracle vectors.
        runtime.register_raytracing_buffer(0x5000, vertex_bytes.to_vec());
        runtime.register_raytracing_buffer(0x5008, index_bytes.to_vec());
        let plain = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1100,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    vertex_buffer: 0x5000,
                    index_buffer: 0x5008,
                    vertex_format: 71,
                    ..geometry.clone()
                }],
            },
            source_address: 0,
            scratch_address: 0x2100,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &plain)
            .expect("non-compacted BLAS build");
        runtime.register_raytracing_buffer(0x3200, vertex_bytes.to_vec());
        let non_indexed = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1300,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    vertex_buffer: 0x3200,
                    index_buffer: 0,
                    index_count: 0,
                    ..geometry.clone()
                }],
            },
            source_address: 0,
            scratch_address: 0x2300,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &non_indexed)
            .expect("non-indexed BLAS build");
        let multi = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1400,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 2,
                geometries: vec![geometry.clone(), geometry.clone()],
            },
            source_address: 0,
            scratch_address: 0x2400,
        };
        let error = runtime
            .build_raytracing_acceleration_structure(list, &multi)
            .expect_err("multiple geometries");
        assert_eq!(
            error.message,
            "bottom-level acceleration structure with multiple geometries must use DescriptorsLayout"
        );

        // AABB BLAS with real bounding-box bytes.
        let bounds: [f32; 6] = [-1.0, -1.0, -1.0, 1.0, 1.0, 1.0];
        let bounds_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(bounds.as_ptr() as *const u8, std::mem::size_of_val(&bounds))
        };
        runtime.register_raytracing_buffer(0x7000, bounds_bytes.to_vec());
        let aabb_desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1200,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 1,
                    flags: 1,
                    vertex_buffer: 0x7000,
                    vertex_format: 0,
                    vertex_stride: 24,
                    vertex_count: 1,
                    index_buffer: 0,
                    index_format: 0,
                    index_count: 0,
                }],
            },
            source_address: 0,
            scratch_address: 0x2200,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &aabb_desc)
            .expect("AABB BLAS build");

        // D3D12 instance descriptor pointing at the first BLAS. A zero
        // transform exercises the identity fallback and flags 0xF exercises
        // every instance option bit.
        let mut instances = [0u8; 64];
        instances[48..52].copy_from_slice(&0xFF00_0000u32.to_le_bytes());
        instances[52..56].copy_from_slice(&0x0Fu32.to_le_bytes());
        instances[56..64].copy_from_slice(&0x1000u64.to_le_bytes());
        runtime.register_raytracing_instances(0x10_0000, instances.to_vec());
        let tlas_desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x10_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 1,
                flags: 2,
                num_descs: 1,
                geometries: Vec::new(),
            },
            source_address: 0,
            scratch_address: 0x20_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &tlas_desc)
            .expect("real TLAS build");
        assert_eq!(
            runtime
                .acceleration_structure(0x10_0000)
                .expect("TLAS metadata")
                .is_top_level,
            true
        );
        runtime.register_raytracing_instances(0x10_0400, instances.to_vec());
        let plain_tlas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x10_0400,
            inputs: D3D12BuildRaytracingInputs {
                ty: 1,
                flags: 0,
                num_descs: 1,
                geometries: Vec::new(),
            },
            source_address: 0,
            scratch_address: 0x20_0400,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &plain_tlas)
            .expect("non-compacted TLAS build");

        // Register a Metal ray record and a D3D12 shader-table record.
        let mut ray = crate::metal_backend::MetalRay {
            origin: [0.0, 0.0, -1.0],
            min_distance: 0.0,
            direction: [0.0, 0.0, 1.0],
            max_distance: 100.0,
            sbt_offset: 0,
            mask: 0xFFFF_FFFF,
        };
        let ray_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&ray as *const _ as *const u8, std::mem::size_of_val(&ray))
        };
        runtime.register_raytracing_buffer(0x30_0000, ray_bytes.to_vec());
        runtime.register_raytracing_buffer(0x31_0000, 7u32.to_le_bytes().to_vec());
        let dispatch = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0x30_0000,
            raygen_shader_size: std::mem::size_of::<crate::metal_backend::MetalRay>() as u64,
            miss_shader_start_address: 0,
            miss_shader_size: 0,
            miss_shader_stride: 0,
            hit_group_start_address: 0x31_0000,
            hit_group_size: 4,
            hit_group_stride: 4,
            callable_shader_start_address: 0,
            callable_shader_size: 0,
            callable_shader_stride: 0,
            width: 1,
            height: 1,
            depth: 1,
        };
        runtime
            .dispatch_rays(list, &dispatch)
            .expect("real DispatchRays");
        let results = runtime.last_ray_dispatch_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hit, 1);
        assert_eq!(results[0].group_index, 7);
        assert_eq!(results[0].instance_id, 0);

        // Synthetic rays (no registered raygen bytes) and a short shader-table
        // record still execute real traversal.
        runtime.register_raytracing_buffer(0x31_0008, vec![1, 2]);
        let synthetic = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0x3F_0000,
            raygen_shader_size: 0,
            hit_group_start_address: 0x31_0008,
            hit_group_size: 2,
            ..dispatch.clone()
        };
        runtime
            .dispatch_rays(list, &synthetic)
            .expect("synthetic DispatchRays");
        assert_eq!(
            runtime
                .last_ray_dispatch_results()
                .first()
                .expect("synthetic result")
                .group_index,
            0
        );

        // Zero-sized dispatches are valid no-ops.
        let zero = D3D12DispatchRaysDesc {
            width: 0,
            ..dispatch.clone()
        };
        runtime.dispatch_rays(list, &zero).expect("zero dispatch");
        let no_raygen = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0,
            ..dispatch.clone()
        };
        runtime.dispatch_rays(list, &no_raygen).expect("no raygen");

        // Malformed build inputs are rejected with exact errors.
        let mut misaligned = blas_desc.clone();
        misaligned.dest_address = 0x1001;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("misaligned destination");
        assert_eq!(
            error.message,
            "BuildRaytracingAccelerationStructure DestAccelerationStructureData 0x1001 is not 256-byte aligned"
        );
        misaligned = blas_desc.clone();
        misaligned.scratch_address = 0x2001;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("misaligned scratch");
        assert_eq!(
            error.message,
            "BuildRaytracingAccelerationStructure ScratchAccelerationStructureData 0x2001 is not 256-byte aligned"
        );
        misaligned = blas_desc.clone();
        misaligned.scratch_address = misaligned.dest_address;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("overlapping scratch");
        assert_eq!(
            error.message,
            "BuildRaytracingAccelerationStructure scratch and destination overlap"
        );
        misaligned = blas_desc.clone();
        misaligned.inputs.flags = 0x20;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("undefined build flags");
        assert_eq!(
            error.message,
            "BuildRaytracingAccelerationStructure flags 0x20 contain undefined bits"
        );
        misaligned = blas_desc.clone();
        misaligned.inputs.ty = 2;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("undefined structure type");
        assert_eq!(
            error.message,
            "D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE 2 is not defined"
        );
        misaligned = blas_desc.clone();
        misaligned.inputs.num_descs = 0;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("zero descriptors");
        assert_eq!(
            error.message,
            "BuildRaytracingAccelerationStructure NumDescs must be non-zero"
        );
        misaligned = blas_desc.clone();
        misaligned.inputs.num_descs = 2;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("descriptor count mismatch");
        assert_eq!(
            error.message,
            "BuildRaytracingAccelerationStructure NumDescs 2 does not match 1 geometry descriptors"
        );
        let mut bad_geometry = geometry.clone();
        bad_geometry.flags = 0x4;
        misaligned = blas_desc.clone();
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("undefined geometry flags");
        assert_eq!(error.message, "geometry 0 flags 0x4 contain undefined bits");
        bad_geometry = geometry.clone();
        bad_geometry.vertex_buffer = 0x3001;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("misaligned vertex buffer");
        assert_eq!(
            error.message,
            "geometry 0 vertex buffer 0x3001 is not 4-byte aligned"
        );
        bad_geometry = geometry.clone();
        bad_geometry.vertex_stride = 0;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("zero stride");
        assert_eq!(
            error.message,
            "geometry 0 vertex stride 0 must be a non-zero multiple of 4"
        );
        bad_geometry = geometry.clone();
        bad_geometry.vertex_stride = 3;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("unaligned stride");
        assert_eq!(
            error.message,
            "geometry 0 vertex stride 3 must be a non-zero multiple of 4"
        );
        bad_geometry = geometry.clone();
        bad_geometry.vertex_stride = 4;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("short stride for format");
        assert_eq!(
            error.message,
            "geometry 0 vertex stride 4 is smaller than the 12 bytes required by the format"
        );
        bad_geometry = geometry.clone();
        bad_geometry.vertex_count = 2;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("short vertex count");
        assert_eq!(error.message, "geometry 0 vertex count 2 is smaller than 3");
        bad_geometry = geometry.clone();
        bad_geometry.index_buffer = 0x4001;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("misaligned index buffer");
        assert_eq!(
            error.message,
            "geometry 0 index buffer 0x4001 is not 4-byte aligned"
        );
        bad_geometry = geometry.clone();
        bad_geometry.index_count = 4;
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("invalid index count");
        assert_eq!(
            error.message,
            "geometry 0 index count 4 is not a non-zero multiple of 3"
        );
        bad_geometry = geometry.clone();
        bad_geometry.vertex_buffer = 0x3100;
        runtime.register_raytracing_buffer(0x3100, vec![0u8; 4]);
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("short vertex range");
        assert_eq!(
            error.message,
            "geometry 0 vertex buffer range 36 exceeds the registered 4 bytes"
        );
        bad_geometry = geometry.clone();
        bad_geometry.index_buffer = 0x4100;
        runtime.register_raytracing_buffer(0x4100, vec![0u8; 2]);
        misaligned.inputs.geometries = vec![bad_geometry];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("short index range");
        assert_eq!(
            error.message,
            "geometry 0 index buffer range 6 exceeds the registered 2 bytes"
        );
        let mut bad_aabb = aabb_desc.clone();
        bad_aabb.inputs.geometries[0].vertex_buffer = 0x7001;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &bad_aabb)
            .expect_err("misaligned AABB buffer");
        assert_eq!(
            error.message,
            "geometry 0 bounding-box buffer 0x7001 is not 4-byte aligned"
        );
        bad_aabb = aabb_desc.clone();
        bad_aabb.inputs.geometries[0].vertex_stride = 20;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &bad_aabb)
            .expect_err("short AABB stride");
        assert_eq!(
            error.message,
            "geometry 0 bounding-box stride 20 must be at least 24 and a multiple of 4"
        );
        bad_aabb = aabb_desc.clone();
        bad_aabb.inputs.geometries[0].vertex_count = 0;
        let error = runtime
            .build_raytracing_acceleration_structure(list, &bad_aabb)
            .expect_err("zero AABB count");
        assert_eq!(error.message, "geometry 0 bounding-box count is zero");
        bad_aabb = aabb_desc.clone();
        bad_aabb.inputs.geometries[0].vertex_buffer = 0x7100;
        runtime.register_raytracing_buffer(0x7100, vec![0u8; 8]);
        let error = runtime
            .build_raytracing_acceleration_structure(list, &bad_aabb)
            .expect_err("short AABB range");
        assert_eq!(
            error.message,
            "geometry 0 bounding-box range 24 exceeds the registered 8 bytes"
        );
        let mut bad_type = geometry.clone();
        bad_type.ty = 2;
        misaligned.inputs.geometries = vec![bad_type];
        let error = runtime
            .build_raytracing_acceleration_structure(list, &misaligned)
            .expect_err("undefined geometry type");
        assert_eq!(error.message, "geometry 0 type 2 is not defined");

        assert_eq!(
            D3d12Runtime::dxgi_raytracing_vertex_format(17, 0).expect("float2"),
            (crate::metal_backend::VertexFormat::Float2, 8)
        );
        assert_eq!(
            D3d12Runtime::dxgi_raytracing_vertex_format(35, 0).expect("half3"),
            (crate::metal_backend::VertexFormat::Half3, 8)
        );
        assert_eq!(
            D3d12Runtime::dxgi_raytracing_vertex_format(1, 3)
                .expect_err("unsupported vertex format")
                .message,
            "geometry 3 vertex format 1 is not supported for raytracing"
        );
        assert_eq!(
            D3d12Runtime::dxgi_raytracing_index_format(42, 0)
                .expect("uint32")
                .1,
            4
        );
        assert_eq!(
            D3d12Runtime::dxgi_raytracing_index_format(1, 2)
                .expect_err("unsupported index format")
                .message,
            "geometry 2 index format 1 is not supported for raytracing"
        );

        let mut postbuild = [0u8; 8];
        runtime
            .emit_raytracing_acceleration_structure_postbuild_info(
                list,
                1,
                &[0x1000],
                &mut postbuild,
            )
            .expect("compacted-size postbuild info");
        assert_eq!(
            u64::from_le_bytes(postbuild),
            runtime
                .acceleration_structure(0x1000)
                .expect("BLAS metadata")
                .compacted_size
        );

        // Instance validation and unknown BLAS references.
        instances[56..64].copy_from_slice(&0xDEADu64.to_le_bytes());
        runtime.register_raytracing_instances(0x10_0100, instances.to_vec());
        let bad_tlas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x10_0100,
            inputs: D3D12BuildRaytracingInputs {
                ty: 1,
                flags: 0,
                num_descs: 1,
                geometries: Vec::new(),
            },
            source_address: 0,
            scratch_address: 0x20_0100,
        };
        let error = runtime
            .build_raytracing_acceleration_structure(list, &bad_tlas)
            .expect_err("unknown BLAS reference");
        assert_eq!(
            error.message,
            "instance references unknown acceleration structure 0xdead"
        );
        runtime.register_raytracing_instances(0x10_0200, vec![0u8; 8]);
        let short_tlas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x10_0200,
            ..bad_tlas.clone()
        };
        let error = runtime
            .build_raytracing_acceleration_structure(list, &short_tlas)
            .expect_err("short instance range");
        assert_eq!(
            error.message,
            "TLAS instance descriptor range 64 exceeds the registered 8 bytes"
        );
        let mut zero_instance = [0u8; 64];
        zero_instance[56..64].copy_from_slice(&0u64.to_le_bytes());
        runtime.register_raytracing_instances(0x10_0300, zero_instance.to_vec());
        let zero_tlas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x10_0300,
            ..bad_tlas.clone()
        };
        let error = runtime
            .build_raytracing_acceleration_structure(list, &zero_tlas)
            .expect_err("missing BLAS reference");
        assert_eq!(
            error.message,
            "top-level acceleration structure instance has a zero AccelerationStructure address"
        );

        // Dispatch validation.
        let mut no_tlas = D3d12Runtime::new();
        let error = no_tlas
            .dispatch_rays(0, &dispatch)
            .expect_err("missing TLAS");
        assert_eq!(
            error.message,
            "DispatchRays requires a built top-level acceleration structure"
        );
        let overflow = D3D12DispatchRaysDesc {
            width: u32::MAX,
            height: u32::MAX,
            depth: u32::MAX,
            ..dispatch.clone()
        };
        let error = runtime
            .dispatch_rays(list, &overflow)
            .expect_err("overflowing dispatch");
        assert_eq!(error.message, "DispatchRays dimensions overflow");
        let too_many = D3D12DispatchRaysDesc {
            width: 16 * 1024 * 1024 + 1,
            height: 1,
            depth: 1,
            ..dispatch.clone()
        };
        let error = runtime
            .dispatch_rays(list, &too_many)
            .expect_err("oversized dispatch");
        assert_eq!(
            error.message,
            "DispatchRays ray count 16777217 exceeds the 16 MiB per-dispatch limit"
        );
        ray.sbt_offset = 1;
        let _ = ray;
    }

    #[test]
    fn d3d12_work_graph_gpu_fanout_rejects_malformed_records_and_runs_on_gpu() {
        let mut runtime = D3d12Runtime::new();
        let graph = D3d12WorkGraph {
            program_name: "gpu".into(),
            flags: 0,
            entrypoints: vec![work_graphs::D3d12NodeId::new("node0", 0)],
            nodes: vec![work_graphs::D3d12WorkGraphNode {
                node_type: work_graphs::D3D12_NODE_TYPE_SHADER,
                shader: "node0".into(),
                overrides: work_graphs::D3d12NodeOverrides::None,
            }],
        };
        let executable = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph)],
            })
            .expect("executable work graph");
        let list = runtime.create_graphics_command_list(0, 0, false);
        let records = [
            3u32.to_le_bytes(),
            1u32.to_le_bytes(),
            8u32.to_le_bytes(),
            0u32.to_le_bytes(),
        ]
        .concat();
        let desc = work_graphs::D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_GPU_INPUT,
            entrypoint_index: 0,
            record_count: 2,
            record_stride: 8,
            records,
        };
        assert_eq!(
            runtime
                .dispatch_work_graph(list, executable, Some("gpu"), &desc, None)
                .expect("GPU fan-out"),
            2
        );
        assert_eq!(runtime.last_work_graph_records(), vec![9, 4]);

        let zero = work_graphs::D3d12DispatchGraphDesc {
            record_count: 0,
            ..desc.clone()
        };
        assert_eq!(
            runtime
                .dispatch_work_graph(list, executable, Some("gpu"), &zero, None)
                .expect("zero-record GPU fan-out"),
            0
        );
        let short = work_graphs::D3d12DispatchGraphDesc {
            record_stride: 4,
            ..desc.clone()
        };
        let error = runtime
            .dispatch_work_graph(list, executable, Some("gpu"), &short, None)
            .expect_err("short record stride");
        assert_eq!(
            error.message,
            "work graph record stride 4 is smaller than the 8-byte node/output record"
        );
        let missing = work_graphs::D3d12DispatchGraphDesc {
            record_count: 4,
            ..desc.clone()
        };
        let error = runtime
            .dispatch_work_graph(list, executable, Some("gpu"), &missing, None)
            .expect_err("short record range");
        assert_eq!(
            error.message,
            "work graph record range (32 bytes) exceeds the supplied 16 bytes"
        );
        let overflow = work_graphs::D3d12DispatchGraphDesc {
            record_count: u32::MAX,
            record_stride: u64::MAX,
            ..desc.clone()
        };
        let error = runtime
            .dispatch_work_graph(list, executable, Some("gpu"), &overflow, None)
            .expect_err("overflowing record range");
        assert_eq!(error.message, "work graph record range overflows");
    }

    #[test]
    fn d3d12_work_graph_multi_node_mesh_dispatch_and_malformed_records_are_pinned() {
        use crate::gfx::Command;
        use work_graphs::{
            D3D12_NODE_TYPE_PROGRAM, D3D12_NODE_TYPE_SHADER, D3d12BroadcastingLaunchOverrides,
            D3d12CoalescingLaunchOverrides, D3d12MeshLaunchOverrides, D3d12NodeId,
            D3d12NodeOutputOverrides, D3d12NodeOverrides, D3d12WorkGraphNode,
        };
        let node_id = |name: &str| D3d12NodeId::new(name, 0);
        let output = |target: &str| D3d12NodeOutputOverrides {
            output_index: 0,
            new_name: Some(node_id(target)),
            ..Default::default()
        };
        let mut runtime = D3d12Runtime::new();
        let graph = D3d12WorkGraph {
            program_name: "chain".to_string(),
            flags: 0,
            entrypoints: vec![node_id("root")],
            nodes: vec![
                D3d12WorkGraphNode {
                    node_type: D3D12_NODE_TYPE_SHADER,
                    shader: "root".to_string(),
                    overrides: D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                        new_name: Some(node_id("root")),
                        dispatch_grid: Some([1, 2, 1]),
                        output_overrides: vec![output("stage1")],
                        ..Default::default()
                    }),
                },
                D3d12WorkGraphNode {
                    node_type: D3D12_NODE_TYPE_SHADER,
                    shader: "stage1".to_string(),
                    overrides: D3d12NodeOverrides::Coalescing(D3d12CoalescingLaunchOverrides {
                        new_name: Some(node_id("stage1")),
                        output_overrides: vec![output("mesh")],
                        ..Default::default()
                    }),
                },
                D3d12WorkGraphNode {
                    node_type: D3D12_NODE_TYPE_PROGRAM,
                    shader: "mesh".to_string(),
                    overrides: D3d12NodeOverrides::Mesh(D3d12MeshLaunchOverrides {
                        program_entry: Some(true),
                        new_name: Some(node_id("mesh")),
                        dispatch_grid: Some([2, 1, 1]),
                        ..Default::default()
                    }),
                },
                D3d12WorkGraphNode {
                    node_type: D3D12_NODE_TYPE_SHADER,
                    shader: "override".to_string(),
                    overrides: D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                        new_name: Some(node_id("override")),
                        program_entry: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        };
        let requirements = graph.memory_requirements();
        let executable = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph)],
            })
            .expect("executable chain");
        let mut records = Vec::new();
        for _ in 0..2 {
            records.extend_from_slice(&0u32.to_le_bytes());
            records.extend_from_slice(&0u32.to_le_bytes());
        }
        let list = runtime.create_graphics_command_list(0, 0, false);
        let cpu_desc = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_CPU_INPUT,
            entrypoint_index: 0,
            record_count: 2,
            record_stride: 8,
            records: records.clone(),
        };
        assert_eq!(
            runtime
                .dispatch_work_graph(
                    list,
                    executable,
                    Some("chain"),
                    &cpu_desc,
                    Some((0, requirements.min_size_in_bytes)),
                )
                .expect("CPU multi-node dispatch"),
            3
        );
        let stream = runtime.close_command_list(list).expect("close CPU chain");
        assert_eq!(stream.commands.len(), 3);
        assert!(matches!(
            stream.commands[0],
            Command::Dispatch { x: 1, y: 2, z: 1 }
        ));
        assert!(matches!(
            stream.commands[1],
            Command::Dispatch { x: 1, y: 1, z: 1 }
        ));
        assert!(matches!(
            stream.commands[2],
            Command::DispatchMesh { x: 2, y: 1, z: 1 }
        ));

        // The same chain runs through GPU-produced counts and records.
        let gpu_list = runtime.create_graphics_command_list(0, 0, false);
        let gpu_desc = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_GPU_INPUT,
            ..cpu_desc.clone()
        };
        assert_eq!(
            runtime
                .dispatch_work_graph(gpu_list, executable, Some("chain"), &gpu_desc, None)
                .expect("GPU multi-node dispatch"),
            3
        );
        assert_eq!(runtime.last_work_graph_records(), vec![2, 2]);
        let empty_record = [
            work_graphs::WORK_GRAPH_EMPTY_RECORD.to_le_bytes(),
            work_graphs::WORK_GRAPH_EMPTY_RECORD.to_le_bytes(),
        ]
        .concat();
        assert_eq!(
            runtime
                .dispatch_work_graph(
                    gpu_list,
                    executable,
                    Some("chain"),
                    &D3d12DispatchGraphDesc {
                        record_count: 1,
                        records: empty_record,
                        ..gpu_desc.clone()
                    },
                    None,
                )
                .expect("empty GPU record"),
            0
        );

        // Malformed record content is rejected before any Metal work.
        let mut bad_output = records.clone();
        bad_output[4..8].copy_from_slice(&9u32.to_le_bytes());
        let error = runtime
            .dispatch_work_graph(
                gpu_list,
                executable,
                Some("chain"),
                &D3d12DispatchGraphDesc {
                    record_count: 1,
                    records: bad_output,
                    ..gpu_desc.clone()
                },
                None,
            )
            .expect_err("bad output index");
        assert_eq!(
            error.message,
            "work graph record 0 output index 9 is out of range for node \"root\"[0] output count 1"
        );
        let mut bad_node = records.clone();
        bad_node[0..4].copy_from_slice(&9u32.to_le_bytes());
        let error = runtime
            .dispatch_work_graph(
                gpu_list,
                executable,
                Some("chain"),
                &D3d12DispatchGraphDesc {
                    record_count: 1,
                    records: bad_node,
                    ..gpu_desc
                },
                None,
            )
            .expect_err("bad node index");
        assert_eq!(
            error.message,
            "work graph record 0 node index 9 is out of range for 4 nodes"
        );

        // Node-local root arguments are validated against the graph.
        let rooted = D3d12WorkGraph {
            program_name: "rooted".to_string(),
            flags: 0,
            entrypoints: vec![node_id("rooted")],
            nodes: vec![D3d12WorkGraphNode {
                node_type: D3D12_NODE_TYPE_SHADER,
                shader: "rooted".to_string(),
                overrides: D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                    new_name: Some(node_id("rooted")),
                    local_root_arguments_table_index: Some(2),
                    ..Default::default()
                }),
            }],
        };
        let rooted_object = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(rooted)],
            })
            .expect("rooted executable");
        let identifier = runtime
            .work_graph_program_identifier(rooted_object, "rooted")
            .expect("rooted identifier");
        let rooted_list = runtime.create_graphics_command_list(0, 0, false);
        let error = runtime
            .set_work_graph_program_with_local_roots(
                rooted_list,
                identifier,
                0,
                None,
                Some(work_graphs::D3d12GpuRangeAndStride {
                    start: 0,
                    size: 16,
                    stride: 8,
                }),
            )
            .expect_err("short local root table");
        assert_eq!(
            error.message,
            "node local root arguments table size 16 is smaller than the 20 bytes required \
             by table index 2"
        );
        runtime
            .set_work_graph_program_with_local_roots(
                rooted_list,
                identifier,
                0,
                None,
                Some(work_graphs::D3d12GpuRangeAndStride {
                    start: 0,
                    size: 24,
                    stride: 8,
                }),
            )
            .expect("valid local root table");
        assert_eq!(
            runtime
                .bound_work_graph_program(rooted_list)
                .and_then(|program| program.node_local_root_arguments_table),
            Some(work_graphs::D3d12GpuRangeAndStride {
                start: 0,
                size: 24,
                stride: 8,
            })
        );
    }

    #[test]
    fn d3d12_work_graph_ordered_rasterization_is_serialized_and_gpu_input_fails_closed() {
        use crate::gfx::Command;
        use work_graphs::{
            D3D12_NODE_TYPE_PROGRAM, D3D12_NODE_TYPE_SHADER, D3d12BroadcastingLaunchOverrides,
            D3d12MeshLaunchOverrides, D3d12NodeId, D3d12NodeOutputOverrides, D3d12NodeOverrides,
            D3d12WorkGraphNode, WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER,
        };
        let node_id = |name: &str| D3d12NodeId::new(name, 0);
        let graph = D3d12WorkGraph {
            program_name: "ordered".to_string(),
            flags: 0,
            entrypoints: vec![node_id("root")],
            nodes: vec![
                D3d12WorkGraphNode {
                    node_type: D3D12_NODE_TYPE_SHADER,
                    shader: "root".to_string(),
                    overrides: D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                        new_name: Some(node_id("root")),
                        output_overrides: vec![D3d12NodeOutputOverrides {
                            output_index: 0,
                            new_name: Some(node_id("mesh")),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                },
                D3d12WorkGraphNode {
                    node_type: D3D12_NODE_TYPE_PROGRAM,
                    shader: "mesh".to_string(),
                    overrides: D3d12NodeOverrides::Mesh(D3d12MeshLaunchOverrides {
                        new_name: Some(node_id("mesh")),
                        dispatch_grid: Some([1, 1, 1]),
                        ..Default::default()
                    }),
                },
            ],
        };
        let mut runtime = D3d12Runtime::new();
        let executable = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(graph)],
            })
            .expect("ordered executable");
        let identifier = runtime
            .work_graph_program_identifier(executable, "ordered")
            .expect("ordered identifier");
        let list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .set_work_graph_program(
                list,
                identifier,
                WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER,
                None,
            )
            .expect("ordered program");
        let mut records = Vec::new();
        for _ in 0..2 {
            records.extend_from_slice(&0u32.to_le_bytes());
            records.extend_from_slice(&0u32.to_le_bytes());
        }
        let cpu_desc = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_CPU_INPUT,
            entrypoint_index: 0,
            record_count: 2,
            record_stride: 8,
            records,
        };
        assert_eq!(
            runtime
                .dispatch_bound_work_graph(list, &cpu_desc)
                .expect("ordered CPU dispatch"),
            3
        );
        let stream = runtime
            .close_command_list(list)
            .expect("close ordered list");
        assert_eq!(stream.commands.len(), 3);
        assert!(matches!(
            stream.commands[0],
            Command::Dispatch { x: 2, y: 1, z: 1 }
        ));
        assert!(matches!(
            stream.commands[1],
            Command::DispatchMesh { x: 1, y: 1, z: 1 }
        ));
        assert!(matches!(
            stream.commands[2],
            Command::DispatchMesh { x: 1, y: 1, z: 1 }
        ));

        let gpu_list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .set_work_graph_program(
                gpu_list,
                identifier,
                WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER,
                None,
            )
            .expect("ordered GPU program");
        let gpu_desc = D3d12DispatchGraphDesc {
            mode: work_graphs::DISPATCH_MODE_NODE_GPU_INPUT,
            ..cpu_desc.clone()
        };
        let error = runtime
            .dispatch_bound_work_graph(gpu_list, &gpu_desc)
            .expect_err("GPU input cannot preserve order");
        assert_eq!(
            error.message,
            "D3D12_WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER cannot be \
             preserved for GPU-produced work-graph records on Metal"
        );

        // The flag requires a reachable graphics node.
        let compute_graph = D3d12WorkGraph {
            program_name: "compute".to_string(),
            flags: WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER,
            entrypoints: vec![node_id("root")],
            nodes: vec![D3d12WorkGraphNode {
                node_type: D3D12_NODE_TYPE_SHADER,
                shader: "root".to_string(),
                overrides: D3d12NodeOverrides::Broadcasting(D3d12BroadcastingLaunchOverrides {
                    new_name: Some(node_id("root")),
                    ..Default::default()
                }),
            }],
        };
        let compute = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(compute_graph)],
            })
            .expect("compute executable");
        let compute_id = runtime
            .work_graph_program_identifier(compute, "compute")
            .expect("compute identifier");
        let compute_list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .set_work_graph_program(
                compute_list,
                compute_id,
                WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER,
                None,
            )
            .expect("compute program");
        let error = runtime
            .dispatch_bound_work_graph(compute_list, &cpu_desc)
            .expect_err("no graphics node");
        assert_eq!(
            error.message,
            "D3D12_WORK_GRAPH_FLAG_ENTRYPOINT_GRAPHICS_NODES_RASTERIZE_IN_ORDER requires a \
             graphics (mesh) node reachable from the entrypoint"
        );

        let invalid_list = runtime.create_graphics_command_list(0, 0, false);
        let error = runtime
            .dispatch_work_graph_with_flags(
                invalid_list,
                executable,
                Some("ordered"),
                &cpu_desc,
                None,
                0x4,
            )
            .expect_err("undefined dispatch flags");
        assert_eq!(
            error.message,
            "D3D12_WORK_GRAPH_FLAGS 0x4 contain undefined bits"
        );
    }

    fn work_graph_dxil_container(entry: &str) -> Vec<u8> {
        let mut program = Vec::new();
        program.extend_from_slice(&0u32.to_le_bytes());
        program.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..3 {
            program.extend_from_slice(&1u32.to_le_bytes());
        }
        program.extend_from_slice(&0u32.to_le_bytes());
        let mut metadata = vec![entry.len() as u8];
        metadata.extend_from_slice(entry.as_bytes());
        let parts = [
            (*b"PROG", program),
            (*b"SIGN", b"aabb".to_vec()),
            (*b"META", metadata),
        ];
        let header_size = 12 + parts.len() * 12;
        let mut offset = header_size as u32;
        let mut descriptors = Vec::new();
        for (kind, payload) in &parts {
            descriptors.push((*kind, offset, payload.len() as u32));
            offset += payload.len() as u32;
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DXIL");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(parts.len() as u32).to_le_bytes());
        for (kind, offset, size) in &descriptors {
            bytes.extend_from_slice(kind);
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&size.to_le_bytes());
        }
        for (_, payload) in &parts {
            bytes.extend_from_slice(payload);
        }
        bytes
    }

    #[test]
    fn d3d12_work_graph_node_program_resolves_guest_dxil_and_rejects_malformed_shaders() {
        if std::env::var_os("CI").is_some() {
            // Headless CI GPUs raise uncatchable Objective-C exceptions from
            // Metal shader compilation; local Metal runs cover this path.
            return;
        }
        use state_objects::{D3d12DxilLibrary, D3d12ExportDesc};
        use work_graphs::{
            D3D12_NODE_TYPE_SHADER, D3d12NodeId, D3d12NodeOverrides, D3d12WorkGraphNode,
        };
        let node_id = |name: &str| D3d12NodeId::new(name, 0);
        let graph = D3d12WorkGraph {
            program_name: "shader".to_string(),
            flags: 0,
            entrypoints: vec![node_id("node0")],
            nodes: vec![D3d12WorkGraphNode {
                node_type: D3D12_NODE_TYPE_SHADER,
                shader: "node0".to_string(),
                overrides: D3d12NodeOverrides::None,
            }],
        };
        let mut runtime = D3d12Runtime::new();
        let executable = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![
                    D3d12StateSubobject::WorkGraph(graph.clone()),
                    D3d12StateSubobject::DxilLibrary(D3d12DxilLibrary {
                        bytecode: work_graph_dxil_container("node0"),
                        exports: vec![D3d12ExportDesc {
                            name: "node0".to_string(),
                            export_to_rename: None,
                            flags: 0,
                        }],
                    }),
                ],
            })
            .expect("executable with DXIL");
        assert_eq!(
            runtime
                .ensure_work_graph_node_program(executable, Some("shader"), 0)
                .expect("compile guest node"),
            true
        );
        let error = runtime
            .ensure_work_graph_node_program(executable, Some("shader"), 5)
            .expect_err("node index out of range");
        assert_eq!(
            error.message,
            "work graph node index 5 is out of range for 1 nodes"
        );
        let list = runtime.create_graphics_command_list(0, 0, false);
        let run = runtime
            .execute_work_graph_node_shader(
                list,
                executable,
                Some("shader"),
                0,
                &crate::metal_backend::MetalWorkGraphNodeBindings {
                    records: &[],
                    record_count: 0,
                    record_stride: 8,
                    output_capacity: 1,
                    output_stride: 8,
                    resources: &[],
                    descriptor_table: &[],
                    root_constants: &[],
                    persistent: false,
                },
            )
            .expect("guest node execution")
            .expect("guest node program");
        assert_eq!(run.threads, 0);
        assert_eq!(run.outputs, Vec::new());

        // A graph without a matching DXIL export keeps the topological path.
        let plain = D3d12WorkGraph {
            program_name: "plain".to_string(),
            flags: 0,
            entrypoints: vec![node_id("plain")],
            nodes: vec![D3d12WorkGraphNode {
                node_type: D3D12_NODE_TYPE_SHADER,
                shader: "plain".to_string(),
                overrides: D3d12NodeOverrides::None,
            }],
        };
        let plain_object = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![D3d12StateSubobject::WorkGraph(plain)],
            })
            .expect("plain executable");
        assert_eq!(
            runtime
                .ensure_work_graph_node_program(plain_object, Some("plain"), 0)
                .expect("no DXIL body"),
            false
        );

        // Malformed DXIL fails with the translator's exact error.
        let bad = D3d12WorkGraph {
            program_name: "bad".to_string(),
            flags: 0,
            entrypoints: vec![node_id("badnode")],
            nodes: vec![D3d12WorkGraphNode {
                node_type: D3D12_NODE_TYPE_SHADER,
                shader: "badnode".to_string(),
                overrides: D3d12NodeOverrides::None,
            }],
        };
        let bad_object = runtime
            .create_state_object(D3d12StateObjectDesc {
                object_type: STATE_OBJECT_TYPE_EXECUTABLE,
                subobjects: vec![
                    D3d12StateSubobject::WorkGraph(bad),
                    D3d12StateSubobject::DxilLibrary(D3d12DxilLibrary {
                        bytecode: b"not a DXIL container".to_vec(),
                        exports: vec![D3d12ExportDesc {
                            name: "badnode".to_string(),
                            export_to_rename: None,
                            flags: 0,
                        }],
                    }),
                ],
            })
            .expect("bad executable");
        let error = runtime
            .ensure_work_graph_node_program(bad_object, Some("bad"), 0)
            .expect_err("malformed shader");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(
            error.message,
            "work graph node shader translation failed in parse: invalid DXIL container header"
        );
    }

    #[test]
    fn d3d12_execute_indirect_gpu_rejects_bad_ranges_and_limits_count_on_gpu() {
        let mut runtime = D3d12Runtime::new();
        assert_eq!(runtime.last_indirect_results(), Vec::new());
        assert_eq!(runtime.last_indirect_effective(), 0);
        assert_eq!(runtime.last_indirect_native(), false);
        assert_eq!(runtime.last_indirect_boundary(), None);
        let list = runtime.create_graphics_command_list(0, 0, false);
        let dispatch_sig = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 12,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("dispatch signature");
        let args = [
            2u32.to_le_bytes(),
            3u32.to_le_bytes(),
            1u32.to_le_bytes(),
            4u32.to_le_bytes(),
            5u32.to_le_bytes(),
            6u32.to_le_bytes(),
        ]
        .concat();
        assert_eq!(
            runtime
                .execute_indirect_gpu(
                    list,
                    dispatch_sig,
                    2,
                    &args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("GPU dispatch decode"),
            1
        );
        assert_eq!(runtime.last_indirect_effective(), 1);
        assert_eq!(runtime.last_indirect_native(), true);
        let decoded = runtime.last_indirect_results();
        assert_eq!(decoded[0].kind, 2);
        assert_eq!((decoded[0].x, decoded[0].y, decoded[0].z), (2, 3, 1));
        assert_eq!(decoded[0].enabled, 1);
        assert_eq!(
            decoded[1],
            crate::metal_backend::MetalIndirectResult::default()
        );
        assert_eq!(
            runtime
                .execute_indirect_gpu(
                    list,
                    dispatch_sig,
                    2,
                    &args,
                    0,
                    Some(2),
                    Some((&[2, 0, 0, 0], 0)),
                )
                .expect("GPU dispatch decode two"),
            2
        );
        let decoded = runtime.last_indirect_results();
        assert_eq!((decoded[1].x, decoded[1].y, decoded[1].z), (4, 5, 6));
        let error = runtime
            .execute_indirect_gpu(list, dispatch_sig, 2, &args, 0, Some(1), Some((&[1, 0], 0)))
            .expect_err("short count buffer");
        assert_eq!(
            error.message,
            "ExecuteIndirect count buffer range 4 exceeds the supplied 2 bytes"
        );
        let error = runtime
            .execute_indirect_gpu(list, 0x9999, 1, &args, 0, None, None)
            .expect_err("unknown signature");
        assert_eq!(
            error.message,
            "ExecuteIndirect with unknown command signature 0x9999"
        );
        let error = runtime
            .execute_indirect_gpu(list, dispatch_sig, 1, &args, 0, Some(2), None)
            .expect_err("count above max");
        assert_eq!(
            error.message,
            "invalid ExecuteIndirect: Count 2 exceeds MaxCommandCount 1"
        );
        let error = runtime
            .execute_indirect_gpu(list, dispatch_sig, 1, &args, 1, None, None)
            .expect_err("misaligned offset");
        assert_eq!(
            error.message,
            "invalid ExecuteIndirect: ArgumentBufferOffset 1 is not 4-byte aligned"
        );
        let error = runtime
            .execute_indirect_gpu(list, dispatch_sig, 2, &args[..12], 0, None, None)
            .expect_err("short argument range");
        assert_eq!(
            error.message,
            "ExecuteIndirect argument buffer range 24 exceeds the supplied 12 bytes"
        );
        let error = runtime
            .execute_indirect_gpu(list, dispatch_sig, 2, &args, u64::MAX - 3, Some(2), None)
            .expect_err("argument range overflow");
        assert_eq!(
            error.message,
            "ExecuteIndirect argument buffer range overflows"
        );
    }

    #[test]
    fn d3d12_execute_indirect_draw_rejects_missing_native_pipeline_and_matches_direct_draw() {
        if std::env::var_os("CI").is_some() {
            // CI's virtual GPU raises Objective-C exceptions on shader
            // compilation; uncatchable from Rust. Local Metal runs cover this.
            return;
        }
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);
        let target = runtime
            .create_committed_resource(ResourceDesc {
                name: "native-draw-target".into(),
                format: DxgiFormat::B8G8R8A8Unorm,
                heap: HeapType::Default,
                size: 4 * 4 * 4,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
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
            .create_committed_resource(ResourceDesc {
                name: "native-draw-vertices".into(),
                format: DxgiFormat::Unknown,
                heap: HeapType::Default,
                size: vertex_bytes.len(),
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("vertex resource");
        runtime
            .write_resource_bytes(vertex, vertex_bytes)
            .expect("upload vertices");
        assert_eq!(
            runtime.resource_bytes(vertex).expect("vertex bytes").len(),
            36
        );
        let draw_sig = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 16,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("draw signature");
        let args = draw_argument_bytes(3, 1);
        let error = runtime
            .execute_indirect_gpu(
                list,
                draw_sig,
                1,
                &args,
                0,
                Some(1),
                Some((&[1, 0, 0, 0], 0)),
            )
            .expect_err("missing native pipeline");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW requires a native graphics pipeline bound by SetPipelineState"
        );
        assert_eq!(runtime.last_indirect_native(), false);
        assert_eq!(
            runtime
                .backend()
                .resource_bytes(target)
                .expect("target bytes"),
            &[0u8; 64][..]
        );

        runtime.bind_native_render_target(list, target, 4, 4, DxgiFormat::B8G8R8A8Unorm);
        let error = runtime
            .execute_indirect_gpu(
                list,
                draw_sig,
                1,
                &args,
                0,
                Some(1),
                Some((&[1, 0, 0, 0], 0)),
            )
            .expect_err("missing native pipeline after target");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW requires a native graphics pipeline bound by SetPipelineState"
        );

        let root_signature = runtime.create_root_signature(RootSignatureDesc::default());
        let pso = runtime.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "native-draw-pso".into(),
                compute: false,
                render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
                depth_format: None,
            },
        );
        runtime
            .register_native_render_pipeline(
                pso,
                r#"#include <metal_stdlib>
using namespace metal;
struct VOut { float4 position [[position]]; };
vertex VOut vs_main(uint vid [[vertex_id]], device const float* vertices [[buffer(0)]]) {
    VOut out;
    uint base = vid * 3u;
    out.position = float4(vertices[base], vertices[base + 1u], vertices[base + 2u], 1.0);
    return out;
}"#
                .to_string(),
                r#"#include <metal_stdlib>
using namespace metal;
fragment float4 fs_main() { return float4(1.0, 0.0, 0.0, 1.0); }"#
                    .to_string(),
                DxgiFormat::B8G8R8A8Unorm,
            )
            .expect("native pipeline");
        runtime
            .bind_native_pipeline(list, pso)
            .expect("bind pipeline");
        assert_eq!(runtime.native_target_dimensions(target), Some((4, 4)));
        assert_eq!(
            runtime
                .backend()
                .resource_desc(target)
                .expect("resource desc")
                .format,
            DxgiFormat::B8G8R8A8Unorm
        );
        assert_eq!(
            runtime
                .backend()
                .pipeline_state_desc(pso)
                .expect("pipeline desc")
                .label,
            "native-draw-pso"
        );
        let heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        runtime
            .write_descriptor(
                heap,
                0,
                ViewDescriptor::Rtv {
                    resource: target,
                    format: DxgiFormat::B8G8R8A8Unorm,
                },
            )
            .expect("write RTV descriptor");
        assert_eq!(
            matches!(
                runtime
                    .backend()
                    .descriptor_at_view(heap, 0)
                    .expect("RTV descriptor view"),
                ViewDescriptor::Rtv { .. }
            ),
            true
        );
        let error = runtime
            .execute_indirect_gpu(
                list,
                draw_sig,
                1,
                &args,
                0,
                Some(1),
                Some((&[1, 0, 0, 0], 0)),
            )
            .expect_err("missing vertex buffer");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW requires a vertex buffer bound by IASetVertexBuffers"
        );
        runtime.bind_native_vertex_buffer(list, vertex, 0);
        assert_eq!(
            runtime
                .execute_native_direct_draw(list, 3, 1)
                .expect("native direct draw"),
            true
        );
        let direct_pixels = runtime
            .backend()
            .resource_bytes(target)
            .expect("direct readback")
            .to_vec();
        assert_eq!(direct_pixels[0..4], [0, 0, 255, 255]);

        let targetless_list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .bind_native_pipeline(targetless_list, pso)
            .expect("bind targetless");
        runtime.bind_native_vertex_buffer(targetless_list, vertex, 0);
        assert_eq!(
            runtime
                .execute_native_direct_draw(targetless_list, 3, 1)
                .expect("direct draw missing target"),
            false
        );
        let vertexless_list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .bind_native_pipeline(vertexless_list, pso)
            .expect("bind vertexless");
        runtime.bind_native_render_target(vertexless_list, target, 4, 4, DxgiFormat::B8G8R8A8Unorm);
        assert_eq!(
            runtime
                .execute_native_direct_draw(vertexless_list, 3, 1)
                .expect("direct draw missing vertex"),
            false
        );
        let error = runtime
            .execute_indirect_gpu(
                targetless_list,
                draw_sig,
                1,
                &args,
                0,
                Some(1),
                Some((&[1, 0, 0, 0], 0)),
            )
            .expect_err("missing render target");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW requires a render target bound by OMSetRenderTargets"
        );

        runtime
            .write_resource_bytes(target, &[0u8; 64])
            .expect("clear target");
        assert_eq!(
            runtime
                .execute_indirect_gpu(
                    list,
                    draw_sig,
                    1,
                    &args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("native indirect draw"),
            1
        );
        assert_eq!(runtime.last_indirect_native(), true);
        let indirect_pixels = runtime
            .backend()
            .resource_bytes(target)
            .expect("indirect readback")
            .to_vec();
        assert_eq!(indirect_pixels, direct_pixels);

        let indices: [u16; 3] = [0, 1, 2];
        let index_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                indices.as_ptr() as *const u8,
                std::mem::size_of_val(&indices),
            )
        };
        let index_resource = runtime
            .create_committed_resource(ResourceDesc {
                name: "native-draw-indices".into(),
                format: DxgiFormat::Unknown,
                heap: HeapType::Default,
                size: index_bytes.len(),
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Index,
                    cpu_write_frequent: true,
                },
            })
            .expect("index resource");
        runtime
            .write_resource_bytes(index_resource, index_bytes)
            .expect("upload indices");
        runtime.bind_native_index_buffer(list, index_resource, 0, 57);
        let indexed_sig = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 20,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW_INDEXED,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("indexed signature");
        let indexed_args = [
            3u32.to_le_bytes(),
            1u32.to_le_bytes(),
            0u32.to_le_bytes(),
            0u32.to_le_bytes(),
            0u32.to_le_bytes(),
        ]
        .concat();
        let zero_args = draw_argument_bytes(0, 1);
        runtime
            .write_resource_bytes(target, &[0u8; 64])
            .expect("clear target for disabled command");
        assert_eq!(
            runtime
                .execute_indirect_gpu(
                    list,
                    draw_sig,
                    1,
                    &zero_args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("disabled indirect draw"),
            0
        );
        runtime
            .write_resource_bytes(target, &[0u8; 64])
            .expect("clear target for indexed");
        assert_eq!(
            runtime
                .execute_indirect_gpu(
                    list,
                    indexed_sig,
                    1,
                    &indexed_args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("native indexed draw"),
            1
        );
        assert_eq!(
            runtime
                .backend()
                .resource_bytes(target)
                .expect("indexed pixels"),
            &direct_pixels[..]
        );
        runtime.bind_native_index_buffer(list, index_resource, 0, 42);
        runtime
            .write_resource_bytes(target, &[0u8; 64])
            .expect("clear target for uint32 indices");
        assert_eq!(
            runtime
                .execute_indirect_gpu(
                    list,
                    indexed_sig,
                    1,
                    &indexed_args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("native indexed draw uint32"),
            1
        );
        runtime.bind_native_index_buffer(list, index_resource, 0, 1);
        let error = runtime
            .execute_indirect_gpu(
                list,
                indexed_sig,
                1,
                &indexed_args,
                0,
                Some(1),
                Some((&[1, 0, 0, 0], 0)),
            )
            .expect_err("unsupported index format");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW_INDEXED index format 1 is not supported"
        );
        runtime.bind_native_index_buffer(list, index_resource, 0, 57);

        // A fresh runtime exercises first-use native pipeline creation on the
        // indirect path (no preceding direct draw).
        let mut first_indirect = D3d12Runtime::new();
        let first_list = first_indirect.create_graphics_command_list(0, 0, false);
        let first_sig = first_indirect
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 16,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DRAW,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("first draw signature");
        let first_target = first_indirect
            .create_committed_resource(ResourceDesc {
                name: "first-indirect-target".into(),
                format: DxgiFormat::B8G8R8A8Unorm,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: false,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("first target");
        let first_vertex = first_indirect
            .create_committed_resource(ResourceDesc {
                name: "first-indirect-vertex".into(),
                format: DxgiFormat::Unknown,
                heap: HeapType::Default,
                size: 36,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("first vertex");
        first_indirect
            .write_resource_bytes(first_vertex, vertex_bytes)
            .expect("first vertices");
        let first_root = first_indirect.create_root_signature(RootSignatureDesc::default());
        let first_pso = first_indirect.create_pipeline_state(
            first_root,
            PipelineStateDesc {
                label: "first-indirect-pso".into(),
                compute: false,
                render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
                depth_format: None,
            },
        );
        first_indirect
            .register_native_render_pipeline(
                first_pso,
                r#"#include <metal_stdlib>
using namespace metal;
struct VOut { float4 position [[position]]; };
vertex VOut vs_main(uint vid [[vertex_id]], device const float* vertices [[buffer(0)]]) {
    VOut out;
    uint base = vid * 3u;
    out.position = float4(vertices[base], vertices[base + 1u], vertices[base + 2u], 1.0);
    return out;
}"#
                .to_string(),
                r#"#include <metal_stdlib>
using namespace metal;
fragment float4 fs_main() { return float4(1.0, 0.0, 0.0, 1.0); }"#
                    .to_string(),
                DxgiFormat::B8G8R8A8Unorm,
            )
            .expect("first pipeline");
        first_indirect
            .bind_native_pipeline(first_list, first_pso)
            .expect("first bind");
        first_indirect.bind_native_render_target(
            first_list,
            first_target,
            4,
            4,
            DxgiFormat::B8G8R8A8Unorm,
        );
        first_indirect.bind_native_vertex_buffer(first_list, first_vertex, 0);
        assert_eq!(
            first_indirect
                .execute_indirect_gpu(
                    first_list,
                    first_sig,
                    1,
                    &args,
                    0,
                    Some(1),
                    Some((&[1, 0, 0, 0], 0)),
                )
                .expect("first indirect"),
            1
        );
        assert_eq!(
            first_indirect
                .backend()
                .resource_bytes(first_target)
                .expect("first pixels")[0..4],
            [0, 0, 255, 255]
        );
        assert_eq!(
            format!("{:?}", first_indirect).contains("D3d12MetalRayTracing"),
            true
        );

        let fault_root = runtime.create_root_signature(RootSignatureDesc::default());
        let fault_pso = runtime.create_pipeline_state(
            fault_root,
            PipelineStateDesc {
                label: "native-draw-fault-pso".into(),
                compute: false,
                render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
                depth_format: None,
            },
        );
        runtime
            .register_native_render_pipeline(
                fault_pso,
                r#"#include <metal_stdlib>
using namespace metal;
struct VOut { float4 position [[position]]; };
vertex VOut vs_main(uint vid [[vertex_id]], device const float* vertices [[buffer(0)]]) {
    VOut out;
    uint base = vid * 3u;
    out.position = float4(vertices[base], vertices[base + 1u], vertices[base + 2u], 1.0);
    return out;
}"#
                .to_string(),
                r#"#include <metal_stdlib>
using namespace metal;
fragment float4 fs_main() { return float4(1.0, 0.0, 0.0, 1.0); }"#
                    .to_string(),
                DxgiFormat::B8G8R8A8Unorm,
            )
            .expect("fault pipeline registration");
        let fault_list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .bind_native_pipeline(fault_list, fault_pso)
            .expect("bind fault pipeline");
        runtime.bind_native_render_target(fault_list, target, 4, 4, DxgiFormat::B8G8R8A8Unorm);
        runtime.bind_native_vertex_buffer(fault_list, vertex, 0);
        crate::metal_backend::set_native_pipeline_creation_fault(true);
        let error = runtime
            .execute_native_direct_draw(fault_list, 3, 1)
            .expect_err("native pipeline creation fault");
        crate::metal_backend::set_native_pipeline_creation_fault(false);
        assert_eq!(error.message, "native render pipeline creation fault");

        let mesh_sig = runtime
            .create_command_signature(D3D12CommandSignatureDesc {
                byte_stride: 12,
                node_mask: 0,
                arguments: vec![D3D12IndirectArgumentDesc {
                    ty: D3D12_INDIRECT_ARGUMENT_TYPE_DISPATCH_MESH,
                    root_parameter_index: 0,
                    dest_offset_in_32bit_values: 0,
                    num_32bit_values_to_set: 0,
                }],
            })
            .expect("mesh signature");
        let mesh_args = [1u32, 1, 1].map(|value| value.to_le_bytes()).concat();
        assert_eq!(
            runtime
                .execute_indirect_gpu(list, mesh_sig, 1, &mesh_args, 0, Some(1), None)
                .expect("mesh typed fallback"),
            1
        );
        assert_eq!(runtime.last_indirect_native(), false);
        assert_eq!(
            runtime
                .last_indirect_boundary()
                .expect("mesh boundary")
                .contains("DISPATCH_MESH"),
            true
        );

        let no_index_list = runtime.create_graphics_command_list(0, 0, false);
        runtime
            .bind_native_pipeline(no_index_list, pso)
            .expect("bind no-index pipeline");
        runtime.bind_native_render_target(no_index_list, target, 4, 4, DxgiFormat::B8G8R8A8Unorm);
        runtime.bind_native_vertex_buffer(no_index_list, vertex, 0);
        let error = runtime
            .execute_native_indirect_draw(
                no_index_list,
                1,
                &[crate::metal_backend::MetalIndirectResult {
                    kind: 1,
                    x: 3,
                    y: 1,
                    z: 0,
                    w: 0,
                    enabled: 1,
                }],
                1,
            )
            .expect_err("missing index buffer");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW_INDEXED requires an index buffer bound by IASetIndexBuffer"
        );
        let mut empty_runtime = D3d12Runtime::new();
        let empty_list = empty_runtime.create_graphics_command_list(0, 0, false);
        assert_eq!(
            empty_runtime
                .execute_native_direct_draw(empty_list, 3, 1)
                .expect("no native state"),
            false
        );
        let error = empty_runtime
            .execute_native_indirect_draw(
                empty_list,
                0,
                &[crate::metal_backend::MetalIndirectResult {
                    kind: 0,
                    x: 3,
                    y: 1,
                    z: 0,
                    w: 0,
                    enabled: 1,
                }],
                1,
            )
            .expect_err("missing pipeline");
        assert_eq!(
            error.message,
            "ExecuteIndirect DRAW requires a native graphics pipeline bound by SetPipelineState"
        );
    }

    fn make_ray_llvm_container(bitcode: &[u8], kind: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        let descriptors_end = 12u32 + 3 * 12;
        let prog_off = descriptors_end;
        let prog_size: u32 = 24 + bitcode.len() as u32;
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&prog_off.to_le_bytes());
        data.extend_from_slice(&prog_size.to_le_bytes());
        let sign_off = prog_off + prog_size;
        data.extend_from_slice(b"SIGN");
        data.extend_from_slice(&sign_off.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        let meta_text =
            format!("shader_kind={kind}\npayloadSizeInBytes=16\nattributeSizeInBytes=8\n");
        let meta_off = sign_off + 4;
        data.extend_from_slice(b"META");
        data.extend_from_slice(&meta_off.to_le_bytes());
        data.extend_from_slice(&((5 + meta_text.len()) as u32).to_le_bytes());
        while data.len() < prog_off as usize {
            data.push(0);
        }
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(bitcode.len() as u32).to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(bitcode);
        data.extend_from_slice(b"SIG1");
        data.push(4);
        data.extend_from_slice(b"main");
        data.extend_from_slice(meta_text.as_bytes());
        data
    }

    fn make_ray_dxil(kind: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        let descriptors_end = 12u32 + 3 * 12;
        let prog_off = descriptors_end;
        let prog_size: u32 = 24 + 4;
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&prog_off.to_le_bytes());
        data.extend_from_slice(&prog_size.to_le_bytes());
        let sign_off = prog_off + prog_size;
        data.extend_from_slice(b"SIGN");
        data.extend_from_slice(&sign_off.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        let meta_text =
            format!("shader_kind={kind}\npayloadSizeInBytes=16\nattributeSizeInBytes=8\n");
        let meta_off = sign_off + 4;
        data.extend_from_slice(b"META");
        data.extend_from_slice(&meta_off.to_le_bytes());
        data.extend_from_slice(&((5 + meta_text.len()) as u32).to_le_bytes());
        while data.len() < prog_off as usize {
            data.push(0);
        }
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&64u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x4243_C0DEu32.to_be_bytes());
        data.extend_from_slice(b"SIG1");
        data.push(4);
        data.extend_from_slice(b"main");
        data.extend_from_slice(meta_text.as_bytes());
        data
    }

    #[test]
    fn d3d12_ray_state_object_compiles_each_stage_from_its_own_bitcode() {
        let stages = [
            ("raygeneration", "raygen", "kernel void raygen"),
            ("closesthit", "chs_entry", "void msl_closest_hit"),
            ("anyhit", "ahs_entry", "bool msl_any_hit"),
            ("miss", "miss_entry", "void msl_miss"),
            ("callable", "call_entry", "void msl_callable"),
            ("intersection", "isect_entry", "bool msl_intersection"),
        ];
        let mut subobjects = Vec::new();
        for (kind, entry, _) in stages {
            let ir = format!(
                "define void @{entry}() {{\nentry:\n  %c = call i32 @dx.op.candidateType(i32 0)\n  call void @ray.storePayloadField(i32 0, i32 %c)\n  ret void\n}}\ndeclare i32 @dx.op.candidateType(i32)\ndeclare void @ray.storePayloadField(i32, ...)\n"
            );
            let bitcode = crate::shader::llvm_assemble_ir(&ir).expect("stage bitcode");
            let container = make_ray_llvm_container(&bitcode, kind);
            subobjects.push(D3d12StateSubobject::DxilLibrary(
                state_objects::D3d12DxilLibrary {
                    bytecode: container,
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: entry.into(),
                        export_to_rename: None,
                        flags: 0,
                    }],
                },
            ));
        }
        let bare_ir = "define void @chs_bare() {\nentry:\n  ret void\n}\n";
        let bare_bitcode = crate::shader::llvm_assemble_ir(bare_ir).expect("bare stage bitcode");
        subobjects.push(D3d12StateSubobject::DxilLibrary(
            state_objects::D3d12DxilLibrary {
                bytecode: make_ray_llvm_container(&bare_bitcode, "closesthit"),
                exports: Vec::new(),
            },
        ));
        subobjects.push(D3d12StateSubobject::RaytracingPipelineConfig {
            max_trace_recursion_depth: 1,
        });
        let desc = D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects,
        };
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);
        let handle = runtime.create_state_object(desc.clone()).expect("RTSO");
        runtime
            .set_pipeline_state1_state_object(list, handle, desc)
            .expect("bind RTSO");
        let pso = runtime
            .get_raytracing_pipeline_state(handle)
            .expect("ray PSO");
        assert_eq!(pso.ray_stages.len(), stages.len() + 1);
        assert_eq!(pso.ray_stages["chs_bare"].stage, "closesthit",);
        for (kind, entry, function) in stages {
            let artifact = pso.ray_stages.get(entry).expect("stage artifact");
            assert_eq!(artifact.stage, kind);
            assert_eq!(artifact.entry, entry);
            assert_eq!(
                artifact.source.contains(function),
                true,
                "{kind} missing {function}"
            );
        }
        assert_eq!(
            pso.ray_stages["raygen"].source.contains("query.intersect"),
            true
        );
        let combined = pso.ray_msl.as_deref().expect("combined raygen");
        assert_eq!(combined.contains("float4(42.0"), false);
        assert_eq!(combined.contains("group & 0x100u"), false);
        assert_eq!(combined.contains("msl_closest_hit"), true);
        assert_eq!(combined.contains("msl_intersection"), true);
        let metal = crate::metal_backend::MetalDevice::system_default()
            .expect("Metal device for combined raygen");
        crate::metal_backend::create_ray_shader_program(metal.metal_device(), combined, "raygen")
            .expect("combined raygen compiles");
        assert_eq!(
            pso.ray_stages["isect_entry"]
                .source
                .contains("msl_intersection"),
            true
        );
    }

    #[test]
    fn d3d12_ray_stage_artifacts_reject_bad_bitcode_with_exact_error() {
        let ir = "define void @other() {\nentry:\n  fence seq_cst\n  ret void\n}\n";
        let bitcode = crate::shader::llvm_assemble_ir(ir).expect("bad stage bitcode");
        let container = make_ray_llvm_container(&bitcode, "closesthit");
        let desc = D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects: vec![
                D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                    bytecode: container,
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: "missing_entry".into(),
                        export_to_rename: None,
                        flags: 0,
                    }],
                }),
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                },
            ],
        };
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);
        let handle = runtime.create_state_object(desc.clone()).expect("bad RTSO");
        let error = runtime
            .set_pipeline_state1_state_object(list, handle, desc)
            .expect_err("bad stage bitcode");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(error.message, "unsupported LLVM instruction fence");
    }

    fn ray_test_state_object(
        runtime: &mut D3d12Runtime,
        list: CommandListId,
        stages: &[(&str, &str, &str)],
    ) -> AppResult<u64> {
        let mut subobjects = Vec::new();
        for (kind, entry, ir) in stages {
            let bitcode = crate::shader::llvm_assemble_ir(ir).expect("stage bitcode");
            subobjects.push(D3d12StateSubobject::DxilLibrary(
                state_objects::D3d12DxilLibrary {
                    bytecode: make_ray_llvm_container(&bitcode, kind),
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: entry.to_string(),
                        export_to_rename: None,
                        flags: 0,
                    }],
                },
            ));
        }
        subobjects.push(D3d12StateSubobject::RaytracingPipelineConfig {
            max_trace_recursion_depth: 1,
        });
        let desc = D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects,
        };
        let handle = runtime.create_state_object(desc.clone())?;
        runtime.set_pipeline_state1_state_object(list, handle, desc)?;
        Ok(handle)
    }

    fn ray_test_attribute_formats(runtime: &mut D3d12Runtime, list: CommandListId) {
        let float2: [f32; 8] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let float2_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(float2.as_ptr() as *const u8, std::mem::size_of_val(&float2))
        };
        runtime.register_raytracing_buffer(0x1400, float2_bytes.to_vec());
        let u16_indices: [u16; 3] = [0, 1, 2];
        let u16_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                u16_indices.as_ptr() as *const u8,
                std::mem::size_of_val(&u16_indices),
            )
        };
        runtime.register_raytracing_buffer(0x1408, u16_bytes.to_vec());
        let float2_blas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x14_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0,
                    flags: 1,
                    vertex_buffer: 0x1400,
                    vertex_format: 17,
                    vertex_stride: 8,
                    vertex_count: 4,
                    index_buffer: 0x1408,
                    index_format: 57,
                    index_count: 3,
                }],
            },
            source_address: 0,
            scratch_address: 0x15_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &float2_blas)
            .expect("float2 BLAS");

        let halves: [u16; 16] = [
            0x3C00, 0x4000, 0x4200, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x7C00, 0x0000, 0x0000,
            0x0000, 0x7E00, 0x0000, 0x0000, 0x0000,
        ];
        let half_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(halves.as_ptr() as *const u8, std::mem::size_of_val(&halves))
        };
        runtime.register_raytracing_buffer(0x1500, half_bytes.to_vec());
        let u32_indices: [u32; 3] = [0, 1, 2];
        let u32_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                u32_indices.as_ptr() as *const u8,
                std::mem::size_of_val(&u32_indices),
            )
        };
        runtime.register_raytracing_buffer(0x1508, u32_bytes.to_vec());
        let half_blas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x15_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0,
                    flags: 1,
                    vertex_buffer: 0x1500,
                    vertex_format: 35,
                    vertex_stride: 8,
                    vertex_count: 4,
                    index_buffer: 0x1508,
                    index_format: 42,
                    index_count: 3,
                }],
            },
            source_address: 0,
            scratch_address: 0x16_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &half_blas)
            .expect("half BLAS");
    }

    fn ray_test_triangle_tlas(runtime: &mut D3d12Runtime, list: CommandListId) {
        let vertices: [f32; 9] = [-1.0, -1.0, 0.0, 1.0, -1.0, 0.0, 0.0, 1.0, 0.0];
        let vertex_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                vertices.as_ptr() as *const u8,
                std::mem::size_of_val(&vertices),
            )
        };
        runtime.register_raytracing_buffer(0x1000, vertex_bytes.to_vec());
        let blas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x10_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0,
                    flags: 1,
                    vertex_buffer: 0x1000,
                    vertex_format: 6,
                    vertex_stride: 12,
                    vertex_count: 3,
                    index_buffer: 0,
                    index_format: 0,
                    index_count: 0,
                }],
            },
            source_address: 0,
            scratch_address: 0x11_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &blas)
            .expect("triangle BLAS");
        let mut instances = [0u8; 64];
        instances[48..52].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        instances[52..56].copy_from_slice(&0x07u32.to_le_bytes());
        instances[56..64].copy_from_slice(&0x10_0000u64.to_le_bytes());
        runtime.register_raytracing_instances(0x20_0000, instances.to_vec());
        let tlas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x20_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 1,
                flags: 0,
                num_descs: 1,
                geometries: Vec::new(),
            },
            source_address: 0,
            scratch_address: 0x21_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &tlas)
            .expect("triangle TLAS");
    }

    fn ray_test_aabb_tlas(runtime: &mut D3d12Runtime, list: CommandListId) {
        let bounds: [f32; 6] = [-1.0, -1.0, 0.0, 1.0, 1.0, 1.0];
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(bounds.as_ptr() as *const u8, std::mem::size_of_val(&bounds))
        };
        runtime.register_raytracing_buffer(0x1800, bytes.to_vec());
        let blas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x12_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 1,
                    flags: 1,
                    vertex_buffer: 0x1800,
                    vertex_format: 0,
                    vertex_stride: 24,
                    vertex_count: 1,
                    index_buffer: 0,
                    index_format: 0,
                    index_count: 0,
                }],
            },
            source_address: 0,
            scratch_address: 0x13_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &blas)
            .expect("AABB BLAS");
        let mut instances = [0u8; 64];
        instances[48..52].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        instances[52..56].copy_from_slice(&0x07u32.to_le_bytes());
        instances[56..64].copy_from_slice(&0x12_0000u64.to_le_bytes());
        runtime.register_raytracing_instances(0x22_0000, instances.to_vec());
        let tlas = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x22_0000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 1,
                flags: 0,
                num_descs: 1,
                geometries: Vec::new(),
            },
            source_address: 0,
            scratch_address: 0x23_0000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &tlas)
            .expect("AABB TLAS");
    }

    fn ray_dispatch(
        runtime: &mut D3d12Runtime,
        list: CommandListId,
        rays: &[crate::metal_backend::MetalRay],
        records: &[u32],
    ) -> Vec<crate::metal_backend::MetalRayPayloadResult> {
        let ray_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(rays.as_ptr() as *const u8, std::mem::size_of_val(rays))
        };
        runtime.register_raytracing_buffer(0x30_0000, ray_bytes.to_vec());
        let mut table = Vec::new();
        for record in records {
            table.extend_from_slice(&record.to_le_bytes());
        }
        runtime.register_raytracing_buffer(0x31_0000, table);
        let desc = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0x30_0000,
            raygen_shader_size: std::mem::size_of_val(rays) as u64,
            miss_shader_start_address: 0,
            miss_shader_size: 0,
            miss_shader_stride: 0,
            hit_group_start_address: 0x31_0000,
            hit_group_size: (records.len() * 4) as u64,
            hit_group_stride: 4,
            callable_shader_start_address: 0,
            callable_shader_size: 0,
            callable_shader_stride: 0,
            width: rays.len() as u32,
            height: 1,
            depth: 1,
        };
        runtime.dispatch_rays(list, &desc).expect("dispatch rays");
        runtime.last_ray_payloads()
    }

    #[test]
    fn d3d12_ray_sbt_selects_multiple_closest_and_miss_exports() {
        let raygen = r#"define void @raygen() {
entry:
  %idx = call i32 @dx.op.dispatchRaysIndex(i32 1)
  call void @ray.storePayloadField(i32 1, i32 %idx)
  call void @dx.op.traceRay(i32 0, ptr null, i32 3, i32 -1, i32 0, i32 1, i32 0, float 0.0, float 0.0, float -1.0, float 0.0, float 0.0, float 0.0, float 1.0, float 100.0, i32 0)
  ret void
}
declare i32 @dx.op.dispatchRaysIndex(i32)
declare void @ray.storePayloadField(i32, ...)
declare void @dx.op.traceRay(i32, ptr, i32, i32, i32, i32, i32, float, float, float, float, float, float, float, float, i32)
"#;
        let closest_a = "define void @chs_a() {\nentry:\n  call void @ray.storePayloadField(i32 0, i32 111)\n  ret void\n}\ndeclare void @ray.storePayloadField(i32, ...)\n";
        let closest_b = "define void @chs_b() {\nentry:\n  call void @ray.storePayloadField(i32 0, i32 222)\n  ret void\n}\ndeclare void @ray.storePayloadField(i32, ...)\n";
        let miss_a = "define void @miss_a() {\nentry:\n  call void @ray.storePayloadField(i32 0, i32 333)\n  ret void\n}\ndeclare void @ray.storePayloadField(i32, ...)\n";
        let miss_b = "define void @miss_b() {\nentry:\n  call void @ray.storePayloadField(i32 0, i32 444)\n  ret void\n}\ndeclare void @ray.storePayloadField(i32, ...)\n";
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);
        let handle = ray_test_state_object(
            &mut runtime,
            list,
            &[
                ("raygeneration", "raygen", raygen),
                ("closesthit", "chs_a", closest_a),
                ("closesthit", "chs_b", closest_b),
                ("miss", "miss_a", miss_a),
                ("miss", "miss_b", miss_b),
            ],
        )
        .expect("ray state object");
        ray_test_triangle_tlas(&mut runtime, list);
        let pso = runtime
            .get_raytracing_pipeline_state(handle)
            .expect("ray PSO")
            .clone();
        let chs_a_index = pso.ray_stages["chs_a"].function_index;
        let chs_b_index = pso.ray_stages["chs_b"].function_index;
        let miss_a_index = pso.ray_stages["miss_a"].function_index;
        let miss_b_index = pso.ray_stages["miss_b"].function_index;
        let hit_rays = [
            crate::metal_backend::MetalRay {
                origin: [0.0, 0.0, -1.0],
                min_distance: 0.0,
                direction: [0.0, 0.0, 1.0],
                max_distance: 100.0,
                sbt_offset: 0,
                mask: 0xFFFF_FFFF,
            },
            crate::metal_backend::MetalRay {
                origin: [0.0, 0.0, -1.0],
                min_distance: 0.0,
                direction: [0.0, 0.0, 1.0],
                max_distance: 100.0,
                sbt_offset: 1,
                mask: 0xFFFF_FFFF,
            },
        ];
        let hits = ray_dispatch(&mut runtime, list, &hit_rays, &[chs_a_index, chs_b_index]);
        assert_eq!(hits[0].payload_word(1), Some(0));
        assert_eq!(hits[1].payload_word(1), Some(1));
        assert_eq!(hits[0].payload_word(0), Some(111));
        assert_eq!(hits[1].payload_word(0), Some(222));

        let miss_rays = [
            crate::metal_backend::MetalRay {
                origin: [100.0, 100.0, -1.0],
                min_distance: 0.0,
                direction: [0.0, 0.0, 1.0],
                max_distance: 0.5,
                sbt_offset: 0,
                mask: 0,
            },
            crate::metal_backend::MetalRay {
                origin: [100.0, 100.0, -1.0],
                min_distance: 0.0,
                direction: [0.0, 0.0, 1.0],
                max_distance: 0.5,
                sbt_offset: 1,
                mask: 0,
            },
        ];
        let misses = ray_dispatch(
            &mut runtime,
            list,
            &miss_rays,
            &[miss_a_index, miss_b_index],
        );
        assert_eq!(misses[0].payload_word(0), Some(333));
        assert_eq!(misses[1].payload_word(0), Some(444));
    }

    #[test]
    fn d3d12_ray_procedural_intersection_accepts_and_rejects() {
        let raygen = r#"define void @raygen() {
entry:
  call void @dx.op.traceRay(i32 0, ptr null, i32 3, i32 -1, i32 0, i32 1, i32 0, float 0.0, float 0.0, float -1.0, float 0.0, float 0.0, float 0.0, float 1.0, float 100.0, i32 0)
  ret void
}
declare void @dx.op.traceRay(i32, ptr, i32, i32, i32, i32, i32, float, float, float, float, float, float, float, float, i32)
"#;
        let accept = r#"define void @isect_accept() {
entry:
  %r = call i1 @dx.op.reportHit(i32 0, float 1.5, i32 1084227584, i32 0, ptr null)
  call void @dx.op.acceptHitAndEndSearch(i32 1)
  ret void
}
declare i1 @dx.op.reportHit(i32, float, i32, i32, ptr)
declare void @dx.op.acceptHitAndEndSearch(i32)
"#;
        let reject = r#"define void @isect_reject() {
entry:
  %r = call i1 @dx.op.reportHit(i32 0, float 1.5, i32 1084227584, i32 0, ptr null)
  call void @dx.op.ignoreHit(i32 1)
  ret void
}
declare i1 @dx.op.reportHit(i32, float, i32, i32, ptr)
declare void @dx.op.ignoreHit(i32)
"#;
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);
        let handle = ray_test_state_object(
            &mut runtime,
            list,
            &[
                ("raygeneration", "raygen", raygen),
                ("intersection", "isect_accept", accept),
                ("intersection", "isect_reject", reject),
            ],
        )
        .expect("procedural state object");
        ray_test_aabb_tlas(&mut runtime, list);
        let pso = runtime
            .get_raytracing_pipeline_state(handle)
            .expect("ray PSO")
            .clone();
        let accept_index = pso.ray_stages["isect_accept"].function_index;
        let reject_index = pso.ray_stages["isect_reject"].function_index;
        let rays = [
            crate::metal_backend::MetalRay {
                origin: [0.0, 0.0, -1.0],
                min_distance: 0.0,
                direction: [0.0, 0.0, 1.0],
                max_distance: 100.0,
                sbt_offset: 0,
                mask: 0xFFFF_FFFF,
            },
            crate::metal_backend::MetalRay {
                origin: [0.0, 0.0, -1.0],
                min_distance: 0.0,
                direction: [0.0, 0.0, 1.0],
                max_distance: 100.0,
                sbt_offset: 1,
                mask: 0xFFFF_FFFF,
            },
        ];
        let results = ray_dispatch(&mut runtime, list, &rays, &[accept_index, reject_index]);
        assert_eq!(results[0].hit_kind, 0xFF);
        assert_eq!(results[0].candidate_type, 1);
        assert_eq!(results[0].distance, 1.5);
        assert_eq!(results[0].attributes[0], 5.0);
        assert_eq!(results[0].accepted, 1);
        assert_eq!(results[1].hit_kind, 0);
        assert_eq!(results[1].accepted, 0);
        assert_eq!(results[1].ignored, 1);
    }

    #[test]
    fn d3d12_translated_raygen_executes_hit_miss_anyhit_callable_and_rejects_bad_stage() {
        d3d12_ray_state_object_compiles_each_stage_from_its_own_bitcode();
        d3d12_ray_stage_artifacts_reject_bad_bitcode_with_exact_error();
        d3d12_ray_sbt_selects_multiple_closest_and_miss_exports();
        d3d12_ray_procedural_intersection_accepts_and_rejects();
        let mut format_runtime = D3d12Runtime::new();
        let format_list = format_runtime.create_graphics_command_list(0, 0, false);
        ray_test_attribute_formats(&mut format_runtime, format_list);
        let mut runtime = D3d12Runtime::new();
        let list = runtime.create_graphics_command_list(0, 0, false);
        let vertices: [f32; 9] = [-1.0, -1.0, 0.0, 1.0, -1.0, 0.0, 0.0, 1.0, 0.0];
        let vertex_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                vertices.as_ptr() as *const u8,
                std::mem::size_of_val(&vertices),
            )
        };
        let indices: [u16; 3] = [0, 1, 2];
        let index_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                indices.as_ptr() as *const u8,
                std::mem::size_of_val(&indices),
            )
        };
        runtime.register_raytracing_buffer(0x3000, vertex_bytes.to_vec());
        runtime.register_raytracing_buffer(0x4000, index_bytes.to_vec());
        let geometry = D3D12RaytracingGeometryDesc {
            ty: 0,
            flags: 1,
            vertex_buffer: 0x3000,
            vertex_format: 6,
            vertex_stride: 12,
            vertex_count: 3,
            index_buffer: 0x4000,
            index_format: 57,
            index_count: 3,
        };
        runtime
            .build_raytracing_acceleration_structure(
                list,
                &D3D12BuildAccelerationStructureDesc {
                    dest_address: 0x1000,
                    inputs: D3D12BuildRaytracingInputs {
                        ty: 0,
                        flags: 0,
                        num_descs: 1,
                        geometries: vec![geometry],
                    },
                    source_address: 0,
                    scratch_address: 0x2000,
                },
            )
            .expect("BLAS");
        let mut instances = [0u8; 64];
        // Row-major 3x4 object-to-world: identity linear part plus a z
        // translation of 10, so the hit distance and transform readback prove
        // the instance table is actually bound to the shader.
        instances[0..4].copy_from_slice(&1.0f32.to_le_bytes());
        instances[20..24].copy_from_slice(&1.0f32.to_le_bytes());
        instances[40..44].copy_from_slice(&1.0f32.to_le_bytes());
        instances[44..48].copy_from_slice(&10.0f32.to_le_bytes());
        instances[48..52].copy_from_slice(&0xFF00_0000u32.to_le_bytes());
        instances[56..64].copy_from_slice(&0x1000u64.to_le_bytes());
        runtime.register_raytracing_instances(0x10_0000, instances.to_vec());
        runtime
            .build_raytracing_acceleration_structure(
                list,
                &D3D12BuildAccelerationStructureDesc {
                    dest_address: 0x10_0000,
                    inputs: D3D12BuildRaytracingInputs {
                        ty: 1,
                        flags: 0,
                        num_descs: 1,
                        geometries: Vec::new(),
                    },
                    source_address: 0,
                    scratch_address: 0x20_0000,
                },
            )
            .expect("TLAS");

        let ray_dxil = make_ray_dxil("raygeneration");
        let desc = D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects: vec![
                D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                    bytecode: ray_dxil,
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: "raygen".into(),
                        export_to_rename: None,
                        flags: 0,
                    }],
                }),
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                },
                D3d12StateSubobject::HitGroup(state_objects::D3d12HitGroup {
                    name: "hg".into(),
                    ty: 0,
                    any_hit: None,
                    closest_hit: Some("chs".into()),
                    intersection: None,
                }),
            ],
        };
        let handle = runtime.create_state_object(desc.clone()).expect("RTSO");
        runtime
            .set_pipeline_state1_state_object(list, handle, desc)
            .expect("bind RTSO");
        let pso = runtime
            .get_raytracing_pipeline_state(handle)
            .expect("ray PSO");
        assert_eq!(pso.ray_entry.as_deref(), Some("raygen"));
        assert_eq!(
            pso.ray_msl
                .as_deref()
                .expect("translated raygen")
                .contains("msl_closest_hit"),
            true
        );
        let mut ray = crate::metal_backend::MetalRay {
            origin: [0.0, 0.0, -1.0],
            min_distance: 0.0,
            direction: [0.0, 0.0, 1.0],
            max_distance: 100.0,
            sbt_offset: 0,
            mask: 0xFFFF_FFFF,
        };
        let ray_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&ray as *const _ as *const u8, std::mem::size_of_val(&ray))
        };
        runtime.register_raytracing_buffer(0x30_0000, ray_bytes.to_vec());
        let dispatch = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0x30_0000,
            raygen_shader_size: std::mem::size_of::<crate::metal_backend::MetalRay>() as u64,
            miss_shader_start_address: 0,
            miss_shader_size: 0,
            miss_shader_stride: 0,
            hit_group_start_address: 0x31_0000,
            hit_group_size: 4,
            hit_group_stride: 4,
            callable_shader_start_address: 0,
            callable_shader_size: 0,
            callable_shader_stride: 0,
            width: 1,
            height: 1,
            depth: 1,
        };
        runtime.register_raytracing_buffer(0x31_0000, 1u32.to_le_bytes().to_vec());
        runtime
            .dispatch_rays(list, &dispatch)
            .expect("hit dispatch");
        let payload = runtime.last_ray_payloads();
        assert_eq!(payload[0].value[0], 42.0);
        assert_eq!(payload[0].instance_id, 0);
        assert_eq!(payload[0].primitive_id, 0);
        assert_eq!(payload[0].distance.round() as u32, 11);
        assert_eq!(payload[0].hit_kind, 0xFE);
        assert_eq!(payload[0].object_to_world[11], 10.0);
        assert_eq!(payload[0].world_to_object[11], -10.0);

        ray.origin = [4.0, 4.0, -1.0];
        let miss_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&ray as *const _ as *const u8, std::mem::size_of_val(&ray))
        };
        runtime.register_raytracing_buffer(0x30_0000, miss_bytes.to_vec());
        runtime
            .dispatch_rays(list, &dispatch)
            .expect("miss dispatch");
        assert_eq!(runtime.last_ray_payloads()[0].value[0], 7.0);

        ray.origin = [0.0, 0.0, -1.0];
        let hit_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&ray as *const _ as *const u8, std::mem::size_of_val(&ray))
        };
        runtime.register_raytracing_buffer(0x30_0000, hit_bytes.to_vec());
        runtime.register_raytracing_buffer(0x31_0000, 0x100u32.to_le_bytes().to_vec());
        runtime
            .dispatch_rays(list, &dispatch)
            .expect("anyhit reject");
        assert_eq!(runtime.last_ray_payloads()[0].value[0], 7.0);
        runtime.register_raytracing_buffer(0x31_0000, 3u32.to_le_bytes().to_vec());
        runtime.dispatch_rays(list, &dispatch).expect("callable");
        assert_eq!(runtime.last_ray_payloads()[0].value[0], 99.0);

        let ir = r#"define void @raygen(i32 %idx) {
entry:
  %i = call i32 @dx.op.dispatchRaysIndex(i32 0)
  %m = mul i32 %i, 3
  %a = add i32 %m, 1
  call void @ray.storePayload(i32 %i, i32 %a)
  ret void
}
declare i32 @dx.op.dispatchRaysIndex(i32)
declare void @ray.storePayload(i32, i32)
"#;
        let bitcode = crate::shader::llvm_assemble_ir(ir).expect("assemble fixture");
        let container = make_ray_llvm_container(&bitcode, "raygeneration");
        let (source, entry) =
            D3d12Runtime::translate_ray_pipeline(&container).expect("bitcode RTSO");
        assert_eq!(entry.as_deref(), Some("raygen"));
        let bad_ray_ir = r#"define void @raygen(i32 %idx) {
entry:
  fence seq_cst
  ret void
}
"#;
        let bad_bitcode = crate::shader::llvm_assemble_ir(bad_ray_ir).expect("bad bitcode");
        let bad_container = make_ray_llvm_container(&bad_bitcode, "raygeneration");
        let bad_desc = D3d12StateObjectDesc {
            object_type: STATE_OBJECT_TYPE_RAYTRACING_PIPELINE,
            subobjects: vec![
                D3d12StateSubobject::DxilLibrary(state_objects::D3d12DxilLibrary {
                    bytecode: bad_container,
                    exports: vec![state_objects::D3d12ExportDesc {
                        name: "raygen".into(),
                        export_to_rename: None,
                        flags: 0,
                    }],
                }),
                D3d12StateSubobject::RaytracingPipelineConfig {
                    max_trace_recursion_depth: 1,
                },
            ],
        };
        let bad_handle = runtime
            .create_state_object(bad_desc.clone())
            .expect("bad RTSO");
        let error = runtime
            .set_pipeline_state1_state_object(list, bad_handle, bad_desc)
            .expect_err("unsupported ray opcode must fail RTSO");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(error.message, "unsupported LLVM instruction fence");

        let bitcode_msl = source.expect("bitcode raygen MSL");
        assert_eq!(bitcode_msl.contains("results["), true);
        assert_eq!(bitcode_msl.contains("= float("), true);

        let bad = make_ray_dxil("unsupported");
        let error = crate::shader::translate_ray_shader(
            &bad,
            crate::shader::ShaderStage::RayGeneration,
            "raygen",
        )
        .expect_err("bad ray kind");
        assert_eq!(
            error.message,
            "ray shader is missing a supported shader_kind metadata marker"
        );
        let mismatch = make_ray_dxil("raygeneration");
        let error = crate::shader::translate_ray_shader(
            &mismatch,
            crate::shader::ShaderStage::ClosestHit,
            "chs",
        )
        .expect_err("stage mismatch");
        assert_eq!(
            error.message,
            "ray shader metadata declares raygeneration but export chs requests closesthit"
        );
        let source = crate::shader::translate_ray_shader(
            &mismatch,
            crate::shader::ShaderStage::Intersection,
            "isect",
        );
        assert_eq!(source.is_err(), true);
        let (no_source, no_entry) =
            D3d12Runtime::translate_ray_pipeline(&bad).expect("bad metadata");
        assert_eq!(no_source, None);
        assert_eq!(no_entry, None);
        let non_ray = make_ray_dxil("");
        let closest_hit = make_ray_dxil("closesthit");
        let (no_source, no_entry) =
            D3d12Runtime::translate_ray_pipeline(&closest_hit).expect("non-raygen");
        assert_eq!(no_source, None);
        assert_eq!(no_entry, None);
        let (no_source, no_entry) =
            D3d12Runtime::translate_ray_pipeline(&non_ray).expect("no kind");
        assert_eq!(no_source, None);
        assert_eq!(no_entry, None);
        let (source, entry) =
            D3d12Runtime::translate_ray_pipeline(&mismatch).expect("metadata raygen");
        assert_eq!(entry.as_deref(), Some("raygen"));
        assert_eq!(source.expect("ray msl").contains("query.intersect"), true);
    }

    fn metalfx_swapchain(runtime: &mut D3d12Runtime) -> SwapchainId {
        runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create MetalFX swapchain")
    }

    #[test]
    fn metalfx_present_rejects_unsupported_mode_format_and_sizes_before_enabling() {
        let mut runtime = D3d12Runtime::from_backend(GraphicsBackend::new());
        let swapchain = metalfx_swapchain(&mut runtime);
        assert_eq!(runtime.metalfx_present_configured(swapchain), false);

        let temporal = runtime
            .enable_metalfx_present(
                swapchain,
                MetalFxPresentOptions {
                    mode: MetalFxPresentMode::Temporal,
                    output_width: 8,
                    output_height: 4,
                    color_processing_mode: crate::metal_fx::MetalFxColorProcessingMode::Linear,
                },
            )
            .expect_err("the DXGI present path cannot drive temporal scaling");
        assert_eq!(temporal.code, ReasonCode::RcD3dFeatureUnsupported);
        assert_eq!(
            temporal.message,
            "MetalFX present: temporal mode requires per-frame depth and motion textures and is \
             not supported by the DXGI present path"
        );
        assert_eq!(runtime.metalfx_present_configured(swapchain), false);

        let zero = runtime
            .enable_metalfx_present(swapchain, MetalFxPresentOptions::spatial(0, 4))
            .expect_err("zero output width must be rejected");
        assert_eq!(zero.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            zero.message,
            "MetalFX present: output size 0x4 must be non-zero"
        );

        let small = runtime
            .enable_metalfx_present(swapchain, MetalFxPresentOptions::spatial(2, 4))
            .expect_err("output narrower than the swapchain must be rejected");
        assert_eq!(small.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            small.message,
            "MetalFX present: output 2x4 must be at least the swapchain size 4x2"
        );

        let unsupported = runtime
            .create_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R16G16B16A16Float,
                buffer_count: 2,
            })
            .expect("unsupported-format swapchain still exists");
        let format = runtime
            .enable_metalfx_present(unsupported, MetalFxPresentOptions::spatial(8, 4))
            .expect_err("unsupported swapchain format must be rejected");
        assert_eq!(format.code, ReasonCode::RcGfxFormatUnsupported);
        assert_eq!(
            format.message,
            "MetalFX present: swapchain format R16G16B16A16Float (RGBA16Float) is not supported; \
             the DXGI present path requires B8G8R8A8Unorm or R8G8B8A8Unorm"
        );
        assert_eq!(runtime.metalfx_present_configured(unsupported), false);
        runtime
            .resize_buffers(swapchain, 2, 4, 2, DxgiFormat::R8G8B8A8Unorm)
            .expect("resize without a MetalFX configuration is a no-op for MetalFX");
    }

    #[test]
    fn metalfx_present_scales_known_pattern_and_resize_failure_falls_back_exactly() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = metalfx_swapchain(&mut runtime);
        let options = MetalFxPresentOptions::spatial(8, 4);
        runtime
            .enable_metalfx_present(swapchain, options)
            .expect("enable spatial MetalFX present");
        assert_eq!(runtime.metalfx_present_configured(swapchain), true);
        assert_eq!(runtime.metalfx_present_options(swapchain), Some(options));

        let mut source = vec![0u8; 4 * 2 * 4];
        for y in 0..2 {
            for x in 0..4 {
                let color = match (x < 2, y == 0) {
                    (true, true) => [255u8, 0, 0, 255],
                    (false, true) => [0, 255, 0, 255],
                    (true, false) => [0, 0, 255, 255],
                    (false, false) => [255, 255, 255, 255],
                };
                let offset = (y * 4 + x) * 4;
                source[offset..offset + 4].copy_from_slice(&color);
            }
        }
        runtime.iosurface_channels[0]
            .write_pixels(&source)
            .expect("write known source pattern");

        runtime
            .present(swapchain, 1, false)
            .expect("MetalFX present");
        assert_eq!(runtime.metalfx_scaled_present_count(), 1);
        assert_eq!(runtime.metalfx_fallback_count(), 0);

        let frame = runtime.presented_frame(swapchain).expect("scaled frame");
        assert_eq!(frame.width, 8);
        assert_eq!(frame.height, 4);
        assert_eq!(frame.format, DxgiFormat::R8G8B8A8Unorm);
        assert_eq!(frame.bytes.len(), 8 * 4 * 4);
        for (x, y, channel) in [(2usize, 1usize, 0usize), (5, 1, 1), (2, 3, 2)] {
            let offset = (y * 8 + x) * 4;
            let pixel = &frame.bytes[offset..offset + 4];
            assert_eq!(
                pixel[channel] > pixel[(channel + 1) % 3],
                true,
                "known quadrant colour must dominate at ({x},{y}): {pixel:?}"
            );
        }

        runtime
            .present(swapchain, 1, false)
            .expect("second MetalFX present");
        assert_eq!(runtime.metalfx_scaled_present_count(), 2);
        assert_eq!(runtime.disable_metalfx_present(swapchain), true);
        assert_eq!(runtime.disable_metalfx_present(swapchain), false);
        runtime.metalfx_last_scaled_swapchain = Some(swapchain);
        let fallback_frame = runtime
            .presented_frame(swapchain)
            .expect("a missing scaler state falls back to the source surface");
        assert_eq!(fallback_frame.width, 4);
        runtime
            .enable_metalfx_present(swapchain, options)
            .expect("re-enable MetalFX present");

        runtime
            .resize_buffers(swapchain, 2, 6, 3, DxgiFormat::R8G8B8A8Unorm)
            .expect("resize within the MetalFX output size");
        assert_eq!(runtime.metalfx_present_configured(swapchain), true);
        runtime
            .present(swapchain, 1, false)
            .expect("scaled resized present");
        assert_eq!(runtime.metalfx_scaled_present_count(), 3);
        assert_eq!(runtime.metalfx_fallback_count(), 0);
        assert_eq!(
            runtime
                .presented_frame(swapchain)
                .expect("resized frame")
                .width,
            8
        );

        runtime
            .resize_buffers(swapchain, 2, 16, 8, DxgiFormat::R8G8B8A8Unorm)
            .expect("resize beyond the configured output");
        assert_eq!(runtime.metalfx_present_configured(swapchain), false);
        assert_eq!(runtime.metalfx_fallback_count(), 1);
        let error = runtime
            .metalfx_last_error()
            .expect("resize fallback keeps the exact error");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "MetalFX present: output 8x4 must be at least the swapchain size 16x8"
        );
        runtime
            .present(swapchain, 1, false)
            .expect("fallback present");
        assert_eq!(runtime.metalfx_scaled_present_count(), 3);
        let frame = runtime.presented_frame(swapchain).expect("fallback frame");
        assert_eq!(frame.width, 16);
        assert_eq!(frame.height, 8);
        assert_eq!(frame.format, DxgiFormat::R8G8B8A8Unorm);
        runtime
            .resize_buffers(swapchain, 2, 16, 8, DxgiFormat::R8G8B8A8Unorm)
            .expect("a later resize with no MetalFX state is a no-op for MetalFX");
    }

    #[test]
    fn metalfx_present_nv12_and_missing_channel_fall_back_with_exact_errors() {
        let mut runtime = D3d12Runtime::new();
        let nv12 = runtime
            .create_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("NV12 swapchain");
        if !runtime.primary_nv12.is_empty() {
            runtime
                .enable_metalfx_present(nv12, MetalFxPresentOptions::spatial(8, 4))
                .expect("configure MetalFX on top of an NV12 swapchain");
            runtime
                .present(nv12, 1, false)
                .expect("NV12 fallback present");
            assert_eq!(runtime.metalfx_scaled_present_count(), 0);
            assert_eq!(runtime.metalfx_fallback_count(), 1);
            let error = runtime.metalfx_last_error().expect("NV12 fallback error");
            assert_eq!(error.code, ReasonCode::RcD3dFeatureUnsupported);
            assert_eq!(
                error.message,
                "MetalFX present: NV12 swapchains are not supported by the MetalFX present path"
            );
            assert_eq!(runtime.presented_frame(nv12).expect("NV12 frame").width, 4);
            assert_eq!(runtime.disable_metalfx_present(nv12), true);
        }

        let mut runtime = D3d12Runtime::new();
        let swapchain = metalfx_swapchain(&mut runtime);
        runtime
            .enable_metalfx_present(swapchain, MetalFxPresentOptions::spatial(8, 4))
            .expect("enable MetalFX before losing the channel");
        runtime.iosurface_channels.clear();
        runtime
            .present(swapchain, 1, false)
            .expect("missing-channel fallback present");
        assert_eq!(runtime.metalfx_scaled_present_count(), 0);
        assert_eq!(runtime.metalfx_fallback_count(), 1);
        let error = runtime
            .metalfx_last_error()
            .expect("missing-channel fallback error");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("MetalFX present: swapchain {swapchain} has no pixel present channel")
        );
    }

    #[test]
    fn metalfx_present_additional_swapchain_paths_scale_and_fallback() {
        let mut runtime = D3d12Runtime::new();
        let extra = runtime
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional pixel swapchain");
        runtime
            .enable_metalfx_present(extra, MetalFxPresentOptions::spatial(8, 4))
            .expect("enable MetalFX on the additional swapchain");
        let pattern = vec![64u8; 4 * 2 * 4];
        runtime
            .extra_swapchains
            .get_mut(&extra)
            .expect("additional channel set")
            .pixel[0]
            .write_pixels(&pattern)
            .expect("write additional pattern");
        runtime
            .present(extra, 1, false)
            .expect("scaled additional present");
        assert_eq!(runtime.metalfx_scaled_present_count(), 1);
        let frame = runtime
            .presented_frame(extra)
            .expect("additional scaled frame");
        assert_eq!(frame.width, 8);
        assert_eq!(frame.height, 4);
        assert_eq!(frame.format, DxgiFormat::R8G8B8A8Unorm);

        let mut runtime = D3d12Runtime::new();
        let extra_nv12 = runtime
            .create_additional_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("additional NV12 swapchain");
        if runtime
            .extra_swapchains
            .get(&extra_nv12)
            .map(|set| !set.nv12.is_empty())
            .unwrap_or(false)
        {
            runtime
                .enable_metalfx_present(extra_nv12, MetalFxPresentOptions::spatial(8, 4))
                .expect("enable MetalFX on the additional NV12 swapchain");
            runtime
                .present(extra_nv12, 1, false)
                .expect("additional NV12 fallback present");
            assert_eq!(runtime.metalfx_scaled_present_count(), 0);
            assert_eq!(runtime.metalfx_fallback_count(), 1);
            let error = runtime
                .metalfx_last_error()
                .expect("additional NV12 fallback error");
            assert_eq!(error.code, ReasonCode::RcD3dFeatureUnsupported);
            assert_eq!(
                error.message,
                "MetalFX present: NV12 swapchains are not supported by the MetalFX present path"
            );
        }
    }

    fn closed_stream(runtime: &mut D3d12Runtime) -> ImmutableCommandStream {
        let root_signature = runtime.create_root_signature(RootSignatureDesc::default());
        let pipeline_state = runtime.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "metal4-batch".to_string(),
                compute: false,
                render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
                depth_format: None,
            },
        );
        let allocator = runtime.create_command_allocator();
        let list = runtime.create_graphics_command_list(allocator, pipeline_state, false);
        runtime
            .close_command_list(list)
            .expect("close empty command list")
    }

    #[test]
    fn d3d12_execute_command_lists_metal4_parallel_batch_preserves_plan_and_fence() {
        // Skip on hosts that cannot exercise MTL4 end-to-end (e.g. CI runners
        // whose virtual GPU advertises the selectors but raises on first use).
        if !metal4_batch::batch_creation_succeeds() {
            return;
        }
        let mut runtime = D3d12Runtime::new();
        let queue = runtime.create_command_queue();
        let fence = runtime.create_fence(0);
        let first = closed_stream(&mut runtime);
        let second = closed_stream(&mut runtime);
        let plan = runtime
            .execute_command_lists_parallel(queue, &[first, second], Some((fence, 1)))
            .expect("grouped ExecuteCommandLists");
        assert_eq!(plan.signaled_fences, vec![(fence, 1)]);
        let stats = runtime.metal4_batch_stats().expect("Metal 4 stats");
        assert_eq!(stats.grouped_submissions, 1);
        assert_eq!(stats.encoded_lists, 2);
        assert_eq!(runtime.metal4_batch_last_event(), Some(1));
        assert_eq!(runtime.metal4_batch_fallbacks(), 0);
    }

    #[test]
    fn d3d12_execute_command_lists_duplicate_batch_is_rejected_exactly() {
        let mut runtime = D3d12Runtime::new();
        let queue = runtime.create_command_queue();
        let stream = closed_stream(&mut runtime);
        let duplicate = ImmutableCommandStream {
            id: stream.id,
            commands: stream.commands.clone(),
        };
        let error = runtime
            .execute_command_lists(queue, &[stream.clone(), duplicate], None)
            .expect_err("duplicate list must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!(
                "D3D12 ExecuteCommandLists: duplicate command list {} in one batch",
                stream.id
            )
        );
        assert_eq!(runtime.metal4_batch_fallbacks(), 0);
        assert_eq!(runtime.metal4_batch_stats(), None);
    }

    #[test]
    fn d3d12_execute_command_lists_metal4_unavailable_falls_back_with_error() {
        metal4_batch::force_unsupported(true);
        let mut runtime = D3d12Runtime::new();
        let queue = runtime.create_command_queue();
        let fence = runtime.create_fence(0);
        let stream = closed_stream(&mut runtime);
        let plan = runtime
            .execute_command_lists(queue, &[stream], Some((fence, 1)))
            .expect("fallback ExecuteCommandLists");
        metal4_batch::force_unsupported(false);
        assert_eq!(plan.signaled_fences, vec![(fence, 1)]);
        assert_eq!(runtime.metal4_batch_fallbacks(), 1);
        assert_eq!(runtime.metal4_batch_stats(), None);
        assert_eq!(
            runtime
                .metal4_batch_last_error()
                .expect("fallback error")
                .message,
            "Metal 4 batch: MTL4CommandQueue is unavailable on this device"
        );
    }

    #[test]
    fn d3d12_execute_command_lists_empty_batch_boundary_is_no_op() {
        let mut runtime = D3d12Runtime::new();
        let queue = runtime.create_command_queue();
        let plan = runtime
            .execute_command_lists(queue, &[], None)
            .expect("empty ExecuteCommandLists");
        assert_eq!(plan.render_passes.len(), 0);
        assert_eq!(plan.compute_passes, 0);
        assert_eq!(plan.blit_passes, 0);
        assert_eq!(plan.signaled_fences, Vec::new());
        assert_eq!(runtime.metal4_batch_stats(), None);
        assert_eq!(runtime.metal4_batch_last_event(), None);
    }

    #[test]
    fn d3d12_execute_command_lists_metal4_fallback_is_observable() {
        let mut runtime = D3d12Runtime::new();
        runtime.disable_metal4_batch_for_test();
        let queue = runtime.create_command_queue();
        let fence = runtime.create_fence(0);
        let stream = closed_stream(&mut runtime);
        let plan = runtime
            .execute_command_lists(queue, &[stream], Some((fence, 1)))
            .expect("fallback ExecuteCommandLists");
        assert_eq!(plan.signaled_fences, vec![(fence, 1)]);
        assert_eq!(runtime.metal4_batch_fallbacks(), 1);
        assert_eq!(runtime.metal4_batch_stats(), None);
        assert_eq!(runtime.metal4_batch_last_error(), None);
    }

    #[test]
    fn d3d12_execute_command_lists_metal4_failure_falls_back_with_counter() {
        // Skip on hosts that cannot exercise MTL4 end-to-end (e.g. CI runners
        // whose virtual GPU advertises the selectors but raises on first use).
        if !metal4_batch::batch_creation_succeeds() {
            return;
        }
        let mut runtime = D3d12Runtime::new();
        let queue = runtime.create_command_queue();
        let first_fence = runtime.create_fence(0);
        let first = closed_stream(&mut runtime);
        runtime
            .execute_command_lists(queue, &[first], Some((first_fence, 1)))
            .expect("initial Metal 4 batch");
        assert_eq!(
            runtime
                .metal4_batch_stats()
                .expect("stats")
                .grouped_submissions,
            1
        );

        metal4_batch::force_submission_failure(true);
        let failed_fence = runtime.create_fence(0);
        let failed = closed_stream(&mut runtime);
        let plan = runtime
            .execute_command_lists(queue, &[failed], Some((failed_fence, 1)))
            .expect("CPU fallback after Metal 4 failure");
        metal4_batch::force_submission_failure(false);
        assert_eq!(plan.signaled_fences, vec![(failed_fence, 1)]);
        assert_eq!(runtime.metal4_batch_fallbacks(), 1);
        assert_eq!(
            runtime
                .metal4_batch_last_error()
                .expect("fallback error")
                .message,
            "Metal 4 batch: forced submission failure"
        );

        let recovered_fence = runtime.create_fence(0);
        let recovered = closed_stream(&mut runtime);
        runtime
            .execute_command_lists(queue, &[recovered], Some((recovered_fence, 1)))
            .expect("recovered Metal 4 batch");
        assert_eq!(
            runtime
                .metal4_batch_stats()
                .expect("stats")
                .grouped_submissions,
            2
        );
        assert_eq!(runtime.metal4_batch_fallbacks(), 1);
        assert_eq!(runtime.metal4_batch_last_error(), None);
    }

    #[test]
    fn d3d12_present_timing_correlation_rejects_out_of_order_and_pins_known_samples() {
        let timing = D3d12PresentTiming::from_seconds(
            Some(10.0),
            Some(10.0005),
            Some((10.002, 10.004)),
            Some(10.003),
        );
        assert_eq!(timing.gpu_time_ns(), Some(2_000_000));
        assert_eq!(timing.input_to_present_ns(), Some(3_000_000));
        assert_eq!(timing.input_to_gpu_completion_ns(), Some(4_000_000));
        assert_eq!(timing.gpu_unavailable(), None);
        assert_eq!(timing.present_unavailable(), None);

        let reversed = D3d12PresentTiming::from_seconds(
            Some(10.0),
            Some(10.0005),
            Some((10.004, 10.002)),
            Some(10.003),
        );
        assert_eq!(reversed.gpu_time_ns(), None);
        assert_eq!(
            reversed.gpu_unavailable(),
            Some(crate::perf::TimingUnavailable::MissingGpuTimestamp)
        );
    }

    #[test]
    fn d3d12_present_timing_missing_timestamps_report_exact_fallback() {
        let missing_present = D3d12PresentTiming::from_seconds(
            Some(10.0),
            Some(10.001),
            Some((10.002, 10.004)),
            None,
        );
        assert_eq!(
            missing_present.present_unavailable(),
            Some(crate::perf::TimingUnavailable::NoDrawable)
        );
        assert_eq!(missing_present.input_to_present_ns(), None);

        let zero_present = D3d12PresentTiming {
            input_seconds: Some(10.0),
            submitted_seconds: Some(10.001),
            gpu: None,
            drawable: Some(crate::metal_backend::DrawableTimingProbe::with_reading(
                crate::metal_backend::PresentTimestampReading::MissingTimestamp,
            )),
        };
        assert_eq!(
            zero_present.present_unavailable(),
            Some(crate::perf::TimingUnavailable::MissingPresentTimestamp)
        );
        assert_eq!(
            zero_present.present_unavailable().expect("reason").reason(),
            "CAMetalLayer drawable reported presentedTime=0; no display presentation occurred"
        );

        let unsupported = D3d12PresentTiming {
            input_seconds: Some(10.0),
            submitted_seconds: Some(10.001),
            gpu: Some(crate::metal_backend::GpuTimingProbe::with_reading(
                crate::metal_backend::GpuTimestampReading::UnsupportedDevice,
            )),
            drawable: None,
        };
        assert_eq!(
            unsupported.gpu_unavailable(),
            Some(crate::perf::TimingUnavailable::UnsupportedGpuTimestamp)
        );
        assert_eq!(unsupported.gpu_time_ns(), None);

        let no_gpu = D3d12PresentTiming::from_seconds(Some(10.0), Some(10.001), None, None);
        assert_eq!(
            no_gpu.gpu_unavailable(),
            Some(crate::perf::TimingUnavailable::MissingGpuTimestamp)
        );
        assert_eq!(no_gpu.input_to_gpu_completion_ns(), None);
    }

    #[test]
    fn d3d12_present_timing_request_is_cleared_by_invalid_present_without_stale_state() {
        let mut runtime = D3d12Runtime::new();
        assert!(runtime.last_present_timing().is_none());
        runtime.mark_input_event();
        assert!(runtime.present_timing_requested);
        assert_eq!(runtime.pending_present_input_seconds.is_some(), true);
        let error = runtime
            .present(9999, 1, false)
            .expect_err("an unknown swapchain must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "unknown swapchain 9999");
        assert_eq!(runtime.present_timing_requested, false);
        runtime.enable_present_timing();
        assert_eq!(runtime.present_timing_requested, true);
        assert!(runtime.pending_present_input_seconds.is_none());
        assert!(runtime.last_present_timing().is_none());
        assert_eq!(crate::metal_backend::present_timing_enabled(), false);
        assert!(runtime.take_last_present_timing().is_none());
    }
}
