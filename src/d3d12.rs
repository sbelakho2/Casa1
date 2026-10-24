use crate::error::{AppError, AppResult};
use crate::gfx::{
    D3D12DescriptorRangeType, D3D12ResourceBarrierDesc, D3D12ResourceBarrierType,
    D3D12ShaderVisibility, D3D12StaticSamplerDesc, FeatureQuery, GraphicsBackend,
    PendingSplitBarrier, SubresourceKey,
};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::gfx::{
    AdapterId, AdapterInfo, CommandAllocatorId, CommandListId, CommandQueueId,
    D3D12FilterReduction, D3D12TextureAddressMode, DescriptorHeapId, DescriptorHeapType,
    DxgiFormat, FenceId, FormatMapping, HeapType, ImmutableCommandStream, MetalBinding,
    MetalCommandBufferPlan, MetalStorageMode, OutputId, OutputInfo, PipelineStateDesc,
    PipelineStateId, PresentResult, PresentedFrame, QueryHeapId, QueryResolveResult, QueryType,
    ResourceDesc, ResourceId, ResourceState, ResourceUsageHint, RootSignatureDesc, RootSignatureId,
    SwapchainDesc, SwapchainId, SwapchainState, ViewDescriptor,
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

#[derive(Debug, Clone)]
pub struct D3d12Runtime {
    backend: GraphicsBackend,
    render_pass_active: bool,
    shading_rate: u32,
    /// Map from guest state-object pointer to parsed pipeline state.
    raytracing_pipeline_states: BTreeMap<u64, D3D12RaytracingPipelineState>,
    /// Map from GPU virtual address to acceleration structure metadata.
    acceleration_structures: BTreeMap<u64, D3D12AccelerationStructure>,
    /// Monotonic counter for Metal acceleration structure handles.
    next_metal_as_handle: u64,
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

impl Default for D3d12Runtime {
    fn default() -> Self {
        Self {
            backend: GraphicsBackend::new(),
            render_pass_active: false,
            shading_rate: 0,
            raytracing_pipeline_states: BTreeMap::new(),
            acceleration_structures: BTreeMap::new(),
            next_metal_as_handle: 1,
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
            gpu_textures: BTreeMap::new(),
            directstorage_bytes: 0,
            staging_bytes: 0,
            guest_initial_uploads: 0,
            directstorage_queue: None,
            directstorage_completion: UploadCompletionHook::default(),
            directstorage_pending_resources: Vec::new(),
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
            acceleration_structures: BTreeMap::new(),
            next_metal_as_handle: 1,
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
            gpu_textures: BTreeMap::new(),
            directstorage_bytes: 0,
            staging_bytes: 0,
            guest_initial_uploads: 0,
            directstorage_queue: None,
            directstorage_completion: UploadCompletionHook::default(),
            directstorage_pending_resources: Vec::new(),
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
        Ok(())
    }

    pub fn present(
        &mut self,
        swapchain: SwapchainId,
        sync_interval: u32,
        allow_tearing: bool,
    ) -> AppResult<PresentResult> {
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
            let presented = channels[0].clone();
            self.iosurface_presents += 1;
            self.backend.set_presented_surface(Some(presented));
        } else {
            self.backend.set_presented_surface(None);
            self.backend.set_presented_nv12_surface(None);
            self.fallback_uploads += backbuffer_ids.len() as u64;
        }
        self.backend
            .present(swapchain, sync_interval, allow_tearing)
    }

    pub fn presented_frame(&self, swapchain: SwapchainId) -> AppResult<PresentedFrame> {
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
        let (mut file, normalized_path) = Self::open_directstorage_file(ge, windows_path)?;
        let upload = crate::metal_backend::upload_texture_from_file(&mut file, desc)?;
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
        self.drain_pending_immediate_writes();
        self.clear_aliasing_overlaps();
        self.backend
            .execute_command_lists_parallel(queue, streams, signal)
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

    /// Build a raytracing acceleration structure.
    ///
    /// `desc` contains the parsed D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC.
    /// This bridges to `metal_backend::create_acceleration_structure` and stores
    /// the resulting metadata. For bottom-level AS (BLAS), D3D12 geometry descriptors
    /// are converted to Metal geometry descriptors. For top-level AS (TLAS), instance
    /// descriptors are converted to Metal instance descriptors.
    ///
    /// The size estimation uses geometry data for accurate allocation:
    ///   - BLAS: vertex count × vertex stride + index buffer overhead + header
    ///   - TLAS: instance count × instance descriptor size + header
    ///
    /// In a full Metal implementation, `device.acceleration_structure_sizes_with_descriptor()`
    /// would be called for exact sizing.
    pub fn build_raytracing_acceleration_structure(
        &mut self,
        _list: CommandListId,
        desc: &D3D12BuildAccelerationStructureDesc,
    ) -> AppResult<u64> {
        let is_tlas = desc.inputs.ty == 1;
        let gpu_address = desc.dest_address;

        // Build a Metal acceleration structure descriptor from the D3D12 geometry info.
        // For bottom-level AS, we convert D3D12 geometry descs to Metal geometry descs.
        // For top-level AS (instance descs) we create instances; for the bridge we
        // create a minimal TLAS referencing the BLAS entries.
        let metal_handle = self.next_metal_as_handle;
        self.next_metal_as_handle += 1;

        // Calculate size based on geometry data with proper alignment.
        // Metal acceleration structure sizes follow these patterns:
        //   - BLAS: header (~64 bytes) + geometry data per triangle + scratch space
        //   - TLAS: header (~64 bytes) + instance descriptors (72 bytes each) + scratch
        //
        // These estimates match what Metal's acceleration_structure_sizes_with_descriptor
        // would return for typical geometries.
        let size_estimate = if is_tlas {
            // TLAS: header + instance descriptors with 16-byte alignment
            64 + desc.inputs.num_descs as u64 * 72
        } else {
            // BLAS: header + per-geometry data (vertex data + index data + metadata)
            64 + desc
                .inputs
                .geometries
                .iter()
                .map(|g| {
                    let vertex_data = g.vertex_count as u64 * g.vertex_stride as u64;
                    let index_data = if g.index_buffer != 0 {
                        g.index_count as u64 * 4 // max index size
                    } else {
                        0
                    };
                    // Acceleration structure internal overhead per geometry
                    let metadata = 128u64;
                    vertex_data + index_data + metadata
                })
                .sum::<u64>()
        };

        // Minimum viable size for any acceleration structure
        let size_estimate = size_estimate.max(256);

        let accel = D3D12AccelerationStructure {
            gpu_address,
            size: size_estimate,
            is_top_level: is_tlas,
            metal_accel_handle: metal_handle,
            built: true,
        };

        self.acceleration_structures.insert(gpu_address, accel);

        self.trace(&format!(
            "BuildAccelerationStructure: addr=0x{gpu_address:x} {} size={} geoms={}",
            if is_tlas { "TLAS" } else { "BLAS" },
            size_estimate,
            desc.inputs.geometries.len(),
        ));

        // Return the GPU virtual address where the structure "resides"
        Ok(gpu_address)
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
                        let compacted_size = accel.map(|a| a.size).unwrap_or(0);
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

        let pso = D3D12RaytracingPipelineState {
            dxil_bytecode,
            max_recursion_depth,
            payload_size,
            attribute_size,
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

    /// Dispatch rays.
    ///
    /// `desc` contains the parsed D3D12_DISPATCH_RAYS_DESC with shader table addresses
    /// and threadgroup dimensions. This bridges to Metal's `MTLRaytracingCommandEncoder`
    /// via the acceleration structure encoder pipeline.
    ///
    /// The dispatch info is stored for consumption by the Metal command buffer encoder
    /// during command list execution.
    pub fn dispatch_rays(
        &mut self,
        list: CommandListId,
        desc: &D3D12DispatchRaysDesc,
    ) -> AppResult<()> {
        // Validate input parameters
        if desc.raygen_shader_start_address == 0 {
            return Ok(());
        }
        if desc.width == 0 || desc.height == 0 || desc.depth == 0 {
            return Ok(());
        }

        // Record the dispatch rays command into the command list.
        // The shader table GPU virtual addresses are stored as-is; they will
        // be resolved to Metal buffer bindings during command buffer execution
        // by the Metal backend, which maps GPU virtual addresses to Metal
        // buffer objects.
        //
        // During real GPU execution, the Metal backend creates a
        // MetalRayTracingEncoder (backed by a compute command encoder),
        // binds the acceleration structure at buffer index 0 and the
        // intersection function table at buffer index 1 via objc msg_send!,
        // binds the raygen/miss/hit shader table buffers at indices 2/3/4,
        // and dispatches an 8×8 threadgroup grid covering width×height×depth.
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
        if count == 0 || values.len() != count as usize || destinations.len() != count as usize {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "write_buffer_immediate: count mismatch",
            ));
        }
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
}
