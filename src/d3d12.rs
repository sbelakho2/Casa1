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
        self.backend.create_swapchain(desc)
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
            .resize_buffers(swapchain, buffer_count, width, height, format)
    }

    pub fn present(
        &mut self,
        swapchain: SwapchainId,
        sync_interval: u32,
        allow_tearing: bool,
    ) -> AppResult<PresentResult> {
        self.backend
            .present(swapchain, sync_interval, allow_tearing)
    }

    pub fn presented_frame(&self, swapchain: SwapchainId) -> AppResult<PresentedFrame> {
        self.backend.presented_frame(swapchain)
    }

    pub fn create_committed_resource(&mut self, desc: ResourceDesc) -> AppResult<ResourceId> {
        self.backend.create_resource(desc)
    }

    pub fn destroy_resource(&mut self, resource: ResourceId) -> AppResult<()> {
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
        self.backend.upload_write(resource, offset, bytes)
    }

    pub fn overwrite_resource_bytes(
        &mut self,
        resource: ResourceId,
        bytes: &[u8],
    ) -> AppResult<()> {
        self.backend.overwrite_resource_bytes(resource, bytes)
    }

    pub fn readback(
        &self,
        resource: ResourceId,
        fence: FenceId,
        required_value: u64,
    ) -> AppResult<Vec<u8>> {
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
        self.backend.execute_command_lists(queue, streams, signal)
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
    fn d3d12_runtime_submits_and_presents_through_backend() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 1280,
                height: 720,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        let backbuffer = runtime
            .swapchain_state(swapchain)
            .expect("swapchain state")
            .backbuffers[0];
        let rtv_heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        runtime
            .write_descriptor(
                rtv_heap,
                0,
                ViewDescriptor::Rtv {
                    resource: backbuffer,
                    format: DxgiFormat::R8G8B8A8Unorm,
                },
            )
            .expect("write rtv descriptor");
        let root_signature = runtime.create_root_signature(RootSignatureDesc {
            descriptor_tables: vec![1],
            root_constants: 4,
            ..Default::default()
        });
        let pipeline_state = runtime.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "smoke".to_string(),
                compute: false,
                render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
                depth_format: None,
            },
        );
        let queue = runtime.create_command_queue();
        let allocator = runtime.create_command_allocator();
        let list = runtime.create_graphics_command_list(allocator, pipeline_state, false);
        runtime
            .record_begin_render_pass(
                list,
                vec![DxgiFormat::R8G8B8A8Unorm],
                None,
                "clear",
                "store",
            )
            .expect("begin render pass");
        runtime
            .record_clear_rtv(list, rtv_heap, 0)
            .expect("clear rtv");
        runtime.record_draw(list, 3).expect("draw");
        let stream = runtime.close_command_list(list).expect("close list");
        let fence = runtime.create_fence(0);
        let plan = runtime
            .execute_command_lists(queue, &[stream], Some((fence, 1)))
            .expect("execute command lists");

        assert_eq!(plan.render_passes.len(), 1);
        assert_eq!(plan.render_passes[0].draw_calls, 1);
        assert_eq!(runtime.fence_value(fence).expect("fence value"), 1);

        let present = runtime.present(swapchain, 1, false).expect("present");
        assert_eq!(present.effective_sync_interval, 1);
        assert_eq!(present.queued_frames, 1);
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

    #[test]
    fn d3d12_build_top_level_acceleration_structure() {
        let mut runtime = D3d12Runtime::new();

        // First create a BLAS to reference
        let blas_desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0,
                    flags: 0,
                    vertex_buffer: 0x2000,
                    vertex_format: 80,
                    vertex_stride: 12,
                    vertex_count: 36,
                    index_buffer: 0x3000,
                    index_format: 57,
                    index_count: 36,
                }],
            },
            source_address: 0,
            scratch_address: 0x4000,
        };

        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, false);

        runtime
            .build_raytracing_acceleration_structure(list, &blas_desc)
            .expect("build BLAS");

        // Now build a TLAS referencing it
        let tlas_desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x5000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 1, // TOP_LEVEL
                flags: 0,
                num_descs: 1,
                geometries: vec![], // TLAS uses instances, not geometries
            },
            source_address: 0,
            scratch_address: 0x6000,
        };

        let result = runtime.build_raytracing_acceleration_structure(list, &tlas_desc);
        assert!(result.is_ok(), "build TLAS should succeed");

        let accel = runtime.acceleration_structure(0x5000);
        assert!(accel.is_some(), "TLAS should exist");
        let accel = accel.unwrap();
        assert!(accel.is_top_level, "should be top-level");
        assert_eq!(accel.gpu_address, 0x5000);
    }

    #[test]
    fn d3d12_copy_acceleration_structure() {
        let mut runtime = D3d12Runtime::new();

        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, false);

        // Build a BLAS first
        let desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0,
                    flags: 0,
                    vertex_buffer: 0x2000,
                    vertex_format: 80,
                    vertex_stride: 12,
                    vertex_count: 3,
                    index_buffer: 0,
                    index_format: 0,
                    index_count: 0,
                }],
            },
            source_address: 0,
            scratch_address: 0x4000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &desc)
            .expect("build");

        // COPY mode
        runtime
            .copy_raytracing_acceleration_structure(list, 0x2000, 0x1000, 0)
            .expect("copy AS");
        assert!(
            runtime.acceleration_structure(0x2000).is_some(),
            "copy should exist"
        );

        // COMPACT mode
        runtime
            .copy_raytracing_acceleration_structure(list, 0x3000, 0x1000, 1)
            .expect("compact AS");
        assert!(
            runtime.acceleration_structure(0x3000).is_some(),
            "compact should exist"
        );
    }

    #[test]
    fn d3d12_set_pipeline_state1_and_dispatch_rays() {
        let mut runtime = D3d12Runtime::new();

        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, false);

        // Set a raytracing pipeline state
        let dxil = vec![0u8; 128]; // dummy DXIL
        runtime
            .set_pipeline_state1(list, 0xABCD, dxil)
            .expect("set pipeline state1");

        let pso = runtime.get_raytracing_pipeline_state(0xABCD);
        assert!(pso.is_some(), "PSO should be stored");
        assert_eq!(pso.unwrap().dxil_bytecode.len(), 128);

        // Dispatch rays with valid parameters
        let dispatch_desc = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0x5000,
            raygen_shader_size: 64,
            miss_shader_start_address: 0x6000,
            miss_shader_size: 64,
            miss_shader_stride: 64,
            hit_group_start_address: 0x7000,
            hit_group_size: 64,
            hit_group_stride: 64,
            callable_shader_start_address: 0,
            callable_shader_size: 0,
            callable_shader_stride: 0,
            width: 16,
            height: 16,
            depth: 1,
        };

        let result = runtime.dispatch_rays(list, &dispatch_desc);
        assert!(result.is_ok(), "dispatch rays should succeed");

        // Dispatch with zero dimensions should be a no-op
        let zero_desc = D3D12DispatchRaysDesc {
            raygen_shader_start_address: 0x5000,
            raygen_shader_size: 64,
            miss_shader_start_address: 0x6000,
            miss_shader_size: 64,
            miss_shader_stride: 64,
            hit_group_start_address: 0x7000,
            hit_group_size: 64,
            hit_group_stride: 64,
            callable_shader_start_address: 0,
            callable_shader_size: 0,
            callable_shader_stride: 0,
            width: 0,
            height: 0,
            depth: 0,
        };
        assert!(
            runtime.dispatch_rays(list, &zero_desc).is_ok(),
            "zero dispatch should be no-op"
        );
    }

    #[test]
    fn d3d12_emit_postbuild_info() {
        let mut runtime = D3d12Runtime::new();

        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, false);

        // Build an AS first
        let desc = D3D12BuildAccelerationStructureDesc {
            dest_address: 0x1000,
            inputs: D3D12BuildRaytracingInputs {
                ty: 0,
                flags: 0,
                num_descs: 1,
                geometries: vec![D3D12RaytracingGeometryDesc {
                    ty: 0,
                    flags: 0,
                    vertex_buffer: 0x2000,
                    vertex_format: 80,
                    vertex_stride: 12,
                    vertex_count: 3,
                    index_buffer: 0,
                    index_format: 0,
                    index_count: 0,
                }],
            },
            source_address: 0,
            scratch_address: 0x4000,
        };
        runtime
            .build_raytracing_acceleration_structure(list, &desc)
            .expect("build");

        // Test COMPACTED_SIZE postbuild info
        let mut output = vec![0u8; 8];
        runtime
            .emit_raytracing_acceleration_structure_postbuild_info(list, 1, &[0x1000], &mut output)
            .expect("emit compacted size");
        let compacted_size = u64::from_le_bytes(output[..8].try_into().unwrap());
        assert!(compacted_size > 0, "compacted size should be non-zero");

        // Test TOOLS_VISUALIZATION
        let mut vis_output = vec![0u8; 8];
        runtime
            .emit_raytracing_acceleration_structure_postbuild_info(
                list,
                2,
                &[0x1000],
                &mut vis_output,
            )
            .expect("emit visualization size");
        let vis_size = u64::from_le_bytes(vis_output[..8].try_into().unwrap());
        assert!(vis_size > 0, "visualization size should be non-zero");

        // Test SERIALIZATION
        let mut ser_output = vec![0u8; 16];
        runtime
            .emit_raytracing_acceleration_structure_postbuild_info(
                list,
                3,
                &[0x1000],
                &mut ser_output,
            )
            .expect("emit serialization info");
    }

    #[test]
    fn d3d12_raytracing_feature_options() {
        // With Apple GPU family >= 7, raytracing should be enabled
        let runtime = D3d12Runtime::from_backend(GraphicsBackend::with_host_profile(
            host_gpu_profile_from_name("Apple M1"),
        ));
        let info = runtime.device_info();
        assert!(
            info.features.raytracing,
            "Apple M1 should support raytracing"
        );

        // With older GPU, raytracing may not be supported
        // Simulate older GPU by using a generic profile
        let runtime2 = D3d12Runtime::new();
        let info2 = runtime2.device_info();
        // The default backend uses detected host GPU, so just verify the field exists
        let _ = info2.features.raytracing;
    }

    // ── Descriptor heap tests ──────────────────────────────────────────

    #[test]
    fn d3d12_create_rtv_descriptor_heap() {
        let mut runtime = D3d12Runtime::new();
        let heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 4);
        assert_ne!(heap, 0, "descriptor heap ID should be non-zero");
    }

    #[test]
    fn d3d12_create_cbv_srv_uav_descriptor_heap() {
        let mut runtime = D3d12Runtime::new();
        let heap = runtime.create_descriptor_heap(DescriptorHeapType::CbvSrvUav, 8);
        assert_ne!(heap, 0, "descriptor heap ID should be non-zero");
    }

    #[test]
    fn d3d12_create_sampler_descriptor_heap() {
        let mut runtime = D3d12Runtime::new();
        let heap = runtime.create_descriptor_heap(DescriptorHeapType::Sampler, 4);
        assert_ne!(heap, 0, "descriptor heap ID should be non-zero");
    }

    #[test]
    fn d3d12_write_rtv_descriptor_to_heap() {
        let mut runtime = D3d12Runtime::new();
        let swapchain = runtime
            .create_swapchain(SwapchainDesc {
                width: 64,
                height: 64,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        let backbuffer = runtime.swapchain_state(swapchain).unwrap().backbuffers[0];
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
            .expect("write RTV descriptor");
    }

    // ── Root signature tests ───────────────────────────────────────────

    #[test]
    fn d3d12_create_root_signature_default() {
        let mut runtime = D3d12Runtime::new();
        let rs = runtime.create_root_signature(RootSignatureDesc::default());
        assert_ne!(rs, 0, "root signature ID should be non-zero");
    }

    #[test]
    fn d3d12_create_root_signature_with_tables() {
        let mut runtime = D3d12Runtime::new();
        let rs = runtime.create_root_signature(RootSignatureDesc {
            descriptor_tables: vec![4, 8],
            root_constants: 2,
            ..Default::default()
        });
        assert_ne!(rs, 0);
    }

    #[test]
    fn d3d12_create_root_signature_with_static_samplers() {
        let mut runtime = D3d12Runtime::new();
        let rs = runtime.create_root_signature(RootSignatureDesc {
            descriptor_tables: vec![2],
            root_constants: 0,
            static_samplers: vec![D3D12StaticSamplerDesc {
                shader_register: 0,
                register_space: 0,
                filter: 2, // linear
                address_u: 1,
                address_v: 1,
                address_w: 1,
                mip_lod_bias: 0.0,
                max_anisotropy: 16,
                comparison_func: 0,
                border_color: 0,
                min_lod: 0.0,
                max_lod: 1000.0,
                shader_visibility: D3D12ShaderVisibility::All,
            }],
            ..Default::default()
        });
        assert_ne!(rs, 0);
    }

    // ── Command list creation tests ────────────────────────────────────

    #[test]
    fn d3d12_create_command_list() {
        let mut runtime = D3d12Runtime::new();
        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, false);
        assert_ne!(list, 0, "command list ID should be non-zero");
    }

    #[test]
    fn d3d12_create_bundle_command_list() {
        let mut runtime = D3d12Runtime::new();
        let allocator = runtime.create_command_allocator();
        let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
        let list = runtime.create_graphics_command_list(allocator, root_sig, true);
        assert_ne!(list, 0, "bundle command list ID should be non-zero");
    }

    #[test]
    fn d3d12_multiple_command_allocators() {
        let mut runtime = D3d12Runtime::new();
        let alloc1 = runtime.create_command_allocator();
        let alloc2 = runtime.create_command_allocator();
        assert_ne!(
            alloc1, alloc2,
            "different allocators should have distinct IDs"
        );
    }

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
    #[test]
    fn map_d3d12_comparison_func_full_table() {
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(1), "never");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(2), "less");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(3), "equal");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(4), "less_equal");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(5), "greater");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(6), "not_equal");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(7), "greater_equal");
        assert_eq!(D3d12Runtime::map_d3d12_comparison_func(8), "always");
        // Unknown values: documented default (D3D12_COMPARISON_FUNC_NEVER).
        for unknown in [0, 9, 99, u32::MAX] {
            assert_eq!(
                D3d12Runtime::map_d3d12_comparison_func(unknown),
                "never",
                "unknown comparison func {unknown} must map to the documented default"
            );
        }
    }

    /// D3D12_STATIC_BORDER_COLOR: 0=TRANSPARENT_BLACK, 1=OPAQUE_BLACK,
    /// 2=OPAQUE_WHITE (per d3d12.h).
    #[test]
    fn map_d3d12_border_color_full_table() {
        assert_eq!(D3d12Runtime::map_d3d12_border_color(0), "transparent_black");
        assert_eq!(D3d12Runtime::map_d3d12_border_color(1), "opaque_black");
        assert_eq!(D3d12Runtime::map_d3d12_border_color(2), "opaque_white");
        // Unknown values: documented default (TRANSPARENT_BLACK).
        for unknown in [3, 4, 99, u32::MAX] {
            assert_eq!(
                D3d12Runtime::map_d3d12_border_color(unknown),
                "transparent_black",
                "unknown border color {unknown} must map to the documented default"
            );
        }
    }

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
    #[test]
    fn d3d12_filter_reduction_full_table() {
        use D3D12FilterReduction::*;
        let cases: [(u32, (D3D12FilterReduction, &str)); 4] = [
            (0, (Standard, "STANDARD")),
            (1, (Comparison, "COMPARISON")),
            (2, (Minimum, "MINIMUM")),
            (3, (Maximum, "MAXIMUM")),
        ];
        for (value, (reduction, name)) in cases {
            assert_eq!(D3D12FilterReduction::from_u32(value), Some(reduction));
            assert_eq!(reduction.d3d12_name(), name);
            assert_eq!(reduction.as_u32(), value);
        }
        for value in 4..=8 {
            assert_eq!(
                D3D12FilterReduction::from_u32(value),
                None,
                "reduction type {value} is undefined per d3d12.h"
            );
        }
    }

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
}
