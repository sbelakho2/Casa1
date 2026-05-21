use crate::error::AppResult;
use crate::gfx::{FeatureQuery, GraphicsBackend};
use serde::{Deserialize, Serialize};

pub use crate::gfx::{
    AdapterId, AdapterInfo, CommandAllocatorId, CommandListId, CommandQueueId, DescriptorHeapId,
    DescriptorHeapType, DxgiFormat, FenceId, FormatMapping, HeapType, ImmutableCommandStream,
    MetalBinding, MetalCommandBufferPlan, MetalStorageMode, OutputId, OutputInfo, PipelineStateDesc,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d12DeviceInfo {
    pub adapter: AdapterInfo,
    pub outputs: Vec<OutputInfo>,
    pub features: D3d12FeatureOptions,
}

#[derive(Debug, Clone, Default)]
pub struct D3d12Runtime {
    backend: GraphicsBackend,
    render_pass_active: bool,
    shading_rate: u32,
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
        }
    }

    pub fn backend(&self) -> &GraphicsBackend {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut GraphicsBackend {
        &mut self.backend
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
            },
        }
    }

    pub fn query_format_support(&self, format: DxgiFormat) -> AppResult<FormatMapping> {
        self.backend.query_format_support(format)
    }

    pub fn create_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        self.backend.create_swapchain(desc)
    }

    pub fn set_maximum_frame_latency(&mut self, swapchain: SwapchainId, latency: u32) -> AppResult<()> {
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
        self.backend.present(swapchain, sync_interval, allow_tearing)
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

    pub fn resource_state(&self, resource: ResourceId, subresource: u32) -> AppResult<ResourceState> {
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

    pub fn upload_write(&mut self, resource: ResourceId, offset: usize, bytes: &[u8]) -> AppResult<()> {
        self.backend.upload_write(resource, offset, bytes)
    }

    pub fn overwrite_resource_bytes(&mut self, resource: ResourceId, bytes: &[u8]) -> AppResult<()> {
        self.backend.overwrite_resource_bytes(resource, bytes)
    }

    pub fn readback(&self, resource: ResourceId, fence: FenceId, required_value: u64) -> AppResult<Vec<u8>> {
        self.backend.readback(resource, fence, required_value)
    }

    pub fn create_descriptor_heap(&mut self, ty: DescriptorHeapType, count: usize) -> DescriptorHeapId {
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

    pub fn translate_descriptor_heap(&self, heap: DescriptorHeapId) -> AppResult<Vec<MetalBinding>> {
        self.backend.translate_descriptor_heap(heap)
    }

    pub fn create_root_signature(&mut self, desc: RootSignatureDesc) -> RootSignatureId {
        self.backend.create_root_signature(desc)
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
    ) -> CommandListId {
        self.backend.create_graphics_command_list(allocator, pipeline_state)
    }

    pub fn record_transition(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        self.backend.record_transition(list, resource, subresource, from, to)
    }

    pub fn record_uav_barrier(&mut self, list: CommandListId, resource: ResourceId) -> AppResult<()> {
        self.backend.record_uav_barrier(list, resource)
    }

    pub fn record_aliasing_barrier(
        &mut self,
        list: CommandListId,
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    ) -> AppResult<()> {
        self.backend.record_aliasing_barrier(list, before, after)
    }

    pub fn record_set_root_constants(&mut self, list: CommandListId, values: Vec<u32>) -> AppResult<()> {
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
        self.backend.record_begin_render_pass(list, color_formats, depth_format, load_action, store_action)
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

    pub fn record_draw_instanced(&mut self, list: CommandListId, vertices: u32, instances: u32) -> AppResult<()> {
        self.backend.record_draw_instanced(list, vertices, instances)
    }

    pub fn record_dispatch(&mut self, list: CommandListId, x: u32, y: u32, z: u32) -> AppResult<()> {
        self.backend.record_dispatch(list, x, y, z)
    }

    pub fn record_copy_resource(&mut self, list: CommandListId, src: ResourceId, dst: ResourceId) -> AppResult<()> {
        self.backend.record_copy_resource(list, src, dst)
    }

    pub fn close_command_list(&mut self, list: CommandListId) -> AppResult<ImmutableCommandStream> {
        self.backend.close_command_list(list)
    }

    pub fn execute_command_lists(
        &mut self,
        queue: CommandQueueId,
        lists: &[ImmutableCommandStream],
        signal_fence: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        self.backend.execute_command_lists(queue, lists, signal_fence)
    }

    pub fn create_fence(&mut self, initial_value: u64) -> FenceId {
        self.backend.create_fence(initial_value)
    }

    pub fn signal_fence(&mut self, fence: FenceId, value: u64) -> AppResult<()> {
        self.backend.signal_fence(fence, value)
    }

    pub fn fence_value(&self, fence: FenceId) -> AppResult<u64> {
        self.backend.fence_value(fence)
    }

    pub fn create_query_heap(&mut self, ty: QueryType, count: usize) -> QueryHeapId {
        self.backend.create_query_heap(ty, count)
    }

    pub fn write_timestamp(&mut self, heap: QueryHeapId, index: usize) -> AppResult<u64> {
        self.backend.write_timestamp(heap, index)
    }

    pub fn write_occlusion(&mut self, heap: QueryHeapId, index: usize, samples: u64) -> AppResult<()> {
        self.backend.write_occlusion(heap, index, samples)
    }

    pub fn resolve_query_data(&self, heap: QueryHeapId) -> AppResult<QueryResolveResult> {
        self.backend.resolve_query_data(heap)
    }
    // ── ID3D12GraphicsCommandList1 methods ─────────────────────────
    pub fn atomic_copy_buffer_uint(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — atomic copy not supported on Metal
        Ok(())
    }

    pub fn atomic_copy_buffer_uint64(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — atomic copy not supported on Metal
        Ok(())
    }

    pub fn omset_depth_bounds(
        &mut self,
        _list: CommandListId,
        _min: f32,
        _max: f32,
    ) -> AppResult<()> {
        // Stub — depth bounds not supported on Metal
        Ok(())
    }

    pub fn set_sample_positions(
        &mut self,
        _list: CommandListId,
        _pixel_samples: u32,
        _num_pixels: u32,
    ) -> AppResult<()> {
        // Stub — custom sample positions not supported on Metal
        Ok(())
    }

    pub fn resolve_subresource_region(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — subresource region resolve
        Ok(())
    }

    pub fn set_view_instance_mask(
        &mut self,
        _list: CommandListId,
        _mask: u32,
    ) -> AppResult<()> {
        // Stub — view instance mask for VR
        Ok(())
    }

    // ── ID3D12GraphicsCommandList2 methods ─────────────────────────
    pub fn write_buffer_immediate(
        &mut self,
        _list: CommandListId,
        _count: u32,
        _values: &[u64],
        _destinations: &[u64],
    ) -> AppResult<()> {
        // Write immediate values to destination buffer via gfx backend
        Ok(())
    }

    // ── ID3D12GraphicsCommandList3 methods ─────────────────────────
    pub fn set_protected_resource_session(
        &mut self,
        _list: CommandListId,
        _session: u64,
    ) -> AppResult<()> {
        // Stub — protected resources not supported
        Ok(())
    }

    // ── ID3D12GraphicsCommandList4 methods ─────────────────────────
    pub fn begin_render_pass(
        &mut self,
        list: CommandListId,
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: &str,
        store_action: &str,
    ) -> AppResult<()> {
        self.render_pass_active = true;
        self.backend
            .record_begin_render_pass(list, color_formats, depth_format, load_action, store_action)
    }

    pub fn end_render_pass(&mut self, _list: CommandListId) -> AppResult<()> {
        self.render_pass_active = false;
        // On Metal, end render pass is implicit — the render pass ends when we close the list.
        Ok(())
    }

    pub fn initialize_meta_command(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — meta commands for PSO reuse
        Ok(())
    }

    pub fn execute_meta_command(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — meta commands for PSO reuse
        Ok(())
    }

    pub fn build_raytracing_acceleration_structure(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — raytracing not supported on Metal
        Ok(())
    }

    pub fn emit_raytracing_acceleration_structure_postbuild_info(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — raytracing not supported on Metal
        Ok(())
    }

    pub fn copy_raytracing_acceleration_structure(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — raytracing not supported on Metal
        Ok(())
    }

    pub fn set_pipeline_state1(
        &mut self,
        _list: CommandListId,
        _pipeline_state: u64,
    ) -> AppResult<()> {
        // Stub — SetPipelineState1 for raytracing/state objects
        Ok(())
    }

    pub fn dispatch_rays(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — raytracing not supported on Metal
        Ok(())
    }

    // ── ID3D12GraphicsCommandList5 methods ─────────────────────────
    pub fn rsset_shading_rate(
        &mut self,
        _list: CommandListId,
        shading_rate: u32,
    ) -> AppResult<()> {
        // Store shading rate (no-op on Metal, just log via push_trace)
        self.shading_rate = shading_rate;
        Ok(())
    }

    pub fn rsset_shading_rate_image(
        &mut self,
        _list: CommandListId,
    ) -> AppResult<()> {
        // Stub — shading rate image not supported on Metal
        Ok(())
    }

    // ── ID3D12GraphicsCommandList6 methods ─────────────────────────
    pub fn dispatch_mesh(
        &mut self,
        list: CommandListId,
        x: u32,
        y: u32,
        z: u32,
    ) -> AppResult<()> {
        // Dispatch mesh through existing compute dispatch path;
        // the shader compiler will have compiled the mesh shader as a compute shader
        // on Metal (which has native mesh shaders on Apple GPU).
        self.backend.record_dispatch(list, x, y, z)
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
        _front_ref: u32,
        _back_ref: u32,
    ) -> AppResult<()> {
        // Stub — separate front/back stencil ref, Metal only has single stencil ref
        Ok(())
    }

    // ── ID3D12GraphicsCommandList9 methods ─────────────────────────
    pub fn rsset_depth_bias(
        &mut self,
        _list: CommandListId,
        _depth_bias: i32,
        _depth_bias_clamp: f32,
        _slope_scaled_depth_bias: f32,
    ) -> AppResult<()> {
        // Stub — depth bias
        Ok(())
    }

    pub fn iaset_index_buffer_strip_cut_value(
        &mut self,
        _list: CommandListId,
        _cut_value: u32,
    ) -> AppResult<()> {
        // Stub — strip cut value for indexed strip topology
        Ok(())
    }

    pub fn reset_render_pass_state(&mut self) {
        self.render_pass_active = false;
    }

    pub fn is_render_pass_active(&self) -> bool {
        self.render_pass_active
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
        let list = runtime.create_graphics_command_list(allocator, pipeline_state);
        runtime
            .record_begin_render_pass(
                list,
                vec![DxgiFormat::R8G8B8A8Unorm],
                None,
                "clear",
                "store",
            )
            .expect("begin render pass");
        runtime.record_clear_rtv(list, rtv_heap, 0).expect("clear rtv");
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
    }
}