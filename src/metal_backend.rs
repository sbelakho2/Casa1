//! Real Metal GPU backend for Casa1.
//!
//! Provides real Metal rendering via the `metal` crate, creating actual MTLDevice,
//! MTLCommandQueue, MTLRenderPipelineState, MTLBuffer, MTLTexture, and CAMetalLayer
//! swapchain. This replaces the software-simulated graphics in `src/gfx.rs` with
//! genuine hardware-accelerated rendering on Apple Silicon.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use core_graphics_types::geometry::CGSize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// ID allocation
// ---------------------------------------------------------------------------

static NEXT_GPU_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_gpu_id() -> u64 {
    NEXT_GPU_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Metal device wrapper
// ---------------------------------------------------------------------------

/// Wrapper around a real Metal device (MTLDevice).
pub struct MetalDevice {
    device: metal::Device,
    name: String,
    unified_memory: bool,
    max_buffer_length: u64,
}

impl MetalDevice {
    /// Create a MetalDevice wrapping the system default Metal device.
    pub fn system_default() -> AppResult<Self> {
        let device = metal::Device::system_default().ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, "no Metal device available on this system")
        })?;

        let name = device.name().to_string();
        let unified_memory = device.has_unified_memory();
        let max_buffer_length = device.max_buffer_length();

        Ok(Self {
            device,
            name,
            unified_memory,
            max_buffer_length,
        })
    }

    /// Create a new command queue.
    pub fn create_command_queue(&self) -> metal::CommandQueue {
        self.device.new_command_queue().to_owned()
    }

    /// Create a new buffer with initial data.
    pub fn create_buffer_with_data(&self, data: &[u8], options: metal::MTLResourceOptions) -> metal::Buffer {
        self.device.new_buffer_with_data(
            data.as_ptr() as *const std::ffi::c_void,
            data.len() as u64,
            options,
        )
    }

    /// Create a new zero-initialized buffer.
    pub fn create_buffer(&self, length: u64, options: metal::MTLResourceOptions) -> metal::Buffer {
        self.device.new_buffer(length, options)
    }

    /// Create a new texture.
    pub fn create_texture(
        &self,
        width: u64,
        height: u64,
        pixel_format: metal::MTLPixelFormat,
        usage: metal::MTLTextureUsage,
        storage_mode: metal::MTLStorageMode,
    ) -> metal::Texture {
        let descriptor = metal::TextureDescriptor::new();
        descriptor.set_texture_type(metal::MTLTextureType::D2);
        descriptor.set_pixel_format(pixel_format);
        descriptor.set_width(width);
        descriptor.set_height(height);
        descriptor.set_usage(usage);
        descriptor.set_storage_mode(storage_mode);
        descriptor.set_sample_count(1);

        self.device.new_texture(&descriptor)
    }

    /// Compile a Metal shader library from source.
    pub fn compile_shader_library(&self, source: &str) -> AppResult<metal::Library> {
        let options = metal::CompileOptions::new();
        self.device.new_library_with_source(source, &options).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Metal shader compilation failed: {e}"),
            )
        })
    }

    /// Load a Metal shader library from a precompiled metallib file.
    pub fn load_shader_library(&self, path: &std::path::Path) -> AppResult<metal::Library> {
        self.device.new_library_with_file(path).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Failed to load Metal library from {}: {e}", path.display()),
            )
        })
    }

    /// Create a render pipeline state.
    pub fn create_render_pipeline_state(
        &self,
        descriptor: &metal::RenderPipelineDescriptorRef,
    ) -> AppResult<metal::RenderPipelineState> {
        self.device.new_render_pipeline_state(descriptor).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Failed to create render pipeline state: {e}"),
            )
        })
    }

    /// Create a compute pipeline state.
    pub fn create_compute_pipeline_state(
        &self,
        function: &metal::FunctionRef,
    ) -> AppResult<metal::ComputePipelineState> {
        self.device.new_compute_pipeline_state_with_function(function).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Failed to create compute pipeline state: {e}"),
            )
        })
    }

    /// Create a depth stencil state.
    pub fn create_depth_stencil_state(
        &self,
        depth_compare: metal::MTLCompareFunction,
        depth_write_enabled: bool,
    ) -> metal::DepthStencilState {
        let descriptor = metal::DepthStencilDescriptor::new();
        descriptor.set_depth_compare_function(depth_compare);
        descriptor.set_depth_write_enabled(depth_write_enabled);
        self.device.new_depth_stencil_state(&descriptor)
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this device has unified memory.
    pub fn unified_memory(&self) -> bool {
        self.unified_memory
    }

    /// Get the underlying Metal device reference.
    pub fn device(&self) -> &metal::Device {
        &self.device
    }

    /// Get max buffer length.
    pub fn max_buffer_length(&self) -> u64 {
        self.max_buffer_length
    }
}

// ---------------------------------------------------------------------------
// DXGI format to Metal pixel format mapping
// ---------------------------------------------------------------------------

/// Map a DXGI format to a Metal pixel format.
pub fn dxgi_to_metal_format(dxgi: crate::gfx::DxgiFormat) -> metal::MTLPixelFormat {
    match dxgi {
        crate::gfx::DxgiFormat::R8G8B8A8Unorm => metal::MTLPixelFormat::RGBA8Unorm,
        crate::gfx::DxgiFormat::B8G8R8A8Unorm => metal::MTLPixelFormat::BGRA8Unorm,
        crate::gfx::DxgiFormat::R16Float => metal::MTLPixelFormat::R16Float,
        crate::gfx::DxgiFormat::R32Float => metal::MTLPixelFormat::R32Float,
        crate::gfx::DxgiFormat::R10G10B10A2Unorm => metal::MTLPixelFormat::RGB10A2Unorm,
        crate::gfx::DxgiFormat::D24UnormS8Uint => metal::MTLPixelFormat::Depth24Unorm_Stencil8,
        crate::gfx::DxgiFormat::Bc1Unorm => metal::MTLPixelFormat::BC1_RGBA,
        crate::gfx::DxgiFormat::B5G6R5Unorm => metal::MTLPixelFormat::B5G6R5Unorm,
    }
}

// ---------------------------------------------------------------------------
// Swapchain (CAMetalLayer backed)
// ---------------------------------------------------------------------------

/// Manages the Metal swapchain via a CAMetalLayer.
pub struct MetalSwapchain {
    layer: metal::MetalLayer,
    width: u64,
    height: u64,
}

impl MetalSwapchain {
    /// Create a new swapchain with the specified dimensions.
    pub fn new(device: &metal::Device, width: u64, height: u64) -> Self {
        let layer = metal::MetalLayer::new();
        layer.set_device(device);
        layer.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
        layer.set_opaque(true);
        layer.set_drawable_size(CGSize {
            width: width as f64,
            height: height as f64,
        });
        layer.set_framebuffer_only(false);
        layer.set_presents_with_transaction(false);

        MetalSwapchain {
            layer,
            width,
            height,
        }
    }

    /// Get the next drawable.
    pub fn next_drawable(&self) -> AppResult<&metal::MetalDrawableRef> {
        self.layer.next_drawable().ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, "failed to get next drawable from Metal layer")
        })
    }

    /// Get the Metal layer reference (for attaching to a window).
    pub fn layer(&self) -> &metal::MetalLayer {
        &self.layer
    }

    /// Resize the swapchain.
    pub fn resize(&mut self, width: u64, height: u64) {
        self.width = width;
        self.height = height;
        self.layer.set_drawable_size(CGSize {
            width: width as f64,
            height: height as f64,
        });
    }

    /// Get the drawable size.
    pub fn size(&self) -> (u64, u64) {
        (self.width, self.height)
    }
}

// ---------------------------------------------------------------------------
// Render pass helpers
// ---------------------------------------------------------------------------

/// Create a render pass descriptor for rendering to a texture.
pub fn create_render_pass_descriptor(
    color_texture: &metal::TextureRef,
    clear_color: Option<(f64, f64, f64, f64)>,
) -> &metal::RenderPassDescriptorRef {
    let descriptor = metal::RenderPassDescriptor::new();
    let color_attachment = descriptor.color_attachments().object_at(0).unwrap();

    color_attachment.set_texture(Some(color_texture));
    color_attachment.set_load_action(match clear_color {
        Some(_) => metal::MTLLoadAction::Clear,
        None => metal::MTLLoadAction::Load,
    });
    color_attachment.set_store_action(metal::MTLStoreAction::Store);

    if let Some((r, g, b, a)) = clear_color {
        color_attachment.set_clear_color(metal::MTLClearColor { red: r, green: g, blue: b, alpha: a });
    }

    descriptor
}

/// Configure depth attachment on a render pass descriptor.
pub fn configure_depth_attachment(
    descriptor: &metal::RenderPassDescriptorRef,
    depth_texture: &metal::TextureRef,
    clear_depth: Option<f64>,
) {
    if let Some(depth_attachment) = descriptor.depth_attachment() {
        depth_attachment.set_texture(Some(depth_texture));
        depth_attachment.set_load_action(match clear_depth {
            Some(_) => metal::MTLLoadAction::Clear,
            None => metal::MTLLoadAction::Load,
        });
        depth_attachment.set_store_action(metal::MTLStoreAction::Store);

        if let Some(depth) = clear_depth {
            depth_attachment.set_clear_depth(depth);
        }
    }
}

// ---------------------------------------------------------------------------
// Metal GPU backend manager
// ---------------------------------------------------------------------------

/// Central manager for all Metal GPU resources.
pub struct MetalGpuBackend {
    device: MetalDevice,
    command_queue: metal::CommandQueue,
    swapchain: Option<MetalSwapchain>,
    buffers: BTreeMap<u64, metal::Buffer>,
    textures: BTreeMap<u64, metal::Texture>,
    libraries: BTreeMap<u64, metal::Library>,
    render_pipelines: BTreeMap<u64, metal::RenderPipelineState>,
    compute_pipelines: BTreeMap<u64, metal::ComputePipelineState>,
}

impl MetalGpuBackend {
    /// Create a new Metal GPU backend using the system default device.
    pub fn new() -> AppResult<Self> {
        let device = MetalDevice::system_default()?;
        let command_queue = device.create_command_queue().to_owned();

        Ok(Self {
            device,
            command_queue,
            swapchain: None,
            buffers: BTreeMap::new(),
            textures: BTreeMap::new(),
            libraries: BTreeMap::new(),
            render_pipelines: BTreeMap::new(),
            compute_pipelines: BTreeMap::new(),
        })
    }

    /// Create a swapchain with the specified dimensions.
    pub fn create_swapchain(&mut self, width: u64, height: u64) {
        self.swapchain = Some(MetalSwapchain::new(self.device.device(), width, height));
    }

    /// Get the device.
    pub fn device(&self) -> &MetalDevice {
        &self.device
    }

    /// Get the command queue.
    pub fn command_queue(&self) -> &metal::CommandQueueRef {
        &self.command_queue
    }

    /// Get the swapchain.
    pub fn swapchain(&self) -> Option<&MetalSwapchain> {
        self.swapchain.as_ref()
    }

    /// Get the swapchain mutably.
    pub fn swapchain_mut(&mut self) -> Option<&mut MetalSwapchain> {
        self.swapchain.as_mut()
    }

    /// Create and register a buffer with data.
    pub fn create_buffer(&mut self, data: &[u8], options: metal::MTLResourceOptions) -> u64 {
        let buffer = self.device.create_buffer_with_data(data, options);
        let id = alloc_gpu_id();
        self.buffers.insert(id, buffer);
        id
    }

    /// Create and register a zero-initialized buffer.
    pub fn create_empty_buffer(&mut self, length: u64, options: metal::MTLResourceOptions) -> u64 {
        let buffer = self.device.create_buffer(length, options);
        let id = alloc_gpu_id();
        self.buffers.insert(id, buffer);
        id
    }

    /// Get a buffer by ID.
    pub fn get_buffer(&self, id: u64) -> Option<&metal::BufferRef> {
        self.buffers.get(&id).map(|b| b.as_ref())
    }

    /// Create and register a texture.
    pub fn create_texture(
        &mut self,
        width: u64,
        height: u64,
        pixel_format: metal::MTLPixelFormat,
        usage: metal::MTLTextureUsage,
    ) -> u64 {
        let texture = self.device.create_texture(
            width,
            height,
            pixel_format,
            usage,
            metal::MTLStorageMode::Private,
        );
        let id = alloc_gpu_id();
        self.textures.insert(id, texture);
        id
    }

    /// Get a texture by ID.
    pub fn get_texture(&self, id: u64) -> Option<&metal::TextureRef> {
        self.textures.get(&id).map(|t| t.as_ref())
    }

    /// Compile and register a shader library.
    pub fn compile_shader(&mut self, source: &str) -> AppResult<u64> {
        let library = self.device.compile_shader_library(source)?;
        let id = alloc_gpu_id();
        self.libraries.insert(id, library);
        Ok(id)
    }

    /// Get a shader library by ID.
    pub fn get_shader_library(&self, id: u64) -> Option<&metal::LibraryRef> {
        self.libraries.get(&id).map(|l| l.as_ref())
    }

    /// Create and register a render pipeline.
    pub fn create_render_pipeline(
        &mut self,
        vertex_fn_name: &str,
        fragment_fn_name: &str,
        library_id: u64,
        color_format: metal::MTLPixelFormat,
        depth_format: Option<metal::MTLPixelFormat>,
    ) -> AppResult<u64> {
        let library = self.libraries.get(&library_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("library {library_id} not found"))
        })?;

        let vertex_fn = library.get_function(vertex_fn_name, None).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("vertex function '{vertex_fn_name}' not found: {e}"))
        })?;

        let _fragment_fn = library.get_function(fragment_fn_name, None).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("fragment function '{fragment_fn_name}' not found: {e}"))
        })?;

        let descriptor = metal::RenderPipelineDescriptor::new();
        descriptor.set_vertex_function(Some(&vertex_fn));

        if let Some(color_attachment) = descriptor.color_attachments().object_at(0) {
            color_attachment.set_pixel_format(color_format);
            color_attachment.set_blending_enabled(true);
            color_attachment.set_source_rgb_blend_factor(metal::MTLBlendFactor::SourceAlpha);
            color_attachment.set_destination_rgb_blend_factor(metal::MTLBlendFactor::OneMinusSourceAlpha);
            color_attachment.set_source_alpha_blend_factor(metal::MTLBlendFactor::One);
            color_attachment.set_destination_alpha_blend_factor(metal::MTLBlendFactor::OneMinusSourceAlpha);
        }

        if let Some(depth_fmt) = depth_format {
            descriptor.set_depth_attachment_pixel_format(depth_fmt);
        }

        let pipeline = self.device.create_render_pipeline_state(&descriptor)?;
        let id = alloc_gpu_id();
        self.render_pipelines.insert(id, pipeline);
        Ok(id)
    }

    /// Get a render pipeline by ID.
    pub fn get_render_pipeline(&self, id: u64) -> Option<&metal::RenderPipelineStateRef> {
        self.render_pipelines.get(&id).map(|p| p.as_ref())
    }

    /// Create and register a compute pipeline.
    pub fn create_compute_pipeline(
        &mut self,
        compute_fn_name: &str,
        library_id: u64,
    ) -> AppResult<u64> {
        let library = self.libraries.get(&library_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcCliInvalid, format!("library {library_id} not found"))
        })?;

        let compute_fn = library.get_function(compute_fn_name, None).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("compute function '{compute_fn_name}' not found: {e}"))
        })?;

        let pipeline = self.device.create_compute_pipeline_state(&compute_fn)?;
        let id = alloc_gpu_id();
        self.compute_pipelines.insert(id, pipeline);
        Ok(id)
    }

    /// Get a compute pipeline by ID.
    pub fn get_compute_pipeline(&self, id: u64) -> Option<&metal::ComputePipelineStateRef> {
        self.compute_pipelines.get(&id).map(|p| p.as_ref())
    }

    /// Destroy a buffer.
    pub fn destroy_buffer(&mut self, id: u64) {
        self.buffers.remove(&id);
    }

    /// Destroy a texture.
    pub fn destroy_texture(&mut self, id: u64) {
        self.textures.remove(&id);
    }

    /// Destroy a pipeline.
    pub fn destroy_pipeline(&mut self, id: u64) {
        self.render_pipelines.remove(&id);
        self.compute_pipelines.remove(&id);
    }

    /// Get device info.
    pub fn device_info(&self) -> (String, bool, u64) {
        (
            self.device.name().to_string(),
            self.device.unified_memory(),
            self.device.max_buffer_length,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_backend() -> MetalGpuBackend {
        MetalGpuBackend::new().expect("Metal GPU backend creation failed - no Metal device?")
    }

    #[test]
    fn metal_device_creation() {
        let device = MetalDevice::system_default();
        assert!(device.is_ok());
        let device = device.unwrap();
        assert!(!device.name().is_empty());
    }

    #[test]
    fn metal_device_properties() {
        let device = MetalDevice::system_default().unwrap();
        let _unified = device.unified_memory();
        assert!(device.max_buffer_length() > 0);
    }

    #[test]
    fn metal_command_queue_creation() {
        let device = MetalDevice::system_default().unwrap();
        let _queue = device.create_command_queue();
    }

    #[test]
    fn metal_buffer_creation_with_data() {
        let mut backend = create_backend();
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let id = backend.create_buffer(&data, metal::MTLResourceOptions::StorageModeShared);
        let buffer = backend.get_buffer(id).unwrap();
        assert_eq!(buffer.length(), 8);
    }

    #[test]
    fn metal_buffer_contents() {
        let mut backend = create_backend();
        let data = [42u8; 64];
        let id = backend.create_buffer(&data, metal::MTLResourceOptions::StorageModeShared);
        let buffer = backend.get_buffer(id).unwrap();
        assert_eq!(buffer.length(), 64);
        // Verify contents via raw pointer
        let contents = unsafe {
            std::slice::from_raw_parts(buffer.contents() as *const u8, 64)
        };
        assert_eq!(contents, &[42u8; 64]);
    }

    #[test]
    fn metal_empty_buffer_creation() {
        let mut backend = create_backend();
        let id = backend.create_empty_buffer(256, metal::MTLResourceOptions::StorageModeShared);
        let buffer = backend.get_buffer(id).unwrap();
        assert_eq!(buffer.length(), 256);
    }

    #[test]
    fn metal_texture_creation() {
        let mut backend = create_backend();
        let id = backend.create_texture(
            256,
            256,
            metal::MTLPixelFormat::BGRA8Unorm,
            metal::MTLTextureUsage::RenderTarget,
        );
        let texture = backend.get_texture(id).unwrap();
        assert_eq!(texture.width(), 256);
        assert_eq!(texture.height(), 256);
    }

    #[test]
    fn metal_shader_compilation() {
        let mut backend = create_backend();
        let source = r#"
            #include <metal_stdlib>
            using namespace metal;

            vertex float4 vertex_main(uint vid [[vertex_id]]) {
                return float4(0.0, 0.0, 0.0, 1.0);
            }

            fragment float4 fragment_main() {
                return float4(1.0, 0.0, 0.0, 1.0);
            }
        "#;
        let id = backend.compile_shader(source).unwrap();
        let library = backend.get_shader_library(id).unwrap();

        let vertex_fn = library.get_function("vertex_main", None).unwrap();
        assert_eq!(vertex_fn.name(), "vertex_main");

        let fragment_fn = library.get_function("fragment_main", None).unwrap();
        assert_eq!(fragment_fn.name(), "fragment_main");
    }

    #[test]
    fn metal_render_pipeline_creation() {
        let mut backend = create_backend();
        let source = r#"
            #include <metal_stdlib>
            using namespace metal;

            vertex float4 vertex_main(uint vid [[vertex_id]]) {
                float2 positions[3] = { float2(-1, -1), float2(1, -1), float2(0, 1) };
                return float4(positions[vid], 0.0, 1.0);
            }

            fragment float4 fragment_main() {
                return float4(0.0, 1.0, 0.0, 1.0);
            }
        "#;
        let lib_id = backend.compile_shader(source).unwrap();

        let pipeline_id = backend.create_render_pipeline(
            "vertex_main",
            "fragment_main",
            lib_id,
            metal::MTLPixelFormat::BGRA8Unorm,
            None,
        ).unwrap();

        let _pipeline = backend.get_render_pipeline(pipeline_id).unwrap();
        // Render pipeline created successfully
    }

    #[test]
    fn metal_compute_pipeline_creation() {
        let mut backend = create_backend();
        let source = r#"
            #include <metal_stdlib>
            using namespace metal;

            kernel void compute_main(device float* output [[buffer(0)]],
                                     uint gid [[thread_position_in_grid]]) {
                output[gid] = float(gid);
            }
        "#;
        let lib_id = backend.compile_shader(source).unwrap();
        let pipeline_id = backend.create_compute_pipeline("compute_main", lib_id).unwrap();
        assert!(backend.get_compute_pipeline(pipeline_id).is_some());
    }

    #[test]
    fn metal_swapchain_creation() {
        let device = MetalDevice::system_default().unwrap();
        let swapchain = MetalSwapchain::new(device.device(), 800, 600);
        assert_eq!(swapchain.size(), (800, 600));
    }

    #[test]
    fn metal_swapchain_resize() {
        let device = MetalDevice::system_default().unwrap();
        let mut swapchain = MetalSwapchain::new(device.device(), 800, 600);
        swapchain.resize(1024, 768);
        assert_eq!(swapchain.size(), (1024, 768));
    }

    #[test]
    fn metal_depth_stencil_creation() {
        let device = MetalDevice::system_default().unwrap();
        let _state = device.create_depth_stencil_state(
            metal::MTLCompareFunction::Less,
            true,
        );
    }

    #[test]
    fn metal_resource_destruction() {
        let mut backend = create_backend();
        let id = backend.create_buffer(&[1, 2, 3, 4], metal::MTLResourceOptions::StorageModeShared);
        assert!(backend.get_buffer(id).is_some());
        backend.destroy_buffer(id);
        assert!(backend.get_buffer(id).is_none());
    }

    #[test]
    fn dxgi_format_mapping() {
        assert_eq!(
            dxgi_to_metal_format(crate::gfx::DxgiFormat::B8G8R8A8Unorm),
            metal::MTLPixelFormat::BGRA8Unorm
        );
        assert_eq!(
            dxgi_to_metal_format(crate::gfx::DxgiFormat::R8G8B8A8Unorm),
            metal::MTLPixelFormat::RGBA8Unorm
        );
        assert_eq!(
            dxgi_to_metal_format(crate::gfx::DxgiFormat::D24UnormS8Uint),
            metal::MTLPixelFormat::Depth24Unorm_Stencil8
        );
    }

    #[test]
    fn metal_backend_device_info() {
        let backend = create_backend();
        let (name, _unified, max_buf) = backend.device_info();
        assert!(!name.is_empty());
        assert!(max_buf > 0);
    }
}
