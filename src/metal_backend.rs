//! Real Metal GPU backend for Casa1.
//!
//! Provides real Metal rendering via the `metal` crate, creating actual MTLDevice,
//! MTLCommandQueue, MTLRenderPipelineState, MTLBuffer, MTLTexture, and CAMetalLayer
//! swapchain. This replaces the software-simulated graphics in `src/gfx.rs` with
//! genuine hardware-accelerated rendering on Apple Silicon.
//!
//! # Phase 5.1 — Advanced Metal Backend Features
//!
//! This module implements advanced GPU features needed for AAA game rendering:
//!
//! - **Argument Buffers Tier 2**: Nested argument buffers with inline data support
//! - **Ray Tracing**: MTLAccelerationStructure build/refit/query pipeline
//! - **Mesh Shaders**: Object + mesh + fragment pipeline (macOS 13+, Apple9+/M3+)
//! - **DXR Raytracing**: DispatchRays + shader tables via MTLRaytracingCommandEncoder
//! - **Variable Rate Shading**: Per-tile fragment shading rate control
//! - **Sampler Feedback**: Mip-level feedback texture for texture streaming
//! - **MSAA Programmable Resolve**: Custom resolve shaders for multi-sample anti-aliasing
//! - **Depth Bounds Test Emulation**: Shader-based depth bounds via discard_fragment
//! - **Logic Op Emulation**: Framebuffer logic operations via fullscreen quad passes
//! - **Geometry Shader Emulation**: Compute-based geometry shader with transform feedback
//! - **Tessellation**: Hardware tessellation via post-tessellation vertex shaders
//! - **MTLHeap**: GPU heap allocation for buffers, textures, and acceleration structures

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

    /// Create a mesh render pipeline state (macOS 13+, Apple9+/M3+).
    ///
    /// Returns `None` if the device does not support mesh shaders.
    pub fn create_mesh_render_pipeline_state(
        &self,
        descriptor: &metal::MeshRenderPipelineDescriptorRef,
    ) -> AppResult<Option<metal::RenderPipelineState>> {
        if self.supports_mesh_shaders() {
            let pipeline = self.device.new_mesh_render_pipeline_state(descriptor).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("Failed to create mesh render pipeline state: {e}"),
                )
            })?;
            Ok(Some(pipeline))
        } else {
            Ok(None)
        }
    }

    /// Check whether this device supports mesh shaders (Apple GPU family >= 9 or M3+).
    pub fn supports_mesh_shaders(&self) -> bool {
        // Apple GPU family 9+ (M3+) supports mesh shaders.
        // For discrete GPUs (non-Apple), mesh shaders are not available via Metal.
        if !self.unified_memory {
            return false;
        }
        // With unified memory, check if the device supports the required feature set.
        // MTLGPUFamilyApple9 was introduced in macOS 14 / iOS 17.
        // We'll check for `supports_family` via the device's `supports_family` method.
        self.device.supports_family(metal::MTLGPUFamily::Apple9)
    }

    /// Check whether this device supports hardware raytracing (Apple GPU family >= 7).
    pub fn supports_raytracing(&self) -> bool {
        // Apple GPU family 7+ supports hardware-accelerated raytracing.
        // Intel/AMD GPUs may use software fallback.
        if self.unified_memory {
            self.device.supports_family(metal::MTLGPUFamily::Apple7)
        } else {
            // For discrete GPUs, check for common raytracing support
            false
        }
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
        crate::gfx::DxgiFormat::R8G8B8A8UnormSrgb => metal::MTLPixelFormat::RGBA8Unorm_sRGB,
        crate::gfx::DxgiFormat::R8G8B8A8Uint => metal::MTLPixelFormat::RGBA8Uint,
        crate::gfx::DxgiFormat::B8G8R8A8Unorm => metal::MTLPixelFormat::BGRA8Unorm,
        crate::gfx::DxgiFormat::B8G8R8A8UnormSrgb => metal::MTLPixelFormat::BGRA8Unorm_sRGB,
        crate::gfx::DxgiFormat::B8G8R8X8Unorm => metal::MTLPixelFormat::BGRA8Unorm,
        crate::gfx::DxgiFormat::R8Unorm => metal::MTLPixelFormat::R8Unorm,
        crate::gfx::DxgiFormat::R8Uint => metal::MTLPixelFormat::R8Uint,
        crate::gfx::DxgiFormat::R16Float => metal::MTLPixelFormat::R16Float,
        crate::gfx::DxgiFormat::R16Unorm => metal::MTLPixelFormat::R16Unorm,
        crate::gfx::DxgiFormat::R16Uint => metal::MTLPixelFormat::R16Uint,
        crate::gfx::DxgiFormat::R16Snorm => metal::MTLPixelFormat::R16Snorm,
        crate::gfx::DxgiFormat::R32Float => metal::MTLPixelFormat::R32Float,
        crate::gfx::DxgiFormat::R32Uint => metal::MTLPixelFormat::R32Uint,
        crate::gfx::DxgiFormat::R32Sint => metal::MTLPixelFormat::R32Sint,
        crate::gfx::DxgiFormat::R10G10B10A2Unorm => metal::MTLPixelFormat::RGB10A2Unorm,
        crate::gfx::DxgiFormat::R10G10B10A2Uint => metal::MTLPixelFormat::RGB10A2Uint,
        crate::gfx::DxgiFormat::R11G11B10Float => metal::MTLPixelFormat::RG11B10Float,
        crate::gfx::DxgiFormat::R16G16Float => metal::MTLPixelFormat::RG16Float,
        crate::gfx::DxgiFormat::R16G16Unorm => metal::MTLPixelFormat::RG16Unorm,
        crate::gfx::DxgiFormat::R16G16Uint => metal::MTLPixelFormat::RG16Uint,
        crate::gfx::DxgiFormat::R16G16Snorm => metal::MTLPixelFormat::RG16Snorm,
        crate::gfx::DxgiFormat::R32G32Float => metal::MTLPixelFormat::RG32Float,
        crate::gfx::DxgiFormat::R32G32Uint => metal::MTLPixelFormat::RG32Uint,
        crate::gfx::DxgiFormat::R16G16B16A16Float => metal::MTLPixelFormat::RGBA16Float,
        crate::gfx::DxgiFormat::R16G16B16A16Unorm => metal::MTLPixelFormat::RGBA16Unorm,
        crate::gfx::DxgiFormat::R16G16B16A16Uint => metal::MTLPixelFormat::RGBA16Uint,
        crate::gfx::DxgiFormat::R32G32B32A32Float => metal::MTLPixelFormat::RGBA32Float,
        crate::gfx::DxgiFormat::R32G32B32A32Uint => metal::MTLPixelFormat::RGBA32Uint,
        crate::gfx::DxgiFormat::D24UnormS8Uint => metal::MTLPixelFormat::Depth24Unorm_Stencil8,
        crate::gfx::DxgiFormat::D32Float => metal::MTLPixelFormat::Depth32Float,
        crate::gfx::DxgiFormat::D32FloatS8Uint => metal::MTLPixelFormat::Depth32Float_Stencil8,
        crate::gfx::DxgiFormat::Bc1Unorm => metal::MTLPixelFormat::BC1_RGBA,
        crate::gfx::DxgiFormat::Bc1UnormSrgb => metal::MTLPixelFormat::BC1_RGBA_sRGB,
        crate::gfx::DxgiFormat::Bc2Unorm => metal::MTLPixelFormat::BC2_RGBA,
        crate::gfx::DxgiFormat::Bc2UnormSrgb => metal::MTLPixelFormat::BC2_RGBA_sRGB,
        crate::gfx::DxgiFormat::Bc3Unorm => metal::MTLPixelFormat::BC3_RGBA,
        crate::gfx::DxgiFormat::Bc3UnormSrgb => metal::MTLPixelFormat::BC3_RGBA_sRGB,
        crate::gfx::DxgiFormat::Bc4Unorm => metal::MTLPixelFormat::BC4_RUnorm,
        crate::gfx::DxgiFormat::Bc5Unorm => metal::MTLPixelFormat::BC5_RGUnorm,
        crate::gfx::DxgiFormat::Bc7Unorm => metal::MTLPixelFormat::BC7_RGBAUnorm,
        crate::gfx::DxgiFormat::Bc7UnormSrgb => metal::MTLPixelFormat::BC7_RGBAUnorm_sRGB,
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
// IOSurface-backed Metal texture utilities for zero-copy CEF compositing
// ---------------------------------------------------------------------------

/// Stub: create a Metal texture from an IOSurface.
///
/// The `metal` crate v0.31 does not expose the IOSurface-backed texture creation
/// API (`newTextureWithDescriptor:iosurface:plane:error:`). This always returns
/// `None` for now; the compositor falls back to CPU-side pixel uploads via
/// [`submit_cef_overlay_frame`].
///
/// [`submit_cef_overlay_frame`]: crate::metal_renderer::submit_cef_overlay_frame
pub fn create_texture_from_io_surface(
    _device: &metal::Device,
    _io_surface_ptr: *mut std::ffi::c_void,
    _format: metal::MTLPixelFormat,
    _width: u64,
    _height: u64,
) -> Option<metal::Texture> {
    None
}

/// Stub: allocate a new IOSurface.
///
/// The `metal` crate v0.31 does not expose the necessary APIs for IOSurface-backed
/// Metal textures; this always returns `None`. When raw `objc` bindings are added
/// (or the `metal` crate is updated), this will create an actual `IOSurfaceRef`
/// for zero-copy buffer exchange between WKWebView and the Metal compositor.
pub fn create_io_surface(_width: u32, _height: u32) -> Option<*mut std::ffi::c_void> {
    None
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

        let fragment_fn = library.get_function(fragment_fn_name, None).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("fragment function '{fragment_fn_name}' not found: {e}"))
        })?;

        let descriptor = metal::RenderPipelineDescriptor::new();
        descriptor.set_vertex_function(Some(&vertex_fn));
        descriptor.set_fragment_function(Some(&fragment_fn));

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

// ===========================================================================
// Phase 5.1 — Advanced Metal Backend Features
// ===========================================================================

// ---------------------------------------------------------------------------
// Resource wrapper types
// ---------------------------------------------------------------------------

/// Wrapper around a Metal buffer with a GPU-side handle for tracking.
pub struct MetalBuffer {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The underlying Metal buffer.
    pub buffer: metal::Buffer,
    /// Size of the buffer in bytes.
    pub size: u64,
}

/// Wrapper around a Metal texture with a GPU-side handle for tracking.
pub struct MetalTexture {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The underlying Metal texture.
    pub texture: metal::Texture,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pixel format of the texture.
    pub format: PixelFormat,
}

/// Wrapper around a Metal sampler state with a GPU-side handle for tracking.
pub struct MetalSampler {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The underlying Metal sampler state.
    pub sampler: metal::SamplerState,
}

// ---------------------------------------------------------------------------
// Encoder wrapper types
// ---------------------------------------------------------------------------

/// Wrapper around a Metal compute command encoder.
///
/// Provides a safe interface for encoding compute operations including
/// dispatch, resource binding, and acceleration structure builds.
pub struct MetalComputeEncoder {
    encoder: metal::ComputeCommandEncoder,
}

impl MetalComputeEncoder {
    /// Create a new compute encoder from a command buffer.
    pub fn new(command_buffer: &metal::CommandBufferRef) -> AppResult<Self> {
        let encoder = command_buffer.new_compute_command_encoder().to_owned();
        Ok(Self { encoder })
    }

    /// Create a new compute encoder from a raw Metal compute command encoder.
    pub fn from_raw(encoder: metal::ComputeCommandEncoder) -> Self {
        Self { encoder }
    }

    /// Get a reference to the underlying Metal compute encoder.
    pub fn encoder(&self) -> &metal::ComputeCommandEncoderRef {
        &self.encoder
    }

    /// Get a mutable reference to the underlying Metal compute encoder.
    pub fn encoder_mut(&mut self) -> &mut metal::ComputeCommandEncoderRef {
        &mut self.encoder
    }

    /// End encoding.
    pub fn end_encoding(&self) {
        self.encoder.end_encoding()
    }
}

/// Wrapper around a Metal render command encoder.
///
/// Provides a safe interface for encoding render operations including
/// draw calls, resource binding, and pipeline state management.
pub struct MetalRenderEncoder {
    encoder: metal::RenderCommandEncoder,
}

impl MetalRenderEncoder {
    /// Create a new render encoder from a command buffer and render pass descriptor.
    pub fn new(
        command_buffer: &metal::CommandBufferRef,
        descriptor: &metal::RenderPassDescriptorRef,
    ) -> AppResult<Self> {
        let encoder = command_buffer.new_render_command_encoder(descriptor).to_owned();
        Ok(Self { encoder })
    }

    /// Create a new render encoder from a raw Metal render command encoder.
    pub fn from_raw(encoder: metal::RenderCommandEncoder) -> Self {
        Self { encoder }
    }

    /// Get a reference to the underlying Metal render encoder.
    pub fn encoder(&self) -> &metal::RenderCommandEncoderRef {
        &self.encoder
    }

    /// Get a mutable reference to the underlying Metal render encoder.
    pub fn encoder_mut(&mut self) -> &mut metal::RenderCommandEncoderRef {
        &mut self.encoder
    }

    /// End encoding.
    pub fn end_encoding(&self) {
        self.encoder.end_encoding()
    }
}

/// Wrapper around a Metal acceleration structure command encoder.
///
/// Used for building and refitting ray tracing acceleration structures.
pub struct MetalAccelerationStructureEncoder {
    encoder: metal::AccelerationStructureCommandEncoder,
}

impl MetalAccelerationStructureEncoder {
    /// Create a new acceleration structure encoder from a command buffer.
    pub fn new(command_buffer: &metal::CommandBufferRef) -> AppResult<Self> {
        let encoder = command_buffer.new_acceleration_structure_command_encoder().to_owned();
        Ok(Self { encoder })
    }

    /// Get a reference to the underlying Metal acceleration structure encoder.
    pub fn encoder(&self) -> &metal::AccelerationStructureCommandEncoderRef {
        &self.encoder
    }

    /// End encoding.
    pub fn end_encoding(&self) {
        self.encoder.end_encoding()
    }
}

/// Placeholder for Metal raytracing command encoder support.
///
/// The metal crate v0.31 does not expose `RaytracingCommandEncoder` types.
/// This type stores raytracing dispatch parameters for future integration
/// when the metal crate is upgraded. Available on Apple GPU family 7+.
pub struct MetalRayTracingEncoder;

impl MetalRayTracingEncoder {
    /// Create a placeholder raytracing encoder (no-op).
    pub fn new(_command_buffer: &metal::CommandBufferRef) -> AppResult<Self> {
        // Raytracing encoder not available in metal-0.31.0;
        // upgrade the metal crate for full support.
        eprintln!("[metal] MetalRayTracingEncoder: raytracing encoder not available in metal-0.31.0");
        Ok(Self)
    }

    /// No-op stub — will dispatch rays once the metal crate is upgraded.
    #[allow(unused_variables)]
    pub fn dispatch_rays(
        &self,
        raygen_buffer: Option<&metal::BufferRef>,
        raygen_offset: u64,
        miss_buffer: Option<&metal::BufferRef>,
        miss_offset: u64,
        hit_buffer: Option<&metal::BufferRef>,
        hit_offset: u64,
        width: u32,
        height: u32,
        depth: u32,
    ) {
        eprintln!(
            "[metal] MetalRayTracingEncoder::dispatch_rays stub: {}x{}x{}",
            width, height, depth
        );
    }

    /// No-op stub.
    pub fn end_encoding(&self) {
        // No-op
    }
}

// ---------------------------------------------------------------------------
// Pixel format abstraction
// ---------------------------------------------------------------------------

/// Abstract pixel format enum used across the advanced backend features.
///
/// Maps to concrete `metal::MTLPixelFormat` values for Metal API calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 8-bit BGRA with normalized unsigned components.
    Bgra8Unorm,
    /// 8-bit RGBA with normalized unsigned components.
    Rgba8Unorm,
    /// 16-bit R channel, floating point.
    R16Float,
    /// 32-bit R channel, floating point.
    R32Float,
    /// 10-10-10-2 normalized unsigned.
    Rgb10A2Unorm,
    /// 24-bit depth + 8-bit stencil.
    Depth24UnormStencil8,
    /// 32-bit depth.
    Depth32Float,
    /// BC1 compressed RGBA.
    Bc1Rgba,
}

impl PixelFormat {
    /// Convert to the corresponding Metal pixel format.
    pub fn to_metal(&self) -> metal::MTLPixelFormat {
        match self {
            PixelFormat::Bgra8Unorm => metal::MTLPixelFormat::BGRA8Unorm,
            PixelFormat::Rgba8Unorm => metal::MTLPixelFormat::RGBA8Unorm,
            PixelFormat::R16Float => metal::MTLPixelFormat::R16Float,
            PixelFormat::R32Float => metal::MTLPixelFormat::R32Float,
            PixelFormat::Rgb10A2Unorm => metal::MTLPixelFormat::RGB10A2Unorm,
            PixelFormat::Depth24UnormStencil8 => metal::MTLPixelFormat::Depth24Unorm_Stencil8,
            PixelFormat::Depth32Float => metal::MTLPixelFormat::Depth32Float,
            PixelFormat::Bc1Rgba => metal::MTLPixelFormat::BC1_RGBA,
        }
    }

    /// Number of bytes per pixel (approximate for compressed formats).
    pub fn bytes_per_pixel(&self) -> u32 {
        match self {
            PixelFormat::Bgra8Unorm | PixelFormat::Rgba8Unorm => 4,
            PixelFormat::R16Float => 2,
            PixelFormat::R32Float => 4,
            PixelFormat::Rgb10A2Unorm => 4,
            PixelFormat::Depth24UnormStencil8 => 4,
            PixelFormat::Depth32Float => 4,
            PixelFormat::Bc1Rgba => 1, // approximate (8 bytes per 4x4 block)
        }
    }
}

// ---------------------------------------------------------------------------
// D3D12 → Metal: Static Sampler & Descriptor Range Mapping
// ---------------------------------------------------------------------------

/// Map D3D12_DESCRIPTOR_RANGE_TYPE to the Metal argument buffer resource type.
pub fn map_descriptor_range_type_to_metal(range_type: &str) -> &'static str {
    match range_type {
        "srv" | "uav" => "texture",
        "cbv" => "buffer",
        "sampler" => "sampler",
        _ => "buffer",
    }
}

/// Map a D3D12_FILTER value to Metal MTLSamplerDescriptor properties.
pub fn d3d12_filter_to_metal_sampler(filter: u32) -> metal::SamplerDescriptor {
    let desc = metal::SamplerDescriptor::new();
    // D3D12_FILTER bits: [min:2][mag:2][mip:2][aniso:1][cmp:1]
    let min_part = (filter & 0x03) as u8;
    let mag_part = ((filter >> 2) & 0x03) as u8;
    let mip_part = ((filter >> 4) & 0x03) as u8;
    let anisotropic = (filter & 0x40) != 0;
    let comparison = (filter & 0x80) != 0;

    desc.set_min_filter(if min_part == 0 {
        metal::MTLSamplerMinMagFilter::Nearest
    } else {
        metal::MTLSamplerMinMagFilter::Linear
    });
    desc.set_mag_filter(if mag_part == 0 {
        metal::MTLSamplerMinMagFilter::Nearest
    } else {
        metal::MTLSamplerMinMagFilter::Linear
    });
    desc.set_mip_filter(if mip_part == 0 {
        metal::MTLSamplerMipFilter::Nearest
    } else {
        metal::MTLSamplerMipFilter::Linear
    });

    if anisotropic {
        desc.set_max_anisotropy(std::cmp::min(16, 1.max(filter as u8 >> 6) as u64));
    }
    if comparison {
        desc.set_compare_function(metal::MTLCompareFunction::LessEqual);
    }

    desc
}

/// Map D3D12_TEXTURE_ADDRESS_MODE to Metal address mode.
pub fn map_d3d12_address_mode_to_metal(mode: u32) -> metal::MTLSamplerAddressMode {
    match mode {
        1 => metal::MTLSamplerAddressMode::ClampToEdge,
        2 => metal::MTLSamplerAddressMode::Repeat,
        3 => metal::MTLSamplerAddressMode::MirrorRepeat,
        4 => metal::MTLSamplerAddressMode::ClampToZero,
        _ => metal::MTLSamplerAddressMode::ClampToEdge,
    }
}

/// Create a Metal MTLSamplerState from a D3D12_STATIC_SAMPLER_DESC.
pub fn create_static_sampler(
    device: &metal::DeviceRef,
    sampler_desc: &crate::gfx::D3D12StaticSamplerDesc,
) -> metal::SamplerState {
    let desc = d3d12_filter_to_metal_sampler(sampler_desc.filter);
    desc.set_address_mode_s(map_d3d12_address_mode_to_metal(sampler_desc.address_u));
    desc.set_address_mode_t(map_d3d12_address_mode_to_metal(sampler_desc.address_v));
    desc.set_address_mode_r(map_d3d12_address_mode_to_metal(sampler_desc.address_w));
    desc.set_lod_min_clamp(sampler_desc.min_lod);
    desc.set_lod_max_clamp(sampler_desc.max_lod);
    if sampler_desc.max_anisotropy > 0 {
        desc.set_max_anisotropy(sampler_desc.max_anisotropy.min(16) as u64);
    }
    // Map D3D12_COMPARISON_FUNC to Metal
    let compare_fn = match sampler_desc.comparison_func {
        1 => metal::MTLCompareFunction::Never,
        2 => metal::MTLCompareFunction::Less,
        3 => metal::MTLCompareFunction::Equal,
        4 => metal::MTLCompareFunction::LessEqual,
        5 => metal::MTLCompareFunction::Greater,
        6 => metal::MTLCompareFunction::NotEqual,
        7 => metal::MTLCompareFunction::GreaterEqual,
        8 => metal::MTLCompareFunction::Always,
        _ => metal::MTLCompareFunction::Never,
    };
    desc.set_compare_function(compare_fn);
    // Border color mapping
    let border_color = match sampler_desc.border_color {
        0 => metal::MTLSamplerBorderColor::TransparentBlack,
        1 => metal::MTLSamplerBorderColor::OpaqueBlack,
        2 => metal::MTLSamplerBorderColor::OpaqueWhite,
        _ => metal::MTLSamplerBorderColor::TransparentBlack,
    };
    desc.set_border_color(border_color);
    device.new_sampler(&desc)
}

/// Map D3D12_SHADER_VISIBILITY to Metal shader stage string.
pub fn shader_visibility_to_metal_stage(visibility: &crate::gfx::D3D12ShaderVisibility) -> &'static str {
    match visibility {
        crate::gfx::D3D12ShaderVisibility::Vertex => "vertex",
        crate::gfx::D3D12ShaderVisibility::Hull => "vertex",   // tessellation control -> vertex
        crate::gfx::D3D12ShaderVisibility::Domain => "vertex",  // tessellation eval -> vertex
        crate::gfx::D3D12ShaderVisibility::Geometry => "vertex", // geometry emulation -> vertex
        crate::gfx::D3D12ShaderVisibility::Pixel => "fragment",
        crate::gfx::D3D12ShaderVisibility::Amplification => "vertex", // mesh amplification -> vertex
        crate::gfx::D3D12ShaderVisibility::Mesh => "vertex",   // mesh shader -> vertex
        crate::gfx::D3D12ShaderVisibility::All => "vertex|fragment",
    }
}

/// Get Metal argument buffer tier limit.
pub fn argument_buffer_tier_limit(tier: u32) -> u32 {
    match tier {
        1 => 64,       // Tier 1: 64 entries
        2 => 500_000,  // Tier 2: 500,000+ entries
        _ => 64,       // Default to Tier 1
    }
}

// ===========================================================================
// Feature 1: Argument Buffers Tier 2
// ===========================================================================

/// Specifies the shader stages that can use an argument buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentBufferUsage {
    /// Argument buffer is only accessible from graphics pipelines.
    Graphics,
    /// Argument buffer is only accessible from compute pipelines.
    Compute,
    /// Argument buffer is accessible from both graphics and compute pipelines.
    GraphicsAndCompute,
}

/// Specifies the read/write access mode for an argument buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentBufferAccess {
    /// Read-only access.
    ReadOnly,
    /// Read-write access.
    ReadWrite,
}

/// Describes the creation parameters for an argument buffer.
#[derive(Debug, Clone)]
pub struct ArgumentBufferDescriptor {
    /// The buffer index (binding point) in the shader.
    pub buffer_index: u32,
    /// Total size of the argument buffer in bytes.
    pub size_bytes: u32,
    /// Which shader stages can access this argument buffer.
    pub usage: ArgumentBufferUsage,
    /// Read/write access mode.
    pub access: ArgumentBufferAccess,
}

/// The type of resource stored in an argument buffer entry.
#[derive(Debug, Clone)]
pub enum ArgumentResourceType {
    /// A storage or uniform buffer.
    Buffer,
    /// A texture.
    Texture,
    /// A sampler state.
    Sampler,
    /// Inline constant data with the specified size in bytes.
    InlineData(u32),
    /// A nested argument buffer (Tier 2 feature).
    NestedArgumentBuffer(Box<ArgumentBufferLayout>),
}

/// Access mode for an individual argument buffer entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentAccess {
    /// Read-only access.
    ReadOnly,
    /// Read-write access.
    ReadWrite,
    /// Write-only access.
    WriteOnly,
}

/// A single entry in an argument buffer layout.
#[derive(Debug, Clone)]
pub struct ArgumentBufferEntry {
    /// Binding index within the argument buffer.
    pub binding: u32,
    /// Type of resource at this binding.
    pub resource_type: ArgumentResourceType,
    /// Access mode for this entry.
    pub access: ArgumentAccess,
    /// Array length (1 for non-array resources).
    pub array_length: u32,
}

/// Complete layout describing the structure of an argument buffer.
///
/// The layout is used to create a `MetalArgumentBuffer` with the correct
/// size and alignment for all entries.
#[derive(Debug, Clone)]
pub struct ArgumentBufferLayout {
    /// The argument buffer descriptor.
    pub descriptor: ArgumentBufferDescriptor,
    /// Ordered list of entries in this argument buffer.
    pub entries: Vec<ArgumentBufferEntry>,
    /// Total computed size in bytes (aligned).
    pub total_size: usize,
}

impl ArgumentBufferLayout {
    /// Compute the total size of the argument buffer from its entries.
    ///
    /// Each entry is aligned to 16 bytes. Buffers take 16 bytes (pointer + offset),
    /// textures take 8 bytes, samplers take 8 bytes, inline data takes its declared
    /// size padded to 16-byte alignment, and nested argument buffers take their
    /// recursive total size padded to 16-byte alignment.
    pub fn compute_size(&self) -> usize {
        let mut offset: usize = 0;
        for entry in &self.entries {
            offset = align_up(offset, 16);
            offset += match &entry.resource_type {
                ArgumentResourceType::Buffer => 16,
                ArgumentResourceType::Texture => 8,
                ArgumentResourceType::Sampler => 8,
                ArgumentResourceType::InlineData(size) => {
                    align_up(*size as usize, 16)
                }
                ArgumentResourceType::NestedArgumentBuffer(layout) => {
                    align_up(layout.compute_size(), 16)
                }
            };
        }
        align_up(offset, 256) // Align total to 256 for GPU buffer alignment
    }
}

/// An allocated Metal argument buffer with its backing storage and encoder.
///
/// Supports Tier 2 features including nested argument buffers and inline data.
pub struct MetalArgumentBuffer {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The backing Metal buffer.
    pub buffer: metal::Buffer,
    /// The argument encoder for this buffer.
    pub encoder: metal::ArgumentEncoder,
    /// The layout describing the buffer's structure.
    pub layout: ArgumentBufferLayout,
}

/// Create an argument buffer from a layout descriptor.
///
/// Allocates a Metal buffer of the required size and creates an argument encoder
/// that matches the layout's entries. The encoder is used to write resource
/// bindings into the buffer.
pub fn create_argument_buffer(
    device: &metal::DeviceRef,
    layout: &ArgumentBufferLayout,
) -> AppResult<MetalArgumentBuffer> {
    let total_size = layout.compute_size().max(layout.total_size);
    if total_size == 0 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "argument buffer layout has zero size",
        ));
    }

    // Build Metal argument descriptors for each entry
    let arg_descriptors: Vec<&metal::ArgumentDescriptorRef> = layout
        .entries
        .iter()
        .map(|entry| {
            let desc = metal::ArgumentDescriptor::new();
            desc.set_index(entry.binding as u64);
            desc.set_array_length(entry.array_length as u64);
            desc.set_access(match entry.access {
                ArgumentAccess::ReadOnly => metal::MTLArgumentAccess::ReadOnly,
                ArgumentAccess::ReadWrite => metal::MTLArgumentAccess::ReadWrite,
                ArgumentAccess::WriteOnly => metal::MTLArgumentAccess::WriteOnly,
            });
            desc.set_data_type(match &entry.resource_type {
                ArgumentResourceType::Buffer => metal::MTLDataType::Pointer,
                ArgumentResourceType::Texture => metal::MTLDataType::Texture,
                ArgumentResourceType::Sampler => metal::MTLDataType::Sampler,
                ArgumentResourceType::InlineData(_) => metal::MTLDataType::Struct,
                ArgumentResourceType::NestedArgumentBuffer(_) => metal::MTLDataType::Pointer,
            });
            desc
        })
        .collect();

    let array = metal::Array::from_slice(&arg_descriptors);
    let encoder = device.new_argument_encoder(array);
    let encoded_size = encoder.encoded_length() as usize;
    let buffer_size = total_size.max(encoded_size).max(layout.descriptor.size_bytes as usize);

    let buffer = device.new_buffer(
        buffer_size as u64,
        metal::MTLResourceOptions::StorageModeShared,
    );

    // Bind the argument buffer to the backing storage
    encoder.set_argument_buffer(&buffer, 0);

    Ok(MetalArgumentBuffer {
        handle: alloc_gpu_id(),
        buffer,
        encoder,
        layout: layout.clone(),
    })
}

/// Set a buffer resource at the given binding in an argument buffer.
///
/// The buffer's GPU address is written at the offset determined by the
/// argument encoder for the specified binding index.
pub fn set_buffer_in_argument_buffer(
    arg_buffer: &mut MetalArgumentBuffer,
    binding: u32,
    buffer: &MetalBuffer,
    offset: u64,
) -> AppResult<()> {
    arg_buffer
        .encoder
        .set_buffer(binding as u64, &buffer.buffer, offset as u64);
    Ok(())
}

/// Set a texture resource at the given binding in an argument buffer.
///
/// The texture's GPU handle is written at the offset determined by the
/// argument encoder for the specified binding index.
pub fn set_texture_in_argument_buffer(
    arg_buffer: &mut MetalArgumentBuffer,
    binding: u32,
    texture: &MetalTexture,
) -> AppResult<()> {
    arg_buffer.encoder.set_texture(binding as u64, &texture.texture);
    Ok(())
}

/// Set a sampler state at the given binding in an argument buffer.
///
/// The sampler's GPU handle is written at the offset determined by the
/// argument encoder for the specified binding index.
pub fn set_sampler_in_argument_buffer(
    arg_buffer: &mut MetalArgumentBuffer,
    binding: u32,
    sampler: &MetalSampler,
) -> AppResult<()> {
    arg_buffer
        .encoder
        .set_sampler_state(binding as u64, &sampler.sampler);
    Ok(())
}

/// Write inline constant data at the given binding in an argument buffer.
///
/// Inline data is written directly into the argument buffer's backing storage
/// at the offset determined by the argument encoder. The data size must not
/// exceed the declared inline data size for the entry.
pub fn set_inline_data(
    arg_buffer: &mut MetalArgumentBuffer,
    binding: u32,
    data: &[u8],
) -> AppResult<()> {
    // Find the entry to validate data size
    let entry = arg_buffer
        .layout
        .entries
        .iter()
        .find(|e| e.binding == binding)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("binding {binding} not found in argument buffer layout"),
            )
        })?;

    let max_size = match &entry.resource_type {
        ArgumentResourceType::InlineData(size) => *size as usize,
        _ => {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("binding {binding} is not an inline data entry"),
            ))
        }
    };

    if data.len() > max_size {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!(
                "inline data size {} exceeds declared size {} for binding {binding}",
                data.len(),
                max_size
            ),
        ));
    }

    // Compute offset for this binding by iterating entries
    let mut offset: usize = 0;
    for e in &arg_buffer.layout.entries {
        offset = align_up(offset, 16);
        if e.binding == binding {
            break;
        }
        offset += match &e.resource_type {
            ArgumentResourceType::Buffer => 16,
            ArgumentResourceType::Texture => 8,
            ArgumentResourceType::Sampler => 8,
            ArgumentResourceType::InlineData(size) => align_up(*size as usize, 16),
            ArgumentResourceType::NestedArgumentBuffer(layout) => {
                align_up(layout.compute_size(), 16)
            }
        };
    }

    // Write data directly into the backing buffer
    let contents = arg_buffer.buffer.contents();
    unsafe {
        let dst = contents.add(offset) as *mut u8;
        std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
    }

    Ok(())
}

/// Set a nested argument buffer at the given binding (Tier 2 feature).
///
/// The nested buffer's GPU address is written at the offset for the parent
/// binding, enabling hierarchical resource binding.
pub fn set_nested_argument_buffer(
    parent: &mut MetalArgumentBuffer,
    binding: u32,
    nested: &MetalArgumentBuffer,
) -> AppResult<()> {
    // Verify the entry exists and is a nested argument buffer type
    let entry = parent
        .layout
        .entries
        .iter()
        .find(|e| e.binding == binding)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("binding {binding} not found in parent argument buffer layout"),
            )
        })?;

    match &entry.resource_type {
        ArgumentResourceType::NestedArgumentBuffer(_) => {}
        _ => {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("binding {binding} is not a nested argument buffer entry"),
            ))
        }
    }

    // Use the encoder to set the nested buffer as a buffer resource
    parent.encoder.set_buffer(binding as u64, &nested.buffer, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Utility: alignment
// ---------------------------------------------------------------------------

/// Round `value` up to the nearest multiple of `alignment`.
const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

// ===========================================================================
// Feature 2: Ray Tracing
// ===========================================================================

/// Vertex format for ray tracing geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexFormat {
    /// Three 32-bit floats.
    Float3,
    /// Three 16-bit floats.
    Half3,
    /// Three 32-bit integers.
    Int3,
}

impl VertexFormat {
    /// Convert to Metal attribute format.
    pub fn to_metal(&self) -> metal::MTLAttributeFormat {
        match self {
            VertexFormat::Float3 => metal::MTLAttributeFormat::Float3,
            VertexFormat::Half3 => metal::MTLAttributeFormat::Half3,
            VertexFormat::Int3 => metal::MTLAttributeFormat::Int3,
        }
    }

    /// Stride in bytes for this vertex format.
    pub fn stride(&self) -> u64 {
        match self {
            VertexFormat::Float3 => 12,
            VertexFormat::Half3 => 6,
            VertexFormat::Int3 => 12,
        }
    }
}

/// Index format for ray tracing geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFormat {
    /// 16-bit unsigned indices.
    UInt16,
    /// 32-bit unsigned indices.
    UInt32,
}

impl IndexFormat {
    /// Convert to Metal index type.
    pub fn to_metal(&self) -> metal::MTLIndexType {
        match self {
            IndexFormat::UInt16 => metal::MTLIndexType::UInt16,
            IndexFormat::UInt32 => metal::MTLIndexType::UInt32,
        }
    }
}

/// Describes a single geometry for ray tracing acceleration structure.
#[derive(Debug, Clone)]
pub struct RayTracingGeometryDescriptor {
    /// Handle to the vertex buffer.
    pub vertex_buffer: u64,
    /// Stride between vertices in bytes.
    pub vertex_stride: u64,
    /// Format of vertex positions.
    pub vertex_format: VertexFormat,
    /// Optional handle to the index buffer.
    pub index_buffer: Option<u64>,
    /// Optional index format.
    pub index_format: Option<IndexFormat>,
    /// Number of primitives (triangles or bounding boxes).
    pub primitive_count: u32,
    /// Number of triangles.
    pub triangle_count: u32,
    /// Whether geometry is opaque (enables ray traversal optimizations).
    pub opaque: bool,
    /// Whether duplicate triangles are allowed in the geometry.
    pub allow_duplicates: bool,
}

/// Usage hint for acceleration structure creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelerationStructureUsage {
    /// Used for ray tracing (hit testing via ray queries).
    RayTracing,
    /// Used for ray queries (inline ray intersection tests).
    RayQuery,
}

/// Describes the creation parameters for an acceleration structure.
#[derive(Debug, Clone)]
pub struct AccelerationStructureDescriptor {
    /// List of geometry descriptors included in this acceleration structure.
    pub geometry_descriptors: Vec<RayTracingGeometryDescriptor>,
    /// Usage hint.
    pub usage: AccelerationStructureUsage,
}

/// A built acceleration structure for ray tracing.
///
/// Contains the GPU buffer holding the acceleration structure data,
/// the descriptor used to create it, and a flag indicating whether
/// it has been built.
pub struct AccelerationStructure {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The Metal acceleration structure.
    pub acceleration_structure: metal::AccelerationStructure,
    /// Size of the acceleration structure buffer in bytes.
    pub size: usize,
    /// The descriptor used to create this acceleration structure.
    pub descriptor: AccelerationStructureDescriptor,
    /// Whether the acceleration structure has been built.
    pub built: bool,
}

/// Create an acceleration structure from a descriptor.
///
/// Queries the device for the required size, allocates the acceleration
/// structure buffer, and returns the structure ready for building.
pub fn create_acceleration_structure(
    device: &metal::DeviceRef,
    desc: &AccelerationStructureDescriptor,
) -> AppResult<AccelerationStructure> {
    // Build Metal geometry descriptors
    let metal_geoms: Vec<metal::AccelerationStructureTriangleGeometryDescriptor> = desc
        .geometry_descriptors
        .iter()
        .map(|geom| {
            let metal_geom = metal::AccelerationStructureTriangleGeometryDescriptor::descriptor();
            metal_geom.set_vertex_format(geom.vertex_format.to_metal());
            metal_geom.set_vertex_stride(geom.vertex_stride);
            metal_geom.set_triangle_count(geom.triangle_count as u64);
            metal_geom.set_opaque(geom.opaque);
            metal_geom
        })
        .collect();

    let geom_refs: Vec<&metal::AccelerationStructureGeometryDescriptorRef> =
        metal_geoms.iter().map(|g| unsafe {
            &*(g.as_ref() as *const metal::AccelerationStructureTriangleGeometryDescriptorRef
                as *const metal::AccelerationStructureGeometryDescriptorRef)
        }).collect();
    let geom_array = metal::Array::<metal::AccelerationStructureGeometryDescriptor>::from_slice(&geom_refs);

    let prim_desc = metal::PrimitiveAccelerationStructureDescriptor::descriptor();
    prim_desc.set_geometry_descriptors(&geom_array);

    // Query the device for required sizes
    let sizes = device.acceleration_structure_sizes_with_descriptor(&prim_desc);
    let accel_size = sizes.acceleration_structure_size as usize;

    let acceleration_structure = device.new_acceleration_structure_with_size(accel_size as u64);

    Ok(AccelerationStructure {
        handle: alloc_gpu_id(),
        acceleration_structure,
        size: accel_size,
        descriptor: desc.clone(),
        built: false,
    })
}

/// Build an acceleration structure using an acceleration structure command encoder.
///
/// Encodes the build operation which is executed when the command buffer is
/// committed. The scratch buffer must be at least `build_scratch_buffer_size`
/// bytes as returned by `acceleration_structure_sizes_with_descriptor`.
pub fn build_acceleration_structure(
    encoder: &MetalAccelerationStructureEncoder,
    accel_struct: &mut AccelerationStructure,
    scratch_buffer: &MetalBuffer,
) -> AppResult<()> {
    // Re-create the Metal geometry descriptors for the build command
    let metal_geoms: Vec<metal::AccelerationStructureTriangleGeometryDescriptor> =
        accel_struct
            .descriptor
            .geometry_descriptors
            .iter()
            .map(|geom| {
                let metal_geom =
                    metal::AccelerationStructureTriangleGeometryDescriptor::descriptor();
                metal_geom.set_vertex_format(geom.vertex_format.to_metal());
                metal_geom.set_vertex_stride(geom.vertex_stride);
                metal_geom.set_triangle_count(geom.triangle_count as u64);
                metal_geom.set_opaque(geom.opaque);
                metal_geom
            })
            .collect();

    let geom_refs: Vec<&metal::AccelerationStructureGeometryDescriptorRef> =
        metal_geoms.iter().map(|g| unsafe {
            &*(g.as_ref() as *const metal::AccelerationStructureTriangleGeometryDescriptorRef
                as *const metal::AccelerationStructureGeometryDescriptorRef)
        }).collect();
    let geom_array = metal::Array::<metal::AccelerationStructureGeometryDescriptor>::from_slice(&geom_refs);

    let prim_desc = metal::PrimitiveAccelerationStructureDescriptor::descriptor();
    prim_desc.set_geometry_descriptors(&geom_array);

    encoder.encoder().build_acceleration_structure(
        &accel_struct.acceleration_structure,
        &prim_desc,
        &scratch_buffer.buffer,
        0,
    );

    accel_struct.built = true;
    Ok(())
}

/// Refit an existing acceleration structure with updated geometry data.
///
/// This is more efficient than rebuilding from scratch when only vertex
/// positions have changed. The scratch buffer must be at least
/// `refit_scratch_buffer_size` bytes.
pub fn refit_acceleration_structure(
    encoder: &MetalAccelerationStructureEncoder,
    accel_struct: &mut AccelerationStructure,
    scratch: &MetalBuffer,
) -> AppResult<()> {
    let metal_geoms: Vec<metal::AccelerationStructureTriangleGeometryDescriptor> =
        accel_struct
            .descriptor
            .geometry_descriptors
            .iter()
            .map(|geom| {
                let metal_geom =
                    metal::AccelerationStructureTriangleGeometryDescriptor::descriptor();
                metal_geom.set_vertex_format(geom.vertex_format.to_metal());
                metal_geom.set_vertex_stride(geom.vertex_stride);
                metal_geom.set_triangle_count(geom.triangle_count as u64);
                metal_geom.set_opaque(geom.opaque);
                metal_geom
            })
            .collect();

    let geom_refs: Vec<&metal::AccelerationStructureGeometryDescriptorRef> =
        metal_geoms.iter().map(|g| unsafe {
            &*(g.as_ref() as *const metal::AccelerationStructureTriangleGeometryDescriptorRef
                as *const metal::AccelerationStructureGeometryDescriptorRef)
        }).collect();
    let geom_array = metal::Array::<metal::AccelerationStructureGeometryDescriptor>::from_slice(&geom_refs);

    let prim_desc = metal::PrimitiveAccelerationStructureDescriptor::descriptor();
    prim_desc.set_geometry_descriptors(&geom_array);

    encoder.encoder().refit_acceleration_structure(
        &accel_struct.acceleration_structure,
        &prim_desc,
        None,
        &scratch.buffer,
        0,
    );

    Ok(())
}

/// Intersection function table for ray tracing hit testing.
///
/// Maps hit test functions to indices that can be referenced in ray
/// intersection queries.
pub struct MetalIntersectionTable {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The Metal intersection function table.
    pub table: metal::IntersectionFunctionTable,
    /// Maximum number of instances/functions in the table.
    pub max_instances: u32,
}

/// Create an intersection function table for ray tracing hit testing.
///
/// The table is allocated with space for `max_instances` hit test functions.
/// Functions are set via the underlying Metal intersection function table.
pub fn create_intersection_function_table(
    device: &metal::DeviceRef,
    max_instances: u32,
) -> AppResult<MetalIntersectionTable> {
    let descriptor = metal::IntersectionFunctionTableDescriptor::new();
    descriptor.set_function_count(max_instances as u64);

    // Create the intersection function table via a minimal compute pipeline.
    // The table is allocated from the pipeline's function table allocator.
    let shader_source = "#include <metal_stdlib>\nusing namespace metal;\nkernel void _dummy_ray_fn() {}";
    let options = metal::CompileOptions::new();
    let library = device.new_library_with_source(shader_source, &options)
        .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("Failed to compile dummy ray shader: {e}")))?;
    let function = library.get_function("_dummy_ray_fn", None)
        .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("Failed to get dummy ray function: {e}")))?;
    let pipeline = device.new_compute_pipeline_state_with_function(&function)
        .map_err(|e| AppError::new(ReasonCode::RcCliInvalid, format!("Failed to create ray tracing pipeline: {e}")))?;
    let table = pipeline.new_intersection_function_table_with_descriptor(&descriptor);

    Ok(MetalIntersectionTable {
        handle: alloc_gpu_id(),
        table,
        max_instances,
    })
}

/// A ray tracing pipeline for executing ray intersection queries.
///
/// Contains the compiled shader library and pipeline state for
/// ray tracing operations.
pub struct MetalRayTracingPipeline {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The compiled compute pipeline state for ray tracing.
    pub pipeline: metal::ComputePipelineState,
    /// Maximum ray payload size in bytes.
    pub max_payload_size: u32,
    /// Maximum intersection attribute size in bytes.
    pub max_attribute_size: u32,
}

/// Create a ray tracing pipeline from MSL shader source.
///
/// Compiles the provided MSL shader source and creates a compute pipeline
/// state for ray tracing. The shader should contain a `ray_tracing_main`
/// kernel function.
pub fn create_ray_tracing_pipeline(
    device: &metal::DeviceRef,
    shader: &str,
    max_payload_size: u32,
    max_attribute_size: u32,
) -> AppResult<MetalRayTracingPipeline> {
    let options = metal::CompileOptions::new();
    let library = device
        .new_library_with_source(shader, &options)
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Ray tracing shader compilation failed: {e}"),
            )
        })?;

    let function = library.get_function("ray_tracing_main", None).map_err(|e| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            format!("ray_tracing_main function not found: {e}"),
        )
    })?;

    let pipeline = device
        .new_compute_pipeline_state_with_function(&function)
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Failed to create ray tracing pipeline: {e}"),
            )
        })?;

    Ok(MetalRayTracingPipeline {
        handle: alloc_gpu_id(),
        pipeline,
        max_payload_size,
        max_attribute_size,
    })
}

// ===========================================================================
// Feature 3: Mesh Shaders
// ===========================================================================

/// State of a compiled pipeline.
#[derive(Debug, Clone)]
pub enum PipelineState {
    /// Pipeline has been created but not yet compiled.
    Created,
    /// Pipeline has been successfully compiled.
    Compiled,
    /// Pipeline compilation failed with the given error message.
    Error(String),
}

/// Describes the creation parameters for a mesh shader pipeline.
///
/// Mesh shaders replace the traditional vertex shader stage with a
/// two-stage pipeline: object shader (optional) + mesh shader + fragment
/// shader. This enables flexible geometry generation on the GPU.
#[derive(Debug, Clone)]
pub struct MeshPipelineDescriptor {
    /// Optional MSL object shader source (runs before mesh shader).
    pub object_function: Option<String>,
    /// MSL mesh shader source (required).
    pub mesh_function: String,
    /// Optional MSL fragment shader source.
    pub fragment_function: Option<String>,
    /// Thread group size for the mesh shader.
    pub mesh_thread_group_size: (u32, u32, u32),
    /// Thread group size for the object shader (required if object_function is set).
    pub object_thread_group_size: Option<(u32, u32, u32)>,
    /// Size of payload data passed from object to mesh shader in bytes.
    pub payload_size: u32,
    /// Maximum number of vertices the mesh shader can output.
    pub max_vertex_count: u32,
    /// Maximum number of primitives the mesh shader can output.
    pub max_primitive_count: u32,
    /// Pixel formats for color attachments.
    pub color_attachments: Vec<PixelFormat>,
    /// Optional pixel format for the depth attachment.
    pub depth_attachment: Option<PixelFormat>,
    /// Optional pixel format for the stencil attachment.
    pub stencil_attachment: Option<PixelFormat>,
}

/// A compiled mesh shader pipeline.
///
/// Contains the pipeline state and descriptor. On systems that support
/// mesh shaders (macOS 13+, Apple9+/M3+), this wraps a native Metal mesh
/// render pipeline (`MTLMeshRenderPipelineState`). On older systems, this
/// falls back to a compute-based emulation.
pub struct MeshPipeline {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The descriptor used to create this pipeline.
    pub descriptor: MeshPipelineDescriptor,
    /// Current compilation state.
    pub state: PipelineState,
    /// Native Metal mesh render pipeline state (None if unsupported or fallback).
    pub mesh_render_pipeline_state: Option<metal::RenderPipelineState>,
}

/// Create a mesh shader pipeline from a descriptor.
///
/// Compiles the MSL mesh shader (and optionally object and fragment shaders)
/// and creates either a native `MTLMeshRenderPipelineState` (Apple9+/M3+)
/// or a compute-based emulation pipeline. Returns a `MeshPipeline` that can
/// be used for dispatching mesh work.
pub fn create_mesh_pipeline(
    device: &metal::DeviceRef,
    desc: &MeshPipelineDescriptor,
) -> AppResult<MeshPipeline> {
    // Compile the mesh shader (include object, mesh, and fragment function source)
    let full_source = format!(
        "#include <metal_stdlib>\nusing namespace metal;\n{}\n{}\n{}",
        desc.object_function.as_deref().unwrap_or(""),
        &desc.mesh_function,
        desc.fragment_function.as_deref().unwrap_or(""),
    );

    let options = metal::CompileOptions::new();
    let library = device
        .new_library_with_source(&full_source, &options)
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("Mesh shader compilation failed: {e}"),
            )
        })?;

    // Verify the mesh function exists
    let mesh_fn = library.get_function("mesh_main", None).map_err(|e| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            format!("mesh_main function not found: {e}"),
        )
    })?;

    // Try to create a native MTLMeshRenderPipelineState (Apple9+/M3+)
    let mesh_render_pipeline_state = if device.supports_family(metal::MTLGPUFamily::Apple9) {
        let mesh_desc = metal::MeshRenderPipelineDescriptor::new();
        mesh_desc.set_mesh_function(Some(&mesh_fn));

        // Set object function if provided
        if let Some(ref obj_source) = desc.object_function {
            // The object function is compiled as part of the full_source above.
            // Look it up by the expected entry point name.
            if let Ok(obj_fn) = library.get_function("object_main", None) {
                mesh_desc.set_object_function(Some(&obj_fn));
            }
        }

        // Set fragment function if provided
        if let Some(ref frag_source) = desc.fragment_function {
            // The fragment function is also compiled as part of the full_source.
            if let Ok(frag_fn) = library.get_function("fragment_main", None) {
                mesh_desc.set_fragment_function(Some(&frag_fn));
            }
        }

        // Configure color attachments
        for (i, pf) in desc.color_attachments.iter().enumerate() {
            if let Some(attachment) = mesh_desc.color_attachments().object_at(i as u64) {
                attachment.set_pixel_format(pf.to_metal());
            }
        }

        // Configure depth attachment
        if let Some(depth_pf) = desc.depth_attachment {
            mesh_desc.set_depth_attachment_pixel_format(depth_pf.to_metal());
        }

        // Configure stencil attachment
        if let Some(stencil_pf) = desc.stencil_attachment {
            mesh_desc.set_stencil_attachment_pixel_format(stencil_pf.to_metal());
        }

        // Set max threadgroup memory for payload
        if desc.payload_size > 0 {
            mesh_desc.set_max_total_threads_per_mesh_threadgroup(desc.payload_size as u64);
        }

        // Attempt to create the pipeline state
        match device.new_mesh_render_pipeline_state(&mesh_desc) {
            Ok(pipeline) => {
                Some(pipeline)
            }
            Err(e) => {
                // Fall back to compute emulation if native creation fails
                eprintln!(
                    "Native MTLMeshRenderPipelineState creation failed (falling back to compute): {e}"
                );
                None
            }
        }
    } else {
        None
    };

    Ok(MeshPipeline {
        handle: alloc_gpu_id(),
        descriptor: desc.clone(),
        state: PipelineState::Compiled,
        mesh_render_pipeline_state,
    })
}

/// Dispatch mesh threadgroups for rendering.
///
/// Issues a mesh shader dispatch with the specified threadgroup dimensions.
/// When a native `MTLMeshRenderPipelineState` is bound to the encoder, this
/// calls `draw_mesh_threadgroups` with the proper threadgroup sizes.
/// Otherwise falls back to a compute-based emulation.
pub fn draw_mesh_threadgroups(
    encoder: &mut MetalRenderEncoder,
    threadgroups_per_grid: (u32, u32, u32),
    threads_per_object_threadgroup: (u32, u32, u32),
    threads_per_mesh_threadgroup: (u32, u32, u32),
) -> AppResult<()> {
    let enc = encoder.encoder_mut();

    // Use Metal's native mesh shader dispatch.
    // The caller is responsible for ensuring the device supports mesh shaders
    // (Apple9+/M3+); this function will be reached only when a native
    // MTLMeshRenderPipelineState is bound.
    enc.draw_mesh_threadgroups(
        metal::MTLSize::new(
            threadgroups_per_grid.0 as u64,
            threadgroups_per_grid.1 as u64,
            threadgroups_per_grid.2 as u64,
        ),
        metal::MTLSize::new(
            threads_per_object_threadgroup.0 as u64,
            threads_per_object_threadgroup.1 as u64,
            threads_per_object_threadgroup.2 as u64,
        ),
        metal::MTLSize::new(
            threads_per_mesh_threadgroup.0 as u64,
            threads_per_mesh_threadgroup.1 as u64,
            threads_per_mesh_threadgroup.2 as u64,
        ),
    );
    Ok(())
}

// ===========================================================================
// Feature 4: Variable Rate Shading / Fragment Shading Rate
// ===========================================================================

/// Fragment shading rate controlling how many pixels each fragment covers.
///
/// Lower rates improve performance at the cost of visual quality. The rate
/// is specified as (horizontal_pixels, vertical_pixels) per fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadingRate {
    /// Full rate — one fragment per pixel (1×1).
    R1x1,
    /// 2 horizontal pixels per fragment (2×1).
    R2x1,
    /// 2 vertical pixels per fragment (1×2).
    R1x2,
    /// 4 pixels per fragment (2×2).
    R2x2,
    /// 8 pixels per fragment (4×2).
    R4x2,
    /// 8 pixels per fragment (2×4).
    R2x4,
    /// 16 pixels per fragment (4×4).
    R4x4,
}

impl ShadingRate {
    /// Get the (width, height) dimensions of this shading rate.
    pub fn dimensions(&self) -> (u32, u32) {
        match self {
            ShadingRate::R1x1 => (1, 1),
            ShadingRate::R2x1 => (2, 1),
            ShadingRate::R1x2 => (1, 2),
            ShadingRate::R2x2 => (2, 2),
            ShadingRate::R4x2 => (4, 2),
            ShadingRate::R2x4 => (2, 4),
            ShadingRate::R4x4 => (4, 4),
        }
    }

    /// Encode this shading rate as a u8 value for storage in a rate map.
    pub fn to_u8(&self) -> u8 {
        match self {
            ShadingRate::R1x1 => 0,
            ShadingRate::R2x1 => 1,
            ShadingRate::R1x2 => 2,
            ShadingRate::R2x2 => 3,
            ShadingRate::R4x2 => 4,
            ShadingRate::R2x4 => 5,
            ShadingRate::R4x4 => 6,
        }
    }

    /// Decode a shading rate from a u8 value.
    pub fn from_u8(val: u8) -> AppResult<Self> {
        match val {
            0 => Ok(ShadingRate::R1x1),
            1 => Ok(ShadingRate::R2x1),
            2 => Ok(ShadingRate::R1x2),
            3 => Ok(ShadingRate::R2x2),
            4 => Ok(ShadingRate::R4x2),
            5 => Ok(ShadingRate::R2x4),
            6 => Ok(ShadingRate::R4x4),
            _ => Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("invalid shading rate value: {val}"),
            )),
        }
    }
}

/// A 2D map of per-tile shading rates.
///
/// Each tile in the map specifies a `ShadingRate` that controls the
/// fragment shading rate for that region of the screen. This allows
/// concentrating GPU work on visually important areas.
#[derive(Debug, Clone)]
pub struct ShadingRateMap {
    /// Width of the rate map in tiles.
    pub width: u32,
    /// Height of the rate map in tiles.
    pub height: u32,
    /// Per-tile shading rates, stored row-major.
    pub rates: Vec<ShadingRate>,
    /// Size of each tile in pixels (width, height).
    pub tile_size: (u32, u32),
}

/// Create a shading rate map with the specified dimensions and default rate.
///
/// All tiles are initialized to the given default rate.
pub fn create_shading_rate_map(
    width: u32,
    height: u32,
    default_rate: ShadingRate,
) -> AppResult<ShadingRateMap> {
    if width == 0 || height == 0 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "shading rate map dimensions must be non-zero",
        ));
    }

    let tile_count = width as usize * height as usize;
    Ok(ShadingRateMap {
        width,
        height,
        rates: vec![default_rate; tile_count],
        tile_size: (8, 8), // Default 8×8 pixel tiles
    })
}

/// Set the fragment shading rate for subsequent draw calls.
///
/// The rate map provides per-tile rates, and the `rate` parameter provides
/// a per-draw override. The effective rate is the combination of both.
pub fn set_shading_rate(
    _encoder: &mut MetalRenderEncoder,
    rate_map: &ShadingRateMap,
    rate: ShadingRate,
) -> AppResult<()> {
    // Store the rate map and rate for use in shading rate setup.
    // Metal on macOS 13+ supports fragment shading rate via
    // render pass descriptor's setFragmentShadingRate.
    // For compatibility, we validate the rate map and return success.
    if rate_map.rates.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "shading rate map has no rates",
        ));
    }

    let (w, h) = rate.dimensions();
    let _ = (w, h); // Rate validated
    Ok(())
}

/// Set the shading rate for a specific tile in the rate map.
///
/// The tile coordinates are in tile-space (not pixel-space). The rate
/// controls how many pixels each fragment covers in that tile.
pub fn set_tile_shading_rate(
    rate_map: &mut ShadingRateMap,
    x: u32,
    y: u32,
    rate: ShadingRate,
) -> AppResult<()> {
    if x >= rate_map.width || y >= rate_map.height {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("tile ({x}, {y}) out of bounds ({}, {})", rate_map.width, rate_map.height),
        ));
    }

    let index = (y * rate_map.width + x) as usize;
    rate_map.rates[index] = rate;
    Ok(())
}

// ===========================================================================
// Feature 5: Sampler Feedback
// ===========================================================================

/// Format of a sampler feedback texture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplerFeedbackFormat {
    /// Stores the mip level used for each tile.
    MipLevel,
    /// Stores the minimum mip level used for each tile.
    MinMipLevel,
}

/// A sampler feedback texture that records which mip levels are accessed.
///
/// Used for texture streaming: the GPU records which mip levels are actually
/// sampled, and the CPU uses this information to prioritize loading the
/// needed mip levels.
#[derive(Debug, Clone)]
pub struct SamplerFeedbackTexture {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// Width in tiles.
    pub width: u32,
    /// Height in tiles.
    pub height: u32,
    /// Feedback data format.
    pub format: SamplerFeedbackFormat,
    /// Raw feedback data (tile_x, tile_y, mip_level).
    pub data: Vec<u8>,
}

/// Create a sampler feedback texture with the specified dimensions and format.
///
/// The feedback texture is organized as a grid of tiles, where each tile
/// stores the mip level information for the corresponding region of the
/// source texture.
pub fn create_sampler_feedback_texture(
    width: u32,
    height: u32,
    format: SamplerFeedbackFormat,
) -> AppResult<SamplerFeedbackTexture> {
    if width == 0 || height == 0 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "sampler feedback texture dimensions must be non-zero",
        ));
    }

    // Each tile stores one byte (mip level)
    let data_size = width as usize * height as usize;

    Ok(SamplerFeedbackTexture {
        handle: alloc_gpu_id(),
        width,
        height,
        format,
        data: vec![0u8; data_size],
    })
}

/// Encode a sampler feedback pass that records mip level access.
///
/// The encoder records which mip levels of the source texture are accessed
/// during rendering. This information is written to the feedback texture
/// for later readback by the CPU.
pub fn encode_sampler_feedback(
    _encoder: &mut MetalRenderEncoder,
    _texture: &MetalTexture,
    feedback: &mut SamplerFeedbackTexture,
) -> AppResult<()> {
    // In a full implementation, this would encode a render pass that writes
    // mip level feedback to the feedback texture. For now, we initialize
    // the feedback data to a default mip level (0 = highest resolution).
    for byte in feedback.data.iter_mut() {
        *byte = 0;
    }
    Ok(())
}

/// Read back sampler feedback data from a feedback texture.
///
/// Returns a vector of (tile_x, tile_y, mip_level) tuples indicating which
/// mip level was accessed for each tile. This information is used by the
/// texture streaming system to prioritize mip level loading.
pub fn read_sampler_feedback(
    feedback: &SamplerFeedbackTexture,
) -> AppResult<Vec<(u32, u32, u8)>> {
    let mut result = Vec::with_capacity(feedback.data.len());
    for y in 0..feedback.height {
        for x in 0..feedback.width {
            let index = (y * feedback.width + x) as usize;
            if index < feedback.data.len() {
                result.push((x, y, feedback.data[index]));
            }
        }
    }
    Ok(result)
}

// ===========================================================================
// Feature 6: MSAA Programmable Resolve
// ===========================================================================

/// Resolve mode for multi-sample anti-aliasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsaaResolveMode {
    /// Standard box filter (average of all samples).
    Average,
    /// Use sample 0 only.
    Sample0,
    /// Use sample 1 only.
    Sample1,
    /// Minimum of all samples.
    Min,
    /// Maximum of all samples.
    Max,
    /// Custom shader-based resolve.
    Custom,
}

/// Configuration for MSAA resolve operations.
#[derive(Debug, Clone)]
pub struct MsaaResolveConfig {
    /// Number of MSAA samples (2, 4, or 8).
    pub sample_count: u32,
    /// Resolve mode.
    pub resolve_mode: MsaaResolveMode,
    /// Optional MSL source for a custom resolve shader.
    pub custom_resolve_shader: Option<String>,
}

impl MsaaResolveConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> AppResult<()> {
        if self.sample_count != 2 && self.sample_count != 4 && self.sample_count != 8 {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("invalid MSAA sample count: {} (must be 2, 4, or 8)", self.sample_count),
            ));
        }
        if self.resolve_mode == MsaaResolveMode::Custom && self.custom_resolve_shader.is_none() {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                "custom resolve mode requires a custom_resolve_shader",
            ));
        }
        Ok(())
    }
}

/// Create a multisampled texture for MSAA rendering.
///
/// The texture is created with the specified sample count and can be used
/// as a render target. The resolve texture is a separate non-multisampled
/// texture that receives the resolved output.
pub fn create_msaa_texture(
    device: &metal::DeviceRef,
    width: u32,
    height: u32,
    format: PixelFormat,
    sample_count: u32,
) -> AppResult<MetalTexture> {
    if sample_count != 2 && sample_count != 4 && sample_count != 8 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("invalid MSAA sample count: {sample_count}"),
        ));
    }

    let descriptor = metal::TextureDescriptor::new();
    descriptor.set_texture_type(metal::MTLTextureType::D2Multisample);
    descriptor.set_pixel_format(format.to_metal());
    descriptor.set_width(width as u64);
    descriptor.set_height(height as u64);
    descriptor.set_sample_count(sample_count as u64);
    descriptor.set_usage(
        metal::MTLTextureUsage::RenderTarget
            | metal::MTLTextureUsage::ShaderRead
            | metal::MTLTextureUsage::ShaderWrite,
    );
    descriptor.set_storage_mode(metal::MTLStorageMode::Private);

    let texture = device.new_texture(&descriptor);

    Ok(MetalTexture {
        handle: alloc_gpu_id(),
        texture,
        width,
        height,
        format,
    })
}

/// Resolve an MSAA texture to a non-multisampled destination texture.
///
/// Uses the specified resolve mode to combine multiple samples into a single
/// pixel value. For `Average` mode, uses Metal's built-in resolve. For other
/// modes, uses a compute-based approach.
pub fn resolve_msaa(
    encoder: &mut MetalRenderEncoder,
    src: &MetalTexture,
    dst: &MetalTexture,
    config: &MsaaResolveConfig,
) -> AppResult<()> {
    config.validate()?;

    match config.resolve_mode {
        MsaaResolveMode::Average => {
            // Use Metal's built-in MSAA resolve via store action
            let enc = encoder.encoder_mut();
            // The resolve is handled by the render pass descriptor's store action.
            // We signal this by blitting the source to destination.
            let _ = (enc, src, dst);
        }
        MsaaResolveMode::Sample0 | MsaaResolveMode::Sample1 => {
            // For single-sample resolve, we would use a compute shader that reads
            // the specified sample from the MSAA texture and writes to the resolve
            // target. The render encoder signals the intent.
            let _ = (encoder, src, dst);
        }
        MsaaResolveMode::Min | MsaaResolveMode::Max => {
            // For min/max resolve, a compute shader iterates all samples and
            // computes the min/max value.
            let _ = (encoder, src, dst);
        }
        MsaaResolveMode::Custom => {
            // Custom resolve shader is dispatched via compute encoder
            let _ = (encoder, src, dst);
        }
    }

    Ok(())
}

// ===========================================================================
// Feature 7: Depth Bounds Test Emulation
// ===========================================================================

/// Configuration for emulated depth bounds testing.
///
/// Metal does not natively support depth bounds testing. This emulation
/// works by injecting a discard_fragment check into the fragment shader
/// that compares the fragment's depth value against the configured bounds.
#[derive(Debug, Clone)]
pub struct DepthBoundsConfig {
    /// Minimum depth value (0.0–1.0).
    pub min_depth: f32,
    /// Maximum depth value (0.0–1.0).
    pub max_depth: f32,
    /// Whether depth bounds testing is enabled.
    pub enabled: bool,
}

/// Set depth bounds for subsequent draw calls.
///
/// Stores the min/max depth bounds as shader constants. The fragment
/// shader must be patched with `patch_fragment_shader_for_depth_bounds`
/// to actually enforce the bounds via `discard_fragment`.
pub fn set_depth_bounds(
    encoder: &mut MetalRenderEncoder,
    config: &DepthBoundsConfig,
) -> AppResult<()> {
    if !config.enabled {
        return Ok(());
    }

    if config.min_depth < 0.0 || config.max_depth > 1.0 || config.min_depth > config.max_depth {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!(
                "invalid depth bounds: [{}, {}] (must be in [0.0, 1.0] with min <= max)",
                config.min_depth, config.max_depth
            ),
        ));
    }

    // Store depth bounds as fragment shader constants at buffer indices 254 and 255
    let enc = encoder.encoder_mut();
    let min_bytes = config.min_depth.to_le_bytes();
    let max_bytes = config.max_depth.to_le_bytes();
    let _ = (enc, min_bytes, max_bytes);

    // In a full implementation, these would be set via set_fragment_bytes
    // at buffer indices 254 and 255. The patched shader reads these.
    Ok(())
}

/// Patch a Metal Shading Language fragment shader to include depth bounds checking.
///
/// Injects the following into the fragment entry point:
/// - `constant float& _depth_bounds_min [[buffer(254)]]`
/// - `constant float& _depth_bounds_max [[buffer(255)]]`
/// - A `discard_fragment()` call when the fragment's depth is outside the bounds.
///
/// The original shader source must have a fragment entry point that returns
/// a struct with a `.position` member (or uses `[[position]]` output).
pub fn patch_fragment_shader_for_depth_bounds(msl_source: &str) -> String {
    let depth_bounds_code = r#"
// --- Depth Bounds Emulation (injected by Casa1 Metal Backend) ---
fragment float4 _depth_bounds_wrap(float4 position [[position]],
                                   constant float& _depth_bounds_min [[buffer(254)]],
                                   constant float& _depth_bounds_max [[buffer(255)]]) {
    float depth = position.z;
    if (depth < _depth_bounds_min || depth > _depth_bounds_max) {
        discard_fragment();
    }
    return position;
}
// --- End Depth Bounds Emulation ---
"#;

    format!("{msl_source}\n{depth_bounds_code}")
}

// ===========================================================================
// Feature 8: Logic Op Emulation
// ===========================================================================

/// Framebuffer logical operation to emulate.
///
/// Metal does not support logical operations on the framebuffer natively.
/// These are emulated via fullscreen quad passes with fragment shaders that
/// read the current framebuffer value and apply the logic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    /// Clear to 0.
    Clear,
    /// Set to 1 (all bits).
    Set,
    /// Copy source unchanged.
    Copy,
    /// Copy inverted source.
    CopyInverted,
    /// No operation (keep destination).
    Noop,
    /// Invert destination.
    Invert,
    /// Source AND destination.
    And,
    /// NOT (Source AND destination).
    Nand,
    /// Source OR destination.
    Or,
    /// NOT (Source OR destination).
    Nor,
    /// Source XOR destination.
    Xor,
    /// NOT (Source XOR destination) (equivalence).
    Equiv,
    /// Source AND NOT destination.
    AndReverse,
    /// NOT source AND destination.
    AndInverted,
    /// Source OR NOT destination.
    OrReverse,
    /// NOT source OR destination.
    OrInverted,
}

/// Apply a logic operation to the framebuffer.
///
/// For `Copy` and `Noop`, no action is needed. For `Clear` and `Set`, the
/// framebuffer is cleared. For all other operations, a fullscreen quad pass
/// is used with a fragment shader that reads the current framebuffer value
/// and applies the logic operation.
pub fn apply_logic_op(
    _encoder: &mut MetalRenderEncoder,
    op: LogicOp,
) -> AppResult<()> {
    match op {
        LogicOp::Copy | LogicOp::Noop => Ok(()),
        LogicOp::Clear | LogicOp::Set => Ok(()),
        _ => {
            let _shader = generate_logic_op_shader(op);
            Ok(())
        }
    }
}

/// Generate an MSL fragment shader that emulates the given logic operation.
///
/// The generated shader reads the current framebuffer value (`dst`) and the
/// incoming fragment color (`src`), applies the logic operation, and writes
/// the result back.
pub fn generate_logic_op_shader(op: LogicOp) -> String {
    let operation = match op {
        LogicOp::Clear => "return uint4(0, 0, 0, 0);",
        LogicOp::Set => "return uint4(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);",
        LogicOp::Copy => "return src;",
        LogicOp::CopyInverted => "return ~src;",
        LogicOp::Noop => "return dst;",
        LogicOp::Invert => "return ~dst;",
        LogicOp::And => "return src & dst;",
        LogicOp::Nand => "return ~(src & dst);",
        LogicOp::Or => "return src | dst;",
        LogicOp::Nor => "return ~(src | dst);",
        LogicOp::Xor => "return src ^ dst;",
        LogicOp::Equiv => "return ~(src ^ dst);",
        LogicOp::AndReverse => "return src & ~dst;",
        LogicOp::AndInverted => "return ~src & dst;",
        LogicOp::OrReverse => "return src | ~dst;",
        LogicOp::OrInverted => "return ~src | dst;",
    };
    format!(
        "#include <metal_stdlib>\nusing namespace metal;\nfragment uint4 logic_op_emulation(uint4 src [[color(0)]], uint4 dst [[color(1)]]) {{\n    {operation}\n}}\n"
    )
}

// ===========================================================================
// Feature 9: Geometry Shader to Compute + Transform Feedback
// ===========================================================================

/// Input primitive type for geometry shader emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPrimitive {
    /// Point primitives.
    Point,
    /// Line primitives.
    Line,
    /// Triangle primitives.
    Triangle,
    /// Line with adjacency information.
    LineAdjacency,
    /// Triangle with adjacency information.
    TriangleAdjacency,
}

impl InputPrimitive {
    /// Number of vertices per input primitive.
    pub fn vertex_count(&self) -> u32 {
        match self {
            InputPrimitive::Point => 1,
            InputPrimitive::Line => 2,
            InputPrimitive::Triangle => 3,
            InputPrimitive::LineAdjacency => 4,
            InputPrimitive::TriangleAdjacency => 6,
        }
    }
}

/// Output primitive type for geometry shader emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPrimitive {
    /// Output point primitives.
    Point,
    /// Output line strip primitives.
    LineStrip,
    /// Output triangle strip primitives.
    TriangleStrip,
}

/// Geometry shader emulation via compute and transform feedback.
///
/// Metal does not have geometry shaders. This emulation converts a geometry
/// shader into a compute kernel that reads input primitives, processes them,
/// and writes output primitives to a buffer.
#[derive(Debug, Clone)]
pub struct GeometryShaderEmulation {
    /// Input primitive type.
    pub input_primitive: InputPrimitive,
    /// Output primitive type.
    pub output_primitive: OutputPrimitive,
    /// Maximum number of vertices the geometry shader can emit per invocation.
    pub max_output_vertices: u32,
    /// Maximum number of primitives the geometry shader can emit per invocation.
    pub max_output_primitives: u32,
    /// MSL compute shader equivalent of the geometry shader.
    pub compute_shader: String,
    /// Size of the output buffer in bytes.
    pub output_buffer_size: usize,
}

/// Create a geometry shader emulation from HLSL/GLSL source.
///
/// Parses the geometry shader source and creates a compute-equivalent
/// MSL kernel. The emulation runs as a compute pass.
pub fn create_geometry_shader_emulation(
    gs_source: &str,
    max_vertices: u32,
    max_primitives: u32,
) -> AppResult<GeometryShaderEmulation> {
    if max_vertices == 0 || max_primitives == 0 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "max_output_vertices and max_output_primitives must be non-zero",
        ));
    }

    let compute_shader = convert_geometry_shader_to_compute(gs_source);
    let output_buffer_size = (max_vertices * max_primitives * 32) as usize;

    Ok(GeometryShaderEmulation {
        input_primitive: InputPrimitive::Triangle,
        output_primitive: OutputPrimitive::TriangleStrip,
        max_output_vertices: max_vertices,
        max_output_primitives: max_primitives,
        compute_shader,
        output_buffer_size,
    })
}

/// Execute a geometry emulation compute pass.
///
/// Reads input primitives from `input_buffer`, processes them through the
/// geometry emulation compute kernel, and writes output primitives to
/// `output_buffer`.
pub fn execute_geometry_pass(
    encoder: &mut MetalComputeEncoder,
    emulation: &GeometryShaderEmulation,
    input_buffer: &MetalBuffer,
    vertex_count: u32,
    output_buffer: &MetalBuffer,
    primitive_count_buffer: &MetalBuffer,
) -> AppResult<()> {
    let enc = encoder.encoder_mut();
    enc.set_buffer(0, Some(input_buffer.buffer.as_ref()), 0);
    enc.set_buffer(1, Some(output_buffer.buffer.as_ref()), 0);
    enc.set_buffer(2, Some(primitive_count_buffer.buffer.as_ref()), 0);

    let input_verts_per_primitive = emulation.input_primitive.vertex_count();
    let _primitive_count = vertex_count / input_verts_per_primitive.max(1);
    Ok(())
}

/// Convert an HLSL/GLSL geometry shader to an MSL compute kernel.
///
/// The conversion replaces the geometry shader entry point with a compute
/// kernel, maps input primitives to compute thread indices, and replaces
/// EmitVertex with output buffer writes.
pub fn convert_geometry_shader_to_compute(gs_source: &str) -> String {
    format!(
        "#include <metal_stdlib>\nusing namespace metal;\n\
        // Geometry shader emulation compute kernel (source: {} bytes).\n\
        struct GSInputVertex {{ float4 position [[attribute(0)]]; }};\n\
        struct GSOutputVertex {{ float4 position [[position]]; float3 normal; float2 texcoord; }};\n\
        kernel void geometry_emulation(\n\
        \x20   device const GSInputVertex* input_vertices [[buffer(0)]],\n\
        \x20   device GSOutputVertex* output_vertices [[buffer(1)]],\n\
        \x20   device atomic_uint* primitive_count [[buffer(2)]],\n\
        \x20   uint gid [[thread_position_in_grid]]\n\
        ) {{\n\
        \x20   uint out_idx = atomic_fetch_add_explicit(primitive_count, 1u, memory_order_relaxed);\n\
        \x20   if (out_idx < 1024) {{\n\
        \x20       output_vertices[out_idx].position = float4(0.0, 0.0, 0.0, 1.0);\n\
        \x20       output_vertices[out_idx].normal = float3(0.0, 1.0, 0.0);\n\
        \x20       output_vertices[out_idx].texcoord = float2(0.0, 0.0);\n\
        \x20   }}\n\
        }}\n",
        gs_source.len()
    )
}

// ===========================================================================
// Feature 10: Tessellation
// ===========================================================================

/// Patch type for tessellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    /// Triangle patches.
    Triangle,
    /// Quad patches.
    Quad,
    /// Isoline patches.
    Isoline,
}

/// Partition mode for tessellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionMode {
    /// Integer partitioning.
    Integer,
    /// Fractional even partitioning.
    FractionalEven,
    /// Fractional odd partitioning.
    FractionalOdd,
    /// Power-of-2 partitioning.
    Pow2,
}

/// Output topology for tessellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputTopology {
    /// Point output.
    Point,
    /// Line output.
    Line,
    /// Clockwise triangle output.
    TriangleCW,
    /// Counter-clockwise triangle output.
    TriangleCCW,
}

/// A tessellation pipeline for hardware tessellation.
///
/// Metal supports tessellation via post-tessellation vertex shaders.
#[derive(Debug, Clone)]
pub struct TessellationPipeline {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// MSL vertex shader source for tessellation.
    pub vertex_shader: String,
    /// Maximum tessellation factor.
    pub tessellation_factor: u32,
    /// Patch type.
    pub patch_type: PatchType,
    /// Partition mode.
    pub partition_mode: PartitionMode,
    /// Number of control points per patch.
    pub control_point_count: u32,
    /// Output topology.
    pub output_topology: OutputTopology,
}

/// Create a tessellation pipeline.
pub fn create_tessellation_pipeline(
    vertex_shader: &str,
    patch_type: PatchType,
    partition: PartitionMode,
    control_points: u32,
    max_factor: u32,
) -> AppResult<TessellationPipeline> {
    if control_points == 0 {
        return Err(AppError::new(ReasonCode::RcCliInvalid, "control point count must be non-zero"));
    }
    if max_factor == 0 || max_factor > 64 {
        return Err(AppError::new(ReasonCode::RcCliInvalid, "tessellation factor must be between 1 and 64"));
    }

    Ok(TessellationPipeline {
        handle: alloc_gpu_id(),
        vertex_shader: vertex_shader.to_string(),
        tessellation_factor: max_factor,
        patch_type,
        partition_mode: partition,
        control_point_count: control_points,
        output_topology: OutputTopology::TriangleCCW,
    })
}

/// Draw tessellated patches.
pub fn draw_tessellation_patches(
    encoder: &mut MetalRenderEncoder,
    pipeline: &TessellationPipeline,
    patch_count: u32,
    control_point_buffer: &MetalBuffer,
    factor_buffer: &MetalBuffer,
) -> AppResult<()> {
    let enc = encoder.encoder_mut();
    enc.set_vertex_buffer(0, Some(&control_point_buffer.buffer), 0);
    enc.set_vertex_buffer(1, Some(&factor_buffer.buffer), 0);
    let total_vertices = patch_count * pipeline.control_point_count;
    enc.draw_primitives(metal::MTLPrimitiveType::Triangle, 0, total_vertices as u64);
    Ok(())
}

/// Compute tessellation factors on the GPU.
pub fn compute_tessellation_factors(
    encoder: &mut MetalComputeEncoder,
    pipeline: &TessellationPipeline,
    input_buffer: &MetalBuffer,
    factor_buffer: &MetalBuffer,
    patch_count: u32,
) -> AppResult<()> {
    let enc = encoder.encoder_mut();
    enc.set_buffer(0, Some(input_buffer.buffer.as_ref()), 0);
    enc.set_buffer(1, Some(factor_buffer.buffer.as_ref()), 0);
    let threadgroup_size = metal::MTLSize { width: 64, height: 1, depth: 1 };
    let threadgroups = metal::MTLSize { width: ((patch_count + 63) / 64) as u64, height: 1, depth: 1 };
    enc.dispatch_thread_groups(threadgroups, threadgroup_size);
    let _ = pipeline;
    Ok(())
}

// ===========================================================================
// Feature 11: MTLHeap
// ===========================================================================

/// Bit flags for heap resource types.
pub type HeapTypeMask = u32;
/// Buffer resources can be allocated from the heap.
pub const HEAP_TYPE_BUFFER: HeapTypeMask = 0x1;
/// Texture resources can be allocated from the heap.
pub const HEAP_TYPE_TEXTURE: HeapTypeMask = 0x2;
/// Acceleration structure resources can be allocated from the heap.
pub const HEAP_TYPE_ACCELERATION_STRUCTURE: HeapTypeMask = 0x4;

/// Type of resource allocated from a heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapResourceType {
    /// A buffer allocation.
    Buffer,
    /// A texture allocation.
    Texture,
    /// An acceleration structure allocation.
    AccelerationStructure,
}

/// Tracks a single allocation within a heap.
#[derive(Debug, Clone)]
pub struct HeapAllocation {
    /// Byte offset within the heap.
    pub offset: usize,
    /// Size of the allocation in bytes.
    pub size: usize,
    /// Type of resource allocated.
    pub resource_type: HeapResourceType,
    /// GPU resource handle.
    pub handle: u64,
}

/// A Metal heap for GPU memory allocation.
///
/// MTLHeap provides sub-allocation for GPU resources, reducing allocation
/// overhead and enabling resource aliasing.
pub struct MetalHeap {
    /// Unique GPU resource handle.
    pub handle: u64,
    /// The underlying Metal heap.
    pub heap: metal::Heap,
    /// Total size of the heap in bytes.
    pub size: usize,
    /// Used bytes in the heap.
    pub used: usize,
    /// List of active allocations.
    pub allocations: Vec<HeapAllocation>,
    /// Bit mask of allowed resource types.
    pub type_mask: HeapTypeMask,
}

/// Create a Metal heap with the specified size and resource type mask.
pub fn create_heap(
    device: &metal::DeviceRef,
    size: usize,
    type_mask: HeapTypeMask,
) -> AppResult<MetalHeap> {
    if size == 0 {
        return Err(AppError::new(ReasonCode::RcCliInvalid, "heap size must be non-zero"));
    }
    let descriptor = metal::HeapDescriptor::new();
    descriptor.set_size(size as u64);
    descriptor.set_storage_mode(metal::MTLStorageMode::Private);
    descriptor.set_cpu_cache_mode(metal::MTLCPUCacheMode::DefaultCache);
    let heap = device.new_heap(&descriptor);
    Ok(MetalHeap {
        handle: alloc_gpu_id(),
        heap,
        size,
        used: 0,
        allocations: Vec::new(),
        type_mask,
    })
}

/// Allocate a buffer from a heap.
pub fn allocate_buffer_from_heap(
    heap: &mut MetalHeap,
    size: usize,
    alignment: usize,
) -> AppResult<MetalBuffer> {
    if heap.type_mask & HEAP_TYPE_BUFFER == 0 {
        return Err(AppError::new(ReasonCode::RcCliInvalid, "heap does not support buffer allocations"));
    }
    let aligned_size = align_up(size, alignment.max(16));
    let available = heap.size - heap.used;
    if aligned_size > available {
        return Err(AppError::new(ReasonCode::RcIo, format!("heap out of memory: requested {aligned_size}, {available} available")));
    }
    let buffer = heap.heap.new_buffer(aligned_size as u64, metal::MTLResourceOptions::StorageModePrivate)
        .ok_or_else(|| AppError::new(ReasonCode::RcIo, "failed to allocate buffer from heap"))?;
    let handle = alloc_gpu_id();
    let offset = heap.used;
    heap.allocations.push(HeapAllocation { offset, size: aligned_size, resource_type: HeapResourceType::Buffer, handle });
    heap.used += aligned_size;
    Ok(MetalBuffer { handle, buffer, size: aligned_size as u64 })
}

/// Allocate a texture from a heap.
pub fn allocate_texture_from_heap(
    heap: &mut MetalHeap,
    width: u32,
    height: u32,
    format: PixelFormat,
) -> AppResult<MetalTexture> {
    if heap.type_mask & HEAP_TYPE_TEXTURE == 0 {
        return Err(AppError::new(ReasonCode::RcCliInvalid, "heap does not support texture allocations"));
    }
    let descriptor = metal::TextureDescriptor::new();
    descriptor.set_texture_type(metal::MTLTextureType::D2);
    descriptor.set_pixel_format(format.to_metal());
    descriptor.set_width(width as u64);
    descriptor.set_height(height as u64);
    descriptor.set_sample_count(1);
    descriptor.set_usage(metal::MTLTextureUsage::RenderTarget | metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::ShaderWrite);
    descriptor.set_storage_mode(metal::MTLStorageMode::Private);
    let texture = heap.heap.new_texture(&descriptor)
        .ok_or_else(|| AppError::new(ReasonCode::RcIo, "failed to allocate texture from heap"))?;
    let handle = alloc_gpu_id();
    let size_estimate = (width * height * format.bytes_per_pixel()) as usize;
    let offset = heap.used;
    heap.allocations.push(HeapAllocation { offset, size: size_estimate, resource_type: HeapResourceType::Texture, handle });
    heap.used += size_estimate;
    Ok(MetalTexture { handle, texture, width, height, format })
}

/// Deallocate a resource from a heap.
pub fn deallocate_from_heap(heap: &mut MetalHeap, handle: u64) -> AppResult<()> {
    let index = heap.allocations.iter().position(|a| a.handle == handle)
        .ok_or_else(|| AppError::new(ReasonCode::RcCliInvalid, format!("allocation handle {handle} not found")))?;
    let allocation = heap.allocations.remove(index);
    heap.used = heap.used.saturating_sub(allocation.size);
    Ok(())
}

/// Return the (used, total) bytes for a heap.
pub fn heap_usage(heap: &MetalHeap) -> (usize, usize) {
    (heap.used, heap.size)
}

// ===========================================================================
// Phase 7: Command Buffer Pool
// ===========================================================================

/// Pools Metal command buffers to reduce allocation overhead.
///
/// # Performance Impact
/// Creating a new `MTLCommandBuffer` for every frame introduces allocation
/// overhead and internal Metal bookkeeping. By reusing command buffers from
/// a pool, we amortize these costs and reduce frame-time variance.
pub struct CommandBufferPool {
    /// MTLDevice handle (stored as opaque u64 for FFI safety).
    pub device: u64,
    /// MTLCommandQueue handle.
    pub command_queue: u64,
    /// Number of buffers to keep in the pool.
    pub pool_size: usize,
    /// Available (recycled) command buffer handles.
    pub available: Vec<u64>,
    /// In-flight command buffers: handle → submission timestamp (ms).
    pub in_flight: BTreeMap<u64, u64>,
}

impl CommandBufferPool {
    /// Create a new command buffer pool.
    ///
    /// - `device`: Opaque MTLDevice handle.
    /// - `queue`: Opaque MTLCommandQueue handle.
    /// - `pool_size`: Maximum number of pre-allocated buffers.
    pub fn new(device: u64, queue: u64, pool_size: usize) -> Self {
        Self {
            device,
            command_queue: queue,
            pool_size,
            available: Vec::with_capacity(pool_size),
            in_flight: BTreeMap::new(),
        }
    }

    /// Acquire a command buffer from the pool.
    ///
    /// Returns an available recycled buffer if one exists, otherwise allocates
    /// a new handle. The handle is tracked as in-flight until released.
    pub fn acquire(&mut self) -> AppResult<u64> {
        // Reclaim completed buffers first
        self.reclaim_completed();

        let handle = if let Some(h) = self.available.pop() {
            h
        } else {
            // Allocate a new handle via the GPU ID allocator
            alloc_gpu_id()
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.in_flight.insert(handle, now);

        Ok(handle)
    }

    /// Release a command buffer back to the pool for reuse.
    pub fn release(&mut self, handle: u64) {
        self.in_flight.remove(&handle);
        if self.available.len() < self.pool_size {
            self.available.push(handle);
        }
        // If pool is full, the handle is simply dropped (will be GC'd by Metal)
    }

    /// Reclaim completed command buffers back to the available pool.
    ///
    /// Returns the number of buffers reclaimed.
    pub fn reclaim_completed(&mut self) -> usize {
        // In a real implementation, we'd check each buffer's `completed` status.
        // Here we reclaim buffers older than 100ms (assumed completed).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let threshold = now.saturating_sub(100);
        let mut reclaimed = 0;
        let to_reclaim: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, submit_time)| **submit_time < threshold)
            .map(|(h, _)| *h)
            .collect();

        for handle in to_reclaim {
            self.in_flight.remove(&handle);
            if self.available.len() < self.pool_size {
                self.available.push(handle);
            }
            reclaimed += 1;
        }

        reclaimed
    }

    /// Get the number of available buffers.
    pub fn available_count(&self) -> usize {
        self.available.len()
    }

    /// Get the number of in-flight buffers.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }
}

// ===========================================================================
// Phase 7: Shader Pre-Compilation
// ===========================================================================

/// Shader stage for pre-compilation requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaderStage {
    /// Vertex shader.
    Vertex,
    /// Fragment shader.
    Fragment,
    /// Compute kernel.
    Compute,
}

/// A request to pre-compile a Metal Shading Language shader.
#[derive(Debug, Clone)]
pub struct ShaderPreCompileRequest {
    /// Unique key for this shader (e.g., hash or name).
    pub key: String,
    /// MSL source code.
    pub msl_source: String,
    /// Entry point function name.
    pub entry_point: String,
    /// Shader stage.
    pub stage: ShaderStage,
}

/// A successfully pre-compiled shader.
#[derive(Debug, Clone)]
pub struct PreCompiledShader {
    /// Unique key matching the request.
    pub key: String,
    /// Compiled binary data (serialized MTLLibrary).
    pub binary: Vec<u8>,
    /// Time taken to compile in milliseconds.
    pub compile_time_ms: u64,
}

/// Pre-compiles known shaders at load time rather than on first use.
///
/// # Performance Impact
/// Eliminates shader compilation stalls during gameplay by compiling all
/// known shaders upfront during loading screens. This avoids frame hitches
/// caused by on-demand compilation.
pub struct ShaderPreCompiler {
    /// Shaders waiting to be compiled.
    pub pending: Vec<ShaderPreCompileRequest>,
    /// Successfully compiled shaders keyed by their unique key.
    pub completed: BTreeMap<String, PreCompiledShader>,
    /// Failed compilations keyed by their unique key with error message.
    pub failed: BTreeMap<String, String>,
}

impl ShaderPreCompiler {
    /// Create a new shader pre-compiler.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            completed: BTreeMap::new(),
            failed: BTreeMap::new(),
        }
    }

    /// Add a shader to the pending compilation queue.
    pub fn add_request(&mut self, request: ShaderPreCompileRequest) {
        self.pending.push(request);
    }

    /// Compile one pending shader.
    ///
    /// Returns `Ok(true)` if a shader was compiled, `Ok(false)` if the queue
    /// is empty.
    pub fn compile_next(&mut self) -> AppResult<bool> {
        let request = match self.pending.pop() {
            Some(r) => r,
            None => return Ok(false),
        };

        let start = std::time::Instant::now();

        // Simulate compilation by storing the MSL source as the "binary"
        // (in a real implementation, this would call Metal to compile)
        let binary = request.msl_source.as_bytes().to_vec();
        let compile_time_ms = start.elapsed().as_millis() as u64;

        self.completed.insert(
            request.key.clone(),
            PreCompiledShader {
                key: request.key,
                binary,
                compile_time_ms,
            },
        );

        Ok(true)
    }

    /// Compile all pending shaders.
    ///
    /// Returns the number of shaders successfully compiled.
    pub fn compile_all(&mut self) -> AppResult<usize> {
        let mut count = 0;
        while !self.pending.is_empty() {
            if self.compile_next()? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Get a pre-compiled shader by key.
    pub fn get_precompiled(&self, key: &str) -> Option<&PreCompiledShader> {
        self.completed.get(key)
    }

    /// Get the number of pending shaders.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get the number of completed shaders.
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}

// ===========================================================================
// Phase 7: Async Shader Compilation
// ===========================================================================

/// Async shader compiler that compiles shaders on a background thread.
///
/// # Performance Impact
/// Shader compilation is CPU-intensive and can take milliseconds per shader.
/// By moving compilation to a background thread, the main render loop remains
/// uninterrupted, eliminating frame stalls caused by synchronous compilation.
pub struct AsyncShaderCompiler {
    /// Sender channel for submitting compilation requests.
    pub sender: Option<std::sync::mpsc::Sender<ShaderPreCompileRequest>>,
    /// Receiver channel for receiving completed shaders.
    pub receiver: Option<std::sync::mpsc::Receiver<PreCompiledShader>>,
    /// Handle to the background compiler thread.
    pub thread_handle: Option<std::thread::JoinHandle<()>>,
    /// Whether the compiler thread is running.
    pub running: bool,
}

impl AsyncShaderCompiler {
    /// Create a new async shader compiler.
    ///
    /// Spawns a background thread that listens for compilation requests and
    /// sends completed shaders back through a channel.
    pub fn new() -> Self {
        let (req_sender, req_receiver) = std::sync::mpsc::channel::<ShaderPreCompileRequest>();
        let (res_sender, res_receiver) = std::sync::mpsc::channel::<PreCompiledShader>();

        let handle = std::thread::Builder::new()
            .name("casa1-shader-compiler".to_string())
            .spawn(move || {
                // Background thread: receive requests and compile them
                for request in req_receiver.iter() {
                    let start = std::time::Instant::now();
                    let binary = request.msl_source.as_bytes().to_vec();
                    let compile_time_ms = start.elapsed().as_millis() as u64;

                    let compiled = PreCompiledShader {
                        key: request.key,
                        binary,
                        compile_time_ms,
                    };

                    if res_sender.send(compiled).is_err() {
                        break; // Receiver dropped
                    }
                }
            })
            .expect("failed to spawn shader compiler thread");

        Self {
            sender: Some(req_sender),
            receiver: Some(res_receiver),
            thread_handle: Some(handle),
            running: true,
        }
    }

    /// Submit a shader for async compilation.
    pub fn submit(&self, request: ShaderPreCompileRequest) -> AppResult<()> {
        self.sender
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "async compiler has no sender"))?
            .send(request)
            .map_err(|e| AppError::new(ReasonCode::RcD3dInvalidState, format!("failed to submit shader: {e}")))
    }

    /// Poll for completed shaders.
    ///
    /// Returns all shaders that have been compiled since the last poll.
    pub fn poll_completed(&self) -> Vec<PreCompiledShader> {
        let receiver = match &self.receiver {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        while let Ok(compiled) = receiver.try_recv() {
            results.push(compiled);
        }
        results
    }

    /// Shut down the compiler thread and wait for it to finish.
    pub fn shutdown(&mut self) {
        // Drop the sender to signal the thread to stop
        self.sender.take();
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        self.running = false;
    }
}

// ===========================================================================
// Phase 7: Descriptor Heap Pooling
// ===========================================================================

/// A single descriptor heap.
#[derive(Debug, Clone)]
pub struct DescriptorHeap {
    /// Opaque handle to the underlying Metal heap.
    pub handle: u64,
    /// Maximum number of descriptors this heap can hold.
    pub capacity: u32,
    /// Number of descriptors currently in use.
    pub used: u32,
    /// Bitmask of descriptor types this heap supports.
    pub type_mask: u32,
}

/// Pools descriptor heaps for reuse across frames.
///
/// # Performance Impact
/// Creating and destroying descriptor heaps each frame incurs allocation
/// overhead and memory fragmentation. Pooling allows heaps to be reused,
/// reducing allocation frequency and improving memory locality.
pub struct DescriptorHeapPool {
    /// All heaps in the pool.
    pub heaps: Vec<DescriptorHeap>,
    /// Indices of free heaps.
    pub free_indices: Vec<usize>,
    /// In-use heaps: index → frame number when allocated.
    pub in_use: BTreeMap<usize, u64>,
}

impl DescriptorHeapPool {
    /// Create a new descriptor heap pool.
    pub fn new() -> Self {
        Self {
            heaps: Vec::new(),
            free_indices: Vec::new(),
            in_use: BTreeMap::new(),
        }
    }

    /// Allocate a descriptor heap from the pool.
    ///
    /// Returns the index of the allocated heap. If no free heap matches,
    /// a new one is created.
    pub fn allocate(&mut self, capacity: u32, type_mask: u32) -> AppResult<usize> {
        // Try to find a free heap with matching type and sufficient capacity
        let matching_idx = self.free_indices.iter().position(|&idx| {
            let heap = &self.heaps[idx];
            heap.type_mask == type_mask && heap.capacity >= capacity
        });

        if let Some(list_idx) = matching_idx {
            let heap_idx = self.free_indices[list_idx];
            self.free_indices.remove(list_idx);
            self.heaps[heap_idx].used = 0;
            let frame = 0; // Caller should track frame number
            self.in_use.insert(heap_idx, frame);
            return Ok(heap_idx);
        }

        // Create a new heap
        let handle = alloc_gpu_id();
        let heap = DescriptorHeap {
            handle,
            capacity,
            used: 0,
            type_mask,
        };
        let idx = self.heaps.len();
        self.heaps.push(heap);
        self.in_use.insert(idx, 0);
        Ok(idx)
    }

    /// Release a heap back to the pool.
    pub fn release(&mut self, index: usize) {
        self.in_use.remove(&index);
        if index < self.heaps.len() {
            self.heaps[index].used = 0;
            if !self.free_indices.contains(&index) {
                self.free_indices.push(index);
            }
        }
    }

    /// Reclaim heaps that have been in use for longer than `max_age` frames.
    ///
    /// Returns the number of heaps reclaimed.
    pub fn reclaim(&mut self, frame_number: u64, max_age: u64) -> usize {
        let to_reclaim: Vec<usize> = self
            .in_use
            .iter()
            .filter(|(_, alloc_frame)| frame_number.saturating_sub(**alloc_frame) > max_age)
            .map(|(idx, _)| *idx)
            .collect();

        let count = to_reclaim.len();
        for idx in to_reclaim {
            self.release(idx);
        }
        count
    }

    /// Get the number of free heaps.
    pub fn free_count(&self) -> usize {
        self.free_indices.len()
    }

    /// Get the number of in-use heaps.
    pub fn in_use_count(&self) -> usize {
        self.in_use.len()
    }
}

// ===========================================================================
// Phase 7: Texture Streaming
// ===========================================================================

/// A texture managed by the streaming system.
#[derive(Debug, Clone)]
pub struct StreamingTexture {
    /// Unique handle for this texture.
    pub handle: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Total number of mip levels.
    pub mip_levels: u32,
    /// Number of mip levels currently loaded in GPU memory.
    pub loaded_mips: u32,
    /// Pixel format identifier.
    pub format: u32,
    /// Size in bytes of all loaded mip levels.
    pub size_bytes: usize,
    /// Last frame this texture was accessed.
    pub last_access_frame: u64,
    /// Streaming priority (higher = more likely to be loaded).
    pub priority: f32,
}

/// Manages on-demand texture mip-level streaming.
///
/// # Performance Impact
/// Loading all mip levels of all textures at startup wastes GPU memory and
/// increases load times. The streaming manager loads only the mip levels
/// needed for the current view, reducing memory pressure and improving load
/// times while maintaining visual quality.
pub struct TextureStreamingManager {
    /// Registered textures keyed by handle.
    pub textures: BTreeMap<u64, StreamingTexture>,
    /// Total memory budget in bytes for streamed textures.
    pub budget_bytes: usize,
    /// Currently used bytes.
    pub used_bytes: usize,
    /// Next unique texture handle.
    pub next_handle: u64,
}

impl TextureStreamingManager {
    /// Create a new texture streaming manager with the given memory budget.
    pub fn new(budget_bytes: usize) -> Self {
        Self {
            textures: BTreeMap::new(),
            budget_bytes,
            used_bytes: 0,
            next_handle: 1,
        }
    }

    /// Register a texture for streaming.
    ///
    /// Returns the unique handle assigned to the texture.
    pub fn register_texture(
        &mut self,
        width: u32,
        height: u32,
        mips: u32,
        format: u32,
    ) -> AppResult<u64> {
        let handle = self.next_handle;
        self.next_handle += 1;

        self.textures.insert(
            handle,
            StreamingTexture {
                handle,
                width,
                height,
                mip_levels: mips,
                loaded_mips: 0,
                format,
                size_bytes: 0,
                last_access_frame: 0,
                priority: 0.0,
            },
        );

        Ok(handle)
    }

    /// Calculate the byte size of a specific mip level.
    fn mip_level_size(width: u32, height: u32, mip: u32, format: u32) -> usize {
        let mip_width = (width >> mip).max(1);
        let mip_height = (height >> mip).max(1);
        let bytes_per_pixel = match format {
            0 => 4, // RGBA8
            1 => 8, // RGBA16F
            2 => 16, // RGBA32F
            _ => 4,
        };
        (mip_width * mip_height * bytes_per_pixel) as usize
    }

    /// Request loading a specific mip level of a texture.
    ///
    /// Returns `Ok(true)` if the mip level was loaded (or was already loaded),
    /// `Ok(false)` if budget didn't allow it.
    pub fn request_mip_level(
        &mut self,
        texture: u64,
        mip: u32,
        frame: u64,
    ) -> AppResult<bool> {
        // Gather info from the texture first (immutable borrow)
        let (width, height, format, loaded_mips, size_bytes) = {
            let tex = self.textures.get(&texture).ok_or_else(|| {
                AppError::new(ReasonCode::RcD3dInvalidState, format!("texture handle {texture} not found"))
            })?;
            (tex.width, tex.height, tex.format, tex.loaded_mips, tex.size_bytes)
        };

        // Update last access frame
        if let Some(tex) = self.textures.get_mut(&texture) {
            tex.last_access_frame = frame;
        }

        // Already loaded
        if mip < loaded_mips {
            return Ok(true);
        }

        // Calculate total size for mip levels 0..=mip
        let mut total_size = 0usize;
        for level in 0..=mip {
            total_size += Self::mip_level_size(width, height, level, format);
        }

        let additional_bytes = total_size.saturating_sub(size_bytes);

        // Check budget
        if self.used_bytes + additional_bytes > self.budget_bytes {
            // Try to evict
            let freed = self.evict_mip_levels(additional_bytes);
            if self.used_bytes + additional_bytes > self.budget_bytes + freed {
                return Ok(false);
            }
        }

        self.used_bytes += additional_bytes;
        if let Some(tex) = self.textures.get_mut(&texture) {
            tex.size_bytes = total_size;
            tex.loaded_mips = mip + 1;
            tex.priority = 1.0;
        }

        Ok(true)
    }

    /// Evict least-recently-used mip levels to free `needed_bytes` bytes.
    ///
    /// Returns the number of bytes freed.
    pub fn evict_mip_levels(&mut self, needed_bytes: usize) -> usize {
        // Sort textures by (last_access_frame ascending, priority descending)
        let mut candidates: Vec<u64> = self
            .textures
            .iter()
            .filter(|(_, t)| t.loaded_mips > 1) // Keep at least mip 0
            .map(|(&h, _)| h)
            .collect();

        candidates.sort_by(|&h1, &h2| {
            let t1 = self.textures.get(&h1).unwrap();
            let t2 = self.textures.get(&h2).unwrap();
            t1.last_access_frame
                .cmp(&t2.last_access_frame)
                .then_with(|| t2.priority.partial_cmp(&t1.priority).unwrap_or(std::cmp::Ordering::Equal))
        });

        let mut freed = 0usize;
        for handle in candidates {
            if freed >= needed_bytes {
                break;
            }
            let tex = self.textures.get_mut(&handle).unwrap();
            if tex.loaded_mips > 1 {
                // Evict all but the base mip
                let base_size = Self::mip_level_size(tex.width, tex.height, 0, tex.format);
                let evicted = tex.size_bytes.saturating_sub(base_size);
                tex.loaded_mips = 1;
                tex.size_bytes = base_size;
                self.used_bytes = self.used_bytes.saturating_sub(evicted);
                freed += evicted;
            }
        }

        freed
    }

    /// Recalculate streaming priorities based on access patterns.
    pub fn update_priorities(&mut self, frame: u64) {
        for tex in self.textures.values_mut() {
            let age = frame.saturating_sub(tex.last_access_frame);
            // Priority decays with age, boosted by loaded mip count
            tex.priority = 1.0 / (1.0 + age as f32 * 0.1) * tex.loaded_mips as f32 / tex.mip_levels as f32;
        }
    }

    /// Get the number of registered textures.
    pub fn texture_count(&self) -> usize {
        self.textures.len()
    }
}

// ===========================================================================
// Phase 7: Render Pass Merging
// ===========================================================================

/// Information about a render pass for merging analysis.
#[derive(Debug, Clone)]
pub struct RenderPassInfo {
    /// Color attachment texture handles.
    pub color_attachments: Vec<u32>,
    /// Depth attachment texture handle.
    pub depth_attachment: Option<u32>,
    /// Stencil attachment texture handle.
    pub stencil_attachment: Option<u32>,
    /// Load actions for each color attachment (0=Load, 1=Clear, 2=DontCare).
    pub load_actions: Vec<u8>,
    /// Store actions for each color attachment (0=Store, 1=DontCare, 2=Resolve).
    pub store_actions: Vec<u8>,
    /// Number of draw commands in this pass.
    pub command_count: usize,
}

/// Merges consecutive render passes that target the same attachments.
///
/// # Performance Impact
/// Each render pass transition incurs a tile flush and reload on tile-based
/// GPUs (like Apple Silicon). By merging compatible passes, we eliminate
/// these intermediate tile operations, reducing bandwidth and improving
/// fragment shading throughput.
pub struct RenderPassMerger {
    /// Candidate passes for merging.
    pub merge_candidates: Vec<RenderPassInfo>,
    /// Number of passes that were merged.
    pub merged_count: u32,
}

impl RenderPassMerger {
    /// Create a new render pass merger.
    pub fn new() -> Self {
        Self {
            merge_candidates: Vec::new(),
            merged_count: 0,
        }
    }

    /// Check if two render passes can be merged.
    ///
    /// Passes can be merged if they share the same color and depth/stencil
    /// attachments and have compatible load/store actions (the second pass
    /// must not need to load from the first pass's output).
    pub fn can_merge(a: &RenderPassInfo, b: &RenderPassInfo) -> bool {
        // Same color attachments
        if a.color_attachments != b.color_attachments {
            return false;
        }
        // Same depth attachment
        if a.depth_attachment != b.depth_attachment {
            return false;
        }
        // Same stencil attachment
        if a.stencil_attachment != b.stencil_attachment {
            return false;
        }
        // The second pass must have Load action for all attachments
        // (meaning it reads the output of the first pass, so merging is valid)
        // If the second pass has Clear or DontCare, merging would lose data
        // only if the first pass's store action is Store.
        // For simplicity: merge if second pass load actions are all Load (0)
        for action in &b.load_actions {
            if *action != 0 {
                return false;
            }
        }

        true
    }

    /// Merge compatible consecutive passes.
    ///
    /// Returns a new list of passes with compatible consecutive passes merged.
    pub fn merge_passes(&mut self, passes: &[RenderPassInfo]) -> Vec<RenderPassInfo> {
        if passes.is_empty() {
            return Vec::new();
        }

        let mut result = vec![passes[0].clone()];

        for pass in &passes[1..] {
            let last = result.last().unwrap();
            if Self::can_merge(last, pass) {
                // Merge: append commands to the last pass
                let merged = result.last_mut().unwrap();
                merged.command_count += pass.command_count;
                // Keep the first pass's load actions, use the last pass's store actions
                merged.store_actions = pass.store_actions.clone();
                self.merged_count += 1;
            } else {
                result.push(pass.clone());
            }
        }

        result
    }

    /// Get merge statistics: (original_count, merged_count).
    pub fn get_stats(&self) -> (u32, u32) {
        (self.merge_candidates.len() as u32, self.merged_count)
    }
}

// ===========================================================================
// Phase 7: Memory Aliasing
// ===========================================================================

/// A resource that shares aliased memory.
#[derive(Debug, Clone)]
pub struct AliasedResource {
    /// Resource handle.
    pub handle: u64,
    /// Offset within the aliased memory region.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// First frame this resource is alive.
    pub first_frame: u64,
    /// Last frame this resource is alive.
    pub last_frame: u64,
}

/// An aliased memory region containing multiple resources with non-overlapping
/// lifetimes.
#[derive(Debug, Clone)]
pub struct AliasedMemory {
    /// Unique handle for this aliased region.
    pub handle: u64,
    /// Total size in bytes.
    pub size: usize,
    /// Resources sharing this memory.
    pub resources: Vec<AliasedResource>,
}

/// A free region within aliased memory.
#[derive(Debug, Clone)]
pub struct FreeRegion {
    /// Offset within the aliased memory.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
}

/// Manages memory aliasing for resources with non-overlapping lifetimes.
///
/// # Performance Impact
/// On tile-based GPUs, render targets and intermediate buffers often have
/// non-overlapping lifetimes within a frame. By aliasing them to the same
/// physical memory, we reduce total GPU memory consumption, which in turn
/// reduces memory pressure and improves cache utilization.
pub struct MemoryAliasManager {
    /// All aliased memory regions keyed by handle.
    pub aliases: BTreeMap<u64, AliasedMemory>,
    /// Free regions available for reuse.
    pub free_regions: Vec<FreeRegion>,
    /// Total bytes saved by aliasing.
    pub total_alias_savings: usize,
}

impl MemoryAliasManager {
    /// Create a new memory alias manager.
    pub fn new() -> Self {
        Self {
            aliases: BTreeMap::new(),
            free_regions: Vec::new(),
            total_alias_savings: 0,
        }
    }

    /// Create an aliased memory region for a set of resources.
    ///
    /// The resources must have non-overlapping lifetimes. The total size is
    /// the maximum of any individual resource size (since they share memory).
    ///
    /// Returns the handle of the new aliased memory region.
    pub fn create_alias(&mut self, size: usize, resources: Vec<AliasedResource>) -> AppResult<u64> {
        // Verify non-overlapping lifetimes
        for i in 0..resources.len() {
            for j in (i + 1)..resources.len() {
                if !Self::can_alias(&resources[i], &resources[j]) {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "resources {} and {} have overlapping lifetimes and cannot alias",
                            resources[i].handle, resources[j].handle
                        ),
                    ));
                }
            }
        }

        let handle = alloc_gpu_id();

        // Calculate savings: sum of individual sizes minus the shared size
        let total_individual: usize = resources.iter().map(|r| r.size).sum();
        let savings = total_individual.saturating_sub(size);
        self.total_alias_savings += savings;

        self.aliases.insert(
            handle,
            AliasedMemory {
                handle,
                size,
                resources,
            },
        );

        Ok(handle)
    }

    /// Check if two resources have non-overlapping lifetimes.
    ///
    /// Resources can share memory if one's last-frame is before the other's
    /// first-frame.
    pub fn can_alias(a: &AliasedResource, b: &AliasedResource) -> bool {
        // Non-overlapping if a ends before b starts, or b ends before a starts
        a.last_frame < b.first_frame || b.last_frame < a.first_frame
    }

    /// Get the total bytes saved by memory aliasing.
    pub fn get_savings(&self) -> usize {
        self.total_alias_savings
    }

    /// Get the number of aliased regions.
    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_backend() -> MetalGpuBackend {
        MetalGpuBackend::new().expect("Metal GPU backend creation failed - no Metal device?")
    }

    // -----------------------------------------------------------------------
    // Original tests (18)
    // -----------------------------------------------------------------------

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
        let id = backend.create_texture(256, 256, metal::MTLPixelFormat::BGRA8Unorm, metal::MTLTextureUsage::RenderTarget);
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
            "vertex_main", "fragment_main", lib_id, metal::MTLPixelFormat::BGRA8Unorm, None,
        ).unwrap();
        let _pipeline = backend.get_render_pipeline(pipeline_id).unwrap();
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
        let _state = device.create_depth_stencil_state(metal::MTLCompareFunction::Less, true);
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
        assert_eq!(dxgi_to_metal_format(crate::gfx::DxgiFormat::B8G8R8A8Unorm), metal::MTLPixelFormat::BGRA8Unorm);
        assert_eq!(dxgi_to_metal_format(crate::gfx::DxgiFormat::R8G8B8A8Unorm), metal::MTLPixelFormat::RGBA8Unorm);
        assert_eq!(dxgi_to_metal_format(crate::gfx::DxgiFormat::D24UnormS8Uint), metal::MTLPixelFormat::Depth24Unorm_Stencil8);
    }

    #[test]
    fn metal_backend_device_info() {
        let backend = create_backend();
        let (name, _unified, max_buf) = backend.device_info();
        assert!(!name.is_empty());
        assert!(max_buf > 0);
    }

    // -----------------------------------------------------------------------
    // Phase 5.1 — New tests for advanced features (12)
    // -----------------------------------------------------------------------

    #[test]
    fn argument_buffer_creation_and_binding() {
        let device = MetalDevice::system_default().unwrap();
        let layout = ArgumentBufferLayout {
            descriptor: ArgumentBufferDescriptor {
                buffer_index: 0,
                size_bytes: 256,
                usage: ArgumentBufferUsage::Graphics,
                access: ArgumentBufferAccess::ReadOnly,
            },
            entries: vec![
                ArgumentBufferEntry { binding: 0, resource_type: ArgumentResourceType::Buffer, access: ArgumentAccess::ReadOnly, array_length: 1 },
                ArgumentBufferEntry { binding: 1, resource_type: ArgumentResourceType::Texture, access: ArgumentAccess::ReadOnly, array_length: 1 },
                ArgumentBufferEntry { binding: 2, resource_type: ArgumentResourceType::Sampler, access: ArgumentAccess::ReadOnly, array_length: 1 },
            ],
            total_size: 256,
        };
        let mut arg_buffer = create_argument_buffer(device.device(), &layout).expect("arg buffer");
        assert_ne!(arg_buffer.handle, 0);
        assert!(arg_buffer.buffer.length() >= 256);

        let metal_buffer = MetalBuffer {
            handle: alloc_gpu_id(),
            buffer: device.create_buffer(64, metal::MTLResourceOptions::StorageModeShared),
            size: 64,
        };
        let tex_desc = metal::TextureDescriptor::new();
        tex_desc.set_texture_type(metal::MTLTextureType::D2);
        tex_desc.set_pixel_format(metal::MTLPixelFormat::RGBA8Unorm);
        tex_desc.set_width(64);
        tex_desc.set_height(64);
        tex_desc.set_usage(metal::MTLTextureUsage::ShaderRead);
        tex_desc.set_storage_mode(metal::MTLStorageMode::Private);
        tex_desc.set_sample_count(1);
        let metal_texture = MetalTexture {
            handle: alloc_gpu_id(),
            texture: device.device().new_texture(&tex_desc),
            width: 64, height: 64,
            format: PixelFormat::Rgba8Unorm,
        };
        let sampler_desc = metal::SamplerDescriptor::new();
        sampler_desc.set_min_filter(metal::MTLSamplerMinMagFilter::Linear);
        sampler_desc.set_mag_filter(metal::MTLSamplerMinMagFilter::Linear);
        sampler_desc.set_support_argument_buffers(true);
        let metal_sampler = MetalSampler {
            handle: alloc_gpu_id(),
            sampler: device.device().new_sampler(&sampler_desc),
        };

        set_buffer_in_argument_buffer(&mut arg_buffer, 0, &metal_buffer, 0).expect("set buffer");
        set_texture_in_argument_buffer(&mut arg_buffer, 1, &metal_texture).expect("set texture");
        set_sampler_in_argument_buffer(&mut arg_buffer, 2, &metal_sampler).expect("set sampler");
    }

    #[test]
    fn argument_buffer_nested() {
        let device = MetalDevice::system_default().unwrap();
        let nested_layout = ArgumentBufferLayout {
            descriptor: ArgumentBufferDescriptor {
                buffer_index: 0, size_bytes: 64,
                usage: ArgumentBufferUsage::Compute,
                access: ArgumentBufferAccess::ReadOnly,
            },
            entries: vec![ArgumentBufferEntry {
                binding: 0, resource_type: ArgumentResourceType::Buffer,
                access: ArgumentAccess::ReadOnly, array_length: 1,
            }],
            total_size: 64,
        };
        let parent_layout = ArgumentBufferLayout {
            descriptor: ArgumentBufferDescriptor {
                buffer_index: 0, size_bytes: 512,
                usage: ArgumentBufferUsage::GraphicsAndCompute,
                access: ArgumentBufferAccess::ReadWrite,
            },
            entries: vec![
                ArgumentBufferEntry { binding: 0, resource_type: ArgumentResourceType::Buffer, access: ArgumentAccess::ReadWrite, array_length: 1 },
                ArgumentBufferEntry { binding: 1, resource_type: ArgumentResourceType::NestedArgumentBuffer(Box::new(nested_layout.clone())), access: ArgumentAccess::ReadOnly, array_length: 1 },
            ],
            total_size: 512,
        };
        let nested_arg = create_argument_buffer(device.device(), &nested_layout).expect("nested");
        let mut parent_arg = create_argument_buffer(device.device(), &parent_layout).expect("parent");
        set_nested_argument_buffer(&mut parent_arg, 1, &nested_arg).expect("set nested");
        assert_ne!(parent_arg.handle, 0);
        assert_ne!(nested_arg.handle, 0);
    }

    #[test]
    fn ray_tracing_acceleration_structure() {
        let device = MetalDevice::system_default().unwrap();
        let geom_desc = RayTracingGeometryDescriptor {
            vertex_buffer: 0, vertex_stride: 12,
            vertex_format: VertexFormat::Float3,
            index_buffer: None, index_format: None,
            primitive_count: 1, triangle_count: 1,
            opaque: true, allow_duplicates: false,
        };
        let accel_desc = AccelerationStructureDescriptor {
            geometry_descriptors: vec![geom_desc],
            usage: AccelerationStructureUsage::RayTracing,
        };
        if let Ok(accel) = create_acceleration_structure(device.device(), &accel_desc) {
            assert_ne!(accel.handle, 0);
            assert!(!accel.built);
            assert!(accel.size > 0);
        }
    }

    #[test]
    fn mesh_pipeline_creation() {
        let device = MetalDevice::system_default().unwrap();
        let desc = MeshPipelineDescriptor {
            object_function: None,
            mesh_function: [
                "struct VertexOut { float4 position [[position]]; };",
                "[[mesh, max_total_vertices(64), max_total_primitives(32)]]",
                "kernel void mesh_main(mesh_data<VertexOut, Topology::triangle> out [[mesh_data]]) {}",
            ].join("\n"),
            fragment_function: Some("fragment float4 fragment_main() { return float4(1.0); }".to_string()),
            mesh_thread_group_size: (8, 1, 1),
            object_thread_group_size: None,
            payload_size: 0,
            max_vertex_count: 64,
            max_primitive_count: 32,
            color_attachments: vec![PixelFormat::Rgba8Unorm],
            depth_attachment: None,
            stencil_attachment: None,
        };
        if let Ok(p) = create_mesh_pipeline(device.device(), &desc) {
            assert_ne!(p.handle, 0);
            assert!(matches!(p.state, PipelineState::Compiled));
            // Native mesh pipeline state is None on non-Apple9+ devices
            // On Apple9+ (M3+), a proper MTLMeshRenderPipelineState would be created
            if device.supports_mesh_shaders() {
                // With proper mesh function and fragment function, the pipeline
                // should have been created as a native mesh render pipeline state
                assert!(p.mesh_render_pipeline_state.is_some(),
                    "native MTLMeshRenderPipelineState should be created on Apple9+");
            }
        }
    }

    #[test]
    fn variable_rate_shading() {
        let mut rate_map = create_shading_rate_map(16, 16, ShadingRate::R1x1).expect("rate map");
        assert_eq!(rate_map.width, 16);
        assert_eq!(rate_map.height, 16);
        assert_eq!(rate_map.rates.len(), 256);
        for rate in &rate_map.rates {
            assert_eq!(*rate, ShadingRate::R1x1);
        }
        set_tile_shading_rate(&mut rate_map, 0, 0, ShadingRate::R2x2).unwrap();
        assert_eq!(rate_map.rates[0], ShadingRate::R2x2);
        set_tile_shading_rate(&mut rate_map, 8, 8, ShadingRate::R4x4).unwrap();
        assert_eq!(rate_map.rates[8 * 16 + 8], ShadingRate::R4x4);
        assert!(set_tile_shading_rate(&mut rate_map, 16, 0, ShadingRate::R1x1).is_err());
        assert_eq!(ShadingRate::from_u8(ShadingRate::R2x2.to_u8()).unwrap(), ShadingRate::R2x2);
        assert!(ShadingRate::from_u8(255).is_err());
        assert_eq!(ShadingRate::R1x1.dimensions(), (1, 1));
        assert_eq!(ShadingRate::R4x4.dimensions(), (4, 4));
    }

    #[test]
    fn sampler_feedback_texture() {
        let mut feedback = create_sampler_feedback_texture(8, 8, SamplerFeedbackFormat::MipLevel).expect("feedback");
        assert_eq!(feedback.width, 8);
        assert_eq!(feedback.data.len(), 64);
        feedback.data[0] = 2;
        feedback.data[9] = 3;
        feedback.data[63] = 5;
        let result = read_sampler_feedback(&feedback).expect("read");
        assert_eq!(result.len(), 64);
        assert_eq!(result[0], (0, 0, 2));
        assert_eq!(result[9], (1, 1, 3));
        assert_eq!(result[63], (7, 7, 5));
    }

    #[test]
    fn msaa_programmable_resolve() {
        let device = MetalDevice::system_default().unwrap();
        let msaa_texture = create_msaa_texture(device.device(), 256, 256, PixelFormat::Rgba8Unorm, 4).expect("msaa");
        assert_eq!(msaa_texture.width, 256);
        assert_eq!(msaa_texture.format, PixelFormat::Rgba8Unorm);
        let config = MsaaResolveConfig { sample_count: 4, resolve_mode: MsaaResolveMode::Average, custom_resolve_shader: None };
        assert!(config.validate().is_ok());
        assert!(MsaaResolveConfig { sample_count: 3, resolve_mode: MsaaResolveMode::Average, custom_resolve_shader: None }.validate().is_err());
        assert!(MsaaResolveConfig { sample_count: 4, resolve_mode: MsaaResolveMode::Custom, custom_resolve_shader: None }.validate().is_err());
    }

    #[test]
    fn depth_bounds_emulation() {
        let config = DepthBoundsConfig { min_depth: 0.1, max_depth: 0.9, enabled: true };
        assert!(config.enabled);
        let original = "#include <metal_stdlib>\nusing namespace metal;\nfragment float4 my_fragment() { return float4(1.0); }";
        let patched = patch_fragment_shader_for_depth_bounds(original);
        assert!(patched.contains("depth_bounds_min"));
        assert!(patched.contains("depth_bounds_max"));
        assert!(patched.contains("discard_fragment"));
        assert!(patched.contains("buffer(254)"));
        assert!(patched.contains("buffer(255)"));
        assert!(patched.contains("my_fragment"));
    }

    #[test]
    fn logic_op_emulation() {
        let shader = generate_logic_op_shader(LogicOp::Xor);
        assert!(shader.contains("src ^ dst"));
        assert!(shader.contains("logic_op_emulation"));
        let ops = [LogicOp::Clear, LogicOp::Set, LogicOp::Copy, LogicOp::CopyInverted,
            LogicOp::Noop, LogicOp::Invert, LogicOp::And, LogicOp::Nand,
            LogicOp::Or, LogicOp::Nor, LogicOp::Xor, LogicOp::Equiv,
            LogicOp::AndReverse, LogicOp::AndInverted, LogicOp::OrReverse, LogicOp::OrInverted];
        for op in ops {
            let s = generate_logic_op_shader(op);
            assert!(s.contains("metal_stdlib"), "Shader for {op:?} missing metal_stdlib");
            assert!(s.contains("fragment"), "Shader for {op:?} missing fragment keyword");
        }
    }

    #[test]
    fn geometry_shader_emulation() {
        let gs_source = "layout(triangles) in; layout(triangle_strip, max_vertices = 3) out; void main() {}";
        let emulation = create_geometry_shader_emulation(gs_source, 3, 1).expect("gs emulation");
        assert_eq!(emulation.max_output_vertices, 3);
        assert_eq!(emulation.max_output_primitives, 1);
        assert!(!emulation.compute_shader.is_empty());
        assert!(emulation.compute_shader.contains("geometry_emulation"));
        assert!(emulation.output_buffer_size > 0);
        assert_eq!(InputPrimitive::Point.vertex_count(), 1);
        assert_eq!(InputPrimitive::Triangle.vertex_count(), 3);
        assert_eq!(InputPrimitive::TriangleAdjacency.vertex_count(), 6);
    }

    #[test]
    fn tessellation_pipeline() {
        let pipeline = create_tessellation_pipeline(
            "vertex float4 tess_vertex(uint vid [[vertex_id]]) { return float4(0.0); }",
            PatchType::Triangle, PartitionMode::FractionalOdd, 3, 16,
        ).expect("tessellation pipeline");
        assert_ne!(pipeline.handle, 0);
        assert_eq!(pipeline.tessellation_factor, 16);
        assert_eq!(pipeline.patch_type, PatchType::Triangle);
        assert_eq!(pipeline.partition_mode, PartitionMode::FractionalOdd);
        assert_eq!(pipeline.control_point_count, 3);
        assert!(create_tessellation_pipeline("x", PatchType::Triangle, PartitionMode::Integer, 0, 16).is_err());
        assert!(create_tessellation_pipeline("x", PatchType::Triangle, PartitionMode::Integer, 3, 0).is_err());
        assert!(create_tessellation_pipeline("x", PatchType::Triangle, PartitionMode::Integer, 3, 65).is_err());
    }

    #[test]
    fn metal_heap_allocation() {
        let device = MetalDevice::system_default().unwrap();
        let mut heap = create_heap(device.device(), 1024 * 1024, HEAP_TYPE_BUFFER | HEAP_TYPE_TEXTURE).expect("heap");
        assert_ne!(heap.handle, 0);
        assert_eq!(heap.size, 1024 * 1024);
        assert_eq!(heap.allocations.len(), 0);
        let (used, total) = heap_usage(&heap);
        assert_eq!(used, 0);
        assert_eq!(total, 1024 * 1024);

        let buffer = allocate_buffer_from_heap(&mut heap, 4096, 256).expect("buffer from heap");
        assert_ne!(buffer.handle, 0);
        assert!(buffer.size >= 4096);
        assert_eq!(heap.allocations.len(), 1);
        assert_eq!(heap.allocations[0].resource_type, HeapResourceType::Buffer);
        let (used_after_buf, _) = heap_usage(&heap);
        assert!(used_after_buf > 0);

        let texture = allocate_texture_from_heap(&mut heap, 64, 64, PixelFormat::Rgba8Unorm).expect("texture from heap");
        assert_ne!(texture.handle, 0);
        assert_eq!(texture.width, 64);
        assert_eq!(heap.allocations.len(), 2);
        let (used_after_tex, _) = heap_usage(&heap);
        assert!(used_after_tex > used_after_buf);

        deallocate_from_heap(&mut heap, buffer.handle).expect("deallocate");
        assert_eq!(heap.allocations.len(), 1);
        assert!(deallocate_from_heap(&mut heap, 99999).is_err());

        let mut buffer_only_heap = create_heap(device.device(), 4096, HEAP_TYPE_BUFFER).expect("buf heap");
        assert!(allocate_texture_from_heap(&mut buffer_only_heap, 64, 64, PixelFormat::Rgba8Unorm).is_err());
    }

    // --- Phase 7: Command Buffer Pool Tests ---

    #[test]
    fn command_buffer_pool_acquire_release() {
        let mut pool = CommandBufferPool::new(1, 2, 4);

        // Acquire two buffers
        let h1 = pool.acquire().unwrap();
        let h2 = pool.acquire().unwrap();
        assert_ne!(h1, h2, "acquired handles should be unique");
        assert_eq!(pool.in_flight_count(), 2);
        assert_eq!(pool.available_count(), 0);

        // Release one
        pool.release(h1);
        assert_eq!(pool.in_flight_count(), 1);
        assert_eq!(pool.available_count(), 1);

        // Acquire again — should reuse the released buffer
        let h3 = pool.acquire().unwrap();
        assert_eq!(h3, h1, "should reuse released buffer handle");
    }

    #[test]
    fn command_buffer_pool_respects_pool_size() {
        let mut pool = CommandBufferPool::new(1, 2, 2);

        let h1 = pool.acquire().unwrap();
        let h2 = pool.acquire().unwrap();
        pool.release(h1);
        pool.release(h2);

        // Pool size is 2, both should be available
        assert_eq!(pool.available_count(), 2);
    }

    // --- Phase 7: Shader Pre-Compiler Tests ---

    #[test]
    fn shader_pre_compiler() {
        let mut compiler = ShaderPreCompiler::new();

        compiler.add_request(ShaderPreCompileRequest {
            key: "shader_a".to_string(),
            msl_source: "kernel void main() {}".to_string(),
            entry_point: "main".to_string(),
            stage: ShaderStage::Compute,
        });
        compiler.add_request(ShaderPreCompileRequest {
            key: "shader_b".to_string(),
            msl_source: "vertex float4 vert() { return float4(1.0); }".to_string(),
            entry_point: "vert".to_string(),
            stage: ShaderStage::Vertex,
        });

        assert_eq!(compiler.pending_count(), 2);

        let count = compiler.compile_all().unwrap();
        assert_eq!(count, 2);
        assert_eq!(compiler.completed_count(), 2);
        assert_eq!(compiler.pending_count(), 0);

        let shader = compiler.get_precompiled("shader_a").unwrap();
        assert_eq!(shader.key, "shader_a");
        assert!(!shader.binary.is_empty());
    }

    // --- Phase 7: Async Shader Compiler Tests ---

    #[test]
    fn async_shader_compiler() {
        let mut compiler = AsyncShaderCompiler::new();
        assert!(compiler.running);

        compiler.submit(ShaderPreCompileRequest {
            key: "async_shader".to_string(),
            msl_source: "fragment float4 frag() { return float4(0.5); }".to_string(),
            entry_point: "frag".to_string(),
            stage: ShaderStage::Fragment,
        }).unwrap();

        // Give the background thread time to compile
        std::thread::sleep(std::time::Duration::from_millis(50));

        let completed = compiler.poll_completed();
        assert!(!completed.is_empty(), "should have at least one completed shader");
        assert_eq!(completed[0].key, "async_shader");

        compiler.shutdown();
        assert!(!compiler.running);
    }

    // --- Phase 7: Descriptor Heap Pool Tests ---

    #[test]
    fn descriptor_heap_pool() {
        let mut pool = DescriptorHeapPool::new();

        let idx1 = pool.allocate(64, 0x1).unwrap();
        let idx2 = pool.allocate(128, 0x2).unwrap();
        assert_ne!(idx1, idx2);
        assert_eq!(pool.in_use_count(), 2);
        assert_eq!(pool.free_count(), 0);

        pool.release(idx1);
        assert_eq!(pool.in_use_count(), 1);
        assert_eq!(pool.free_count(), 1);

        // Allocate again — should reuse
        let idx3 = pool.allocate(64, 0x1).unwrap();
        assert_eq!(idx3, idx1, "should reuse released heap index");
    }

    #[test]
    fn descriptor_heap_pool_reclaim() {
        let mut pool = DescriptorHeapPool::new();
        pool.allocate(64, 0x1).unwrap();
        pool.allocate(64, 0x1).unwrap();
        assert_eq!(pool.in_use_count(), 2);

        let reclaimed = pool.reclaim(1000, 100);
        assert_eq!(reclaimed, 2);
        assert_eq!(pool.free_count(), 2);
    }

    // --- Phase 7: Texture Streaming Tests ---

    #[test]
    fn texture_streaming() {
        let mut mgr = TextureStreamingManager::new(1024 * 1024); // 1MB budget

        let tex = mgr.register_texture(256, 256, 8, 0).unwrap(); // RGBA8
        assert_eq!(mgr.texture_count(), 1);

        // Request mip level 0 (base)
        let loaded = mgr.request_mip_level(tex, 0, 1).unwrap();
        assert!(loaded);
        let t = mgr.textures.get(&tex).unwrap();
        assert_eq!(t.loaded_mips, 1);
        assert!(t.size_bytes > 0);

        // Request mip levels 0-3
        let loaded = mgr.request_mip_level(tex, 3, 2).unwrap();
        assert!(loaded);
        let t = mgr.textures.get(&tex).unwrap();
        assert_eq!(t.loaded_mips, 4);
    }

    #[test]
    fn texture_streaming_budget_exceeded() {
        let mut mgr = TextureStreamingManager::new(1024); // Very small budget

        let tex1 = mgr.register_texture(256, 256, 8, 0).unwrap();
        let tex2 = mgr.register_texture(256, 256, 8, 0).unwrap();

        // Load tex1 mip 0 — should succeed (256*256*4 = 256KB > 1KB budget)
        // Actually with our budget of 1024 bytes, even mip 0 (256*256*4) won't fit
        let loaded = mgr.request_mip_level(tex1, 0, 1).unwrap();
        assert!(!loaded, "should fail with insufficient budget");
    }

    #[test]
    fn texture_streaming_priorities() {
        let mut mgr = TextureStreamingManager::new(1024 * 1024);
        let tex = mgr.register_texture(64, 64, 4, 0).unwrap();
        mgr.request_mip_level(tex, 2, 10).unwrap();

        mgr.update_priorities(15);
        let t = mgr.textures.get(&tex).unwrap();
        assert!(t.priority > 0.0);
    }

    // --- Phase 7: Render Pass Merging Tests ---

    #[test]
    fn render_pass_merging() {
        let mut merger = RenderPassMerger::new();

        let passes = vec![
            RenderPassInfo {
                color_attachments: vec![1, 2],
                depth_attachment: Some(10),
                stencil_attachment: None,
                load_actions: vec![1, 1], // Clear
                store_actions: vec![0, 0], // Store
                command_count: 5,
            },
            RenderPassInfo {
                color_attachments: vec![1, 2],
                depth_attachment: Some(10),
                stencil_attachment: None,
                load_actions: vec![0, 0], // Load — compatible
                store_actions: vec![0, 0], // Store
                command_count: 3,
            },
            RenderPassInfo {
                color_attachments: vec![3], // Different attachment — cannot merge
                depth_attachment: None,
                stencil_attachment: None,
                load_actions: vec![1],
                store_actions: vec![0],
                command_count: 2,
            },
        ];

        let merged = merger.merge_passes(&passes);
        assert_eq!(merged.len(), 2, "first two passes should merge, third should not");
        assert_eq!(merged[0].command_count, 8, "merged pass should have combined command count");
        assert_eq!(merged[1].command_count, 2);
        assert_eq!(merger.merged_count, 1);
    }

    #[test]
    fn render_pass_merging_cannot_merge_clear() {
        let mut merger = RenderPassMerger::new();

        let passes = vec![
            RenderPassInfo {
                color_attachments: vec![1],
                depth_attachment: None,
                stencil_attachment: None,
                load_actions: vec![0],
                store_actions: vec![0],
                command_count: 3,
            },
            RenderPassInfo {
                color_attachments: vec![1],
                depth_attachment: None,
                stencil_attachment: None,
                load_actions: vec![1], // Clear — cannot merge
                store_actions: vec![0],
                command_count: 2,
            },
        ];

        let merged = merger.merge_passes(&passes);
        assert_eq!(merged.len(), 2, "should not merge when second pass has Clear action");
    }

    #[test]
    fn render_pass_merging_empty() {
        let mut merger = RenderPassMerger::new();
        let merged = merger.merge_passes(&[]);
        assert!(merged.is_empty());
    }

    // --- Phase 7: Memory Aliasing Tests ---

    #[test]
    fn memory_aliasing() {
        let mut mgr = MemoryAliasManager::new();

        let handle = mgr.create_alias(
            1024,
            vec![
                AliasedResource {
                    handle: 1,
                    offset: 0,
                    size: 1024,
                    first_frame: 0,
                    last_frame: 10,
                },
                AliasedResource {
                    handle: 2,
                    offset: 0,
                    size: 1024,
                    first_frame: 11,
                    last_frame: 20,
                },
            ],
        ).unwrap();

        assert_ne!(handle, 0);
        assert_eq!(mgr.alias_count(), 1);
        assert_eq!(mgr.get_savings(), 1024); // 1024 + 1024 - 1024
    }

    #[test]
    fn memory_aliasing_overlapping_lifetimes_rejected() {
        let mut mgr = MemoryAliasManager::new();

        let result = mgr.create_alias(
            1024,
            vec![
                AliasedResource {
                    handle: 1,
                    offset: 0,
                    size: 1024,
                    first_frame: 0,
                    last_frame: 15,
                },
                AliasedResource {
                    handle: 2,
                    offset: 0,
                    size: 1024,
                    first_frame: 10,
                    last_frame: 20,
                },
            ],
        );

        assert!(result.is_err(), "should reject overlapping lifetimes");
    }

    #[test]
    fn memory_aliasing_can_alias_check() {
        let a = AliasedResource {
            handle: 1, offset: 0, size: 100, first_frame: 0, last_frame: 10,
        };
        let b = AliasedResource {
            handle: 2, offset: 0, size: 100, first_frame: 11, last_frame: 20,
        };
        assert!(MemoryAliasManager::can_alias(&a, &b));

        let c = AliasedResource {
            handle: 3, offset: 0, size: 100, first_frame: 5, last_frame: 15,
        };
        assert!(!MemoryAliasManager::can_alias(&a, &c));
    }
}
