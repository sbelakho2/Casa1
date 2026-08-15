//! Real Metal rendering pipeline for Casa1.
//!
//! This module also provides the CEF overlay compositing infrastructure for
//! blending Steam UI (WKWebView frames) onto the game content via Metal.
//!
//! Bridges D3D11/D3D12 draw calls to real Metal command encoding, providing
//! actual GPU-accelerated rendering. This module connects the D3D API layer
//! to the Metal GPU backend from `src/metal_backend.rs`.

use crate::error::{AppError, AppResult};
use crate::gfx::DxgiFormat;
use crate::metal_backend::{
    MetalDevice, MetalSwapchain,
    async_pipeline_compiler::{AsyncPipelineCompiler, PipelineState},
    dxgi_to_metal_format,
};
use crate::reason::ReasonCode;

// ---------------------------------------------------------------------------
// Rendering types
// ---------------------------------------------------------------------------

/// Describes a render target configuration.
#[derive(Debug, Clone)]
pub struct RenderTargetDesc {
    pub width: u32,
    pub height: u32,
    pub format: DxgiFormat,
    pub sample_count: u32,
}

/// Describes a viewport.
#[derive(Debug, Clone, Copy)]
pub struct Viewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub min_depth: f32,
    pub max_depth: f32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            width: 800.0,
            height: 600.0,
            min_depth: 0.0,
            max_depth: 1.0,
        }
    }
}

/// Describes a scissor rect.
#[derive(Debug, Clone, Copy)]
pub struct ScissorRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Describes blend state for a render target.
#[derive(Debug, Clone, Copy)]
pub struct BlendDesc {
    pub blend_enable: bool,
    pub src_blend: BlendFactor,
    pub dst_blend: BlendFactor,
    pub blend_op: BlendOp,
    pub src_blend_alpha: BlendFactor,
    pub dst_blend_alpha: BlendFactor,
    pub blend_op_alpha: BlendOp,
    pub render_target_write_mask: u8,
}

impl Default for BlendDesc {
    fn default() -> Self {
        Self {
            blend_enable: false,
            src_blend: BlendFactor::One,
            dst_blend: BlendFactor::Zero,
            blend_op: BlendOp::Add,
            src_blend_alpha: BlendFactor::One,
            dst_blend_alpha: BlendFactor::Zero,
            blend_op_alpha: BlendOp::Add,
            render_target_write_mask: 0x0F,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlendFactor {
    Zero,
    One,
    SrcColor,
    InvSrcColor,
    SrcAlpha,
    InvSrcAlpha,
    DstAlpha,
    InvDstAlpha,
    DstColor,
    InvDstColor,
    SrcAlphaSaturate,
    BlendFactor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlendOp {
    Add,
    Subtract,
    RevSubtract,
    Min,
    Max,
}

/// Describes rasterizer state.
#[derive(Debug, Clone, Copy)]
pub struct RasterizerDesc {
    pub fill_mode: FillMode,
    pub cull_mode: CullMode,
    pub front_counter_clockwise: bool,
    pub depth_bias: i32,
    pub depth_bias_clamp: f32,
    pub slope_scaled_depth_bias: f32,
    pub depth_clip_enable: bool,
    pub scissor_enable: bool,
    pub multisample_enable: bool,
    pub antialiased_line_enable: bool,
}

impl Default for RasterizerDesc {
    fn default() -> Self {
        Self {
            fill_mode: FillMode::Solid,
            cull_mode: CullMode::None,
            front_counter_clockwise: false,
            depth_bias: 0,
            depth_bias_clamp: 0.0,
            slope_scaled_depth_bias: 0.0,
            depth_clip_enable: true,
            scissor_enable: false,
            multisample_enable: false,
            antialiased_line_enable: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillMode {
    Wireframe,
    Solid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CullMode {
    None,
    Front,
    Back,
}

/// Describes depth stencil state.
#[derive(Debug, Clone, Copy)]
pub struct DepthStencilDesc {
    pub depth_enable: bool,
    pub depth_write_enable: bool,
    pub depth_func: ComparisonFunc,
    pub stencil_enable: bool,
    pub stencil_read_mask: u8,
    pub stencil_write_mask: u8,
}

impl Default for DepthStencilDesc {
    fn default() -> Self {
        Self {
            depth_enable: true,
            depth_write_enable: true,
            depth_func: ComparisonFunc::Less,
            stencil_enable: false,
            stencil_read_mask: 0xFF,
            stencil_write_mask: 0xFF,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonFunc {
    Never,
    Less,
    Equal,
    LessEqual,
    Greater,
    NotEqual,
    GreaterEqual,
    Always,
}

impl ComparisonFunc {
    pub fn to_metal(self) -> metal::MTLCompareFunction {
        match self {
            Self::Never => metal::MTLCompareFunction::Never,
            Self::Less => metal::MTLCompareFunction::Less,
            Self::Equal => metal::MTLCompareFunction::Equal,
            Self::LessEqual => metal::MTLCompareFunction::LessEqual,
            Self::Greater => metal::MTLCompareFunction::Greater,
            Self::NotEqual => metal::MTLCompareFunction::NotEqual,
            Self::GreaterEqual => metal::MTLCompareFunction::GreaterEqual,
            Self::Always => metal::MTLCompareFunction::Always,
        }
    }
}

/// Index into the fixed depth-stencil state cache (2 depth flags × 2 write
/// flags × 8 compare functions = 32 entries).
fn depth_stencil_state_index(
    depth_enable: bool,
    depth_write_enable: bool,
    depth_func: ComparisonFunc,
) -> usize {
    let func = match depth_func {
        ComparisonFunc::Never => 0,
        ComparisonFunc::Less => 1,
        ComparisonFunc::Equal => 2,
        ComparisonFunc::LessEqual => 3,
        ComparisonFunc::Greater => 4,
        ComparisonFunc::NotEqual => 5,
        ComparisonFunc::GreaterEqual => 6,
        ComparisonFunc::Always => 7,
    };
    ((depth_enable as usize) << 4) | ((depth_write_enable as usize) << 3) | func
}

/// Primitive topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveTopology {
    PointList,
    LineList,
    LineStrip,
    TriangleList,
    TriangleStrip,
}

impl PrimitiveTopology {
    pub fn to_metal(self) -> metal::MTLPrimitiveType {
        match self {
            Self::PointList => metal::MTLPrimitiveType::Point,
            Self::LineList => metal::MTLPrimitiveType::Line,
            Self::LineStrip => metal::MTLPrimitiveType::LineStrip,
            Self::TriangleList => metal::MTLPrimitiveType::Triangle,
            Self::TriangleStrip => metal::MTLPrimitiveType::TriangleStrip,
        }
    }
}

/// Index buffer format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFormat {
    UInt16,
    UInt32,
}

impl IndexFormat {
    pub fn to_metal(self) -> metal::MTLIndexType {
        match self {
            Self::UInt16 => metal::MTLIndexType::UInt16,
            Self::UInt32 => metal::MTLIndexType::UInt32,
        }
    }
}

// ---------------------------------------------------------------------------
// Metal rendering context
// ---------------------------------------------------------------------------

/// A complete Metal rendering context that manages the GPU pipeline state.
pub struct MetalRenderContext {
    device: MetalDevice,
    command_queue: metal::CommandQueue,
    swapchain: Option<MetalSwapchain>,
    frame_index: u64,
    // Pipeline state cache
    depth_stencil_states: Vec<Option<metal::DepthStencilState>>,
    // CEF overlay compositing
    cef_overlay_texture: Option<metal::Texture>,
    cef_overlay_pipeline: Option<metal::RenderPipelineState>,
    cef_texture_width: u32,
    cef_texture_height: u32,
    // Async pipeline compiler for non-blocking PSO creation
    pipeline_compiler: Option<AsyncPipelineCompiler>,
    /// Request ID for the CEF overlay pipeline submission (0 = none / not yet submitted).
    cef_pipeline_request_id: u64,
}

impl MetalRenderContext {
    /// Create a new rendering context.
    pub fn new() -> AppResult<Self> {
        let device = MetalDevice::system_default()?;
        let command_queue = device.create_command_queue().to_owned();

        // Create the async pipeline compiler (optional — falls back to sync).
        let pipeline_compiler = Some(AsyncPipelineCompiler::new(device.device()));

        Ok(Self {
            device,
            command_queue,
            swapchain: None,
            frame_index: 0,
            depth_stencil_states: vec![None; 32],
            cef_overlay_texture: None,
            cef_overlay_pipeline: None,
            cef_texture_width: 0,
            cef_texture_height: 0,
            pipeline_compiler,
            cef_pipeline_request_id: 0,
        })
    }

    /// Create a swapchain for rendering with default flip model (Discard) and colour space (sRGB).
    pub fn create_swapchain(&mut self, width: u32, height: u32) {
        self.swapchain = Some(MetalSwapchain::new(
            self.device.device(),
            width as u64,
            height as u64,
            crate::metal_backend::FlipModel::Discard,
            crate::metal_backend::ColorSpace::SRGB,
        ));
    }

    /// Resize the swapchain, recreating back-buffer textures at the new size.
    pub fn resize_swapchain(&mut self, width: u32, height: u32) {
        if let Some(ref mut swapchain) = self.swapchain {
            swapchain.resize(self.device.device(), width as u64, height as u64);
        }
    }

    /// Get the device.
    pub fn device(&self) -> &MetalDevice {
        &self.device
    }

    /// Get the swapchain.
    pub fn swapchain(&self) -> Option<&MetalSwapchain> {
        self.swapchain.as_ref()
    }

    /// Get the current frame index.
    pub fn frame_index(&self) -> u64 {
        self.frame_index
    }

    /// Create a new command buffer for rendering.
    pub fn create_command_buffer(&self) -> &metal::CommandBufferRef {
        self.command_queue.new_command_buffer()
    }

    /// Get or create a depth stencil state.
    ///
    /// The cache is a fixed 32-entry table (2 depth flags × 2 write flags × 8
    /// compare functions) so the hot path does no allocation or map lookup.
    pub fn get_depth_stencil_state(
        &mut self,
        depth_enable: bool,
        depth_write_enable: bool,
        depth_func: ComparisonFunc,
    ) -> &metal::DepthStencilStateRef {
        let idx = depth_stencil_state_index(depth_enable, depth_write_enable, depth_func);
        if self.depth_stencil_states[idx].is_none() {
            let state = if depth_enable {
                self.device
                    .create_depth_stencil_state(depth_func.to_metal(), depth_write_enable)
            } else {
                self.device
                    .create_depth_stencil_state(metal::MTLCompareFunction::Always, false)
            };
            self.depth_stencil_states[idx] = Some(state);
        }
        self.depth_stencil_states[idx].as_ref().unwrap()
    }

    /// Begin a new frame.
    ///
    /// NOTE: this API is a placeholder that does not present — GPU work only
    /// happens when the command buffer is committed and presented via
    /// [`present`](Self::present). Callers that expect rendered frames should
    /// use the swapchain present path instead.
    pub fn begin_frame(&mut self) -> AppResult<FrameContext> {
        let (width, height) = self
            .swapchain
            .as_ref()
            .map(|s| s.size())
            .unwrap_or((800, 600));

        let cmd_buffer = self.create_command_buffer();

        Ok(FrameContext {
            command_buffer: cmd_buffer.to_owned(),
            width: width as u32,
            height: height as u32,
            frame_index: self.frame_index,
        })
    }

    /// End the current frame and present.
    ///
    /// NOTE: placeholder — this only advances the frame counter. The frame's
    /// command buffer is committed and presented by the swapchain present path
    /// ([`present`](Self::present)); a caller relying on this stub alone would
    /// never submit GPU work.
    pub fn end_frame(&mut self) {
        self.frame_index += 1;
    }

    /// Present the swapchain.
    ///
    /// If the Steam overlay is active, this automatically uploads the latest
    /// CEF overlay frame and composites it on top of the game content via
    /// [`composite_and_present`](Self::composite_and_present).
    ///
    /// Otherwise, it performs a simple Metal present of the game content.
    pub fn present(&mut self) -> AppResult<()> {
        // Check if the Steam overlay is active
        let overlay_active = crate::steam_integration::steam_overlay_is_active();

        if overlay_active {
            // Upload the latest CEF overlay frame (if any pending)
            self.upload_cef_overlay_if_needed()?;
            // Composite overlay on top of game content and present
            return self.composite_and_present();
        }

        self.present_standard()
    }

    /// Present the swapchain without any overlay compositing.
    fn present_standard(&mut self) -> AppResult<()> {
        let swapchain = self
            .swapchain
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, "no swapchain created"))?;

        let drawable = swapchain.next_drawable()?;
        let cmd_buffer = self.create_command_buffer();
        cmd_buffer.present_drawable(drawable);
        cmd_buffer.commit();

        Ok(())
    }

    /// Get the device name.
    pub fn device_name(&self) -> &str {
        self.device.name()
    }

    // -----------------------------------------------------------------------
    // CEF Overlay Compositing
    // -----------------------------------------------------------------------

    /// Upload the latest CEF overlay frame (from the global compositor) into a
    /// cached Metal texture. Call this once per frame *before* compositing.
    pub fn upload_cef_overlay_if_needed(&mut self) -> AppResult<()> {
        let frame_data = with_global_cef_compositor(|compositor| compositor.take_pending_frame());
        let Some(mut frame) = frame_data else {
            return Ok(());
        };

        let (width, height) = (frame.width, frame.height);
        if width == 0 || height == 0 {
            return Ok(());
        }

        // Zero-copy path: if the frame carries an IOSurface, alias its storage
        // directly into a Metal texture instead of doing a CPU pixel upload.
        if let Some(io_surface) = frame.io_surface.take() {
            let texture = crate::metal_backend::create_texture_from_io_surface(
                self.device.device(),
                io_surface,
                metal::MTLPixelFormat::BGRA8Unorm,
                width as u64,
                height as u64,
            );
            // The frame's +1 reference is released here regardless of whether
            // the texture was created: `newTextureWithDescriptor:iosurface:`
            // keeps the surface alive for the lifetime of the texture.
            release_io_surface(io_surface);
            if let Some(texture) = texture {
                self.cef_overlay_texture = Some(texture);
                self.cef_texture_width = width;
                self.cef_texture_height = height;
                return Ok(());
            }
            // If IOSurface aliasing failed and no CPU pixels are available,
            // there is nothing further to upload this frame.
            if frame.pixels.is_empty() {
                return Ok(());
            }
        }

        // Re-allocate texture if dimensions changed. Both the IOSurface and
        // the CPU path use BGRA8Unorm so the shared compositing shader samples
        // identical colours regardless of which path delivered the frame.
        if self.cef_texture_width != width
            || self.cef_texture_height != height
            || self.cef_overlay_texture.is_none()
        {
            let descriptor = metal::TextureDescriptor::new();
            descriptor.set_texture_type(metal::MTLTextureType::D2);
            descriptor.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
            descriptor.set_width(width as u64);
            descriptor.set_height(height as u64);
            descriptor.set_usage(
                metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::RenderTarget,
            );
            descriptor.set_storage_mode(metal::MTLStorageMode::Shared);
            let texture = self.device.device().new_texture(&descriptor);

            self.cef_overlay_texture = Some(texture);
            self.cef_texture_width = width;
            self.cef_texture_height = height;
        }

        // Upload pixel data. The frame's pixel buffer is untrusted (guest/CEF
        // driven), so validate its length before handing it to Metal — a
        // shorter buffer would otherwise be read past its end (OOB read, UB).
        if let Some(ref texture) = self.cef_overlay_texture {
            let needed = (width as usize)
                .saturating_mul(height as usize)
                .saturating_mul(4);
            if frame.pixels.len() < needed {
                return Ok(());
            }
            let region = metal::MTLRegion {
                origin: metal::MTLOrigin { x: 0, y: 0, z: 0 },
                size: metal::MTLSize {
                    width: width as u64,
                    height: height as u64,
                    depth: 1,
                },
            };
            let bytes_per_row = (width as u64) * 4;
            // The compositor delivers RGBA byte order; the texture is
            // BGRA8Unorm (matching the IOSurface path), so swap R/B in place
            // before the upload so both paths sample identical colours.
            rgba_to_bgra_in_place(&mut frame.pixels[..needed]);
            texture.replace_region(
                region,
                0,
                frame.pixels.as_ptr() as *const std::ffi::c_void,
                bytes_per_row,
            );
        }

        Ok(())
    }

    /// Ensure the CEF overlay compositing pipeline is created (lazily).
    ///
    /// Uses the async pipeline compiler when available so that compilation
    /// happens off the render thread.  If the compiler is not ready yet or
    /// if async compilation fails, falls back to synchronous creation.
    fn ensure_cef_overlay_pipeline(&mut self) -> AppResult<()> {
        // Always poll the async compiler first to drain any completed results,
        // even if we already have a pipeline (avoids leaking PipelineReady entries).
        if self.cef_pipeline_request_id != 0
            && let Some(ref mut compiler) = self.pipeline_compiler
        {
            for ready in compiler.poll() {
                if ready.id == self.cef_pipeline_request_id {
                    if let PipelineState::Render(ps) = ready.state {
                        self.cef_overlay_pipeline = Some(ps);
                        self.cef_pipeline_request_id = 0;
                    }
                    break;
                }
            }
        }

        // Already have the pipeline?
        if self.cef_overlay_pipeline.is_some() {
            return Ok(());
        }

        if let Some(ref mut compiler) = self.pipeline_compiler {
            // A request is still in-flight — try again next frame.
            if self.cef_pipeline_request_id != 0 {
                return Ok(());
            }

            // Compile the shader library and extract functions.
            let library = self
                .device
                .compile_shader_library(CEF_OVERLAY_SHADER_SOURCE)?;
            let vertex_fn = library
                .get_function("cef_overlay_vertex", None)
                .map_err(|_| {
                    AppError::new(
                        ReasonCode::RcIo,
                        "failed to find cef_overlay_vertex in MSL library",
                    )
                })?;
            let fragment_fn = library
                .get_function("cef_overlay_fragment", None)
                .map_err(|_| {
                    AppError::new(
                        ReasonCode::RcIo,
                        "failed to find cef_overlay_fragment in MSL library",
                    )
                })?;

            let pipeline_desc = build_cef_pipeline_descriptor(&vertex_fn, &fragment_fn);

            // Cache hit?
            if let Some(cached) = compiler.get_cached_render_pipeline(&pipeline_desc) {
                self.cef_overlay_pipeline = Some(cached);
                return Ok(());
            }

            // Submit async compilation.
            let id = compiler.submit_render(&pipeline_desc);
            self.cef_pipeline_request_id = id;

            // Also pre-warm with a synchronous fallback so the very first
            // frame has something to draw (this only happens once).
            match self
                .device
                .device()
                .new_render_pipeline_state(&pipeline_desc)
            {
                Ok(ps) => {
                    compiler.cache_render_pipeline(&pipeline_desc, &ps);
                    self.cef_overlay_pipeline = Some(ps);
                }
                Err(e) => {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("sync fallback for CEF overlay pipeline failed: {e:?}"),
                    ));
                }
            }
            return Ok(());
        }

        // No async compiler — original synchronous path.
        let library = self
            .device
            .compile_shader_library(CEF_OVERLAY_SHADER_SOURCE)?;
        let vertex_fn = library
            .get_function("cef_overlay_vertex", None)
            .map_err(|_| {
                AppError::new(
                    ReasonCode::RcIo,
                    "failed to find cef_overlay_vertex in MSL library",
                )
            })?;
        let fragment_fn = library
            .get_function("cef_overlay_fragment", None)
            .map_err(|_| {
                AppError::new(
                    ReasonCode::RcIo,
                    "failed to find cef_overlay_fragment in MSL library",
                )
            })?;

        let pipeline_desc = build_cef_pipeline_descriptor(&vertex_fn, &fragment_fn);

        let pipeline = self
            .device
            .device()
            .new_render_pipeline_state(&pipeline_desc)
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to create CEF overlay pipeline: {e:?}"),
                )
            })?;

        self.cef_overlay_pipeline = Some(pipeline);
        Ok(())
    }

    /// Composite the CEF overlay onto the current drawable and present.
    ///
    /// This performs a two-pass composite:
    ///   1. The existing game content on the drawable is preserved (Load action).
    ///   2. The CEF/Steam UI overlay texture is alpha-blended on top.
    ///   3. Then the drawable is presented.
    ///
    /// When no overlay texture (no frame yet) or no overlay pipeline is
    /// available, this falls back to the normal present path instead of
    /// presenting an unrendered drawable (which would drop the game's content
    /// for that frame).
    pub fn composite_and_present(&mut self) -> AppResult<()> {
        // Create command buffer first (mutable, no borrow conflicts)
        let cmd_buffer_ref = self.create_command_buffer();
        let cmd_buffer = cmd_buffer_ref.to_owned();

        // Ensure the overlay pipeline exists before borrowing self fields immutably
        if self.cef_overlay_texture.is_some() {
            self.ensure_cef_overlay_pipeline()?;
        }

        // Nothing to composite yet (no texture or pipeline): present the game
        // content via the standard path instead of a blank drawable.
        let (Some(texture), Some(pipeline)) = (
            self.cef_overlay_texture.as_ref(),
            self.cef_overlay_pipeline.as_ref(),
        ) else {
            return self.present_standard();
        };

        // Get the drawable after all mutable operations — this borrows self
        // immutably for the rest of the function, so it must be last.
        let drawable = {
            let swapchain = self
                .swapchain
                .as_ref()
                .ok_or_else(|| AppError::new(ReasonCode::RcIo, "no swapchain created"))?;
            swapchain.next_drawable()?
        };

        let descriptor = metal::RenderPassDescriptor::new();
        let ca = descriptor.color_attachments().object_at(0).unwrap();
        ca.set_texture(Some(drawable.texture()));
        // Preserve existing game content
        ca.set_load_action(metal::MTLLoadAction::Load);
        ca.set_store_action(metal::MTLStoreAction::Store);

        let encoder = cmd_buffer.new_render_command_encoder(descriptor);
        encoder.set_render_pipeline_state(pipeline);
        encoder.set_fragment_texture(0, Some(texture));
        // Full-screen triangle (3 vertices, no index/vertex buffer needed)
        encoder.draw_primitives(metal::MTLPrimitiveType::Triangle, 0, 3);
        encoder.end_encoding();

        cmd_buffer.present_drawable(drawable);
        cmd_buffer.commit();

        Ok(())
    }

    /// Resize the CEF overlay texture. Call this when the window/browser is resized.
    ///
    /// Forces a texture reallocation on the next upload at the given size.
    pub fn resize_cef_overlay(&mut self, width: u32, height: u32) {
        // Force texture reallocation on next upload, at the requested size.
        self.cef_overlay_texture = None;
        self.cef_texture_width = width;
        self.cef_texture_height = height;
    }
}

/// Build a `RenderPipelineDescriptor` for the CEF overlay compositing pass.
///
/// Shared between the async and sync compilation paths.
fn build_cef_pipeline_descriptor(
    vertex_fn: &metal::FunctionRef,
    fragment_fn: &metal::FunctionRef,
) -> metal::RenderPipelineDescriptor {
    let pipeline_desc = metal::RenderPipelineDescriptor::new();
    pipeline_desc.set_vertex_function(Some(vertex_fn));
    pipeline_desc.set_fragment_function(Some(fragment_fn));

    let color_attachment = pipeline_desc.color_attachments().object_at(0).unwrap();
    color_attachment.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
    // Enable alpha blending: src_alpha * src + (1 - src_alpha) * dst
    color_attachment.set_blending_enabled(true);
    color_attachment.set_rgb_blend_operation(metal::MTLBlendOperation::Add);
    color_attachment.set_alpha_blend_operation(metal::MTLBlendOperation::Add);
    color_attachment.set_source_rgb_blend_factor(metal::MTLBlendFactor::SourceAlpha);
    color_attachment.set_source_alpha_blend_factor(metal::MTLBlendFactor::SourceAlpha);
    color_attachment.set_destination_rgb_blend_factor(metal::MTLBlendFactor::OneMinusSourceAlpha);
    color_attachment.set_destination_alpha_blend_factor(metal::MTLBlendFactor::OneMinusSourceAlpha);

    pipeline_desc
}

/// Inline Metal Shading Language source for the CEF overlay compositing pass.
///
/// Uses a full-screen triangle (vertex_id only, no vertex buffer) and samples
/// the BGRA8 overlay texture with linear filtering.
const CEF_OVERLAY_SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct VertexOut {
    float4 position [[position]];
    float2 texcoord;
};

/// Full-screen triangle vertex shader. 3 vertices cover the entire clip space
/// without needing a vertex buffer.
vertex VertexOut cef_overlay_vertex(uint vertex_id [[vertex_id]]) {
    float2 positions[3] = {
        float2(-1.0, -1.0),
        float2( 3.0, -1.0),
        float2(-1.0,  3.0)
    };
    float2 texcoords[3] = {
        float2(0.0, 1.0),
        float2(2.0, 1.0),
        float2(0.0, -1.0)
    };
    VertexOut out;
    out.position = float4(positions[vertex_id], 0.0, 1.0);
    out.texcoord = texcoords[vertex_id];
    return out;
}

/// Fragment shader that samples the CEF overlay texture.
fragment float4 cef_overlay_fragment(VertexOut in [[stage_in]],
                                      texture2d<float> overlay [[texture(0)]]) {
    constexpr sampler s(address::clamp_to_edge, filter::linear);
    float4 color = overlay.sample(s, in.texcoord);
    return color;
}
"#;

// ---------------------------------------------------------------------------
// Global CEF Metal Compositor (thread-safe singleton)
// ---------------------------------------------------------------------------

/// Thread-safe pending frame data exchanged between the CEF bridge and the
/// Metal compositor.
/// Wrapper around a raw IOSurface pointer that is explicitly `Send` + `Sync`.
/// Raw pointers are not `Send` by default, but IOSurfaceRefs are safe to
/// transfer between threads (they are CoreFoundation objects with retain/release
/// semantics and can be used from any thread).
#[derive(Clone, Copy)]
struct IoSurfacePtr(*mut std::ffi::c_void);
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Send for IoSurfacePtr {}
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Sync for IoSurfacePtr {}

/// Retain an IOSurfaceRef (+1) so it stays alive while stored in the compositor.
#[cfg(target_os = "macos")]
fn retain_io_surface(surface: *mut std::ffi::c_void) {
    if !surface.is_null() {
        // SAFETY: `surface` is a valid IOSurfaceRef (a CoreFoundation object);
        // CFRetain is thread-safe and takes a +1 reference.
        unsafe {
            core_foundation::base::CFRetain(surface as *const std::ffi::c_void);
        }
    }
}

/// Release an IOSurfaceRef (−1). No-op for null pointers.
#[cfg(target_os = "macos")]
fn release_io_surface(surface: *mut std::ffi::c_void) {
    if !surface.is_null() {
        // SAFETY: `surface` is a valid IOSurfaceRef with a +1 reference owned
        // by the caller (or the compositor/frame that calls this).
        unsafe {
            core_foundation::base::CFRelease(surface as *const std::ffi::c_void);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn retain_io_surface(_surface: *mut std::ffi::c_void) {}

#[cfg(not(target_os = "macos"))]
fn release_io_surface(_surface: *mut std::ffi::c_void) {}

/// Convert a tightly-packed RGBA8 pixel buffer to BGRA8 in place (swap the red
/// and blue channels), so the CPU upload path matches the IOSurface path's
/// BGRA byte order and both paths sample identical colours.
fn rgba_to_bgra_in_place(pixels: &mut [u8]) {
    for px in pixels.chunks_exact_mut(4) {
        px.swap(0, 2);
    }
}

/// Thread-safe pending frame data exchanged between the CEF bridge and the
/// Metal compositor.
pub struct CefMetalCompositor {
    /// Pending overlay frame data (RGBA pixels) from WKWebView snapshot.
    pending_width: u32,
    pending_height: u32,
    pending_pixels: Option<Vec<u8>>,
    /// Optional IOSurface handle for zero-copy frame exchange.
    /// When set, the compositor prefers IOSurface-backed textures over
    /// CPU-side pixel uploads. The compositor owns a +1 reference on the
    /// surface from submit until the frame is consumed.
    pending_io_surface: Option<IoSurfacePtr>,
    /// Last frame number submitted (for tracking updates).
    last_frame_number: u64,
    /// Whether a game is currently rendering (true) or only Steam UI is visible (false).
    /// When false, the compositor renders the CEF overlay as a full-screen texture
    /// covering the entire drawable.
    game_active: bool,
    /// Timestamp of the last vsync-aligned composite (nanoseconds, mach_absolute_time).
    last_vsync_timestamp: u64,
    /// Target frame interval for 60fps compositing (~16.67ms in nanoseconds).
    vsync_interval_ns: u64,
}

impl Default for CefMetalCompositor {
    fn default() -> Self {
        Self::new()
    }
}

impl CefMetalCompositor {
    /// Create a new empty compositor.
    pub fn new() -> Self {
        CefMetalCompositor {
            pending_width: 0,
            pending_height: 0,
            pending_pixels: None,
            pending_io_surface: None,
            last_frame_number: 0,
            game_active: false,
            last_vsync_timestamp: 0,
            vsync_interval_ns: 16_666_667, // ~60fps
        }
    }

    /// Submit a new CEF overlay frame for compositing. Called by the CEF bridge
    /// when a new WKWebView snapshot is available.
    ///
    /// `pixels` are tightly-packed 32-bit RGBA bytes (R, G, B, A per pixel) in
    /// top-down row order. They are converted to BGRA on upload to match the
    /// IOSurface path.
    pub fn submit_frame(&mut self, width: u32, height: u32, pixels: Vec<u8>) {
        // A CPU frame replaces any still-pending IOSurface reference.
        self.clear_pending_io_surface();
        self.pending_width = width;
        self.pending_height = height;
        self.pending_pixels = Some(pixels);
        self.last_frame_number += 1;
    }

    /// Submit a new CEF overlay frame via IOSurface (zero-copy path).
    /// The IOSurface must contain BGRA8 pixel data at the given dimensions.
    ///
    /// # Safety
    /// `io_surface_ptr` must be a valid IOSurfaceRef with matching dimensions.
    ///
    /// The compositor retains its own reference on submit and releases it when
    /// the frame is consumed (`take_pending_frame`), so the caller may release
    /// its reference immediately after this call returns.
    pub unsafe fn submit_io_surface_frame(
        &mut self,
        width: u32,
        height: u32,
        io_surface_ptr: *mut std::ffi::c_void,
    ) {
        // Replace any still-pending surface (releasing our old reference).
        self.clear_pending_io_surface();
        self.pending_width = width;
        self.pending_height = height;
        // Take our own reference so the surface stays alive until the frame is
        // consumed, regardless of what the caller does with its copy.
        retain_io_surface(io_surface_ptr);
        self.pending_io_surface = Some(IoSurfacePtr(io_surface_ptr));
        self.pending_pixels = None;
        self.last_frame_number += 1;
    }

    /// Drop the pending IOSurface reference, if any.
    fn clear_pending_io_surface(&mut self) {
        if let Some(ptr) = self.pending_io_surface.take() {
            release_io_surface(ptr.0);
        }
    }

    /// Take the pending frame data (if any) for upload to the Metal texture.
    /// Returns `None` if no new frame has arrived since the last take.
    pub fn take_pending_frame(&mut self) -> Option<PendingCefFrame> {
        let io_surface = self.pending_io_surface.take().map(|p| p.0);
        let pixels = self.pending_pixels.take();
        if io_surface.is_none() && pixels.is_none() {
            return None;
        }
        Some(PendingCefFrame {
            width: self.pending_width,
            height: self.pending_height,
            pixels: pixels.unwrap_or_default(),
            io_surface,
            frame_number: self.last_frame_number,
        })
    }

    /// Check whether a pending frame is available without consuming it.
    pub fn has_pending_frame(&self) -> bool {
        self.pending_pixels.is_some() || self.pending_io_surface.is_some()
    }

    /// Get the dimensions of the pending frame (if available).
    pub fn pending_dimensions(&self) -> Option<(u32, u32)> {
        if self.pending_pixels.is_some() || self.pending_io_surface.is_some() {
            Some((self.pending_width, self.pending_height))
        } else {
            None
        }
    }

    /// Set whether a game is actively rendering (vs. only Steam UI visible).
    /// When `game_active` is false, the compositor renders the CEF overlay as
    /// a full-screen texture covering the entire drawable (Steam library/store).
    pub fn set_game_active(&mut self, active: bool) {
        self.game_active = active;
    }

    /// Check whether a game is actively rendering.
    pub fn is_game_active(&self) -> bool {
        self.game_active
    }

    /// Get the last frame number submitted.
    pub fn last_frame_number(&self) -> u64 {
        self.last_frame_number
    }

    /// Check if enough time has elapsed since the last composite to issue
    /// a new vsync-aligned frame (60fps throttle).
    pub fn should_composite(&mut self) -> bool {
        let now = mach_absolute_time();
        let elapsed = now.saturating_sub(self.last_vsync_timestamp);
        if elapsed >= self.vsync_interval_ns {
            self.last_vsync_timestamp = now;
            true
        } else {
            false
        }
    }
}

/// A pending CEF overlay frame ready for GPU upload.
pub struct PendingCefFrame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    /// Optional IOSurface pointer for zero-copy texture creation.
    /// The frame owns a +1 reference, released when the frame is dropped
    /// (see [`Drop`]).
    pub io_surface: Option<*mut std::ffi::c_void>,
    /// Monotonically increasing frame number.
    pub frame_number: u64,
}

impl Drop for PendingCefFrame {
    fn drop(&mut self) {
        // Release the +1 reference we own on the IOSurface, if the consumer
        // has not taken it out of the frame (e.g. on early-return paths).
        if let Some(surface) = self.io_surface {
            release_io_surface(surface);
        }
    }
}

// Global singleton following the same pattern as GLOBAL_CEF_BRIDGE in cef_bridge.rs
static GLOBAL_CEF_METAL_COMPOSITOR: std::sync::LazyLock<std::sync::Mutex<CefMetalCompositor>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(CefMetalCompositor::new()));

/// Access the global CEF Metal compositor with a closure.
pub fn with_global_cef_compositor<F, R>(f: F) -> R
where
    F: FnOnce(&mut CefMetalCompositor) -> R,
{
    let mut guard = GLOBAL_CEF_METAL_COMPOSITOR.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Submit a CEF overlay frame to the global compositor. This is the primary
/// entry point called by the CEF bridge when new WKWebView content arrives.
pub fn submit_cef_overlay_frame(width: u32, height: u32, pixels: Vec<u8>) {
    with_global_cef_compositor(|compositor| {
        compositor.submit_frame(width, height, pixels);
    });
}

/// Submit a CEF overlay frame via IOSurface (zero-copy path).
///
/// # Safety
/// `io_surface_ptr` must be a valid IOSurfaceRef.
pub unsafe fn submit_cef_overlay_io_surface(
    width: u32,
    height: u32,
    io_surface_ptr: *mut std::ffi::c_void,
) {
    with_global_cef_compositor(|compositor| unsafe {
        compositor.submit_io_surface_frame(width, height, io_surface_ptr);
    });
}

/// Mark whether a game is actively rendering in the global compositor.
pub fn set_cef_compositor_game_active(active: bool) {
    with_global_cef_compositor(|compositor| {
        compositor.set_game_active(active);
    });
}

// ---------------------------------------------------------------------------
// Vsync helper — macOS mach_absolute_time for frame pacing
// ---------------------------------------------------------------------------

/// Get the current time in nanoseconds from mach_absolute_time.
/// Uses mach_timebase_info to convert from Mach absolute time units.
///
/// The multiplication is done in 128-bit so a long-running timer value cannot
/// wrap around (timebase.numer is usually 125).
fn mach_absolute_time() -> u64 {
    #[cfg(target_os = "macos")]
    {
        #[allow(deprecated)]
        // SAFETY: Objective-C FFI for Metal rendering pipeline
        unsafe {
            let mut timebase: libc::mach_timebase_info = std::mem::zeroed();
            libc::mach_timebase_info(&mut timebase);
            let mach_time = libc::mach_absolute_time();
            let nanos = ((mach_time as u128) * (timebase.numer as u128)) / (timebase.denom as u128);
            nanos.min(u64::MAX as u128) as u64
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Fallback: use std::time
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

// ---------------------------------------------------------------------------
// Frame context
// ---------------------------------------------------------------------------

/// Context for a single frame's rendering.
pub struct FrameContext {
    command_buffer: metal::CommandBuffer,
    width: u32,
    height: u32,
    frame_index: u64,
}

impl FrameContext {
    /// Get the command buffer.
    pub fn command_buffer(&self) -> &metal::CommandBufferRef {
        &self.command_buffer
    }

    /// Get the frame width.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get the frame height.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get the frame index.
    pub fn frame_index(&self) -> u64 {
        self.frame_index
    }

    /// Create a default viewport for the frame.
    pub fn default_viewport(&self) -> Viewport {
        Viewport {
            x: 0.0,
            y: 0.0,
            width: self.width as f32,
            height: self.height as f32,
            min_depth: 0.0,
            max_depth: 1.0,
        }
    }

    /// Create a default scissor rect for the frame.
    pub fn default_scissor(&self) -> ScissorRect {
        ScissorRect {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        }
    }
}

// ---------------------------------------------------------------------------
// Blend factor translation
// ---------------------------------------------------------------------------

/// Translate a D3D11 blend factor to Metal for the **RGB** channels.
///
/// `BlendFactor::BlendFactor` (D3D11_BLEND_BLEND_FACTOR) applies the blend
/// constant to all components, so RGB factors map to Metal's `BlendColor`.
pub fn blend_factor_to_metal(factor: BlendFactor) -> metal::MTLBlendFactor {
    match factor {
        BlendFactor::Zero => metal::MTLBlendFactor::Zero,
        BlendFactor::One => metal::MTLBlendFactor::One,
        BlendFactor::SrcColor => metal::MTLBlendFactor::SourceColor,
        BlendFactor::InvSrcColor => metal::MTLBlendFactor::OneMinusSourceColor,
        BlendFactor::SrcAlpha => metal::MTLBlendFactor::SourceAlpha,
        BlendFactor::InvSrcAlpha => metal::MTLBlendFactor::OneMinusSourceAlpha,
        BlendFactor::DstAlpha => metal::MTLBlendFactor::DestinationAlpha,
        BlendFactor::InvDstAlpha => metal::MTLBlendFactor::OneMinusDestinationAlpha,
        BlendFactor::DstColor => metal::MTLBlendFactor::DestinationColor,
        BlendFactor::InvDstColor => metal::MTLBlendFactor::OneMinusDestinationColor,
        BlendFactor::SrcAlphaSaturate => metal::MTLBlendFactor::SourceAlphaSaturated,
        BlendFactor::BlendFactor => metal::MTLBlendFactor::BlendColor,
    }
}

/// Translate a D3D11 blend factor to Metal for the **alpha** channel.
///
/// Alpha factors of `BlendFactor::BlendFactor` map to Metal's `BlendAlpha`
/// (which uses only the alpha component of the blend constant).
pub fn blend_factor_to_metal_alpha(factor: BlendFactor) -> metal::MTLBlendFactor {
    match factor {
        BlendFactor::BlendFactor => metal::MTLBlendFactor::BlendAlpha,
        other => blend_factor_to_metal(other),
    }
}

/// Translate a D3D11 blend operation to Metal.
pub fn blend_op_to_metal(op: BlendOp) -> metal::MTLBlendOperation {
    match op {
        BlendOp::Add => metal::MTLBlendOperation::Add,
        BlendOp::Subtract => metal::MTLBlendOperation::Subtract,
        BlendOp::RevSubtract => metal::MTLBlendOperation::ReverseSubtract,
        BlendOp::Min => metal::MTLBlendOperation::Min,
        BlendOp::Max => metal::MTLBlendOperation::Max,
    }
}

/// Translate a D3D11 fill mode to Metal.
pub fn fill_mode_to_metal(mode: FillMode) -> metal::MTLTriangleFillMode {
    match mode {
        FillMode::Wireframe => metal::MTLTriangleFillMode::Lines,
        FillMode::Solid => metal::MTLTriangleFillMode::Fill,
    }
}

/// Translate a D3D11 cull mode to Metal.
pub fn cull_mode_to_metal(mode: CullMode) -> metal::MTLCullMode {
    match mode {
        CullMode::None => metal::MTLCullMode::None,
        CullMode::Front => metal::MTLCullMode::Front,
        CullMode::Back => metal::MTLCullMode::Back,
    }
}

/// Translate a D3D11 winding to Metal.
pub fn winding_to_metal(counter_clockwise: bool) -> metal::MTLWinding {
    if counter_clockwise {
        metal::MTLWinding::CounterClockwise
    } else {
        metal::MTLWinding::Clockwise
    }
}

// ---------------------------------------------------------------------------
// Format support queries
// ---------------------------------------------------------------------------

/// Check if a DXGI format is supported for a given usage on Metal.
pub fn is_format_supported(format: DxgiFormat, usage: FormatUsage) -> bool {
    let mtl_format = dxgi_to_metal_format(format);
    match usage {
        FormatUsage::RenderTarget => matches!(
            mtl_format,
            metal::MTLPixelFormat::RGBA8Unorm
                | metal::MTLPixelFormat::BGRA8Unorm
                | metal::MTLPixelFormat::R16Float
                | metal::MTLPixelFormat::R32Float
                | metal::MTLPixelFormat::RGB10A2Unorm
        ),
        FormatUsage::DepthStencil => matches!(
            mtl_format,
            metal::MTLPixelFormat::Depth24Unorm_Stencil8
                | metal::MTLPixelFormat::Depth32Float
                | metal::MTLPixelFormat::Depth16Unorm
        ),
        FormatUsage::ShaderResource => true, // Most formats are readable
        FormatUsage::UnorderedAccess => matches!(
            mtl_format,
            metal::MTLPixelFormat::RGBA8Unorm
                | metal::MTLPixelFormat::R32Float
                | metal::MTLPixelFormat::BGRA8Unorm
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatUsage {
    RenderTarget,
    DepthStencil,
    ShaderResource,
    UnorderedAccess,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_context_creation() {
        let ctx = MetalRenderContext::new();
        assert!(ctx.is_ok(), "expected Metal render context to be created");
        let ctx = ctx.unwrap();
        assert!(!ctx.device_name().is_empty());
    }

    #[test]
    fn swapchain_creation() {
        let mut ctx = MetalRenderContext::new().unwrap();
        ctx.create_swapchain(1024, 768);
        assert!(ctx.swapchain().is_some());
        assert_eq!(ctx.swapchain().unwrap().size(), (1024, 768));
    }

    #[test]
    fn swapchain_resize() {
        let mut ctx = MetalRenderContext::new().unwrap();
        ctx.create_swapchain(800, 600);
        ctx.resize_swapchain(1920, 1080);
        assert_eq!(ctx.swapchain().unwrap().size(), (1920, 1080));
    }

    #[test]
    fn frame_context() {
        let mut ctx = MetalRenderContext::new().unwrap();
        ctx.create_swapchain(800, 600);
        let frame = ctx.begin_frame().unwrap();
        assert_eq!(frame.width(), 800);
        assert_eq!(frame.height(), 600);
        assert_eq!(frame.frame_index(), 0);
        let vp = frame.default_viewport();
        assert_eq!(vp.width, 800.0);
    }

    #[test]
    fn depth_stencil_state_caching() {
        let mut ctx = MetalRenderContext::new().unwrap();
        ctx.get_depth_stencil_state(true, true, ComparisonFunc::Less);
        ctx.get_depth_stencil_state(true, true, ComparisonFunc::Less);
        // If we get here without panic, caching works (no duplicate creation error)
        let idx = depth_stencil_state_index(true, true, ComparisonFunc::Less);
        assert!(ctx.depth_stencil_states[idx].is_some());
        // A different function variant occupies a different slot.
        let other = depth_stencil_state_index(true, true, ComparisonFunc::Greater);
        assert!(ctx.depth_stencil_states[other].is_none());
    }

    #[test]
    fn comparison_func_translation() {
        assert_eq!(
            ComparisonFunc::Less.to_metal(),
            metal::MTLCompareFunction::Less
        );
        assert_eq!(
            ComparisonFunc::Always.to_metal(),
            metal::MTLCompareFunction::Always
        );
        assert_eq!(
            ComparisonFunc::Greater.to_metal(),
            metal::MTLCompareFunction::Greater
        );
    }

    #[test]
    fn primitive_topology_translation() {
        assert_eq!(
            PrimitiveTopology::TriangleList.to_metal(),
            metal::MTLPrimitiveType::Triangle
        );
        assert_eq!(
            PrimitiveTopology::LineList.to_metal(),
            metal::MTLPrimitiveType::Line
        );
        assert_eq!(
            PrimitiveTopology::PointList.to_metal(),
            metal::MTLPrimitiveType::Point
        );
    }

    #[test]
    fn blend_factor_translation() {
        assert_eq!(
            blend_factor_to_metal(BlendFactor::SrcAlpha),
            metal::MTLBlendFactor::SourceAlpha
        );
        assert_eq!(
            blend_factor_to_metal(BlendFactor::InvSrcAlpha),
            metal::MTLBlendFactor::OneMinusSourceAlpha
        );
        assert_eq!(
            blend_factor_to_metal(BlendFactor::Zero),
            metal::MTLBlendFactor::Zero
        );
    }

    #[test]
    fn blend_op_translation() {
        assert_eq!(
            blend_op_to_metal(BlendOp::Add),
            metal::MTLBlendOperation::Add
        );
        assert_eq!(
            blend_op_to_metal(BlendOp::Subtract),
            metal::MTLBlendOperation::Subtract
        );
    }

    #[test]
    fn blend_factor_translation_rgb_vs_alpha() {
        // D3D11_BLEND_BLEND_FACTOR applies the blend constant to every
        // component: RGB → BlendColor, alpha → BlendAlpha.
        assert_eq!(
            blend_factor_to_metal(BlendFactor::BlendFactor),
            metal::MTLBlendFactor::BlendColor
        );
        assert_eq!(
            blend_factor_to_metal_alpha(BlendFactor::BlendFactor),
            metal::MTLBlendFactor::BlendAlpha
        );
        // Non-BlendFactor factors are identical in both variants.
        assert_eq!(
            blend_factor_to_metal(BlendFactor::SrcAlpha),
            blend_factor_to_metal_alpha(BlendFactor::SrcAlpha)
        );
    }

    #[test]
    fn rgba_to_bgra_in_place_swaps_channels() {
        // Both the IOSurface path (BGRA8) and the CPU path must sample the
        // same colours; the CPU upload converts RGBA → BGRA exactly once.
        let mut px = vec![0x11, 0x22, 0x33, 0xFF, 0xAA, 0xBB, 0xCC, 0x00];
        rgba_to_bgra_in_place(&mut px);
        assert_eq!(px, vec![0x33, 0x22, 0x11, 0xFF, 0xCC, 0xBB, 0xAA, 0x00]);
        // Converting again must not be a no-op if re-run (safety check), so a
        // second pass swaps back — callers must apply it exactly once.
        rgba_to_bgra_in_place(&mut px);
        assert_eq!(px, vec![0x11, 0x22, 0x33, 0xFF, 0xAA, 0xBB, 0xCC, 0x00]);
    }

    #[test]
    fn compositor_io_surface_ownership_is_balanced() {
        // Ownership bookkeeping is pointer-agnostic; a null surface must not
        // crash retain/release paths.
        retain_io_surface(std::ptr::null_mut());
        release_io_surface(std::ptr::null_mut());

        // submit_frame must not leak a previously pending IO surface
        // reference (clear_pending_io_surface handles it).
        let mut compositor = CefMetalCompositor::new();
        compositor.submit_frame(2, 2, vec![0u8; 16]);
        let frame = compositor.take_pending_frame().unwrap();
        assert!(frame.io_surface.is_none());
        assert!(compositor.take_pending_frame().is_none());
    }

    #[test]
    fn fill_mode_translation() {
        assert_eq!(
            fill_mode_to_metal(FillMode::Solid),
            metal::MTLTriangleFillMode::Fill
        );
        assert_eq!(
            fill_mode_to_metal(FillMode::Wireframe),
            metal::MTLTriangleFillMode::Lines
        );
    }

    #[test]
    fn cull_mode_translation() {
        assert_eq!(cull_mode_to_metal(CullMode::None), metal::MTLCullMode::None);
        assert_eq!(cull_mode_to_metal(CullMode::Back), metal::MTLCullMode::Back);
    }

    #[test]
    fn format_support_render_target() {
        assert!(is_format_supported(
            DxgiFormat::B8G8R8A8Unorm,
            FormatUsage::RenderTarget
        ));
        assert!(is_format_supported(
            DxgiFormat::R8G8B8A8Unorm,
            FormatUsage::RenderTarget
        ));
        assert!(!is_format_supported(
            DxgiFormat::D24UnormS8Uint,
            FormatUsage::RenderTarget
        ));
    }

    #[test]
    fn format_support_depth() {
        assert!(is_format_supported(
            DxgiFormat::D24UnormS8Uint,
            FormatUsage::DepthStencil
        ));
        assert!(!is_format_supported(
            DxgiFormat::B8G8R8A8Unorm,
            FormatUsage::DepthStencil
        ));
    }

    #[test]
    fn default_viewport() {
        let vp = Viewport::default();
        assert_eq!(vp.width, 800.0);
        assert_eq!(vp.height, 600.0);
        assert_eq!(vp.min_depth, 0.0);
        assert_eq!(vp.max_depth, 1.0);
    }

    #[test]
    fn default_blend_state() {
        let blend = BlendDesc::default();
        assert!(!blend.blend_enable);
        assert_eq!(blend.src_blend, BlendFactor::One);
        assert_eq!(blend.dst_blend, BlendFactor::Zero);
    }

    #[test]
    fn default_rasterizer_state() {
        let raster = RasterizerDesc::default();
        assert_eq!(raster.fill_mode, FillMode::Solid);
        assert_eq!(raster.cull_mode, CullMode::None);
        assert!(raster.depth_clip_enable);
    }

    #[test]
    fn default_depth_stencil_state() {
        let ds = DepthStencilDesc::default();
        assert!(ds.depth_enable);
        assert!(ds.depth_write_enable);
        assert_eq!(ds.depth_func, ComparisonFunc::Less);
        assert!(!ds.stencil_enable);
    }
}
