//! Real Metal rendering pipeline for Casa1.
//!
//! Bridges D3D11/D3D12 draw calls to real Metal command encoding, providing
//! actual GPU-accelerated rendering. This module connects the D3D API layer
//! to the Metal GPU backend from `src/metal_backend.rs`.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::gfx::DxgiFormat;
use crate::metal_backend::{MetalDevice, MetalSwapchain, dxgi_to_metal_format};
use std::collections::BTreeMap;

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
    depth_stencil_states: BTreeMap<String, metal::DepthStencilState>,
}

impl MetalRenderContext {
    /// Create a new rendering context.
    pub fn new() -> AppResult<Self> {
        let device = MetalDevice::system_default()?;
        let command_queue = device.create_command_queue().to_owned();

        Ok(Self {
            device,
            command_queue,
            swapchain: None,
            frame_index: 0,
            depth_stencil_states: BTreeMap::new(),
        })
    }

    /// Create a swapchain for rendering.
    pub fn create_swapchain(&mut self, width: u32, height: u32) {
        self.swapchain = Some(MetalSwapchain::new(self.device.device(), width as u64, height as u64));
    }

    /// Resize the swapchain.
    pub fn resize_swapchain(&mut self, width: u32, height: u32) {
        if let Some(ref mut swapchain) = self.swapchain {
            swapchain.resize(width as u64, height as u64);
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
    pub fn get_depth_stencil_state(
        &mut self,
        depth_enable: bool,
        depth_write_enable: bool,
        depth_func: ComparisonFunc,
    ) -> &metal::DepthStencilStateRef {
        let key = format!("{depth_enable}_{depth_write_enable}_{:?}", depth_func);
        if !self.depth_stencil_states.contains_key(&key) {
            let state = if depth_enable {
                self.device.create_depth_stencil_state(
                    depth_func.to_metal(),
                    depth_write_enable,
                )
            } else {
                self.device.create_depth_stencil_state(
                    metal::MTLCompareFunction::Always,
                    false,
                )
            };
            self.depth_stencil_states.insert(key.clone(), state);
        }
        self.depth_stencil_states.get(&key).unwrap()
    }

    /// Begin a new frame.
    pub fn begin_frame(&mut self) -> AppResult<FrameContext> {
        let (width, height) = self.swapchain
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
    pub fn end_frame(&mut self) {
        self.frame_index += 1;
    }

    /// Present the swapchain.
    pub fn present(&self) -> AppResult<()> {
        let swapchain = self.swapchain.as_ref().ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, "no swapchain created")
        })?;

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

/// Translate a D3D11 blend factor to Metal.
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
        BlendFactor::BlendFactor => metal::MTLBlendFactor::BlendAlpha,
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
        assert!(ctx.is_ok());
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
        assert_eq!(ctx.depth_stencil_states.len(), 1);
    }

    #[test]
    fn comparison_func_translation() {
        assert_eq!(ComparisonFunc::Less.to_metal(), metal::MTLCompareFunction::Less);
        assert_eq!(ComparisonFunc::Always.to_metal(), metal::MTLCompareFunction::Always);
        assert_eq!(ComparisonFunc::Greater.to_metal(), metal::MTLCompareFunction::Greater);
    }

    #[test]
    fn primitive_topology_translation() {
        assert_eq!(PrimitiveTopology::TriangleList.to_metal(), metal::MTLPrimitiveType::Triangle);
        assert_eq!(PrimitiveTopology::LineList.to_metal(), metal::MTLPrimitiveType::Line);
        assert_eq!(PrimitiveTopology::PointList.to_metal(), metal::MTLPrimitiveType::Point);
    }

    #[test]
    fn blend_factor_translation() {
        assert_eq!(blend_factor_to_metal(BlendFactor::SrcAlpha), metal::MTLBlendFactor::SourceAlpha);
        assert_eq!(blend_factor_to_metal(BlendFactor::InvSrcAlpha), metal::MTLBlendFactor::OneMinusSourceAlpha);
        assert_eq!(blend_factor_to_metal(BlendFactor::Zero), metal::MTLBlendFactor::Zero);
    }

    #[test]
    fn blend_op_translation() {
        assert_eq!(blend_op_to_metal(BlendOp::Add), metal::MTLBlendOperation::Add);
        assert_eq!(blend_op_to_metal(BlendOp::Subtract), metal::MTLBlendOperation::Subtract);
    }

    #[test]
    fn fill_mode_translation() {
        assert_eq!(fill_mode_to_metal(FillMode::Solid), metal::MTLTriangleFillMode::Fill);
        assert_eq!(fill_mode_to_metal(FillMode::Wireframe), metal::MTLTriangleFillMode::Lines);
    }

    #[test]
    fn cull_mode_translation() {
        assert_eq!(cull_mode_to_metal(CullMode::None), metal::MTLCullMode::None);
        assert_eq!(cull_mode_to_metal(CullMode::Back), metal::MTLCullMode::Back);
    }

    #[test]
    fn format_support_render_target() {
        assert!(is_format_supported(DxgiFormat::B8G8R8A8Unorm, FormatUsage::RenderTarget));
        assert!(is_format_supported(DxgiFormat::R8G8B8A8Unorm, FormatUsage::RenderTarget));
        assert!(!is_format_supported(DxgiFormat::D24UnormS8Uint, FormatUsage::RenderTarget));
    }

    #[test]
    fn format_support_depth() {
        assert!(is_format_supported(DxgiFormat::D24UnormS8Uint, FormatUsage::DepthStencil));
        assert!(!is_format_supported(DxgiFormat::B8G8R8A8Unorm, FormatUsage::DepthStencil));
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
