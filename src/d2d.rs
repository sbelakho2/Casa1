//! Direct2D (D2D) implementation.
//!
//! This module provides D2D-compatible primitives and render targets.
//! Pixel output delegates to the software rasterizer in
//! [`gdiplus_render`](crate::gdiplus_render) by default. When a
//! [`MetalD2DRenderer`](crate::metal_backend::MetalD2DRenderer) is attached,
//! rendering is hardware-accelerated via Metal.

use std::collections::HashMap;

use crate::gdiplus_render;
use crate::metal_backend::MetalD2DRenderer;
use crate::user32::{GDIPLUS_COMPOSITING_MODE_SOURCE_OVER, GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS};

// ── Forward declarations from dwrite ────────────────────────────────────

use crate::dwrite::{DWriteFactory, DWriteTextFormat};

// ── Constants ───────────────────────────────────────────────────────────

/// D2D1_ALPHA_MODE constants
pub const D2D1_ALPHA_MODE_UNKNOWN: u32 = 0;
pub const D2D1_ALPHA_MODE_PREMULTIPLIED: u32 = 1;
pub const D2D1_ALPHA_MODE_STRAIGHT: u32 = 2;
pub const D2D1_ALPHA_MODE_IGNORE: u32 = 3;

/// DXGI_FORMAT constants (subset used by D2D)
pub const DXGI_FORMAT_UNKNOWN: u32 = 0;
pub const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
pub const DXGI_FORMAT_B8G8R8A8_UNORM_SRGB: u32 = 91;

/// D2D1_ANTIALIAS_MODE
pub const D2D1_ANTIALIAS_MODE_PER_PRIMITIVE: u32 = 0;
pub const D2D1_ANTIALIAS_MODE_ALIASED: u32 = 1;

/// D2D1_TEXT_ANTIALIAS_MODE
pub const D2D1_TEXT_ANTIALIAS_MODE_DEFAULT: u32 = 0;
pub const D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE: u32 = 1;
pub const D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE: u32 = 2;
pub const D2D1_TEXT_ANTIALIAS_MODE_ALIASED: u32 = 3;

/// D2D1_RENDER_TARGET_TYPE
pub const D2D1_RENDER_TARGET_TYPE_DEFAULT: u32 = 0;
pub const D2D1_RENDER_TARGET_TYPE_SOFTWARE: u32 = 2;

/// D2D1_RENDER_TARGET_USAGE
pub const D2D1_RENDER_TARGET_USAGE_NONE: u32 = 0;
pub const D2D1_RENDER_TARGET_USAGE_FORCE_BITMAP_REMOTE: u32 = 1;
pub const D2D1_RENDER_TARGET_USAGE_GDI_COMPATIBLE: u32 = 2;

/// D2D1_FACTORY_TYPE
pub const D2D1_FACTORY_TYPE_SINGLE_THREADED: u32 = 0;
pub const D2D1_FACTORY_TYPE_MULTI_THREADED: u32 = 1;

/// IID for ID2D1Factory: {06152247-6F50-465A-9245-118BFD3B6007}
pub const IID_ID2D1Factory: [u8; 16] = [
    0x47, 0x22, 0x15, 0x06, 0x50, 0x6F, 0x5A, 0x46, 0x92, 0x45, 0x11, 0x8B, 0xFD, 0x3B, 0x60, 0x07,
];
/// IID for ID2D1HwndRenderTarget.
///
/// ID2D1HwndRenderTarget is a pure C++ extension of ID2D1RenderTarget and
/// has no distinct IID in d2d1.h; guests QI it with the ID2D1RenderTarget
/// IID: {2CD90694-12E2-11DC-9FED-001143A055F9}
pub const IID_ID2D1HwndRenderTarget: [u8; 16] = [
    0x94, 0x06, 0xD9, 0x2C, 0xE2, 0x12, 0xDC, 0x11, 0x9F, 0xED, 0x00, 0x11, 0x43, 0xA0, 0x55, 0xF9,
];

// ── Core types ──────────────────────────────────────────────────────────

/// 3×3 affine transformation matrix stored in row-major order.
/// Index layout:
///   [0]=M11 [1]=M12 [2]=M21 [3]=M22 [4]=DX  [5]=DY
///   The remaining 3 slots are zero-padding for the 3×3 matrix.
pub type D2DMatrix = [f32; 9];

/// Pixel format descriptor.
#[derive(Debug, Clone, Copy)]
pub struct D2DPixelFormat {
    pub dxgi_format: u32,
    pub alpha_mode: u32,
}

impl Default for D2DPixelFormat {
    fn default() -> Self {
        D2DPixelFormat {
            dxgi_format: DXGI_FORMAT_B8G8R8A8_UNORM,
            alpha_mode: D2D1_ALPHA_MODE_PREMULTIPLIED,
        }
    }
}

/// Gradient stop for brush definitions.
#[derive(Debug, Clone)]
pub struct D2DGradientStop {
    pub position: f32,
    pub color: (f32, f32, f32, f32),
}

/// Render state tracked between BeginDraw/EndDraw.
#[derive(Debug, Clone)]
pub struct RenderState {
    pub antialias_mode: u32,
    pub text_antialias_mode: u32,
    pub tags: (u64, u64),
    pub drawing: bool,
}

impl Default for RenderState {
    fn default() -> Self {
        RenderState {
            antialias_mode: D2D1_ANTIALIAS_MODE_PER_PRIMITIVE,
            text_antialias_mode: D2D1_TEXT_ANTIALIAS_MODE_DEFAULT,
            tags: (0, 0),
            drawing: false,
        }
    }
}

/// A D2D bitmap (surface).
#[derive(Debug, Clone)]
pub struct D2DBitmap {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub data: Vec<u8>,
    pub dpi: f32,
    pub pixel_format: D2DPixelFormat,
}

/// A solid-color brush.
#[derive(Debug, Clone)]
pub struct D2DSolidColorBrush {
    pub color: (f32, f32, f32, f32),
    pub opacity: f32,
}

/// A linear-gradient brush.
#[derive(Debug, Clone)]
pub struct D2DLinearGradientBrush {
    pub start_point: (f32, f32),
    pub end_point: (f32, f32),
    pub stops: Vec<D2DGradientStop>,
}

/// A radial-gradient brush.
#[derive(Debug, Clone)]
pub struct D2DRadialGradientBrush {
    pub center: (f32, f32),
    pub radius_x: f32,
    pub radius_y: f32,
    pub stops: Vec<D2DGradientStop>,
}

/// Enum of all D2D brush types.
#[derive(Debug, Clone)]
pub enum D2DBrush {
    Solid(D2DSolidColorBrush),
    LinearGradient(D2DLinearGradientBrush),
    RadialGradient(D2DRadialGradientBrush),
}

/// Interpolate the gradient color at parameter `t`.
///
/// `t` is clamped to the first and last stop positions so values outside
/// the stop range do not extrapolate (which would produce out-of-range,
/// possibly negative, channel values).
fn interpolate_gradient(t: f32, stops: &[D2DGradientStop]) -> (f32, f32, f32, f32) {
    match stops {
        [] => (1.0, 1.0, 1.0, 1.0),
        [only] => only.color,
        _ => {
            let first = stops.first().expect("non-empty stops");
            let last = stops.last().expect("non-empty stops");
            let t = if t.is_finite()
                && first.position.is_finite()
                && last.position.is_finite()
                && first.position <= last.position
            {
                t.clamp(first.position, last.position)
            } else {
                // Degenerate or non-finite stop positions: clamp to [0, 1].
                t.clamp(0.0, 1.0)
            };
            // Find the last stop at or before t
            let i = stops
                .iter()
                .rposition(|stop| stop.position <= t)
                .unwrap_or(0);
            let next = (i + 1).min(stops.len() - 1);
            if i == next {
                stops[i].color
            } else {
                let span = stops[next].position - stops[i].position;
                let local_t = if span > 0.0 {
                    (t - stops[i].position) / span
                } else {
                    0.0
                };
                let it = 1.0 - local_t;
                (
                    stops[i].color.0 * it + stops[next].color.0 * local_t,
                    stops[i].color.1 * it + stops[next].color.1 * local_t,
                    stops[i].color.2 * it + stops[next].color.2 * local_t,
                    stops[i].color.3 * it + stops[next].color.3 * local_t,
                )
            }
        }
    }
}

impl D2DBrush {
    /// Resolve the colour at the given point.
    pub fn color_at(&self, px: f32, py: f32) -> u32 {
        let (color, opacity) = match self {
            D2DBrush::Solid(s) => ((s.color.0, s.color.1, s.color.2, s.color.3), s.opacity),
            D2DBrush::LinearGradient(lb) => {
                let dx = lb.end_point.0 - lb.start_point.0;
                let dy = lb.end_point.1 - lb.start_point.1;
                let len_sq = dx * dx + dy * dy;
                let t = if len_sq > 0.0001 {
                    ((px - lb.start_point.0) * dx + (py - lb.start_point.1) * dy) / len_sq
                } else {
                    0.0
                };
                (interpolate_gradient(t, &lb.stops), 1.0)
            }
            D2DBrush::RadialGradient(rb) => {
                let dx = px - rb.center.0;
                let dy = py - rb.center.1;
                let radius_x_sq = rb.radius_x * rb.radius_x;
                let radius_y_sq = rb.radius_y * rb.radius_y;
                let t = if radius_x_sq > 0.0 && radius_y_sq > 0.0 {
                    ((dx * dx) / radius_x_sq + (dy * dy) / radius_y_sq)
                        .sqrt()
                        .min(1.0)
                } else {
                    1.0
                };
                (interpolate_gradient(t, &rb.stops), 1.0)
            }
        };
        // Apply the brush opacity to the resolved color uniformly. Gradient
        // brushes carry no opacity field today (D2D1_BRUSH_PROPERTIES is not
        // forwarded at the thunk layer), so their opacity is 1.0.
        let r = (color.0 * 255.0 * opacity) as u8;
        let g = (color.1 * 255.0 * opacity) as u8;
        let b = (color.2 * 255.0 * opacity) as u8;
        let a = (color.3 * 255.0) as u8;
        (a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32
    }
}

// ── Render target types ─────────────────────────────────────────────────

/// A hardware (or software) render target for HWND-based rendering.
///
/// When `hw_renderer` is `Some`, all drawing operations are accelerated
/// via Metal. The software `pixels` buffer is used as a readback target
/// for compatibility with callers that expect CPU-accessible pixel data.
///
/// To enable hardware acceleration, call
/// [`attach_hardware_renderer`](HwndRenderTarget::attach_hardware_renderer)
/// before [`begin_draw`](HwndRenderTarget::begin_draw).
#[derive(Debug)]
pub struct HwndRenderTarget {
    pub width: u32,
    pub height: u32,
    pub hwnd: u64,
    pub dpi: f32,
    pub pixel_format: D2DPixelFormat,
    pub transform: D2DMatrix,
    pub state: RenderState,
    /// Software pixel buffer (used as fallback or readback target).
    pub pixels: Vec<u8>,
    pub stride: i32,
    /// Optional Metal-accelerated hardware renderer.
    pub hw_renderer: Option<MetalD2DRenderer>,
    /// True between `begin_draw` and the first `flush_hardware`; makes
    /// flushes idempotent so `end_draw` after a mid-frame flush (e.g. from
    /// `draw_text`) does not commit the Metal frame twice.
    hw_frame_active: bool,
    /// True when hardware drawing occurred this frame; gates the GPU readback
    /// in `flush_hardware` so frames without GPU work skip the sync + copy.
    hw_dirty: bool,
}

// Manual Clone implementation: MetalD2DRenderer is not Clone.
impl Clone for HwndRenderTarget {
    fn clone(&self) -> Self {
        Self {
            width: self.width,
            height: self.height,
            hwnd: self.hwnd,
            dpi: self.dpi,
            pixel_format: self.pixel_format,
            transform: self.transform,
            state: self.state.clone(),
            pixels: self.pixels.clone(),
            stride: self.stride,
            hw_renderer: None, // Hardware renderer is not cloned.
            hw_frame_active: false,
            hw_dirty: false,
        }
    }
}

/// A device-context render target.
#[derive(Debug, Clone)]
pub struct DcRenderTarget {
    pub width: u32,
    pub height: u32,
    pub dpi: f32,
    pub pixel_format: D2DPixelFormat,
}

/// Enum of all render target types.
#[derive(Debug)]
pub enum D2DRenderTarget {
    Hwnd(Box<HwndRenderTarget>),
    Dc(DcRenderTarget),
}

// ── D2D Factory ─────────────────────────────────────────────────────────

/// A D2D factory, like `ID2D1Factory`.
pub struct D2DFactory {
    pub render_targets: HashMap<u64, D2DRenderTarget>,
    pub next_id: u64,
}

impl Default for D2DFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl D2DFactory {
    pub fn new() -> Self {
        D2DFactory {
            render_targets: HashMap::new(),
            next_id: 1,
        }
    }
    /// Create an HWND render target.
    ///
    /// Returns 0 (no render target created) if the requested dimensions are
    /// invalid, to match the fail-closed behavior of D2D surface creation
    /// without panicking on guest-controlled sizes.
    pub fn create_hwnd_render_target(
        &mut self,
        hwnd: u64,
        width: u32,
        height: u32,
        dpi: f32,
        pixel_format: D2DPixelFormat,
    ) -> u64 {
        // Reject absurd dimensions up front: the buffer allocation below is
        // guest-controlled, and 32-bit arithmetic on the stride could wrap.
        const MAX_SURFACE_DIMENSION: u32 = 32768;
        if width == 0
            || height == 0
            || width > MAX_SURFACE_DIMENSION
            || height > MAX_SURFACE_DIMENSION
        {
            return 0;
        }
        let stride = (width as usize) * 4;
        let Some(pixel_count) = stride.checked_mul(height as usize) else {
            return 0;
        };
        let id = self.next_id;
        self.next_id += 1;

        let target = HwndRenderTarget {
            width,
            height,
            hwnd,
            dpi,
            pixel_format,
            transform: d2d_identity_matrix(),
            state: RenderState::default(),
            pixels: vec![0u8; pixel_count],
            stride: stride as i32,
            hw_renderer: None,
            hw_frame_active: false,
            hw_dirty: false,
        };

        self.render_targets
            .insert(id, D2DRenderTarget::Hwnd(Box::new(target)));
        id
    }

    /// Create a DC render target.
    pub fn create_dc_render_target(
        &mut self,
        width: u32,
        height: u32,
        dpi: f32,
        pixel_format: D2DPixelFormat,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let target = DcRenderTarget {
            width,
            height,
            dpi,
            pixel_format,
        };

        self.render_targets.insert(id, D2DRenderTarget::Dc(target));
        id
    }

    /// Get a mutable reference to an HWND render target.
    pub fn hwnd_target_mut(&mut self, id: u64) -> Option<&mut HwndRenderTarget> {
        match self.render_targets.get_mut(&id) {
            Some(D2DRenderTarget::Hwnd(t)) => Some(t.as_mut()),
            _ => None,
        }
    }

    /// Get an immutable reference to an HWND render target.
    pub fn hwnd_target(&self, id: u64) -> Option<&HwndRenderTarget> {
        match self.render_targets.get(&id) {
            Some(D2DRenderTarget::Hwnd(t)) => Some(t.as_ref()),
            _ => None,
        }
    }

    /// Remove a render target.
    pub fn release_render_target(&mut self, id: u64) {
        self.render_targets.remove(&id);
    }
}

// ── HwndRenderTarget methods ────────────────────────────────────────────

impl HwndRenderTarget {
    /// Attach a Metal hardware renderer, enabling GPU-accelerated drawing.
    ///
    /// The renderer is created with the same dimensions as this target.
    /// Call this before [`begin_draw`] to use the hardware path.
    ///
    /// Returns an error if the Metal device cannot create the renderer.
    pub fn attach_hardware_renderer(
        &mut self,
        device: &crate::metal_backend::MetalDevice,
    ) -> crate::error::AppResult<()> {
        let renderer = MetalD2DRenderer::new(device, self.width, self.height)?;
        self.hw_renderer = Some(renderer);
        Ok(())
    }

    /// Detach and drop the hardware renderer, falling back to software.
    pub fn detach_hardware_renderer(&mut self) {
        self.hw_renderer = None;
    }

    /// Returns `true` if hardware acceleration is active.
    pub fn is_hardware_accelerated(&self) -> bool {
        self.hw_renderer.is_some()
    }

    /// Flush the hardware renderer: end the current frame and, when GPU work
    /// happened this frame, read back pixels into the software buffer so that
    /// callers can access pixel data.
    ///
    /// Flushing is idempotent per frame: at most one commit+readback happens
    /// between `begin_draw` and `end_draw`, so a mid-frame flush (e.g. from
    /// `draw_text`) followed by `end_draw` does not end the Metal frame
    /// twice. Frames without GPU work skip the GPU→CPU readback entirely.
    pub fn flush_hardware(&mut self) {
        if !self.hw_frame_active {
            return;
        }
        self.hw_frame_active = false;
        let dirty = self.hw_dirty;
        self.hw_dirty = false;
        if let Some(ref mut hw) = self.hw_renderer {
            hw.end_frame();
            if dirty {
                // Read back pixel data for compatibility
                if let Ok((_, _, stride, data)) = hw.readback() {
                    self.pixels = data;
                    self.stride = stride;
                }
            }
        }
    }

    /// Mark that GPU drawing occurred this frame (drives the readback gate).
    fn mark_hw_dirty(&mut self) {
        self.hw_dirty = true;
    }

    pub fn begin_draw(&mut self) {
        self.state.drawing = true;
        // Start a hardware frame if hardware acceleration is available.
        if let Some(ref mut hw) = self.hw_renderer {
            hw.begin_frame();
            self.hw_frame_active = true;
        }
    }

    pub fn end_draw(&mut self) {
        // Flush the hardware renderer (commit GPU commands, read back pixels)
        // before clearing the drawing flag; flush_hardware is a no-op when no
        // frame is active, so repeated end_draw calls are safe.
        self.flush_hardware();
        self.state.drawing = false;
    }

    pub fn clear(&mut self, color: (f32, f32, f32, f32)) {
        // Convert float color to ARGB
        let r = (color.0 * 255.0) as u8;
        let g = (color.1 * 255.0) as u8;
        let b = (color.2 * 255.0) as u8;
        let a = (color.3 * 255.0) as u8;
        let argb_color = (a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32;

        if let Some(ref mut hw) = self.hw_renderer {
            // Hardware clear via Metal render-pass load action.
            hw.clear(
                r as f32 / 255.0,
                g as f32 / 255.0,
                b as f32 / 255.0,
                a as f32 / 255.0,
            );
            self.mark_hw_dirty();
        } else {
            // Software fallback: fill the entire surface with the constant
            // ARGB pattern instead of a per-pixel function-call loop.
            let pattern = argb_color.to_le_bytes();
            let row_len = (self.width as usize) * 4;
            for row in self.pixels.chunks_exact_mut(row_len) {
                for chunk in row.as_chunks_mut::<4>().0 {
                    chunk.copy_from_slice(&pattern);
                }
            }
        }
    }

    pub fn draw_line(
        &mut self,
        p1: (f32, f32),
        p2: (f32, f32),
        brush_id: u64,
        stroke_width: f32,
        brushes: &HashMap<u64, D2DBrush>,
    ) {
        let color = brush_color_or_default(brush_id, brushes, p1.0, p1.1);

        if let Some(ref hw) = self.hw_renderer {
            hw.draw_line(p1.0, p1.1, p2.0, p2.1, stroke_width, color);
            self.mark_hw_dirty();
        } else {
            gdiplus_render::draw_line(
                &mut self.pixels,
                self.width,
                self.height,
                self.stride,
                p1.0,
                p1.1,
                p2.0,
                p2.1,
                color,
                stroke_width,
                GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
                GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS,
            );
        }
    }

    pub fn fill_rectangle(
        &mut self,
        rect: (f32, f32, f32, f32),
        brush_id: u64,
        brushes: &HashMap<u64, D2DBrush>,
    ) {
        let color = brush_color_or_default(brush_id, brushes, rect.0, rect.1);

        if let Some(ref hw) = self.hw_renderer {
            hw.fill_rect(rect.0, rect.1, rect.2, rect.3, color);
            self.mark_hw_dirty();
        } else {
            gdiplus_render::fill_rect(
                &mut self.pixels,
                self.width,
                self.height,
                self.stride,
                rect.0,
                rect.1,
                rect.2,
                rect.3,
                color,
                GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
            );
        }
    }

    pub fn draw_rectangle(
        &mut self,
        rect: (f32, f32, f32, f32),
        brush_id: u64,
        stroke_width: f32,
        brushes: &HashMap<u64, D2DBrush>,
    ) {
        let color = brush_color_or_default(brush_id, brushes, rect.0, rect.1);

        if let Some(ref hw) = self.hw_renderer {
            // Outline rectangle as 4 line segments. The corners are shared
            // endpoints between adjacent segments; each segment is clipped to
            // exclude the shared endpoint so corner pixels are not drawn
            // twice (double alpha blending).
            let (x, y, w, h) = rect;
            let sw = stroke_width;
            let half = sw / 2.0;
            // Top edge (excluding the right corner)
            hw.draw_line(x, y + half, x + w - half, y + half, sw, color);
            // Bottom edge (excluding the right corner)
            hw.draw_line(x, y + h - half, x + w - half, y + h - half, sw, color);
            // Left edge (excluding the bottom corner)
            hw.draw_line(x + half, y, x + half, y + h - half, sw, color);
            // Right edge (excluding the bottom corner)
            hw.draw_line(x + w - half, y, x + w - half, y + h - half, sw, color);
            self.mark_hw_dirty();
        } else {
            gdiplus_render::draw_rect(
                &mut self.pixels,
                self.width,
                self.height,
                self.stride,
                rect.0,
                rect.1,
                rect.2,
                rect.3,
                color,
                stroke_width,
                GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
                GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS,
            );
        }
    }

    pub fn fill_ellipse(
        &mut self,
        center: (f32, f32),
        radius_x: f32,
        radius_y: f32,
        brush_id: u64,
        brushes: &HashMap<u64, D2DBrush>,
    ) {
        let color = brush_color_or_default(brush_id, brushes, center.0, center.1);

        if let Some(ref hw) = self.hw_renderer {
            hw.fill_ellipse(center.0, center.1, radius_x, radius_y, color, 32);
            self.mark_hw_dirty();
        } else {
            // gdiplus_render::fill_ellipse uses (x, y, w, h) bounding rect
            let x = center.0 - radius_x;
            let y = center.1 - radius_y;
            let w = radius_x * 2.0;
            let h = radius_y * 2.0;
            gdiplus_render::fill_ellipse(
                &mut self.pixels,
                self.width,
                self.height,
                self.stride,
                x,
                y,
                w,
                h,
                color,
                GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
            );
        }
    }

    pub fn draw_ellipse(
        &mut self,
        center: (f32, f32),
        radius_x: f32,
        radius_y: f32,
        brush_id: u64,
        stroke_width: f32,
        brushes: &HashMap<u64, D2DBrush>,
    ) {
        let color = brush_color_or_default(brush_id, brushes, center.0, center.1);

        if let Some(ref hw) = self.hw_renderer {
            // Approximate an outlined ellipse by tessellating it as a thick line.
            // We draw line segments around the perimeter.
            let segments = 32;
            let (cx, cy, rx, ry) = (center.0, center.1, radius_x, radius_y);
            for i in 0..segments {
                let a1 = (i as f32) * std::f32::consts::TAU / segments as f32;
                let a2 = ((i + 1) as f32) * std::f32::consts::TAU / segments as f32;
                let x1 = cx + rx * a1.cos();
                let y1 = cy + ry * a1.sin();
                let x2 = cx + rx * a2.cos();
                let y2 = cy + ry * a2.sin();
                hw.draw_line(x1, y1, x2, y2, stroke_width, color);
            }
            self.mark_hw_dirty();
        } else {
            let x = center.0 - radius_x;
            let y = center.1 - radius_y;
            let w = radius_x * 2.0;
            let h = radius_y * 2.0;
            gdiplus_render::draw_ellipse(
                &mut self.pixels,
                self.width,
                self.height,
                self.stride,
                x,
                y,
                w,
                h,
                color,
                stroke_width,
                GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
                GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_text(
        &mut self,
        text: &str,
        format_id: u64,
        rect: (f32, f32, f32, f32),
        brush_id: u64,
        _dwrite_factory: &DWriteFactory,
        formats: &HashMap<u64, DWriteTextFormat>,
        brushes: &HashMap<u64, D2DBrush>,
    ) {
        // Text rendering always uses the software path because glyph-level
        // hardware rendering requires a glyph atlas and signed-distance-field
        // shaders. The flush_hardware() call in end_draw() ensures any
        // preceding hardware draws are committed before text is blended.
        if self.hw_renderer.is_some() {
            self.flush_hardware();
        }

        // Look up the text format
        let format = match formats.get(&format_id) {
            Some(f) => f,
            None => {
                eprintln!("[d2d] draw_text: unknown text format id {format_id}");
                return;
            }
        };

        // Get brush color
        let color = brush_color_or_default(brush_id, brushes, rect.0, rect.1);

        // Render using the existing string renderer
        gdiplus_render::draw_string(
            &mut self.pixels,
            self.width,
            self.height,
            self.stride,
            text,
            rect.0,
            rect.1,
            format.font_size,
            color,
            GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
        );
    }

    pub fn draw_bitmap(
        &mut self,
        bitmap_id: u64,
        dest_rect: (f32, f32, f32, f32),
        opacity: f32,
        bitmaps: &HashMap<u64, D2DBitmap>,
    ) {
        let bitmap = match bitmaps.get(&bitmap_id) {
            Some(b) => b,
            None => {
                eprintln!("[d2d] draw_bitmap: unknown bitmap id {bitmap_id}");
                return;
            }
        };

        if let Some(ref hw) = self.hw_renderer {
            hw.draw_bitmap(
                &bitmap.data,
                bitmap.width,
                bitmap.height,
                dest_rect.0,
                dest_rect.1,
                dest_rect.2,
                dest_rect.3,
                opacity,
            );
            self.mark_hw_dirty();
        } else {
            gdiplus_render::draw_image_rect(
                &mut self.pixels,
                self.width,
                self.height,
                self.stride,
                &bitmap.data,
                bitmap.width,
                bitmap.height,
                bitmap.stride as i32,
                dest_rect.0,
                dest_rect.1,
                dest_rect.2,
                dest_rect.3,
                GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
            );
        }
    }

    pub fn set_transform(&mut self, matrix: &D2DMatrix) {
        self.transform = *matrix;
    }

    pub fn get_size(&self) -> (f32, f32) {
        (self.width as f32, self.height as f32)
    }

    pub fn get_dpi(&self) -> (f32, f32) {
        (self.dpi, self.dpi)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Resolve a brush's colour or return a default (black).
fn brush_color_or_default(
    brush_id: u64,
    brushes: &HashMap<u64, D2DBrush>,
    px: f32,
    py: f32,
) -> u32 {
    match brushes.get(&brush_id) {
        Some(brush) => brush.color_at(px, py),
        None => 0xFF000000, // Black default
    }
}

// ── Matrix helpers ──────────────────────────────────────────────────────

/// Identity matrix.
pub fn d2d_identity_matrix() -> D2DMatrix {
    [1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0]
}

/// Create a rotation matrix around a center point.
/// `angle` is in degrees (clockwise).
pub fn d2d_make_rotate_matrix(angle: f32, center: (f32, f32)) -> D2DMatrix {
    let rad = angle.to_radians(); // D2D uses clockwise
    let cos = rad.cos();
    let sin = rad.sin();
    let (cx, cy) = center;

    [
        cos,
        sin,
        -sin,
        cos,
        cx - cos * cx + sin * cy,
        cy - sin * cx - cos * cy,
        0.0,
        0.0,
        0.0,
    ]
}

/// Create a skew (shear) matrix around a center point.
/// `angle_x` and `angle_y` are in degrees.
pub fn d2d_make_skew_matrix(angle_x: f32, angle_y: f32, center: (f32, f32)) -> D2DMatrix {
    let tan_x = angle_x.to_radians().tan();
    let tan_y = angle_y.to_radians().tan();
    let (cx, cy) = center;

    [
        1.0,
        tan_y,
        tan_x,
        1.0,
        -tan_x * cy,
        -tan_y * cx,
        0.0,
        0.0,
        0.0,
    ]
}

/// Check if a matrix is invertible.
pub fn d2d_is_matrix_invertible(matrix: &D2DMatrix) -> bool {
    let det = matrix[0] * matrix[3] - matrix[1] * matrix[2];
    det.abs() > 0.0001
}

/// Invert a matrix. Returns `false` if not invertible.
pub fn d2d_invert_matrix(matrix: &mut D2DMatrix) -> bool {
    let det = matrix[0] * matrix[3] - matrix[1] * matrix[2];
    if det.abs() <= 0.0001 {
        return false;
    }
    let inv_det = 1.0 / det;
    let m11 = matrix[0];
    let m12 = matrix[1];
    let m21 = matrix[2];
    let m22 = matrix[3];
    let dx = matrix[4];
    let dy = matrix[5];

    matrix[0] = m22 * inv_det;
    matrix[1] = -m12 * inv_det;
    matrix[2] = -m21 * inv_det;
    matrix[3] = m11 * inv_det;
    matrix[4] = (m21 * dy - m22 * dx) * inv_det;
    matrix[5] = (m12 * dx - m11 * dy) * inv_det;

    true
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_d2d1_create_factory() {
        let factory = D2DFactory::new();
        assert_eq!(factory.next_id, 1);
        assert!(factory.render_targets.is_empty());
    }

    #[test]
    fn test_d2d1_create_rendertarget() {
        let mut factory = D2DFactory::new();
        let id =
            factory.create_hwnd_render_target(0x12345, 640, 480, 96.0, D2DPixelFormat::default());
        assert_eq!(id, 1);
        let target = factory.hwnd_target(id);
        assert!(target.is_some());
        assert_eq!(target.unwrap().width, 640);
        assert_eq!(target.unwrap().height, 480);
    }

    #[test]
    fn test_d2d1_solid_color_brush() {
        let brush = D2DBrush::Solid(D2DSolidColorBrush {
            color: (1.0, 0.0, 0.0, 1.0), // Red, full opacity
            opacity: 1.0,
        });
        let color = brush.color_at(0.0, 0.0);
        assert_eq!(color, 0xFFFF0000); // ARGB: Red

        let brush2 = D2DBrush::Solid(D2DSolidColorBrush {
            color: (0.0, 1.0, 0.0, 0.5), // Green, half opacity
            opacity: 1.0,
        });
        let color2 = brush2.color_at(0.0, 0.0);
        assert_eq!(color2, 0x7F00FF00); // ARGB: Semi-transparent Green
    }

    #[test]
    fn test_d2d1_draw_line() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 100, 100, 96.0, D2DPixelFormat::default());
        let target = factory.hwnd_target_mut(id).unwrap();
        let brushes = HashMap::new();

        target.begin_draw();
        target.draw_line((10.0, 10.0), (90.0, 10.0), 0, 1.0, &brushes);
        target.end_draw();

        // Check that some pixels were drawn (line at y=10)
        let idx = (10 * target.stride + 10 * 4) as usize;
        let pixel = u32::from_le_bytes([
            target.pixels[idx],
            target.pixels[idx + 1],
            target.pixels[idx + 2],
            target.pixels[idx + 3],
        ]);
        assert_ne!(pixel, 0); // Should have been drawn
    }

    #[test]
    fn test_d2d1_fill_rectangle() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 100, 100, 96.0, D2DPixelFormat::default());

        // Create a red brush
        let mut brushes = HashMap::new();
        let brush = D2DBrush::Solid(D2DSolidColorBrush {
            color: (1.0, 0.0, 0.0, 1.0),
            opacity: 1.0,
        });
        brushes.insert(1, brush);

        let target = factory.hwnd_target_mut(id).unwrap();
        target.fill_rectangle((10.0, 10.0, 20.0, 20.0), 1, &brushes);

        // Check center pixel
        let idx = (20 * target.stride + 20 * 4) as usize;
        let pixel = u32::from_le_bytes([
            target.pixels[idx],
            target.pixels[idx + 1],
            target.pixels[idx + 2],
            target.pixels[idx + 3],
        ]);
        assert_eq!(pixel, 0xFFFF0000); // Red
    }

    #[test]
    fn test_d2d1_clear() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 50, 50, 96.0, D2DPixelFormat::default());
        let target = factory.hwnd_target_mut(id).unwrap();
        target.clear((0.0, 0.0, 1.0, 1.0)); // Blue

        // Check a pixel
        let idx = 0usize;
        let pixel = u32::from_le_bytes([
            target.pixels[idx],
            target.pixels[idx + 1],
            target.pixels[idx + 2],
            target.pixels[idx + 3],
        ]);
        assert_eq!(pixel, 0xFF0000FF); // Blue (ARGB)
    }

    #[test]
    fn test_d2d1_make_rotate_matrix() {
        // 0-degree rotation should be identity-like
        let m = d2d_make_rotate_matrix(0.0, (0.0, 0.0));
        assert!((m[0] - 1.0).abs() < 0.001);
        assert!((m[1]).abs() < 0.001);
        assert!((m[2]).abs() < 0.001);
        assert!((m[3] - 1.0).abs() < 0.001);

        // 90-degree rotation
        let m90 = d2d_make_rotate_matrix(90.0, (0.0, 0.0));
        assert!((m90[0]).abs() < 0.001); // cos(90) ≈ 0
        assert!((m90[1] - 1.0).abs() < 0.001); // sin(90) = 1 but negated
        assert!((m90[2] + 1.0).abs() < 0.001); // -sin(90) = -1
        assert!((m90[3]).abs() < 0.001); // cos(90) ≈ 0
    }

    #[test]
    fn test_d2d1_make_skew_matrix() {
        let m = d2d_make_skew_matrix(0.0, 0.0, (0.0, 0.0));
        assert!((m[0] - 1.0).abs() < 0.001);
        assert!((m[1]).abs() < 0.001);
        assert!((m[2]).abs() < 0.001);
        assert!((m[3] - 1.0).abs() < 0.001);

        // 45-degree skew
        let m45 = d2d_make_skew_matrix(45.0, 0.0, (0.0, 0.0));
        assert!((m45[2] - 1.0).abs() < 0.001); // tan(45) = 1
    }

    #[test]
    fn test_d2d1_invert_matrix() {
        let mut m = d2d_identity_matrix();
        assert!(d2d_is_matrix_invertible(&m));
        assert!(d2d_invert_matrix(&mut m));
        // Identity inverted is identity
        assert!((m[0] - 1.0).abs() < 0.001);
        assert!((m[3] - 1.0).abs() < 0.001);

        // Test a non-invertible matrix (zero determinant)
        let mut bad = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        assert!(!d2d_is_matrix_invertible(&bad));
        assert!(!d2d_invert_matrix(&mut bad));

        // Test inversion of a scale matrix
        let mut scale = [2.0, 0.0, 0.0, 3.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        assert!(d2d_invert_matrix(&mut scale));
        assert!((scale[0] - 0.5).abs() < 0.001);
        assert!((scale[3] - 0.333).abs() < 0.001);
    }

    #[test]
    fn test_d2d1_create_dc_rendertarget() {
        let mut factory = D2DFactory::new();
        let id = factory.create_dc_render_target(800, 600, 96.0, D2DPixelFormat::default());
        assert_eq!(id, 1);
    }

    #[test]
    fn test_d2d1_release_rendertarget() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 100, 100, 96.0, D2DPixelFormat::default());
        assert!(factory.hwnd_target(id).is_some());
        factory.release_render_target(id);
        assert!(factory.hwnd_target(id).is_none());
    }

    #[test]
    fn test_d2d1_begin_end_draw() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 100, 100, 96.0, D2DPixelFormat::default());
        let target = factory.hwnd_target_mut(id).unwrap();
        assert!(!target.state.drawing);
        target.begin_draw();
        assert!(target.state.drawing);
        target.end_draw();
        assert!(!target.state.drawing);
    }

    #[test]
    fn test_d2d1_linear_gradient_brush() {
        let brush = D2DBrush::LinearGradient(D2DLinearGradientBrush {
            start_point: (0.0, 0.0),
            end_point: (10.0, 0.0),
            stops: vec![
                D2DGradientStop {
                    position: 0.0,
                    color: (1.0, 0.0, 0.0, 1.0), // Red
                },
                D2DGradientStop {
                    position: 1.0,
                    color: (0.0, 0.0, 1.0, 1.0), // Blue
                },
            ],
        });

        let color_start = brush.color_at(0.0, 0.0);
        assert_eq!(color_start, 0xFFFF0000);

        let color_end = brush.color_at(10.0, 0.0);
        assert_eq!(color_end, 0xFF0000FF);
    }

    #[test]
    fn test_d2d1_get_size_dpi() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 1920, 1080, 144.0, D2DPixelFormat::default());
        let target = factory.hwnd_target(id).unwrap();
        let (w, h) = target.get_size();
        assert_eq!(w, 1920.0);
        assert_eq!(h, 1080.0);
        let (dpi_x, dpi_y) = target.get_dpi();
        assert_eq!(dpi_x, 144.0);
        assert_eq!(dpi_y, 144.0);
    }

    #[test]
    fn test_d2d1_set_transform() {
        let mut factory = D2DFactory::new();
        let id = factory.create_hwnd_render_target(0, 100, 100, 96.0, D2DPixelFormat::default());
        let target = factory.hwnd_target_mut(id).unwrap();
        let transform = d2d_make_rotate_matrix(45.0, (50.0, 50.0));
        target.set_transform(&transform);
        assert_eq!(target.transform[0], transform[0]);
    }
}
