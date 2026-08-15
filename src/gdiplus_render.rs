//! Software rasterizer for GDI+ drawing primitives.
//!
//! All functions operate on a raw [`&mut [u8]`] pixel buffer with a given
//! `width`, `height` and `stride`.  Pixels are stored in **32‑bit ARGB** order
//! (byte order: B, G, R, A in memory; little‑endian `u32` is `0xAARRGGBB`).
//!
//! The pixel buffer is assumed to be **top‑down** (first pixel = top‑left
//! corner of the bitmap), matching GDI+ convention.
//!
//! No external dependencies are required – this is a pure‑Rust software renderer.

// The software-rasterizer entry points mirror the GDI+ API surface, which has
// many parameters by design; keep the public signatures intact.
#![allow(clippy::too_many_arguments)]

use crate::user32::{
    GDIPLUS_COMPOSITING_MODE_SOURCE_COPY, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
    GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS, GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY,
    GDIPLUS_WRAP_MODE_CLAMP, GDIPLUS_WRAP_MODE_TILE, GDIPLUS_WRAP_MODE_TILE_FLIP_X,
    GDIPLUS_WRAP_MODE_TILE_FLIP_XY, GDIPLUS_WRAP_MODE_TILE_FLIP_Y, GdiplusBrush, GdiplusPath,
    GdiplusPathElement, GdiplusPen, GdiplusPointF,
};

// ── helpers ─────────────────────────────────────────────────────────────────

/// Pack individual ARGB components into a `u32` in 0xAARRGGBB format.
#[inline]
fn argb(a: u8, r: u8, g: u8, b: u8) -> u32 {
    (a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32
}

/// Extract alpha component from 0xAARRGGBB.
#[inline]
fn alpha_of(c: u32) -> u8 {
    (c >> 24) as u8
}

/// Extract red component from 0xAARRGGBB.
#[inline]
fn red_of(c: u32) -> u8 {
    (c >> 16) as u8
}

/// Extract green component from 0xAARRGGBB.
#[inline]
fn green_of(c: u32) -> u8 {
    (c >> 8) as u8
}

/// Extract blue component from 0xAARRGGBB.
#[inline]
fn blue_of(c: u32) -> u8 {
    c as u8
}

/// Blend two ARGB pixels using the **source‑over** (`src * a_src + dst * (1‑a_src)`)
/// compositing rule.  If `compositing_mode` is `SOURCE_COPY`, the source pixel
/// replaces the destination entirely (including alpha).
#[inline]
fn blend_pixel(src: u32, dst: u32, compositing_mode: u32) -> u32 {
    if compositing_mode == GDIPLUS_COMPOSITING_MODE_SOURCE_COPY {
        return src;
    }
    let sa = alpha_of(src) as u32;
    if sa == 255 {
        return src;
    }
    if sa == 0 {
        return dst;
    }
    let sr = red_of(src) as u32;
    let sg = green_of(src) as u32;
    let sb = blue_of(src) as u32;
    let da = alpha_of(dst) as u32;
    let dr = red_of(dst) as u32;
    let dg = green_of(dst) as u32;
    let db = blue_of(dst) as u32;

    let inv_sa = 255 - sa;
    let out_a = sa + da * inv_sa / 255;
    let out_r = (sr * sa + dr * inv_sa) / 255;
    let out_g = (sg * sa + dg * inv_sa) / 255;
    let out_b = (sb * sa + db * inv_sa) / 255;

    argb(out_a as u8, out_r as u8, out_g as u8, out_b as u8)
}

/// Write a single ARGB pixel into the buffer at `(x, y)`, respecting clipping
/// and compositing mode.
#[inline]
pub fn put_pixel(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: i32,
    y: i32,
    color: u32,
    compositing_mode: u32,
) {
    if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 {
        return;
    }
    // Negative strides (bottom-up DIBs) store row 0 at the bottom, so flip the
    // row index. i64 arithmetic keeps the offset from overflowing.
    let row = if stride < 0 {
        (height as i64 - 1 - y as i64) * stride as i64
    } else {
        y as i64 * stride as i64
    };
    let idx = row.saturating_add(x as i64 * 4);
    if idx < 0 || idx.saturating_add(3) >= pixels.len() as i64 {
        return;
    }
    let idx = idx as usize;
    let existing = u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]);
    let blended = blend_pixel(color, existing, compositing_mode);
    let bytes = blended.to_le_bytes();
    pixels[idx] = bytes[0];
    pixels[idx + 1] = bytes[1];
    pixels[idx + 2] = bytes[2];
    pixels[idx + 3] = bytes[3];
}

/// Clamp an `f32` coordinate to a safe integer range.
#[inline]
fn clamp_f32(v: f32) -> i32 {
    if v.is_nan() || v.is_infinite() {
        0
    } else {
        v.round() as i32
    }
}

// ── Brush helpers ───────────────────────────────────────────────────────────

/// Resolve the colour of a brush at an arbitrary point `(px, py)`.
/// For `SolidFill` this is trivial; for `LineBrush` we interpolate;
/// for `Texture` we sample the underlying bitmap pixels using the
/// brush's wrap mode, with optional externally-provided texture data.
///
/// `texture_data` — when `Some((pixels, width, height, stride))` the
/// function samples the texture bitmap; when `None` the texture branch
/// falls back to `0x00000000` (transparent black).
pub fn brush_color_at(
    brush: &GdiplusBrush,
    px: f32,
    py: f32,
    texture_data: Option<(&[u8], u32, u32, i32)>,
) -> u32 {
    match brush {
        GdiplusBrush::SolidFill(sf) => sf.color,
        GdiplusBrush::LineBrush(lb) => {
            // Simple linear interpolation between the two colours along the
            // projection of (px,py) onto the line segment.
            let dx = lb.point2.0 - lb.point1.0;
            let dy = lb.point2.1 - lb.point1.1;
            let len_sq = dx * dx + dy * dy;
            if len_sq < 0.0001 {
                return lb.color1;
            }
            let t = ((px - lb.point1.0) * dx + (py - lb.point1.1) * dy) / len_sq;
            let t = t.clamp(0.0, 1.0);
            lerp_color(lb.color1, lb.color2, t)
        }
        GdiplusBrush::Texture(tb) => {
            // Sample the texture bitmap at (px, py) using the brush's wrap mode.
            if let Some((pixels, width, height, stride)) = texture_data {
                if width == 0 || height == 0 || pixels.is_empty() {
                    return 0x00000000;
                }
                let u = wrap_coord(px, width, tb.wrap_mode);
                let v = wrap_coord(py, height, tb.wrap_mode);
                // GDI+ bitmaps are top-down ARGB in memory (byte order B,G,R,A).
                // stride may be larger than width*4 for alignment; a negative
                // stride means bottom-up storage, so flip the row index.
                let row = if stride < 0 {
                    (height as i64 - 1 - v as i64) * stride as i64
                } else {
                    v as i64 * stride as i64
                };
                let col = (u as usize) * 4;
                if row < 0 || row.saturating_add(col as i64 + 3) >= pixels.len() as i64 {
                    return 0x00000000;
                }
                let idx = row as usize + col;
                let b = pixels[idx] as u32;
                let g = pixels[idx + 1] as u32;
                let r = pixels[idx + 2] as u32;
                let a = pixels[idx + 3] as u32;
                (a << 24) | (r << 16) | (g << 8) | b
            } else {
                // No texture data available — return transparent black.
                0x00000000
            }
        }
    }
}

/// Wrap a floating-point coordinate into `[0, size)` using a GDI+ wrap mode.
fn wrap_coord(coord: f32, size: u32, wrap_mode: u32) -> u32 {
    if size == 0 {
        return 0;
    }
    let sz = size as i32;
    match wrap_mode {
        GDIPLUS_WRAP_MODE_TILE => {
            let mut c = coord as i32 % sz;
            if c < 0 {
                c += sz;
            }
            c as u32
        }
        GDIPLUS_WRAP_MODE_TILE_FLIP_X => {
            let period = sz * 2;
            let mut c = coord as i32 % period;
            if c < 0 {
                c += period;
            }
            if c >= sz {
                (period - c - 1) as u32
            } else {
                c as u32
            }
        }
        GDIPLUS_WRAP_MODE_TILE_FLIP_Y => {
            let period = sz * 2;
            let mut c = coord as i32 % period;
            if c < 0 {
                c += period;
            }
            if c >= sz {
                (period - c - 1) as u32
            } else {
                c as u32
            }
        }
        GDIPLUS_WRAP_MODE_TILE_FLIP_XY => {
            let period = sz * 2;
            let mut c = coord as i32 % period;
            if c < 0 {
                c += period;
            }
            // Flip both X and Y — handled by the two wrap_coord calls independently.
            if c >= sz {
                (period - c - 1) as u32
            } else {
                c as u32
            }
        }
        GDIPLUS_WRAP_MODE_CLAMP => {
            if coord < 0.0 {
                0
            } else if coord >= (size - 1) as f32 {
                size - 1
            } else {
                coord as u32
            }
        }
        _ => {
            // Unknown wrap mode — default to clamp
            if coord < 0.0 {
                0
            } else if coord >= (size - 1) as f32 {
                size - 1
            } else {
                coord as u32
            }
        }
    }
}

/// Linearly interpolate between two ARGB colours.
fn lerp_color(c1: u32, c2: u32, t: f32) -> u32 {
    let it = 1.0 - t;
    let a = (alpha_of(c1) as f32 * it + alpha_of(c2) as f32 * t) as u8;
    let r = (red_of(c1) as f32 * it + red_of(c2) as f32 * t) as u8;
    let g = (green_of(c1) as f32 * it + green_of(c2) as f32 * t) as u8;
    let b = (blue_of(c1) as f32 * it + blue_of(c2) as f32 * t) as u8;
    argb(a, r, g, b)
}

/// Pen colour: prefer the pen's own colour; fall back to brushing the
/// brush_handle colour (cheap path).
pub fn pen_color(pen: &GdiplusPen, _px: f32, _py: f32) -> u32 {
    pen.color
}

// ── Line drawing (Bresenham + anti-aliasing) ────────────────────────────────

/// Draw an anti‑aliased or aliased line.
///
/// When `smoothing_mode` is `ANTI_ALIAS` or `HIGH_QUALITY`, pixel coverage is
/// computed from the distance between each pixel centre and the mathematical
/// line segment, producing smooth edges with sub‑pixel precision.
///
/// For aliased mode the original Bresenham midpoint algorithm is used.
pub fn draw_line(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    smoothing_mode: u32,
) {
    let w = pen_width.max(1.0);
    let w_half = w / 2.0;
    let w_int = w.round() as i32;

    let is_aa = smoothing_mode == GDIPLUS_SMOOTHING_MODE_ANTI_ALIAS
        || smoothing_mode == GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY;

    if is_aa {
        // ── Anti-aliased path ────────────────────────────────────────────
        // Bounding-box of the thickened line, padded by a 1-pixel fringe.
        let bx0 = x1.min(x2) - w_half - 1.0;
        let by0 = y1.min(y2) - w_half - 1.0;
        let bx1 = x1.max(x2) + w_half + 1.0;
        let by1 = y1.max(y2) + w_half + 1.0;

        let ix0 = (bx0.floor() as i32).max(0);
        let iy0 = (by0.floor() as i32).max(0);
        let ix1 = (bx1.ceil() as i32).min(width as i32 - 1);
        let iy1 = (by1.ceil() as i32).min(height as i32 - 1);

        let line_dx = x2 - x1;
        let line_dy = y2 - y1;
        let line_len_sq = line_dx * line_dx + line_dy * line_dy;

        for py in iy0..=iy1 {
            for px in ix0..=ix1 {
                // Pixel centre in continuous space
                let cx = px as f32 + 0.5;
                let cy = py as f32 + 0.5;

                // Distance from (cx,cy) to the line segment
                let dist = if line_len_sq < 0.0001 {
                    // Degenerate: treat as point
                    ((cx - x1).powi(2) + (cy - y1).powi(2)).sqrt()
                } else {
                    let t = ((cx - x1) * line_dx + (cy - y1) * line_dy) / line_len_sq;
                    let t = t.clamp(0.0, 1.0);
                    let px0 = x1 + t * line_dx;
                    let py0 = y1 + t * line_dy;
                    ((cx - px0).powi(2) + (cy - py0).powi(2)).sqrt()
                };

                // Coverage: 1 inside the pen, 0 outside, linear falloff in the
                // 1-pixel fringe.
                let coverage = if dist <= w_half - 0.5 {
                    1.0
                } else if dist <= w_half + 0.5 {
                    (w_half + 0.5 - dist).max(0.0)
                } else {
                    continue;
                };

                // Modulate the source alpha by coverage
                let src_alpha = (color >> 24) as f32 * coverage;
                let src_alpha = (src_alpha as u32).min(255);
                let blended_color = (color & 0x00FF_FFFF) | (src_alpha << 24);

                put_pixel(
                    pixels, width, height, stride, px, py, blended_color, compositing_mode,
                );
            }
        }
    } else {
        // ── Aliased path (original Bresenham) ────────────────────────────
        let x0 = clamp_f32(x1);
        let y0 = clamp_f32(y1);
        let x1i = clamp_f32(x2);
        let y1i = clamp_f32(y2);

        let dx = (x1i - x0).abs();
        let dy = -(y1i - y0).abs();
        let sx = if x0 < x1i { 1 } else { -1 };
        let sy = if y0 < y1i { 1 } else { -1 };
        let mut err = dx + dy;

        let mut cx = x0;
        let mut cy = y0;
        loop {
            for wy in -(w_int / 2)..=(w_int / 2) {
                for wx in -(w_int / 2)..=(w_int / 2) {
                    put_pixel(
                        pixels, width, height, stride, cx + wx, cy + wy, color, compositing_mode,
                    );
                }
            }
            if cx == x1i && cy == y1i {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                cx += sx;
            }
            if e2 <= dx {
                err += dx;
                cy += sy;
            }
        }
    }
}

/// Draw a polyline from a set of points.
pub fn draw_lines(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    points: &[GdiplusPointF],
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    smoothing_mode: u32,
) {
    for i in 1..points.len() {
        draw_line(
            pixels,
            width,
            height,
            stride,
            points[i - 1].x,
            points[i - 1].y,
            points[i].x,
            points[i].y,
            color,
            pen_width,
            compositing_mode,
            smoothing_mode,
        );
    }
}

// ── Rectangle drawing ───────────────────────────────────────────────────────

/// Draw the outline of a rectangle.
pub fn draw_rect(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    smoothing_mode: u32,
) {
    let x2 = x + w;
    let y2 = y + h;
    // Top edge
    draw_line(
        pixels,
        width,
        height,
        stride,
        x,
        y,
        x2,
        y,
        color,
        pen_width,
        compositing_mode,
        smoothing_mode,
    );
    // Bottom edge
    draw_line(
        pixels,
        width,
        height,
        stride,
        x,
        y2,
        x2,
        y2,
        color,
        pen_width,
        compositing_mode,
        smoothing_mode,
    );
    // Left edge
    draw_line(
        pixels,
        width,
        height,
        stride,
        x,
        y,
        x,
        y2,
        color,
        pen_width,
        compositing_mode,
        smoothing_mode,
    );
    // Right edge
    draw_line(
        pixels,
        width,
        height,
        stride,
        x2,
        y,
        x2,
        y2,
        color,
        pen_width,
        compositing_mode,
        smoothing_mode,
    );
}

/// Fill a rectangle.
pub fn fill_rect(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
    compositing_mode: u32,
) {
    let rx0 = clamp_f32(x);
    let ry0 = clamp_f32(y);
    let rx1 = clamp_f32(x + w);
    let ry1 = clamp_f32(y + h);

    for py in ry0..ry1 {
        for px in rx0..rx1 {
            put_pixel(
                pixels,
                width,
                height,
                stride,
                px,
                py,
                color,
                compositing_mode,
            );
        }
    }
}

// ── Ellipse drawing (midpoint algorithm) ────────────────────────────────────

/// Maximum ellipse radius (pixels) used by the midpoint algorithm. Larger
/// radii are clamped so the i64 accumulation can never overflow and the loop
/// is guaranteed to terminate.
const MAX_ELLIPSE_RADIUS: i64 = 32_768;

/// Maximum pen width (pixels) for the outline loops.
const MAX_PEN_WIDTH: f32 = 1024.0;

/// Draw the outline of an ellipse using the midpoint algorithm.
///
/// All step arithmetic is done in `i64` (with `rx`/`ry` clamped) so that
/// guest-supplied extents cannot overflow `i32` — which previously caused a
/// debug panic and, in release builds, an infinite loop when `d1` wrapped.
pub fn draw_ellipse(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    _smoothing_mode: u32,
) {
    let cx = (x + w / 2.0).round() as i32;
    let cy = (y + h / 2.0).round() as i32;
    let rx = ((w / 2.0).max(1.0).round() as i64).min(MAX_ELLIPSE_RADIUS);
    let ry = ((h / 2.0).max(1.0).round() as i64).min(MAX_ELLIPSE_RADIUS);
    let pw = pen_width.max(1.0).round().min(MAX_PEN_WIDTH) as i32;

    let rxrx = rx * rx;
    let ryry = ry * ry;

    let mut dx: i64 = 0;
    let mut dy: i64 = ry;
    let mut d1 = ryry - rxrx * ry + rxrx / 4;

    // Region 1
    while dx * ryry < dy * rxrx {
        for wy in -(pw / 2)..=(pw / 2) {
            for wx in -(pw / 2)..=(pw / 2) {
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 + dx + wx as i64) as i32,
                    (cy as i64 + dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 - dx + wx as i64) as i32,
                    (cy as i64 + dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 + dx + wx as i64) as i32,
                    (cy as i64 - dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 - dx + wx as i64) as i32,
                    (cy as i64 - dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
            }
        }
        if d1 < 0 {
            dx += 1;
            d1 += 2 * ryry * dx + ryry;
        } else {
            dx += 1;
            dy -= 1;
            d1 += 2 * ryry * dx - 2 * rxrx * dy + ryry;
        }
    }

    let mut d2 = (ryry as f64 * (dx as f64 + 0.5) * (dx as f64 + 0.5)
        + rxrx as f64 * (dy as f64 - 1.0) * (dy as f64 - 1.0)
        - (rxrx * ryry) as f64)
        .round() as i64;
    while dy >= 0 {
        for wy in -(pw / 2)..=(pw / 2) {
            for wx in -(pw / 2)..=(pw / 2) {
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 + dx + wx as i64) as i32,
                    (cy as i64 + dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 - dx + wx as i64) as i32,
                    (cy as i64 + dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 + dx + wx as i64) as i32,
                    (cy as i64 - dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    (cx as i64 - dx + wx as i64) as i32,
                    (cy as i64 - dy + wy as i64) as i32,
                    color,
                    compositing_mode,
                );
            }
        }
        if d2 > 0 {
            dy -= 1;
            d2 -= 2 * rxrx * dy + rxrx;
        } else {
            dy -= 1;
            dx += 1;
            d2 += 2 * ryry * dx - 2 * rxrx * dy + rxrx;
        }
    }
}

/// Fill an ellipse using a simple scanline approach.
pub fn fill_ellipse(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
    compositing_mode: u32,
) {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = (w / 2.0).max(1.0);
    let ry = (h / 2.0).max(1.0);
    let _rx2 = rx * rx;
    let _ry2 = ry * ry;

    let y0 = clamp_f32(y);
    let y1 = clamp_f32(y + h);
    for py in y0..y1 {
        let dy = (py as f32 - cy) / ry;
        let half_width = (rx * (1.0 - dy * dy).sqrt()).round() as i32;
        let cx_i = cx.round() as i32;
        for px in (cx_i - half_width)..=(cx_i + half_width) {
            put_pixel(
                pixels,
                width,
                height,
                stride,
                px,
                py,
                color,
                compositing_mode,
            );
        }
    }
}

// ── Polygon / scanline fill ─────────────────────────────────────────────────

/// Fill a convex or simple polygon using a scanline algorithm.
/// `points` must be in order (either clockwise or counter‑clockwise).
///
/// Edge traversal uses `i64` arithmetic so that extreme-but-plausible guest
/// coordinates cannot overflow `i32` (which previously filled wrong regions
/// or panicked in debug builds).
pub fn fill_polygon(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    points: &[GdiplusPointF],
    color: u32,
    compositing_mode: u32,
) {
    if points.len() < 3 {
        return;
    }

    // Build edge table: (min_y, max_y, x_at_min_y, dx/dy per scanline).
    let mut edges: Vec<(i32, i32, i64, i64)> = Vec::new();
    for i in 0..points.len() {
        let j = (i + 1) % points.len();
        let p1 = &points[i];
        let p2 = &points[j];
        let y1 = p1.y.round() as i32;
        let y2 = p2.y.round() as i32;
        if y1 == y2 {
            continue;
        }
        let (y_min, y_max, x_at_y_min, x_at_y_max) = if y1 < y2 {
            (y1, y2, p1.x, p2.x)
        } else {
            (y2, y1, p2.x, p1.x)
        };
        let dx = (x_at_y_max - x_at_y_min) / (y_max - y_min) as f32;
        edges.push((y_min, y_max, x_at_y_min.round() as i64, dx as i64));
    }

    if edges.is_empty() {
        return;
    }

    let min_y = edges.iter().map(|e| e.0).min().unwrap_or(0).max(0);
    let max_y = edges
        .iter()
        .map(|e| e.1)
        .max()
        .unwrap_or(0)
        .min(height as i32 - 1);

    for scan_y in min_y..=max_y {
        let mut intersections: Vec<i32> = Vec::new();
        for &(y_min, y_max, x_at_min, step) in &edges {
            if scan_y >= y_min && scan_y < y_max {
                // Saturating i64 arithmetic: extreme coordinates cannot panic
                // here; out-of-range results are clamped to the bitmap.
                let x = x_at_min.saturating_add(step.saturating_mul(scan_y as i64 - y_min as i64));
                intersections.push(x.clamp(0, width as i64 - 1) as i32);
            }
        }
        intersections.sort_unstable();
        for chunk in intersections.chunks(2) {
            if chunk.len() == 2 {
                let x0 = chunk[0].max(0);
                let x1 = chunk[1].min(width as i32 - 1);
                for px in x0..=x1 {
                    put_pixel(
                        pixels,
                        width,
                        height,
                        stride,
                        px,
                        scan_y,
                        color,
                        compositing_mode,
                    );
                }
            }
        }
    }
}

// ── Pie / Arc helpers ───────────────────────────────────────────────────────

/// Approximate an arc or pie by generating line segments.
/// If `is_pie`, the segment list includes the centre point to form a pie shape.
fn arc_to_line_segments(
    cx: f32,
    cy: f32,
    rx: f32,
    ry: f32,
    start_angle: f32,
    sweep_angle: f32,
    is_pie: bool,
) -> Vec<GdiplusPointF> {
    // Cap the segment count: `sweep_angle` is guest-controlled and a huge
    // value would otherwise allocate an unbounded point vector (OOM/hang).
    let segments = 64.max((sweep_angle.abs() * 0.5).min(4096.0) as i32);
    let step = sweep_angle.to_radians() / segments as f32;
    let start_rad = start_angle.to_radians();

    let mut pts = Vec::new();
    if is_pie {
        pts.push(GdiplusPointF { x: cx, y: cy });
    }
    for i in 0..=segments {
        let angle = start_rad + step * i as f32;
        pts.push(GdiplusPointF {
            x: cx + rx * angle.cos(),
            y: cy + ry * angle.sin(),
        });
    }
    pts
}

/// Draw a pie (outline).
pub fn draw_pie(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    start_angle: f32,
    sweep_angle: f32,
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    smoothing_mode: u32,
) {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = w / 2.0;
    let ry = h / 2.0;
    let pts = arc_to_line_segments(cx, cy, rx, ry, start_angle, sweep_angle, true);
    for i in 1..pts.len() {
        draw_line(
            pixels, width, height, stride, pts[i - 1].x, pts[i - 1].y, pts[i].x, pts[i].y,
            color, pen_width, compositing_mode, smoothing_mode,
        );
    }
}

/// Fill a pie.
pub fn fill_pie(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    start_angle: f32,
    sweep_angle: f32,
    color: u32,
    compositing_mode: u32,
) {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = w / 2.0;
    let ry = h / 2.0;
    let pts = arc_to_line_segments(cx, cy, rx, ry, start_angle, sweep_angle, true);
    fill_polygon(pixels, width, height, stride, &pts, color, compositing_mode);
}

/// Draw an arc (open curve).
pub fn draw_arc(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    start_angle: f32,
    sweep_angle: f32,
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    smoothing_mode: u32,
) {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = w / 2.0;
    let ry = h / 2.0;
    let pts = arc_to_line_segments(cx, cy, rx, ry, start_angle, sweep_angle, false);
    for i in 1..pts.len() {
        draw_line(
            pixels, width, height, stride, pts[i - 1].x, pts[i - 1].y, pts[i].x, pts[i].y,
            color, pen_width, compositing_mode, smoothing_mode,
        );
    }
}

// ── Path rendering ──────────────────────────────────────────────────────────

/// Draw a path's outline using the given pen.
pub fn draw_path(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    path: &GdiplusPath,
    color: u32,
    pen_width: f32,
    compositing_mode: u32,
    smoothing_mode: u32,
) {
    let mut i = 0;
    while i < path.elements.len() {
        match &path.elements[i] {
            GdiplusPathElement::Line { x1, y1, x2, y2 } => {
                draw_line(
                    pixels,
                    width,
                    height,
                    stride,
                    *x1,
                    *y1,
                    *x2,
                    *y2,
                    color,
                    pen_width,
                    compositing_mode,
                    smoothing_mode,
                );
                i += 1;
            }
            GdiplusPathElement::Rectangle { x, y, w, h } => {
                draw_rect(
                    pixels,
                    width,
                    height,
                    stride,
                    *x,
                    *y,
                    *w,
                    *h,
                    color,
                    pen_width,
                    compositing_mode,
                    smoothing_mode,
                );
                i += 1;
            }
            GdiplusPathElement::Ellipse { x, y, w, h } => {
                draw_ellipse(
                    pixels,
                    width,
                    height,
                    stride,
                    *x,
                    *y,
                    *w,
                    *h,
                    color,
                    pen_width,
                    compositing_mode,
                    smoothing_mode,
                );
                i += 1;
            }
            GdiplusPathElement::Arc {
                x,
                y,
                w,
                h,
                start_angle,
                sweep_angle,
            } => {
                draw_arc(
                    pixels,
                    width,
                    height,
                    stride,
                    *x,
                    *y,
                    *w,
                    *h,
                    *start_angle,
                    *sweep_angle,
                    color,
                    pen_width,
                    compositing_mode,
                    smoothing_mode,
                );
                i += 1;
            }
            GdiplusPathElement::Pie {
                x,
                y,
                w,
                h,
                start_angle,
                sweep_angle,
            } => {
                draw_pie(
                    pixels,
                    width,
                    height,
                    stride,
                    *x,
                    *y,
                    *w,
                    *h,
                    *start_angle,
                    *sweep_angle,
                    color,
                    pen_width,
                    compositing_mode,
                    smoothing_mode,
                );
                i += 1;
            }
            GdiplusPathElement::Bezier { points } => {
                // Decompose Bezier into line segments
                let segments = 32;
                for s in 1..=segments {
                    let t1 = (s - 1) as f32 / segments as f32;
                    let t2 = s as f32 / segments as f32;
                    let p1 = eval_cubic_bezier(points, t1);
                    let p2 = eval_cubic_bezier(points, t2);
                    draw_line(
                        pixels,
                        width,
                        height,
                        stride,
                        p1.x,
                        p1.y,
                        p2.x,
                        p2.y,
                        color,
                        pen_width,
                        compositing_mode,
                        smoothing_mode,
                    );
                }
                i += 1;
            }
            GdiplusPathElement::Polygon { points } => {
                for j in 1..points.len() {
                    draw_line(
                        pixels,
                        width,
                        height,
                        stride,
                        points[j - 1].x,
                        points[j - 1].y,
                        points[j].x,
                        points[j].y,
                        color,
                        pen_width,
                        compositing_mode,
                        smoothing_mode,
                    );
                }
                i += 1;
            }
            GdiplusPathElement::Lines { points } => {
                for j in 1..points.len() {
                    draw_line(
                        pixels,
                        width,
                        height,
                        stride,
                        points[j - 1].x,
                        points[j - 1].y,
                        points[j].x,
                        points[j].y,
                        color,
                        pen_width,
                        compositing_mode,
                        smoothing_mode,
                    );
                }
                i += 1;
            }
            GdiplusPathElement::Curve { points, tension: _ } => {
                // Simple approximation: treat as polyline
                for j in 1..points.len() {
                    draw_line(
                        pixels,
                        width,
                        height,
                        stride,
                        points[j - 1].x,
                        points[j - 1].y,
                        points[j].x,
                        points[j].y,
                        color,
                        pen_width,
                        compositing_mode,
                        smoothing_mode,
                    );
                }
                i += 1;
            }
            GdiplusPathElement::ClosedCurve { points, tension: _ } => {
                for j in 0..points.len() {
                    let j2 = (j + 1) % points.len();
                    draw_line(
                        pixels,
                        width,
                        height,
                        stride,
                        points[j].x,
                        points[j].y,
                        points[j2].x,
                        points[j2].y,
                        color,
                        pen_width,
                        compositing_mode,
                        smoothing_mode,
                    );
                }
                i += 1;
            }
            GdiplusPathElement::StartFigure | GdiplusPathElement::CloseFigure => {
                i += 1;
            }
            GdiplusPathElement::String { .. } => {
                i += 1; // Not handled for path stroking
            }
        }
    }
}

/// Fill a path using the given colour (from a brush).
///
/// Each connected figure (separated by `StartFigure`/`CloseFigure`, or a
/// self-contained closed element such as a rectangle, ellipse or pie) is
/// filled on its own, so disjoint figures are never merged into one polygon
/// (which produced spurious fills between unrelated shapes).
pub fn fill_path(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    path: &GdiplusPath,
    color: u32,
    compositing_mode: u32,
) {
    let mut figures: Vec<Vec<GdiplusPointF>> = Vec::new();
    let mut current: Vec<GdiplusPointF> = Vec::new();

    for elem in &path.elements {
        match elem {
            GdiplusPathElement::StartFigure | GdiplusPathElement::CloseFigure => {
                // Figure boundary: close off the accumulated points.
                if !current.is_empty() {
                    figures.push(std::mem::take(&mut current));
                }
            }
            GdiplusPathElement::Line { x1, y1, x2, y2 } => {
                current.push(GdiplusPointF { x: *x1, y: *y1 });
                current.push(GdiplusPointF { x: *x2, y: *y2 });
            }
            // Self-contained closed shapes form their own figure.
            GdiplusPathElement::Rectangle { x, y, w, h } => {
                if !current.is_empty() {
                    figures.push(std::mem::take(&mut current));
                }
                figures.push(vec![
                    GdiplusPointF { x: *x, y: *y },
                    GdiplusPointF { x: *x + *w, y: *y },
                    GdiplusPointF { x: *x + *w, y: *y + *h },
                    GdiplusPointF { x: *x, y: *y + *h },
                ]);
            }
            GdiplusPathElement::Ellipse { x, y, w, h } => {
                if !current.is_empty() {
                    figures.push(std::mem::take(&mut current));
                }
                figures.push(ellipse_points(*x, *y, *w, *h));
            }
            GdiplusPathElement::Pie {
                x,
                y,
                w,
                h,
                start_angle,
                sweep_angle,
            } => {
                if !current.is_empty() {
                    figures.push(std::mem::take(&mut current));
                }
                let cx = x + w / 2.0;
                let cy = y + h / 2.0;
                let rx = w / 2.0;
                let ry = h / 2.0;
                figures.push(arc_to_line_segments(
                    cx, cy, rx, ry, *start_angle, *sweep_angle, true,
                ));
            }
            GdiplusPathElement::Polygon { points } | GdiplusPathElement::Lines { points } => {
                current.extend(points.iter().cloned());
            }
            GdiplusPathElement::Bezier { points } => {
                let segs = 32;
                for s in 0..=segs {
                    let t = s as f32 / segs as f32;
                    current.push(eval_cubic_bezier(points, t));
                }
            }
            GdiplusPathElement::Curve { points, tension: _ } => {
                current.extend(points.iter().cloned());
            }
            GdiplusPathElement::ClosedCurve { points, tension: _ } => {
                current.extend(points.iter().cloned());
            }
            GdiplusPathElement::Arc { .. } | GdiplusPathElement::String { .. } => {
                // Open arcs have no interior to fill; strings are not handled.
            }
        }
    }
    if !current.is_empty() {
        figures.push(current);
    }

    for figure in figures {
        if figure.len() >= 3 {
            fill_polygon(pixels, width, height, stride, &figure, color, compositing_mode);
        }
    }
}

/// Approximate an ellipse with 32 line segments (the scanline filler closes
/// the loop back to the first point).
fn ellipse_points(x: f32, y: f32, w: f32, h: f32) -> Vec<GdiplusPointF> {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = w / 2.0;
    let ry = h / 2.0;
    let segs = 32;
    let mut pts = Vec::with_capacity(segs as usize + 1);
    for s in 0..=segs {
        let a = 2.0 * std::f32::consts::PI * s as f32 / segs as f32;
        pts.push(GdiplusPointF {
            x: cx + rx * a.cos(),
            y: cy + ry * a.sin(),
        });
    }
    pts
}

/// Evaluate a cubic Bezier at parameter `t` (0..=1).
fn eval_cubic_bezier(pts: &[GdiplusPointF; 4], t: f32) -> GdiplusPointF {
    let t2 = t * t;
    let t3 = t2 * t;
    let mt = 1.0 - t;
    let mt2 = mt * mt;
    let mt3 = mt2 * mt;
    GdiplusPointF {
        x: mt3 * pts[0].x + 3.0 * mt2 * t * pts[1].x + 3.0 * mt * t2 * pts[2].x + t3 * pts[3].x,
        y: mt3 * pts[0].y + 3.0 * mt2 * t * pts[1].y + 3.0 * mt * t2 * pts[2].y + t3 * pts[3].y,
    }
}

// ── Image drawing (simple copy / stretch) ───────────────────────────────────

/// Draw a source bitmap onto the destination pixel buffer at position `(dx, dy)`.
/// No scaling is performed (1:1 copy).  Alpha blending is applied per pixel.
pub fn draw_image(
    dst_pixels: &mut [u8],
    dst_width: u32,
    dst_height: u32,
    dst_stride: i32,
    src_pixels: &[u8],
    src_width: u32,
    src_height: u32,
    src_stride: i32,
    dx: f32,
    dy: f32,
    compositing_mode: u32,
) {
    let ox = clamp_f32(dx);
    let oy = clamp_f32(dy);
    for sy in 0..src_height as i32 {
        for sx in 0..src_width as i32 {
            // Negative source strides (bottom-up DIBs) flip the row index.
            let src_row = if src_stride < 0 {
                src_height as i64 - 1 - sy as i64
            } else {
                sy as i64
            };
            let src_off = src_row.saturating_mul(src_stride as i64) + sx as i64 * 4;
            if src_off < 0 || src_off.saturating_add(3) >= src_pixels.len() as i64 {
                continue;
            }
            let src_idx = src_off as usize;
            let color = u32::from_le_bytes([
                src_pixels[src_idx],
                src_pixels[src_idx + 1],
                src_pixels[src_idx + 2],
                src_pixels[src_idx + 3],
            ]);
            put_pixel(
                dst_pixels,
                dst_width,
                dst_height,
                dst_stride,
                ox + sx,
                oy + sy,
                color,
                compositing_mode,
            );
        }
    }
}

/// Draw a source bitmap onto the destination, scaling to `(dw, dh)`.
pub fn draw_image_rect(
    dst_pixels: &mut [u8],
    dst_width: u32,
    dst_height: u32,
    dst_stride: i32,
    src_pixels: &[u8],
    src_width: u32,
    src_height: u32,
    src_stride: i32,
    dx: f32,
    dy: f32,
    dw: f32,
    dh: f32,
    compositing_mode: u32,
) {
    // Zero-size sources would underflow the `src_width - 1` clamp below.
    if src_width == 0 || src_height == 0 {
        return;
    }
    let ox = clamp_f32(dx);
    let oy = clamp_f32(dy);
    let ow = dw.max(1.0).round() as i32;
    let oh = dh.max(1.0).round() as i32;

    for py in 0..oh {
        for px in 0..ow {
            let src_x =
                (px as f32 / ow as f32 * src_width as f32).min((src_width - 1) as f32) as i32;
            let src_y =
                (py as f32 / oh as f32 * src_height as f32).min((src_height - 1) as f32) as i32;
            // Negative source strides (bottom-up DIBs) flip the row index.
            let src_row = if src_stride < 0 {
                src_height as i64 - 1 - src_y as i64
            } else {
                src_y as i64
            };
            let src_off = src_row.saturating_mul(src_stride as i64) + src_x as i64 * 4;
            if src_off < 0 || src_off.saturating_add(3) >= src_pixels.len() as i64 {
                continue;
            }
            let src_idx = src_off as usize;
            let color = u32::from_le_bytes([
                src_pixels[src_idx],
                src_pixels[src_idx + 1],
                src_pixels[src_idx + 2],
                src_pixels[src_idx + 3],
            ]);
            put_pixel(
                dst_pixels,
                dst_width,
                dst_height,
                dst_stride,
                ox + px,
                oy + py,
                color,
                compositing_mode,
            );
        }
    }
}

// ── Text rendering (simple placeholder) ─────────────────────────────────────

/// Render text as filled rectangles (placeholder).
/// Real text rendering would require CoreText or similar.
pub fn draw_string(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    text: &str,
    x: f32,
    y: f32,
    font_size: f32,
    color: u32,
    compositing_mode: u32,
) {
    // Placeholder: render a semi-transparent block for each character.
    let char_w = (font_size * 0.6).max(4.0) as i32;
    let char_h = (font_size * 1.2).max(8.0) as i32;
    let ox = clamp_f32(x);
    let oy = clamp_f32(y);

    // Enumerate characters (not byte offsets): multi-byte UTF-8 must not
    // produce over-wide spacing.
    for (i, _) in text.chars().enumerate() {
        let cx = ox + (i as i32 * char_w);
        for py in oy..(oy + char_h) {
            for px in cx..(cx + char_w) {
                put_pixel(
                    pixels,
                    width,
                    height,
                    stride,
                    px,
                    py,
                    color,
                    compositing_mode,
                );
            }
        }
    }
}

// ── Public convenience entry points (called from dispatch handlers) ─────────

/// Helper: resolve a GDI+ object's compositing mode for a given graphics handle.
/// If the handle is invalid, returns SOURCE_OVER as default.
pub fn get_compositing_mode(_brush_color: u32) -> u32 {
    // This is passed through from the dispatch handler; we don't look up state here.
    GDIPLUS_COMPOSITING_MODE_SOURCE_OVER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user32::GdiplusLineBrush;

    fn make_buffer(w: u32, h: u32) -> (Vec<u8>, i32) {
        let stride = (w * 4) as i32;
        (vec![0; (stride * h as i32) as usize], stride)
    }

    fn get_pixel(buf: &[u8], stride: i32, x: i32, y: i32) -> u32 {
        let idx = (y * stride + x * 4) as usize;
        u32::from_le_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]])
    }

    #[test]
    fn test_put_pixel_simple() {
        let (mut buf, stride) = make_buffer(10, 10);
        put_pixel(
            &mut buf,
            10,
            10,
            stride,
            5,
            5,
            0xFFFF0000,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        assert_eq!(get_pixel(&buf, stride, 5, 5), 0xFFFF0000);
    }

    #[test]
    fn test_put_pixel_clip() {
        let (mut buf, stride) = make_buffer(10, 10);
        // Outside bounds should not panic
        put_pixel(
            &mut buf,
            10,
            10,
            stride,
            20,
            20,
            0xFFFF0000,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        put_pixel(
            &mut buf,
            10,
            10,
            stride,
            -1,
            -1,
            0xFFFF0000,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
    }

    #[test]
    fn test_alpha_blend() {
        // Source-over: src=0x80FF0000 (semi-transparent red), dst=0xFF0000FF (opaque blue)
        let blended = blend_pixel(0x80FF0000, 0xFF0000FF, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER);
        let a = alpha_of(blended);
        let r = red_of(blended);
        let b = blue_of(blended);
        assert!(a > 128, "alpha should be > 128 (sa + da*(1-sa/255))");
        assert!(r > 0, "should have some red");
        assert!(b > 0, "should have some blue");
    }

    #[test]
    fn test_source_copy() {
        let blended = blend_pixel(0x80FF0000, 0xFF0000FF, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        assert_eq!(
            blended, 0x80FF0000,
            "source copy should replace dst entirely"
        );
    }

    #[test]
    fn test_fill_rect() {
        let (mut buf, stride) = make_buffer(20, 20);
        fill_rect(
            &mut buf,
            20,
            20,
            stride,
            5.0,
            5.0,
            10.0,
            10.0,
            0xFFFF0000,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        // Check a pixel inside
        assert_eq!(get_pixel(&buf, stride, 10, 10), 0xFFFF0000);
        // Check a pixel outside
        assert_eq!(get_pixel(&buf, stride, 0, 0), 0x00000000);
    }

    #[test]
    fn test_draw_line() {
        let (mut buf, stride) = make_buffer(20, 20);
        draw_line(
            &mut buf,
            20,
            20,
            stride,
            2.0,
            10.0,
            18.0,
            10.0,
            0xFFFF0000,
            1.0,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
            0, // smoothing_mode: aliased
        );
        // The horizontal line should set some pixels at y=10
        assert_eq!(get_pixel(&buf, stride, 5, 10), 0xFFFF0000);
        assert_eq!(get_pixel(&buf, stride, 15, 10), 0xFFFF0000);
    }

    #[test]
    fn test_draw_image() {
        let (mut dst, dstride) = make_buffer(10, 10);
        let (_src, sstride) = make_buffer(3, 3);
        // We'd need to fill src first, then draw
        let src_copy = {
            let stride = sstride;
            let mut v = vec![0u8; (stride * 3) as usize];
            // Set a pixel
            let idx = (stride + 4) as usize;
            v[idx..idx + 4].copy_from_slice(&0xFFFF0000u32.to_le_bytes());
            v
        };
        draw_image(
            &mut dst,
            10,
            10,
            dstride,
            &src_copy,
            3,
            3,
            sstride,
            2.0,
            2.0,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        assert_eq!(get_pixel(&dst, dstride, 3, 3), 0xFFFF0000);
    }

    #[test]
    fn test_fill_ellipse() {
        let (mut buf, stride) = make_buffer(40, 40);
        fill_ellipse(
            &mut buf,
            40,
            40,
            stride,
            5.0,
            5.0,
            30.0,
            30.0,
            0xFF00FF00,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        // Centre should be filled
        assert_eq!(get_pixel(&buf, stride, 20, 20), 0xFF00FF00);
    }

    #[test]
    fn test_fill_polygon() {
        let (mut buf, stride) = make_buffer(20, 20);
        let pts = vec![
            GdiplusPointF { x: 2.0, y: 2.0 },
            GdiplusPointF { x: 18.0, y: 2.0 },
            GdiplusPointF { x: 10.0, y: 18.0 },
        ];
        fill_polygon(
            &mut buf,
            20,
            20,
            stride,
            &pts,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        // Centre-ish should be filled
        assert_eq!(get_pixel(&buf, stride, 10, 10), 0xFF0000FF);
    }

    #[test]
    fn test_brush_color_solid() {
        let brush = GdiplusBrush::SolidFill(crate::user32::GdiplusSolidFill { color: 0xFFAABBCC });
        assert_eq!(brush_color_at(&brush, 0.0, 0.0, None), 0xFFAABBCC);
    }

    #[test]
    fn test_brush_color_line() {
        let brush = GdiplusBrush::LineBrush(GdiplusLineBrush {
            point1: (0.0, 0.0),
            point2: (10.0, 0.0),
            color1: 0xFFFF0000,
            color2: 0xFF0000FF,
            wrap_mode: 0,
        });
        // At the start point
        let c = brush_color_at(&brush, 0.0, 0.0, None);
        assert_eq!(c, 0xFFFF0000);
        // At the end point
        let c = brush_color_at(&brush, 10.0, 0.0, None);
        assert_eq!(c, 0xFF0000FF);
    }

    #[test]
    fn test_brush_color_texture() {
        // 2x2 ARGB bitmap: red, green, blue, white (byte order B,G,R,A)
        let pixels: Vec<u8> = vec![
            0x00, 0x00, 0xFF, 0xFF, // (0,0) = red
            0x00, 0xFF, 0x00, 0xFF, // (1,0) = green
            0xFF, 0x00, 0x00, 0xFF, // (0,1) = blue
            0xFF, 0xFF, 0xFF, 0xFF, // (1,1) = white
        ];
        let brush = GdiplusBrush::Texture(crate::user32::GdiplusTextureBrush {
            image_handle: 1,
            wrap_mode: 0,
        });
        let td = Some((pixels.as_slice(), 2, 2, 8));
        assert_eq!(
            brush_color_at(&brush, 0.0, 0.0, td),
            0xFFFF0000,
            "(0,0) should be red"
        );
        assert_eq!(
            brush_color_at(&brush, 1.0, 0.0, td),
            0xFF00FF00,
            "(1,0) should be green"
        );
        assert_eq!(
            brush_color_at(&brush, 0.0, 1.0, td),
            0xFF0000FF,
            "(0,1) should be blue"
        );
        assert_eq!(
            brush_color_at(&brush, 1.0, 1.0, td),
            0xFFFFFFFF,
            "(1,1) should be white"
        );
        // Wrap mode TILE: (2,0) wraps to (0,0)
        assert_eq!(
            brush_color_at(&brush, 2.0, 0.0, td),
            0xFFFF0000,
            "(2,0) with tile wrap should be red"
        );
        // No texture data should return transparent black
        assert_eq!(
            brush_color_at(&brush, 0.0, 0.0, None),
            0x00000000,
            "no texture data should return transparent black"
        );
    }

    // ── GDI resource cleanup tests ─────────────────────────────────────

    #[test]
    fn repeated_put_pixel_no_panic() {
        let width = 64u32;
        let height = 64u32;
        let stride = (width * 4) as i32;
        let mut pixels = vec![0u8; (stride * height as i32) as usize];

        for _ in 0..100 {
            for y in 0..height {
                for x in (0..width).step_by(4) {
                    put_pixel(
                        &mut pixels,
                        width,
                        height,
                        stride,
                        x as i32,
                        y as i32,
                        0xFFFF0000,
                        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
                    );
                }
            }
            // Clear
            pixels.fill(0);
        }
    }

    #[test]
    fn repeated_blend_pixel_no_panic() {
        let width = 32u32;
        let height = 32u32;
        let stride = (width * 4) as i32;
        let mut pixels = vec![0u8; (stride * height as i32) as usize];

        for i in 0..200 {
            let color = if i % 2 == 0 { 0x80FF0000 } else { 0x4000FF00 };
            for y in 0..height {
                for x in (0..width).step_by(8) {
                    put_pixel(
                        &mut pixels,
                        width,
                        height,
                        stride,
                        x as i32,
                        y as i32,
                        color,
                        GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
                    );
                }
            }
        }
    }

    #[test]
    fn draw_rect_repeated_create_destroy_no_leak() {
        let width = 16u32;
        let height = 16u32;
        let stride = (width * 4) as i32;

        for _ in 0..50 {
            let mut pixels = vec![0u8; (stride * height as i32) as usize];
            // Draw a filled rectangle
            for y in 0..height {
                for x in 0..width {
                    put_pixel(
                        &mut pixels,
                        width,
                        height,
                        stride,
                        x as i32,
                        y as i32,
                        0xFFFFFFFF,
                        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
                    );
                }
            }
            // "Destroy" — pixels go out of scope and are freed
            assert_eq!(pixels.len(), (stride * height as i32) as usize);
        }
    }

    #[test]
    fn out_of_bounds_put_pixel_is_noop() {
        let width = 4u32;
        let height = 4u32;
        let stride = 16i32;
        let mut pixels = vec![0u8; 64];

        // These should all be no-ops (no panic, no OOB write)
        put_pixel(
            &mut pixels,
            width,
            height,
            stride,
            -1,
            0,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        put_pixel(
            &mut pixels,
            width,
            height,
            stride,
            0,
            -1,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        put_pixel(
            &mut pixels,
            width,
            height,
            stride,
            4,
            0,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        put_pixel(
            &mut pixels,
            width,
            height,
            stride,
            0,
            4,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        put_pixel(
            &mut pixels,
            width,
            height,
            stride,
            100,
            100,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );

        // All pixels should still be zero
        assert!(
            pixels.iter().all(|&b| b == 0),
            "out-of-bounds writes should be no-ops"
        );
    }

    #[test]
    fn put_pixel_supports_negative_stride() {
        // 2 rows, bottom-up storage: row 0 (y=0) lives at the *bottom*.
        let stride = -8i32;
        let mut pixels = vec![0u8; 16];
        put_pixel(
            &mut pixels,
            2,
            2,
            stride,
            1,
            1,
            0xFFFF0000,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        // y=1 (top row) with negative stride maps to row offset 0, x=1 → byte 4.
        assert_eq!(
            u32::from_le_bytes([pixels[4], pixels[5], pixels[6], pixels[7]]),
            0xFFFF0000
        );
    }

    #[test]
    fn draw_ellipse_large_extents_do_not_overflow_or_hang() {
        let (mut buf, stride) = make_buffer(64, 64);
        // rx = ry = 1500 previously overflowed i32 (debug panic / release hang).
        draw_ellipse(
            &mut buf,
            64,
            64,
            stride,
            -5000.0,
            -5000.0,
            3000.0,
            3000.0,
            0xFFFF0000,
            1.0,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
            0,
        );
        // And with an absurd pen width the loop must still terminate.
        draw_ellipse(
            &mut buf,
            64,
            64,
            stride,
            5.0,
            5.0,
            20.0,
            20.0,
            0xFF00FF00,
            1.0e9,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
            0,
        );
    }

    #[test]
    fn fill_polygon_extreme_coordinates_do_not_panic() {
        let (mut buf, stride) = make_buffer(32, 32);
        let pts = vec![
            GdiplusPointF { x: -1.0e9, y: -1.0e9 },
            GdiplusPointF { x: 1.0e9, y: -1.0e9 },
            GdiplusPointF { x: 0.0, y: 1.0e9 },
        ];
        fill_polygon(
            &mut buf,
            32,
            32,
            stride,
            &pts,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
    }

    #[test]
    fn draw_image_rect_zero_size_source_is_noop() {
        let (mut dst, dstride) = make_buffer(8, 8);
        let empty: Vec<u8> = Vec::new();
        // src_width == 0 previously underflowed `src_width - 1` (debug panic).
        draw_image_rect(
            &mut dst,
            8,
            8,
            dstride,
            &empty,
            0,
            0,
            0,
            0.0,
            0.0,
            8.0,
            8.0,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
    }

    #[test]
    fn arc_segment_count_is_bounded() {
        // A huge sweep angle previously produced ~2.1e9 segments (OOM).
        let pts = arc_to_line_segments(0.0, 0.0, 10.0, 10.0, 0.0, 1.0e9, false);
        assert!(
            pts.len() <= 4097,
            "arc segment count must be bounded, got {}",
            pts.len()
        );
    }

    #[test]
    fn fill_path_fills_disjoint_figures_separately() {
        let (mut buf, stride) = make_buffer(40, 40);
        // Two disjoint triangles: filling them as one polygon would fill the
        // area between them; filling them separately leaves the gap clear.
        let path = GdiplusPath {
            fill_mode: 0,
            elements: vec![
                crate::user32::GdiplusPathElement::Polygon {
                    points: vec![
                        GdiplusPointF { x: 2.0, y: 2.0 },
                        GdiplusPointF { x: 10.0, y: 2.0 },
                        GdiplusPointF { x: 6.0, y: 10.0 },
                    ],
                },
                crate::user32::GdiplusPathElement::Polygon {
                    points: vec![
                        GdiplusPointF { x: 22.0, y: 22.0 },
                        GdiplusPointF { x: 30.0, y: 22.0 },
                        GdiplusPointF { x: 26.0, y: 30.0 },
                    ],
                },
            ],
        };
        fill_path(
            &mut buf,
            40,
            40,
            stride,
            &path,
            0xFF0000FF,
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
        );
        // Centres of both triangles are filled…
        assert_eq!(get_pixel(&buf, stride, 6, 6), 0xFF0000FF);
        assert_eq!(get_pixel(&buf, stride, 26, 26), 0xFF0000FF);
        // …but the gap between them is not (a merged polygon would fill it).
        assert_eq!(get_pixel(&buf, stride, 15, 15), 0x00000000);
    }
}
