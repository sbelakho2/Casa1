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

use crate::user32::{
    GdiplusBrush, GdiplusLineBrush, GdiplusMatrix, GdiplusPath, GdiplusPathElement,
    GdiplusPen, GdiplusPointF, GdiplusRectF,
    GDIPLUS_COMPOSITING_MODE_SOURCE_COPY, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
    GDIPLUS_DASH_STYLE_DASH, GDIPLUS_DASH_STYLE_DASH_DOT, GDIPLUS_DASH_STYLE_DASH_DOT_DOT,
    GDIPLUS_DASH_STYLE_DOT, GDIPLUS_DASH_STYLE_SOLID, GDIPLUS_FILL_MODE_ALTERNATE,
    GDIPLUS_LINE_CAP_FLAT, GDIPLUS_LINE_CAP_ROUND, GDIPLUS_LINE_CAP_SQUARE,
    GDIPLUS_PIXEL_FORMAT_32BPP_ARGB,
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
    let idx = (y as i32 * stride) + (x as i32 * 4);
    if idx < 0 || idx + 3 >= pixels.len() as i32 {
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

/// Return an (x, y, w, h) rectangle from the given ellipse bounds,
/// clamping to integer pixels and the actual bitmap extents.
fn clip_rect_for_bounds(
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    bw: u32,
    bh: u32,
) -> (i32, i32, i32, i32) {
    let x0 = x.min(x + w) as i32;
    let y0 = y.min(y + h) as i32;
    let x1 = x.max(x + w) as i32;
    let y1 = y.max(y + h) as i32;
    let cx0 = x0.max(0).min(bw as i32 - 1);
    let cy0 = y0.max(0).min(bh as i32 - 1);
    let cx1 = x1.max(0).min(bw as i32 - 1);
    let cy1 = y1.max(0).min(bh as i32 - 1);
    (cx0, cy0, cx1 - cx0 + 1, cy1 - cy0 + 1)
}

// ── Brush helpers ───────────────────────────────────────────────────────────

/// Resolve the colour of a brush at an arbitrary point `(px, py)`.
/// For `SolidFill` this is trivial; for `LineBrush` we interpolate;
/// for `Texture` we return a default.
pub fn brush_color_at(
    brush: &GdiplusBrush,
    px: f32,
    py: f32,
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
        GdiplusBrush::Texture(_) => 0xFFFF00FF, // magenta placeholder
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
pub fn pen_color(pen: &GdiplusPen, px: f32, py: f32) -> u32 {
    pen.color
}

// ── Line drawing (Bresenham) ─────────────────────────────────────────────────

/// Draw an anti‑aliased or aliased line using Bresenham's midpoint algorithm.
/// Only aliased is implemented here; smoothing is ignored for now.
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
) {
    let w = pen_width.max(1.0).round() as i32;
    let x0 = clamp_f32(x1);
    let y0 = clamp_f32(y1);
    let x1 = clamp_f32(x2);
    let y1 = clamp_f32(y2);

    let mut dx = (x1 - x0).abs();
    let mut dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    let mut cx = x0;
    let mut cy = y0;
    loop {
        // Draw a small square for pen width
        for wy in -(w / 2)..=(w / 2) {
            for wx in -(w / 2)..=(w / 2) {
                put_pixel(pixels, width, height, stride, cx + wx, cy + wy, color, compositing_mode);
            }
        }
        if cx == x1 && cy == y1 {
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
) {
    for i in 1..points.len() {
        draw_line(
            pixels, width, height, stride,
            points[i - 1].x, points[i - 1].y,
            points[i].x, points[i].y,
            color, pen_width, compositing_mode,
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
) {
    let x2 = x + w;
    let y2 = y + h;
    // Top edge
    draw_line(pixels, width, height, stride, x, y, x2, y, color, pen_width, compositing_mode);
    // Bottom edge
    draw_line(pixels, width, height, stride, x, y2, x2, y2, color, pen_width, compositing_mode);
    // Left edge
    draw_line(pixels, width, height, stride, x, y, x, y2, color, pen_width, compositing_mode);
    // Right edge
    draw_line(pixels, width, height, stride, x2, y, x2, y2, color, pen_width, compositing_mode);
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
            put_pixel(pixels, width, height, stride, px, py, color, compositing_mode);
        }
    }
}

// ── Ellipse drawing (midpoint algorithm) ────────────────────────────────────

/// Draw the outline of an ellipse using the midpoint algorithm.
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
) {
    let cx = (x + w / 2.0).round() as i32;
    let cy = (y + h / 2.0).round() as i32;
    let rx = (w / 2.0).max(1.0).round() as i32;
    let ry = (h / 2.0).max(1.0).round() as i32;
    let pw = pen_width.max(1.0).round() as i32;

    let mut dx = 0;
    let mut dy = ry;
    let mut d1 = (ry * ry) - (rx * rx * ry) + (rx * rx) / 4;
    let mut d2;

    // Region 1
    while dx * ry * ry < dy * rx * rx {
        for wy in -(pw / 2)..=(pw / 2) {
            for wx in -(pw / 2)..=(pw / 2) {
                put_pixel(pixels, width, height, stride, cx + dx + wx, cy + dy + wy, color, compositing_mode);
                put_pixel(pixels, width, height, stride, cx - dx + wx, cy + dy + wy, color, compositing_mode);
                put_pixel(pixels, width, height, stride, cx + dx + wx, cy - dy + wy, color, compositing_mode);
                put_pixel(pixels, width, height, stride, cx - dx + wx, cy - dy + wy, color, compositing_mode);
            }
        }
        if d1 < 0 {
            dx += 1;
            d1 += 2 * ry * ry * dx + ry * ry;
        } else {
            dx += 1;
            dy -= 1;
            d1 += 2 * ry * ry * dx - 2 * rx * rx * dy + ry * ry;
        }
    }

    d2 = ((ry * ry) as f32 * (dx as f32 + 0.5) * (dx as f32 + 0.5) + (rx * rx) as f32 * (dy as f32 - 1.0) * (dy as f32 - 1.0) - (rx * rx * ry * ry) as f32) as i32;
    while dy >= 0 {
        for wy in -(pw / 2)..=(pw / 2) {
            for wx in -(pw / 2)..=(pw / 2) {
                put_pixel(pixels, width, height, stride, cx + dx + wx, cy + dy + wy, color, compositing_mode);
                put_pixel(pixels, width, height, stride, cx - dx + wx, cy + dy + wy, color, compositing_mode);
                put_pixel(pixels, width, height, stride, cx + dx + wx, cy - dy + wy, color, compositing_mode);
                put_pixel(pixels, width, height, stride, cx - dx + wx, cy - dy + wy, color, compositing_mode);
            }
        }
        if d2 > 0 {
            dy -= 1;
            d2 -= 2 * rx * rx * dy + rx * rx;
        } else {
            dy -= 1;
            dx += 1;
            d2 += 2 * ry * ry * dx - 2 * rx * rx * dy + rx * rx;
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
    let rx2 = rx * rx;
    let ry2 = ry * ry;

    let y0 = clamp_f32(y);
    let y1 = clamp_f32(y + h);
    for py in y0..y1 {
        let dy = (py as f32 - cy) / ry;
        let half_width = (rx * (1.0 - dy * dy).sqrt()).round() as i32;
        let cx_i = cx.round() as i32;
        for px in (cx_i - half_width)..=(cx_i + half_width) {
            put_pixel(pixels, width, height, stride, px, py, color, compositing_mode);
        }
    }
}

// ── Polygon / scanline fill ─────────────────────────────────────────────────

/// Fill a convex or simple polygon using a scanline algorithm.
/// `points` must be in order (either clockwise or counter‑clockwise).
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

    // Build edge table
    let mut edges: Vec<(i32, i32, i32, i32)> = Vec::new(); // (min_y, max_y, x_at_min_y, dx/dy)
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
        edges.push((y_min, y_max, x_at_y_min.round() as i32, dx as i32));
    }

    if edges.is_empty() {
        return;
    }

    let min_y = edges.iter().map(|e| e.0).min().unwrap_or(0).max(0);
    let max_y = edges.iter().map(|e| e.1).max().unwrap_or(0).min(height as i32 - 1);

    for scan_y in min_y..=max_y {
        let mut intersections: Vec<i32> = Vec::new();
        for &(y_min, y_max, x_at_min, step) in &edges {
            if scan_y >= y_min && scan_y < y_max {
                let x = x_at_min + step * (scan_y - y_min);
                intersections.push(x);
            }
        }
        intersections.sort_unstable();
        for chunk in intersections.chunks(2) {
            if chunk.len() == 2 {
                let x0 = chunk[0].max(0);
                let x1 = chunk[1].min(width as i32 - 1);
                for px in x0..=x1 {
                    put_pixel(pixels, width, height, stride, px, scan_y, color, compositing_mode);
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
    let segments = 64.max((sweep_angle.abs() * 0.5) as i32);
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
    if !is_pie {
        // Include the ending point back if just an arc
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
) {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = w / 2.0;
    let ry = h / 2.0;
    let pts = arc_to_line_segments(cx, cy, rx, ry, start_angle, sweep_angle, true);
    for i in 1..pts.len() {
        draw_line(
            pixels, width, height, stride,
            pts[i - 1].x, pts[i - 1].y,
            pts[i].x, pts[i].y,
            color, pen_width, compositing_mode,
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
) {
    let cx = x + w / 2.0;
    let cy = y + h / 2.0;
    let rx = w / 2.0;
    let ry = h / 2.0;
    let pts = arc_to_line_segments(cx, cy, rx, ry, start_angle, sweep_angle, false);
    for i in 1..pts.len() {
        draw_line(
            pixels, width, height, stride,
            pts[i - 1].x, pts[i - 1].y,
            pts[i].x, pts[i].y,
            color, pen_width, compositing_mode,
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
) {
    let mut i = 0;
    while i < path.elements.len() {
        match &path.elements[i] {
            GdiplusPathElement::Line { x1, y1, x2, y2 } => {
                draw_line(pixels, width, height, stride, *x1, *y1, *x2, *y2, color, pen_width, compositing_mode);
                i += 1;
            }
            GdiplusPathElement::Rectangle { x, y, w, h } => {
                draw_rect(pixels, width, height, stride, *x, *y, *w, *h, color, pen_width, compositing_mode);
                i += 1;
            }
            GdiplusPathElement::Ellipse { x, y, w, h } => {
                draw_ellipse(pixels, width, height, stride, *x, *y, *w, *h, color, pen_width, compositing_mode);
                i += 1;
            }
            GdiplusPathElement::Arc { x, y, w, h, start_angle, sweep_angle } => {
                draw_arc(pixels, width, height, stride, *x, *y, *w, *h, *start_angle, *sweep_angle, color, pen_width, compositing_mode);
                i += 1;
            }
            GdiplusPathElement::Pie { x, y, w, h, start_angle, sweep_angle } => {
                draw_pie(pixels, width, height, stride, *x, *y, *w, *h, *start_angle, *sweep_angle, color, pen_width, compositing_mode);
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
                    draw_line(pixels, width, height, stride, p1.x, p1.y, p2.x, p2.y, color, pen_width, compositing_mode);
                }
                i += 1;
            }
            GdiplusPathElement::Polygon { points } => {
                for j in 1..points.len() {
                    draw_line(pixels, width, height, stride, points[j - 1].x, points[j - 1].y, points[j].x, points[j].y, color, pen_width, compositing_mode);
                }
                i += 1;
            }
            GdiplusPathElement::Lines { points } => {
                for j in 1..points.len() {
                    draw_line(pixels, width, height, stride, points[j - 1].x, points[j - 1].y, points[j].x, points[j].y, color, pen_width, compositing_mode);
                }
                i += 1;
            }
            GdiplusPathElement::Curve { points, tension: _ } => {
                // Simple approximation: treat as polyline
                for j in 1..points.len() {
                    draw_line(pixels, width, height, stride, points[j - 1].x, points[j - 1].y, points[j].x, points[j].y, color, pen_width, compositing_mode);
                }
                i += 1;
            }
            GdiplusPathElement::ClosedCurve { points, tension: _ } => {
                for j in 0..points.len() {
                    let j2 = (j + 1) % points.len();
                    draw_line(pixels, width, height, stride, points[j].x, points[j].y, points[j2].x, points[j2].y, color, pen_width, compositing_mode);
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
pub fn fill_path(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    path: &GdiplusPath,
    color: u32,
    compositing_mode: u32,
) {
    // Collect all polygon points from the path for a simple fill.
    let mut poly_points: Vec<GdiplusPointF> = Vec::new();
    for elem in &path.elements {
        match elem {
            GdiplusPathElement::Line { x1, y1, x2, y2 } => {
                poly_points.push(GdiplusPointF { x: *x1, y: *y1 });
                poly_points.push(GdiplusPointF { x: *x2, y: *y2 });
            }
            GdiplusPathElement::Rectangle { x, y, w, h } => {
                poly_points.push(GdiplusPointF { x: *x, y: *y });
                poly_points.push(GdiplusPointF { x: *x + *w, y: *y });
                poly_points.push(GdiplusPointF { x: *x + *w, y: *y + *h });
                poly_points.push(GdiplusPointF { x: *x, y: *y + *h });
            }
            GdiplusPathElement::Ellipse { x, y, w, h } => {
                let cx = x + w / 2.0;
                let cy = y + h / 2.0;
                let rx = w / 2.0;
                let ry = h / 2.0;
                let segs = 32;
                for s in 0..=segs {
                    let a = 2.0 * std::f32::consts::PI * s as f32 / segs as f32;
                    poly_points.push(GdiplusPointF {
                        x: cx + rx * a.cos(),
                        y: cy + ry * a.sin(),
                    });
                }
            }
            GdiplusPathElement::Pie { x, y, w, h, start_angle, sweep_angle } => {
                let cx = x + w / 2.0;
                let cy = y + h / 2.0;
                let rx = w / 2.0;
                let ry = h / 2.0;
                let pts = arc_to_line_segments(cx, cy, rx, ry, *start_angle, *sweep_angle, true);
                poly_points.extend(pts);
            }
            GdiplusPathElement::Polygon { points } => {
                poly_points.extend(points.iter().cloned());
            }
            GdiplusPathElement::Lines { points } => {
                poly_points.extend(points.iter().cloned());
            }
            GdiplusPathElement::Bezier { points } => {
                let segs = 32;
                for s in 0..=segs {
                    let t = s as f32 / segs as f32;
                    let p = eval_cubic_bezier(points, t);
                    poly_points.push(p);
                }
            }
            GdiplusPathElement::Curve { points, tension: _ } => {
                poly_points.extend(points.iter().cloned());
            }
            GdiplusPathElement::ClosedCurve { points, tension: _ } => {
                poly_points.extend(points.iter().cloned());
            }
            _ => {}
        }
    }
    if poly_points.len() >= 3 {
        fill_polygon(pixels, width, height, stride, &poly_points, color, compositing_mode);
    }
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
            let src_idx = (sy * src_stride + sx * 4) as usize;
            if src_idx + 3 >= src_pixels.len() {
                continue;
            }
            let color = u32::from_le_bytes([
                src_pixels[src_idx],
                src_pixels[src_idx + 1],
                src_pixels[src_idx + 2],
                src_pixels[src_idx + 3],
            ]);
            put_pixel(dst_pixels, dst_width, dst_height, dst_stride, ox + sx, oy + sy, color, compositing_mode);
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
    let ox = clamp_f32(dx);
    let oy = clamp_f32(dy);
    let ow = dw.max(1.0).round() as i32;
    let oh = dh.max(1.0).round() as i32;

    for py in 0..oh {
        for px in 0..ow {
            let src_x = (px as f32 / ow as f32 * src_width as f32).min((src_width - 1) as f32) as i32;
            let src_y = (py as f32 / oh as f32 * src_height as f32).min((src_height - 1) as f32) as i32;
            let src_idx = (src_y * src_stride + src_x * 4) as usize;
            if src_idx + 3 >= src_pixels.len() {
                continue;
            }
            let color = u32::from_le_bytes([
                src_pixels[src_idx],
                src_pixels[src_idx + 1],
                src_pixels[src_idx + 2],
                src_pixels[src_idx + 3],
            ]);
            put_pixel(dst_pixels, dst_width, dst_height, dst_stride, ox + px, oy + py, color, compositing_mode);
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

    for (i, _) in text.char_indices() {
        let cx = ox + (i as i32 * char_w);
        for py in oy..(oy + char_h) {
            for px in cx..(cx + char_w) {
                put_pixel(pixels, width, height, stride, px, py, color, compositing_mode);
            }
        }
    }
}

// ── Public convenience entry points (called from dispatch handlers) ─────────

/// Helper: resolve a GDI+ object's compositing mode for a given graphics handle.
/// If the handle is invalid, returns SOURCE_OVER as default.
pub fn get_compositing_mode(brush_color: u32) -> u32 {
    // This is passed through from the dispatch handler; we don't look up state here.
    GDIPLUS_COMPOSITING_MODE_SOURCE_OVER
}

#[cfg(test)]
mod tests {
    use super::*;

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
        put_pixel(&mut buf, 10, 10, stride, 5, 5, 0xFFFF0000, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        assert_eq!(get_pixel(&buf, stride, 5, 5), 0xFFFF0000);
    }

    #[test]
    fn test_put_pixel_clip() {
        let (mut buf, stride) = make_buffer(10, 10);
        // Outside bounds should not panic
        put_pixel(&mut buf, 10, 10, stride, 20, 20, 0xFFFF0000, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        put_pixel(&mut buf, 10, 10, stride, -1, -1, 0xFFFF0000, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
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
        assert_eq!(blended, 0x80FF0000, "source copy should replace dst entirely");
    }

    #[test]
    fn test_fill_rect() {
        let (mut buf, stride) = make_buffer(20, 20);
        fill_rect(&mut buf, 20, 20, stride, 5.0, 5.0, 10.0, 10.0, 0xFFFF0000, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        // Check a pixel inside
        assert_eq!(get_pixel(&buf, stride, 10, 10), 0xFFFF0000);
        // Check a pixel outside
        assert_eq!(get_pixel(&buf, stride, 0, 0), 0x00000000);
    }

    #[test]
    fn test_draw_line() {
        let (mut buf, stride) = make_buffer(20, 20);
        draw_line(&mut buf, 20, 20, stride, 2.0, 10.0, 18.0, 10.0, 0xFFFF0000, 1.0, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        // The horizontal line should set some pixels at y=10
        assert_eq!(get_pixel(&buf, stride, 5, 10), 0xFFFF0000);
        assert_eq!(get_pixel(&buf, stride, 15, 10), 0xFFFF0000);
    }

    #[test]
    fn test_draw_image() {
        let (mut dst, dstride) = make_buffer(10, 10);
        let (src, sstride) = make_buffer(3, 3);
        // We'd need to fill src first, then draw
        let src_copy = {
            let stride = sstride;
            let mut v = vec![0u8; (stride * 3) as usize];
            // Set a pixel
            let idx = (1 * stride + 1 * 4) as usize;
            v[idx..idx + 4].copy_from_slice(&0xFFFF0000u32.to_le_bytes());
            v
        };
        draw_image(&mut dst, 10, 10, dstride, &src_copy, 3, 3, sstride, 2.0, 2.0, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        assert_eq!(get_pixel(&dst, dstride, 3, 3), 0xFFFF0000);
    }

    #[test]
    fn test_fill_ellipse() {
        let (mut buf, stride) = make_buffer(40, 40);
        fill_ellipse(&mut buf, 40, 40, stride, 5.0, 5.0, 30.0, 30.0, 0xFF00FF00, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
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
        fill_polygon(&mut buf, 20, 20, stride, &pts, 0xFF0000FF, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY);
        // Centre-ish should be filled
        assert_eq!(get_pixel(&buf, stride, 10, 10), 0xFF0000FF);
    }

    #[test]
    fn test_brush_color_solid() {
        let brush = GdiplusBrush::SolidFill(crate::user32::GdiplusSolidFill { color: 0xFFAABBCC });
        assert_eq!(brush_color_at(&brush, 0.0, 0.0), 0xFFAABBCC);
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
        let c = brush_color_at(&brush, 0.0, 0.0);
        assert_eq!(c, 0xFFFF0000);
        // At the end point
        let c = brush_color_at(&brush, 10.0, 0.0);
        assert_eq!(c, 0xFF0000FF);
    }
}
