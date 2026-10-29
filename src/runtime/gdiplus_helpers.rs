//! GDI+ geometry, raster, and codec helpers.

use super::*;

/// Read an array of GdiplusPointF from guest memory.
pub(crate) fn read_gdiplus_pointf_array(
    memory: &MemoryImage,
    ptr: u64,
    count: u32,
) -> Vec<crate::user32::GdiplusPointF> {
    let mut pts = Vec::with_capacity(count as usize);
    for i in 0..count {
        let offset = ptr + (i as u64 * 8);
        let x = f32::from_bits(read_u32(memory, offset).unwrap_or(0));
        let y = f32::from_bits(read_u32(memory, offset + 4).unwrap_or(0));
        pts.push(crate::user32::GdiplusPointF { x, y });
    }
    pts
}

/// Read a UTF-16 string from guest memory.
/// If length < 0, reads until null terminator.
pub(crate) fn read_guest_utf16_string(memory: &MemoryImage, ptr: u64, length: i32) -> String {
    if ptr == 0 {
        return String::new();
    }
    let mut units = Vec::new();
    if length >= 0 {
        for i in 0..(length as usize) {
            let cu = memory.read_u16(ptr + (i as u64 * 2)).unwrap_or(0);
            units.push(cu);
        }
    } else {
        loop {
            let cu = memory.read_u16(ptr + (units.len() as u64 * 2)).unwrap_or(0);
            if cu == 0 {
                break;
            }
            units.push(cu);
        }
    }
    String::from_utf16_lossy(&units)
}

// ── GDI+ paint-session types ────────────────────────────────────────────────

/// Resolved pen properties for one drawing call (device-pixel width).
#[derive(Debug, Clone, Copy)]
pub(crate) struct GdiplusStrokeStyle {
    pub(crate) color: u32,
    pub(crate) width_px: f32,
    pub(crate) dash: u32,
    pub(crate) join: u32,
    pub(crate) start_cap: u32,
    pub(crate) end_cap: u32,
    pub(crate) cm: u32,
    pub(crate) sm: u32,
}

/// The graphics state that shapes rasterise under.
#[derive(Debug, Clone)]
pub(crate) struct GdiplusRenderState {
    pub(crate) cm: u32,
    pub(crate) sm: u32,
    pub(crate) interp: u32,
    pub(crate) clip: Option<(f32, f32, f32, f32)>,
    /// Scanned device-space clip (path clips and scanned regions).  Applied
    /// as a real per-pixel test by `gdiplus_paint`.
    pub(crate) clip_region: Option<Box<crate::user32::GdiplusRegion>>,
    pub(crate) world: [f32; 6],
}

/// Where a graphics object's pixels live: a GDI+ bitmap object, a window
/// surface (window DC), or the GDI bitmap selected into a memory DC.
#[derive(Debug, Clone, Copy)]
pub(crate) enum GdiplusTargetKind {
    Bitmap(u64),
    Window(u32),
    MemoryDc(u64),
}

#[derive(Debug, Clone)]
pub(crate) struct GdiplusGraphicsInfo {
    pub(crate) target: Option<GdiplusTargetKind>,
    pub(crate) state: GdiplusRenderState,
}

/// A decoded GpRegion reference: the infinite region, a rectangle, or a real
/// scanned region (character-range output / path clip).
pub(crate) enum GdiplusDecodedRegion {
    Infinite,
    Rect((f32, f32, f32, f32)),
    Scanned(Box<crate::user32::GdiplusRegion>),
}

/// Run a raster operation under an optional scanned region clip.  The op is
/// allowed to draw unconstrained into `pixels` (preserving its compositing
/// arithmetic); afterwards every pixel outside the region is restored from a
/// snapshot, so the region acts as a genuine per-pixel clip.
pub(crate) fn gdiplus_paint_with_region_clip(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    region: Option<&crate::user32::GdiplusRegion>,
    op: impl FnOnce(&mut [u8], u32, u32, i32),
) {
    match region {
        // An unbounded region with no finite hole allows every pixel.
        Some(region) if !(region.inverted && region.spans.is_empty()) => {
            let snapshot = pixels.to_vec();
            op(pixels, width, height, stride);
            crate::gdiplus_render::restore_outside_region(
                pixels, width, height, stride, &snapshot, region,
            );
        }
        _ => op(pixels, width, height, stride),
    }
}

// ── GDI+ geometry / state / codec helpers (shared by the phase-2.7 arms) ───

/// GDI+ unit → pixels at the engine's fixed 96 dpi.  `UnitWorld`,
/// `UnitDisplay` and `UnitPixel` are 1:1; `UnitPoint`/`UnitInch`/
/// `UnitDocument`/`UnitMillimeter` scale by their physical size.
pub(crate) fn gdiplus_unit_to_pixels(value: f32, unit: u32) -> f32 {
    match unit {
        crate::user32::GDIPLUS_UNIT_POINT => value * 96.0 / 72.0,
        crate::user32::GDIPLUS_UNIT_INCH => value * 96.0,
        crate::user32::GDIPLUS_UNIT_DOCUMENT => value * 96.0 / 300.0,
        crate::user32::GDIPLUS_UNIT_MILLIMETER => value * 96.0 / 25.4,
        _ => value,
    }
}

/// GDI+ world matrix elements are `[m11, m12, m21, m22, dx, dy]` with
/// `x' = m11·x + m12·y + dx`, `y' = m21·x + m22·y + dy`.
pub(crate) fn gdiplus_matrix_identity() -> [f32; 6] {
    [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
}

/// True when the matrix leaves coordinates unchanged.
pub(crate) fn gdiplus_matrix_is_identity(m: &[f32; 6]) -> bool {
    (m[0] - 1.0).abs() < 1e-5
        && m[1].abs() < 1e-5
        && m[2].abs() < 1e-5
        && (m[3] - 1.0).abs() < 1e-5
        && m[4].abs() < 1e-5
        && m[5].abs() < 1e-5
}

pub(crate) fn gdiplus_matrix_apply(m: &[f32; 6], x: f32, y: f32) -> (f32, f32) {
    (m[0] * x + m[1] * y + m[4], m[2] * x + m[3] * y + m[5])
}

/// True when the transform is translate + axis-aligned scale only (no
/// rotation or shear), so rectangles stay rectangles.
pub(crate) fn gdiplus_matrix_axis_aligned(m: &[f32; 6]) -> bool {
    m[1].abs() < 1e-5 && m[2].abs() < 1e-5
}

/// Uniform scale factor of a transform (√|det|), used to scale pen widths.
pub(crate) fn gdiplus_matrix_scale(m: &[f32; 6]) -> f32 {
    let det = m[0] * m[3] - m[1] * m[2];
    det.abs().max(0.0).sqrt()
}

/// Bounding rect (device space) of a world-space rect mapped through `m`.
pub(crate) fn gdiplus_matrix_rect_bounds(
    m: &[f32; 6],
    x: f32,
    y: f32,
    w: f32,
    h: f32,
) -> (f32, f32, f32, f32) {
    let corners = [
        gdiplus_matrix_apply(m, x, y),
        gdiplus_matrix_apply(m, x + w, y),
        gdiplus_matrix_apply(m, x + w, y + h),
        gdiplus_matrix_apply(m, x, y + h),
    ];
    let min_x = corners.iter().map(|c| c.0).fold(f32::INFINITY, f32::min);
    let max_x = corners
        .iter()
        .map(|c| c.0)
        .fold(f32::NEG_INFINITY, f32::max);
    let min_y = corners.iter().map(|c| c.1).fold(f32::INFINITY, f32::min);
    let max_y = corners
        .iter()
        .map(|c| c.1)
        .fold(f32::NEG_INFINITY, f32::max);
    (min_x, min_y, max_x - min_x, max_y - min_y)
}

/// Matrix multiply `a × b` (column-vector convention).
pub(crate) fn gdiplus_matrix_mul(a: &[f32; 6], b: &[f32; 6]) -> [f32; 6] {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[0] * b[4] + a[1] * b[5] + a[4],
        a[2] * b[4] + a[3] * b[5] + a[5],
    ]
}

/// Compose `m` with an operation matrix `op`.  GDI+ order semantics:
/// `MatrixOrderPrepend` (0) applies the operation first (`op × m`),
/// `MatrixOrderAppend` (1) applies it last (`m × op`).
pub(crate) fn gdiplus_matrix_compose(m: &[f32; 6], op: &[f32; 6], order: u32) -> [f32; 6] {
    if order == 0 {
        gdiplus_matrix_mul(op, m)
    } else {
        gdiplus_matrix_mul(m, op)
    }
}

pub(crate) fn gdiplus_matrix_translation(dx: f32, dy: f32) -> [f32; 6] {
    [1.0, 0.0, 0.0, 1.0, dx, dy]
}

pub(crate) fn gdiplus_matrix_scaling(sx: f32, sy: f32) -> [f32; 6] {
    [sx, 0.0, 0.0, sy, 0.0, 0.0]
}

/// Rotation by `angle` degrees.  GDI+ positive angles rotate clockwise on
/// screen (the guest y axis points down), so the matrix is the transpose of
/// the standard math rotation.
pub(crate) fn gdiplus_matrix_rotation(angle: f32) -> [f32; 6] {
    let r = angle.to_radians();
    [r.cos(), -r.sin(), r.sin(), r.cos(), 0.0, 0.0]
}

/// Clip a segment against a convex clip polygon (device space) with the
/// half-plane parameter algorithm.  Returns the visible sub-segment.
pub(crate) fn gdiplus_clip_segment(
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
    clip: &[GdiplusPointF; 4],
) -> Option<((f32, f32), (f32, f32))> {
    let mut t0 = 0.0f32;
    let mut t1 = 1.0f32;
    let dx = x2 - x1;
    let dy = y2 - y1;
    let cross = |ex: f32, ey: f32, sx: f32, sy: f32, px: f32, py: f32| -> f32 {
        (ex - sx) * (py - sy) - (ey - sy) * (px - sx)
    };
    for i in 0..4 {
        let e0 = clip[i];
        let e1 = clip[(i + 1) % 4];
        let f0 = cross(e1.x, e1.y, e0.x, e0.y, x1, y1);
        let f1 = cross(e1.x, e1.y, e0.x, e0.y, x2, y2);
        if f0 < 0.0 && f1 < 0.0 {
            return None;
        }
        if f0 < 0.0 {
            // Entering the half-plane.
            let t = f0 / (f0 - f1);
            t0 = t0.max(t);
        } else if f1 < 0.0 {
            // Leaving the half-plane.
            let t = f0 / (f0 - f1);
            t1 = t1.min(t);
        }
    }
    if t1 < t0 {
        return None;
    }
    Some(((x1 + t0 * dx, y1 + t0 * dy), (x1 + t1 * dx, y1 + t1 * dy)))
}

/// Sutherland–Hodgman clipping of a subject polygon against a convex clip
/// polygon (device space).
pub(crate) fn gdiplus_clip_polygon(
    points: &[GdiplusPointF],
    clip: &[GdiplusPointF; 4],
) -> Vec<GdiplusPointF> {
    let mut subject: Vec<GdiplusPointF> = points.to_vec();
    if subject.len() < 3 {
        return subject;
    }
    let cross = |ex: f32, ey: f32, sx: f32, sy: f32, px: f32, py: f32| -> f32 {
        (ex - sx) * (py - sy) - (ey - sy) * (px - sx)
    };
    for i in 0..4 {
        if subject.is_empty() {
            break;
        }
        let e0 = clip[i];
        let e1 = clip[(i + 1) % 4];
        let mut output: Vec<GdiplusPointF> = Vec::new();
        let mut prev = subject[subject.len() - 1];
        for &curr in &subject {
            let prev_inside = cross(e1.x, e1.y, e0.x, e0.y, prev.x, prev.y) >= 0.0;
            let curr_inside = cross(e1.x, e1.y, e0.x, e0.y, curr.x, curr.y) >= 0.0;
            if curr_inside {
                if !prev_inside {
                    let (ix, iy) = gdiplus_line_intersection(
                        prev.x, prev.y, curr.x, curr.y, e0.x, e0.y, e1.x, e1.y,
                    );
                    output.push(GdiplusPointF { x: ix, y: iy });
                }
                output.push(curr);
            } else if prev_inside {
                let (ix, iy) = gdiplus_line_intersection(
                    prev.x, prev.y, curr.x, curr.y, e0.x, e0.y, e1.x, e1.y,
                );
                output.push(GdiplusPointF { x: ix, y: iy });
            }
            prev = curr;
        }
        subject = output;
    }
    subject
}

pub(crate) fn gdiplus_line_intersection(
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
    x3: f32,
    y3: f32,
    x4: f32,
    y4: f32,
) -> (f32, f32) {
    let denom = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4);
    if denom.abs() < 1e-9 {
        return ((x1 + x2) / 2.0, (y1 + y2) / 2.0);
    }
    let t = ((x1 - x3) * (y3 - y4) - (y1 - y3) * (x3 - x4)) / denom;
    (x1 + t * (x2 - x1), y1 + t * (y2 - y1))
}

/// Device-space clip polygon of a graphics object: the world-space clip rect
/// mapped through the world transform.
pub(crate) fn gdiplus_device_clip_quad(
    world: &[f32; 6],
    clip: Option<(f32, f32, f32, f32)>,
) -> Option<[GdiplusPointF; 4]> {
    let (cx, cy, cw, ch) = clip?;
    let corners = [(cx, cy), (cx + cw, cy), (cx + cw, cy + ch), (cx, cy + ch)];
    let mut quad = [GdiplusPointF { x: 0.0, y: 0.0 }; 4];
    for (i, &(x, y)) in corners.iter().enumerate() {
        let (x, y) = gdiplus_matrix_apply(world, x, y);
        quad[i] = GdiplusPointF { x, y };
    }
    Some(quad)
}

/// Dash pattern (on/off lengths in pen-width units) for the GDI+ dash styles.
pub(crate) fn gdiplus_dash_pattern(dash: u32) -> &'static [f32] {
    match dash {
        crate::user32::GDIPLUS_DASH_STYLE_DASH => &[3.0, 1.0],
        crate::user32::GDIPLUS_DASH_STYLE_DOT => &[1.0, 1.0],
        crate::user32::GDIPLUS_DASH_STYLE_DASH_DOT => &[3.0, 1.0, 1.0, 1.0],
        crate::user32::GDIPLUS_DASH_STYLE_DASH_DOT_DOT => &[3.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        _ => &[1.0],
    }
}

/// Split a polyline into dash-on spans, following the cumulative distance
/// along the line so the pattern continues across vertices.  When `closed`
/// the last point joins back to the first before dashing.
pub(crate) fn gdiplus_dash_spans(
    points: &[GdiplusPointF],
    closed: bool,
    dash: u32,
    width: f32,
) -> Vec<Vec<GdiplusPointF>> {
    if points.len() < 2 {
        return Vec::new();
    }
    let pattern = gdiplus_dash_pattern(dash);
    let unit = width.max(0.25);
    let mut working: Vec<GdiplusPointF> = points.to_vec();
    if closed && working.len() >= 2 {
        let first = working[0];
        working.push(first);
    }
    // Cumulative segment lengths.
    let mut seg_len: Vec<f32> = Vec::with_capacity(working.len());
    let mut total = 0.0f32;
    for pair in working.windows(2) {
        let d = ((pair[1].x - pair[0].x).powi(2) + (pair[1].y - pair[0].y).powi(2)).sqrt();
        seg_len.push(d);
        total += d;
    }
    if total <= 1e-6 {
        return Vec::new();
    }
    let pat_scaled: Vec<f32> = pattern.iter().map(|p| p * unit).collect();
    let period: f32 = pat_scaled.iter().sum();
    let mut spans: Vec<Vec<GdiplusPointF>> = Vec::new();
    // Walk the polyline in distance space, emitting points inside "on" runs.
    let mut cursor = 0.0f32; // distance into the current pattern cycle
    let mut current_span: Option<Vec<GdiplusPointF>> = None;
    for i in 0..working.len() - 1 {
        let (p0, p1) = (working[i], working[i + 1]);
        let mut d = seg_len[i];
        let mut from = 0.0f32;
        while d > 1e-6 {
            let on = gdiplus_pattern_on(cursor, &pat_scaled);
            let into_run = gdiplus_run_end(cursor, &pat_scaled) - cursor;
            if into_run < 1e-6 {
                // Advance to the next pattern transition.
                let step = period - cursor;
                let consume = step.min(d);
                from += consume;
                d -= consume;
                cursor = (cursor + consume) % period;
                continue;
            }
            let consume = into_run.min(d);
            let t0 = from / seg_len[i];
            let t1 = (from + consume) / seg_len[i];
            let seg_p0 = GdiplusPointF {
                x: p0.x + (p1.x - p0.x) * t0,
                y: p0.y + (p1.y - p0.y) * t0,
            };
            let seg_p1 = GdiplusPointF {
                x: p0.x + (p1.x - p0.x) * t1,
                y: p0.y + (p1.y - p0.y) * t1,
            };
            if on {
                gdiplus_span_push(&mut current_span, seg_p0);
                gdiplus_span_push(&mut current_span, seg_p1);
            } else if let Some(span) = current_span.take() {
                if span.len() >= 2 {
                    spans.push(span);
                }
            }
            from += consume;
            d -= consume;
            cursor = (cursor + consume) % period;
        }
        // Snap to the true vertex (float drift).
        if let Some(span) = current_span.as_mut() {
            if let Some(last) = span.last_mut() {
                if (last.x - p1.x).abs() > 1e-3 || (last.y - p1.y).abs() > 1e-3 {
                    *last = p1;
                }
            }
        }
    }
    if let Some(span) = current_span.take() {
        if span.len() >= 2 {
            spans.push(span);
        }
    }
    spans
}

pub(crate) fn gdiplus_span_push(span: &mut Option<Vec<GdiplusPointF>>, pt: GdiplusPointF) {
    if span.is_none() {
        *span = Some(Vec::new());
    }
    if let Some(s) = span.as_mut() {
        let dup = s
            .last()
            .map(|last| last.x == pt.x && last.y == pt.y)
            .unwrap_or(false);
        if !dup {
            s.push(pt);
        }
    }
}

pub(crate) fn gdiplus_pattern_on(cursor: f32, pattern: &[f32]) -> bool {
    let mut acc = 0.0f32;
    for (i, &len) in pattern.iter().enumerate() {
        acc += len;
        if cursor < acc {
            return i % 2 == 0;
        }
    }
    true
}

pub(crate) fn gdiplus_run_end(cursor: f32, pattern: &[f32]) -> f32 {
    let mut acc = 0.0f32;
    for &len in pattern.iter() {
        acc += len;
        if cursor < acc {
            return acc;
        }
    }
    acc
}

/// The lattice-text scale: an em square maps to the 8-row glyph grid
/// (`s = max(1, round(em_px / 8))`), giving 5×7 dot glyphs at pitch `s`.
pub(crate) fn gdiplus_text_scale(em_px: f32) -> i32 {
    if em_px.is_nan() || em_px.is_infinite() || em_px <= 0.0 {
        1
    } else {
        (em_px / 8.0).round().max(1.0) as i32
    }
}

/// Measure lattice text: per line `chars·6s − s` wide (the trailing advance
/// is not part of the text), `lines·8s` tall.
pub(crate) fn gdiplus_measure_lattice(text: &str, em_px: f32) -> (f32, f32) {
    let s = gdiplus_text_scale(em_px).max(1) as f32;
    let mut max_width = 0.0f32;
    let mut line_chars = 0u32;
    let mut line_count = 1u32;
    for ch in text.chars() {
        if ch == '\n' {
            let w = (line_chars as f32 * 6.0 * s - s).max(0.0);
            max_width = max_width.max(w);
            line_chars = 0;
            line_count += 1;
        } else {
            line_chars += 1;
        }
    }
    let w = (line_chars as f32 * 6.0 * s - s).max(0.0);
    max_width = max_width.max(w);
    (max_width, line_count as f32 * 8.0 * s)
}

/// Render text with the 5×7 lattice glyphs at the given scale.  Glyph dots
/// are blended through `gdiplus_render::put_pixel`, honouring the
/// compositing mode.  When `clip` is set (layout-rect clipping for the
/// default StringFormat), dots outside it are skipped.
#[allow(clippy::too_many_arguments)]
pub(crate) fn gdiplus_draw_lattice_text(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    text: &str,
    x: f32,
    y: f32,
    em_px: f32,
    color: u32,
    compositing_mode: u32,
    clip: Option<(f32, f32, f32, f32)>,
) {
    let s = gdiplus_text_scale(em_px).max(1);
    let ox = x.round() as i32;
    let oy = y.round() as i32;
    let mut cursor_x = ox;
    let mut cursor_y = oy;
    let inside = |px: i32, py: i32| -> bool {
        match clip {
            Some((cx, cy, cw, ch)) => {
                let fx = px as f32;
                let fy = py as f32;
                fx >= cx && fy >= cy && fx < cx + cw && fy < cy + ch
            }
            None => true,
        }
    };
    for ch in text.chars() {
        if ch == '\n' {
            cursor_x = ox;
            cursor_y += 8 * s;
            continue;
        }
        let Some(rows) = glyph_5x7(ch) else {
            cursor_x += 6 * s;
            continue;
        };
        for (ri, row) in rows.iter().enumerate() {
            for col in 0..5 {
                if row & (1 << (4 - col)) == 0 {
                    continue;
                }
                let gx = cursor_x + col as i32 * s;
                let gy = cursor_y + ri as i32 * s;
                for dy in 0..s {
                    for dx in 0..s {
                        if inside(gx + dx, gy + dy) {
                            crate::gdiplus_render::put_pixel(
                                pixels,
                                width,
                                height,
                                stride,
                                gx + dx,
                                gy + dy,
                                color,
                                compositing_mode,
                            );
                        }
                    }
                }
            }
        }
        cursor_x += 6 * s;
    }
}

/// Canonicalise guest Scan0 bytes into the engine's top-down 32-bpp ARGB
/// buffer.  Handles negative strides (bottom-up sources are flipped),
/// 24-bpp BGR expansion and 32-bpp PARGB un-premultiplication.  Unsupported
/// source formats return `None`.
pub(crate) fn gdiplus_scan0_to_canonical(
    width: u32,
    height: u32,
    stride: i32,
    format: u32,
    source: &[u8],
) -> Option<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    let stride_abs = stride.unsigned_abs() as usize;
    if w == 0 || h == 0 {
        return None;
    }
    let bpp = match format {
        crate::user32::GDIPLUS_PIXEL_FORMAT_24BPP_RGB => 3,
        crate::user32::GDIPLUS_PIXEL_FORMAT_32BPP_ARGB
        | crate::user32::GDIPLUS_PIXEL_FORMAT_32BPP_PARGB => 4,
        _ => return None,
    };
    let bytes = bpp * w;
    if stride_abs < bytes {
        return None;
    }
    if source.len() < h * stride_abs {
        return None;
    }
    let mut out = vec![0u8; w * h * 4];
    let premul = format == crate::user32::GDIPLUS_PIXEL_FORMAT_32BPP_PARGB;
    for y in 0..h {
        // Source row: bottom-up when the stride is negative.
        let src_y = if stride < 0 { h - 1 - y } else { y };
        let row_off = src_y * stride_abs;
        for x in 0..w {
            let s = row_off + x * bpp;
            let d = (y * w + x) * 4;
            if s + bpp > source.len() {
                continue;
            }
            let (b, g, r, a) = if bpp == 3 {
                (source[s], source[s + 1], source[s + 2], 0xff)
            } else {
                (source[s], source[s + 1], source[s + 2], source[s + 3])
            };
            if premul && a != 0 && a != 255 {
                let scale = a as u32;
                out[d] = (b as u32 * 255 / scale) as u8;
                out[d + 1] = (g as u32 * 255 / scale) as u8;
                out[d + 2] = (r as u32 * 255 / scale) as u8;
            } else {
                out[d] = b;
                out[d + 1] = g;
                out[d + 2] = r;
            }
            out[d + 3] = a;
        }
    }
    Some(out)
}

/// Read the ARGB colour of a canonical 32-bpp ARGB pixel.
#[allow(dead_code)]
pub(crate) fn gdiplus_argb_at(
    pixels: &[u8],
    width: u32,
    stride: i32,
    x: u32,
    y: u32,
) -> Option<u32> {
    if x >= width {
        return None;
    }
    let idx = (y as i64 * stride as i64 + x as i64 * 4) as usize;
    if idx + 3 >= pixels.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]))
}

/// BMP decode (BITMAPFILEHEADER + BITMAPINFOHEADER, BI_RGB).  Returns
/// `(width, height, top-down 32-bpp ARGB)`.
pub(crate) fn gdiplus_decode_bmp(data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    if data.len() < 14 || &data[0..2] != b"BM" {
        return None;
    }
    let pixel_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    if data.len() < 14 + 40 {
        return None;
    }
    let header = &data[14..];
    let bi_size = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if bi_size < 40 {
        return None; // OS/2 headers are not decoded by the engine.
    }
    let width = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let height_raw = i32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let planes = u16::from_le_bytes([header[12], header[13]]);
    let bpp = u16::from_le_bytes([header[14], header[15]]);
    let compression = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    if width <= 0 || height_raw == 0 || planes != 1 {
        return None;
    }
    if compression != 0 {
        return None; // BI_RLE / BI_BITFIELDS not decoded.
    }
    let (height, bottom_up) = if height_raw > 0 {
        (height_raw as u32, true)
    } else {
        (height_raw.unsigned_abs(), false)
    };
    let palette_colors = if bpp <= 8 {
        let used = u32::from_le_bytes([header[32], header[33], header[34], header[35]]);
        if used != 0 {
            used.min(1 << bpp)
        } else {
            1 << bpp
        }
    } else {
        0
    } as usize;
    let palette_off = 14 + bi_size as usize;
    let row_size = (width as u32 * bpp as u32).div_ceil(32) * 4;
    let w = width as usize;
    let h = height as usize;
    if pixel_offset + row_size as usize * h > data.len() {
        return None;
    }
    let mut out = vec![0u8; w * h * 4];
    let bytes_per_px = bpp / 8;
    for y in 0..h {
        let src_y = if bottom_up { h - 1 - y } else { y };
        let row = pixel_offset + src_y * row_size as usize;
        for x in 0..w {
            let d = (y * w + x) * 4;
            match bpp {
                32 => {
                    let s = row + x * 4;
                    out[d] = data[s];
                    out[d + 1] = data[s + 1];
                    out[d + 2] = data[s + 2];
                    out[d + 3] = data[s + 3];
                }
                24 => {
                    let s = row + x * 3;
                    out[d] = data[s];
                    out[d + 1] = data[s + 1];
                    out[d + 2] = data[s + 2];
                    out[d + 3] = 0xff;
                }
                16 => {
                    let s = row + x * 2;
                    let v = u16::from_le_bytes([data[s], data[s + 1]]);
                    let r = ((v >> 10) & 0x1f) as u32 * 255 / 31;
                    let g = ((v >> 5) & 0x1f) as u32 * 255 / 31;
                    let b = (v & 0x1f) as u32 * 255 / 31;
                    out[d] = b as u8;
                    out[d + 1] = g as u8;
                    out[d + 2] = r as u8;
                    out[d + 3] = 0xff;
                }
                8 | 4 | 1 => {
                    let index = if bpp == 8 {
                        data[row + x] as usize
                    } else if bpp == 4 {
                        let byte = data[row + x / 2];
                        if x % 2 == 0 {
                            (byte >> 4) as usize
                        } else {
                            (byte & 0x0f) as usize
                        }
                    } else {
                        let byte = data[row + x / 8];
                        ((byte >> (7 - (x % 8))) & 1) as usize
                    };
                    if let Some(entry) = palette_off
                        .checked_add(index * 4)
                        .and_then(|pp| data.get(pp..pp + 4))
                    {
                        out[d] = entry[0];
                        out[d + 1] = entry[1];
                        out[d + 2] = entry[2];
                        out[d + 3] = 0xff;
                    }
                }
                _ => return None,
            }
        }
    }
    let _ = palette_colors;
    let _ = bytes_per_px;
    Some((width as u32, height, out))
}

/// BMP encode of a top-down 32-bpp ARGB buffer (32-bpp BI_RGB file).
pub(crate) fn gdiplus_encode_bmp(width: u32, height: u32, argb: &[u8]) -> Option<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    if w == 0 || h == 0 || argb.len() < w * h * 4 {
        return None;
    }
    let row_size = w * 4;
    let pixel_bytes = row_size * h;
    let file_size = 14 + 40 + pixel_bytes;
    let mut out = Vec::with_capacity(file_size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(file_size as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(width as i32).to_le_bytes());
    out.extend_from_slice(&(height as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // Bottom-up rows: row 0 of the file is the bottom image row.
    for y in (0..h).rev() {
        let row = y * row_size;
        out.extend_from_slice(&argb[row..row + row_size]);
    }
    Some(out)
}

/// PNG decode (any colour type, expanded to RGBA8).  Returns
/// `(width, height, top-down 32-bpp ARGB)`.
pub(crate) fn gdiplus_decode_png(data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let decoder = png::Decoder::new(std::io::Cursor::new(data));
    let mut reader = decoder.read_info().ok()?;
    let mut out = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut out).ok()?;
    let width = info.width;
    let height = info.height;
    let pixels = &out[..info.buffer_size()];
    let channels = match info.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::Rgb => 3,
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        _ => return None,
    };
    let mut argb = vec![0u8; width as usize * height as usize * 4];
    for (i, chunk) in pixels.chunks(channels).enumerate() {
        let (r, g, b, a) = match channels {
            4 => (chunk[0], chunk[1], chunk[2], chunk[3]),
            3 => (chunk[0], chunk[1], chunk[2], 255),
            2 => (chunk[0], chunk[0], chunk[0], chunk[1]),
            _ => (chunk[0], chunk[0], chunk[0], 255),
        };
        let d = i * 4;
        argb[d] = b;
        argb[d + 1] = g;
        argb[d + 2] = r;
        argb[d + 3] = a;
    }
    Some((width, height, argb))
}

/// PNG encode of a top-down 32-bpp ARGB buffer (RGBA8 PNG).
pub(crate) fn gdiplus_encode_png(width: u32, height: u32, argb: &[u8]) -> Option<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    if w == 0 || h == 0 || argb.len() < w * h * 4 {
        return None;
    }
    let mut rgba = Vec::with_capacity(w * h * 4);
    for px in argb.chunks(4) {
        rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
    }
    let mut png_bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut png_bytes, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(&rgba).ok()?;
    drop(writer);
    Some(png_bytes)
}

/// Decode an image payload by magic bytes.  Returns
/// `(raw_kind, width, height, top-down ARGB)`; `raw_kind` is 1 for BMP and
/// 2 for PNG.
pub(crate) fn gdiplus_decode_image(data: &[u8]) -> Option<(u32, u32, u32, Vec<u8>)> {
    if data.len() >= 8 && data[0] == 0x89 && &data[1..4] == b"PNG" {
        gdiplus_decode_png(data).map(|(w, h, px)| (2, w, h, px))
    } else if data.starts_with(b"BM") {
        gdiplus_decode_bmp(data).map(|(w, h, px)| (1, w, h, px))
    } else {
        None
    }
}

/// Raw-format GUID of a bitmap (`GdipGetImageRawFormat` output), keyed by
/// the bitmap's `raw_kind`.
pub(crate) fn gdiplus_raw_format_guid(kind: u32) -> [u8; 16] {
    match kind {
        1 => gdiplus_guid_bytes("b96b3cab-0728-11d3-9d7b-0000f81ef32e"), // ImageFormatBMP
        2 => gdiplus_guid_bytes("b96b3caf-0728-11d3-9d7b-0000f81ef32e"), // ImageFormatPNG
        _ => gdiplus_guid_bytes("b96b3caa-0728-11d3-9d7b-0000f81ef32e"), // ImageFormatMemoryBMP
    }
}

/// Parse a GUID string into its 16 little-endian bytes.
pub(crate) fn gdiplus_guid_bytes(guid: &str) -> [u8; 16] {
    let clean: String = guid
        .chars()
        .filter(|c| *c != '-' && *c != '{' && *c != '}')
        .collect();
    let mut out = [0u8; 16];
    let mut hex = [0u8; 32];
    for (i, ch) in clean.chars().enumerate() {
        if i < 32 {
            hex[i] = ch as u8;
        }
    }
    let byte = |h: u8, l: u8| -> u8 {
        let hd = (h as char).to_digit(16).unwrap_or(0) as u8;
        let ld = (l as char).to_digit(16).unwrap_or(0) as u8;
        hd << 4 | ld
    };
    for i in 0..16 {
        out[i] = byte(hex[i * 2], hex[i * 2 + 1]);
    }
    // GUID memory layout: u32/u16 fields are little-endian in the byte
    // stream, the final 8 bytes stay in order.
    out.swap(0, 3);
    out.swap(1, 2);
    out.swap(4, 5);
    out.swap(6, 7);
    out
}

/// Encoder-CLSID → format family for `GdipSaveImageToFile` / `ToStream`:
/// 0 = unknown, 1 = BMP, 2 = PNG.
pub(crate) fn gdiplus_encoder_kind(clsid: Option<[u8; 16]>) -> u32 {
    let Some(clsid) = clsid else {
        return 1; // NULL CLSID selects the BMP encoder, like GDI+.
    };
    if clsid == gdiplus_guid_bytes("557cf406-1a04-11d3-9a73-0000f81ef32e") {
        2 // PNG encoder
    } else if clsid == gdiplus_guid_bytes("557cf400-1a04-11d3-9a73-0000f81ef32e") {
        1 // BMP encoder
    } else {
        0
    }
}

/// Convert a bitmap's canonical ARGB pixels to packed 24-bpp BGR rows
/// (bottom-up, `height` rows of `stride` bytes), used by the HBITMAP
/// interop path.
pub(crate) fn gdiplus_argb_to_bgr24_bottom_up(
    width: u32,
    height: u32,
    argb: &[u8],
) -> Option<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    if w == 0 || h == 0 || argb.len() < w * h * 4 {
        return None;
    }
    let row_size = w * 3;
    let padded = row_size.div_ceil(4) * 4;
    let mut out = vec![0u8; padded * h];
    for y in 0..h {
        let dst_y = h - 1 - y; // bottom-up
        let src = y * w * 4;
        for x in 0..w {
            let d = dst_y * padded + x * 3;
            out[d] = argb[src + x * 4];
            out[d + 1] = argb[src + x * 4 + 1];
            out[d + 2] = argb[src + x * 4 + 2];
        }
    }
    Some(out)
}

/// The byte-width of a `MemoryBitmap` pixel.  GDI bitmaps are registered
/// with either a byte bpp (1..=4) or a bit bpp (8/16/24/32) depending on
/// the creation path; normalise both.
pub(crate) fn gdiplus_memory_bpp_bytes(bitmap: &MemoryBitmap) -> usize {
    if bitmap.bpp > 4 {
        (bitmap.bpp / 8).max(1)
    } else {
        bitmap.bpp.max(1)
    }
}

/// Convert a GDI `MemoryBitmap`'s native pixels (bottom-up, 1/2/3/4 bpp)
/// into the engine's top-down 32-bpp ARGB layout, mirroring the mapping the
/// GDI readback paths use.
pub(crate) fn gdiplus_bitmap_to_argb(bitmap: &MemoryBitmap) -> Option<Vec<u8>> {
    let w = bitmap.width;
    let h = bitmap.height;
    if w == 0 || h == 0 {
        return None;
    }
    let bpp = gdiplus_memory_bpp_bytes(bitmap);
    let mut out = vec![0u8; w * h * 4];
    for y in 0..h {
        let s_row = h - 1 - y; // bottom-up: memory row 0 is the bottom
        for x in 0..w {
            let s_idx = (s_row * w + x) * bpp;
            if s_idx + bpp > bitmap.bytes.len() {
                continue;
            }
            let px = &bitmap.bytes[s_idx..s_idx + bpp];
            let d_idx = (y * w + x) * 4;
            match bpp {
                1 => {
                    let v = px[0];
                    out[d_idx] = v;
                    out[d_idx + 1] = v;
                    out[d_idx + 2] = v;
                    out[d_idx + 3] = 0xff;
                }
                2 => {
                    let v = u16::from_le_bytes([px[0], px[1]]);
                    let r = ((v >> 10) & 0x1f) as u8 * 255 / 31;
                    let g = ((v >> 5) & 0x1f) as u8 * 255 / 31;
                    let b = (v & 0x1f) as u8 * 255 / 31;
                    out[d_idx] = b;
                    out[d_idx + 1] = g;
                    out[d_idx + 2] = r;
                    out[d_idx + 3] = 0xff;
                }
                3 => {
                    out[d_idx] = px[0];
                    out[d_idx + 1] = px[1];
                    out[d_idx + 2] = px[2];
                    out[d_idx + 3] = 0xff;
                }
                _ => {
                    out[d_idx] = px[0];
                    out[d_idx + 1] = px[1];
                    out[d_idx + 2] = px[2];
                    out[d_idx + 3] = if px.len() >= 4 { px[3] } else { 0xff };
                }
            }
        }
    }
    Some(out)
}

/// Convert engine ARGB (top-down) pixels back into a GDI `MemoryBitmap`'s
/// native bottom-up layout.  32-bpp content keeps its BGRA byte order;
/// other depths are truncated to the target bpp.
pub(crate) fn gdiplus_argb_to_bitmap(bitmap: &MemoryBitmap, argb: &[u8]) -> Option<Vec<u8>> {
    let w = bitmap.width;
    let h = bitmap.height;
    if w == 0 || h == 0 || argb.len() < w * h * 4 {
        return None;
    }
    let bpp = gdiplus_memory_bpp_bytes(bitmap);
    let mut out = vec![0u8; w * h * bpp];
    for y in 0..h {
        let d_row = h - 1 - y;
        for x in 0..w {
            let s_idx = (y * w + x) * 4;
            let d_idx = (d_row * w + x) * bpp;
            if d_idx + bpp > out.len() {
                continue;
            }
            let b = argb[s_idx];
            let g = argb[s_idx + 1];
            let r = argb[s_idx + 2];
            let a = argb[s_idx + 3];
            match bpp {
                1 => out[d_idx] = (r.max(g).max(b) + a) / 2,
                2 => {
                    // 16bpp RGB555 packing (matches the read mapping).
                    let v = ((r as u16 >> 3) << 10) | ((g as u16 >> 3) << 5) | (b as u16 >> 3);
                    out[d_idx] = v as u8;
                    out[d_idx + 1] = (v >> 8) as u8;
                }
                3 => {
                    out[d_idx] = b;
                    out[d_idx + 1] = g;
                    out[d_idx + 2] = r;
                }
                _ => {
                    out[d_idx] = b;
                    out[d_idx + 1] = g;
                    out[d_idx + 2] = r;
                    out[d_idx + 3] = a;
                }
            }
        }
    }
    Some(out)
}

/// Stroke device-space polylines with caps/joins handled by the rasterizer:
/// flat caps/joins draw the raw chain, square caps extend the end segments
/// by half the pen width, round caps/joins stamp discs.  When `already_split`
/// is set (clip boundaries cut the chain) no cap/join decoration is applied.
pub(crate) fn gdiplus_render_stroke_chain(
    pixels: &mut [u8],
    width: u32,
    height: u32,
    stride: i32,
    points: &[GdiplusPointF],
    style: &GdiplusStrokeStyle,
    already_split: bool,
    dash_shrink: bool,
) {
    if points.len() < 2 {
        return;
    }
    let width_px = style.width_px.max(1.0);
    let cm = style.cm;
    let sm = style.sm;
    // Extend for square caps when the chain is not split.
    let mut chain: Vec<GdiplusPointF> = points.to_vec();
    if !already_split && chain.len() >= 2 {
        if style.start_cap == crate::user32::GDIPLUS_LINE_CAP_SQUARE {
            let (dx, dy) = (chain[1].x - chain[0].x, chain[1].y - chain[0].y);
            let len = (dx * dx + dy * dy).sqrt().max(1e-6);
            let extend = width_px * 0.5 / len;
            chain[0].x -= dx * extend;
            chain[0].y -= dy * extend;
        }
        if style.end_cap == crate::user32::GDIPLUS_LINE_CAP_SQUARE {
            let n = chain.len();
            let (dx, dy) = (
                chain[n - 1].x - chain[n - 2].x,
                chain[n - 1].y - chain[n - 2].y,
            );
            let len = (dx * dx + dy * dy).sqrt().max(1e-6);
            let extend = width_px * 0.5 / len;
            chain[n - 1].x += dx * extend;
            chain[n - 1].y += dy * extend;
        }
    }
    for pair in chain.windows(2) {
        let (mut x0, mut y0, mut x1, mut y1) = (pair[0].x, pair[0].y, pair[1].x, pair[1].y);
        if dash_shrink {
            // The rasterizer's square pen stamps extend half a width past
            // segment endpoints, so inset dash spans by half a width at each
            // end (a dash shorter than the pen becomes a centred dot).
            let (dx, dy) = (x1 - x0, y1 - y0);
            let len = (dx * dx + dy * dy).sqrt();
            if len > 1e-6 {
                let inset = (width_px * 0.5).min(len * 0.5);
                if len - 2.0 * inset < 0.5 {
                    let cxm = (x0 + x1) * 0.5;
                    let cym = (y0 + y1) * 0.5;
                    let reach = 0.25;
                    x0 = cxm - reach;
                    x1 = cxm + reach;
                    y0 = cym - reach * dy / len.max(1e-6);
                    y1 = cym + reach * dy / len.max(1e-6);
                } else {
                    x0 += dx / len * inset;
                    y0 += dy / len * inset;
                    x1 -= dx / len * inset;
                    y1 -= dy / len * inset;
                }
            }
        }
        crate::gdiplus_render::draw_line(
            pixels,
            width,
            height,
            stride,
            x0,
            y0,
            x1,
            y1,
            style.color,
            width_px,
            cm,
            sm,
        );
    }
    if already_split {
        return;
    }
    let mut disc = |x: f32, y: f32| {
        let r = width_px * 0.5;
        crate::gdiplus_render::fill_ellipse(
            pixels,
            width,
            height,
            stride,
            x - r,
            y - r,
            width_px,
            width_px,
            style.color,
            cm,
        );
    };
    if style.join == crate::user32::GDIPLUS_LINE_JOIN_ROUND {
        // Round joins stamp discs at every interior vertex of the chain.
        for p in &chain[1..chain.len().saturating_sub(1)] {
            disc(p.x, p.y);
        }
    }
    if style.start_cap == crate::user32::GDIPLUS_LINE_CAP_ROUND {
        disc(chain[0].x, chain[0].y);
    }
    if style.end_cap == crate::user32::GDIPLUS_LINE_CAP_ROUND && chain.len() >= 2 {
        let last = chain.len() - 1;
        disc(chain[last].x, chain[last].y);
    }
}

pub(crate) fn write_i16(memory: &mut MemoryImage, address: u64, value: i16) {
    memory.map_bytes(address, &value.to_le_bytes());
}
