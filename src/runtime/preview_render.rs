//! Live window preview rendering helpers.

use super::*;

pub(crate) const PREVIEW_CLIENT_ORIGIN_X: usize = 12;
pub(crate) const PREVIEW_CLIENT_ORIGIN_Y: usize = 36;

/// Compose the live frame from REAL guest GDI window surfaces only.
///
/// Synthetic chrome/theme/text composition is deliberately NOT used here:
/// the published frame must contain real guest pixels.  When no real window
/// surface exists (nothing has been blitted into a guest window yet), this
/// returns `None` and nothing is published.
pub(crate) fn render_live_window_preview(
    previews: &[WindowPreview],
    window_surfaces: &BTreeMap<u32, WindowSurface>,
) -> Option<LiveFrame> {
    let layout = build_preview_layout(previews)?;

    // Real frames only: zero REAL guest surfaces means no frame to publish.
    // `real_pixels` provenance is set exclusively by guest-driven blits, so
    // a surface that only ever received host-invented chrome does not count.
    let has_real_surface = window_surfaces
        .get(&layout.root.hwnd)
        .is_some_and(|surface| surface.real_pixels)
        || layout.children.iter().any(|(child, _)| {
            window_surfaces
                .get(&child.hwnd)
                .is_some_and(|s| s.real_pixels)
        });
    if !has_real_surface {
        return None;
    }

    let mut bytes = vec![0_u8; layout.width.checked_mul(layout.height)?.checked_mul(4)?];

    // Blit the root window's GDI-rendered surface (real guest pixels only).
    if let Some(surface) = window_surfaces
        .get(&layout.root.hwnd)
        .filter(|s| s.real_pixels)
    {
        blit_window_surface(
            &mut bytes,
            layout.width,
            PREVIEW_CLIENT_ORIGIN_X,
            PREVIEW_CLIENT_ORIGIN_Y,
            surface,
        );
    }

    // Blit each child window surface at its real position (guest-driven
    // blits landed here via BitBlt/StretchBlt on the child's DC).
    for (child, rect) in &layout.children {
        if let Some(surface) = window_surfaces.get(&child.hwnd).filter(|s| s.real_pixels) {
            blit_window_surface(&mut bytes, layout.width, rect.x, rect.y, surface);
        }
    }

    Some(LiveFrame {
        width: layout.width as u32,
        height: layout.height as u32,
        format: DxgiFormat::B8G8R8A8Unorm,
        bytes,
        displayed_frame_index: 0,
    })
}

pub(crate) fn select_preview_root(previews: &[WindowPreview]) -> Option<&WindowPreview> {
    let score = |window: &WindowPreview| {
        let child_count = previews
            .iter()
            .filter(|candidate| candidate.parent == Some(window.hwnd))
            .count();
        let visible_children = previews
            .iter()
            .filter(|candidate| candidate.parent == Some(window.hwnd) && candidate.visible)
            .count();
        (
            usize::from(window.visible || visible_children > 0),
            visible_children,
            child_count,
            window.width as usize * window.height as usize,
            window.hwnd,
        )
    };

    previews
        .iter()
        .filter(|window| window.parent.is_none())
        .max_by_key(|window| score(window))
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PreviewRect {
    pub(crate) x: usize,
    pub(crate) y: usize,
    pub(crate) width: usize,
    pub(crate) height: usize,
}

impl PreviewRect {
    pub(crate) fn contains(&self, x: usize, y: usize) -> bool {
        x >= self.x
            && y >= self.y
            && x < self.x.saturating_add(self.width)
            && y < self.y.saturating_add(self.height)
    }
}

#[derive(Debug)]
pub(crate) struct PreviewLayout<'a> {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) root: &'a WindowPreview,
    pub(crate) children: Vec<(&'a WindowPreview, PreviewRect)>,
}

pub(crate) fn build_preview_layout<'a>(previews: &'a [WindowPreview]) -> Option<PreviewLayout<'a>> {
    let root = select_preview_root(previews)?;
    let width = root.width.clamp(320, 960) as usize;
    let height = root.height.max(160).clamp(160, 720) as usize;
    let client_width = width.saturating_sub(32);
    let mut cursor_y = 48usize;
    let visible_children = previews
        .iter()
        .filter(|window| window.parent == Some(root.hwnd) && window.visible)
        .collect::<Vec<_>>();
    let use_guest_positions = visible_children
        .iter()
        .any(|window| window.x != 0 || window.y != 0);
    let mut children = Vec::with_capacity(visible_children.len());

    for child in visible_children {
        let (child_width, child_height, x, y) = if use_guest_positions {
            (
                child.width.max(1) as usize,
                child.height.max(1) as usize,
                PREVIEW_CLIENT_ORIGIN_X.saturating_add(child.x.max(0) as usize),
                PREVIEW_CLIENT_ORIGIN_Y.saturating_add(child.y.max(0) as usize),
            )
        } else {
            let child_width = (child.width as usize).clamp(72, client_width.max(72));
            let child_height = (child.height as usize).clamp(14, 56);
            let x = 16usize + client_width.saturating_sub(child_width) / 2;
            let y = cursor_y;
            cursor_y = cursor_y.saturating_add(child_height + 12);
            (child_width, child_height, x, y)
        };
        children.push((
            child,
            PreviewRect {
                x,
                y,
                width: child_width,
                height: child_height,
            },
        ));
    }

    Some(PreviewLayout {
        width,
        height,
        root,
        children,
    })
}

pub(crate) fn live_preview_hit_test(previews: &[WindowPreview], x: i32, y: i32) -> Option<u32> {
    let layout = build_preview_layout(previews)?;
    let x = usize::try_from(x).ok()?;
    let y = usize::try_from(y).ok()?;
    if x >= layout.width || y >= layout.height {
        return None;
    }
    for (child, rect) in layout.children.iter().rev() {
        if child.enabled && rect.contains(x, y) {
            return Some(child.hwnd);
        }
    }
    Some(layout.root.hwnd)
}

pub(crate) fn preview_rect_from_bounds(
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> PreviewRect {
    PreviewRect {
        x: left.max(0) as usize,
        y: top.max(0) as usize,
        width: right.saturating_sub(left).max(0) as usize,
        height: bottom.saturating_sub(top).max(0) as usize,
    }
}

pub(crate) fn sys_color_value(index: i32) -> u32 {
    // Windows COLOR_* system color indices → COLORREF (0x00BBGGRR)
    match index {
        0 => 0x00_80_80_80,  // COLOR_SCROLLBAR
        1 => 0x00_00_80_00,  // COLOR_BACKGROUND (desktop)
        2 => 0x00_FF_00_00,  // COLOR_ACTIVECAPTION
        3 => 0x00_FF_FF_00,  // COLOR_INACTIVECAPTION
        4 => 0x00_C0_C0_C0,  // COLOR_MENU
        5 => 0x00_FF_FF_FF,  // COLOR_WINDOW
        6 => 0x00_00_00_00,  // COLOR_WINDOWFRAME
        7 => 0x00_00_00_00,  // COLOR_MENUTEXT
        8 => 0x00_00_00_00,  // COLOR_WINDOWTEXT
        9 => 0x00_C0_C0_C0,  // COLOR_CAPTIONTEXT
        10 => 0x00_C0_C0_C0, // COLOR_ACTIVEBORDER
        11 => 0x00_C0_C0_C0, // COLOR_INACTIVEBORDER
        12 => 0x00_80_80_80, // COLOR_APPWORKSPACE
        13 => 0x00_00_00_00, // COLOR_HIGHLIGHT
        14 => 0x00_FF_FF_FF, // COLOR_HIGHLIGHTTEXT
        15 => 0x00_C0_C0_C0, // COLOR_BTNFACE
        16 => 0x00_80_80_80, // COLOR_BTNSHADOW
        17 => 0x00_00_00_00, // COLOR_GRAYTEXT
        18 => 0x00_00_00_00, // COLOR_BTNTEXT
        19 => 0x00_00_00_00, // COLOR_INACTIVECAPTIONTEXT
        20 => 0x00_FF_FF_FF, // COLOR_BTNHIGHLIGHT
        21 => 0x00_00_00_00, // COLOR_3DDKSHADOW
        22 => 0x00_DF_DF_DF, // COLOR_3DLIGHT
        23 => 0x00_00_00_00, // COLOR_INFOTEXT
        24 => 0x00_FF_FF_E1, // COLOR_INFOBK
        26 => 0x00_80_00_80, // COLOR_HOTLIGHT
        27 => 0x00_DB_DB_DB, // COLOR_GRADIENTACTIVECAPTION
        28 => 0x00_DB_DB_DB, // COLOR_GRADIENTINACTIVECAPTION
        _ => 0x00_C0_C0_C0,  // default: silver
    }
}

pub(crate) fn colorref_to_bgra(color: u32) -> [u8; 4] {
    let [red, green, blue, _] = color.to_le_bytes();
    [blue, green, red, 0xff]
}

pub(crate) fn brush_to_bgra(brush: u64, gdi_brushes: &BTreeMap<u64, u32>) -> [u8; 4] {
    // Stock object handles (0x8000_0001..0x8000_0020) are looked up via
    // gdi_brushes which GetStockObject populates with correct COLORREFs.
    // Legacy handles 1..=32 (used by older code paths) map via sys_color_value.
    match brush {
        0x8000_0001..=0x8000_0020 => gdi_brushes
            .get(&brush)
            .map(|&color| colorref_to_bgra(color))
            .unwrap_or([0xf0, 0xf0, 0xf0, 0xff]),
        1..=32 => colorref_to_bgra(sys_color_value(brush as i32 - 1)),
        _ => gdi_brushes
            .get(&brush)
            .map(|&color| colorref_to_bgra(color))
            .unwrap_or([0xf0, 0xf0, 0xf0, 0xff]),
    }
}

pub(crate) fn blit_window_surface(
    bytes: &mut [u8],
    frame_width: usize,
    dst_x: usize,
    dst_y: usize,
    surface: &WindowSurface,
) {
    if frame_width == 0 || surface.width == 0 || surface.height == 0 {
        return;
    }
    let frame_height = bytes.len() / 4 / frame_width;
    for row in 0..surface.height {
        let target_y = dst_y.saturating_add(row);
        if target_y >= frame_height {
            break;
        }
        for column in 0..surface.width {
            let target_x = dst_x.saturating_add(column);
            if target_x >= frame_width {
                break;
            }
            let src_offset = (row * surface.width + column) * 4;
            let dst_offset = (target_y * frame_width + target_x) * 4;
            bytes[dst_offset..dst_offset + 4]
                .copy_from_slice(&surface.bytes[src_offset..src_offset + 4]);
        }
    }
}

pub(crate) fn fill_bgra_rect(
    bytes: &mut [u8],
    frame_width: usize,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    color: [u8; 4],
) {
    if frame_width == 0 {
        return;
    }
    let frame_height = bytes.len() / 4 / frame_width;
    let x_end = x.saturating_add(width).min(frame_width);
    let y_end = y.saturating_add(height).min(frame_height);
    for row in y..y_end {
        for column in x..x_end {
            let offset = (row * frame_width + column) * 4;
            bytes[offset..offset + 4].copy_from_slice(&color);
        }
    }
}

/// Rasterize an ellipse bounded by `[left, right) × [top, bottom)` into a
/// BGRA surface with the documented GDI convention: the interior is filled
/// with `fill_color` and the one-pixel outline is drawn with `pen_color`
/// (the ellipse equation `((x−cx)/rx)² + ((y−cy)/ry)² = 1` evaluated at
/// pixel centers; pixels on the boundary are painted with the pen).
#[allow(clippy::too_many_arguments)]
pub(crate) fn fill_ellipse_bgra(
    bytes: &mut [u8],
    frame_width: usize,
    frame_height: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    fill_color: [u8; 4],
    pen_color: [u8; 4],
) {
    if frame_width == 0 || right <= left || bottom <= top {
        return;
    }
    let rx = f64::from(right - left) / 2.0;
    let ry = f64::from(bottom - top) / 2.0;
    if rx <= 0.0 || ry <= 0.0 {
        return;
    }
    let cx = f64::from(left) + rx;
    let cy = f64::from(top) + ry;
    let inv_rx2 = 1.0 / (rx * rx);
    let inv_ry2 = 1.0 / (ry * ry);
    for row in top.max(0)..bottom.min(frame_height as i32) {
        for column in left.max(0)..right.min(frame_width as i32) {
            let dx = f64::from(column) + 0.5 - cx;
            let dy = f64::from(row) + 0.5 - cy;
            let inside = dx * dx * inv_rx2 + dy * dy * inv_ry2 <= 1.0;
            if !inside {
                continue;
            }
            // Boundary test: a pixel is on the outline when a 4-neighbor
            // lies outside the ellipse (or outside the surface bounds).
            let on_outline = !is_inside_ellipse(dx - 1.0, dy, inv_rx2, inv_ry2)
                || !is_inside_ellipse(dx + 1.0, dy, inv_rx2, inv_ry2)
                || !is_inside_ellipse(dx, dy - 1.0, inv_rx2, inv_ry2)
                || !is_inside_ellipse(dx, dy + 1.0, inv_rx2, inv_ry2);
            let offset = (row as usize * frame_width + column as usize) * 4;
            bytes[offset..offset + 4].copy_from_slice(if on_outline {
                &pen_color
            } else {
                &fill_color
            });
        }
    }
}

pub(crate) fn is_inside_ellipse(dx: f64, dy: f64, inv_rx2: f64, inv_ry2: f64) -> bool {
    dx * dx * inv_rx2 + dy * dy * inv_ry2 <= 1.0
}

/// Invert the color of every pixel in `[left, right) × [top, bottom)`
/// (DSTINVERT semantics: NOT applied to every channel, including alpha,
/// matching the documented raster op on 32-bpp surfaces).
pub(crate) fn invert_bgra_rect(
    bytes: &mut [u8],
    frame_width: usize,
    frame_height: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) {
    if frame_width == 0 {
        return;
    }
    for row in top.max(0)..bottom.min(frame_height as i32) {
        for column in left.max(0)..right.min(frame_width as i32) {
            let offset = (row as usize * frame_width + column as usize) * 4;
            for channel in 0..4 {
                bytes[offset + channel] = !bytes[offset + channel];
            }
        }
    }
}

pub(crate) fn draw_text_bgra(
    bytes: &mut [u8],
    frame_width: usize,
    x: usize,
    y: usize,
    text: &str,
    color: [u8; 4],
    scale: usize,
) {
    let mut cursor_x = x;
    let scale = scale.max(1);
    for ch in text.chars() {
        if ch == '\n' {
            cursor_x = x;
            continue;
        }
        if let Some(rows) = glyph_5x7(ch) {
            draw_glyph_bgra(bytes, frame_width, cursor_x, y, &rows, color, scale);
        }
        cursor_x = cursor_x.saturating_add((5 + 1) * scale);
    }
}

pub(crate) fn measure_text_bgra(text: &str, scale: usize) -> (usize, usize) {
    let scale = scale.max(1);
    let mut max_width = 0usize;
    let mut line_width = 0usize;
    let mut line_count = 1usize;
    for ch in text.chars() {
        if ch == '\n' {
            max_width = max_width.max(line_width.saturating_sub(scale));
            line_width = 0;
            line_count += 1;
            continue;
        }
        line_width = line_width.saturating_add((5 + 1) * scale);
    }
    max_width = max_width.max(line_width.saturating_sub(scale));
    let line_height = 7usize.saturating_mul(scale).saturating_add(scale);
    (
        max_width,
        line_count.saturating_mul(line_height).max(line_height),
    )
}

pub(crate) fn draw_text_bgra_in_rect(
    bytes: &mut [u8],
    frame_width: usize,
    rect: PreviewRect,
    text: &str,
    color: [u8; 4],
    scale: usize,
    format: u32,
) -> i32 {
    let scale = scale.max(1);
    let (text_width, text_height) = measure_text_bgra(text, scale);
    let horizontal_margin = 2usize.saturating_mul(scale);
    let x = if format & 0x0002 != 0 {
        rect.x.saturating_add(
            rect.width
                .saturating_sub(text_width)
                .saturating_sub(horizontal_margin),
        )
    } else if format & 0x0001 != 0 {
        rect.x
            .saturating_add(rect.width.saturating_sub(text_width) / 2)
    } else {
        rect.x.saturating_add(horizontal_margin)
    };
    let y = if format & 0x0004 != 0 {
        rect.y
            .saturating_add(rect.height.saturating_sub(text_height) / 2)
    } else {
        rect.y.saturating_add(scale)
    };
    draw_text_bgra(bytes, frame_width, x, y, text, color, scale);
    text_height as i32
}

pub(crate) fn draw_glyph_bgra(
    bytes: &mut [u8],
    frame_width: usize,
    x: usize,
    y: usize,
    rows: &[u8; 7],
    color: [u8; 4],
    scale: usize,
) {
    for (row_index, row_bits) in rows.iter().enumerate() {
        for column in 0..5usize {
            if row_bits & (1 << (4 - column)) == 0 {
                continue;
            }
            fill_bgra_rect(
                bytes,
                frame_width,
                x + column * scale,
                y + row_index * scale,
                scale,
                scale,
                color,
            );
        }
    }
}

pub(crate) fn glyph_5x7(ch: char) -> Option<[u8; 7]> {
    let ch = if ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase()
    } else {
        ch
    };
    Some(match ch {
        'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        'B' => [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
        'C' => [0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e],
        'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        'F' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
        'G' => [0x0e, 0x11, 0x10, 0x10, 0x13, 0x11, 0x0f],
        'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        'I' => [0x0e, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e],
        'J' => [0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0e],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
        'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        'Q' => [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
        'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        '0' => [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
        '1' => [0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e],
        '2' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
        '3' => [0x1f, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0e],
        '4' => [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
        '5' => [0x1f, 0x10, 0x1e, 0x01, 0x01, 0x11, 0x0e],
        '6' => [0x06, 0x08, 0x10, 0x1e, 0x11, 0x11, 0x0e],
        '7' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
        '9' => [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x02, 0x0c],
        ' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c],
        ',' => [0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c, 0x08],
        ':' => [0x00, 0x0c, 0x0c, 0x00, 0x0c, 0x0c, 0x00],
        '-' => [0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00],
        '_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f],
        '/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        '(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        ')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        '+' => [0x00, 0x04, 0x04, 0x1f, 0x04, 0x04, 0x00],
        '!' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
        '?' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
        _ => return None,
    })
}
