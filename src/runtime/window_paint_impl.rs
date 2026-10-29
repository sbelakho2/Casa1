//! Live window surfaces, GDI painting, and built-in window procedures.

use super::*;

impl PeHostRuntime {
    pub(crate) fn window_preview(&self, hwnd: u32) -> Option<WindowPreview> {
        self.user32
            .window_previews()
            .into_iter()
            .find(|window| window.hwnd == hwnd)
    }

    pub(crate) fn ensure_window_surface(
        &mut self,
        hwnd: u32,
        width: usize,
        height: usize,
    ) -> &mut WindowSurface {
        let width = width.max(1);
        let height = height.max(1);
        let surface = self
            .window_surfaces
            .entry(hwnd)
            .or_insert_with(|| WindowSurface {
                width,
                height,
                bytes: vec![0; width.saturating_mul(height).saturating_mul(4)],
                real_pixels: false,
            });
        if surface.width != width || surface.height != height {
            surface.width = width;
            surface.height = height;
            surface.bytes = vec![0; width.saturating_mul(height).saturating_mul(4)];
            // A resize wipes the pixels; whatever provenance the surface had
            // no longer describes its (empty) content.
            surface.real_pixels = false;
        }
        surface
    }

    /// Resolve the bitmap currently selected into a memory DC, refreshing its
    /// host-side pixel mirror from guest memory first (DIB sections give the
    /// guest a direct pointer to the pixel buffer, so the guest writes pixels
    /// without going through any GDI thunk).
    pub(crate) fn refresh_dc_bitmap(
        &mut self,
        memory: &MemoryImage,
        hdc: u64,
    ) -> Option<(u64, MemoryBitmap)> {
        let object = self.dc_selected_objects.get(&hdc).copied()?;
        let bitmap = self.gdi_bitmaps.get_mut(&object)?;
        // Refresh the host-side mirror from guest memory.
        if bitmap.guest_pixel_ptr != 0
            && !bitmap.bytes.is_empty()
            && let Ok(slice) = memory.read_bytes(bitmap.guest_pixel_ptr, bitmap.bytes.len())
            && slice.len() == bitmap.bytes.len()
        {
            bitmap.bytes.copy_from_slice(&slice);
        }
        Some((object, bitmap.clone()))
    }

    /// Copy a rectangle of pixels from `hdc_src` to `hdc_dest`, with
    /// nearest-neighbour scaling when the source and destination sizes
    /// differ (StretchBlt).  Handles the four DC combinations:
    ///   memory-DC → window DC   (the common "present composed frame" case)
    ///   window DC → memory DC   (readback)
    ///   memory-DC → memory-DC
    ///   window DC → window DC
    ///
    /// Only `SRCCOPY` (0x00CC0020) is implemented pixel-faithfully; the other
    /// ternary raster ops fall back to a plain copy (good enough for the vast
    /// majority of app-side BitBlt usage, which is SRCCOPY).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn blit_dc_to_dc(
        &mut self,
        memory: &mut MemoryImage,
        hdc_dest: u64,
        x_dest: i64,
        y_dest: i64,
        w_dest: i64,
        h_dest: i64,
        hdc_src: u64,
        _x_src: i64,
        _y_src: i64,
        w_src: i64,
        h_src: i64,
        _rop: u32,
    ) {
        let _ = _rop; // SRCCOPY assumed; other ROPs approximated as copy.
        if w_dest <= 0 || h_dest <= 0 {
            return;
        }
        // Gather source pixels into a flat BGRA buffer (top-down).
        let (src_w, src_h, src_pixels) = match self.gather_dc_pixels(memory, hdc_src) {
            Some(p) => p,
            None => return, // No source pixels (e.g. source DC uninitialised).
        };
        if src_w == 0 || src_h == 0 {
            return;
        }

        // Determine destination.
        let dest_is_window = self.hdc_target_window(hdc_dest).is_some();
        if dest_is_window {
            let hwnd = self.hdc_target_window(hdc_dest).unwrap();
            let Some(preview) = self.window_preview(hwnd) else {
                return;
            };
            let surface =
                self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
            let surf_w = surface.width;
            // Stretch (nearest-neighbour) or 1:1 copy into the window surface.
            let need_stretch = w_src != w_dest || h_src != h_dest;
            for dy in 0..h_dest.max(0) as usize {
                let sy = if need_stretch {
                    (dy as i64 * h_src.max(1) / h_dest.max(1)) as usize
                } else {
                    dy
                };
                for dx in 0..w_dest.max(0) as usize {
                    let sx = if need_stretch {
                        (dx as i64 * w_src.max(1) / w_dest.max(1)) as usize
                    } else {
                        dx
                    };
                    if sy >= src_h || sx >= src_w {
                        continue;
                    }
                    let tx = x_dest + dx as i64;
                    let ty = y_dest + dy as i64;
                    if tx < 0 || ty < 0 {
                        continue;
                    }
                    let tx = tx as usize;
                    let ty = ty as usize;
                    if tx >= surf_w || ty >= surface.height {
                        continue;
                    }
                    let s_idx = (sy * src_w + sx) * 4;
                    let d_idx = (ty * surf_w + tx) * 4;
                    if s_idx + 3 < src_pixels.len() && d_idx + 3 < surface.bytes.len() {
                        surface.bytes[d_idx..d_idx + 4]
                            .copy_from_slice(&src_pixels[s_idx..s_idx + 4]);
                    }
                }
            }
            // A guest-driven copy just landed real GDI pixels in a window
            // surface: this is the only place (besides the real memory-DC
            // conversion in `gather_dc_pixels`) where `last_real_gdi_frame`
            // may be assigned.  No synthetic content is ever cached here.
            // `gather_dc_pixels` already returned None for any source without
            // real pixels, so reaching this point proves the source surface
            // was real — record that provenance on the destination surface.
            surface.real_pixels = true;
            self.last_real_gdi_frame = Some(LiveFrame {
                width: surf_w as u32,
                height: surface.height as u32,
                format: DxgiFormat::B8G8R8A8Unorm,
                bytes: surface.bytes.clone(),
                displayed_frame_index: 0,
            });
        } else {
            // Dest is a memory DC: write into its selected bitmap.
            let Some(object) = self.dc_selected_objects.get(&hdc_dest).copied() else {
                return;
            };
            let Some(bitmap) = self.gdi_bitmaps.get_mut(&object) else {
                return;
            };
            let bmp_w = bitmap.width;
            // DIB sections are bottom-up: row 0 is the bottom of the image.
            // We write top-down into the source-equivalent row mapping.
            for dy in 0..h_dest.max(0) as usize {
                let sy = if w_src != w_dest || h_src != h_dest {
                    (dy as i64 * h_src.max(1) / h_dest.max(1)) as usize
                } else {
                    dy
                };
                for dx in 0..w_dest.max(0) as usize {
                    let sx = if w_src != w_dest || h_src != h_dest {
                        (dx as i64 * w_src.max(1) / w_dest.max(1)) as usize
                    } else {
                        dx
                    };
                    if sy >= src_h || sx >= src_w {
                        continue;
                    }
                    let tx = x_dest + dx as i64;
                    let ty = y_dest + dy as i64;
                    if tx < 0 || ty < 0 {
                        continue;
                    }
                    let tx = tx as usize;
                    let ty = ty as usize;
                    if tx >= bmp_w || ty >= bitmap.height {
                        continue;
                    }
                    // bottom-up: row (height-1-ty)
                    let d_row = bitmap.height - 1 - ty;
                    let bpp = gdiplus_memory_bpp_bytes(&bitmap);
                    let d_idx = (d_row * bmp_w + tx) * bpp;
                    let s_idx = (sy * src_w + sx) * 4;
                    if d_idx + bpp <= bitmap.bytes.len() && s_idx + 3 < src_pixels.len() {
                        // Store as BGRA when 32bpp, else truncate.
                        let n = bpp.min(4);
                        bitmap.bytes[d_idx..d_idx + n]
                            .copy_from_slice(&src_pixels[s_idx..s_idx + n]);
                    }
                }
            }
            // Write the mirror back to guest memory so the guest sees the blit.
            if bitmap.guest_pixel_ptr != 0 && !bitmap.bytes.is_empty() {
                let ptr = bitmap.guest_pixel_ptr;
                let bytes = bitmap.bytes.clone();
                for (i, &b) in bytes.iter().enumerate() {
                    memory.write_u8(ptr + i as u64, b);
                }
            }
        }
    }

    /// Gather a DC's current pixel content into a flat, top-down, 32-bpp BGRA
    /// `Vec<u8>`.  Returns `(width, height, pixels)`.  For a window DC this
    /// reads the window surface; for a memory DC it reads the selected bitmap
    /// (refreshed from guest memory).
    pub(crate) fn gather_dc_pixels(
        &mut self,
        memory: &mut MemoryImage,
        hdc: u64,
    ) -> Option<(usize, usize, Vec<u8>)> {
        if let Some(hwnd) = self.hdc_target_window(hdc) {
            // Window DC: copy the current window surface.  Only REAL guest
            // pixels may propagate: a window with no surface (or only
            // host-invented chrome) has no real content, so return None
            // rather than fabricating a blank buffer that `blit_dc_to_dc`
            // would otherwise cache as a "real" GDI frame and propagate.
            let preview = self.window_preview(hwnd)?;
            let w = preview.width as usize;
            let h = preview.height as usize;
            let surface = self.window_surfaces.get(&hwnd)?;
            if !surface.real_pixels {
                return None;
            }
            return Some((w, h, surface.bytes.clone()));
        }
        // Memory DC: read selected bitmap.
        let (_obj, bitmap) = self.refresh_dc_bitmap(memory, hdc)?;
        let w = bitmap.width;
        let h = bitmap.height;
        let bpp = gdiplus_memory_bpp_bytes(&bitmap);
        let mut out = vec![0u8; w * h * 4];
        // Convert native (bottom-up) bitmap → top-down BGRA.
        for y in 0..h {
            for x in 0..w {
                let s_row = h - 1 - y;
                let s_idx = (s_row * w + x) * bpp;
                let d_idx = (y * w + x) * 4;
                if s_idx + bpp <= bitmap.bytes.len() {
                    let px = &bitmap.bytes[s_idx..s_idx + bpp];
                    let (b, g, r, a) = match bpp {
                        1 => (px[0], px[0], px[0], 0xff),
                        2 => {
                            // 16bpp RGB555/565 — approximate.
                            let v = u16::from_le_bytes([px[0], px[1]]);
                            let r = ((v >> 10) & 0x1f) as u8 * 255 / 31;
                            let g = ((v >> 5) & 0x1f) as u8 * 255 / 31;
                            let b = (v & 0x1f) as u8 * 255 / 31;
                            (b, g, r, 0xff)
                        }
                        3 => (px[0], px[1], px[2], 0xff), // BGR
                        _ => (
                            px[0],
                            px[1],
                            px[2],
                            if px.len() >= 4 { px[3] } else { 0xff },
                        ),
                    };
                    out[d_idx] = b;
                    out[d_idx + 1] = g;
                    out[d_idx + 2] = r;
                    out[d_idx + 3] = a;
                }
            }
        }
        // Real memory-DC pixel extraction: cache the converted pixels so the
        // live pipeline can publish them.  This is one of exactly two real
        // GDI extraction sites (the other is the guest-driven blit in
        // `blit_dc_to_dc`); synthetic frames are never cached here.
        self.last_real_gdi_frame = Some(LiveFrame {
            width: w as u32,
            height: h as u32,
            format: DxgiFormat::B8G8R8A8Unorm,
            bytes: out.clone(),
            displayed_frame_index: 0,
        });
        Some((w, h, out))
    }

    pub(crate) fn clear_window_surface(&mut self, hwnd: u32, color: [u8; 4]) {
        let Some(preview) = self.window_preview(hwnd) else {
            return;
        };
        let surface =
            self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
        fill_bgra_rect(
            &mut surface.bytes,
            surface.width,
            0,
            0,
            surface.width,
            surface.height,
            color,
        );
    }

    pub(crate) fn hdc_target_window(&self, hdc: u64) -> Option<u32> {
        self.device_contexts.get(&hdc).copied().flatten()
    }

    /// `GetPixel` semantics: the COLORREF (0x00BBGGRR) of the pixel at
    /// (x, y) in the DC.  Window DCs read the window surface; memory DCs
    /// read the selected bitmap (bottom-up native layout, refreshed from
    /// guest memory).  Returns CLR_INVALID (0xFFFFFFFF) when the DC or the
    /// pixel is out of bounds.
    pub(crate) fn gdi_get_pixel(&mut self, memory: &MemoryImage, hdc: u64, x: i64, y: i64) -> u32 {
        if x < 0 || y < 0 {
            return 0xFFFF_FFFF;
        }
        if let Some(hwnd) = self.hdc_target_window(hdc) {
            let Some(preview) = self.window_preview(hwnd) else {
                return 0xFFFF_FFFF;
            };
            let width = preview.width as usize;
            let height = preview.height as usize;
            let Some(surface) = self.window_surfaces.get(&hwnd) else {
                return 0xFFFF_FFFF;
            };
            let (x, y) = (x as usize, y as usize);
            if x >= width || y >= height {
                return 0xFFFF_FFFF;
            }
            let index = (y * width + x) * 4;
            if index + 3 >= surface.bytes.len() {
                return 0xFFFF_FFFF;
            }
            // BGRA surface → COLORREF 0x00BBGGRR: the low byte is RED,
            // the high byte is BLUE.
            u32::from(surface.bytes[index + 2])
                | (u32::from(surface.bytes[index + 1]) << 8)
                | (u32::from(surface.bytes[index]) << 16)
        } else {
            let Some((_object, bitmap)) = self.refresh_dc_bitmap(memory, hdc) else {
                return 0xFFFF_FFFF;
            };
            let (x, y) = (x as usize, y as usize);
            if x >= bitmap.width || y >= bitmap.height {
                return 0xFFFF_FFFF;
            }
            let bpp = gdiplus_memory_bpp_bytes(&bitmap);
            // Bitmaps are bottom-up: row 0 is the bottom of the image.
            let row = bitmap.height - 1 - y;
            let index = (row * bitmap.width + x) * bpp;
            if index + bpp > bitmap.bytes.len() {
                return 0xFFFF_FFFF;
            }
            let pixel = &bitmap.bytes[index..index + bpp];
            match bpp {
                1 => u32::from(pixel[0]) * 0x01_0101,
                2 => {
                    let value = u16::from_le_bytes([pixel[0], pixel[1]]);
                    let r = (((value >> 10) & 0x1f) * 255 / 31) as u32;
                    let g = (((value >> 5) & 0x1f) * 255 / 31) as u32;
                    let b = ((value & 0x1f) * 255 / 31) as u32;
                    r | (g << 8) | (b << 16)
                }
                _ => {
                    // Native BGRA/BGR layout.
                    u32::from(pixel[2]) | (u32::from(pixel[1]) << 8) | (u32::from(pixel[0]) << 16)
                }
            }
        }
    }

    /// `SetPixel` semantics: set the pixel at (x, y) in the DC to the
    /// COLORREF.  Window DCs write the window surface; memory DCs write
    /// the selected bitmap and mirror the bytes back into guest memory.
    /// Returns the color actually set, or CLR_INVALID (0xFFFFFFFF) when
    /// the DC or the pixel is out of bounds.
    pub(crate) fn gdi_set_pixel(
        &mut self,
        memory: &mut MemoryImage,
        hdc: u64,
        x: i64,
        y: i64,
        color: u32,
    ) -> u32 {
        if x < 0 || y < 0 {
            return 0xFFFF_FFFF;
        }
        if let Some(hwnd) = self.hdc_target_window(hdc) {
            let Some(preview) = self.window_preview(hwnd) else {
                return 0xFFFF_FFFF;
            };
            let width = preview.width as usize;
            let height = preview.height as usize;
            let (x, y) = (x as usize, y as usize);
            if x >= width || y >= height {
                return 0xFFFF_FFFF;
            }
            let surface =
                self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
            let index = (y * width + x) * 4;
            if index + 3 >= surface.bytes.len() {
                return 0xFFFF_FFFF;
            }
            let bgra = colorref_to_bgra(color);
            surface.bytes[index..index + 4].copy_from_slice(&bgra);
            color
        } else {
            let Some(object) = self.dc_selected_objects.get(&hdc).copied() else {
                return 0xFFFF_FFFF;
            };
            let Some(bitmap) = self.gdi_bitmaps.get_mut(&object) else {
                return 0xFFFF_FFFF;
            };
            let (x, y) = (x as usize, y as usize);
            if x >= bitmap.width || y >= bitmap.height {
                return 0xFFFF_FFFF;
            }
            let bpp = gdiplus_memory_bpp_bytes(&bitmap);
            let row = bitmap.height - 1 - y;
            let index = (row * bitmap.width + x) * bpp;
            if index + bpp > bitmap.bytes.len() {
                return 0xFFFF_FFFF;
            }
            let bgra = colorref_to_bgra(color);
            let n = bpp.min(4);
            bitmap.bytes[index..index + n].copy_from_slice(&bgra[..n]);
            if bitmap.guest_pixel_ptr != 0 {
                for (offset, &byte) in bgra.iter().take(n).enumerate() {
                    memory.write_u8(bitmap.guest_pixel_ptr + index as u64 + offset as u64, byte);
                }
            }
            color
        }
    }

    /// `AlphaBlend` semantics: alpha-composite a source DC region into the
    /// destination DC's window surface.  `source_alpha` (the
    /// BLENDFUNCTION.SourceConstantAlpha) scales every source pixel; with
    /// `use_source_alpha` (AC_SRC_ALPHA) the source per-pixel alpha is
    /// used instead, using the documented formula
    /// `dst = src·a + dst·(1−a)` per channel.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn alpha_blend_dc(
        &mut self,
        memory: &mut MemoryImage,
        hdc_dest: u64,
        x_dest: i64,
        y_dest: i64,
        w_dest: i64,
        h_dest: i64,
        hdc_src: u64,
        x_src: i64,
        y_src: i64,
        w_src: i64,
        h_src: i64,
        source_alpha: u32,
        use_source_alpha: bool,
    ) -> bool {
        let Some(hwnd) = self.hdc_target_window(hdc_dest) else {
            return false;
        };
        let Some(preview) = self.window_preview(hwnd) else {
            return false;
        };
        let Some((src_w, src_h, src_pixels)) = self.gather_dc_pixels(memory, hdc_src) else {
            return false;
        };
        if src_w == 0 || src_h == 0 || w_dest <= 0 || h_dest <= 0 {
            return false;
        }
        let surface =
            self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
        let surf_w = surface.width;
        for dy in 0..h_dest as usize {
            let sy = ((dy as i64 * h_src.max(1) / h_dest.max(1)) + y_src) as usize;
            for dx in 0..w_dest as usize {
                let sx = ((dx as i64 * w_src.max(1) / w_dest.max(1)) + x_src) as usize;
                if sy >= src_h || sx >= src_w {
                    continue;
                }
                let tx = x_dest + dx as i64;
                let ty = y_dest + dy as i64;
                if tx < 0 || ty < 0 || tx as usize >= surf_w || ty as usize >= surface.height {
                    continue;
                }
                let s_idx = (sy * src_w + sx) * 4;
                let d_idx = (ty as usize * surf_w + tx as usize) * 4;
                if s_idx + 3 >= src_pixels.len() || d_idx + 3 >= surface.bytes.len() {
                    continue;
                }
                let src_b = src_pixels[s_idx];
                let src_g = src_pixels[s_idx + 1];
                let src_r = src_pixels[s_idx + 2];
                let src_a = src_pixels[s_idx + 3];
                let dst_b = surface.bytes[d_idx];
                let dst_g = surface.bytes[d_idx + 1];
                let dst_r = surface.bytes[d_idx + 2];
                let dst_a = surface.bytes[d_idx + 3];
                // Per-pixel alpha: AC_SRC_ALPHA uses the source alpha;
                // otherwise only SourceConstantAlpha applies.
                let alpha = if use_source_alpha {
                    (u32::from(src_a) * source_alpha.min(255)) / 255
                } else {
                    source_alpha.min(255)
                };
                let alpha = alpha.min(255);
                let inv = 255 - alpha;
                let blend = |src: u8, dst: u8| {
                    ((u32::from(src) * alpha + u32::from(dst) * inv) / 255) as u8
                };
                surface.bytes[d_idx] = blend(src_b, dst_b);
                surface.bytes[d_idx + 1] = blend(src_g, dst_g);
                surface.bytes[d_idx + 2] = blend(src_r, dst_r);
                // The destination alpha channel follows the same blend.
                surface.bytes[d_idx + 3] = blend(src_a, dst_a);
            }
        }
        true
    }

    /// `TransparentBlt` semantics: copy a source DC region into the
    /// destination DC's window surface, skipping source pixels that match
    /// the transparent COLORREF.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn transparent_blit_dc(
        &mut self,
        memory: &mut MemoryImage,
        hdc_dest: u64,
        x_dest: i64,
        y_dest: i64,
        w_dest: i64,
        h_dest: i64,
        hdc_src: u64,
        x_src: i64,
        y_src: i64,
        w_src: i64,
        h_src: i64,
        transparent: u32,
    ) -> bool {
        let Some(hwnd) = self.hdc_target_window(hdc_dest) else {
            return false;
        };
        let Some(preview) = self.window_preview(hwnd) else {
            return false;
        };
        let Some((src_w, src_h, src_pixels)) = self.gather_dc_pixels(memory, hdc_src) else {
            return false;
        };
        if src_w == 0 || src_h == 0 || w_dest <= 0 || h_dest <= 0 {
            return false;
        }
        let transparent_bgra = colorref_to_bgra(transparent);
        let surface =
            self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
        let surf_w = surface.width;
        for dy in 0..h_dest as usize {
            let sy = ((dy as i64 * h_src.max(1) / h_dest.max(1)) + y_src) as usize;
            for dx in 0..w_dest as usize {
                let sx = ((dx as i64 * w_src.max(1) / w_dest.max(1)) + x_src) as usize;
                if sy >= src_h || sx >= src_w {
                    continue;
                }
                let s_idx = (sy * src_w + sx) * 4;
                if s_idx + 3 >= src_pixels.len() {
                    continue;
                }
                // Skip the transparent color (RGB match; alpha is not part
                // of the COLORREF).
                if src_pixels[s_idx] == transparent_bgra[0]
                    && src_pixels[s_idx + 1] == transparent_bgra[1]
                    && src_pixels[s_idx + 2] == transparent_bgra[2]
                {
                    continue;
                }
                let tx = x_dest + dx as i64;
                let ty = y_dest + dy as i64;
                if tx < 0 || ty < 0 || tx as usize >= surf_w || ty as usize >= surface.height {
                    continue;
                }
                let d_idx = (ty as usize * surf_w + tx as usize) * 4;
                if d_idx + 3 < surface.bytes.len() {
                    surface.bytes[d_idx..d_idx + 4].copy_from_slice(&src_pixels[s_idx..s_idx + 4]);
                }
            }
        }
        true
    }

    /// Format a Windows GUID struct (16 bytes, little-endian Data1/Data2/
    /// Data3 followed by the 8 Data4 bytes) as the canonical
    /// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` string.
    pub(crate) fn guid_bytes_to_string(bytes: &[u8; 16]) -> String {
        let data1 = u32::from_le_bytes(bytes[0..4].try_into().expect("guid data1"));
        let data2 = u16::from_le_bytes(bytes[4..6].try_into().expect("guid data2"));
        let data3 = u16::from_le_bytes(bytes[6..8].try_into().expect("guid data3"));
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            data1,
            data2,
            data3,
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }

    /// Parse a GUID string (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`) into
    /// the 16-byte Windows GUID struct layout; returns `None` for strings
    /// that do not follow the canonical form.
    pub(crate) fn parse_guid_string(guid: &str) -> Option<[u8; 16]> {
        let trimmed = guid.trim().trim_start_matches('{').trim_end_matches('}');
        let hex = trimmed.replace('-', "");
        if hex.len() != 32 {
            return None;
        }
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<_>>()?;
        let mut out = [0_u8; 16];
        out[0..4].copy_from_slice(&u32::from_be_bytes(bytes[0..4].try_into().ok()?).to_le_bytes());
        out[4..6].copy_from_slice(&u16::from_be_bytes(bytes[4..6].try_into().ok()?).to_le_bytes());
        out[6..8].copy_from_slice(&u16::from_be_bytes(bytes[6..8].try_into().ok()?).to_le_bytes());
        out[8..16].copy_from_slice(&bytes[8..16]);
        Some(out)
    }

    /// Read a guest registry string value (REG_SZ) from the device
    /// enumeration store.
    pub(crate) fn setupapi_registry_string(
        &self,
        hive: &str,
        key: &str,
        value_name: &str,
    ) -> Option<String> {
        self.win32
            .ge()
            .registry_get_value(hive, key, value_name, RegistryView::Native)
            .ok()
            .flatten()
            .and_then(|stored| stored.data.as_str().map(str::to_string))
    }

    /// Enumerate the device instances in the guest registry's device store
    /// (`HKLM\SYSTEM\CurrentControlSet\Enum`), optionally filtered by class
    /// GUID and enumerator — the device-info-set contents behind
    /// `SetupDiGetClassDevsW`.
    pub(crate) fn setupapi_device_list(
        &self,
        class_guid: Option<&str>,
        enumerator: Option<&str>,
    ) -> Vec<SetupDeviceInfo> {
        const ENUM_ROOT: &str = "SYSTEM\\CurrentControlSet\\Enum";
        let ge = self.win32.ge();
        let mut devices = Vec::new();
        let Ok(enumerators) = ge.registry_enum_keys("HKLM", ENUM_ROOT, RegistryView::Native) else {
            return devices;
        };
        for enumerator_name in enumerators {
            if let Some(filter) = enumerator
                && !filter.eq_ignore_ascii_case(&enumerator_name)
            {
                continue;
            }
            let enumerator_key = format!("{ENUM_ROOT}\\{enumerator_name}");
            let Ok(device_ids) =
                ge.registry_enum_keys("HKLM", &enumerator_key, RegistryView::Native)
            else {
                continue;
            };
            for device_id in device_ids {
                let device_key = format!("{enumerator_key}\\{device_id}");
                let Ok(instances) =
                    ge.registry_enum_keys("HKLM", &device_key, RegistryView::Native)
                else {
                    continue;
                };
                for instance in instances {
                    let registry_key = format!("{device_key}\\{instance}");
                    let instance_id = format!("{enumerator_name}\\{device_id}\\{instance}");
                    let device_class =
                        self.setupapi_registry_string("HKLM", &registry_key, "ClassGUID");
                    if let Some(filter) = class_guid
                        && device_class
                            .as_deref()
                            .is_some_and(|class| !class.eq_ignore_ascii_case(filter))
                    {
                        continue;
                    }
                    devices.push(SetupDeviceInfo {
                        instance_id,
                        class_guid: device_class.unwrap_or_default(),
                        registry_key,
                    });
                }
            }
        }
        devices
    }

    /// Resolve a device-information element (devinst) within a
    /// device-info-set to its device record.
    pub(crate) fn setupapi_device(
        &self,
        dev_info_set: u64,
        devinst: u32,
    ) -> Option<SetupDeviceInfo> {
        let devices = self.setup_devices.get(&dev_info_set)?;
        devices.get(devinst as usize).cloned()
    }

    /// The SPDRP_* property → guest-registry value-name mapping for
    /// `SetupDiGetDeviceRegistryPropertyW` / `SetupDiSetDeviceRegistryPropertyW`.
    pub(crate) fn setupapi_property_value_name(property: u32) -> Option<&'static str> {
        match property {
            0 => Some("DeviceDesc"),     // SPDRP_DEVICEDESC
            1 => Some("HardwareID"),     // SPDRP_HARDWAREID
            2 => Some("CompatibleIDs"),  // SPDRP_COMPATIBLEIDS
            4 => Some("Service"),        // SPDRP_SERVICE
            7 => Some("Class"),          // SPDRP_CLASS
            8 => Some("ClassGUID"),      // SPDRP_CLASSGUID
            9 => Some("Driver"),         // SPDRP_DRIVER
            11 => Some("Mfg"),           // SPDRP_MFG
            12 => Some("FriendlyName"),  // SPDRP_FRIENDLYNAME
            34 => Some("InstallState"),  // SPDRP_INSTALL_STATE (DWORD)
            47 => Some("DevType"),       // SPDRP_DEVTYPE (DWORD)
            48 => Some("BusTypeGUID"),   // SPDRP_BUSTYPEGUID
            49 => Some("LegacyBusType"), // SPDRP_LEGACYBUSTYPE (DWORD)
            50 => Some("BusNumber"),     // SPDRP_BUSNUMBER (DWORD)
            _ => None,
        }
    }

    /// Read the typed data of a device property from the guest registry:
    /// returns `(registry_type, bytes)` for the property buffer.
    pub(crate) fn setupapi_read_property(
        &self,
        device: &SetupDeviceInfo,
        property: u32,
    ) -> Option<(u32, Vec<u8>)> {
        let value_name = Self::setupapi_property_value_name(property)?;
        let stored = self
            .win32
            .ge()
            .registry_get_value(
                "HKLM",
                &device.registry_key,
                value_name,
                RegistryView::Native,
            )
            .ok()
            .flatten()?;
        match stored.value_type.as_str() {
            "REG_DWORD" => stored
                .data
                .as_u64()
                .map(|value| (4, (value as u32).to_le_bytes().to_vec())),
            "REG_QWORD" => stored
                .data
                .as_u64()
                .map(|value| (11, value.to_le_bytes().to_vec())),
            "REG_SZ" | "REG_EXPAND_SZ" => stored.data.as_str().map(|text| {
                let mut bytes = text
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>();
                bytes.extend_from_slice(&[0, 0]);
                (1, bytes)
            }),
            _ => None,
        }
    }

    /// Write a typed device property into the guest registry.
    pub(crate) fn setupapi_write_property(
        &self,
        device: &SetupDeviceInfo,
        property: u32,
        bytes: &[u8],
    ) -> bool {
        let Some(value_name) = Self::setupapi_property_value_name(property) else {
            return false;
        };
        let ge = self.win32.ge();
        let is_dword = matches!(property, 34 | 47 | 49 | 50);
        if is_dword {
            if bytes.len() < 4 {
                return false;
            }
            let value = u32::from_le_bytes(bytes[..4].try_into().expect("dword"));
            ge.registry_set_value(
                "HKLM",
                &device.registry_key,
                value_name,
                "REG_DWORD",
                json!(value),
                RegistryView::Native,
            )
            .is_ok()
        } else {
            // String property (REG_SZ): the buffer is a NUL-terminated
            // UTF-16 string.
            let units = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            let text = String::from_utf16_lossy(&units);
            ge.registry_set_value(
                "HKLM",
                &device.registry_key,
                value_name,
                "REG_SZ",
                json!(text),
                RegistryView::Native,
            )
            .is_ok()
        }
    }

    pub(crate) fn selected_text_scale(&self, hdc: u64) -> usize {
        let height = self
            .dc_selected_objects
            .get(&hdc)
            .and_then(|handle| self.gdi_fonts.get(handle))
            .map(|font| font.height.abs())
            .unwrap_or(14);
        ((height.max(8) as usize) / 8).clamp(1, 3)
    }

    pub(crate) fn fill_hdc_rect(&mut self, hdc: u64, rect: PreviewRect, color: [u8; 4]) -> bool {
        let Some(hwnd) = self.hdc_target_window(hdc) else {
            return false;
        };
        let Some(preview) = self.window_preview(hwnd) else {
            return false;
        };
        let surface =
            self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
        fill_bgra_rect(
            &mut surface.bytes,
            surface.width,
            rect.x,
            rect.y,
            rect.width,
            rect.height,
            color,
        );
        true
    }

    pub(crate) fn draw_text_to_hdc(
        &mut self,
        hdc: u64,
        rect: PreviewRect,
        text: &str,
        format: u32,
    ) -> i32 {
        let Some(hwnd) = self.hdc_target_window(hdc) else {
            return 0;
        };
        let Some(preview) = self.window_preview(hwnd) else {
            return 0;
        };
        let scale = self.selected_text_scale(hdc);
        let color = self
            .dc_text_colors
            .get(&hdc)
            .copied()
            .map(colorref_to_bgra)
            .unwrap_or([0x30, 0x30, 0x30, 0xff]);
        let surface =
            self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
        draw_text_bgra_in_rect(
            &mut surface.bytes,
            surface.width,
            rect,
            text,
            color,
            scale,
            format,
        )
    }

    pub(crate) fn paint_builtin_window(&mut self, hwnd: u32) -> AppResult<bool> {
        let Some(preview) = self.window_preview(hwnd) else {
            return Ok(false);
        };
        let class_name = preview.class_name.to_ascii_lowercase();
        if class_name.contains("button") {
            let surface =
                self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
            fill_bgra_rect(
                &mut surface.bytes,
                surface.width,
                0,
                0,
                surface.width,
                surface.height,
                [0xb8, 0xc3, 0xcf, 0xff],
            );
            fill_bgra_rect(
                &mut surface.bytes,
                surface.width,
                1,
                1,
                surface.width.saturating_sub(2),
                surface.height.saturating_sub(2),
                [0xeb, 0xf0, 0xf5, 0xff],
            );
            if !preview.title.trim().is_empty() {
                draw_text_bgra_in_rect(
                    &mut surface.bytes,
                    surface.width,
                    PreviewRect {
                        x: 4,
                        y: 2,
                        width: surface.width.saturating_sub(8),
                        height: surface.height.saturating_sub(4),
                    },
                    &preview.title,
                    [0x42, 0x4e, 0x5c, 0xff],
                    1,
                    0x0001 | 0x0004 | 0x0020,
                );
            }
        } else if class_name.contains("progress") {
            let state = self
                .progress_bar_states
                .get(&hwnd)
                .copied()
                .unwrap_or_default();
            let surface =
                self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
            fill_bgra_rect(
                &mut surface.bytes,
                surface.width,
                0,
                0,
                surface.width,
                surface.height,
                [0xdc, 0xe3, 0xea, 0xff],
            );
            fill_bgra_rect(
                &mut surface.bytes,
                surface.width,
                2,
                2,
                surface.width.saturating_sub(4),
                surface.height.saturating_sub(4),
                [0xf9, 0xfb, 0xfd, 0xff],
            );
            let span = (state.max - state.min).max(1);
            let progress = (state.pos - state.min).clamp(0, span) as usize;
            let fill_width =
                surface.width.saturating_sub(6).saturating_mul(progress) / span as usize;
            fill_bgra_rect(
                &mut surface.bytes,
                surface.width,
                3,
                3,
                fill_width,
                surface.height.saturating_sub(6),
                [0x4f, 0xb3, 0x59, 0xff],
            );
        } else if class_name.contains("static") {
            let surface =
                self.ensure_window_surface(hwnd, preview.width as usize, preview.height as usize);
            fill_bgra_rect(
                &mut surface.bytes,
                surface.width,
                0,
                0,
                surface.width,
                surface.height,
                [0xf8, 0xfa, 0xfc, 0xff],
            );
            if !preview.title.trim().is_empty() {
                draw_text_bgra_in_rect(
                    &mut surface.bytes,
                    surface.width,
                    PreviewRect {
                        x: 2,
                        y: 1,
                        width: surface.width.saturating_sub(4),
                        height: surface.height.saturating_sub(2),
                    },
                    &preview.title,
                    [0x56, 0x56, 0x56, 0xff],
                    1,
                    0,
                );
            }
        } else {
            return Ok(false);
        }
        // A builtin control paint renders synthetic chrome into the window
        // surface for guest-visible behavior; it is NOT a real guest frame,
        // so it never publishes to the live channel and never counts as a
        // real guest present.  Explicitly revoke any real-pixel provenance
        // so overwritten content is never mistaken for guest pixels.
        if let Some(surface) = self.window_surfaces.get_mut(&hwnd) {
            surface.real_pixels = false;
        }
        Ok(true)
    }

    pub(crate) fn dispatch_builtin_window_message(
        &mut self,
        hwnd: u32,
        message_id: u32,
        wparam: i64,
        lparam: i64,
    ) -> AppResult<Option<i64>> {
        let Some(preview) = self.window_preview(hwnd) else {
            return Ok(None);
        };
        let class_name = preview.class_name.to_ascii_lowercase();
        if message_id == 0x000f && self.paint_builtin_window(hwnd)? {
            // After painting a built-in window, submit the CEF frame for the
            // browser specifically associated with this HWND (if any).
            if let Some(cef_handle) = self.user32.cef_browser_for_window(hwnd) {
                crate::cef_bridge::with_global_cef_bridge(|bridge| {
                    bridge.submit_latest_frame_to_compositor(cef_handle);
                });
            }
            return Ok(Some(0));
        }
        // WM_ERASEBKGND (0x0014): return non-zero to indicate the background was
        // erased, preventing the default erase from causing flicker.
        if message_id == 0x0014 {
            return Ok(Some(1));
        }
        // WM_SIZE (0x0005): notify the CEF browser host associated with this HWND
        // when the window is resized, so the WKWebView frame and pixel buffers
        // are updated accordingly.
        // lparam encodes the new client area: LOWORD = width, HIWORD = height.
        if message_id == 0x0005 {
            let new_width = (lparam as u32) & 0xFFFF;
            let new_height = ((lparam as u32) >> 16) & 0xFFFF;
            if new_width > 0
                && new_height > 0
                && let Some(cef_handle) = self.user32.cef_browser_for_window(hwnd)
            {
                crate::cef_bridge::with_global_cef_bridge(|bridge| {
                    let _ = bridge.cef_browser_host_was_resized(cef_handle, new_width, new_height);
                });
            }
            return Ok(Some(0));
        }
        // --- Common Control Message Dispatch ---
        // Dispatch by class name for listview, treeview, tab, combobox, listbox, edit,
        // button, static, progress, up-down, toolbar, status bar, and header controls.
        if class_name.contains("progress") {
            const PBM_SETRANGE: u32 = 0x0401;
            const PBM_SETPOS: u32 = 0x0402;
            const PBM_DELTAPOS: u32 = 0x0403;
            const PBM_SETSTEP: u32 = 0x0404;
            const PBM_STEPIT: u32 = 0x0405;
            const PBM_SETRANGE32: u32 = 0x0406;
            let state = self.progress_bar_states.entry(hwnd).or_default();
            let result = match message_id {
                PBM_SETRANGE => {
                    let packed = lparam as u32;
                    state.min = (packed & 0xffff) as i16 as i32;
                    state.max = ((packed >> 16) & 0xffff) as i16 as i32;
                    0
                }
                PBM_SETPOS => {
                    let previous = state.pos;
                    state.pos = (wparam as i32).clamp(state.min, state.max);
                    previous as i64
                }
                PBM_DELTAPOS => {
                    let previous = state.pos;
                    state.pos = (state.pos + wparam as i32).clamp(state.min, state.max);
                    previous as i64
                }
                PBM_SETSTEP => {
                    let previous = state.step;
                    state.step = wparam as i32;
                    previous as i64
                }
                PBM_STEPIT => {
                    let previous = state.pos;
                    state.pos = (state.pos + state.step).clamp(state.min, state.max);
                    previous as i64
                }
                PBM_SETRANGE32 => {
                    state.min = wparam as i32;
                    state.max = lparam as i32;
                    0
                }
                _ => return Ok(None),
            };
            self.paint_builtin_window(hwnd)?;
            return Ok(Some(result));
        }
        if class_name.contains("listview") || class_name == "syslistview32" {
            const LVM_GETITEMCOUNT: u32 = 0x1004;
            const LVM_DELETEITEM: u32 = 0x1008;
            const LVM_DELETEALLITEMS: u32 = 0x1009;
            const LVM_INSERTITEM: u32 = 0x1007;
            const LVM_GETITEMTEXT: u32 = 0x102D;
            const LVM_SETITEMTEXT: u32 = 0x102E;
            const LVM_GETITEM: u32 = 0x1005;
            const LVM_SETITEM: u32 = 0x1006;
            const LVM_GETITEMSTATE: u32 = 0x105C;
            const LVM_SETITEMSTATE: u32 = 0x105D;
            const LVM_GETSELECTEDCOUNT: u32 = 0x1032;
            const LVM_GETCOLUMNWIDTH: u32 = 0x101D;
            const LVM_SETCOLUMNWIDTH: u32 = 0x101E;
            const LVM_GETHEADER: u32 = 0x101F;
            const LVM_GETITEMRECT: u32 = 0x100E;
            const LVM_GETEDITCONTROL: u32 = 0x1018;
            const LVM_REDRAWITEMS: u32 = 0x1015;
            const LVM_GETCOLUMN: u32 = 0x1019;
            const LVM_SETCOLUMN: u32 = 0x101A;
            let result = match message_id {
                LVM_GETITEMCOUNT | LVM_GETSELECTEDCOUNT | LVM_GETCOLUMNWIDTH | LVM_GETHEADER
                | LVM_GETEDITCONTROL => 0,
                LVM_DELETEITEM | LVM_DELETEALLITEMS | LVM_SETITEMTEXT | LVM_SETCOLUMNWIDTH
                | LVM_REDRAWITEMS | LVM_SETITEMSTATE => 1,
                LVM_INSERTITEM => 0,
                LVM_GETITEMTEXT => 0,
                LVM_GETITEM | LVM_GETCOLUMN | LVM_GETITEMRECT => 0,
                LVM_SETITEM | LVM_SETCOLUMN => 0,
                LVM_GETITEMSTATE => 0,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("treeview") || class_name == "systreeview32" {
            const TVM_GETCOUNT: u32 = 0x1105;
            const TVM_DELETEITEM: u32 = 0x1101;
            const TVM_INSERTITEM: u32 = 0x1100;
            const TVM_GETNEXTITEM: u32 = 0x110A;
            const TVM_SELECTITEM: u32 = 0x110B;
            const TVM_EXPAND: u32 = 0x1102;
            const TVM_GETITEM: u32 = 0x110C;
            const TVM_SETITEM: u32 = 0x110D;
            const TVM_GETITEMRECT: u32 = 0x1104;
            const TVM_GETVISIBLECOUNT: u32 = 0x1110;
            let result = match message_id {
                TVM_GETCOUNT | TVM_GETVISIBLECOUNT => 0,
                TVM_DELETEITEM | TVM_SELECTITEM | TVM_EXPAND => 1,
                TVM_INSERTITEM | TVM_GETNEXTITEM => 0,
                TVM_GETITEM | TVM_SETITEM | TVM_GETITEMRECT => 0,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("tab") || class_name == "systabcontrol32" {
            const TCM_GETITEMCOUNT: u32 = 0x1304;
            const TCM_GETCURSEL: u32 = 0x130B;
            const TCM_SETCURSEL: u32 = 0x130C;
            const TCM_DELETEITEM: u32 = 0x1308;
            const TCM_INSERTITEM: u32 = 0x1307;
            const TCM_GETITEM: u32 = 0x1305;
            const TCM_SETITEM: u32 = 0x1306;
            const TCM_ADJUSTRECT: u32 = 0x1328;
            let result = match message_id {
                TCM_GETITEMCOUNT => 0,
                TCM_GETCURSEL | TCM_SETCURSEL => -1i64,
                TCM_DELETEITEM | TCM_GETITEM | TCM_SETITEM | TCM_ADJUSTRECT => 0,
                TCM_INSERTITEM => -1i64,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("combo") || class_name == "combobox" {
            const CB_GETCOUNT: u32 = 0x0146;
            const CB_GETLBTEXT: u32 = 0x0148;
            const CB_GETLBTEXTLEN: u32 = 0x0149;
            const CB_ADDSTRING: u32 = 0x0143;
            const CB_DELETESTRING: u32 = 0x0144;
            const CB_RESETCONTENT: u32 = 0x014B;
            const CB_SETCURSEL: u32 = 0x014E;
            const CB_GETCURSEL: u32 = 0x0147;
            const CB_SHOWDROPDOWN: u32 = 0x014F;
            const CB_INITSTORAGE: u32 = 0x0161;
            const CB_ERR: i64 = -1;
            let result = match message_id {
                CB_GETCOUNT | CB_INITSTORAGE => 0,
                CB_GETLBTEXT | CB_GETLBTEXTLEN => 0,
                CB_ADDSTRING | CB_RESETCONTENT => 0,
                CB_DELETESTRING | CB_SETCURSEL | CB_GETCURSEL => CB_ERR,
                CB_SHOWDROPDOWN => 1,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("listbox") {
            const LB_GETCOUNT: u32 = 0x018B;
            const LB_GETTEXT: u32 = 0x0189;
            const LB_GETTEXTLEN: u32 = 0x018A;
            const LB_ADDSTRING: u32 = 0x0180;
            const LB_DELETESTRING: u32 = 0x0182;
            const LB_RESETCONTENT: u32 = 0x0184;
            const LB_SETCURSEL: u32 = 0x0186;
            const LB_GETCURSEL: u32 = 0x0188;
            const LB_GETSELCOUNT: u32 = 0x0190;
            const LB_GETSELITEMS: u32 = 0x0191;
            const LB_GETITEMDATA: u32 = 0x0192;
            const LB_SETITEMDATA: u32 = 0x019A;
            const LB_INSERTSTRING: u32 = 0x0181;
            const LB_FINDSTRING: u32 = 0x018F;
            const LB_SETSEL: u32 = 0x0185;
            const LB_ERR: i64 = -1;
            let result = match message_id {
                LB_GETCOUNT | LB_GETSELCOUNT | LB_GETTEXTLEN => 0,
                LB_GETTEXT | LB_GETITEMDATA | LB_GETSELITEMS => 0,
                LB_ADDSTRING | LB_RESETCONTENT | LB_INSERTSTRING => 0,
                LB_DELETESTRING | LB_SETCURSEL | LB_GETCURSEL | LB_SETITEMDATA | LB_FINDSTRING
                | LB_SETSEL => LB_ERR,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("edit") {
            const EM_GETSEL: u32 = 0x00B0;
            const EM_SETSEL: u32 = 0x00B1;
            const EM_GETRECT: u32 = 0x00B2;
            const EM_SETRECT: u32 = 0x00B3;
            const EM_GETLIMITTEXT: u32 = 0x00D5;
            const EM_SETLIMITTEXT: u32 = 0x00C5;
            const EM_GETMODIFY: u32 = 0x0008;
            const EM_SETMODIFY: u32 = 0x0009;
            const EM_LINELENGTH: u32 = 0x00C1;
            const EM_GETLINE: u32 = 0x00C4;
            const EM_REPLACESEL: u32 = 0x00C2;
            const EM_SCROLL: u32 = 0x00B5;
            const EM_SETMARGINS: u32 = 0x00D3;
            const EM_GETMARGINS: u32 = 0x00D4;
            const EM_SCROLLCARET: u32 = 0x00B7;
            const EM_CANUNDO: u32 = 0x00C6;
            const EM_UNDO: u32 = 0x00C7;
            const EM_SETREADONLY: u32 = 0x00CF;
            let result = match message_id {
                EM_GETSEL | EM_GETRECT | EM_GETMARGINS => 0,
                EM_SETSEL | EM_SETRECT | EM_SETLIMITTEXT | EM_SETMODIFY | EM_SETREADONLY
                | EM_SETMARGINS => 0,
                EM_GETLIMITTEXT => 0x7FFFFFFEi64,
                EM_GETMODIFY | EM_CANUNDO => 0,
                EM_LINELENGTH | EM_GETLINE => 0,
                EM_REPLACESEL | EM_SCROLL => 0,
                EM_SCROLLCARET => 1,
                EM_UNDO => 0,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("button") {
            const BM_GETCHECK: u32 = 0x00F0;
            const BM_SETCHECK: u32 = 0x00F1;
            const BM_GETSTATE: u32 = 0x00F2;
            const BM_SETSTATE: u32 = 0x00F3;
            const BM_SETSTYLE: u32 = 0x00F4;
            const BM_CLICK: u32 = 0x00F5;
            const BM_GETIMAGE: u32 = 0x00F6;
            const BM_SETIMAGE: u32 = 0x00F7;
            let result = match message_id {
                BM_GETCHECK | BM_GETSTATE | BM_GETIMAGE => 0,
                BM_SETCHECK | BM_SETSTATE | BM_SETSTYLE | BM_CLICK | BM_SETIMAGE => 0,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("static") {
            const STM_SETIMAGE: u32 = 0x0172;
            const STM_GETIMAGE: u32 = 0x0173;
            const STM_SETICON: u32 = 0x0170;
            const STM_GETICON: u32 = 0x0171;
            let result = match message_id {
                STM_SETIMAGE | STM_SETICON => 0,
                STM_GETIMAGE | STM_GETICON => 0,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("updown") || class_name == "msctls_updown32" {
            const UDM_SETRANGE: u32 = 0x0461;
            const UDM_SETPOS: u32 = 0x0462;
            const UDM_GETPOS: u32 = 0x0463;
            const UDM_SETBUDDY: u32 = 0x0464;
            const UDM_GETBUDDY: u32 = 0x0465;
            const UDM_SETRANGE32: u32 = 0x0466;
            const UDM_GETRANGE: u32 = 0x0467;
            const UDM_GETACCEL: u32 = 0x0468;
            const UDM_SETACCEL: u32 = 0x0469;
            const UDM_GETBASE: u32 = 0x046A;
            const UDM_SETBASE: u32 = 0x046B;
            let result = match message_id {
                UDM_SETRANGE | UDM_SETPOS | UDM_SETBUDDY | UDM_SETRANGE32 | UDM_SETACCEL
                | UDM_SETBASE => 0,
                UDM_GETPOS | UDM_GETBUDDY | UDM_GETRANGE | UDM_GETACCEL => 0,
                UDM_GETBASE => 10,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("toolbar") || class_name == "toolbarwindow32" {
            const TB_BUTTONCOUNT: u32 = 0x0418;
            const TB_GETBUTTON: u32 = 0x0417;
            const TB_ADDBUTTONS: u32 = 0x0414;
            const TB_INSERTBUTTON: u32 = 0x0415;
            const TB_DELETEBUTTON: u32 = 0x0416;
            const TB_AUTOSIZE: u32 = 0x0421;
            const TB_GETROWS: u32 = 0x0423;
            const TB_SETBUTTONSIZE: u32 = 0x041F;
            const TB_SETBITMAPSIZE: u32 = 0x0420;
            const TB_GETRECT: u32 = 0x0419;
            const TB_GETBUTTONTEXT: u32 = 0x042D;
            const TB_GETBUTTONINFO: u32 = 0x043F;
            const TB_SETBUTTONINFO: u32 = 0x0440;
            const TB_GETSTRING: u32 = 0x044D;
            const TB_ADDBITMAP: u32 = 0x0413;
            const TB_BUTTONSTRUCTSIZE: u32 = 0x041E;
            const TB_SETIMAGELIST: u32 = 0x0430;
            const TB_GETIMAGELIST: u32 = 0x0431;
            const TB_GETDISPLAYINFO: u32 = 0x0443;
            const TB_INSERTMARK: u32 = 0x0447;
            const TB_SETEXTENDEDSTYLE: u32 = 0x0454;
            const TB_GETEXTENDEDSTYLE: u32 = 0x0455;
            const TB_SETCMDID: u32 = 0x0422;
            const TB_GETITEMDROP: u32 = 0x043B;
            const TB_GETTOOLTIPS: u32 = 0x0425;
            const TB_SETTOOLTIPS: u32 = 0x0426;
            const TB_ISBUTTONENABLED: u32 = 0x0412;
            const TB_ENABLEBUTTON: u32 = 0x0401;
            const TB_CHECKBUTTON: u32 = 0x0402;
            const TB_PRESSBUTTON: u32 = 0x0403;
            const TB_HIDEBUTTON: u32 = 0x0404;
            const TB_INDETERMINATE: u32 = 0x0405;
            const TB_MARKBUTTON: u32 = 0x0406;
            let result = match message_id {
                TB_BUTTONCOUNT | TB_GETROWS | TB_ADDBITMAP | TB_BUTTONSTRUCTSIZE
                | TB_GETEXTENDEDSTYLE | TB_GETIMAGELIST | TB_GETTOOLTIPS => 0,
                TB_GETBUTTON | TB_ADDBUTTONS | TB_INSERTBUTTON | TB_DELETEBUTTON | TB_GETRECT
                | TB_SETCMDID | TB_GETITEMDROP | TB_GETDISPLAYINFO | TB_GETBUTTONINFO
                | TB_SETBUTTONINFO => 0,
                TB_AUTOSIZE | TB_SETBUTTONSIZE | TB_SETBITMAPSIZE | TB_SETIMAGELIST
                | TB_SETTOOLTIPS | TB_SETEXTENDEDSTYLE | TB_INSERTMARK => 0,
                TB_GETBUTTONTEXT | TB_GETSTRING => 0,
                TB_ISBUTTONENABLED => 1,
                TB_ENABLEBUTTON | TB_CHECKBUTTON | TB_PRESSBUTTON | TB_HIDEBUTTON
                | TB_INDETERMINATE | TB_MARKBUTTON => 1,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("statusbar") || class_name == "msctls_statusbar32" {
            const SB_SETTEXT: u32 = 0x0401;
            const SB_GETTEXT: u32 = 0x0402;
            const SB_GETTEXTLENGTH: u32 = 0x0403;
            const SB_SETPARTS: u32 = 0x0404;
            const SB_GETPARTS: u32 = 0x0405;
            const SB_SETMINHEIGHT: u32 = 0x0408;
            const SB_SIMPLE: u32 = 0x0409;
            const SB_GETRECT: u32 = 0x040A;
            const SB_SETICON: u32 = 0x040B;
            const SB_GETICON: u32 = 0x040C;
            const SB_SETTIPTEXT: u32 = 0x0410;
            const SB_GETTIPTEXT: u32 = 0x0411;
            let result = match message_id {
                SB_SETTEXT | SB_SETPARTS | SB_SETMINHEIGHT | SB_SIMPLE | SB_SETICON
                | SB_SETTIPTEXT => 1,
                SB_GETTEXT | SB_GETTEXTLENGTH | SB_GETPARTS | SB_GETICON | SB_GETTIPTEXT
                | SB_GETRECT => 0,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        if class_name.contains("header") || class_name == "sysheader32" {
            const HDM_GETITEMCOUNT: u32 = 0x1200;
            const HDM_GETITEM: u32 = 0x1203;
            const HDM_SETITEM: u32 = 0x1204;
            const HDM_INSERTITEM: u32 = 0x1201;
            const HDM_DELETEITEM: u32 = 0x1202;
            const HDM_LAYOUT: u32 = 0x1205;
            let result = match message_id {
                HDM_GETITEMCOUNT => 0,
                HDM_GETITEM | HDM_SETITEM | HDM_DELETEITEM | HDM_LAYOUT => 0,
                HDM_INSERTITEM => -1i64,
                _ => return Ok(None),
            };
            return Ok(Some(result));
        }
        Ok(None)
    }

    pub(crate) fn export_final_frame_if_requested(
        &self,
        env: &BTreeMap<String, String>,
    ) -> AppResult<()> {
        let Some(path) = env.get(EXPORT_FINAL_FRAME_ENV).map(String::as_str) else {
            return Ok(());
        };
        if path.trim().is_empty() {
            return Ok(());
        }
        let export_path = Path::new(path);
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to create {}", parent.display()),
                    &error,
                )
            })?;
        }
        let Some(device) = self
            .d3d11_devices
            .values()
            .find(|device| device.swapchain_object.is_some())
        else {
            return Ok(());
        };
        device.device.export_presented_frame_ppm(export_path)
    }
}
