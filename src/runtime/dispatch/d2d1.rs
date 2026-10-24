//! Direct2D/DirectWrite handlers and the GDI+ drawing helpers, moved out of
//! the runtime monolith as inherent `PeHostRuntime` impls.

use super::super::*;

impl PeHostRuntime {
    // ── D2D/DWrite dispatch handlers (Phase 3.6) ──────────────────────

    pub(crate) fn dispatch_d2d1_factory_create_stroke_style(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _factory = state.get(Register::Rcx);
        let _props_ptr = state.get(Register::Rdx);
        let _dashes_ptr = state.get(Register::R8);
        let _dashes_count = state.get(Register::R9) as u32;
        let sp = state.get(Register::Rsp);
        let style_ptr = memory.read_u64(sp + 0x20)?;
        if style_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1StrokeStyle::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let style_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1StrokeStyle, vtable)?;
            write_u64(memory, style_ptr, style_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1Factory::CreateStrokeStyle",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d2d1_factory_create_drawing_state_block(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _factory = state.get(Register::Rcx);
        let _desc_ptr = state.get(Register::Rdx);
        let _text_ptr = state.get(Register::R8);
        let _state_block_ptr = state.get(Register::R9);
        let block_ptr = state.get(Register::R9);
        if block_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1DrawingStateBlock::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let block_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1DrawingStateBlock, vtable)?;
            write_u64(memory, block_ptr, block_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1Factory::CreateDrawingStateBlock",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d2d1_hwnd_render_target_create_solid_color_brush(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _target = state.get(Register::Rcx);
        let _color_ptr = state.get(Register::Rdx);
        let _alpha = state.get(Register::R8) as u32;
        let sp = state.get(Register::Rsp);
        let brush_ptr = memory.read_u64(sp + 0x20)?;
        if brush_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1SolidColorBrush::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                HostThunk::ID2D1SolidColorBrush_SetColor,
                HostThunk::ID2D1SolidColorBrush_SetOpacity,
                HostThunk::ID2D1SolidColorBrush_Release,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let brush_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1Brush, vtable)?;
            write_u64(memory, brush_ptr, brush_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1HwndRenderTarget::CreateSolidColorBrush",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d2d1_hwnd_render_target_create_linear_gradient_brush(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _target = state.get(Register::Rcx);
        let _props_ptr = state.get(Register::Rdx);
        let _colors_ptr = state.get(Register::R8);
        let sp = state.get(Register::Rsp);
        let brush_ptr = memory.read_u64(sp + 0x20)?;
        if brush_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1LinearGradientBrush::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let brush_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1Brush, vtable)?;
            write_u64(memory, brush_ptr, brush_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1HwndRenderTarget::CreateLinearGradientBrush",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d2d1_hwnd_render_target_create_radial_gradient_brush(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _target = state.get(Register::Rcx);
        let _props_ptr = state.get(Register::Rdx);
        let _colors_ptr = state.get(Register::R8);
        let sp = state.get(Register::Rsp);
        let brush_ptr = memory.read_u64(sp + 0x20)?;
        if brush_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1RadialGradientBrush::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let brush_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1Brush, vtable)?;
            write_u64(memory, brush_ptr, brush_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1HwndRenderTarget::CreateRadialGradientBrush",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d2d1_hwnd_render_target_create_bitmap(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _target = state.get(Register::Rcx);
        let _size_ptr = state.get(Register::Rdx);
        let _data_ptr = state.get(Register::R8);
        let _pitch = state.get(Register::R9) as u32;
        let sp = state.get(Register::Rsp);
        let _props_ptr = memory.read_u64(sp + 0x20)?;
        let bitmap_ptr = memory.read_u64(sp + 0x28)?;
        if bitmap_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1Bitmap::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                HostThunk::ID2D1Bitmap_Release,
                HostThunk::ID2D1Bitmap_GetSize,
                HostThunk::ID2D1Bitmap_GetDpi,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let bitmap_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1Bitmap, vtable)?;
            write_u64(memory, bitmap_ptr, bitmap_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1HwndRenderTarget::CreateBitmap",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    pub(crate) fn dispatch_d2d1_hwnd_render_target_create_compatible_render_target(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let _target = state.get(Register::Rcx);
        let _desired_size = state.get(Register::Rdx);
        let _desired_pixel_size = state.get(Register::R8);
        let _desired_format = state.get(Register::R9) as u32;
        let sp = state.get(Register::Rsp);
        let _compat_options = memory.read_u32(sp + 0x20)?;
        let target_ptr = memory.read_u64(sp + 0x28)?;
        if target_ptr != 0 {
            let methods = vec![
                unsupported_method(&self.telemetry, "ID2D1BitmapRenderTarget::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let target_object =
                self.alloc_guest_object(memory, GuestObjectKind::D2d1RenderTarget, vtable)?;
            write_u64(memory, target_ptr, target_object);
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d2d1",
            "ID2D1HwndRenderTarget::CreateCompatibleRenderTarget",
            BTreeMap::new(),
            json!(0),
        );
        Ok(())
    }

    // ── GDI+ drawing helpers ──────────────────────────────────────────

    /// Resolve a graphics object's drawing environment: the raster target
    /// (GDI+ bitmap, window surface, or memory-DC bitmap), the compositing /
    /// smoothing modes, the world transform and the world-space clip rect.
    pub(crate) fn gdiplus_graphics_info(&self, graphics: u64) -> Option<GdiplusGraphicsInfo> {
        let gfx = match self.user32.gdiplus_state.get(graphics) {
            Some(GdiplusObject::Graphics(g)) => g,
            _ => return None,
        };
        let world = match gfx.world_transform {
            Some(handle) => match self.user32.gdiplus_state.get(handle) {
                Some(GdiplusObject::Matrix(m)) => m.elements,
                _ => gdiplus_matrix_identity(),
            },
            None => gdiplus_matrix_identity(),
        };
        let target = if let Some(tb) = gfx.target_bitmap {
            Some(GdiplusTargetKind::Bitmap(tb))
        } else if gfx.hdc != 0 {
            if let Some(hwnd) = self.device_contexts.get(&gfx.hdc).copied().flatten() {
                Some(GdiplusTargetKind::Window(hwnd))
            } else if self.dc_selected_objects.contains_key(&gfx.hdc) {
                Some(GdiplusTargetKind::MemoryDc(gfx.hdc))
            } else {
                None
            }
        } else {
            None
        };
        Some(GdiplusGraphicsInfo {
            target,
            state: GdiplusRenderState {
                cm: gfx.compositing_mode,
                sm: gfx.smoothing_mode,
                interp: gfx.interpolation_mode,
                clip: gfx.clip_rect,
                clip_region: gfx.clip_region.clone(),
                world,
            },
        })
    }

    /// The world transform of a graphics object (identity when unset).
    pub(crate) fn gdiplus_world_matrix(&self, graphics: u64) -> [f32; 6] {
        match self.user32.gdiplus_state.get(graphics) {
            Some(GdiplusObject::Graphics(gfx)) => match gfx.world_transform {
                Some(handle) => match self.user32.gdiplus_state.get(handle) {
                    Some(GdiplusObject::Matrix(m)) => m.elements,
                    _ => gdiplus_matrix_identity(),
                },
                None => gdiplus_matrix_identity(),
            },
            _ => gdiplus_matrix_identity(),
        }
    }

    /// The graphics object's current clip as a device-space scanned region:
    /// the rect clip (mapped through the world transform) intersected with any
    /// scanned region.  `None` when the graphics handle is invalid.
    pub(crate) fn gdiplus_effective_clip_region(
        &self,
        graphics: u64,
    ) -> Option<crate::user32::GdiplusRegion> {
        let gfx = match self.user32.gdiplus_state.get(graphics) {
            Some(GdiplusObject::Graphics(g)) => g,
            _ => return None,
        };
        let world = self.gdiplus_world_matrix(graphics);
        let rect_region = gfx.clip_rect.map(|(x, y, w, h)| {
            if gdiplus_matrix_axis_aligned(&world) {
                // An axis-aligned rect clip maps to an exact half-open rect.
                let (bx, by, bw, bh) = gdiplus_matrix_rect_bounds(&world, x, y, w, h);
                crate::user32::GdiplusRegion::from_rect(bx, by, bw, bh)
            } else {
                let corners = [
                    gdiplus_matrix_apply(&world, x, y),
                    gdiplus_matrix_apply(&world, x + w, y),
                    gdiplus_matrix_apply(&world, x + w, y + h),
                    gdiplus_matrix_apply(&world, x, y + h),
                ];
                let points: Vec<GdiplusPointF> = corners
                    .iter()
                    .map(|&(cx, cy)| GdiplusPointF { x: cx, y: cy })
                    .collect();
                crate::user32::GdiplusRegion::from_spans(
                    crate::gdiplus_render::polygon_scanlines(&points),
                    false,
                )
            }
        });
        let region = match (&gfx.clip_region, rect_region) {
            (Some(region), Some(rect)) => region.intersect(&rect),
            (Some(region), None) => (**region).clone(),
            (None, Some(rect)) => rect,
            (None, None) => crate::user32::GdiplusRegion::infinite(),
        };
        Some(region)
    }

    /// Resolve a pen into concrete drawing style, sampling brush-backed pens
    /// at `(sample_x, sample_y)` (world coordinates).
    pub(crate) fn gdiplus_pen_style(
        &self,
        pen_handle: u64,
        sample_x: f32,
        sample_y: f32,
    ) -> Option<GdiplusStrokeStyle> {
        let pen = match self.user32.gdiplus_state.get(pen_handle) {
            Some(GdiplusObject::Pen(p)) => p,
            _ => return None,
        };
        let color = match pen.brush_handle {
            Some(brush_handle) => self.gdiplus_brush_color(brush_handle, sample_x, sample_y),
            None => None,
        }
        .unwrap_or(pen.color);
        Some(GdiplusStrokeStyle {
            color,
            width_px: gdiplus_unit_to_pixels(pen.width, pen.unit).max(0.0),
            dash: pen.dash_style,
            join: pen.line_join,
            start_cap: pen.start_cap,
            end_cap: pen.end_cap,
            cm: 0,
            sm: 0,
        })
    }

    /// Resolve a brush's colour at a world-space point (solid brushes are
    /// exact; linear-gradient and texture brushes are sampled at the point,
    /// with texture data read from the brush's image).
    pub(crate) fn gdiplus_brush_color(&self, brush_handle: u64, px: f32, py: f32) -> Option<u32> {
        let tex_image_handle = match self.user32.gdiplus_state.get(brush_handle) {
            Some(GdiplusObject::Brush(brush)) => match brush.as_ref() {
                GdiplusBrush::Texture(tb) => Some(tb.image_handle),
                _ => None,
            },
            _ => return None,
        };
        let tex_data: Option<(&[u8], u32, u32, i32)> = tex_image_handle.and_then(|image_handle| {
            self.user32.gdiplus_state.get(image_handle).and_then(|obj| {
                if let GdiplusObject::Image(img) = obj {
                    match img.as_ref() {
                        GdiplusImage::Bitmap(bmp) => {
                            Some((bmp.pixels.as_slice(), bmp.width, bmp.height, bmp.stride))
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            })
        });
        self.user32.gdiplus_state.get(brush_handle).and_then(|obj| {
            if let GdiplusObject::Brush(brush) = obj {
                Some(crate::gdiplus_render::brush_color_at(
                    brush, px, py, tex_data,
                ))
            } else {
                None
            }
        })
    }

    /// Run a raster operation against the pixels of a graphics object's
    /// surface.  The closure receives the raw top-down ARGB pixel buffer and
    /// its geometry; memory-DC targets are refreshed from guest memory before
    /// the draw and mirrored back afterwards, and window surfaces are marked
    /// as carrying real guest pixels and published to the live channel.
    pub(crate) fn gdiplus_paint(
        &mut self,
        memory: &mut MemoryImage,
        graphics: u64,
        op: impl FnOnce(&mut [u8], u32, u32, i32),
    ) -> GdiplusStatus {
        let Some(info) = self.gdiplus_graphics_info(graphics) else {
            return GdiplusStatus::InvalidParameter;
        };
        let Some(target) = info.target else {
            return GdiplusStatus::InvalidParameter;
        };
        let clip_region = info.state.clip_region.clone();
        match target {
            GdiplusTargetKind::Bitmap(handle) => {
                let Some(GdiplusObject::Image(img)) = self.user32.gdiplus_state.get_mut(handle)
                else {
                    return GdiplusStatus::InvalidParameter;
                };
                let GdiplusImage::Bitmap(bmp) = &mut **img else {
                    return GdiplusStatus::InvalidParameter;
                };
                gdiplus_paint_with_region_clip(
                    &mut bmp.pixels,
                    bmp.width,
                    bmp.height,
                    bmp.stride,
                    clip_region.as_deref(),
                    op,
                );
            }
            GdiplusTargetKind::Window(hwnd) => {
                let preview = match self
                    .user32
                    .window_previews()
                    .into_iter()
                    .find(|window| window.hwnd == hwnd)
                {
                    Some(p) => p,
                    None => return GdiplusStatus::InvalidParameter,
                };
                let w = (preview.width as usize).max(1);
                let h = (preview.height as usize).max(1);
                let surface = self
                    .window_surfaces
                    .entry(hwnd)
                    .or_insert_with(|| WindowSurface {
                        width: w,
                        height: h,
                        bytes: vec![0; w.saturating_mul(h).saturating_mul(4)],
                        real_pixels: false,
                    });
                if surface.width != w || surface.height != h {
                    surface.width = w;
                    surface.height = h;
                    surface.bytes = vec![0; w.saturating_mul(h).saturating_mul(4)];
                    surface.real_pixels = false;
                }
                let stride = (surface.width * 4) as i32;
                let width = surface.width as u32;
                let height = surface.height as u32;
                gdiplus_paint_with_region_clip(
                    &mut surface.bytes,
                    width,
                    height,
                    stride,
                    clip_region.as_deref(),
                    op,
                );
                surface.real_pixels = true;
                self.publish_live_window_preview_if_needed();
            }
            GdiplusTargetKind::MemoryDc(hdc) => {
                let object = match self.dc_selected_objects.get(&hdc).copied() {
                    Some(o) => o,
                    None => return GdiplusStatus::InvalidParameter,
                };
                let Some(bitmap) = self.gdi_bitmaps.get_mut(&object) else {
                    return GdiplusStatus::InvalidParameter;
                };
                // Refresh the host mirror: the guest may have written the DIB
                // pixels directly through the DIB section pointer.
                if bitmap.guest_pixel_ptr != 0
                    && !bitmap.bytes.is_empty()
                    && let Ok(slice) = memory.read_bytes(bitmap.guest_pixel_ptr, bitmap.bytes.len())
                    && slice.len() == bitmap.bytes.len()
                {
                    bitmap.bytes.copy_from_slice(&slice);
                }
                let w = bitmap.width as u32;
                let h = bitmap.height as u32;
                let mut scratch = gdiplus_bitmap_to_argb(bitmap).unwrap_or_default();
                if scratch.len() >= w as usize * h as usize * 4 {
                    gdiplus_paint_with_region_clip(
                        &mut scratch,
                        w,
                        h,
                        w as i32 * 4,
                        clip_region.as_deref(),
                        op,
                    );
                }
                if let Some(native) = gdiplus_argb_to_bitmap(bitmap, &scratch) {
                    bitmap.bytes = native;
                }
                // Mirror the result back into guest memory.
                if bitmap.guest_pixel_ptr != 0 && !bitmap.bytes.is_empty() {
                    for (i, &byte) in bitmap.bytes.iter().enumerate() {
                        memory.write_u8(bitmap.guest_pixel_ptr + i as u64, byte);
                    }
                }
            }
        }
        GdiplusStatus::Ok
    }

    /// Stroke a world-space polyline through the full pipeline: world
    /// transform, dash pattern, device-space clipping and pen caps/joins.
    /// Closed polylines join their last point back to the first.
    pub(crate) fn gdiplus_paint_stroke(
        &mut self,
        memory: &mut MemoryImage,
        graphics: u64,
        style: &GdiplusStrokeStyle,
        world_points: &[GdiplusPointF],
        closed: bool,
    ) -> GdiplusStatus {
        if world_points.len() < 2 {
            return GdiplusStatus::Ok;
        }
        let Some(info) = self.gdiplus_graphics_info(graphics) else {
            return GdiplusStatus::InvalidParameter;
        };
        let scale = gdiplus_matrix_scale(&info.state.world);
        let width_px = if scale > 0.0 && (scale - 1.0).abs() > 1e-4 {
            style.width_px * scale
        } else {
            style.width_px
        };
        let mut style = *style;
        style.width_px = width_px.max(0.01);
        style.cm = info.state.cm;
        style.sm = info.state.sm;
        let world = &info.state.world;
        let dev: Vec<GdiplusPointF> = world_points
            .iter()
            .map(|p| {
                let (x, y) = gdiplus_matrix_apply(world, p.x, p.y);
                GdiplusPointF { x, y }
            })
            .collect();
        let clip_quad = gdiplus_device_clip_quad(world, info.state.clip);
        if clip_quad.is_none() && style.dash == crate::user32::GDIPLUS_DASH_STYLE_SOLID {
            // Draw the (possibly closed) polyline directly.
            let mut chain = dev.clone();
            if closed && chain.len() >= 2 {
                let first = chain[0];
                chain.push(first);
            }
            return self.gdiplus_paint(memory, graphics, |px, w, h, s| {
                gdiplus_render_stroke_chain(px, w, h, s, &chain, &style, false, false);
            });
        }
        // Dash first (device space), then clip each span.
        let mut chains: Vec<Vec<GdiplusPointF>> =
            if style.dash == crate::user32::GDIPLUS_DASH_STYLE_SOLID {
                vec![dev.clone()]
            } else {
                gdiplus_dash_spans(&dev, closed, style.dash, style.width_px)
            };
        if chains.is_empty() {
            return GdiplusStatus::Ok;
        }
        if let Some(clip) = &clip_quad {
            chains = chains
                .into_iter()
                .flat_map(|span| {
                    let mut clipped: Vec<Vec<GdiplusPointF>> = Vec::new();
                    let mut run: Vec<GdiplusPointF> = Vec::new();
                    for pair in span.windows(2) {
                        if let Some(((ax, ay), (bx, by))) =
                            gdiplus_clip_segment(pair[0].x, pair[0].y, pair[1].x, pair[1].y, clip)
                        {
                            if run.is_empty() {
                                run.push(GdiplusPointF { x: ax, y: ay });
                            }
                            run.push(GdiplusPointF { x: bx, y: by });
                        } else if !run.is_empty() {
                            clipped.push(std::mem::take(&mut run));
                        }
                    }
                    if !run.is_empty() {
                        clipped.push(run);
                    }
                    clipped
                })
                .collect();
        }
        if chains.is_empty() {
            return GdiplusStatus::Ok;
        }
        self.gdiplus_paint(memory, graphics, |px, w, h, s| {
            for chain in &chains {
                gdiplus_render_stroke_chain(
                    px,
                    w,
                    h,
                    s,
                    chain,
                    &style,
                    true,
                    style.dash != crate::user32::GDIPLUS_DASH_STYLE_SOLID,
                );
            }
        })
    }

    /// Fill world-space polygons through the transform + clip pipeline.
    /// Each polygon is treated as a closed figure.
    pub(crate) fn gdiplus_paint_fill(
        &mut self,
        memory: &mut MemoryImage,
        graphics: u64,
        color: u32,
        world_figures: &[Vec<GdiplusPointF>],
    ) -> GdiplusStatus {
        let Some(info) = self.gdiplus_graphics_info(graphics) else {
            return GdiplusStatus::InvalidParameter;
        };
        let world = &info.state.world;
        let clip_quad = gdiplus_device_clip_quad(world, info.state.clip);
        let mut dev_figures: Vec<Vec<GdiplusPointF>> = Vec::new();
        for figure in world_figures {
            if figure.len() < 3 {
                continue;
            }
            let mapped: Vec<GdiplusPointF> = figure
                .iter()
                .map(|p| {
                    let (x, y) = gdiplus_matrix_apply(world, p.x, p.y);
                    GdiplusPointF { x, y }
                })
                .collect();
            if let Some(clip) = &clip_quad {
                let clipped = gdiplus_clip_polygon(&mapped, clip);
                if clipped.len() >= 3 {
                    dev_figures.push(clipped);
                }
            } else {
                dev_figures.push(mapped);
            }
        }
        if dev_figures.is_empty() {
            return GdiplusStatus::Ok;
        }
        self.gdiplus_paint(memory, graphics, |px, w, h, s| {
            for figure in &dev_figures {
                crate::gdiplus_render::fill_polygon(px, w, h, s, figure, color, info.state.cm);
            }
        })
    }

    /// Blit a source bitmap through the world transform with optional clip,
    /// colour key and colour matrix.  Axis-aligned destinations are exact
    /// (destination rect ∩ clip rect with a proportional source crop);
    /// rotated destinations are genuinely unsupported by the software
    /// rasterizer and report NotImplemented.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn gdiplus_blit_image(
        &mut self,
        memory: &mut MemoryImage,
        graphics: u64,
        info: &GdiplusGraphicsInfo,
        src_pixels: Vec<u8>,
        src_width: u32,
        src_height: u32,
        src_stride: i32,
        src_x: f32,
        src_y: f32,
        src_w: f32,
        src_h: f32,
        dst_x: f32,
        dst_y: f32,
        dst_w: f32,
        dst_h: f32,
        color_key: Option<(u32, u32)>,
        color_matrix: Option<[[f32; 5]; 5]>,
    ) -> GdiplusStatus {
        if dst_w <= 0.0 || dst_h <= 0.0 || src_w <= 0.0 || src_h <= 0.0 {
            return GdiplusStatus::Ok;
        }
        let world = &info.state.world;
        if !gdiplus_matrix_axis_aligned(world) {
            return GdiplusStatus::NotImplemented;
        }
        let (ddx, ddy, ddw, ddh) = gdiplus_matrix_rect_bounds(world, dst_x, dst_y, dst_w, dst_h);
        let mut vis = (ddx, ddy, ddw, ddh);
        if let Some(clip) = info.state.clip {
            let (cx, cy, cw, ch) =
                gdiplus_matrix_rect_bounds(world, clip.0, clip.1, clip.2, clip.3);
            let nx0 = vis.0.max(cx);
            let ny0 = vis.1.max(cy);
            let nx1 = (vis.0 + vis.2).min(cx + cw);
            let ny1 = (vis.1 + vis.3).min(cy + ch);
            vis = (nx0, ny0, (nx1 - nx0).max(0.0), (ny1 - ny0).max(0.0));
        }
        if vis.2 <= 0.0 || vis.3 <= 0.0 {
            return GdiplusStatus::Ok;
        }
        // Crop the source to the visible destination region.
        let crop_sx = src_x + (vis.0 - ddx) / ddw * src_w;
        let crop_sy = src_y + (vis.1 - ddy) / ddh * src_h;
        let crop_sw = src_w * vis.2 / ddw;
        let crop_sh = src_h * vis.3 / ddh;
        let bilinear = matches!(
            info.state.interp,
            2 | 3 | 4 | 6 | 7 // HighQuality/Bilinear/Bicubic/HighQualityBilinear/HighQualityBicubic
        );
        let cm = info.state.cm;
        self.gdiplus_paint(memory, graphics, |px, pw, ph, ps| {
            crate::gdiplus_render::draw_image_ex(
                px,
                pw,
                ph,
                ps,
                &src_pixels,
                src_width,
                src_height,
                src_stride,
                crop_sx,
                crop_sy,
                crop_sw,
                crop_sh,
                vis.0,
                vis.1,
                vis.2,
                vis.3,
                color_key,
                color_matrix,
                bilinear,
                cm,
            );
        })
    }

    /// Decode a GpRegion reference.  Two representations exist:
    ///
    /// * a live region handle from the GDI+ object table (created by
    ///   `GdipMeasureCharacterRanges` and the path-clip machinery), or
    /// * the byte encoding `GdipGetClip` writes (u32 type: 0 = infinite,
    ///   1 = rect followed by four i32 bounds).
    ///
    /// `Err` is an undecodable pointer/handle.
    pub(crate) fn gdiplus_decode_region(
        &self,
        memory: &MemoryImage,
        region: u64,
    ) -> Result<GdiplusDecodedRegion, ()> {
        if region == 0 {
            return Err(());
        }
        // A live region handle resolves through the object table first; its
        // exact rectangle is exposed when the spans form one, otherwise the
        // scanned region is returned as-is.
        if let Some(GdiplusObject::Region(scanned)) = self.user32.gdiplus_state.get(region) {
            return Ok(match scanned.as_rect() {
                Some(rect) => GdiplusDecodedRegion::Rect(rect),
                None => GdiplusDecodedRegion::Scanned(Box::new((**scanned).clone())),
            });
        }
        let Ok(region_type) = read_u32(memory, region) else {
            return Err(());
        };
        match region_type {
            0 => Ok(GdiplusDecodedRegion::Infinite), // RegionDataTypeInfinite
            1 => {
                let (Ok(x), Ok(y), Ok(w), Ok(h)) = (
                    read_u32(memory, region + 4),
                    read_u32(memory, region + 8),
                    read_u32(memory, region + 12),
                    read_u32(memory, region + 16),
                ) else {
                    return Err(());
                };
                Ok(GdiplusDecodedRegion::Rect((
                    x as i32 as f32,
                    y as i32 as f32,
                    w as i32 as f32,
                    h as i32 as f32,
                )))
            }
            _ => Err(()),
        }
    }

    pub(crate) fn gdiplus_pixel_count(format: u32) -> Option<u32> {
        match format {
            crate::user32::GDIPLUS_PIXEL_FORMAT_24BPP_RGB => Some(24),
            crate::user32::GDIPLUS_PIXEL_FORMAT_32BPP_ARGB
            | crate::user32::GDIPLUS_PIXEL_FORMAT_32BPP_PARGB => Some(32),
            _ => None,
        }
    }
}
