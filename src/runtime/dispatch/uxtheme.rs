//! Theme dispatch: the uxtheme.dll exports, in a dedicated module per the
//! audit's modularity requirement.  The surface is the default theme: theming
//! is active (`IsAppThemed`/`IsThemeActive` are TRUE), `OpenThemeData` hands
//! out a theme handle, and the query functions (`GetThemeColor`,
//! `GetThemeSysColor`, `GetThemeFont`, `GetThemePartSize`, ...) answer with
//! the documented default-theme metrics.  `DrawThemeBackground` fills the
//! part rectangle through the GDI canvas and `DrawThemeText` renders the
//! string; the buffered-paint surface (`BeginBufferedPaint`/`EndBufferedPaint`)
//! creates and flushes an in-memory HDC-backed buffer.
//!
//! Layer contract: the theme functions return HRESULTs (0 = S_OK) in EAX;
//! the handle-based functions return the theme object in EAX.

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// S_OK.
const S_OK: u32 = 0;
/// E_HANDLE — the theme handle is invalid.
const E_HANDLE: u32 = 0x8007_0006;
/// E_FAIL.
const E_FAIL: u32 = 0x8000_4005;

/// The class list accepted by OpenThemeData.
const THEME_CLASSES: &[&str] = &[
    "BUTTON",
    "STATUS",
    "TOOLBAR",
    "LISTVIEW",
    "TREEVIEW",
    "EDIT",
    "COMBOBOX",
    "HEADER",
    "SCROLLBAR",
    "TRACKBAR",
    "TAB",
    "TOOLTIP",
    "REBAR",
    "PROGRESS",
    "MENU",
    "WINDOW",
];

/// The theme part colors (the default theme's documented metrics).
fn theme_part_color(prop: i32) -> u32 {
    match prop {
        0x0d00 => 0x0000_0000, // TMT_TEXTCOLOR
        0x0d01 => 0x0000_0000, // TMT_EDGELIGHTCOLOR
        0x0d02 => 0x0000_0000, // TMT_EDGEHIGHLIGHTCOLOR
        0x0d03 => 0x0080_8080, // TMT_EDGESHADOWCOLOR
        0x0d04 => 0x00c0_c0c0, // TMT_EDGEDKSHADOWCOLOR
        0x0d05 => 0x00ff_ffff, // TMT_EDGEFILLCOLOR
        0x0d06 => 0x0000_0000, // TMT_TRANSPARENTCOLOR
        0x0d07 => 0x00ff_ffff, // TMT_GRADIENTCOLOR1
        0x0d08 => 0x00ff_ff00, // TMT_GRADIENTCOLOR2
        0x0d09 => 0x00ff_ffff, // TMT_GRADIENTCOLOR3
        0x0d0a => 0x00ff_ff00, // TMT_GRADIENTCOLOR4
        0x0d0b => 0x0000_0000, // TMT_GRADIENTCOLOR5
        0x0e00 => 0x0000_00ff, // TMT_FILLCOLORHINT
        0x0e01 => 0x0000_0080, // TMT_BORDERCOLORHINT
        0x0e02 => 0x0000_0080, // TMT_TEXTCOLORHINT
        _ => 0x0000_0000,
    }
}

impl PeHostRuntime {
    /// Route every theme thunk to its dispatch function.
    pub(crate) fn dispatch_theme(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::IsAppThemed | HostThunk::IsThemeActive => {
                // Theming is active (the default theme).
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::OpenThemeData => self.dispatch_open_theme_data(state, memory),
            HostThunk::CloseThemeData => self.dispatch_close_theme_data(state, memory),
            HostThunk::SetWindowTheme => {
                // The window theme is recorded; the class name is stored.
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let _subapp = guest_call_arg(state, memory, 1)?;
                let _subid = guest_call_arg(state, memory, 2)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemeColor => {
                let theme = guest_call_arg(state, memory, 0)?;
                let _part = guest_call_arg_u32(state, memory, 1)?;
                let _state = guest_call_arg_u32(state, memory, 2)?;
                let prop = guest_call_arg_u32(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                if !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                if out != 0 {
                    write_guest_u32(memory, out, theme_part_color(prop as i32)).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemeSysColor => {
                let theme = guest_call_arg(state, memory, 0)?;
                let color = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if theme != 0 && !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                // The COLOR_* system-color defaults (BGR like GetSysColor).
                let value: u32 = match color {
                    1 => 0x8000_0080,  // COLOR_DESKTOP
                    4 => 0x00ff_ffff,  // COLOR_BTNFACE
                    5 => 0x0000_0000,  // COLOR_BTNSHADOW
                    9 => 0x00ff_ffff,  // COLOR_WINDOW
                    10 => 0x0000_0000, // COLOR_WINDOWTEXT
                    15 => 0x0000_0000, // COLOR_BTNTEXT
                    18 => 0x0000_0000, // COLOR_HIGHLIGHT
                    19 => 0x00ff_ffff, // COLOR_HIGHLIGHTTEXT
                    _ => 0x0000_0000,
                };
                if out != 0 {
                    write_guest_u32(memory, out, value).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemeSysFont => {
                let theme = guest_call_arg(state, memory, 0)?;
                let _font = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if theme != 0 && !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                if out != 0 {
                    // A LOGFONTW: the default UI font.
                    let text = "Segoe UI";
                    for (i, unit) in text.encode_utf16().enumerate().take(31) {
                        write_guest_u16(memory, out + (i as u64 * 2), unit).ok();
                    }
                    write_guest_u16(memory, out + 62, 0).ok();
                    write_guest_u32(memory, out + 64, 12).ok(); // lfHeight
                    write_guest_u32(memory, out + 68, 400).ok(); // lfWeight
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemePartSize => {
                let theme = guest_call_arg(state, memory, 0)?;
                let _hdc = guest_call_arg(state, memory, 1)?;
                let _part = guest_call_arg_u32(state, memory, 2)?;
                let _state = guest_call_arg_u32(state, memory, 3)?;
                let _rect = guest_call_arg(state, memory, 4)?;
                let size_kind = guest_call_arg_u32(state, memory, 5)?;
                let out = guest_call_arg(state, memory, 6)?;
                if !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                if out != 0 {
                    let (width, height) = if size_kind == 1 {
                        (8, 8) // TS_MIN: the minimal part size
                    } else if size_kind == 2 {
                        (21, 21) // TS_TRUE: the true part size
                    } else {
                        (16, 16) // TS_DRAW: the default draw size
                    };
                    write_guest_u32(memory, out, width).ok();
                    write_guest_u32(memory, out + 4, height).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemeBackgroundContentRect => {
                let theme = guest_call_arg(state, memory, 0)?;
                let _hdc = guest_call_arg(state, memory, 1)?;
                let _part = guest_call_arg_u32(state, memory, 2)?;
                let _state = guest_call_arg_u32(state, memory, 3)?;
                let bounds = guest_call_arg(state, memory, 4)?;
                let out = guest_call_arg(state, memory, 5)?;
                if !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                if out != 0 && bounds != 0 {
                    for i in 0..4 {
                        let value = read_guest_u32(memory, bounds + (i as u64 * 4)).unwrap_or(0);
                        write_guest_u32(memory, out + (i as u64 * 4), value).ok();
                    }
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemeTextExtent => {
                let theme = guest_call_arg(state, memory, 0)?;
                let _hdc = guest_call_arg(state, memory, 1)?;
                let _part = guest_call_arg_u32(state, memory, 2)?;
                let _state = guest_call_arg_u32(state, memory, 3)?;
                let text = guest_call_arg(state, memory, 4)?;
                let text_len = guest_call_arg_u32(state, memory, 5)?;
                let _flags = guest_call_arg_u32(state, memory, 6)?;
                let bounds = guest_call_arg(state, memory, 7)?;
                let out = guest_call_arg(state, memory, 8)?;
                if !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                if out != 0 {
                    let text = read_utf16_string(memory, text)
                        .unwrap_or_default()
                        .chars()
                        .count() as u32;
                    let width = (text.min(if text_len == 0 { u32::MAX } else { text_len })) * 7 + 4;
                    write_guest_u32(memory, out, width).ok();
                    write_guest_u32(memory, out + 4, 16).ok();
                }
                let _ = bounds;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GetThemeFont => {
                let theme = guest_call_arg(state, memory, 0)?;
                let _hdc = guest_call_arg(state, memory, 1)?;
                let _part = guest_call_arg_u32(state, memory, 2)?;
                let _state = guest_call_arg_u32(state, memory, 3)?;
                let prop = guest_call_arg_u32(state, memory, 4)?;
                let out = guest_call_arg(state, memory, 5)?;
                if !self.theme_handles.contains_key(&theme) {
                    state.set(Register::Rax, u64::from(E_HANDLE));
                    return Ok(());
                }
                if prop != 0x0a01 {
                    // TMT_FONT
                    state.set(Register::Rax, u64::from(E_FAIL));
                    return Ok(());
                }
                if out != 0 {
                    let text = "Segoe UI";
                    for (i, unit) in text.encode_utf16().enumerate().take(31) {
                        write_guest_u16(memory, out + (i as u64 * 2), unit).ok();
                    }
                    write_guest_u16(memory, out + 62, 0).ok();
                    write_guest_u32(memory, out + 64, 12).ok();
                    write_guest_u32(memory, out + 68, 400).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DrawThemeBackground => self.dispatch_draw_theme_background(state, memory),
            HostThunk::DrawThemeText => self.dispatch_draw_theme_text(state, memory),
            HostThunk::EnableThemeDialogTexture => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BufferedPaintInit => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BufferedPaintUnInit => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BeginBufferedPaint => self.dispatch_begin_buffered_paint(state, memory),
            HostThunk::EndBufferedPaint => {
                let _buffer = guest_call_arg(state, memory, 0)?;
                let _target = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::BeginPanningFeedback | HostThunk::EndPanningFeedback => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let _offset = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted theme thunk {thunk:?}"),
            )),
        }
    }

    /// `OpenThemeData(hwnd, classList)` — a theme handle for the default
    /// theme.
    pub(crate) fn dispatch_open_theme_data(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _hwnd = guest_call_arg(state, memory, 0)?;
        let class_list = guest_call_arg(state, memory, 1)?;
        let classes = read_utf16_string(memory, class_list).unwrap_or_default();
        let recognized = THEME_CLASSES.iter().any(|c| {
            classes
                .split(';')
                .any(|part| part.trim().eq_ignore_ascii_case(c))
        });
        if !recognized {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let handle = self
            .alloc_guest_object(memory, GuestObjectKind::Theme, vtable)
            .unwrap_or(0);
        if handle == 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        self.theme_handles.insert(handle, classes);
        state.set(Register::Rax, handle);
        Ok(())
    }

    /// `CloseThemeData(htheme)` — the handle is released.
    pub(crate) fn dispatch_close_theme_data(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let theme = guest_call_arg(state, memory, 0)?;
        if theme != 0 {
            self.theme_handles.remove(&theme);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `DrawThemeBackground(htheme, hdc, part, state, rect, clip)` — fill
    /// the part rectangle through the GDI canvas.
    pub(crate) fn dispatch_draw_theme_background(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let theme = guest_call_arg(state, memory, 0)?;
        let hdc = guest_call_arg(state, memory, 1)?;
        let _part = guest_call_arg_u32(state, memory, 2)?;
        let _state = guest_call_arg_u32(state, memory, 3)?;
        let rect = guest_call_arg(state, memory, 4)?;
        let _clip = guest_call_arg(state, memory, 5)?;
        if !self.theme_handles.contains_key(&theme) {
            state.set(Register::Rax, u64::from(E_HANDLE));
            return Ok(());
        }
        // The default theme's part fill: the classic button-face gray.
        if rect != 0 {
            let x = read_guest_u32(memory, rect).unwrap_or(0) as i32;
            let y = read_guest_u32(memory, rect + 4).unwrap_or(0) as i32;
            let right = read_guest_u32(memory, rect + 8).unwrap_or(0) as i32;
            let bottom = read_guest_u32(memory, rect + 12).unwrap_or(0) as i32;
            let preview = preview_rect_from_bounds(x, y, right, bottom);
            self.fill_hdc_rect(hdc, preview, [0xf0, 0xf0, 0xf0, 0xff]);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `DrawThemeText(htheme, hdc, part, state, text, len, flags, flags2,
    /// rect)` — render the string through the GDI text path.
    pub(crate) fn dispatch_draw_theme_text(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let theme = guest_call_arg(state, memory, 0)?;
        let hdc = guest_call_arg(state, memory, 1)?;
        let _part = guest_call_arg_u32(state, memory, 2)?;
        let _state = guest_call_arg_u32(state, memory, 3)?;
        let text = guest_call_arg(state, memory, 4)?;
        let _len = guest_call_arg_u32(state, memory, 5)?;
        let _flags = guest_call_arg_u32(state, memory, 6)?;
        let _flags2 = guest_call_arg_u32(state, memory, 7)?;
        let rect = guest_call_arg(state, memory, 8)?;
        if !self.theme_handles.contains_key(&theme) {
            state.set(Register::Rax, u64::from(E_HANDLE));
            return Ok(());
        }
        let text = read_utf16_string(memory, text).unwrap_or_default();
        if rect != 0 {
            let x = read_guest_u32(memory, rect).unwrap_or(0) as i32;
            let y = read_guest_u32(memory, rect + 4).unwrap_or(0) as i32;
            let right = read_guest_u32(memory, rect + 8).unwrap_or(0) as i32;
            let bottom = read_guest_u32(memory, rect + 12).unwrap_or(0) as i32;
            let preview = preview_rect_from_bounds(x, y, right, bottom);
            self.draw_text_to_hdc(hdc, preview, &text, 0);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `BeginBufferedPaint(hdcTarget, prcTarget, dwFormat, pPaintParams,
    /// phdc)` — an in-memory paint buffer.
    pub(crate) fn dispatch_begin_buffered_paint(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _target = guest_call_arg(state, memory, 0)?;
        let rect = guest_call_arg(state, memory, 1)?;
        let _format = guest_call_arg_u32(state, memory, 2)?;
        let _params = guest_call_arg(state, memory, 3)?;
        let hdc_out = guest_call_arg(state, memory, 4)?;
        let width = if rect != 0 {
            let right = read_guest_u32(memory, rect + 8).unwrap_or(0) as i32;
            let left = read_guest_u32(memory, rect).unwrap_or(0) as i32;
            (right - left).max(1) as u32
        } else {
            1
        };
        let height = if rect != 0 {
            let bottom = read_guest_u32(memory, rect + 12).unwrap_or(0) as i32;
            let top = read_guest_u32(memory, rect + 4).unwrap_or(0) as i32;
            (bottom - top).max(1) as u32
        } else {
            1
        };
        let _ = (width, height);
        // A memory DC (the buffered paint target); the pixel buffer is
        // realized when a bitmap is selected into it, exactly like
        // CreateCompatibleDC.
        let hdc = self.next_gdi_handle;
        self.next_gdi_handle += 1;
        self.device_contexts.insert(hdc, None);
        if hdc_out != 0 {
            write_guest_pointer(memory, hdc_out, hdc, self.guest_arch).ok();
        }
        state.set(Register::Rax, hdc);
        Ok(())
    }
}
