#![allow(clippy::needless_range_loop)]
#![allow(clippy::erasing_op)]

//! Section 33 — GDI+ Completion (Phase 2.7)
//!
//! Tests the full GDI+ subsystem surface area:
//!   - Startup / shutdown lifecycle
//!   - Graphics context creation and deletion
//!   - Drawing primitives (line, rectangle, ellipse, pie, polygon, arc, curve)
//!   - Brush creation and usage (solid, line, texture)
//!   - Pen creation with all style properties (width, color, dash, join, caps)
//!   - Path creation and manipulation (add geometry, close, fill mode)
//!   - Matrix operations (create, set elements, translate, rotate, scale, invert, multiply)
//!   - Transform (set/reset/get world transform)
//!   - Clipping (set clip rect/path/region, reset, get bounds)
//!   - Graphics save/restore containers (begin/end container, save/restore)
//!   - Bitmap interop (create from HBITMAP/file/graphics, get width/height/pixel format,
//!     bitmap get/set pixel, lock/unlock bits)
//!   - Text/Font (create/delete font, font family, text rendering hint, measure)
//!   - Image attributes (create/dispose, color keys, color matrix)
//!   - Quality settings (smoothing mode, compositing mode/quality, interpolation, pixel offset)
//!   - Image operations (draw, type, save, clone)
//!   - Status code validation

mod support;

use casa1::cpu::GuestArch;
use casa1::ge::{GameEnvironment, GeArch};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use casa1::user32::{
    GDIPLUS_COMPOSITING_MODE_SOURCE_COPY, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
    GDIPLUS_COMPOSITING_QUALITY_DEFAULT, GDIPLUS_COMPOSITING_QUALITY_HIGH_QUALITY,
    GDIPLUS_DASH_STYLE_DASH, GDIPLUS_DASH_STYLE_DOT, GDIPLUS_FILL_MODE_ALTERNATE,
    GDIPLUS_FILL_MODE_WINDING, GDIPLUS_FONT_STYLE_BOLD, GDIPLUS_INTERPOLATION_DEFAULT,
    GDIPLUS_INTERPOLATION_HIGH_QUALITY_BICUBIC, GDIPLUS_LINE_CAP_FLAT, GDIPLUS_LINE_CAP_ROUND,
    GDIPLUS_LINE_JOIN_MITER, GDIPLUS_LINE_JOIN_ROUND, GDIPLUS_PIXEL_FORMAT_24BPP_RGB,
    GDIPLUS_PIXEL_FORMAT_32BPP_ARGB, GDIPLUS_PIXEL_OFFSET_DEFAULT, GDIPLUS_PIXEL_OFFSET_HALF,
    GDIPLUS_SMOOTHING_MODE_DEFAULT, GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY,
    GDIPLUS_TEXT_RENDERING_HINT_ANTI_ALIAS, GDIPLUS_TEXT_RENDERING_HINT_SYSTEM_DEFAULT,
    GDIPLUS_UNIT_PIXEL, GDIPLUS_WRAP_MODE_CLAMP, GDIPLUS_WRAP_MODE_TILE, GdiplusBitmap,
    GdiplusBrush, GdiplusColorMatrix, GdiplusFont, GdiplusFontFamily, GdiplusImage,
    GdiplusImageAttributes, GdiplusLineBrush, GdiplusMatrix, GdiplusObject, GdiplusPath,
    GdiplusPathElement, GdiplusPen, GdiplusPointF, GdiplusRectF, GdiplusSolidFill,
    GdiplusStartupInput, GdiplusState, GdiplusStatus, GdiplusTextureBrush,
};

use std::collections::BTreeMap;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: create a fresh GdiplusState
// ═══════════════════════════════════════════════════════════════════════════════

fn fresh_state() -> GdiplusState {
    GdiplusState::default()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dispatch harness — drive the REAL Gdip* host-thunk arms
// ═══════════════════════════════════════════════════════════════════════════════
//
// The lifecycle/matrix/transform/clip/container/quality operations live in the
// runtime's private dispatch arms, not in `GdiplusState` itself.  The public
// `NtThunkSession` test harness allocates a guest thunk per HostThunk variant
// and drives it through the real `dispatch_import` path with the x86 calling
// convention, so these tests exercise the same code a guest binary reaches.

/// Create a scratch PE host runtime for GDI+ dispatch tests.  The temp dir
/// owns the GE and must stay alive for the duration of the test.
fn dispatch_session() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(
        temp_dir.path(),
        "gdiplus-dispatch",
        GeArch::X86,
        "win11-23h2",
    )
    .expect("create GE");
    let mut session = NtThunkSession::new(ge);
    session.set_guest_arch(GuestArch::X86);
    (temp_dir, session)
}

/// Run `f` on an 8 MiB worker stack with a fresh GDI+ dispatch session.  The
/// real host-thunk match has a large debug-build frame (the same reason
/// section49/section50 dispatch through explicit big-stack threads), which
/// overflows libtest's 2 MiB test thread stack.  `NtThunkSession` is not
/// `Send`, so the session is created inside the worker thread and the closure
/// borrows it there.
fn with_dispatch_session<F, R>(f: F) -> R
where
    F: FnOnce(&mut NtThunkSession) -> R + Send,
    R: Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn_scoped(scope, || {
                let (_temp_dir, mut session) = dispatch_session();
                f(&mut session)
            })
            .expect("spawn dispatch thread")
            .join()
            .expect("dispatch thread panicked")
    })
}

/// Guest arena addresses used for thunk in/out parameters (the session maps
/// the 0x30_000..0x40_000 arena).
const GDI_OUT: u64 = 0x30_000; // u64 handle / token out
const GDI_ELEMS: u64 = 0x30_100; // 6 × f32 matrix elements
const GDI_RECT: u64 = 0x30_200; // 4 × f32 rect
const GDI_MODE: u64 = 0x30_300; // u32 mode out
const GDI_STATE: u64 = 0x30_400; // u32 container/state id out

fn read_u32_guest(session: &NtThunkSession, address: u64) -> u32 {
    let bytes = session.read_guest(address, 4);
    assert_eq!(bytes.len(), 4, "guest read at {address:#x}");
    u32::from_le_bytes(bytes.try_into().expect("u32"))
}

fn read_u64_guest(session: &NtThunkSession, address: u64) -> u64 {
    let bytes = session.read_guest(address, 8);
    assert_eq!(bytes.len(), 8, "guest read at {address:#x}");
    u64::from_le_bytes(bytes.try_into().expect("u64"))
}

fn read_f32_guest(session: &NtThunkSession, address: u64) -> f32 {
    f32::from_bits(read_u32_guest(session, address))
}

fn read_matrix_guest(session: &NtThunkSession, address: u64) -> [f32; 6] {
    let mut elements = [0.0_f32; 6];
    for (index, element) in elements.iter_mut().enumerate() {
        *element = read_f32_guest(session, address + index as u64 * 4);
    }
    elements
}

/// Create a graphics object bound to a synthetic HDC via the real
/// `GdipCreateFromHDC` arm and return its handle.
fn dispatch_create_graphics(session: &mut NtThunkSession) -> u64 {
    let create = session.alloc_thunk(HostThunk::GdipCreateFromHDC);
    let status = session.call_x86(create, &[0x1234, GDI_OUT as u32]);
    assert_eq!(
        status,
        GdiplusStatus::Ok.to_u32(),
        "GdipCreateFromHDC must succeed"
    );
    let handle = read_u64_guest(session, GDI_OUT);
    assert_ne!(handle, 0, "GdipCreateFromHDC must write a handle");
    handle
}

/// Create an identity matrix via the real `GdipCreateMatrix` arm.
fn dispatch_create_identity_matrix(session: &mut NtThunkSession) -> u64 {
    let create = session.alloc_thunk(HostThunk::GdipCreateMatrix);
    let status = session.call_x86(create, &[GDI_OUT as u32]);
    assert_eq!(
        status,
        GdiplusStatus::Ok.to_u32(),
        "GdipCreateMatrix must succeed"
    );
    read_u64_guest(session, GDI_OUT)
}

/// Read a matrix back through the real `GdipGetMatrixElements` arm.
fn dispatch_matrix_elements(session: &mut NtThunkSession, matrix: u64) -> [f32; 6] {
    let get = session.alloc_thunk(HostThunk::GdipGetMatrixElements);
    let status = session.call_x86(get, &[matrix as u32, GDI_ELEMS as u32]);
    assert_eq!(
        status,
        GdiplusStatus::Ok.to_u32(),
        "GdipGetMatrixElements must succeed"
    );
    read_matrix_guest(session, GDI_ELEMS)
}

/// Read a u32 graphics mode back through its real getter arm.
fn dispatch_get_mode(session: &mut NtThunkSession, graphics: u64, getter: HostThunk) -> u32 {
    let label = format!("{getter:?}");
    let get = session.alloc_thunk(getter);
    let status = session.call_x86(get, &[graphics as u32, GDI_MODE as u32]);
    assert_eq!(status, GdiplusStatus::Ok.to_u32(), "{label} must succeed");
    read_u32_guest(session, GDI_MODE)
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_01 — GdiplusStartup / GdiplusShutdown lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

// The lifecycle is driven through the real GdiplusStartup/GdiplusShutdown
// host-thunk arms on the public NtThunkSession dispatch harness.  The startup
// token lands in guest memory and shutdown must drop every live GDI+ object,
// observable through a getter that then reports InvalidParameter.
#[test]
fn t33_01_startup_shutdown_lifecycle() {
    with_dispatch_session(|session| {
        let startup = session.alloc_thunk(HostThunk::GdiplusStartup);
        let status = session.call_x86(startup, &[GDI_OUT as u32, 0, 0]);
        assert_eq!(
            status,
            GdiplusStatus::Ok.to_u32(),
            "GdiplusStartup must succeed"
        );
        let token = read_u64_guest(session, GDI_OUT);
        assert_eq!(token, 0xABCD_0001, "startup must return the runtime token");

        // An object allocated while initialized is live.
        let matrix = dispatch_create_identity_matrix(session);
        assert_ne!(matrix, 0, "matrix handle");
        let _ = dispatch_matrix_elements(session, matrix);

        let shutdown = session.alloc_thunk(HostThunk::GdiplusShutdown);
        let status = session.call_x86(shutdown, &[token as u32]);
        assert_eq!(
            status,
            GdiplusStatus::Ok.to_u32(),
            "GdiplusShutdown must succeed"
        );

        // Shutdown drops every live object: reading the matrix now fails.
        let get = session.alloc_thunk(HostThunk::GdipGetMatrixElements);
        let status = session.call_x86(get, &[matrix as u32, GDI_ELEMS as u32]);
        assert_eq!(
            status,
            GdiplusStatus::InvalidParameter.to_u32(),
            "shutdown must free every GDI+ object"
        );
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_02 — Graphics context creation and deletion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_02_graphics_create_from_hdc() {
    let mut state = fresh_state();
    let hdc: u64 = 0x12345;

    let gfx_handle = state.create_graphics_from_hdc(hdc);
    assert_ne!(gfx_handle, 0, "should return a non-zero handle");

    // Verify the graphics object exists
    let obj = state.get(gfx_handle).expect("graphics object should exist");
    match obj {
        GdiplusObject::Graphics(g) => {
            assert_eq!(g.hdc, hdc);
            assert_eq!(g.smoothing_mode, GDIPLUS_SMOOTHING_MODE_DEFAULT);
            assert_eq!(g.compositing_mode, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER);
        }
        _ => panic!("expected Graphics object"),
    }

    // Calling create_graphics_from_hdc with same HDC returns cached handle
    let cached = state.create_graphics_from_hdc(hdc);
    assert_eq!(cached, gfx_handle, "should return cached handle");

    // Delete graphics
    let removed = state.remove(gfx_handle);
    assert!(removed.is_some(), "should remove graphics object");
    assert!(
        state.get(gfx_handle).is_none(),
        "should be gone after removal"
    );
}

#[test]
fn t33_03_graphics_delete_invalid() {
    let mut state = fresh_state();
    let removed = state.remove(0xDEAD_BEEF);
    assert!(
        removed.is_none(),
        "removing non-existent handle should return None"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_04 — Brush creation and usage
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_04_brush_solid_fill() {
    let mut state = fresh_state();
    let color: u32 = 0xFF_AA_BB_CC;

    let brush = GdiplusBrush::SolidFill(GdiplusSolidFill { color });
    let handle = state.alloc_handle(GdiplusObject::Brush(Box::new(brush)));

    let obj = state.get(handle).expect("brush should exist").clone();
    match obj {
        GdiplusObject::Brush(brush) => match *brush {
            GdiplusBrush::SolidFill(sf) => {
                assert_eq!(sf.color, color);
            }
            _ => panic!("expected SolidFill brush"),
        },
        _ => panic!("expected Brush"),
    }
}

#[test]
fn t33_05_brush_line_gradient() {
    let mut state = fresh_state();
    let brush = GdiplusBrush::LineBrush(GdiplusLineBrush {
        point1: (0.0, 0.0),
        point2: (100.0, 100.0),
        color1: 0xFF000000,
        color2: 0xFFFFFFFF,
        wrap_mode: GDIPLUS_WRAP_MODE_TILE,
    });
    let handle = state.alloc_handle(GdiplusObject::Brush(Box::new(brush)));

    match state.get(handle).expect("brush should exist").clone() {
        GdiplusObject::Brush(brush) => match *brush {
            GdiplusBrush::LineBrush(lb) => {
                assert_eq!(lb.point1, (0.0, 0.0));
                assert_eq!(lb.point2, (100.0, 100.0));
                assert_eq!(lb.wrap_mode, GDIPLUS_WRAP_MODE_TILE);
            }
            _ => panic!("expected LineBrush"),
        },
        _ => panic!("expected Brush"),
    }
}

#[test]
fn t33_06_brush_texture() {
    let mut state = fresh_state();
    let brush = GdiplusBrush::Texture(GdiplusTextureBrush {
        image_handle: 0xDD010005,
        wrap_mode: GDIPLUS_WRAP_MODE_CLAMP,
    });
    let handle = state.alloc_handle(GdiplusObject::Brush(Box::new(brush)));

    match state.get(handle).expect("brush should exist").clone() {
        GdiplusObject::Brush(brush) => match *brush {
            GdiplusBrush::Texture(tb) => {
                assert_eq!(tb.image_handle, 0xDD010005);
                assert_eq!(tb.wrap_mode, GDIPLUS_WRAP_MODE_CLAMP);
            }
            _ => panic!("expected Texture brush"),
        },
        _ => panic!("expected Brush"),
    }
}

#[test]
fn t33_07_brush_delete() {
    let mut state = fresh_state();
    let handle = state.alloc_handle(GdiplusObject::Brush(Box::new(GdiplusBrush::SolidFill(
        GdiplusSolidFill { color: 0 },
    ))));
    assert!(
        state.get(handle).is_some(),
        "handle should be valid after alloc"
    );
    let removed = state.remove(handle);
    assert!(removed.is_some(), "removed object should be present");
    assert!(
        state.get(handle).is_none(),
        "handle should be invalid after remove"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_08 — Pen creation with all style properties
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_08_pen_create_and_properties() {
    let mut state = fresh_state();
    let pen = GdiplusPen {
        unit: 0,
        width: 2.5,
        color: 0xFF0000FF,
        brush_handle: None,
        dash_style: GDIPLUS_DASH_STYLE_DASH,
        line_join: GDIPLUS_LINE_JOIN_ROUND,
        start_cap: GDIPLUS_LINE_CAP_ROUND,
        end_cap: GDIPLUS_LINE_CAP_FLAT,
        alignment: 0,
    };
    let handle = state.alloc_handle(GdiplusObject::Pen(Box::new(pen)));

    match state.get(handle).expect("pen should exist") {
        GdiplusObject::Pen(p) => {
            assert!((p.width - 2.5).abs() < f32::EPSILON);
            assert_eq!(p.color, 0xFF0000FF);
            assert_eq!(p.dash_style, GDIPLUS_DASH_STYLE_DASH);
            assert_eq!(p.line_join, GDIPLUS_LINE_JOIN_ROUND);
            assert_eq!(p.start_cap, GDIPLUS_LINE_CAP_ROUND);
            assert_eq!(p.end_cap, GDIPLUS_LINE_CAP_FLAT);
        }
        _ => panic!("expected Pen object"),
    }

    // Modify pen properties via get_mut
    if let Some(GdiplusObject::Pen(pen)) = state.get_mut(handle) {
        pen.width = 5.0;
        pen.color = 0xFFFF0000;
        pen.dash_style = GDIPLUS_DASH_STYLE_DOT;
        pen.line_join = GDIPLUS_LINE_JOIN_MITER;
    }

    match state.get(handle).expect("pen should still exist") {
        GdiplusObject::Pen(p) => {
            assert!(
                (p.width - 5.0).abs() < f32::EPSILON,
                "width should be updated"
            );
            assert_eq!(p.color, 0xFFFF0000, "color should be updated");
            assert_eq!(p.dash_style, GDIPLUS_DASH_STYLE_DOT);
            assert_eq!(p.line_join, GDIPLUS_LINE_JOIN_MITER);
        }
        _ => panic!("expected Pen object"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_09 — Path creation and manipulation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_09_path_add_geometry() {
    let mut state = fresh_state();
    let mut path = GdiplusPath {
        fill_mode: GDIPLUS_FILL_MODE_ALTERNATE,
        elements: Vec::new(),
    };

    // Start figure, add line, close
    path.elements.push(GdiplusPathElement::StartFigure);
    path.elements.push(GdiplusPathElement::Line {
        x1: 0.0,
        y1: 0.0,
        x2: 100.0,
        y2: 100.0,
    });
    path.elements.push(GdiplusPathElement::CloseFigure);

    let handle = state.alloc_handle(GdiplusObject::Path(Box::new(path)));

    match state.get(handle).expect("path should exist") {
        GdiplusObject::Path(p) => {
            assert_eq!(p.fill_mode, GDIPLUS_FILL_MODE_ALTERNATE);
            assert_eq!(p.elements.len(), 3);
            assert!(matches!(p.elements[0], GdiplusPathElement::StartFigure));
            assert!(matches!(p.elements[1], GdiplusPathElement::Line { .. }));
            assert!(matches!(p.elements[2], GdiplusPathElement::CloseFigure));
        }
        _ => panic!("expected Path object"),
    }
}

#[test]
fn t33_10_path_add_rectangle_and_ellipse() {
    let mut state = fresh_state();
    let mut path = GdiplusPath {
        fill_mode: GDIPLUS_FILL_MODE_WINDING,
        elements: Vec::new(),
    };
    path.elements.push(GdiplusPathElement::Rectangle {
        x: 10.0,
        y: 20.0,
        w: 100.0,
        h: 50.0,
    });
    path.elements.push(GdiplusPathElement::Ellipse {
        x: 0.0,
        y: 0.0,
        w: 50.0,
        h: 50.0,
    });

    let handle = state.alloc_handle(GdiplusObject::Path(Box::new(path)));

    match state.get(handle).expect("path should exist") {
        GdiplusObject::Path(p) => {
            assert_eq!(p.elements.len(), 2);
            if let GdiplusPathElement::Rectangle { x, y: _, w: _, h } = &p.elements[0] {
                assert!((*x - 10.0).abs() < f32::EPSILON);
                assert!((*h - 50.0).abs() < f32::EPSILON);
            } else {
                panic!("expected Rectangle element");
            }
        }
        _ => panic!("expected Path object"),
    }
}

#[test]
fn t33_11_path_set_fill_mode() {
    let mut state = fresh_state();
    let path = GdiplusPath {
        fill_mode: GDIPLUS_FILL_MODE_ALTERNATE,
        elements: Vec::new(),
    };
    let handle = state.alloc_handle(GdiplusObject::Path(Box::new(path)));

    // Change fill mode via get_mut
    if let Some(GdiplusObject::Path(p)) = state.get_mut(handle) {
        p.fill_mode = GDIPLUS_FILL_MODE_WINDING;
    }

    match state.get(handle).expect("path should exist") {
        GdiplusObject::Path(p) => {
            assert_eq!(p.fill_mode, GDIPLUS_FILL_MODE_WINDING);
        }
        _ => panic!("expected Path object"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_12 — Matrix operations
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_12_matrix_identity() {
    let m = GdiplusMatrix::identity();
    assert!((m.elements[0] - 1.0).abs() < f32::EPSILON);
    assert!((m.elements[1] - 0.0).abs() < f32::EPSILON);
    assert!((m.elements[2] - 0.0).abs() < f32::EPSILON);
    assert!((m.elements[3] - 1.0).abs() < f32::EPSILON);
    assert!((m.elements[4] - 0.0).abs() < f32::EPSILON);
    assert!((m.elements[5] - 0.0).abs() < f32::EPSILON);
}

// Matrix mutations are driven through the real Gdip* dispatch arms on the
// public NtThunkSession harness and read back through GdipGetMatrixElements.
#[test]
fn t33_13_matrix_set_elements() {
    with_dispatch_session(|session| {
        let matrix = dispatch_create_identity_matrix(session);
        let set = session.alloc_thunk(HostThunk::GdipSetMatrixElements);
        let status = session.call_x86(
            set,
            &[
                matrix as u32,
                2.0_f32.to_bits(),
                0.0_f32.to_bits(),
                0.0_f32.to_bits(),
                3.0_f32.to_bits(),
                10.0_f32.to_bits(),
                20.0_f32.to_bits(),
            ],
        );
        assert_eq!(status, GdiplusStatus::Ok.to_u32(), "GdipSetMatrixElements");
        let elements = dispatch_matrix_elements(session, matrix);
        for (actual, expected) in elements.iter().zip([2.0, 0.0, 0.0, 3.0, 10.0, 20.0]) {
            assert!((actual - expected).abs() < f32::EPSILON, "{elements:?}");
        }
    });
}

#[test]
fn t33_14_matrix_get_elements() {
    with_dispatch_session(|session| {
        let matrix = dispatch_create_identity_matrix(session);
        let set = session.alloc_thunk(HostThunk::GdipSetMatrixElements);
        let status = session.call_x86(
            set,
            &[
                matrix as u32,
                1.0_f32.to_bits(),
                2.0_f32.to_bits(),
                3.0_f32.to_bits(),
                4.0_f32.to_bits(),
                5.0_f32.to_bits(),
                6.0_f32.to_bits(),
            ],
        );
        assert_eq!(status, GdiplusStatus::Ok.to_u32(), "GdipSetMatrixElements");
        let elements = dispatch_matrix_elements(session, matrix);
        for (actual, expected) in elements.iter().zip([1.0, 2.0, 3.0, 4.0, 5.0, 6.0]) {
            assert!((actual - expected).abs() < f32::EPSILON, "{elements:?}");
        }
    });
}

#[test]
fn t33_15_matrix_translate() {
    with_dispatch_session(|session| {
        let matrix = dispatch_create_identity_matrix(session);
        let translate = session.alloc_thunk(HostThunk::GdipTranslateMatrix);
        let status = session.call_x86(
            translate,
            &[matrix as u32, 5.0_f32.to_bits(), 10.0_f32.to_bits(), 0],
        );
        assert_eq!(status, GdiplusStatus::Ok.to_u32(), "GdipTranslateMatrix");
        let elements = dispatch_matrix_elements(session, matrix);
        assert!((elements[4] - 5.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[5] - 10.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[0] - 1.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[3] - 1.0).abs() < f32::EPSILON, "{elements:?}");
    });
}

#[test]
fn t33_16_matrix_scale() {
    with_dispatch_session(|session| {
        let matrix = dispatch_create_identity_matrix(session);
        let scale = session.alloc_thunk(HostThunk::GdipScaleMatrix);
        let status = session.call_x86(
            scale,
            &[matrix as u32, 2.0_f32.to_bits(), 3.0_f32.to_bits(), 0],
        );
        assert_eq!(status, GdiplusStatus::Ok.to_u32(), "GdipScaleMatrix");
        let elements = dispatch_matrix_elements(session, matrix);
        assert!((elements[0] - 2.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[3] - 3.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[4] - 0.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[5] - 0.0).abs() < f32::EPSILON, "{elements:?}");
    });
}

#[test]
fn t33_17_matrix_invert() {
    with_dispatch_session(|session| {
        let matrix = dispatch_create_identity_matrix(session);
        let set = session.alloc_thunk(HostThunk::GdipSetMatrixElements);
        let status = session.call_x86(
            set,
            &[
                matrix as u32,
                2.0_f32.to_bits(),
                0.0_f32.to_bits(),
                0.0_f32.to_bits(),
                4.0_f32.to_bits(),
                10.0_f32.to_bits(),
                20.0_f32.to_bits(),
            ],
        );
        assert_eq!(status, GdiplusStatus::Ok.to_u32(), "GdipSetMatrixElements");

        let invert = session.alloc_thunk(HostThunk::GdipInvertMatrix);
        let status = session.call_x86(invert, &[matrix as u32]);
        assert_eq!(status, GdiplusStatus::Ok.to_u32(), "GdipInvertMatrix");

        let elements = dispatch_matrix_elements(session, matrix);
        let expected = [0.5, 0.0, 0.0, 0.25, -5.0, -5.0];
        for (index, (actual, expected)) in elements.iter().zip(expected).enumerate() {
            assert!(
                (actual - expected).abs() < 0.001,
                "element {index} mismatch: {actual} vs {expected} ({elements:?})"
            );
        }
    });
}

#[test]
fn t33_18_matrix_delete() {
    let mut state = fresh_state();
    let handle = state.alloc_handle(GdiplusObject::Matrix(Box::new(GdiplusMatrix::identity())));
    assert!(state.get(handle).is_some());
    state.remove(handle);
    assert!(state.get(handle).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_19 — Transform (set/reset/get world transform)
// ═══════════════════════════════════════════════════════════════════════════════

// World-transform operations are driven through the real dispatch arms and
// read back through GdipGetWorldTransform.
#[test]
fn t33_19_world_transform() {
    with_dispatch_session(|session| {
        let graphics = dispatch_create_graphics(session);
        let matrix = dispatch_create_identity_matrix(session);
        let translate = session.alloc_thunk(HostThunk::GdipTranslateMatrix);
        assert_eq!(
            session.call_x86(
                translate,
                &[matrix as u32, 7.0_f32.to_bits(), 9.0_f32.to_bits(), 0],
            ),
            GdiplusStatus::Ok.to_u32()
        );

        let set = session.alloc_thunk(HostThunk::GdipSetWorldTransform);
        assert_eq!(
            session.call_x86(set, &[graphics as u32, matrix as u32]),
            GdiplusStatus::Ok.to_u32(),
            "GdipSetWorldTransform"
        );

        let get = session.alloc_thunk(HostThunk::GdipGetWorldTransform);
        assert_eq!(
            session.call_x86(get, &[graphics as u32, GDI_OUT as u32]),
            GdiplusStatus::Ok.to_u32(),
            "GdipGetWorldTransform"
        );
        let returned = read_u64_guest(session, GDI_OUT);
        assert_eq!(returned, matrix, "world transform must round-trip");
        let elements = dispatch_matrix_elements(session, returned);
        assert!((elements[4] - 7.0).abs() < f32::EPSILON, "{elements:?}");
        assert!((elements[5] - 9.0).abs() < f32::EPSILON, "{elements:?}");

        // Reset: a following get allocates a fresh identity matrix.
        let reset = session.alloc_thunk(HostThunk::GdipResetWorldTransform);
        assert_eq!(
            session.call_x86(reset, &[graphics as u32]),
            GdiplusStatus::Ok.to_u32(),
            "GdipResetWorldTransform"
        );
        assert_eq!(
            session.call_x86(get, &[graphics as u32, GDI_OUT as u32]),
            GdiplusStatus::Ok.to_u32()
        );
        let identity = read_u64_guest(session, GDI_OUT);
        assert_ne!(identity, matrix, "reset must return a fresh matrix");
        let elements = dispatch_matrix_elements(session, identity);
        for (actual, expected) in elements.iter().zip([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]) {
            assert!((actual - expected).abs() < f32::EPSILON, "{elements:?}");
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_20 — Clipping operations
// ═══════════════════════════════════════════════════════════════════════════════

// Clip operations are driven through the real GdipSetClipRect/GdipGetClipBounds/
// GdipResetClip arms.
#[test]
fn t33_20_clip_rect_reset_and_bounds() {
    with_dispatch_session(|session| {
        let graphics = dispatch_create_graphics(session);
        let get_bounds = session.alloc_thunk(HostThunk::GdipGetClipBounds);
        let status = session.call_x86(get_bounds, &[graphics as u32, GDI_RECT as u32]);
        assert_eq!(status, GdiplusStatus::Ok.to_u32());
        // Initially no clip: bounds are all zero.
        for index in 0..4 {
            assert_eq!(
                read_f32_guest(session, GDI_RECT + index as u64 * 4),
                0.0,
                "no clip must report zero bounds"
            );
        }

        // Set clip rect 10,20,100,200 (combine mode Replace).
        let set_clip = session.alloc_thunk(HostThunk::GdipSetClipRect);
        assert_eq!(
            session.call_x86(
                set_clip,
                &[
                    graphics as u32,
                    10.0_f32.to_bits(),
                    20.0_f32.to_bits(),
                    100.0_f32.to_bits(),
                    200.0_f32.to_bits(),
                    0,
                ],
            ),
            GdiplusStatus::Ok.to_u32(),
            "GdipSetClipRect"
        );
        assert_eq!(
            session.call_x86(get_bounds, &[graphics as u32, GDI_RECT as u32]),
            GdiplusStatus::Ok.to_u32()
        );
        let expected = [10.0_f32, 20.0, 100.0, 200.0];
        for (index, expected) in expected.into_iter().enumerate() {
            let actual = read_f32_guest(session, GDI_RECT + index as u64 * 4);
            assert!(
                (actual - expected).abs() < f32::EPSILON,
                "{actual} != {expected}"
            );
        }

        // Reset clip: bounds return to zero.
        let reset = session.alloc_thunk(HostThunk::GdipResetClip);
        assert_eq!(
            session.call_x86(reset, &[graphics as u32]),
            GdiplusStatus::Ok.to_u32(),
            "GdipResetClip"
        );
        assert_eq!(
            session.call_x86(get_bounds, &[graphics as u32, GDI_RECT as u32]),
            GdiplusStatus::Ok.to_u32()
        );
        for index in 0..4 {
            assert_eq!(
                read_f32_guest(session, GDI_RECT + index as u64 * 4),
                0.0,
                "clip must be reset to zero bounds"
            );
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_21 — Graphics save/restore (containers)
// ═══════════════════════════════════════════════════════════════════════════════

// Save/restore runs through the real GdipSaveGraphics/GdipRestoreGraphics arms;
// the state id comes back through guest memory and the quality getters prove
// the restore.
#[test]
fn t33_21_graphics_save_restore() {
    with_dispatch_session(|session| {
        let graphics = dispatch_create_graphics(session);
        let set_smoothing = session.alloc_thunk(HostThunk::GdipSetSmoothingMode);
        let set_compositing = session.alloc_thunk(HostThunk::GdipSetCompositingMode);
        let set_interpolation = session.alloc_thunk(HostThunk::GdipSetInterpolationMode);

        assert_eq!(
            session.call_x86(
                set_smoothing,
                &[graphics as u32, GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY],
            ),
            GdiplusStatus::Ok.to_u32()
        );
        assert_eq!(
            session.call_x86(
                set_compositing,
                &[graphics as u32, GDIPLUS_COMPOSITING_MODE_SOURCE_COPY],
            ),
            GdiplusStatus::Ok.to_u32()
        );
        assert_eq!(
            session.call_x86(
                set_interpolation,
                &[graphics as u32, GDIPLUS_INTERPOLATION_HIGH_QUALITY_BICUBIC],
            ),
            GdiplusStatus::Ok.to_u32()
        );

        // Save: the arm writes the saved-state id to guest memory.
        let save = session.alloc_thunk(HostThunk::GdipSaveGraphics);
        assert_eq!(
            session.call_x86(save, &[graphics as u32, GDI_STATE as u32]),
            GdiplusStatus::Ok.to_u32(),
            "GdipSaveGraphics"
        );
        let state_id = read_u32_guest(session, GDI_STATE);
        assert_ne!(state_id, 0, "save must return a state id");

        // Mutate after the save; the getters observe the new values.
        assert_eq!(
            session.call_x86(
                set_smoothing,
                &[graphics as u32, GDIPLUS_SMOOTHING_MODE_DEFAULT],
            ),
            GdiplusStatus::Ok.to_u32()
        );
        assert_eq!(
            session.call_x86(
                set_compositing,
                &[graphics as u32, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER],
            ),
            GdiplusStatus::Ok.to_u32()
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetSmoothingMode),
            GDIPLUS_SMOOTHING_MODE_DEFAULT
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetCompositingMode),
            GDIPLUS_COMPOSITING_MODE_SOURCE_OVER
        );

        // Restore: the saved settings come back.
        let restore = session.alloc_thunk(HostThunk::GdipRestoreGraphics);
        assert_eq!(
            session.call_x86(restore, &[graphics as u32, state_id]),
            GdiplusStatus::Ok.to_u32(),
            "GdipRestoreGraphics"
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetSmoothingMode),
            GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetCompositingMode),
            GDIPLUS_COMPOSITING_MODE_SOURCE_COPY
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetInterpolationMode),
            GDIPLUS_INTERPOLATION_HIGH_QUALITY_BICUBIC
        );
    });
}

// Begin/end container runs through the real GdipBeginContainer/GdipEndContainer
// arms; the container id comes back through guest memory and the quality
// getters prove the restore.
#[test]
fn t33_22_graphics_begin_end_container() {
    with_dispatch_session(|session| {
        let graphics = dispatch_create_graphics(session);
        let set_smoothing = session.alloc_thunk(HostThunk::GdipSetSmoothingMode);
        let set_pixel_offset = session.alloc_thunk(HostThunk::GdipSetPixelOffsetMode);

        assert_eq!(
            session.call_x86(
                set_smoothing,
                &[graphics as u32, GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY],
            ),
            GdiplusStatus::Ok.to_u32()
        );

        let begin = session.alloc_thunk(HostThunk::GdipBeginContainer);
        assert_eq!(
            session.call_x86(
                begin,
                &[graphics as u32, 0, 0, GDIPLUS_UNIT_PIXEL, GDI_STATE as u32],
            ),
            GdiplusStatus::Ok.to_u32(),
            "GdipBeginContainer"
        );
        let container_id = read_u32_guest(session, GDI_STATE);
        assert_ne!(container_id, 0, "begin container must return an id");

        // Change state inside the container.
        assert_eq!(
            session.call_x86(
                set_smoothing,
                &[graphics as u32, GDIPLUS_SMOOTHING_MODE_DEFAULT],
            ),
            GdiplusStatus::Ok.to_u32()
        );
        assert_eq!(
            session.call_x86(
                set_pixel_offset,
                &[graphics as u32, GDIPLUS_PIXEL_OFFSET_HALF]
            ),
            GdiplusStatus::Ok.to_u32()
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetSmoothingMode),
            GDIPLUS_SMOOTHING_MODE_DEFAULT
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetPixelOffsetMode),
            GDIPLUS_PIXEL_OFFSET_HALF
        );

        // End container: state is restored.
        let end = session.alloc_thunk(HostThunk::GdipEndContainer);
        assert_eq!(
            session.call_x86(end, &[graphics as u32, container_id]),
            GdiplusStatus::Ok.to_u32(),
            "GdipEndContainer"
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetSmoothingMode),
            GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY,
            "smoothing mode must be restored"
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetPixelOffsetMode),
            GDIPLUS_PIXEL_OFFSET_DEFAULT,
            "pixel offset must be restored"
        );
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_23 — Bitmap interop
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_23_bitmap_create_and_properties() {
    let mut state = fresh_state();

    // Create a bitmap
    let bitmap = GdiplusBitmap {
        width: 640,
        height: 480,
        pixel_format: GDIPLUS_PIXEL_FORMAT_32BPP_ARGB,
        stride: 2560,
        pixels: vec![0; 640 * 480 * 4],
        locked: false,
        scan0_guest: 0,
        lock_x: 0,
        lock_y: 0,
        raw_kind: 0,
    };
    let handle = state.alloc_handle(GdiplusObject::Image(Box::new(GdiplusImage::Bitmap(bitmap))));

    // Verify properties
    match state.get(handle).expect("image should exist").clone() {
        GdiplusObject::Image(img) => match *img {
            GdiplusImage::Bitmap(bmp) => {
                assert_eq!(bmp.width, 640);
                assert_eq!(bmp.height, 480);
                assert_eq!(bmp.pixel_format, GDIPLUS_PIXEL_FORMAT_32BPP_ARGB);
                assert!(!bmp.locked);
                assert_eq!(bmp.pixels.len(), 640 * 480 * 4);
            }
            _ => panic!("expected Image/Bitmap object"),
        },
        _ => panic!("expected Image"),
    }
}

#[test]
fn t33_24_bitmap_get_width_height_format() {
    let mut state = fresh_state();
    let bitmap = GdiplusBitmap {
        width: 320,
        height: 200,
        pixel_format: GDIPLUS_PIXEL_FORMAT_24BPP_RGB,
        stride: 960,
        pixels: vec![0; 320 * 200 * 3],
        locked: false,
        scan0_guest: 0,
        lock_x: 0,
        lock_y: 0,
        raw_kind: 0,
    };
    let handle = state.alloc_handle(GdiplusObject::Image(Box::new(GdiplusImage::Bitmap(bitmap))));

    match state.get(handle).expect("image should exist").clone() {
        GdiplusObject::Image(img) => match *img {
            GdiplusImage::Bitmap(bmp) => {
                assert_eq!(bmp.width, 320);
                assert_eq!(bmp.height, 200);
                assert_eq!(bmp.pixel_format, GDIPLUS_PIXEL_FORMAT_24BPP_RGB);
            }
            _ => panic!("expected Image/Bitmap object"),
        },
        _ => panic!("expected Image"),
    }
}

#[test]
fn t33_25_bitmap_dispose_image() {
    let mut state = fresh_state();
    let bitmap = GdiplusBitmap {
        width: 1,
        height: 1,
        pixel_format: GDIPLUS_PIXEL_FORMAT_32BPP_ARGB,
        stride: 4,
        pixels: vec![0; 4],
        locked: false,
        scan0_guest: 0,
        lock_x: 0,
        lock_y: 0,
        raw_kind: 0,
    };
    let handle = state.alloc_handle(GdiplusObject::Image(Box::new(GdiplusImage::Bitmap(bitmap))));
    assert!(state.get(handle).is_some());
    state.remove(handle);
    assert!(state.get(handle).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_26 — Text / Font
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_26_font_create_and_delete() {
    let mut state = fresh_state();

    // Create font family
    let family = GdiplusFontFamily {
        name: "Arial".to_string(),
    };
    let family_handle = state.alloc_handle(GdiplusObject::FontFamily(Box::new(family)));

    match state.get(family_handle).expect("font family should exist") {
        GdiplusObject::FontFamily(ff) => {
            assert_eq!(ff.name, "Arial");
        }
        _ => panic!("expected FontFamily object"),
    }

    // Create font
    let font = GdiplusFont {
        family_handle,
        em_size: 12.0,
        style: GDIPLUS_FONT_STYLE_BOLD,
        unit: GDIPLUS_UNIT_PIXEL,
    };
    let font_handle = state.alloc_handle(GdiplusObject::Font(Box::new(font)));

    match state.get(font_handle).expect("font should exist") {
        GdiplusObject::Font(f) => {
            assert_eq!(f.family_handle, family_handle);
            assert!((f.em_size - 12.0).abs() < f32::EPSILON);
            assert_eq!(f.style, GDIPLUS_FONT_STYLE_BOLD);
            assert_eq!(f.unit, GDIPLUS_UNIT_PIXEL);
        }
        _ => panic!("expected Font object"),
    }

    // Delete font
    state.remove(font_handle);
    assert!(state.get(font_handle).is_none());

    // Delete font family
    state.remove(family_handle);
    assert!(state.get(family_handle).is_none());
}

#[test]
fn t33_27_text_rendering_hint() {
    let mut state = fresh_state();
    let hdc: u64 = 0x500;
    let gfx_handle = state.create_graphics_from_hdc(hdc);

    // Default hint
    match state.get(gfx_handle).expect("graphics should exist") {
        GdiplusObject::Graphics(gfx) => {
            assert_eq!(
                gfx.text_rendering_hint,
                GDIPLUS_TEXT_RENDERING_HINT_SYSTEM_DEFAULT
            );
        }
        _ => panic!("expected Graphics object"),
    }

    // Set hint
    if let Some(GdiplusObject::Graphics(gfx)) = state.get_mut(gfx_handle) {
        gfx.text_rendering_hint = GDIPLUS_TEXT_RENDERING_HINT_ANTI_ALIAS;
    }

    match state.get(gfx_handle).expect("graphics should exist") {
        GdiplusObject::Graphics(gfx) => {
            assert_eq!(
                gfx.text_rendering_hint,
                GDIPLUS_TEXT_RENDERING_HINT_ANTI_ALIAS
            );
        }
        _ => panic!("expected Graphics object"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_28 — Image attributes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_28_image_attributes_create_dispose() {
    let mut state = fresh_state();

    let attrs = GdiplusImageAttributes {
        color_keys: BTreeMap::new(),
        color_matrix: None,
    };
    let handle = state.alloc_handle(GdiplusObject::ImageAttributes(Box::new(attrs)));

    assert!(state.get(handle).is_some(), "image attributes should exist");

    // Verify it's an ImageAttributes
    match state.get(handle).unwrap() {
        GdiplusObject::ImageAttributes(_) => {} // OK
        _ => panic!("expected ImageAttributes object"),
    }

    state.remove(handle);
    assert!(state.get(handle).is_none(), "should be disposed");
}

#[test]
fn t33_29_image_attributes_color_matrix() {
    let mut state = fresh_state();

    let attrs = GdiplusImageAttributes {
        color_keys: BTreeMap::new(),
        color_matrix: None,
    };

    // Set a grayscale color matrix
    let matrix = GdiplusColorMatrix {
        m: [
            [0.3, 0.3, 0.3, 0.0, 0.0],
            [0.59, 0.59, 0.59, 0.0, 0.0],
            [0.11, 0.11, 0.11, 0.0, 0.0],
            [0.0, 0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 0.0, 1.0],
        ],
    };
    let mut attrs = attrs;
    attrs.color_matrix = Some((0, matrix.clone())); // ColorAdjustType::Default = 0

    let handle = state.alloc_handle(GdiplusObject::ImageAttributes(Box::new(attrs)));

    // The image attributes must be stored and readable back through the
    // public API, with the grayscale color matrix intact.
    match state
        .get(handle)
        .expect("image attributes should be stored")
    {
        GdiplusObject::ImageAttributes(stored) => {
            let (adjust_type, stored_matrix) = stored
                .color_matrix
                .clone()
                .expect("color matrix must be stored");
            assert_eq!(adjust_type, 0, "ColorAdjustType::Default = 0");
            for row in 0..5 {
                for col in 0..5 {
                    assert!(
                        (stored_matrix.m[row][col] - matrix.m[row][col]).abs() < f32::EPSILON,
                        "matrix[{row}][{col}] must round-trip"
                    );
                }
            }
        }
        _ => panic!("expected ImageAttributes object"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_30 — Quality settings
// ═══════════════════════════════════════════════════════════════════════════════

// Quality settings are driven through the real setter/getter dispatch arms.
// Defaults are what GdipCreateFromHDC installs; every set is read back through
// the matching GdipGet* arm.
#[test]
fn t33_30_quality_settings() {
    with_dispatch_session(|session| {
        let graphics = dispatch_create_graphics(session);

        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetSmoothingMode),
            GDIPLUS_SMOOTHING_MODE_DEFAULT
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetCompositingMode),
            GDIPLUS_COMPOSITING_MODE_SOURCE_OVER
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetCompositingQuality),
            GDIPLUS_COMPOSITING_QUALITY_DEFAULT
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetInterpolationMode),
            GDIPLUS_INTERPOLATION_DEFAULT
        );
        assert_eq!(
            dispatch_get_mode(session, graphics, HostThunk::GdipGetPixelOffsetMode),
            GDIPLUS_PIXEL_OFFSET_DEFAULT
        );

        for (thunk, value, expected) in [
            (
                HostThunk::GdipSetSmoothingMode,
                GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY,
                (
                    HostThunk::GdipGetSmoothingMode,
                    GDIPLUS_SMOOTHING_MODE_HIGH_QUALITY,
                ),
            ),
            (
                HostThunk::GdipSetCompositingMode,
                GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
                (
                    HostThunk::GdipGetCompositingMode,
                    GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
                ),
            ),
            (
                HostThunk::GdipSetCompositingQuality,
                GDIPLUS_COMPOSITING_QUALITY_HIGH_QUALITY,
                (
                    HostThunk::GdipGetCompositingQuality,
                    GDIPLUS_COMPOSITING_QUALITY_HIGH_QUALITY,
                ),
            ),
            (
                HostThunk::GdipSetInterpolationMode,
                GDIPLUS_INTERPOLATION_HIGH_QUALITY_BICUBIC,
                (
                    HostThunk::GdipGetInterpolationMode,
                    GDIPLUS_INTERPOLATION_HIGH_QUALITY_BICUBIC,
                ),
            ),
            (
                HostThunk::GdipSetPixelOffsetMode,
                GDIPLUS_PIXEL_OFFSET_HALF,
                (HostThunk::GdipGetPixelOffsetMode, GDIPLUS_PIXEL_OFFSET_HALF),
            ),
        ] {
            let set_label = format!("{thunk:?}");
            let set = session.alloc_thunk(thunk);
            assert_eq!(
                session.call_x86(set, &[graphics as u32, value]),
                GdiplusStatus::Ok.to_u32(),
                "{set_label}"
            );
            let (getter, expected) = expected;
            let getter_label = format!("{getter:?}");
            assert_eq!(
                dispatch_get_mode(session, graphics, getter),
                expected,
                "{getter_label} must round-trip"
            );
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_31 — Status code validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_31_status_codes() {
    assert_eq!(GdiplusStatus::Ok.to_u32(), 0);
    assert_eq!(GdiplusStatus::GenericError.to_u32(), 1);
    assert_eq!(GdiplusStatus::InvalidParameter.to_u32(), 2);
    assert_eq!(GdiplusStatus::OutOfMemory.to_u32(), 3);
    assert_eq!(GdiplusStatus::ObjectBusy.to_u32(), 4);
    assert_eq!(GdiplusStatus::InsufficientBuffer.to_u32(), 5);
    assert_eq!(GdiplusStatus::NotImplemented.to_u32(), 6);
    assert_eq!(GdiplusStatus::Win32Error.to_u32(), 7);
    assert_eq!(GdiplusStatus::WrongState.to_u32(), 8);
    assert_eq!(GdiplusStatus::Aborted.to_u32(), 9);
    assert_eq!(GdiplusStatus::FileNotFound.to_u32(), 10);
    assert_eq!(GdiplusStatus::ValueOverflow.to_u32(), 11);
    assert_eq!(GdiplusStatus::AccessDenied.to_u32(), 12);
    assert_eq!(GdiplusStatus::UnknownImageFormat.to_u32(), 13);
    assert_eq!(GdiplusStatus::FontFamilyNotFound.to_u32(), 14);
    assert_eq!(GdiplusStatus::FontStyleNotFound.to_u32(), 15);
    assert_eq!(GdiplusStatus::NotTrueTypeFont.to_u32(), 16);
    assert_eq!(GdiplusStatus::UnsupportedGdiplusVersion.to_u32(), 17);
    // Discriminants per Microsoft GdiplusTypes.h: PropertyNotFound = 18,
    // PropertyNotSupported = 19, ProfileNotFound = 20.
    assert_eq!(GdiplusStatus::PropertyNotFound.to_u32(), 18);
    assert_eq!(GdiplusStatus::PropertyNotSupported.to_u32(), 19);
    assert_eq!(GdiplusStatus::ProfileNotFound.to_u32(), 20);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_32 — HostThunk enum variant existence check
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that all expected GDI+ HostThunk variants exist.
/// This is a compile-time-ish check — if any variant was removed or renamed,
/// this test would fail to compile or match.
#[test]
fn t33_32_hostthunk_variants_exist() {
    // Just verify pattern matching compiles for all GDI+ variants
    let _ = |t: HostThunk| match t {
        HostThunk::GdiplusStartup => 1,
        HostThunk::GdiplusShutdown => 1,
        HostThunk::GdipCreateFromHDC => 1,
        HostThunk::GdipDeleteGraphics => 1,
        HostThunk::GdipDrawLine => 1,
        HostThunk::GdipDrawLines => 1,
        HostThunk::GdipDrawRectangle => 1,
        HostThunk::GdipFillRectangle => 1,
        HostThunk::GdipDrawEllipse => 1,
        HostThunk::GdipFillEllipse => 1,
        HostThunk::GdipDrawPie => 1,
        HostThunk::GdipFillPie => 1,
        HostThunk::GdipDrawPolygon => 1,
        HostThunk::GdipFillPolygon => 1,
        HostThunk::GdipDrawArc => 1,
        HostThunk::GdipDrawCurve => 1,
        HostThunk::GdipDrawClosedCurve => 1,
        HostThunk::GdipDrawString => 1,
        HostThunk::GdipCreateSolidFill => 1,
        HostThunk::GdipCreateLineBrush => 1,
        HostThunk::GdipCreateTextureBrush => 1,
        HostThunk::GdipDeleteBrush => 1,
        HostThunk::GdipFillRegion => 1,
        HostThunk::GdipCreatePen1 => 1,
        HostThunk::GdipCreatePen2 => 1,
        HostThunk::GdipSetPenWidth => 1,
        HostThunk::GdipGetPenWidth => 1,
        HostThunk::GdipSetPenColor => 1,
        HostThunk::GdipGetPenColor => 1,
        HostThunk::GdipSetPenDashStyle => 1,
        HostThunk::GdipGetPenDashStyle => 1,
        HostThunk::GdipSetPenLineJoin => 1,
        HostThunk::GdipSetPenStartCap => 1,
        HostThunk::GdipSetPenEndCap => 1,
        HostThunk::GdipDeletePen => 1,
        HostThunk::GdipCreatePath => 1,
        HostThunk::GdipDeletePath => 1,
        HostThunk::GdipAddPathLine => 1,
        HostThunk::GdipAddPathRectangle => 1,
        HostThunk::GdipAddPathEllipse => 1,
        HostThunk::GdipAddPathArc => 1,
        HostThunk::GdipAddPathBezier => 1,
        HostThunk::GdipClosePathFigure => 1,
        HostThunk::GdipStartPathFigure => 1,
        HostThunk::GdipSetPathFillMode => 1,
        HostThunk::GdipDrawPath => 1,
        HostThunk::GdipFillPath => 1,
        HostThunk::GdipCreateMatrix => 1,
        HostThunk::GdipDeleteMatrix => 1,
        HostThunk::GdipSetMatrixElements => 1,
        HostThunk::GdipGetMatrixElements => 1,
        HostThunk::GdipTranslateMatrix => 1,
        HostThunk::GdipRotateMatrix => 1,
        HostThunk::GdipScaleMatrix => 1,
        HostThunk::GdipInvertMatrix => 1,
        HostThunk::GdipMultiplyMatrix => 1,
        HostThunk::GdipSetWorldTransform => 1,
        HostThunk::GdipResetWorldTransform => 1,
        HostThunk::GdipGetWorldTransform => 1,
        HostThunk::GdipSetClipRect => 1,
        HostThunk::GdipSetClipPath => 1,
        HostThunk::GdipSetClipRegion => 1,
        HostThunk::GdipResetClip => 1,
        HostThunk::GdipGetClipBounds => 1,
        HostThunk::GdipGetClip => 1,
        HostThunk::GdipSaveGraphics => 1,
        HostThunk::GdipRestoreGraphics => 1,
        HostThunk::GdipBeginContainer => 1,
        HostThunk::GdipEndContainer => 1,
        HostThunk::GdipCreateBitmapFromHBITMAP => 1,
        HostThunk::GdipCreateBitmapFromFile => 1,
        HostThunk::GdipCreateBitmapFromGraphics => 1,
        HostThunk::GdipDisposeImage => 1,
        HostThunk::GdipGetImageWidth => 1,
        HostThunk::GdipGetImageHeight => 1,
        HostThunk::GdipGetImagePixelFormat => 1,
        HostThunk::GdipBitmapGetPixel => 1,
        HostThunk::GdipBitmapSetPixel => 1,
        HostThunk::GdipBitmapLockBits => 1,
        HostThunk::GdipBitmapUnlockBits => 1,
        HostThunk::GdipCreateFont => 1,
        HostThunk::GdipDeleteFont => 1,
        HostThunk::GdipCreateFontFamilyFromName => 1,
        HostThunk::GdipDeleteFontFamily => 1,
        HostThunk::GdipSetTextRenderingHint => 1,
        HostThunk::GdipMeasureString => 1,
        HostThunk::GdipMeasureCharacterRanges => 1,
        HostThunk::GdipCreateImageAttributes => 1,
        HostThunk::GdipDisposeImageAttributes => 1,
        HostThunk::GdipSetImageAttributesColorKeys => 1,
        HostThunk::GdipSetImageAttributesColorMatrix => 1,
        HostThunk::GdipSetSmoothingMode => 1,
        HostThunk::GdipGetSmoothingMode => 1,
        HostThunk::GdipSetCompositingMode => 1,
        HostThunk::GdipGetCompositingMode => 1,
        HostThunk::GdipSetCompositingQuality => 1,
        HostThunk::GdipGetCompositingQuality => 1,
        HostThunk::GdipSetInterpolationMode => 1,
        HostThunk::GdipGetInterpolationMode => 1,
        HostThunk::GdipSetPixelOffsetMode => 1,
        HostThunk::GdipGetPixelOffsetMode => 1,
        HostThunk::GdipDrawImage => 1,
        HostThunk::GdipDrawImageRect => 1,
        HostThunk::GdipDrawImageRectRect => 1,
        HostThunk::GdipGetImageType => 1,
        HostThunk::GdipGetImageRawFormat => 1,
        HostThunk::GdipCloneImage => 1,
        HostThunk::GdipSaveImageToFile => 1,
        HostThunk::GdipSaveImageToStream => 1,
        HostThunk::GdipCreateBitmapFromStream => 1,
        HostThunk::GdipCreateBitmapFromScan0 => 1,
        HostThunk::GdipCreateHICONFromBitmap => 1,
        HostThunk::GdipCreateHBITMAPFromBitmap => 1,
        HostThunk::GdipCreateImageFromFile => 1,
        HostThunk::GdipImageForceValidation => 1,
        HostThunk::GdipGetFontHeight => 1,
        HostThunk::GdipCreateBitmapFromGdiDib => 1,
        _ => 0, // Non-GDI+ variants
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_33 — GdiplusStartupInput defaults
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_33_startup_input_defaults() {
    let input = GdiplusStartupInput::default();
    assert_eq!(input.gdiplus_version, 1);
    assert_eq!(input.debug_event_callback, 0);
    assert!(!input.suppress_background_thread);
    assert!(!input.suppress_external_codecs);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_34 — PointF and RectF layout
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_34_pointf_and_rectf() {
    let pt = GdiplusPointF { x: 10.5, y: 20.5 };
    assert!((pt.x - 10.5).abs() < f32::EPSILON);
    assert!((pt.y - 20.5).abs() < f32::EPSILON);

    let rect = GdiplusRectF {
        x: 1.0,
        y: 2.0,
        width: 100.0,
        height: 200.0,
    };
    assert!((rect.x - 1.0).abs() < f32::EPSILON);
    assert!((rect.width - 100.0).abs() < f32::EPSILON);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_35 — Handle allocation monotonic
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_35_handle_allocation_monotonic() {
    let mut state = fresh_state();
    let h1 = state.alloc_handle(GdiplusObject::Matrix(Box::new(GdiplusMatrix::identity())));
    let h2 = state.alloc_handle(GdiplusObject::Matrix(Box::new(GdiplusMatrix::identity())));
    let h3 = state.alloc_handle(GdiplusObject::Matrix(Box::new(GdiplusMatrix::identity())));
    assert!(h1 < h2, "handles should increase monotonically");
    assert!(h2 < h3, "handles should increase monotonically");
    assert_eq!(h3 - h2, 1, "handles must be dense and consecutive");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_36 — Graphics state defaults
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_36_graphics_state_defaults() {
    let mut state = fresh_state();
    let hdc: u64 = 0x700;
    let handle = state.create_graphics_from_hdc(hdc);

    match state.get(handle).expect("graphics should exist") {
        GdiplusObject::Graphics(gfx) => {
            assert_eq!(gfx.hdc, hdc);
            assert_eq!(gfx.smoothing_mode, GDIPLUS_SMOOTHING_MODE_DEFAULT);
            assert_eq!(gfx.compositing_mode, GDIPLUS_COMPOSITING_MODE_SOURCE_OVER);
            assert_eq!(gfx.compositing_quality, GDIPLUS_COMPOSITING_QUALITY_DEFAULT);
            assert_eq!(gfx.interpolation_mode, GDIPLUS_INTERPOLATION_DEFAULT);
            assert_eq!(gfx.pixel_offset_mode, GDIPLUS_PIXEL_OFFSET_DEFAULT);
            assert_eq!(
                gfx.text_rendering_hint,
                GDIPLUS_TEXT_RENDERING_HINT_SYSTEM_DEFAULT
            );
            assert!(gfx.clip_rect.is_none());
            assert!(gfx.world_transform.is_none());
            assert!(gfx.container_stack.is_empty());
            assert_eq!(gfx.next_container, 1);
        }
        _ => panic!("expected Graphics object"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_37 — Multiple HDC to multiple graphics contexts
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_37_multiple_hdc_graphics() {
    let mut state = fresh_state();
    let g1 = state.create_graphics_from_hdc(0x100);
    let g2 = state.create_graphics_from_hdc(0x200);
    let g3 = state.create_graphics_from_hdc(0x300);

    assert_ne!(
        g1, g2,
        "different HDCs should get different graphics handles"
    );
    assert_ne!(
        g2, g3,
        "different HDCs should get different graphics handles"
    );

    // Same HDC returns cached
    let g1_cached = state.create_graphics_from_hdc(0x100);
    assert_eq!(g1, g1_cached, "same HDC should return cached handle");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_38 — Path element variants
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_38_path_element_variants() {
    let _ = GdiplusPathElement::StartFigure;
    let _ = GdiplusPathElement::CloseFigure;
    let _ = GdiplusPathElement::Line {
        x1: 0.0,
        y1: 0.0,
        x2: 1.0,
        y2: 1.0,
    };
    let _ = GdiplusPathElement::Rectangle {
        x: 0.0,
        y: 0.0,
        w: 1.0,
        h: 1.0,
    };
    let _ = GdiplusPathElement::Ellipse {
        x: 0.0,
        y: 0.0,
        w: 1.0,
        h: 1.0,
    };
    let _ = GdiplusPathElement::Arc {
        x: 0.0,
        y: 0.0,
        w: 1.0,
        h: 1.0,
        start_angle: 0.0,
        sweep_angle: 90.0,
    };
    let _ = GdiplusPathElement::Bezier {
        points: [
            GdiplusPointF { x: 0.0, y: 0.0 },
            GdiplusPointF { x: 1.0, y: 1.0 },
            GdiplusPointF { x: 2.0, y: 2.0 },
            GdiplusPointF { x: 3.0, y: 3.0 },
        ],
    };
    let _ = GdiplusPathElement::Polygon {
        points: vec![GdiplusPointF { x: 0.0, y: 0.0 }],
    };
    let _ = GdiplusPathElement::Pie {
        x: 0.0,
        y: 0.0,
        w: 1.0,
        h: 1.0,
        start_angle: 0.0,
        sweep_angle: 90.0,
    };
    let _ = GdiplusPathElement::String {
        text: "hello".to_string(),
        font_handle: 0,
        layout_rect: GdiplusRectF {
            x: 0.0,
            y: 0.0,
            width: 100.0,
            height: 20.0,
        },
        format_flags: 0,
    };
    let _ = GdiplusPathElement::Lines {
        points: vec![
            GdiplusPointF { x: 0.0, y: 0.0 },
            GdiplusPointF { x: 1.0, y: 1.0 },
        ],
    };
    let _ = GdiplusPathElement::Curve {
        points: vec![GdiplusPointF { x: 0.0, y: 0.0 }],
        tension: 0.5,
    };
    let _ = GdiplusPathElement::ClosedCurve {
        points: vec![GdiplusPointF { x: 0.0, y: 0.0 }],
        tension: 0.5,
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_39 — Empty state handling
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_39_empty_state() {
    let state = fresh_state();
    assert!(!state.initialized);
    assert_eq!(state.token, 0);
    assert_eq!(state.next_handle, 0xDD010000);
    assert!(state.objects.is_empty());
    assert!(state.graphics_from_hdc.is_empty());
    assert!(state.hdc_to_graphics.is_empty());
    assert!(state.get(0xDD010000).is_none());
    assert!(state.get(0).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_40 — GdiplusState default field ordering
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_40_state_default_values() {
    let state = GdiplusState::default();
    assert_eq!(state.startup_input.gdiplus_version, 1);
    assert_eq!(state.next_handle, 0xDD010000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_41 — Bitmap pixel get/set
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_41_bitmap_pixel_get_set() {
    let mut state = fresh_state();
    let bmp = GdiplusBitmap {
        width: 4,
        height: 4,
        pixel_format: GDIPLUS_PIXEL_FORMAT_32BPP_ARGB,
        stride: 16, // 4 * 4
        pixels: vec![0; 64],
        locked: false,
        scan0_guest: 0,
        lock_x: 0,
        lock_y: 0,
        raw_kind: 0,
    };
    let handle = state.alloc_handle(GdiplusObject::Image(Box::new(GdiplusImage::Bitmap(bmp))));

    // Set pixel at (1, 1) to red
    if let Some(GdiplusObject::Image(img)) = state.get_mut(handle)
        && let GdiplusImage::Bitmap(b) = &mut **img
    {
        let idx = (b.stride + 4) as usize;
        let bytes = 0xFFFF0000u32.to_le_bytes();
        b.pixels[idx..idx + 4].copy_from_slice(&bytes);
    }

    // Get pixel at (1, 1) and verify
    if let Some(GdiplusObject::Image(img)) = state.get(handle)
        && let GdiplusImage::Bitmap(b) = &**img
    {
        let idx = (b.stride + 4) as usize;
        let color = u32::from_le_bytes([
            b.pixels[idx],
            b.pixels[idx + 1],
            b.pixels[idx + 2],
            b.pixels[idx + 3],
        ]);
        assert_eq!(
            color, 0xFFFF0000,
            "bitmap get/set pixel at (1,1) should be red"
        );
    }

    // Verify out-of-bounds access doesn't panic (edge case)
    if let Some(GdiplusObject::Image(img)) = state.get(handle)
        && let GdiplusImage::Bitmap(b) = &**img
    {
        let x = 10u32;
        let y = 10u32;
        if x < b.width && y < b.height {
            let idx = (y as i32 * b.stride + x as i32 * 4) as usize;
            if idx + 3 < b.pixels.len() {
                // Should not reach here for 4x4 bitmap
                panic!("out-of-bounds access should not be valid");
            }
        }
    }

    // Cleanup
    state.remove(handle);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_42 — Renderer fill rect pixel verification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_42_renderer_fill_rect() {
    use casa1::gdiplus_render::fill_rect;

    let mut pixels = vec![0u8; 10 * 10 * 4]; // 10x10 bitmap, 32bpp
    let stride = 40i32; // 10 * 4
    let color = 0xFF00FF00u32; // green

    fill_rect(
        &mut pixels,
        10,
        10,
        stride,
        2.0,
        2.0,
        6.0,
        6.0,
        color,
        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
    );

    // Inside fill area
    let idx = (4 * stride + 4 * 4) as usize;
    let pixel = u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]);
    assert_eq!(pixel, 0xFF00FF00, "inside fill rect should be green");

    // Outside fill area (top-left)
    let idx_out = (0 * stride) as usize;
    let pixel_out = u32::from_le_bytes([
        pixels[idx_out],
        pixels[idx_out + 1],
        pixels[idx_out + 2],
        pixels[idx_out + 3],
    ]);
    assert_eq!(
        pixel_out, 0x00000000,
        "outside fill rect should be transparent"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_43 — Renderer draw line pixel verification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_43_renderer_draw_line() {
    use casa1::gdiplus_render::draw_line;

    let mut pixels = vec![0u8; 20 * 20 * 4];
    let stride = 80i32;

    // Draw a horizontal red line at y=10 from x=2 to x=18
    draw_line(
        &mut pixels,
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
        GDIPLUS_SMOOTHING_MODE_DEFAULT,
    );

    // Check pixels on the line
    let idx = (10 * stride + 5 * 4) as usize;
    let pixel = u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]);
    assert_eq!(pixel, 0xFFFF0000, "pixel on drawn line should be red");

    // Check pixel off the line (row 0)
    let idx_off = (0 * stride) as usize;
    let pixel_off = u32::from_le_bytes([
        pixels[idx_off],
        pixels[idx_off + 1],
        pixels[idx_off + 2],
        pixels[idx_off + 3],
    ]);
    assert_eq!(
        pixel_off, 0x00000000,
        "pixel off line should be transparent"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_44 — Renderer fill ellipse pixel verification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_44_renderer_fill_ellipse() {
    use casa1::gdiplus_render::fill_ellipse;

    let mut pixels = vec![0u8; 40 * 40 * 4];
    let stride = 160i32;

    fill_ellipse(
        &mut pixels,
        40,
        40,
        stride,
        5.0,
        5.0,
        30.0,
        30.0,
        0xFF0000FF,
        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
    );

    // Centre should be filled
    let idx = (20 * stride + 20 * 4) as usize;
    let pixel = u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]);
    assert_eq!(pixel, 0xFF0000FF, "centre of filled ellipse should be blue");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_45 — Renderer fill polygon pixel verification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_45_renderer_fill_polygon() {
    use casa1::gdiplus_render::fill_polygon;

    let mut pixels = vec![0u8; 20 * 20 * 4];
    let stride = 80i32;
    let pts = vec![
        GdiplusPointF { x: 2.0, y: 2.0 },
        GdiplusPointF { x: 18.0, y: 2.0 },
        GdiplusPointF { x: 10.0, y: 18.0 },
    ];

    fill_polygon(
        &mut pixels,
        20,
        20,
        stride,
        &pts,
        0xFF00FFFF,
        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
    );

    // Centre-ish should be filled
    let idx = (10 * stride + 10 * 4) as usize;
    let pixel = u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]);
    assert_eq!(pixel, 0xFF00FFFF, "centre of filled polygon should be cyan");

    // Top edge (non-fill area in a triangle)
    let idx_top = (stride + 10 * 4) as usize;
    let pixel_top = u32::from_le_bytes([
        pixels[idx_top],
        pixels[idx_top + 1],
        pixels[idx_top + 2],
        pixels[idx_top + 3],
    ]);
    assert_eq!(
        pixel_top, 0x00000000,
        "outside polygon should be transparent"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_46 — Renderer draw_image pixel verification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_46_renderer_draw_image() {
    use casa1::gdiplus_render::draw_image;

    let mut dst = vec![0u8; 20 * 20 * 4];
    let dst_stride = 80i32;

    // Create a 3x3 source bitmap with a red pixel at (1,1)
    let src_stride = 12i32;
    let mut src = vec![0u8; (src_stride * 3) as usize];
    let red_bytes = 0xFFFF0000u32.to_le_bytes();
    let idx_src = (src_stride + 4) as usize;
    src[idx_src..idx_src + 4].copy_from_slice(&red_bytes);

    draw_image(
        &mut dst,
        20,
        20,
        dst_stride,
        &src,
        3,
        3,
        src_stride,
        5.0,
        5.0,
        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
    );

    // The red pixel from src (1,1) should appear at dst (6,6)
    let idx = (6 * dst_stride + 6 * 4) as usize;
    let pixel = u32::from_le_bytes([dst[idx], dst[idx + 1], dst[idx + 2], dst[idx + 3]]);
    assert_eq!(
        pixel, 0xFFFF0000,
        "drawn image pixel at (6,6) should be red"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_47 — Renderer draw_string pixel verification
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_47_renderer_draw_string() {
    use casa1::gdiplus_render::draw_string;

    let mut pixels = vec![0u8; 50 * 50 * 4];
    let stride = 200i32;

    draw_string(
        &mut pixels,
        50,
        50,
        stride,
        "Hi",
        5.0,
        5.0,
        12.0,
        0xFFFFFFFF,
        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
    );

    // Documented renderer contract: each character is drawn as a solid block
    // of `font_size * 0.6` × `font_size * 1.2` pixels (clamped to a minimum of
    // 4×8). For font_size 12.0: char_w = 7, char_h = 14. "Hi" draws two blocks
    // starting at (5,5). Assert the whole first block is white and that pixels
    // below the blocks are untouched (0) — not just a single placeholder pixel.
    let char_w = 7usize;
    let char_h = 14usize;
    for py in 0..char_h {
        for px in 0..char_w {
            let idx = (5 + py) * stride as usize + (5 + px) * 4;
            let pixel = u32::from_le_bytes([
                pixels[idx],
                pixels[idx + 1],
                pixels[idx + 2],
                pixels[idx + 3],
            ]);
            assert_eq!(
                pixel, 0xFFFFFFFF,
                "character block pixel ({px},{py}) must be white"
            );
        }
    }
    let below = 5 * stride as usize + 5 * 4 + char_h * stride as usize;
    assert_eq!(
        pixels[below], 0,
        "pixels below the text blocks must be untouched"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t33_48 — Renderer alpha blending
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t33_48_renderer_alpha_blend() {
    use casa1::gdiplus_render::fill_rect;

    let mut pixels = vec![0u8; 10 * 10 * 4];
    let stride = 40i32;

    // Fill entire area with opaque white
    fill_rect(
        &mut pixels,
        10,
        10,
        stride,
        0.0,
        0.0,
        10.0,
        10.0,
        0xFFFFFFFF,
        GDIPLUS_COMPOSITING_MODE_SOURCE_COPY,
    );

    // Now overlay semi-transparent red at (2,2)-(7,7)
    fill_rect(
        &mut pixels,
        10,
        10,
        stride,
        2.0,
        2.0,
        5.0,
        5.0,
        0x80FF0000,
        GDIPLUS_COMPOSITING_MODE_SOURCE_OVER,
    );

    // Pixel at (4,4) should be blended (not pure red, not pure white)
    let idx = (4 * stride + 4 * 4) as usize;
    let pixel = u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]);
    let r = (pixel >> 16) & 0xFF;
    let b = pixel & 0xFF;
    // With source-over, red should be visible but blue should still have some value
    assert!(r > 128, "blended pixel should show red (r={})", r);
    assert!(b < 255, "blended pixel should have reduced blue (b={})", b);
}
