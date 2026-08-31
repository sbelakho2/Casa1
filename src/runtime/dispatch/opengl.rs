//! OpenGL 1.1 fixed-function dispatch: the opengl32.dll gl*/wgl* and
//! glu32.dll exports, in a dedicated module per the audit's modularity
//! requirement.  The guest-facing surface is a real fixed-function state
//! machine: per-context matrix stacks (modelview/projection/texture), the
//! immediate-mode vertex pipeline (glBegin/glEnd, client vertex arrays,
//! glDrawArrays/glDrawElements), texture objects, depth/alpha blending,
//! and a software rasterizer rendering into a per-context framebuffer that
//! glReadPixels can read back and wglSwapBuffers can expose.  glu32 builds
//! on the same matrices (gluPerspective/gluLookAt/gluProject/gluUnProject)
//! and generates quadric geometry (gluSphere/gluCylinder/gluDisk).
//!
//! Layer contract: gl* functions return void (RAX is left undefined);
//! wgl* return BOOL/ints in EAX; glu* return GLU error codes; errors are
//! recorded in the GL error register and reported through glGetError.

use super::super::*;
use crate::runtime::state::{
    GlArrayBinding, GlArraysState, GlFramebufferState, GlTextureState, GlVertexState, OpenGlContext,
};
use std::collections::HashMap;

// ── GL constants (the OpenGL 1.1 token set) ────────────────────────────────

const GL_NO_ERROR: u32 = 0;
const GL_INVALID_ENUM: u32 = 0x0500;
const GL_INVALID_VALUE: u32 = 0x0501;
const GL_INVALID_OPERATION: u32 = 0x0502;

const GL_TRUE: u32 = 1;
const GL_FALSE: u32 = 0;

const GL_POINTS: u32 = 0x0000;
const GL_LINES: u32 = 0x0001;
const GL_LINE_LOOP: u32 = 0x0002;
const GL_LINE_STRIP: u32 = 0x0003;
const GL_TRIANGLES: u32 = 0x0004;
const GL_TRIANGLE_STRIP: u32 = 0x0005;
const GL_TRIANGLE_FAN: u32 = 0x0006;
const GL_QUADS: u32 = 0x0007;
const GL_QUAD_STRIP: u32 = 0x0008;
const GL_POLYGON: u32 = 0x0009;

const GL_MODELVIEW: u32 = 0x1700;
const GL_PROJECTION: u32 = 0x1701;
const GL_TEXTURE: u32 = 0x1702;

const GL_DEPTH_TEST: u32 = 0x0B71;
const GL_CULL_FACE: u32 = 0x0B44;
const GL_LIGHTING: u32 = 0x0B50;
const GL_TEXTURE_2D: u32 = 0x0DE1;
const GL_BLEND: u32 = 0x0BE2;

const GL_NEVER: u32 = 0x0200;
const GL_LESS: u32 = 0x0201;
const GL_EQUAL: u32 = 0x0202;
const GL_LEQUAL: u32 = 0x0203;
const GL_GREATER: u32 = 0x0204;
const GL_NOTEQUAL: u32 = 0x0205;
const GL_GEQUAL: u32 = 0x0206;
const GL_ALWAYS: u32 = 0x0207;

const GL_BACK: u32 = 0x0405;
const GL_FRONT: u32 = 0x0404;
const GL_CW: u32 = 0x0900;
const GL_CCW: u32 = 0x0901;

const GL_FLAT: u32 = 0x1D00;
const GL_SMOOTH: u32 = 0x1D01;

const GL_ZERO: u32 = 0;
const GL_ONE: u32 = 1;
const GL_SRC_ALPHA: u32 = 0x0302;
const GL_ONE_MINUS_SRC_ALPHA: u32 = 0x0303;
const GL_DST_ALPHA: u32 = 0x0304;
const GL_ONE_MINUS_DST_ALPHA: u32 = 0x0305;

const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
const GL_NEAREST: u32 = 0x2600;
const GL_LINEAR: u32 = 0x2601;

const GL_UNSIGNED_BYTE: u32 = 0x1401;
const GL_UNSIGNED_SHORT: u32 = 0x1403;
const GL_UNSIGNED_INT: u32 = 0x1405;
const GL_FLOAT: u32 = 0x1406;

const GL_RGBA: u32 = 0x1908;
const GL_RGB: u32 = 0x1907;
const GL_LUMINANCE: u32 = 0x1909;
const GL_ALPHA: u32 = 0x1906;

const GL_COLOR_BUFFER_BIT: u32 = 0x0000_4000;
const GL_DEPTH_BUFFER_BIT: u32 = 0x0000_0100;

const GL_VERTEX_ARRAY: u32 = 0x8074;
const GL_COLOR_ARRAY: u32 = 0x8076;
const GL_NORMAL_ARRAY: u32 = 0x8075;
const GL_TEXTURE_COORD_ARRAY: u32 = 0x8078;

const GL_LIGHT0: u32 = 0x4000;
const GL_POSITION: u32 = 0x1203;
const GL_AMBIENT_AND_DIFFUSE: u32 = 0x1600;

const GL_VENDOR: u32 = 0x1F00;
const GL_RENDERER: u32 = 0x1F01;
const GL_VERSION: u32 = 0x1F02;
const GL_EXTENSIONS: u32 = 0x1F03;

const GL_FOG: u32 = 0x0B60;
const GL_FOG_DENSITY: u32 = 0x0B62;
const GL_FOG_START: u32 = 0x0B63;
const GL_FOG_END: u32 = 0x0B64;
const GL_FOG_MODE: u32 = 0x0B65;

const GL_PERSPECTIVE_CORRECTION_HINT: u32 = 0x0C50;
const GL_POINT_SMOOTH_HINT: u32 = 0x0C51;
const GL_LINE_SMOOTH_HINT: u32 = 0x0C52;
const GL_POLYGON_SMOOTH_HINT: u32 = 0x0C53;
const GL_FOG_HINT: u32 = 0x0C54;

const GL_AMBIENT: u32 = 0x1200;
const GL_DIFFUSE: u32 = 0x1201;
const GL_SPECULAR: u32 = 0x1202;

// ── Matrix helpers (row-major [16] f32) ────────────────────────────────────

fn mat_identity() -> [f32; 16] {
    let mut m = [0.0; 16];
    m[0] = 1.0;
    m[5] = 1.0;
    m[10] = 1.0;
    m[15] = 1.0;
    m
}

fn mat_mul(a: [f32; 16], b: [f32; 16]) -> [f32; 16] {
    let mut out = [0.0; 16];
    for row in 0..4 {
        for col in 0..4 {
            let mut sum = 0.0;
            for k in 0..4 {
                sum += a[row * 4 + k] * b[k * 4 + col];
            }
            out[row * 4 + col] = sum;
        }
    }
    out
}

fn mat_transform(m: &[f32; 16], v: [f32; 4]) -> [f32; 4] {
    let mut out = [0.0; 4];
    for row in 0..4 {
        let mut sum = 0.0;
        for k in 0..4 {
            sum += m[row * 4 + k] * v[k];
        }
        out[row] = sum;
    }
    out
}

fn mat_ortho(l: f32, r: f32, b: f32, t: f32, n: f32, f: f32) -> [f32; 16] {
    let mut m = mat_identity();
    m[0] = 2.0 / (r - l);
    m[5] = 2.0 / (t - b);
    m[10] = -2.0 / (f - n);
    m[12] = -(r + l) / (r - l);
    m[13] = -(t + b) / (t - b);
    m[14] = -(f + n) / (f - n);
    m
}

fn mat_perspective(fovy_deg: f32, aspect: f32, znear: f32, zfar: f32) -> [f32; 16] {
    let f = 1.0 / (fovy_deg.to_radians() * 0.5).tan();
    let mut m = [0.0; 16];
    m[0] = f / aspect;
    m[5] = f;
    m[10] = (zfar + znear) / (znear - zfar);
    m[11] = -1.0;
    m[14] = 2.0 * zfar * znear / (znear - zfar);
    m
}

fn mat_lookat(eye: [f32; 3], center: [f32; 3], up: [f32; 3]) -> [f32; 16] {
    let f = {
        let mut v = [center[0] - eye[0], center[1] - eye[1], center[2] - eye[2]];
        let len = (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt();
        if len > 0.0 {
            v[0] /= len;
            v[1] /= len;
            v[2] /= len;
        }
        v
    };
    let s = cross3(f, up);
    let u = cross3(s, f);
    let mut m = [0.0; 16];
    m[0] = s[0];
    m[1] = u[0];
    m[2] = -f[0];
    m[4] = s[1];
    m[5] = u[1];
    m[6] = -f[1];
    m[8] = s[2];
    m[9] = u[2];
    m[10] = -f[2];
    m[12] = -(s[0] * eye[0] + s[1] * eye[1] + s[2] * eye[2]);
    m[13] = -(u[0] * eye[0] + u[1] * eye[1] + u[2] * eye[2]);
    m[14] = f[0] * eye[0] + f[1] * eye[1] + f[2] * eye[2];
    m[15] = 1.0;
    m
}

fn cross3(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

fn mat_inverse(m: &[f32; 16]) -> Option<[f32; 16]> {
    let mut a = *m;
    let mut inv = mat_identity();
    for col in 0..4 {
        let mut pivot = col;
        let mut best = a[col * 4 + col].abs();
        for row in (col + 1)..4 {
            let v = a[row * 4 + col].abs();
            if v > best {
                best = v;
                pivot = row;
            }
        }
        if best < 1.0e-12 {
            return None;
        }
        if pivot != col {
            for k in 0..4 {
                a.swap(col * 4 + k, pivot * 4 + k);
                inv.swap(col * 4 + k, pivot * 4 + k);
            }
        }
        let d = a[col * 4 + col];
        for k in 0..4 {
            a[col * 4 + k] /= d;
            inv[col * 4 + k] /= d;
        }
        for row in 0..4 {
            if row == col {
                continue;
            }
            let factor = a[row * 4 + col];
            if factor.abs() < 1.0e-15 {
                continue;
            }
            for k in 0..4 {
                a[row * 4 + k] -= factor * a[col * 4 + k];
                inv[row * 4 + k] -= factor * inv[col * 4 + k];
            }
        }
    }
    Some(inv)
}

// ── Guest argument helpers (f32/f64 in XMM0-3 on x64, the stack beyond) ───

fn gl_arg_f32(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<f32> {
    if state.arch == GuestArch::X64 {
        if index < 4 {
            return Ok(f32::from_bits(state.xmm[index].low as u32));
        }
        let address = state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8);
        Ok(f32::from_bits(memory.read_u32(address)?))
    } else {
        Ok(f32::from_bits(
            memory.read_u32(state.get(Register::Rsp) + (index as u64 * 4))?,
        ))
    }
}

/// Read an integer thunk argument at `position` when `floats_before`
/// floating-point arguments precede it in the call (Win64 numbers the
/// integer registers after the floats are assigned).
fn gl_mixed_int_arg(
    state: &CpuState,
    memory: &MemoryImage,
    position: usize,
    floats_before: usize,
) -> AppResult<u32> {
    if state.arch == GuestArch::X64 {
        let int_index = position - floats_before;
        match int_index {
            0 => Ok(state.get(Register::Rcx) as u32),
            1 => Ok(state.get(Register::Rdx) as u32),
            2 => Ok(state.get(Register::R8) as u32),
            3 => Ok(state.get(Register::R9) as u32),
            _ => memory.read_u32(state.get(Register::Rsp) + 0x20 + ((position - 4) as u64 * 8)),
        }
    } else {
        memory.read_u32(state.get(Register::Rsp) + (position as u64 * 4))
    }
}

fn gl_arg_f64(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<f64> {
    if state.arch == GuestArch::X64 {
        if index < 4 {
            return Ok(f64::from_bits(state.xmm[index].low));
        }
        let address = state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8);
        Ok(f64::from_bits(memory.read_u64(address)?))
    } else {
        Ok(f64::from_bits(
            memory.read_u64(state.get(Register::Rsp) + (index as u64 * 8))?,
        ))
    }
}

// ── The grouped dispatcher ─────────────────────────────────────────────────

impl PeHostRuntime {
    /// Route every OpenGL thunk to its dispatch function.
    pub(crate) fn dispatch_gl_or_glu(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::GlBegin => self.dispatch_gl_begin(state, memory),
            HostThunk::GlEnd => self.dispatch_gl_end(state, memory),
            HostThunk::GlVertex2f => self.dispatch_gl_vertex2f(state, memory),
            HostThunk::GlVertex3f => self.dispatch_gl_vertex3f(state, memory),
            HostThunk::GlColor3f => self.dispatch_gl_color3f(state, memory),
            HostThunk::GlColor4f => self.dispatch_gl_color4f(state, memory),
            HostThunk::GlClearColor => self.dispatch_gl_clear_color(state, memory),
            HostThunk::GlClear => self.dispatch_gl_clear(state, memory),
            HostThunk::GlMatrixMode => self.dispatch_gl_matrix_mode(state, memory),
            HostThunk::GlLoadIdentity => self.dispatch_gl_load_identity(state, memory),
            HostThunk::GlPushMatrix => self.dispatch_gl_push_matrix(state, memory),
            HostThunk::GlPopMatrix => self.dispatch_gl_pop_matrix(state, memory),
            HostThunk::GlOrtho => self.dispatch_gl_ortho(state, memory),
            HostThunk::GlTranslatef => self.dispatch_gl_translatef(state, memory),
            HostThunk::GlRotatef => self.dispatch_gl_rotatef(state, memory),
            HostThunk::GlScalef => self.dispatch_gl_scalef(state, memory),
            HostThunk::GlViewport => self.dispatch_gl_viewport(state, memory),
            HostThunk::GlEnable => self.dispatch_gl_enable(state, memory),
            HostThunk::GlDisable => self.dispatch_gl_disable(state, memory),
            HostThunk::GlDepthFunc => self.dispatch_gl_depth_func(state, memory),
            HostThunk::GlCullFace => self.dispatch_gl_cull_face(state, memory),
            HostThunk::GlFrontFace => self.dispatch_gl_front_face(state, memory),
            HostThunk::GlShadeModel => self.dispatch_gl_shade_model(state, memory),
            HostThunk::GlBlendFunc => self.dispatch_gl_blend_func(state, memory),
            HostThunk::GlHint => self.dispatch_gl_hint(state, memory),
            HostThunk::GlFogf => self.dispatch_gl_fogf(state, memory),
            HostThunk::GlFogi => self.dispatch_gl_fogi(state, memory),
            HostThunk::GlLightfv => self.dispatch_gl_lightfv(state, memory),
            HostThunk::GlMaterialfv => self.dispatch_gl_materialfv(state, memory),
            HostThunk::GlGenTextures => self.dispatch_gl_gen_textures(state, memory),
            HostThunk::GlBindTexture => self.dispatch_gl_bind_texture(state, memory),
            HostThunk::GlDeleteTextures => self.dispatch_gl_delete_textures(state, memory),
            HostThunk::GlTexImage2D => self.dispatch_gl_tex_image_2d(state, memory),
            HostThunk::GlTexParameterf => self.dispatch_gl_tex_parameterf(state, memory),
            HostThunk::GlTexParameteri => self.dispatch_gl_tex_parameteri(state, memory),
            HostThunk::GlTexCoord2f => self.dispatch_gl_tex_coord2f(state, memory),
            HostThunk::GlVertexPointer => self.dispatch_gl_vertex_pointer(state, memory),
            HostThunk::GlColorPointer => self.dispatch_gl_color_pointer(state, memory),
            HostThunk::GlNormalPointer => self.dispatch_gl_normal_pointer(state, memory),
            HostThunk::GlTexCoordPointer => self.dispatch_gl_tex_coord_pointer(state, memory),
            HostThunk::GlEnableClientState => self.dispatch_gl_enable_client_state(state, memory),
            HostThunk::GlDisableClientState => self.dispatch_gl_disable_client_state(state, memory),
            HostThunk::GlDrawArrays => self.dispatch_gl_draw_arrays(state, memory),
            HostThunk::GlDrawElements => self.dispatch_gl_draw_elements(state, memory),
            HostThunk::GlReadPixels => self.dispatch_gl_read_pixels(state, memory),
            HostThunk::GlGetError => self.dispatch_gl_get_error(state, memory),
            HostThunk::GlGetString => self.dispatch_gl_get_string(state, memory),
            HostThunk::GlFlush | HostThunk::GlFinish => {
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::WglChoosePixelFormat => self.dispatch_wgl_choose_pixel_format(state, memory),
            HostThunk::WglDescribePixelFormat => {
                self.dispatch_wgl_describe_pixel_format(state, memory)
            }
            HostThunk::WglGetPixelFormat => self.dispatch_wgl_get_pixel_format(state, memory),
            HostThunk::WglSetPixelFormat => self.dispatch_wgl_set_pixel_format(state, memory),
            HostThunk::WglCreateContext => self.dispatch_wgl_create_context(state, memory),
            HostThunk::WglMakeCurrent => self.dispatch_wgl_make_current(state, memory),
            HostThunk::WglDeleteContext => self.dispatch_wgl_delete_context(state, memory),
            HostThunk::WglGetProcAddress => self.dispatch_wgl_get_proc_address(state, memory),
            HostThunk::WglSwapBuffers => self.dispatch_wgl_swap_buffers(state, memory),
            HostThunk::GluPerspective => self.dispatch_glu_perspective(state, memory),
            HostThunk::GluPickMatrix => self.dispatch_glu_pick_matrix(state, memory),
            HostThunk::GluLookAt => self.dispatch_glu_look_at(state, memory),
            HostThunk::GluOrtho2D => self.dispatch_glu_ortho_2d(state, memory),
            HostThunk::GluErrorString => self.dispatch_glu_error_string(state, memory),
            HostThunk::GluProject => self.dispatch_glu_project(state, memory),
            HostThunk::GluUnProject => self.dispatch_glu_unproject(state, memory),
            HostThunk::GluScaleImage => self.dispatch_glu_scale_image(state, memory),
            HostThunk::GluBuild2DMipmaps => self.dispatch_glu_build_2d_mipmaps(state, memory),
            HostThunk::GluNewQuadric => self.dispatch_glu_new_quadric(state, memory),
            HostThunk::GluDeleteQuadric => self.dispatch_glu_delete_quadric(state, memory),
            HostThunk::GluSphere => self.dispatch_glu_quadric(state, memory, 0),
            HostThunk::GluCylinder => self.dispatch_glu_quadric(state, memory, 1),
            HostThunk::GluDisk => self.dispatch_glu_quadric(state, memory, 2),
            HostThunk::GluPartialDisk => self.dispatch_glu_quadric(state, memory, 3),
            HostThunk::GluNewTess => self.dispatch_glu_new_tess(state, memory),
            HostThunk::GluTessBeginPolygon => self.dispatch_glu_tess_begin_polygon(state, memory),
            HostThunk::GluTessVertex => self.dispatch_glu_tess_vertex(state, memory),
            HostThunk::GluTessEndPolygon => self.dispatch_glu_tess_end_polygon(state, memory),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted GL thunk {thunk:?}"),
            )),
        }
    }

    // ── State helpers ──────────────────────────────────────────────────────

    fn gl_current_context_mut(&mut self) -> Option<&mut OpenGlContext> {
        let current = self.opengl.current_context;
        self.opengl.contexts.get_mut(&current)
    }

    fn gl_record_error(&mut self, error: u32) {
        if self.opengl.error == GL_NO_ERROR {
            self.opengl.error = error;
        }
    }

    fn gl_matrix_stack_mut(ctx: &mut OpenGlContext) -> &mut Vec<[f32; 16]> {
        match ctx.matrix_mode {
            GL_PROJECTION => &mut ctx.projection,
            GL_TEXTURE => &mut ctx.texture,
            _ => &mut ctx.modelview,
        }
    }

    fn gl_multiply_current_matrix(ctx: &mut OpenGlContext, m: [f32; 16]) {
        let stack = Self::gl_matrix_stack_mut(ctx);
        let top = stack.last().copied().unwrap_or_else(mat_identity);
        if let Some(top_slot) = stack.last_mut() {
            *top_slot = mat_mul(top, m);
        }
    }

    // ── Immediate-mode state ───────────────────────────────────────────────

    fn dispatch_gl_begin(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        let valid = matches!(
            mode,
            GL_POINTS
                | GL_LINES
                | GL_LINE_LOOP
                | GL_LINE_STRIP
                | GL_TRIANGLES
                | GL_TRIANGLE_STRIP
                | GL_TRIANGLE_FAN
                | GL_QUADS
                | GL_QUAD_STRIP
                | GL_POLYGON
        );
        if !valid {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if self
            .opengl
            .contexts
            .get(&self.opengl.current_context)
            .is_some_and(|c| c.begin_mode != 0)
        {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.begin_mode = mode;
            ctx.immediate.clear();
        }
        Ok(())
    }

    fn dispatch_gl_end(
        &mut self,
        _state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = self
            .opengl
            .contexts
            .get(&self.opengl.current_context)
            .map(|c| c.begin_mode);
        let Some(mode) = mode else {
            return Ok(());
        };
        if mode == 0 {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        let vertices = self
            .opengl
            .contexts
            .get_mut(&self.opengl.current_context)
            .map(|ctx| {
                ctx.begin_mode = 0;
                std::mem::take(&mut ctx.immediate)
            })
            .unwrap_or_default();
        if let Some(ctx) = self.opengl.contexts.get_mut(&self.opengl.current_context) {
            rasterize(ctx, mode, &vertices);
        }
        Ok(())
    }

    fn dispatch_gl_vertex2f(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = gl_arg_f32(state, memory, 0)?;
        let y = gl_arg_f32(state, memory, 1)?;
        self.gl_push_vertex(state, memory, x, y, 0.0)
    }

    fn dispatch_gl_vertex3f(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = gl_arg_f32(state, memory, 0)?;
        let y = gl_arg_f32(state, memory, 1)?;
        let z = gl_arg_f32(state, memory, 2)?;
        self.gl_push_vertex(state, memory, x, y, z)
    }

    fn gl_push_vertex(
        &mut self,
        _state: &mut CpuState,
        _memory: &mut MemoryImage,
        x: f32,
        y: f32,
        z: f32,
    ) -> AppResult<()> {
        let in_begin = self
            .opengl
            .contexts
            .get(&self.opengl.current_context)
            .is_some_and(|c| c.begin_mode != 0);
        if !in_begin {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.immediate.push(GlVertexState {
                x,
                y,
                z,
                color: ctx.current_color,
                tex: ctx.current_tex_coord,
            });
        }
        Ok(())
    }

    fn dispatch_gl_color3f(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let r = gl_arg_f32(state, memory, 0)?;
        let g = gl_arg_f32(state, memory, 1)?;
        let b = gl_arg_f32(state, memory, 2)?;
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.current_color = [r, g, b, 1.0];
        }
        Ok(())
    }

    fn dispatch_gl_color4f(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let r = gl_arg_f32(state, memory, 0)?;
        let g = gl_arg_f32(state, memory, 1)?;
        let b = gl_arg_f32(state, memory, 2)?;
        let a = gl_arg_f32(state, memory, 3)?;
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.current_color = [r, g, b, a];
        }
        Ok(())
    }

    fn dispatch_gl_clear_color(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let r = gl_arg_f32(state, memory, 0)?;
        let g = gl_arg_f32(state, memory, 1)?;
        let b = gl_arg_f32(state, memory, 2)?;
        let a = gl_arg_f32(state, memory, 3)?;
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.clear_color = [r, g, b, a];
        }
        Ok(())
    }

    fn dispatch_gl_clear(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mask = guest_call_arg_u32(state, memory, 0)?;
        let Some(ctx) = self.gl_current_context_mut() else {
            return Ok(());
        };
        if ctx.framebuffer.width == 0 || ctx.framebuffer.height == 0 {
            return Ok(());
        }
        if mask & GL_COLOR_BUFFER_BIT != 0 {
            let [r, g, b, a] = ctx.clear_color;
            let cr = (r.clamp(0.0, 1.0) * 255.0).round() as u8;
            let cg = (g.clamp(0.0, 1.0) * 255.0).round() as u8;
            let cb = (b.clamp(0.0, 1.0) * 255.0).round() as u8;
            let ca = (a.clamp(0.0, 1.0) * 255.0).round() as u8;
            ctx.framebuffer.pixels.fill(0);
            for px in ctx.framebuffer.pixels.as_chunks_mut::<4>().0 {
                px[0] = cr;
                px[1] = cg;
                px[2] = cb;
                px[3] = ca;
            }
        }
        if mask & GL_DEPTH_BUFFER_BIT != 0 {
            ctx.framebuffer.depth.fill(f32::INFINITY);
        }
        Ok(())
    }

    fn dispatch_gl_matrix_mode(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        if !matches!(mode, GL_MODELVIEW | GL_PROJECTION | GL_TEXTURE) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.matrix_mode = mode;
        }
        Ok(())
    }

    fn dispatch_gl_load_identity(
        &mut self,
        _state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        if let Some(ctx) = self.gl_current_context_mut()
            && let Some(top) = Self::gl_matrix_stack_mut(ctx).last_mut()
        {
            *top = mat_identity();
        }
        Ok(())
    }

    fn dispatch_gl_push_matrix(
        &mut self,
        _state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let depth = self
            .opengl
            .contexts
            .get(&self.opengl.current_context)
            .map(|c| match c.matrix_mode {
                GL_PROJECTION => c.projection.len(),
                GL_TEXTURE => c.texture.len(),
                _ => c.modelview.len(),
            });
        if depth.is_some_and(|len| len >= 32) {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        let Some(ctx) = self.gl_current_context_mut() else {
            return Ok(());
        };
        let stack = Self::gl_matrix_stack_mut(ctx);
        let top = stack.last().copied().unwrap_or_else(mat_identity);
        stack.push(top);
        Ok(())
    }

    fn dispatch_gl_pop_matrix(
        &mut self,
        _state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let depth = self
            .opengl
            .contexts
            .get(&self.opengl.current_context)
            .map(|c| match c.matrix_mode {
                GL_PROJECTION => c.projection.len(),
                GL_TEXTURE => c.texture.len(),
                _ => c.modelview.len(),
            });
        if depth.is_some_and(|len| len <= 1) {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_matrix_stack_mut(ctx).pop();
        }
        Ok(())
    }

    fn dispatch_gl_ortho(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let l = gl_arg_f64(state, memory, 0)? as f32;
        let r = gl_arg_f64(state, memory, 1)? as f32;
        let b = gl_arg_f64(state, memory, 2)? as f32;
        let t = gl_arg_f64(state, memory, 3)? as f32;
        let n = gl_arg_f64(state, memory, 4)? as f32;
        let f = gl_arg_f64(state, memory, 5)? as f32;
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, mat_ortho(l, r, b, t, n, f));
        }
        Ok(())
    }

    fn dispatch_gl_translatef(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = gl_arg_f32(state, memory, 0)?;
        let y = gl_arg_f32(state, memory, 1)?;
        let z = gl_arg_f32(state, memory, 2)?;
        let mut m = mat_identity();
        m[12] = x;
        m[13] = y;
        m[14] = z;
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, m);
        }
        Ok(())
    }

    fn dispatch_gl_rotatef(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let angle = gl_arg_f32(state, memory, 0)?;
        let x = gl_arg_f32(state, memory, 1)?;
        let y = gl_arg_f32(state, memory, 2)?;
        let z = gl_arg_f32(state, memory, 3)?;
        let a = angle.to_radians();
        let c = a.cos();
        let s = a.sin();
        let mut m = mat_identity();
        if x.abs() > 0.0 {
            m[5] = c;
            m[6] = -s;
            m[9] = s;
            m[10] = c;
        } else if y.abs() > 0.0 {
            m[0] = c;
            m[2] = s;
            m[8] = -s;
            m[10] = c;
        } else if z.abs() > 0.0 {
            m[0] = c;
            m[1] = -s;
            m[4] = s;
            m[5] = c;
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, m);
        }
        Ok(())
    }

    fn dispatch_gl_scalef(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = gl_arg_f32(state, memory, 0)?;
        let y = gl_arg_f32(state, memory, 1)?;
        let z = gl_arg_f32(state, memory, 2)?;
        let mut m = mat_identity();
        m[0] = x;
        m[5] = y;
        m[10] = z;
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, m);
        }
        Ok(())
    }

    fn dispatch_gl_viewport(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = guest_call_arg_u32(state, memory, 0)? as i32;
        let y = guest_call_arg_u32(state, memory, 1)? as i32;
        let w = guest_call_arg_u32(state, memory, 2)? as i32;
        let h = guest_call_arg_u32(state, memory, 3)? as i32;
        if w <= 0 || h <= 0 {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        let Some(ctx) = self.gl_current_context_mut() else {
            return Ok(());
        };
        ctx.viewport = [x, y, w, h];
        // The software drawable follows the viewport (the standard
        // headless-GL sizing idiom).
        let width = w.max(1) as u32;
        let height = h.max(1) as u32;
        if ctx.framebuffer.width != width || ctx.framebuffer.height != height {
            ctx.framebuffer = GlFramebufferState {
                width,
                height,
                pixels: vec![0; (width * height * 4) as usize],
                depth: vec![f32::INFINITY; (width * height) as usize],
            };
        }
        Ok(())
    }

    fn gl_capability_bit(cap: u32) -> Option<u32> {
        Some(match cap {
            GL_DEPTH_TEST => 1 << 0,
            GL_CULL_FACE => 1 << 1,
            GL_LIGHTING => 1 << 2,
            GL_TEXTURE_2D => 1 << 3,
            GL_BLEND => 1 << 4,
            GL_FOG => 1 << 5,
            _ => return None,
        })
    }

    fn dispatch_gl_enable(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let cap = guest_call_arg_u32(state, memory, 0)?;
        let Some(bit) = Self::gl_capability_bit(cap) else {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        };
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.enabled |= bit;
        }
        Ok(())
    }

    fn dispatch_gl_disable(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let cap = guest_call_arg_u32(state, memory, 0)?;
        let Some(bit) = Self::gl_capability_bit(cap) else {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        };
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.enabled &= !bit;
        }
        Ok(())
    }

    fn dispatch_gl_depth_func(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let func = guest_call_arg_u32(state, memory, 0)?;
        if !matches!(
            func,
            GL_NEVER
                | GL_LESS
                | GL_EQUAL
                | GL_LEQUAL
                | GL_GREATER
                | GL_NOTEQUAL
                | GL_GEQUAL
                | GL_ALWAYS
        ) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.depth_func = func;
        }
        Ok(())
    }

    fn dispatch_gl_cull_face(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        if !matches!(mode, GL_FRONT | GL_BACK | 0x0408) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.cull_face = mode;
        }
        Ok(())
    }

    fn dispatch_gl_front_face(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        if !matches!(mode, GL_CW | GL_CCW) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.front_face = mode;
        }
        Ok(())
    }

    fn dispatch_gl_shade_model(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        if !matches!(mode, GL_FLAT | GL_SMOOTH) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.shade_model = mode;
        }
        Ok(())
    }

    fn dispatch_gl_blend_func(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let src = guest_call_arg_u32(state, memory, 0)?;
        let dst = guest_call_arg_u32(state, memory, 1)?;
        if !matches!(
            src,
            GL_ZERO
                | GL_ONE
                | GL_SRC_ALPHA
                | GL_ONE_MINUS_SRC_ALPHA
                | GL_DST_ALPHA
                | GL_ONE_MINUS_DST_ALPHA
        ) || !matches!(
            dst,
            GL_ZERO
                | GL_ONE
                | GL_SRC_ALPHA
                | GL_ONE_MINUS_SRC_ALPHA
                | GL_DST_ALPHA
                | GL_ONE_MINUS_DST_ALPHA
        ) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.blend_src = src;
            ctx.blend_dst = dst;
        }
        Ok(())
    }

    fn dispatch_gl_hint(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let target = guest_call_arg_u32(state, memory, 0)?;
        let _mode = guest_call_arg_u32(state, memory, 1)?;
        if !matches!(
            target,
            GL_PERSPECTIVE_CORRECTION_HINT
                | GL_POINT_SMOOTH_HINT
                | GL_LINE_SMOOTH_HINT
                | GL_POLYGON_SMOOTH_HINT
                | GL_FOG_HINT
        ) {
            self.gl_record_error(GL_INVALID_ENUM);
        }
        Ok(())
    }

    fn dispatch_gl_fogf(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let pname = guest_call_arg_u32(state, memory, 0)?;
        let _param = gl_arg_f32(state, memory, 1)?;
        if !matches!(
            pname,
            GL_FOG_DENSITY | GL_FOG_START | GL_FOG_END | GL_FOG_MODE
        ) {
            self.gl_record_error(GL_INVALID_ENUM);
        }
        Ok(())
    }

    fn dispatch_gl_fogi(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let pname = guest_call_arg_u32(state, memory, 0)?;
        let _param = guest_call_arg_u32(state, memory, 1)?;
        if !matches!(
            pname,
            GL_FOG_DENSITY | GL_FOG_START | GL_FOG_END | GL_FOG_MODE
        ) {
            self.gl_record_error(GL_INVALID_ENUM);
        }
        Ok(())
    }

    fn dispatch_gl_lightfv(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let light = guest_call_arg_u32(state, memory, 0)?;
        let pname = guest_call_arg_u32(state, memory, 1)?;
        let params = guest_call_arg(state, memory, 2)?;
        if !(GL_LIGHT0..=GL_LIGHT0 + 7).contains(&light) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if !matches!(pname, GL_AMBIENT | GL_DIFFUSE | GL_SPECULAR | GL_POSITION) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if pname == GL_POSITION && params != 0 {
            let data = memory.read_bytes(params, 16)?;
            let index = ((light - GL_LIGHT0) as usize) % 8;
            let mut pos = [0.0f32; 4];
            for (i, chunk) in data.as_chunks::<4>().0.iter().take(4).enumerate() {
                pos[i] = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            if let Some(ctx) = self.gl_current_context_mut() {
                while ctx.light_positions.len() <= index {
                    ctx.light_positions.push([0.0, 0.0, 1.0, 0.0]);
                }
                ctx.light_positions[index] = pos;
            }
        }
        Ok(())
    }

    fn dispatch_gl_materialfv(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _face = guest_call_arg_u32(state, memory, 0)?;
        let pname = guest_call_arg_u32(state, memory, 1)?;
        let params = guest_call_arg(state, memory, 2)?;
        if !matches!(
            pname,
            GL_AMBIENT | GL_DIFFUSE | GL_SPECULAR | GL_AMBIENT_AND_DIFFUSE
        ) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if params != 0 {
            let data = memory.read_bytes(params, 16)?;
            let mut mat = [0.0f32; 4];
            for (i, chunk) in data.as_chunks::<4>().0.iter().take(4).enumerate() {
                mat[i] = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            if let Some(ctx) = self.gl_current_context_mut() {
                ctx.material = mat;
            }
        }
        Ok(())
    }

    // ── Texture objects ────────────────────────────────────────────────────

    fn dispatch_gl_gen_textures(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let count = guest_call_arg_u32(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        for index in 0..count {
            self.opengl.next_texture += 1;
            let name = self.opengl.next_texture;
            write_guest_u32(memory, out + (index as u64 * 4), name).ok();
        }
        Ok(())
    }

    fn dispatch_gl_bind_texture(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let target = guest_call_arg_u32(state, memory, 0)?;
        let texture = guest_call_arg_u32(state, memory, 1)?;
        if target != GL_TEXTURE_2D {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.bound_texture = texture;
        }
        Ok(())
    }

    fn dispatch_gl_delete_textures(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let count = guest_call_arg_u32(state, memory, 0)?;
        let names = guest_call_arg(state, memory, 1)?;
        if let Some(ctx) = self.gl_current_context_mut() {
            for index in 0..count {
                if let Ok(name) = read_guest_u32(memory, names + (index as u64 * 4)) {
                    ctx.textures.remove(&name);
                    if ctx.bound_texture == name {
                        ctx.bound_texture = 0;
                    }
                }
            }
        }
        Ok(())
    }

    fn dispatch_gl_tex_image_2d(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let target = guest_call_arg_u32(state, memory, 0)?;
        let level = guest_call_arg_u32(state, memory, 1)?;
        let _internalformat = guest_call_arg_u32(state, memory, 2)?;
        let width = guest_call_arg_u32(state, memory, 3)?;
        let height = guest_call_arg_u32(state, memory, 4)?;
        let border = guest_call_arg_u32(state, memory, 5)?;
        let format = guest_call_arg_u32(state, memory, 6)?;
        let kind = guest_call_arg_u32(state, memory, 7)?;
        let pixels = guest_call_arg(state, memory, 8)?;
        if target != GL_TEXTURE_2D {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if level != 0 || border != 0 {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        if width == 0 || height == 0 || width > 16384 || height > 16384 {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        let bytes_per_pixel = match (format, kind) {
            (GL_RGBA, GL_UNSIGNED_BYTE) => 4,
            (GL_RGB, GL_UNSIGNED_BYTE) => 3,
            (GL_LUMINANCE, GL_UNSIGNED_BYTE) => 1,
            (GL_ALPHA, GL_UNSIGNED_BYTE) => 1,
            _ => {
                self.gl_record_error(GL_INVALID_ENUM);
                return Ok(());
            }
        };
        let mut texels = vec![0_u8; (width * height * 4) as usize];
        if pixels != 0 && bytes_per_pixel == 4 {
            texels = memory
                .read_bytes(pixels, (width * height * 4) as usize)
                .unwrap_or_default();
        } else if pixels != 0 {
            let raw = memory
                .read_bytes(pixels, (width * height * bytes_per_pixel) as usize)
                .unwrap_or_default();
            for (i, chunk) in raw.chunks_exact(bytes_per_pixel as usize).enumerate() {
                match bytes_per_pixel {
                    3 => {
                        texels[i * 4] = chunk[0];
                        texels[i * 4 + 1] = chunk[1];
                        texels[i * 4 + 2] = chunk[2];
                        texels[i * 4 + 3] = 255;
                    }
                    _ => {
                        let value = chunk[0];
                        texels[i * 4] = value;
                        texels[i * 4 + 1] = value;
                        texels[i * 4 + 2] = value;
                        texels[i * 4 + 3] = if format == GL_ALPHA { value } else { 255 };
                    }
                }
            }
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.textures.insert(
                ctx.bound_texture,
                GlTextureState {
                    width,
                    height,
                    texels,
                    min_filter: GL_NEAREST,
                    mag_filter: GL_NEAREST,
                },
            );
        }
        Ok(())
    }

    fn gl_tex_parameter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        is_float: bool,
    ) -> AppResult<()> {
        let target = guest_call_arg_u32(state, memory, 0)?;
        let pname = guest_call_arg_u32(state, memory, 1)?;
        let param = if is_float {
            gl_arg_f32(state, memory, 2)? as u32
        } else {
            guest_call_arg_u32(state, memory, 2)?
        };
        if target != GL_TEXTURE_2D {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if !matches!(pname, GL_TEXTURE_MIN_FILTER | GL_TEXTURE_MAG_FILTER) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if !matches!(param, GL_NEAREST | GL_LINEAR) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut()
            && let Some(texture) = ctx.textures.get_mut(&ctx.bound_texture)
        {
            if pname == GL_TEXTURE_MIN_FILTER {
                texture.min_filter = param;
            } else {
                texture.mag_filter = param;
            }
        }
        Ok(())
    }

    fn dispatch_gl_tex_parameterf(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.gl_tex_parameter(state, memory, true)
    }

    fn dispatch_gl_tex_parameteri(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.gl_tex_parameter(state, memory, false)
    }

    fn dispatch_gl_tex_coord2f(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let s = gl_arg_f32(state, memory, 0)?;
        let t = gl_arg_f32(state, memory, 1)?;
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.current_tex_coord = [s, t];
        }
        Ok(())
    }

    // ── Client-side arrays ─────────────────────────────────────────────────

    fn dispatch_gl_vertex_pointer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let size = guest_call_arg_u32(state, memory, 0)?;
        let kind = guest_call_arg_u32(state, memory, 1)?;
        let stride = guest_call_arg_u32(state, memory, 2)?;
        let pointer = guest_call_arg(state, memory, 3)?;
        if !(2..=4).contains(&size) || kind != GL_FLOAT {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.arrays.vertex = GlArrayBinding {
                kind,
                size,
                stride,
                pointer,
            };
        }
        Ok(())
    }

    fn dispatch_gl_color_pointer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let size = guest_call_arg_u32(state, memory, 0)?;
        let kind = guest_call_arg_u32(state, memory, 1)?;
        let stride = guest_call_arg_u32(state, memory, 2)?;
        let pointer = guest_call_arg(state, memory, 3)?;
        if !(3..=4).contains(&size) || !matches!(kind, GL_FLOAT | GL_UNSIGNED_BYTE) {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.arrays.color = GlArrayBinding {
                kind,
                size,
                stride,
                pointer,
            };
        }
        Ok(())
    }

    fn dispatch_gl_normal_pointer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let kind = guest_call_arg_u32(state, memory, 0)?;
        let stride = guest_call_arg_u32(state, memory, 1)?;
        let pointer = guest_call_arg(state, memory, 2)?;
        if kind != GL_FLOAT {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.arrays.normal = GlArrayBinding {
                kind,
                size: 3,
                stride,
                pointer,
            };
        }
        Ok(())
    }

    fn dispatch_gl_tex_coord_pointer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let size = guest_call_arg_u32(state, memory, 0)?;
        let kind = guest_call_arg_u32(state, memory, 1)?;
        let stride = guest_call_arg_u32(state, memory, 2)?;
        let pointer = guest_call_arg(state, memory, 3)?;
        if !(2..=4).contains(&size) || kind != GL_FLOAT {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.arrays.texcoord = GlArrayBinding {
                kind,
                size,
                stride,
                pointer,
            };
        }
        Ok(())
    }

    fn gl_client_capability_bit(cap: u32) -> Option<u32> {
        Some(match cap {
            GL_VERTEX_ARRAY => 1 << 0,
            GL_COLOR_ARRAY => 1 << 1,
            GL_NORMAL_ARRAY => 1 << 2,
            GL_TEXTURE_COORD_ARRAY => 1 << 3,
            _ => return None,
        })
    }

    fn dispatch_gl_enable_client_state(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let cap = guest_call_arg_u32(state, memory, 0)?;
        let Some(bit) = Self::gl_client_capability_bit(cap) else {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        };
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.client_enabled |= bit;
        }
        Ok(())
    }

    fn dispatch_gl_disable_client_state(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let cap = guest_call_arg_u32(state, memory, 0)?;
        let Some(bit) = Self::gl_client_capability_bit(cap) else {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        };
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.client_enabled &= !bit;
        }
        Ok(())
    }

    fn gl_read_vertex_array(
        &self,
        memory: &MemoryImage,
        binding: &GlArrayBinding,
        index: usize,
    ) -> Option<[f32; 4]> {
        if binding.pointer == 0 || binding.size == 0 {
            return None;
        }
        let element_bytes = if binding.kind == GL_UNSIGNED_BYTE {
            1
        } else {
            4
        };
        let stride = if binding.stride == 0 {
            binding.size * element_bytes
        } else {
            binding.stride
        };
        let address = binding.pointer + (index as u64 * stride as u64);
        let mut out = [0.0f32; 4];
        for (i, slot) in out.iter_mut().enumerate().take(binding.size as usize) {
            *slot = match binding.kind {
                GL_UNSIGNED_BYTE => {
                    let b = memory.read_u8(address + i as u64).ok()?;
                    b as f32 / 255.0
                }
                _ => f32::from_bits(memory.read_u32(address + (i as u64 * 4)).ok()?),
            };
        }
        Some(out)
    }

    fn gl_vertex_from_arrays(&self, memory: &MemoryImage, index: usize) -> Option<GlVertexState> {
        let ctx = self.opengl.contexts.get(&self.opengl.current_context)?;
        let position = self.gl_read_vertex_array(memory, &ctx.arrays.vertex, index)?;
        let color = if ctx.client_enabled & (1 << 1) != 0 {
            self.gl_read_vertex_array(memory, &ctx.arrays.color, index)
                .unwrap_or(ctx.current_color)
        } else {
            ctx.current_color
        };
        let tex = if ctx.client_enabled & (1 << 3) != 0 {
            self.gl_read_vertex_array(memory, &ctx.arrays.texcoord, index)
                .map(|t| [t[0], t[1]])
                .unwrap_or(ctx.current_tex_coord)
        } else {
            ctx.current_tex_coord
        };
        let _normal = if ctx.client_enabled & (1 << 2) != 0 {
            self.gl_read_vertex_array(memory, &ctx.arrays.normal, index)
        } else {
            None
        };
        Some(GlVertexState {
            x: position[0],
            y: position[1],
            z: position[2],
            color,
            tex,
        })
    }

    fn gl_draw_assembled(
        &mut self,
        state: &mut CpuState,
        _memory: &MemoryImage,
        mode: u32,
        vertices: &[GlVertexState],
    ) {
        if !valid_draw_mode(mode) {
            self.gl_record_error(GL_INVALID_ENUM);
            return;
        }
        let Some(ctx) = self.opengl.contexts.get_mut(&self.opengl.current_context) else {
            return;
        };
        rasterize(ctx, mode, vertices);
        state.set(Register::Rax, 0);
    }

    fn dispatch_gl_draw_arrays(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        let first = guest_call_arg_u32(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?.min(4_000_000);
        let ctx = self.opengl.contexts.get(&self.opengl.current_context);
        if ctx.is_none_or(|c| c.client_enabled & (1 << 0) == 0) {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        let mut vertices = Vec::with_capacity(count as usize);
        for index in first..first + count {
            if let Some(v) = self.gl_vertex_from_arrays(memory, index as usize) {
                vertices.push(v);
            }
        }
        self.gl_draw_assembled(state, memory, mode, &vertices);
        Ok(())
    }

    fn dispatch_gl_draw_elements(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let mode = guest_call_arg_u32(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)?.min(4_000_000);
        let kind = guest_call_arg_u32(state, memory, 2)?;
        let indices = guest_call_arg(state, memory, 3)?;
        if self
            .opengl
            .contexts
            .get(&self.opengl.current_context)
            .is_none_or(|c| c.client_enabled & (1 << 0) == 0)
        {
            self.gl_record_error(GL_INVALID_OPERATION);
            return Ok(());
        }
        if !matches!(kind, GL_UNSIGNED_BYTE | GL_UNSIGNED_SHORT | GL_UNSIGNED_INT) {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        let width = match kind {
            GL_UNSIGNED_BYTE => 1,
            GL_UNSIGNED_SHORT => 2,
            _ => 4,
        };
        let mut vertices = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let index = match width {
                1 => match memory.read_u8(indices + i as u64) {
                    Ok(value) => value as u32,
                    Err(_) => break,
                },
                2 => match memory.read_u16(indices + (i as u64 * 2)) {
                    Ok(value) => value as u32,
                    Err(_) => break,
                },
                _ => match memory.read_u32(indices + (i as u64 * 4)) {
                    Ok(value) => value,
                    Err(_) => break,
                },
            };
            if let Some(v) = self.gl_vertex_from_arrays(memory, index as usize) {
                vertices.push(v);
            }
        }
        self.gl_draw_assembled(state, memory, mode, &vertices);
        Ok(())
    }

    // ── Readback and query ─────────────────────────────────────────────────

    fn dispatch_gl_read_pixels(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = guest_call_arg_u32(state, memory, 0)? as i32;
        let y = guest_call_arg_u32(state, memory, 1)? as i32;
        let width = guest_call_arg_u32(state, memory, 2)? as i32;
        let height = guest_call_arg_u32(state, memory, 3)? as i32;
        let format = guest_call_arg_u32(state, memory, 4)?;
        let kind = guest_call_arg_u32(state, memory, 5)?;
        let pixels = guest_call_arg(state, memory, 6)?;
        if width <= 0 || height <= 0 {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        if kind != GL_UNSIGNED_BYTE {
            self.gl_record_error(GL_INVALID_ENUM);
            return Ok(());
        }
        let bytes_per_pixel = match format {
            GL_RGBA => 4,
            GL_RGB => 3,
            GL_LUMINANCE | GL_ALPHA => 1,
            _ => {
                self.gl_record_error(GL_INVALID_ENUM);
                return Ok(());
            }
        };
        let Some(ctx) = self.gl_current_context_mut() else {
            return Ok(());
        };
        let fb = &ctx.framebuffer;
        for row in 0..height as usize {
            let fb_row = (fb.height as i32 - 1 - (y + row as i32)).max(0) as usize;
            for col in 0..width as usize {
                let fb_col = (x + col as i32).max(0) as usize;
                if fb_row >= fb.height as usize || fb_col >= fb.width as usize {
                    continue;
                }
                let src = ((fb_row * fb.width as usize + fb_col) * 4) as u64;
                let dst = pixels + (((row * width as usize + col) * bytes_per_pixel) as u64);
                for channel in 0..bytes_per_pixel {
                    let value = match format {
                        GL_RGBA => fb.pixels[(src + channel as u64) as usize],
                        GL_RGB => fb.pixels[(src + channel as u64) as usize],
                        GL_LUMINANCE => {
                            let r = fb.pixels[src as usize];
                            let g = fb.pixels[(src + 1) as usize];
                            let b = fb.pixels[(src + 2) as usize];
                            ((r as u32 + g as u32 + b as u32) / 3) as u8
                        }
                        _ => fb.pixels[(src + 3) as usize],
                    };
                    memory.write_u8(dst + channel as u64, value);
                }
            }
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    fn dispatch_gl_get_error(
        &mut self,
        state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let error = self.opengl.error;
        self.opengl.error = GL_NO_ERROR;
        state.set(Register::Rax, u64::from(error));
        Ok(())
    }

    fn dispatch_gl_get_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let name = guest_call_arg_u32(state, memory, 0)?;
        let (slot, text) = match name {
            GL_VENDOR => (0, "Casa1"),
            GL_RENDERER => (1, "Casa1 Software Rasterizer"),
            GL_VERSION => (2, "1.1 Casa1"),
            GL_EXTENSIONS => (3, ""),
            _ => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        let mut address = self.opengl.string_slots[slot];
        if address == 0 {
            address = self.alloc_zeroed(memory, 128, 8)?;
            self.opengl.string_slots[slot] = address;
        }
        for (i, byte) in text.as_bytes().iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        memory.write_u8(address + text.len() as u64, 0);
        state.set(Register::Rax, address);
        Ok(())
    }

    // ── WGL context surface ────────────────────────────────────────────────

    fn dispatch_wgl_choose_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _hdc = guest_call_arg(state, memory, 0)?;
        let _ppfd = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if count < 1 || out == 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        write_guest_u32(memory, out, 1).ok();
        state.set(Register::Rax, 1);
        Ok(())
    }

    fn wgl_pixel_format_descriptor() -> [u8; 40] {
        let mut pfd = [0_u8; 40];
        // nSize
        pfd[0] = 40;
        pfd[1] = 0;
        // nVersion
        pfd[2] = 1;
        pfd[3] = 0;
        // dwFlags: PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER
        pfd[4] = 0x25;
        pfd[5] = 0x00;
        pfd[6] = 0x00;
        pfd[7] = 0x00;
        // iPixelType = PFD_TYPE_RGBA (0)
        pfd[8] = 0;
        // cColorBits = 32
        pfd[9] = 32;
        // cRedBits = 8, cRedShift = 16, cGreenBits = 8, cGreenShift = 8
        pfd[10] = 8;
        pfd[11] = 16;
        pfd[12] = 8;
        pfd[13] = 8;
        // cBlueBits = 8, cBlueShift = 0, cAlphaBits = 8, cAlphaShift = 24
        pfd[14] = 8;
        pfd[15] = 0;
        pfd[16] = 8;
        pfd[17] = 24;
        // cDepthBits = 24, cStencilBits = 8
        pfd[23] = 24;
        pfd[24] = 8;
        // iLayerType = PFD_MAIN_PLANE (0)
        pfd[24] = 0;
        pfd
    }

    fn dispatch_wgl_describe_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _hdc = guest_call_arg(state, memory, 0)?;
        let format = guest_call_arg_u32(state, memory, 1)?;
        let size = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if format == 0 || format > 1 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        if out != 0 {
            let pfd = Self::wgl_pixel_format_descriptor();
            let copy = size.min(40) as usize;
            for (i, byte) in pfd.iter().enumerate().take(copy) {
                memory.write_u8(out + i as u64, *byte);
            }
        }
        state.set(Register::Rax, 1);
        Ok(())
    }

    fn dispatch_wgl_get_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let hdc = guest_call_arg(state, memory, 0)?;
        let format = self.opengl.dc_pixel_formats.get(&hdc).copied().unwrap_or(0);
        state.set(Register::Rax, format as u64);
        Ok(())
    }

    fn dispatch_wgl_set_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let hdc = guest_call_arg(state, memory, 0)?;
        let format = guest_call_arg_u32(state, memory, 1)?;
        let _ppfd = guest_call_arg(state, memory, 2)?;
        if format == 0 || format > 1 {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        }
        self.opengl.dc_pixel_formats.insert(hdc, format as i32);
        state.set(Register::Rax, GL_TRUE as u64);
        Ok(())
    }

    fn dispatch_wgl_create_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _hdc = guest_call_arg(state, memory, 0)?;
        self.opengl.next_context += 1;
        let handle = self.opengl.next_context;
        self.opengl.contexts.insert(
            handle,
            OpenGlContext {
                matrix_mode: GL_MODELVIEW,
                modelview: vec![mat_identity()],
                projection: vec![mat_identity()],
                texture: vec![mat_identity()],
                viewport: [0, 0, 640, 480],
                clear_color: [0.0, 0.0, 0.0, 0.0],
                current_color: [1.0, 1.0, 1.0, 1.0],
                enabled: 0,
                client_enabled: 0,
                depth_func: GL_LESS,
                cull_face: GL_BACK,
                front_face: GL_CCW,
                shade_model: GL_SMOOTH,
                blend_src: GL_ONE,
                blend_dst: GL_ZERO,
                bound_texture: 0,
                textures: HashMap::new(),
                framebuffer: GlFramebufferState {
                    width: 640,
                    height: 480,
                    pixels: vec![0; 640 * 480 * 4],
                    depth: vec![f32::INFINITY; 640 * 480],
                },
                begin_mode: 0,
                immediate: Vec::new(),
                current_tex_coord: [0.0, 0.0],
                current_normal: [0.0, 0.0, 1.0],
                arrays: GlArraysState::default(),
                light_positions: Vec::new(),
                material: [0.8, 0.8, 0.8, 1.0],
            },
        );
        state.set(Register::Rax, handle);
        Ok(())
    }

    fn dispatch_wgl_make_current(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _hdc = guest_call_arg(state, memory, 0)?;
        let context = guest_call_arg(state, memory, 1)?;
        if context == 0 {
            self.opengl.current_context = 0;
            state.set(Register::Rax, GL_TRUE as u64);
            return Ok(());
        }
        if !self.opengl.contexts.contains_key(&context) {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        }
        self.opengl.current_context = context;
        state.set(Register::Rax, GL_TRUE as u64);
        Ok(())
    }

    fn dispatch_wgl_delete_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let context = guest_call_arg(state, memory, 0)?;
        if self.opengl.contexts.remove(&context).is_some() {
            if self.opengl.current_context == context {
                self.opengl.current_context = 0;
            }
            state.set(Register::Rax, GL_TRUE as u64);
        } else {
            state.set(Register::Rax, GL_FALSE as u64);
        }
        Ok(())
    }

    fn dispatch_wgl_get_proc_address(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        // No GL extensions are provided; the documented answer is NULL,
        // which lets callers fall back to their core-profile paths.
        let _name = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, 0);
        Ok(())
    }

    fn dispatch_wgl_swap_buffers(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        // Rendering is immediate; the framebuffer is already the back
        // buffer, so swap is a no-op that reports success.
        let _hdc = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, GL_TRUE as u64);
        Ok(())
    }

    // ── GLU helpers ────────────────────────────────────────────────────────

    fn dispatch_glu_perspective(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let fovy = gl_arg_f64(state, memory, 0)? as f32;
        let aspect = gl_arg_f64(state, memory, 1)? as f32;
        let znear = gl_arg_f64(state, memory, 2)? as f32;
        let zfar = gl_arg_f64(state, memory, 3)? as f32;
        if fovy <= 0.0 || fovy >= 180.0 || aspect <= 0.0 || znear < 0.0 || zfar <= znear {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, mat_perspective(fovy, aspect, znear, zfar));
        }
        Ok(())
    }

    fn dispatch_glu_pick_matrix(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let x = gl_arg_f64(state, memory, 0)? as f32;
        let y = gl_arg_f64(state, memory, 1)? as f32;
        let width = gl_arg_f64(state, memory, 2)? as f32;
        let height = gl_arg_f64(state, memory, 3)? as f32;
        let viewport = guest_call_arg(state, memory, 4)?;
        let mut vp = [0i32; 4];
        for (i, slot) in vp.iter_mut().enumerate() {
            *slot = read_guest_u32(memory, viewport + (i as u64 * 4)).unwrap_or(0) as i32;
        }
        if width <= 0.0 || height <= 0.0 {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        let mut m = mat_identity();
        m[0] = width * 0.5;
        m[5] = height * 0.5;
        m[12] = x + width * 0.5 - vp[0] as f32;
        m[13] = y + height * 0.5 - vp[1] as f32;
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, m);
        }
        Ok(())
    }

    fn dispatch_glu_look_at(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let eye = [
            gl_arg_f64(state, memory, 0)? as f32,
            gl_arg_f64(state, memory, 1)? as f32,
            gl_arg_f64(state, memory, 2)? as f32,
        ];
        let center = [
            gl_arg_f64(state, memory, 3)? as f32,
            gl_arg_f64(state, memory, 4)? as f32,
            gl_arg_f64(state, memory, 5)? as f32,
        ];
        let up = [
            gl_arg_f64(state, memory, 6)? as f32,
            gl_arg_f64(state, memory, 7)? as f32,
            gl_arg_f64(state, memory, 8)? as f32,
        ];
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, mat_lookat(eye, center, up));
        }
        Ok(())
    }

    fn dispatch_glu_ortho_2d(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let left = gl_arg_f64(state, memory, 0)? as f32;
        let right = gl_arg_f64(state, memory, 1)? as f32;
        let bottom = gl_arg_f64(state, memory, 2)? as f32;
        let top = gl_arg_f64(state, memory, 3)? as f32;
        if let Some(ctx) = self.gl_current_context_mut() {
            Self::gl_multiply_current_matrix(ctx, mat_ortho(left, right, bottom, top, -1.0, 1.0));
        }
        Ok(())
    }

    fn glu_scratch_string(&mut self, memory: &mut MemoryImage, text: &str) -> AppResult<u64> {
        let mut address = self.opengl.string_slots[4];
        if address == 0 {
            address = self.alloc_zeroed(memory, 128, 8)?;
            self.opengl.string_slots[4] = address;
        }
        for (i, byte) in text.as_bytes().iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        memory.write_u8(address + text.len() as u64, 0);
        Ok(address)
    }

    fn dispatch_glu_error_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let error = guest_call_arg_u32(state, memory, 0)?;
        let text = match error {
            GL_NO_ERROR => "no error",
            GL_INVALID_ENUM => "invalid enumerant",
            GL_INVALID_VALUE => "invalid value",
            GL_INVALID_OPERATION => "invalid operation",
            0x0503 => "stack overflow",
            0x0504 => "stack underflow",
            0x0505 => "out of memory",
            _ => "unknown error",
        };
        let address = self.glu_scratch_string(memory, text)?;
        state.set(Register::Rax, address);
        Ok(())
    }

    fn gl_read_matrix(memory: &MemoryImage, pointer: u64) -> AppResult<[f32; 16]> {
        let data = memory.read_bytes(pointer, 64)?;
        let mut m = [0.0f32; 16];
        for (i, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
            m[i] = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        Ok(m)
    }

    fn dispatch_glu_project(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let objx = gl_arg_f64(state, memory, 0)? as f32;
        let objy = gl_arg_f64(state, memory, 1)? as f32;
        let objz = gl_arg_f64(state, memory, 2)? as f32;
        let model = guest_call_arg(state, memory, 3)?;
        let proj = guest_call_arg(state, memory, 4)?;
        let view = guest_call_arg(state, memory, 5)?;
        let winx = guest_call_arg(state, memory, 6)?;
        let winy = guest_call_arg(state, memory, 7)?;
        let winz = guest_call_arg(state, memory, 8)?;
        let Ok(model) = Self::gl_read_matrix(memory, model) else {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        };
        let Ok(proj) = Self::gl_read_matrix(memory, proj) else {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        };
        let vp: Vec<i32> = (0..4)
            .filter_map(|i| {
                read_guest_u32(memory, view + (i as u64 * 4))
                    .ok()
                    .map(|v| v as i32)
            })
            .collect();
        if vp.len() != 4 {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        }
        let combined = mat_mul(proj, model);
        let clip = mat_transform(&combined, [objx, objy, objz, 1.0]);
        if clip[3] == 0.0 {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        }
        let ndc = [clip[0] / clip[3], clip[1] / clip[3], clip[2] / clip[3]];
        let (vx, vy, vw, vh) = (vp[0], vp[1], vp[2], vp[3]);
        let x = vx as f32 + (ndc[0] * 0.5 + 0.5) * vw as f32;
        let y = vy as f32 + (ndc[1] * 0.5 + 0.5) * vh as f32;
        let z = ndc[2] * 0.5 + 0.5;
        write_guest_f64(memory, winx, f64::from(x)).ok();
        write_guest_f64(memory, winy, f64::from(y)).ok();
        write_guest_f64(memory, winz, f64::from(z)).ok();
        state.set(Register::Rax, GL_TRUE as u64);
        Ok(())
    }

    fn dispatch_glu_unproject(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let winx = gl_arg_f64(state, memory, 0)? as f32;
        let winy = gl_arg_f64(state, memory, 1)? as f32;
        let winz = gl_arg_f64(state, memory, 2)? as f32;
        let model = guest_call_arg(state, memory, 3)?;
        let proj = guest_call_arg(state, memory, 4)?;
        let view = guest_call_arg(state, memory, 5)?;
        let objx = guest_call_arg(state, memory, 6)?;
        let objy = guest_call_arg(state, memory, 7)?;
        let objz = guest_call_arg(state, memory, 8)?;
        let Ok(model) = Self::gl_read_matrix(memory, model) else {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        };
        let Ok(proj) = Self::gl_read_matrix(memory, proj) else {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        };
        let vp: Vec<i32> = (0..4)
            .filter_map(|i| {
                read_guest_u32(memory, view + (i as u64 * 4))
                    .ok()
                    .map(|v| v as i32)
            })
            .collect();
        if vp.len() != 4 {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        }
        let combined = mat_mul(proj, model);
        let Some(inverse) = mat_inverse(&combined) else {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        };
        let (vx, vy, vw, vh) = (vp[0], vp[1], vp[2], vp[3]);
        let ndc = [
            2.0 * (winx - vx as f32) / vw as f32 - 1.0,
            2.0 * (winy - vy as f32) / vh as f32 - 1.0,
            2.0 * winz - 1.0,
        ];
        let clip = [ndc[0], ndc[1], ndc[2], 1.0];
        let obj = mat_transform(&inverse, clip);
        if obj[3] == 0.0 {
            state.set(Register::Rax, GL_FALSE as u64);
            return Ok(());
        }
        write_guest_f64(memory, objx, f64::from(obj[0] / obj[3])).ok();
        write_guest_f64(memory, objy, f64::from(obj[1] / obj[3])).ok();
        write_guest_f64(memory, objz, f64::from(obj[2] / obj[3])).ok();
        state.set(Register::Rax, GL_TRUE as u64);
        Ok(())
    }

    fn dispatch_glu_scale_image(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let format = guest_call_arg_u32(state, memory, 0)?;
        let width_in = guest_call_arg_u32(state, memory, 1)? as usize;
        let height_in = guest_call_arg_u32(state, memory, 2)? as usize;
        let kind_in = guest_call_arg_u32(state, memory, 3)?;
        let data_in = guest_call_arg(state, memory, 4)?;
        let width_out = guest_call_arg_u32(state, memory, 5)? as usize;
        let height_out = guest_call_arg_u32(state, memory, 6)? as usize;
        let kind_out = guest_call_arg_u32(state, memory, 7)?;
        let data_out = guest_call_arg(state, memory, 8)?;
        let channels = match format {
            GL_RGBA => 4,
            GL_RGB => 3,
            GL_LUMINANCE | GL_ALPHA => 1,
            _ => {
                state.set(Register::Rax, 0x0008_0001);
                return Ok(());
            }
        };
        if kind_in != GL_UNSIGNED_BYTE || kind_out != GL_UNSIGNED_BYTE {
            state.set(Register::Rax, 0x0008_0001);
            return Ok(());
        }
        if width_in == 0 || height_in == 0 || width_out == 0 || height_out == 0 {
            state.set(Register::Rax, 0x0008_0002);
            return Ok(());
        }
        let input = memory
            .read_bytes(data_in, width_in * height_in * channels)
            .unwrap_or_default();
        for y in 0..height_out {
            for x in 0..width_out {
                let sx = (x as f64 * width_in as f64 / width_out as f64).floor() as usize;
                let sy = (y as f64 * height_in as f64 / height_out as f64).floor() as usize;
                let src = (sy * width_in + sx) * channels;
                for c in 0..channels {
                    let value = input.get(src + c).copied().unwrap_or(0);
                    memory.write_u8(
                        data_out + ((y * width_out + x) * channels + c) as u64,
                        value,
                    );
                }
            }
        }
        state.set(Register::Rax, GL_NO_ERROR as u64);
        Ok(())
    }

    fn dispatch_glu_build_2d_mipmaps(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let target = guest_call_arg_u32(state, memory, 0)?;
        let _components = guest_call_arg_u32(state, memory, 1)?;
        let width = guest_call_arg_u32(state, memory, 2)?;
        let height = guest_call_arg_u32(state, memory, 3)?;
        let format = guest_call_arg_u32(state, memory, 4)?;
        let kind = guest_call_arg_u32(state, memory, 5)?;
        let data = guest_call_arg(state, memory, 6)?;
        if target != GL_TEXTURE_2D {
            state.set(Register::Rax, 0x0008_0001);
            return Ok(());
        }
        if kind != GL_UNSIGNED_BYTE || !matches!(format, GL_RGBA | GL_RGB) {
            state.set(Register::Rax, 0x0008_0001);
            return Ok(());
        }
        let bytes_per_pixel = if format == GL_RGBA { 4 } else { 3 };
        let mut texels = vec![0_u8; (width * height * 4) as usize];
        if data != 0 {
            let raw = memory
                .read_bytes(data, (width * height * bytes_per_pixel) as usize)
                .unwrap_or_default();
            for (i, chunk) in raw.chunks_exact(bytes_per_pixel as usize).enumerate() {
                texels[i * 4] = chunk[0];
                texels[i * 4 + 1] = chunk[1];
                texels[i * 4 + 2] = chunk[2];
                texels[i * 4 + 3] = 255;
            }
        }
        if let Some(ctx) = self.gl_current_context_mut() {
            ctx.textures.insert(
                ctx.bound_texture,
                GlTextureState {
                    width,
                    height,
                    texels,
                    min_filter: GL_NEAREST,
                    mag_filter: GL_NEAREST,
                },
            );
        }
        state.set(Register::Rax, GL_NO_ERROR as u64);
        Ok(())
    }

    fn dispatch_glu_new_quadric(
        &mut self,
        state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        // Quadric handles are plain non-null tokens; quadric drawing is
        // stateless in this implementation.
        state.set(Register::Rax, 0xCA5A_0001);
        Ok(())
    }

    fn dispatch_glu_delete_quadric(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _quadric = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, 0);
        Ok(())
    }

    fn dispatch_glu_quadric(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        kind: u32,
    ) -> AppResult<()> {
        let _quadric = guest_call_arg(state, memory, 0)?;
        let Some(ctx) = self.gl_current_context_mut() else {
            state.set(Register::Rax, 0x0008_0005);
            return Ok(());
        };
        let vertices = match kind {
            0 => {
                // gluSphere(quadric, radius, slices, stacks)
                let radius = gl_arg_f64(state, memory, 1)? as f32;
                let slices = gl_mixed_int_arg(state, memory, 2, 1)?;
                let stacks = gl_mixed_int_arg(state, memory, 3, 1)?;
                if radius <= 0.0 || slices < 3 || stacks < 2 {
                    state.set(Register::Rax, 0x0008_0002);
                    return Ok(());
                }
                sphere_vertices(radius, slices, stacks)
            }
            1 => {
                // gluCylinder(quadric, base, top, height, slices, stacks)
                let base = gl_arg_f64(state, memory, 1)? as f32;
                let top = gl_arg_f64(state, memory, 2)? as f32;
                let height = gl_arg_f64(state, memory, 3)? as f32;
                let slices = gl_mixed_int_arg(state, memory, 4, 3)?;
                let stacks = gl_mixed_int_arg(state, memory, 5, 3)?;
                if base < 0.0 || top < 0.0 || height < 0.0 || slices < 3 || stacks < 1 {
                    state.set(Register::Rax, 0x0008_0002);
                    return Ok(());
                }
                cylinder_vertices(base, top, height, slices, stacks)
            }
            2 => {
                // gluDisk(quadric, inner, outer, slices, loops)
                let inner = gl_arg_f64(state, memory, 1)? as f32;
                let outer = gl_arg_f64(state, memory, 2)? as f32;
                let slices = gl_mixed_int_arg(state, memory, 3, 2)?;
                let loops = gl_mixed_int_arg(state, memory, 4, 2)?;
                if inner < 0.0 || outer <= 0.0 || inner > outer || slices < 3 || loops < 1 {
                    state.set(Register::Rax, 0x0008_0002);
                    return Ok(());
                }
                disk_vertices(inner, outer, slices, loops, 0.0, std::f32::consts::TAU)
            }
            _ => {
                // gluPartialDisk(quadric, inner, outer, slices, loops, start, sweep)
                let inner = gl_arg_f64(state, memory, 1)? as f32;
                let outer = gl_arg_f64(state, memory, 2)? as f32;
                let slices = gl_mixed_int_arg(state, memory, 3, 2)?;
                let loops = gl_mixed_int_arg(state, memory, 4, 2)?;
                let start = gl_arg_f64(state, memory, 5)? as f32;
                let sweep = gl_arg_f64(state, memory, 6)? as f32;
                if inner < 0.0 || outer <= 0.0 || inner > outer || slices < 3 || loops < 1 {
                    state.set(Register::Rax, 0x0008_0002);
                    return Ok(());
                }
                disk_vertices(
                    inner,
                    outer,
                    slices,
                    loops,
                    start.to_radians(),
                    sweep.to_radians(),
                )
            }
        };
        rasterize(ctx, GL_TRIANGLE_STRIP, &vertices);
        state.set(Register::Rax, GL_NO_ERROR as u64);
        Ok(())
    }

    fn dispatch_glu_new_tess(
        &mut self,
        state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.opengl.glu_tess = 0xCA5A_0002;
        state.set(Register::Rax, self.opengl.glu_tess);
        Ok(())
    }

    fn dispatch_glu_tess_begin_polygon(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let tess = guest_call_arg(state, memory, 0)?;
        let _data = guest_call_arg(state, memory, 1)?;
        if tess != self.opengl.glu_tess {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        self.opengl.glu_tess_vertices.clear();
        state.set(Register::Rax, GL_NO_ERROR as u64);
        Ok(())
    }

    fn dispatch_glu_tess_vertex(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let tess = guest_call_arg(state, memory, 0)?;
        let location = guest_call_arg(state, memory, 1)?;
        let _data = guest_call_arg(state, memory, 2)?;
        if tess != self.opengl.glu_tess {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        let x = read_guest_f64(memory, location).unwrap_or(0.0) as f32;
        let y = read_guest_f64(memory, location + 8).unwrap_or(0.0) as f32;
        let z = read_guest_f64(memory, location + 16).unwrap_or(0.0) as f32;
        self.opengl.glu_tess_vertices.push(GlVertexState {
            x,
            y,
            z,
            color: [1.0, 1.0, 1.0, 1.0],
            tex: [0.0, 0.0],
        });
        state.set(Register::Rax, GL_NO_ERROR as u64);
        Ok(())
    }

    fn dispatch_glu_tess_end_polygon(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let tess = guest_call_arg(state, memory, 0)?;
        if tess != self.opengl.glu_tess {
            self.gl_record_error(GL_INVALID_VALUE);
            return Ok(());
        }
        let vertices = std::mem::take(&mut self.opengl.glu_tess_vertices);
        if vertices.len() >= 3
            && let Some(ctx) = self.gl_current_context_mut()
        {
            rasterize(ctx, GL_TRIANGLE_FAN, &vertices);
        }
        state.set(Register::Rax, GL_NO_ERROR as u64);
        Ok(())
    }
}

// ── Primitive assembly + the software rasterizer ───────────────────────────

fn valid_draw_mode(mode: u32) -> bool {
    matches!(
        mode,
        GL_POINTS
            | GL_LINES
            | GL_LINE_LOOP
            | GL_LINE_STRIP
            | GL_TRIANGLES
            | GL_TRIANGLE_STRIP
            | GL_TRIANGLE_FAN
            | GL_QUADS
            | GL_QUAD_STRIP
            | GL_POLYGON
    )
}

/// Assemble the primitive list for a draw mode and dispatch the triangles,
/// lines and points to the framebuffer.
fn rasterize(ctx: &mut OpenGlContext, mode: u32, vertices: &[GlVertexState]) {
    if ctx.framebuffer.width == 0 || ctx.framebuffer.height == 0 {
        return;
    }
    if mode == GL_POINTS {
        for v in vertices {
            if let Some(screen) = transform_vertex(ctx, v) {
                plot_pixel(
                    ctx,
                    screen.0 as i32,
                    screen.1 as i32,
                    screen.2,
                    v.color,
                    v.tex,
                );
            }
        }
        return;
    }
    if matches!(mode, GL_LINES | GL_LINE_STRIP | GL_LINE_LOOP) {
        let pairs: Vec<(usize, usize)> = match mode {
            GL_LINES => (0..vertices.len().saturating_sub(1))
                .step_by(2)
                .map(|i| (i, i + 1))
                .collect(),
            GL_LINE_STRIP => (0..vertices.len().saturating_sub(1))
                .map(|i| (i, i + 1))
                .collect(),
            _ => {
                if vertices.len() >= 2 {
                    let mut pairs = (0..vertices.len().saturating_sub(1))
                        .map(|i| (i, i + 1))
                        .collect::<Vec<_>>();
                    pairs.push((vertices.len() - 1, 0));
                    pairs
                } else {
                    Vec::new()
                }
            }
        };
        for (a, b) in pairs {
            if let (Some(sa), Some(sb)) = (
                transform_vertex(ctx, &vertices[a]),
                transform_vertex(ctx, &vertices[b]),
            ) {
                draw_line(ctx, sa, sb);
            }
        }
        return;
    }
    let mut triangles: Vec<[usize; 3]> = Vec::new();
    match mode {
        GL_TRIANGLES => {
            for tri in vertices.chunks(3) {
                if tri.len() == 3 {
                    triangles.push([0, 1, 2]);
                }
            }
        }
        GL_TRIANGLE_STRIP => {
            for i in 0..vertices.len().saturating_sub(2) {
                if i % 2 == 0 {
                    triangles.push([i, i + 1, i + 2]);
                } else {
                    triangles.push([i + 1, i, i + 2]);
                }
            }
        }
        GL_TRIANGLE_FAN | GL_POLYGON => {
            for i in 1..vertices.len().saturating_sub(1) {
                triangles.push([0, i, i + 1]);
            }
        }
        GL_QUADS => {
            for quad in vertices.chunks(4) {
                if quad.len() == 4 {
                    triangles.push([0, 1, 2]);
                    triangles.push([0, 2, 3]);
                }
            }
        }
        GL_QUAD_STRIP => {
            for i in (0..vertices.len().saturating_sub(2)).step_by(2) {
                triangles.push([i, i + 1, i + 2]);
                triangles.push([i + 2, i + 1, i + 3]);
            }
        }
        _ => {}
    }
    for [a, b, c] in triangles {
        fill_triangle(ctx, &vertices[a], &vertices[b], &vertices[c]);
    }
}

/// Transform a vertex to screen space.  Returns (x, y, z, w).
fn transform_vertex(ctx: &OpenGlContext, v: &GlVertexState) -> Option<(f32, f32, f32, f32)> {
    let modelview = ctx.modelview.last().copied().unwrap_or_else(mat_identity);
    let projection = ctx.projection.last().copied().unwrap_or_else(mat_identity);
    let mv = mat_transform(&modelview, [v.x, v.y, v.z, 1.0]);
    let clip = mat_transform(&projection, mv);
    if clip[3] == 0.0 {
        return None;
    }
    let w = clip[3];
    let ndc = [clip[0] / w, clip[1] / w, clip[2] / w];
    let (vx, vy, vw, vh) = (
        ctx.viewport[0] as f32,
        ctx.viewport[1] as f32,
        ctx.viewport[2] as f32,
        ctx.viewport[3] as f32,
    );
    // The framebuffer rows are top-down, so the GL bottom-left origin is
    // flipped vertically.
    let x = vx + (ndc[0] * 0.5 + 0.5) * vw;
    let y = (ctx.framebuffer.height as f32) - (vy + (ndc[1] * 0.5 + 0.5) * vh);
    let z = ndc[2] * 0.5 + 0.5;
    Some((x, y, z, w))
}

fn depth_passes(ctx: &OpenGlContext, z: f32, depth: f32) -> bool {
    match ctx.depth_func {
        GL_NEVER => false,
        GL_LESS => z < depth,
        GL_EQUAL => (z - depth).abs() < 1.0e-6,
        GL_LEQUAL => z <= depth,
        GL_GREATER => z > depth,
        GL_NOTEQUAL => (z - depth).abs() >= 1.0e-6,
        GL_GEQUAL => z >= depth,
        _ => true,
    }
}

/// Screen-space culling: returns true when the winding should be culled.
fn culled(ctx: &OpenGlContext, ax: f32, ay: f32, bx: f32, by: f32, cx: f32, cy: f32) -> bool {
    if ctx.enabled & (1 << 1) == 0 {
        return false;
    }
    // With top-down rows the signed area is negated; CCW front-faces get a
    // positive area.
    let area = (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
    let front_ccw = ctx.front_face == GL_CCW;
    let is_front = if front_ccw { area > 0.0 } else { area < 0.0 };
    match ctx.cull_face {
        GL_FRONT => is_front,
        GL_BACK => !is_front,
        _ => false,
    }
}

fn sample_texture(ctx: &OpenGlContext, u: f32, v: f32) -> [f32; 4] {
    let Some(texture) = ctx.textures.get(&ctx.bound_texture) else {
        return [1.0, 1.0, 1.0, 1.0];
    };
    if texture.width == 0 || texture.height == 0 {
        return [1.0, 1.0, 1.0, 1.0];
    }
    let u = u.fract().rem_euclid(1.0);
    let v = 1.0 - v.fract().rem_euclid(1.0);
    let x = ((u * texture.width as f32).floor() as usize).min(texture.width as usize - 1);
    let y = ((v * texture.height as f32).floor() as usize).min(texture.height as usize - 1);
    let index = (y * texture.width as usize + x) * 4;
    let texel = texture
        .texels
        .get(index..index + 4)
        .unwrap_or(&[255, 255, 255, 255]);
    [
        texel[0] as f32 / 255.0,
        texel[1] as f32 / 255.0,
        texel[2] as f32 / 255.0,
        texel[3] as f32 / 255.0,
    ]
}

fn blend_pixel(ctx: &OpenGlContext, src: [f32; 4], dst: [f32; 4]) -> [f32; 4] {
    if ctx.enabled & (1 << 4) == 0 {
        return src;
    }
    let (sf, df) = (ctx.blend_src, ctx.blend_dst);
    let (sf, df) = (
        if sf == GL_SRC_ALPHA {
            src[3]
        } else if sf == GL_ONE {
            1.0
        } else {
            0.0
        },
        if df == GL_ONE_MINUS_SRC_ALPHA {
            1.0 - src[3]
        } else if df == GL_ONE {
            1.0
        } else {
            0.0
        },
    );
    let mut out = [0.0; 4];
    for i in 0..4 {
        out[i] = (src[i] * sf + dst[i] * df).clamp(0.0, 1.0);
    }
    out
}

fn plot_pixel(ctx: &mut OpenGlContext, x: i32, y: i32, z: f32, color: [f32; 4], tex: [f32; 2]) {
    let width = ctx.framebuffer.width;
    let height = ctx.framebuffer.height;
    if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 {
        return;
    }
    let index = y as usize * width as usize + x as usize;
    let depth_test = ctx.enabled & (1 << 0) != 0;
    if depth_test {
        let depth = ctx.framebuffer.depth[index];
        if !depth_passes(ctx, z, depth) {
            return;
        }
    }
    let mut final_color = color;
    if ctx.enabled & (1 << 3) != 0 && ctx.bound_texture != 0 {
        let texel = sample_texture(ctx, tex[0], tex[1]);
        final_color = [
            final_color[0] * texel[0],
            final_color[1] * texel[1],
            final_color[2] * texel[2],
            final_color[3] * texel[3],
        ];
    }
    let pixel = &ctx.framebuffer.pixels[index * 4..index * 4 + 4];
    let dst = [
        pixel[0] as f32 / 255.0,
        pixel[1] as f32 / 255.0,
        pixel[2] as f32 / 255.0,
        pixel[3] as f32 / 255.0,
    ];
    let blended = blend_pixel(ctx, final_color, dst);
    let fb = &mut ctx.framebuffer;
    if depth_test {
        fb.depth[index] = z;
    }
    fb.pixels[index * 4] = (blended[0].clamp(0.0, 1.0) * 255.0).round() as u8;
    fb.pixels[index * 4 + 1] = (blended[1].clamp(0.0, 1.0) * 255.0).round() as u8;
    fb.pixels[index * 4 + 2] = (blended[2].clamp(0.0, 1.0) * 255.0).round() as u8;
    fb.pixels[index * 4 + 3] = (blended[3].clamp(0.0, 1.0) * 255.0).round() as u8;
}

fn fill_triangle(ctx: &mut OpenGlContext, a: &GlVertexState, b: &GlVertexState, c: &GlVertexState) {
    let (Some(sa), Some(sb), Some(sc)) = (
        transform_vertex(ctx, a),
        transform_vertex(ctx, b),
        transform_vertex(ctx, c),
    ) else {
        return;
    };
    if culled(ctx, sa.0, sa.1, sb.0, sb.1, sc.0, sc.1) {
        return;
    }
    let (ax, ay, az, _aw) = sa;
    let (bx, by, bz, _bw) = sb;
    let (cx, cy, cz, _cw) = sc;
    let min_x = ax.min(bx).min(cx).floor() as i32;
    let max_x = ax.max(bx).max(cx).ceil() as i32;
    let min_y = ay.min(by).min(cy).floor() as i32;
    let max_y = ay.max(by).max(cy).ceil() as i32;
    let fb = &ctx.framebuffer;
    if min_x >= fb.width as i32 || max_x < 0 || min_y >= fb.height as i32 || max_y < 0 {
        return;
    }
    let area = (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
    if area.abs() < 1.0e-9 {
        return;
    }
    let v0 = [cx - ax, cy - ay];
    let v1 = [bx - ax, by - ay];
    let dot00 = v0[0] * v0[0] + v0[1] * v0[1];
    let dot01 = v0[0] * v1[0] + v0[1] * v1[1];
    let dot11 = v1[0] * v1[0] + v1[1] * v1[1];
    let denom = dot00 * dot11 - dot01 * dot01;
    if denom.abs() < 1.0e-9 {
        return;
    }
    for py in min_y..=max_y {
        for px in min_x..=max_x {
            let v2 = [px as f32 - ax, py as f32 - ay];
            let dot02 = v0[0] * v2[0] + v0[1] * v2[1];
            let dot12 = v1[0] * v2[0] + v1[1] * v2[1];
            let inv = 1.0 / denom;
            let u = (dot11 * dot02 - dot01 * dot12) * inv;
            let v = (dot00 * dot12 - dot01 * dot02) * inv;
            let w0 = 1.0 - u - v;
            if u < -1.0e-4 || v < -1.0e-4 || w0 < -1.0e-4 {
                continue;
            }
            let z = w0 * az + u * bz + v * cz;
            let color = if ctx.shade_model == GL_FLAT {
                c.color
            } else {
                std::array::from_fn(|i| w0 * a.color[i] + u * b.color[i] + v * c.color[i])
            };
            let tex = [
                w0 * a.tex[0] + u * b.tex[0] + v * c.tex[0],
                w0 * a.tex[1] + u * b.tex[1] + v * c.tex[1],
            ];
            plot_pixel(ctx, px, py, z, color, tex);
        }
    }
}

fn draw_line(ctx: &mut OpenGlContext, a: (f32, f32, f32, f32), b: (f32, f32, f32, f32)) {
    let steps = ((a.0 - b.0).abs().max((a.1 - b.1).abs())).ceil().max(1.0) as u32;
    for step in 0..=steps {
        let t = step as f32 / steps as f32;
        let x = a.0 + (b.0 - a.0) * t;
        let y = a.1 + (b.1 - a.1) * t;
        let z = a.2 + (b.2 - a.2) * t;
        let color = ctx.current_color;
        plot_pixel(
            ctx,
            x.round() as i32,
            y.round() as i32,
            z,
            color,
            [0.0, 0.0],
        );
    }
}

/// Generate a UV sphere as a triangle strip.
fn sphere_vertices(radius: f32, slices: u32, stacks: u32) -> Vec<GlVertexState> {
    let mut vertices = Vec::new();
    for stack in 0..=stacks {
        let phi = std::f32::consts::PI * stack as f32 / stacks as f32;
        let y = (phi.cos() * radius).max(-radius).min(radius);
        let r = phi.sin() * radius;
        for slice in 0..=slices {
            let theta = std::f32::consts::TAU * slice as f32 / slices as f32;
            vertices.push(GlVertexState {
                x: theta.cos() * r,
                y,
                z: theta.sin() * r,
                color: [1.0, 1.0, 1.0, 1.0],
                tex: [slice as f32 / slices as f32, stack as f32 / stacks as f32],
            });
        }
    }
    vertices
}

/// Generate a cylinder (or cone) as a triangle strip.
fn cylinder_vertices(
    base: f32,
    top: f32,
    height: f32,
    slices: u32,
    stacks: u32,
) -> Vec<GlVertexState> {
    let mut vertices = Vec::new();
    for stack in 0..=stacks {
        let t = stack as f32 / stacks as f32;
        let y = height * t;
        let radius = base + (top - base) * t;
        for slice in 0..=slices {
            let theta = std::f32::consts::TAU * slice as f32 / slices as f32;
            vertices.push(GlVertexState {
                x: theta.cos() * radius,
                y,
                z: theta.sin() * radius,
                color: [1.0, 1.0, 1.0, 1.0],
                tex: [slice as f32 / slices as f32, t],
            });
        }
    }
    vertices
}

/// Generate an annulus as a triangle strip.
fn disk_vertices(
    inner: f32,
    outer: f32,
    slices: u32,
    loops: u32,
    start: f32,
    sweep: f32,
) -> Vec<GlVertexState> {
    let mut vertices = Vec::new();
    for loop_ring in 0..=loops {
        let t = loop_ring as f32 / loops as f32;
        let radius = inner + (outer - inner) * t;
        for slice in 0..=slices {
            let theta = start + sweep * slice as f32 / slices as f32;
            vertices.push(GlVertexState {
                x: theta.cos() * radius,
                y: theta.sin() * radius,
                z: 0.0,
                color: [1.0, 1.0, 1.0, 1.0],
                tex: [slice as f32 / slices as f32, t],
            });
        }
    }
    vertices
}
