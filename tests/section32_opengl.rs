//! Section 32 — OpenGL via ANGLE (Phase 2.6)
//!
//! Tests the OpenGL translation layer:
//!   - WGL context creation / make current / delete
//!   - GL state defaults
//!   - GL draw call recording
//!   - GLSL shader compilation
//!   - GL state tracking (blend, depth, viewport, scissor, rasterizer, framebuffer)

mod support;

use casa1::vkgl::{
    GLState, GLBlendState, GLDepthState, GLStencilState,
    GLRasterizerState, GLScissorState, GLFramebufferState,
    AngleLoader, GlslToMslTranslator, GlslShaderStage,
    ThreadSafeGLState,
};

// ═══════════════════════════════════════════════════════════════════════════════
// t32_01 — WGL context creation / make current / delete
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_01_wgl_context_lifecycle() {
    let mut gl = GLState::new();

    // Create context
    let ctx1 = gl.gl_create_context().unwrap();
    assert_ne!(ctx1, 0);
    assert_eq!(gl.context_count(), 1);
    assert!(!gl.has_current_context());

    // Make current
    gl.gl_make_current(ctx1).unwrap();
    assert!(gl.has_current_context());
    assert_eq!(gl.current_context_handle(), Some(ctx1));

    // Create second context
    let ctx2 = gl.gl_create_context().unwrap();
    assert_eq!(gl.context_count(), 2);

    // Switch to second context
    gl.gl_make_current(ctx2).unwrap();
    assert_eq!(gl.current_context_handle(), Some(ctx2));

    // Delete first context (not current, should work)
    gl.gl_delete_context(ctx1).unwrap();
    assert_eq!(gl.context_count(), 1);
    assert_eq!(gl.current_context_handle(), Some(ctx2)); // ctx2 still current

    // Delete current context
    gl.gl_delete_context(ctx2).unwrap();
    assert_eq!(gl.context_count(), 0);
    assert!(!gl.has_current_context());

    // Delete non-existent context should fail
    assert!(gl.gl_delete_context(9999).is_err());

    // Make non-existent context current should fail
    assert!(gl.gl_make_current(9999).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_02 — GL state defaults
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_02_gl_state_defaults() {
    let mut gl = GLState::new();
    let ctx = gl.gl_create_context().unwrap();
    gl.gl_make_current(ctx).unwrap();

    // Check viewport defaults
    let ctx_ref = gl.current_context_ref().unwrap();
    assert_eq!(ctx_ref.viewport, (0, 0, 800, 600));
    assert_eq!(ctx_ref.clear_color, (0.0, 0.0, 0.0, 1.0));

    // Check blend state defaults
    assert!(!ctx_ref.blend_state.enabled);
    assert_eq!(ctx_ref.blend_state.src_factor, 1);
    assert_eq!(ctx_ref.blend_state.dst_factor, 0);

    // Check depth state defaults
    assert!(!ctx_ref.depth_state.test_enabled);
    assert!(ctx_ref.depth_state.write_enabled);
    assert_eq!(ctx_ref.depth_state.func, 0x0201); // GL_LESS

    // Check stencil state defaults
    assert!(!ctx_ref.stencil_state.test_enabled);
    assert_eq!(ctx_ref.stencil_state.ref_value, 0);
    assert_eq!(ctx_ref.stencil_state.mask, 0xFFFF_FFFF);

    // Check rasterizer state defaults (Phase 2.6)
    assert!(!ctx_ref.rasterizer_state.cull_face_enabled);
    assert_eq!(ctx_ref.rasterizer_state.cull_face_mode, 0x0405); // GL_BACK
    assert_eq!(ctx_ref.rasterizer_state.front_face, 0x0901);     // GL_CCW
    assert_eq!(ctx_ref.rasterizer_state.polygon_mode, 0x1B02);   // GL_FILL
    assert_eq!(ctx_ref.rasterizer_state.line_width, 1.0);
    assert_eq!(ctx_ref.rasterizer_state.point_size, 1.0);

    // Check scissor state defaults (Phase 2.6)
    assert!(!ctx_ref.scissor_state.test_enabled);
    assert_eq!(ctx_ref.scissor_state.box_x, 0);
    assert_eq!(ctx_ref.scissor_state.box_y, 0);
    assert_eq!(ctx_ref.scissor_state.box_width, 800);
    assert_eq!(ctx_ref.scissor_state.box_height, 600);

    // Check framebuffer state defaults (Phase 2.6)
    assert!(ctx_ref.framebuffer_state.draw_framebuffer.is_none());
    assert!(ctx_ref.framebuffer_state.read_framebuffer.is_none());
    assert!(ctx_ref.framebuffer_state.renderbuffer.is_none());

    // No capabilities enabled by default
    assert!(ctx_ref.enabled_capabilities.is_empty());

    // No program bound
    assert!(ctx_ref.program.is_none());
    // No vertex array bound
    assert!(ctx_ref.vertex_array.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_03 — GL draw call recording
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_03_gl_draw_call_recording() {
    let mut gl = GLState::new();
    let ctx = gl.gl_create_context().unwrap();
    gl.gl_make_current(ctx).unwrap();

    // Draw without program should fail
    assert!(gl.gl_draw_arrays(0x0004, 0, 3).is_err());
    assert!(gl.gl_draw_elements(0x0004, 6, 0x1405, 0).is_err());

    // Create and bind program
    let prog = gl.gl_create_program().unwrap();
    gl.gl_use_program(prog).unwrap();

    // Now draw should succeed
    gl.gl_draw_arrays(0x0004, 0, 3).unwrap(); // GL_TRIANGLES
    gl.gl_draw_elements(0x0004, 6, 0x1405, 0).unwrap(); // GL_UNSIGNED_SHORT

    // Create and bind buffers
    let bufs = gl.gl_gen_buffers(2).unwrap();
    assert_eq!(bufs.len(), 2);
    gl.gl_bind_buffer(0x8892, bufs[0]).unwrap(); // GL_ARRAY_BUFFER
    gl.gl_bind_buffer(0x8893, bufs[1]).unwrap(); // GL_ELEMENT_ARRAY_BUFFER

    // Upload data
    let vertex_data = [1.0f32, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
    let bytes: Vec<u8> = vertex_data.iter().flat_map(|f| f.to_le_bytes()).collect();
    gl.gl_buffer_data(0x8892, &bytes, 0x88E4).unwrap(); // GL_STATIC_DRAW

    // Create and bind textures
    let tex = gl.gl_gen_textures(1).unwrap();
    gl.gl_bind_texture(0x0DE0, tex[0]).unwrap(); // GL_TEXTURE_2D

    // Upload texture data
    let tex_data = vec![255u8; 4 * 4 * 4]; // 4x4 RGBA
    gl.gl_tex_image_2d(tex[0], 0, &tex_data).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_04 — GLSL shader compilation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_04_glsl_shader_compilation() {
    let mut gl = GLState::new();
    let ctx = gl.gl_create_context().unwrap();
    gl.gl_make_current(ctx).unwrap();

    // Create and compile vertex shader
    let vs = gl.gl_create_shader(0x8B31).unwrap(); // GL_VERTEX_SHADER
    let vs_source = r#"#version 330 core
uniform mat4 uMVP;
attribute vec3 aPosition;
void main() {
    gl_Position = uMVP * vec4(aPosition, 1.0);
}"#;
    gl.gl_compile_shader(vs, vs_source).unwrap();

    // Create and compile fragment shader
    let fs = gl.gl_create_shader(0x8B30).unwrap(); // GL_FRAGMENT_SHADER
    let fs_source = r#"#version 330 core
uniform vec4 uColor;
void main() {
    gl_FragColor = uColor;
}"#;
    gl.gl_compile_shader(fs, fs_source).unwrap();

    // Create and link program
    let prog = gl.gl_create_program().unwrap();
    gl.gl_link_program(prog).unwrap();
    gl.gl_use_program(prog).unwrap();

    // Test GLSL→MSL translation (Phase 2.6)
    let msl = GLState::glsl_to_msl(vs_source, GlslShaderStage::Vertex).unwrap();
    assert!(msl.contains("metal_stdlib"));
    assert!(msl.contains("vertex"));
    assert!(msl.contains("casa1_entry"));

    let msl_fs = GLState::glsl_to_msl(fs_source, GlslShaderStage::Fragment).unwrap();
    assert!(msl_fs.contains("metal_stdlib"));
    assert!(msl_fs.contains("fragment"));

    // Test with texture sampling
    let tex_source = r#"#version 330 core
uniform sampler2D uTexture;
void main() {
    gl_FragColor = texture2D(uTexture, vec2(0.5, 0.5));
}"#;
    let msl_tex = GLState::glsl_to_msl(tex_source, GlslShaderStage::Fragment).unwrap();
    assert!(msl_tex.contains("texture2d") || msl_tex.contains("sampler"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_05 — GL state tracking (blend, depth, viewport, scissor, rasterizer)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_05_gl_state_tracking() {
    let mut gl = GLState::new();
    let ctx = gl.gl_create_context().unwrap();
    gl.gl_make_current(ctx).unwrap();

    // --- Blend state ---
    assert!(!gl.gl_is_enabled(0x0BE2).unwrap()); // GL_BLEND
    gl.gl_enable(0x0BE2).unwrap(); // GL_BLEND
    assert!(gl.gl_is_enabled(0x0BE2).unwrap());
    let blend = gl.gl_blend_state().unwrap();
    assert!(blend.enabled);

    gl.gl_blend_func(0x0300, 0x0301).unwrap(); // GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA
    let blend = gl.gl_blend_state().unwrap();
    assert_eq!(blend.src_factor, 0x0300);
    assert_eq!(blend.dst_factor, 0x0301);

    gl.gl_disable(0x0BE2).unwrap();
    assert!(!gl.gl_is_enabled(0x0BE2).unwrap());
    let blend = gl.gl_blend_state().unwrap();
    assert!(!blend.enabled);

    // --- Depth state ---
    assert!(!gl.gl_is_enabled(0x0B71).unwrap()); // GL_DEPTH_TEST
    gl.gl_enable(0x0B71).unwrap();
    assert!(gl.gl_is_enabled(0x0B71).unwrap());

    gl.gl_depth_func(0x0203).unwrap(); // GL_LEQUAL
    let depth = gl.gl_depth_state().unwrap();
    assert!(depth.test_enabled);
    assert_eq!(depth.func, 0x0203);

    gl.gl_depth_mask(false).unwrap();
    let depth = gl.gl_depth_state().unwrap();
    assert!(!depth.write_enabled);

    gl.gl_disable(0x0B71).unwrap();
    let depth = gl.gl_depth_state().unwrap();
    assert!(!depth.test_enabled);

    // --- Viewport ---
    gl.gl_viewport(10, 20, 1024, 768).unwrap();
    let ctx_ref = gl.current_context_ref().unwrap();
    assert_eq!(ctx_ref.viewport, (10, 20, 1024, 768));

    // --- Scissor state ---
    assert!(!gl.gl_is_enabled(0x0C11).unwrap()); // GL_SCISSOR_TEST
    gl.gl_enable(0x0C11).unwrap();
    assert!(gl.gl_is_enabled(0x0C11).unwrap());

    gl.gl_scissor(5, 10, 200, 300).unwrap();
    let scissor = gl.gl_scissor_state().unwrap();
    assert!(scissor.test_enabled);
    assert_eq!(scissor.box_x, 5);
    assert_eq!(scissor.box_y, 10);
    assert_eq!(scissor.box_width, 200);
    assert_eq!(scissor.box_height, 300);

    gl.gl_disable(0x0C11).unwrap();
    let scissor = gl.gl_scissor_state().unwrap();
    assert!(!scissor.test_enabled);

    // --- Rasterizer state ---
    gl.gl_enable(0x0B44).unwrap(); // GL_CULL_FACE
    assert!(gl.gl_is_enabled(0x0B44).unwrap());

    gl.gl_cull_face(0x0404).unwrap(); // GL_FRONT
    let raster = gl.gl_rasterizer_state().unwrap();
    assert!(raster.cull_face_enabled);
    assert_eq!(raster.cull_face_mode, 0x0404);

    gl.gl_front_face(0x0900).unwrap(); // GL_CW
    let raster = gl.gl_rasterizer_state().unwrap();
    assert_eq!(raster.front_face, 0x0900);

    gl.gl_line_width(2.5).unwrap();
    let raster = gl.gl_rasterizer_state().unwrap();
    assert_eq!(raster.line_width, 2.5);

    gl.gl_point_size(5.0).unwrap();
    let raster = gl.gl_rasterizer_state().unwrap();
    assert_eq!(raster.point_size, 5.0);

    gl.gl_polygon_mode(0x0408, 0x1B01).unwrap(); // GL_FRONT_AND_BACK, GL_LINE
    let raster = gl.gl_rasterizer_state().unwrap();
    assert_eq!(raster.polygon_mode, 0x1B01);

    gl.gl_disable(0x0B44).unwrap();
    let raster = gl.gl_rasterizer_state().unwrap();
    assert!(!raster.cull_face_enabled);

    // --- Stencil state ---
    gl.gl_enable(0x0B90).unwrap(); // GL_STENCIL_TEST
    assert!(gl.gl_is_enabled(0x0B90).unwrap());
    gl.gl_disable(0x0B90).unwrap();
    assert!(!gl.gl_is_enabled(0x0B90).unwrap());

    // --- Framebuffer state ---
    let fbos = gl.gl_gen_framebuffers(2).unwrap();
    assert_eq!(fbos.len(), 2);

    gl.gl_bind_framebuffer(0x8D40, fbos[0]).unwrap(); // GL_FRAMEBUFFER
    let fb_state = gl.gl_framebuffer_state().unwrap();
    assert_eq!(fb_state.draw_framebuffer, Some(fbos[0] as u64));

    gl.gl_bind_framebuffer(0x8CA8, fbos[1]).unwrap(); // GL_READ_FRAMEBUFFER
    let fb_state = gl.gl_framebuffer_state().unwrap();
    assert_eq!(fb_state.read_framebuffer, Some(fbos[1] as u64));

    // --- Vertex Array Objects ---
    let vaos = gl.gl_gen_vertex_arrays(1).unwrap();
    assert_eq!(vaos.len(), 1);
    gl.gl_bind_vertex_array(vaos[0]).unwrap();
    let ctx_ref = gl.current_context_ref().unwrap();
    assert_eq!(ctx_ref.vertex_array, Some(vaos[0] as u64));

    // --- Clear color ---
    gl.gl_clear_color(0.2, 0.4, 0.6, 1.0).unwrap();
    let ctx_ref = gl.current_context_ref().unwrap();
    assert_eq!(ctx_ref.clear_color, (0.2, 0.4, 0.6, 1.0));

    // --- Clear (should succeed with current context) ---
    gl.gl_clear(0x00004000 | 0x00000100).unwrap(); // GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_06 — ANGLE detection
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_06_angle_detection() {
    let mut loader = AngleLoader::new();
    assert!(!loader.is_loaded());
    assert!(loader.framework_path().is_none());
    assert!(loader.version().is_none());

    // Detect should succeed even if ANGLE is not installed (graceful fallback)
    let result = loader.detect();
    // Either ANGLE is found (loaded = true) or not found (loaded = false, no error)
    assert!(result.is_ok());

    // Verify default implementation
    let default_loader = AngleLoader::default();
    assert!(!default_loader.is_loaded());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_07 — Thread-safe GL state
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_07_thread_safe_gl_state() {
    let ts_gl = ThreadSafeGLState::new();
    assert_eq!(ts_gl.context_count(), 0);
    assert!(!ts_gl.has_current_context());

    // Create context
    let ctx = ts_gl.gl_create_context().unwrap();
    assert_ne!(ctx, 0);
    assert_eq!(ts_gl.context_count(), 1);

    // Make current
    ts_gl.gl_make_current(ctx).unwrap();
    assert!(ts_gl.has_current_context());

    // Set viewport
    ts_gl.gl_viewport(0, 0, 1920, 1080).unwrap();

    // Set clear color
    ts_gl.gl_clear_color(0.0, 0.0, 0.0, 1.0).unwrap();

    // Enable blend
    ts_gl.gl_enable(0x0BE2).unwrap(); // GL_BLEND

    // Create program and use it
    let prog = ts_gl.gl_create_program().unwrap();
    ts_gl.gl_use_program(prog).unwrap();

    // Draw
    ts_gl.gl_draw_arrays(0x0004, 0, 3).unwrap(); // GL_TRIANGLES

    // Disable blend
    ts_gl.gl_disable(0x0BE2).unwrap();

    // Delete context
    ts_gl.gl_delete_context(ctx).unwrap();
    assert_eq!(ts_gl.context_count(), 0);
    assert!(!ts_gl.has_current_context());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_08 — OpenGL driver info
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_08_opengl_driver_info() {
    let driver = casa1::vkgl::opengl_driver();
    assert!(driver.supported);
    assert_eq!(driver.backend, casa1::vkgl::GraphicsBackend::MetalGl);
    assert!(!driver.version.is_empty());
    assert!(!driver.extensions.is_empty());
    assert!(!driver.renderer.is_empty());

    // Check specific extensions
    assert!(driver.extensions().iter().any(|e| e.contains("framebuffer")));
    assert!(driver.extensions().iter().any(|e| e.contains("vertex_array")));

    // Unsupported driver
    let err = casa1::vkgl::load_opengl_driver(false).unwrap_err();
    assert!(err.to_string().contains("opengl32.dll"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_09 — GLSL→MSL translator edge cases
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_09_glsl_to_msl_edge_cases() {
    // Empty shader
    let empty_source = "void main() {}";
    let msl = GLState::glsl_to_msl(empty_source, GlslShaderStage::Vertex).unwrap();
    assert!(msl.contains("metal_stdlib"));
    assert!(msl.contains("vertex"));

    // Compute shader
    let compute_source = r#"uniform float dt;
void main() {
    float x = dt * 2.0;
}"#;
    let msl = GLState::glsl_to_msl(compute_source, GlslShaderStage::Compute).unwrap();
    assert!(msl.contains("kernel"));

    // Shader with only uniforms (no main body)
    let uniform_only = "uniform mat4 uMVP;\nuniform vec3 uLightDir;";
    let msl = GLState::glsl_to_msl(uniform_only, GlslShaderStage::Fragment).unwrap();
    assert!(msl.contains("Uniforms"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t32_10 — DLL registration exports
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t32_10_dll_registration_exports() {
    let vk_exports = casa1::vkgl::register_vulkan_dll();
    assert!(!vk_exports.is_empty());
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateInstance"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkDestroyInstance"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateDevice"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkDestroyDevice"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateSwapchainKHR"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateShaderModule"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateGraphicsPipelines"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateComputePipelines"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkQueueSubmit"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateBuffer"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateImage"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkAllocateMemory"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateFence"));
    assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateSemaphore"));

    let gl_exports = casa1::vkgl::register_opengl_dll();
    assert!(!gl_exports.is_empty());
    assert!(gl_exports.iter().any(|(name, _)| *name == "wglCreateContext"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "wglMakeCurrent"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "wglDeleteContext"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glDrawArrays"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glDrawElements"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glGenBuffers"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glBindBuffer"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glBufferData"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glCreateShader"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glCompileShader"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glLinkProgram"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glUseProgram"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glGenTextures"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glBindTexture"));
    assert!(gl_exports.iter().any(|(name, _)| *name == "glTexImage2D"));
}
