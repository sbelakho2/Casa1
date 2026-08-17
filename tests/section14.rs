use casa1::reason::ReasonCode;
use casa1::vkgl::{
    OpenGlSample, VulkanSample, load_opengl_driver, load_vulkan_loader, opengl_driver,
    vulkan_loader,
};

// Golden hashes below are pinned literal constants captured from a known-good run of the
// Metal-backed renderer. They are NOT recomputed in the test from the implementation's
// format string: recomputing them here would make the assertions self-referential (a stub
// that hashes the same format string would pass). Pinning the literals means any change to
// the hash inputs, the format, or the sample fields breaks the test, and the
// hash-sensitivity checks below prove the artifact is derived from the sample rather than
// being a constant.
const GOLDEN_VULKAN_SAMPLE_HASH: &str =
    "647bfb1fcc96ef75ca1ddb24bdce4dc65510b279d43185c58c316ca3189bbc94";
const GOLDEN_OPENGL_SAMPLE_HASH: &str =
    "e4f9f5c0a2faca54b5cf95a74ee2f0dcdfd9dc090764fd04c8a1423d6e0de365";

fn vulkan_sample() -> VulkanSample {
    VulkanSample {
        name: "triangle".to_string(),
        required_instance_extensions: vec![
            "VK_KHR_surface".to_string(),
            "VK_EXT_metal_surface".to_string(),
        ],
        required_device_extensions: vec!["VK_KHR_swapchain".to_string()],
        clear_color: [7, 11, 19, 255],
        draw_calls: 3,
        compute_dispatches: 1,
    }
}

fn opengl_sample() -> OpenGlSample {
    OpenGlSample {
        name: "fbo-cube".to_string(),
        required_extensions: vec![
            "GL_ARB_framebuffer_object".to_string(),
            "GL_ARB_vertex_array_object".to_string(),
        ],
        clear_color: [13, 17, 23, 255],
        triangle_count: 12,
        uses_framebuffer_object: true,
    }
}

#[test]
fn t14_1_vulkan_render_sample_produces_stable_sample_derived_hash() {
    let loader = vulkan_loader();
    assert_eq!(
        loader.enumerate_physical_devices(),
        vec!["Casa1 MoltenVK Adapter"]
    );
    assert_eq!(
        loader.enumerate_instance_extension_properties(),
        vec![
            "VK_KHR_surface",
            "VK_EXT_metal_surface",
            "VK_KHR_get_physical_device_properties2",
        ]
    );

    let frame = loader
        .render_sample(&vulkan_sample())
        .expect("render Vulkan sample");
    assert_eq!(
        frame.hash, GOLDEN_VULKAN_SAMPLE_HASH,
        "sample hash drifted from the pinned golden value"
    );
    assert!(
        frame.validation_errors.is_empty(),
        "expected no validation errors, got {:?}",
        frame.validation_errors
    );

    // The hash must be derived from the sample parameters, not a constant: mutating any
    // hashed input must change the artifact hash, and rendering the same sample twice
    // must be deterministic.
    let mut sample = vulkan_sample();
    sample.name = "triangle-renamed".to_string();
    let renamed = loader.render_sample(&sample).expect("renamed sample");
    assert_ne!(renamed.hash, frame.hash, "name must affect the frame hash");

    sample = vulkan_sample();
    sample.draw_calls = 4;
    let more_draws = loader.render_sample(&sample).expect("more draw calls");
    assert_ne!(
        more_draws.hash, frame.hash,
        "draw_calls must affect the hash"
    );

    sample = vulkan_sample();
    sample.compute_dispatches = 2;
    let more_compute = loader
        .render_sample(&sample)
        .expect("more compute dispatches");
    assert_ne!(
        more_compute.hash, frame.hash,
        "compute_dispatches must affect the hash"
    );

    sample = vulkan_sample();
    sample.clear_color = [1, 2, 3, 4];
    let other_clear = loader.render_sample(&sample).expect("other clear color");
    assert_ne!(
        other_clear.hash, frame.hash,
        "clear_color must affect the hash"
    );

    let repeat = loader
        .render_sample(&vulkan_sample())
        .expect("repeat render");
    assert_eq!(repeat.hash, frame.hash, "rendering must be deterministic");

    // NOTE: FrameArtifact exposes no pixel data, and the implementation's single-frame
    // `ssim` field is a placeholder (always 1.0), so no meaningful SSIM assertion can be
    // written against this artifact. Pixel-level comparison is covered by the
    // diagnostics `compute_ssim`/`compare_frames` tests instead.
}

#[test]
fn t14_2_opengl_render_sample_produces_stable_sample_derived_hash() {
    let driver = opengl_driver();
    let frame = driver
        .render_sample(&opengl_sample())
        .expect("render OpenGL sample");
    assert_eq!(
        frame.hash, GOLDEN_OPENGL_SAMPLE_HASH,
        "sample hash drifted from the pinned golden value"
    );
    assert!(
        frame.validation_errors.is_empty(),
        "expected no validation errors, got {:?}",
        frame.validation_errors
    );

    let mut sample = opengl_sample();
    sample.name = "fbo-cube-renamed".to_string();
    let renamed = driver.render_sample(&sample).expect("renamed sample");
    assert_ne!(renamed.hash, frame.hash, "name must affect the frame hash");

    sample = opengl_sample();
    sample.triangle_count = 13;
    let more_triangles = driver.render_sample(&sample).expect("more triangles");
    assert_ne!(
        more_triangles.hash, frame.hash,
        "triangle_count must affect the hash"
    );

    sample = opengl_sample();
    sample.uses_framebuffer_object = false;
    let no_fbo = driver.render_sample(&sample).expect("no FBO");
    assert_ne!(
        no_fbo.hash, frame.hash,
        "uses_framebuffer_object must affect the hash"
    );

    sample = opengl_sample();
    sample.clear_color = [1, 2, 3, 4];
    let other_clear = driver.render_sample(&sample).expect("other clear color");
    assert_ne!(
        other_clear.hash, frame.hash,
        "clear_color must affect the hash"
    );

    let repeat = driver
        .render_sample(&opengl_sample())
        .expect("repeat render");
    assert_eq!(repeat.hash, frame.hash, "rendering must be deterministic");
}

#[test]
fn t14_3_capability_truth_rejects_unadvertised_extensions() {
    let loader = vulkan_loader();
    let driver = opengl_driver();
    assert!(
        loader
            .enumerate_instance_extension_properties()
            .contains(&"VK_EXT_metal_surface".to_string())
    );
    assert!(
        driver
            .extensions()
            .contains(&"GL_ARB_framebuffer_object".to_string())
    );

    let bad_vk = loader.render_sample(&VulkanSample {
        name: "mesh-shader".to_string(),
        required_instance_extensions: vec!["VK_KHR_surface".to_string()],
        required_device_extensions: vec!["VK_EXT_mesh_shader".to_string()],
        clear_color: [0, 0, 0, 255],
        draw_calls: 1,
        compute_dispatches: 0,
    });
    assert_eq!(
        bad_vk.expect_err("vk extension failure").code,
        ReasonCode::RcVulkanNotSupported
    );

    let bad_gl = driver.render_sample(&OpenGlSample {
        name: "bindless-texture".to_string(),
        required_extensions: vec!["GL_ARB_bindless_texture".to_string()],
        clear_color: [0, 0, 0, 255],
        triangle_count: 1,
        uses_framebuffer_object: false,
    });
    assert_eq!(
        bad_gl.expect_err("gl extension failure").code,
        ReasonCode::RcOpenGlNotSupported
    );
}

#[test]
fn t14_4_disabled_vulkan_and_opengl_load_paths_return_explicit_reason_codes() {
    let vk = load_vulkan_loader(false).expect_err("disabled Vulkan loader must fail");
    assert_eq!(vk.code, ReasonCode::RcVulkanNotSupported);

    let gl = load_opengl_driver(false).expect_err("disabled OpenGL loader must fail");
    assert_eq!(gl.code, ReasonCode::RcOpenGlNotSupported);

    // NOTE: message wording is not part of the API contract; only the reason code is
    // asserted (a reworded hint must not fail the test).
}
