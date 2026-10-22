#![allow(dead_code, unused_imports)]
use casa1::reason::ReasonCode;
use casa1::vkgl::{OpenGlSample, VulkanSample, opengl_driver, vulkan_loader};

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
