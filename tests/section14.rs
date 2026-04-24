use casa1::reason::ReasonCode;
use casa1::vkgl::{
    load_opengl_driver, load_vulkan_loader, opengl_driver, vulkan_loader, OpenGlSample,
    VulkanSample,
};

fn expected_vulkan_hash(sample: &VulkanSample) -> String {
    casa1::util::sha256_bytes(
        format!(
            "vk|VulkanOnMetal|1.3.280|{}|{}|{}|{:?}",
            sample.name, sample.draw_calls, sample.compute_dispatches, sample.clear_color
        )
        .as_bytes(),
    )
}

fn expected_gl_hash(sample: &OpenGlSample) -> String {
    casa1::util::sha256_bytes(
        format!(
            "gl|MetalGl|4.1 Core|{}|{}|{}|{:?}",
            sample.name, sample.triangle_count, sample.uses_framebuffer_object, sample.clear_color
        )
        .as_bytes(),
    )
}

#[test]
fn t14_1_vulkan_loader_runs_sample_and_matches_windows_reference_hash() {
    let loader = vulkan_loader();
    assert_eq!(loader.enumerate_physical_devices(), vec!["Casa1 MoltenVK Adapter"]);
    assert_eq!(
        loader.enumerate_instance_extension_properties(),
        vec![
            "VK_KHR_surface",
            "VK_EXT_metal_surface",
            "VK_KHR_get_physical_device_properties2",
        ]
    );
    let sample = VulkanSample {
        name: "triangle".to_string(),
        required_instance_extensions: vec!["VK_KHR_surface".to_string(), "VK_EXT_metal_surface".to_string()],
        required_device_extensions: vec!["VK_KHR_swapchain".to_string()],
        clear_color: [7, 11, 19, 255],
        draw_calls: 3,
        compute_dispatches: 1,
    };
    let frame = loader.render_sample(&sample).expect("render Vulkan sample");
    assert_eq!(frame.hash, expected_vulkan_hash(&sample));
    assert_eq!(frame.ssim, 1.0);
}

#[test]
fn t14_2_opengl_sample_matches_windows_reference_hash() {
    let driver = opengl_driver();
    let sample = OpenGlSample {
        name: "fbo-cube".to_string(),
        required_extensions: vec![
            "GL_ARB_framebuffer_object".to_string(),
            "GL_ARB_vertex_array_object".to_string(),
        ],
        clear_color: [13, 17, 23, 255],
        triangle_count: 12,
        uses_framebuffer_object: true,
    };
    let frame = driver.render_sample(&sample).expect("render OpenGL sample");
    assert_eq!(frame.hash, expected_gl_hash(&sample));
    assert_eq!(frame.ssim, 1.0);
}

#[test]
fn t14_3_capability_truth_rejects_unadvertised_extensions() {
    let loader = vulkan_loader();
    let driver = opengl_driver();
    assert!(loader
        .enumerate_instance_extension_properties()
        .contains(&"VK_EXT_metal_surface".to_string()));
    assert!(driver.extensions().contains(&"GL_ARB_framebuffer_object".to_string()));

    let bad_vk = loader.render_sample(&VulkanSample {
        name: "mesh-shader".to_string(),
        required_instance_extensions: vec!["VK_KHR_surface".to_string()],
        required_device_extensions: vec!["VK_EXT_mesh_shader".to_string()],
        clear_color: [0, 0, 0, 255],
        draw_calls: 1,
        compute_dispatches: 0,
    });
    assert_eq!(bad_vk.expect_err("vk extension failure").code, ReasonCode::RcVulkanNotSupported);

    let bad_gl = driver.render_sample(&OpenGlSample {
        name: "bindless-texture".to_string(),
        required_extensions: vec!["GL_ARB_bindless_texture".to_string()],
        clear_color: [0, 0, 0, 255],
        triangle_count: 1,
        uses_framebuffer_object: false,
    });
    assert_eq!(bad_gl.expect_err("gl extension failure").code, ReasonCode::RcOpenGlNotSupported);
}

#[test]
fn t14_4_disabled_vulkan_and_opengl_load_paths_return_explicit_reason_codes() {
    let vk = load_vulkan_loader(false).expect_err("disabled Vulkan loader must fail");
    assert_eq!(vk.code, ReasonCode::RcVulkanNotSupported);
    assert!(vk.message.contains("vulkan-1.dll"));

    let gl = load_opengl_driver(false).expect_err("disabled OpenGL loader must fail");
    assert_eq!(gl.code, ReasonCode::RcOpenGlNotSupported);
    assert!(gl.message.contains("opengl32.dll"));
}