//! Section 31 — Vulkan / MoltenVK Integration (Phase 2.5)
//!
//! Tests the Vulkan translation layer:
//!   - Instance creation with validation layers
//!   - Device creation and queue family selection
//!   - Swapchain creation parameters
//!   - Buffer and image creation
//!   - Graphics pipeline state tracking
//!   - Compute pipeline creation
//!   - Draw command recording

mod support;

use casa1::vkgl::{
    CommandBufferState, ImageSubresourceRange, KNOWN_VALIDATION_LAYERS, RecordedCommand,
    SUPPORTED_VK_KHR_EXTENSIONS, ThreadSafeVulkanState, VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
    VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
    VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
    VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR, VkColorSpaceKHR, VkCommandBufferLevel,
    VkExtensionRegistry, VkFormat, VkImageLayout, VkImageMemoryBarrier, VkIndexType,
    VkPipelineBindPoint, VkPresentModeKHR, VkSubmitInfo, VkSwapchainCreateInfo, VulkanState,
    load_vulkan_loader, moltenvk_expanded_search_paths, moltenvk_search_paths,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: bootstrap a full Vulkan device + queue
// ═══════════════════════════════════════════════════════════════════════════════

fn bootstrap_device() -> (VulkanState, u64, u64, u64) {
    let mut state = VulkanState::new();
    let inst = state.create_instance("test", "test", &[], &[]).unwrap();
    let phys = state.enumerate_physical_devices(inst).unwrap()[0];
    let dev = state.create_device(phys, &[], &[(0, 1)]).unwrap();
    (state, inst, phys, dev)
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_01 — Vulkan instance creation with validation layers
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_01_instance_creation_with_validation_layers() {
    let mut state = VulkanState::new();
    assert_eq!(state.instance_count(), 0);

    // Create instance without extensions or layers
    let inst = state
        .create_instance("TestApp", "TestEngine", &[], &[])
        .unwrap();
    assert_ne!(inst, 0);
    assert_eq!(state.instance_count(), 1);

    // Create instance with validation layers (simulated)
    let layers = vec!["VK_LAYER_KHRONOS_validation".to_string()];
    let inst2 = state
        .create_instance("App2", "Engine2", &[], &layers)
        .unwrap();
    assert_ne!(inst2, 0);
    assert_eq!(state.instance_count(), 2);

    // Create instance with extensions
    let exts = vec!["VK_KHR_surface".to_string()];
    let inst3 = state
        .create_instance("App3", "Engine3", &exts, &[])
        .unwrap();
    assert_ne!(inst3, 0);
    assert_eq!(state.instance_count(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_02 — Device creation and queue family selection
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_02_device_creation_and_queue_family_selection() {
    let mut state = VulkanState::new();
    let inst = state.create_instance("test", "test", &[], &[]).unwrap();

    // Enumerate physical devices
    let phys_devs = state.enumerate_physical_devices(inst).unwrap();
    assert_eq!(
        phys_devs.len(),
        1,
        "should have exactly one physical device"
    );
    let phys = phys_devs[0];
    assert_ne!(phys, 0);

    // Create device with one queue family, one queue
    let dev = state.create_device(phys, &[], &[(0, 1)]).unwrap();
    assert_ne!(dev, 0);
    assert_eq!(state.device_count(), 1);

    // Get queue from family 0, index 0
    let queue = state.get_device_queue(dev, 0, 0).unwrap();
    assert_ne!(queue, 0);

    // Queue from invalid family should fail
    let _result = state.get_device_queue(dev, 99, 0);
    assert!(_result.is_err(), "expected Err, got {_result:?}");

    // Queue from invalid index should fail
    let _result = state.get_device_queue(dev, 0, 5);
    assert!(_result.is_err(), "expected Err, got {_result:?}");

    // Create device with multiple queue families
    let dev2 = state.create_device(phys, &[], &[(0, 2), (1, 1)]).unwrap();
    assert_ne!(dev2, 0);
    assert_eq!(state.device_count(), 2);

    // Get queues from both families
    let q0 = state.get_device_queue(dev2, 0, 0).unwrap();
    let q1 = state.get_device_queue(dev2, 0, 1).unwrap();
    let q2 = state.get_device_queue(dev2, 1, 0).unwrap();
    assert_ne!(q0, q1);
    assert_ne!(q1, q2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_03 — Swapchain creation parameters
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_03_swapchain_creation_parameters() {
    let (mut state, _, _, dev) = bootstrap_device();
    let surface = state
        .create_surface(1024, 768, VkFormat::B8G8R8A8Unorm)
        .unwrap();

    let ci = VkSwapchainCreateInfo {
        surface,
        min_image_count: 3,
        image_format: VkFormat::B8G8R8A8Unorm,
        image_color_space: VkColorSpaceKHR::SrgbNonlinear,
        image_extent: (1024, 768),
        image_array_layers: 1,
        image_usage: VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
        pre_transform: VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR,
        composite_alpha: VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
        present_mode: VkPresentModeKHR::Mailbox,
        clipped: true,
    };

    let sc = state.create_swapchain(dev, surface, &ci).unwrap();
    let info = state.get_swapchain(sc).unwrap();
    assert_eq!(info.min_image_count, 3);
    assert_eq!(info.image_extent, (1024, 768));
    assert_eq!(info.image_format, VkFormat::B8G8R8A8Unorm);
    assert_eq!(info.image_color_space, VkColorSpaceKHR::SrgbNonlinear);
    assert_eq!(info.present_mode, VkPresentModeKHR::Mailbox);
    assert!(info.clipped);
    assert!(info.metal_layer.is_some());

    // Acquire next image
    let (idx, _) = state.acquire_next_image(sc, None, None).unwrap();
    assert!(idx < 3);

    // Present
    state.queue_present(0, sc, idx).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_04 — Buffer and image creation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_04_buffer_and_image_creation() {
    let (mut state, _, _, dev) = bootstrap_device();

    // Create buffer
    let buf = state
        .create_buffer(dev, 4096, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT)
        .unwrap();
    let buf_info = state.get_buffer(buf).unwrap();
    assert_eq!(buf_info.size, 4096);
    assert_eq!(buf_info.device, dev);

    // Create image
    let img = state
        .create_image(
            dev,
            VkFormat::R8G8B8A8Unorm,
            (512, 512, 1),
            4,
            1,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
        )
        .unwrap();
    let img_info = state.get_image(img).unwrap();
    assert_eq!(img_info.format, VkFormat::R8G8B8A8Unorm);
    assert_eq!(img_info.extent, (512, 512, 1));
    assert_eq!(img_info.mip_levels, 4);
    assert_eq!(img_info.layout, VkImageLayout::Undefined);

    // Create image view
    let view = state
        .create_image_view(img, VkFormat::R8G8B8A8Unorm, 1)
        .unwrap();
    assert_ne!(view, 0);

    // Allocate memory — use memory type 1 (host-visible) so map_memory succeeds
    let mem = state.allocate_memory(dev, 8192, 1).unwrap();
    let mem_info = state.get_device_memory(mem).unwrap();
    assert_eq!(mem_info.size, 8192);
    assert!(mem_info.metal_buffer.is_some());

    // Map/unmap memory
    let ptr = state.map_memory(dev, mem, 0, 1024).unwrap();
    assert!(!ptr.is_null());
    state.unmap_memory(dev, mem).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_05 — Graphics pipeline state tracking
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_05_graphics_pipeline_state_tracking() {
    let (mut state, _, _, dev) = bootstrap_device();

    // Create shader module
    let spirv = minimal_spirv();
    let _module = state.create_shader_module(dev, &spirv).unwrap();

    // Create pipeline layout
    let layout = state.create_pipeline_layout(vec![], vec![]).unwrap();

    // Create render pass
    let rp = state
        .create_render_pass(1, false, "clear", "store")
        .unwrap();

    // Create framebuffer
    let fb = state.create_framebuffer(rp, vec![], 800, 600, 1).unwrap();

    // Create graphics pipeline
    let pipeline = state.create_graphics_pipeline(layout, 2).unwrap();
    let pipe_info = state.get_pipeline(pipeline).unwrap();
    assert_eq!(pipe_info.bind_point, VkPipelineBindPoint::Graphics);
    assert_eq!(pipe_info.stage_count, 2);
    assert_eq!(pipe_info.layout, layout);

    // Create descriptor resources
    let ds_layout = state.create_descriptor_set_layout(2).unwrap();
    let pool = state.create_descriptor_pool(16).unwrap();
    let sets = state.allocate_descriptor_sets(pool, &[ds_layout]).unwrap();
    assert_eq!(sets.len(), 1);

    // Record commands with pipeline bind
    let cmd_pool = state.create_command_pool(dev, 0).unwrap();
    let cmds = state
        .allocate_command_buffers(cmd_pool, VkCommandBufferLevel::Primary, 1)
        .unwrap();
    let cmd = cmds[0];

    state.begin_command_buffer(cmd, 0).unwrap();
    state
        .cmd_begin_render_pass(
            cmd,
            rp,
            fb,
            vec![casa1::vkgl::ClearValue {
                color: [0.0, 0.0, 0.0, 1.0],
            }],
        )
        .unwrap();
    state.cmd_bind_pipeline(cmd, pipeline).unwrap();
    state
        .cmd_bind_descriptor_sets(cmd, layout, sets.clone())
        .unwrap();
    state.cmd_end_render_pass(cmd).unwrap();
    state.end_command_buffer(cmd).unwrap();

    let cmd_info = state.get_command_buffer(cmd).unwrap();
    assert_eq!(cmd_info.state, CommandBufferState::Executable);
    assert_eq!(cmd_info.recorded_commands.len(), 4); // begin rp + bind pipeline + bind sets + end rp
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_06 — Compute pipeline creation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_06_compute_pipeline_creation() {
    let (mut state, _, _, dev) = bootstrap_device();

    // Create pipeline layout
    let layout = state.create_pipeline_layout(vec![], vec![]).unwrap();

    // Create compute pipeline
    let pipeline = state.create_compute_pipeline(layout).unwrap();
    let pipe_info = state.get_pipeline(pipeline).unwrap();
    assert_eq!(pipe_info.bind_point, VkPipelineBindPoint::Compute);
    assert_eq!(pipe_info.stage_count, 1);
    assert_eq!(pipe_info.layout, layout);

    // Record compute dispatch
    let pool = state.create_command_pool(dev, 0).unwrap();
    let cmds = state
        .allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1)
        .unwrap();
    let cmd = cmds[0];

    state.begin_command_buffer(cmd, 0).unwrap();
    state.cmd_bind_pipeline(cmd, pipeline).unwrap();
    state.cmd_dispatch(cmd, 4, 4, 1).unwrap();
    state.end_command_buffer(cmd).unwrap();

    let cmd_info = state.get_command_buffer(cmd).unwrap();
    assert_eq!(cmd_info.recorded_commands.len(), 2);
    match &cmd_info.recorded_commands[1] {
        RecordedCommand::Dispatch {
            group_count_x,
            group_count_y,
            group_count_z,
        } => {
            assert_eq!(*group_count_x, 4);
            assert_eq!(*group_count_y, 4);
            assert_eq!(*group_count_z, 1);
        }
        _ => panic!("expected Dispatch command"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_07 — Draw command recording
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_07_draw_command_recording() {
    let (mut state, _, _, dev) = bootstrap_device();

    // Create resources
    let buf = state.create_buffer(dev, 1024, 0).unwrap();
    let idx_buf = state.create_buffer(dev, 512, 0).unwrap();
    let layout = state.create_pipeline_layout(vec![], vec![]).unwrap();
    let pipeline = state.create_graphics_pipeline(layout, 2).unwrap();

    let pool = state.create_command_pool(dev, 0).unwrap();
    let cmds = state
        .allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1)
        .unwrap();
    let cmd = cmds[0];

    state.begin_command_buffer(cmd, 0).unwrap();

    // Bind pipeline
    state.cmd_bind_pipeline(cmd, pipeline).unwrap();

    // Bind vertex buffers
    state
        .cmd_bind_vertex_buffers(cmd, vec![(0, buf, 0)])
        .unwrap();

    // Bind index buffer
    state
        .cmd_bind_index_buffer(cmd, idx_buf, 0, VkIndexType::Uint16)
        .unwrap();

    // Draw (non-indexed)
    state.cmd_draw(cmd, 36, 1, 0, 0).unwrap();

    // Draw indexed
    state.cmd_draw_indexed(cmd, 36, 1, 0, 0, 0).unwrap();

    state.end_command_buffer(cmd).unwrap();

    let cmd_info = state.get_command_buffer(cmd).unwrap();
    assert_eq!(cmd_info.state, CommandBufferState::Executable);
    assert_eq!(cmd_info.recorded_commands.len(), 5);

    // Verify draw command
    match &cmd_info.recorded_commands[3] {
        RecordedCommand::Draw {
            vertex_count,
            instance_count,
            first_vertex,
            first_instance,
        } => {
            assert_eq!(*vertex_count, 36);
            assert_eq!(*instance_count, 1);
            assert_eq!(*first_vertex, 0);
            assert_eq!(*first_instance, 0);
        }
        _ => panic!("expected Draw command at index 3"),
    }

    // Verify draw indexed command
    match &cmd_info.recorded_commands[4] {
        RecordedCommand::DrawIndexed {
            index_count,
            instance_count,
            first_index,
            vertex_offset,
            first_instance,
        } => {
            assert_eq!(*index_count, 36);
            assert_eq!(*instance_count, 1);
            assert_eq!(*first_index, 0);
            assert_eq!(*vertex_offset, 0);
            assert_eq!(*first_instance, 0);
        }
        _ => panic!("expected DrawIndexed command at index 4"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_08 — Extension registry and validation layer support
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_08_extension_registry_and_validation_layers() {
    let registry = VkExtensionRegistry::new();

    // Check supported instance extensions
    assert!(registry.is_instance_extension_supported("VK_KHR_surface"));
    assert!(registry.is_instance_extension_supported("VK_EXT_metal_surface"));
    assert!(!registry.is_instance_extension_supported("VK_KHR_nonexistent"));

    // Check supported device extensions
    assert!(registry.is_device_extension_supported("VK_KHR_swapchain"));
    assert!(registry.is_device_extension_supported("VK_KHR_maintenance1"));
    assert!(registry.is_device_extension_supported("VK_KHR_maintenance2"));
    assert!(registry.is_device_extension_supported("VK_KHR_maintenance3"));
    assert!(registry.is_device_extension_supported("VK_KHR_shader_draw_parameters"));
    assert!(!registry.is_device_extension_supported("VK_KHR_ray_tracing"));

    // Check validation layers
    assert!(registry.is_layer_supported("VK_LAYER_KHRONOS_validation"));
    assert!(!registry.is_layer_supported("VK_LAYER_NONEXISTENT"));

    // Validate extensions
    let valid_exts = vec!["VK_KHR_surface".to_string()];
    let _result = registry.validate_instance_extensions(&valid_exts);
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");

    let invalid_exts = vec!["VK_KHR_nonexistent".to_string()];
    let _result = registry.validate_instance_extensions(&invalid_exts);
    assert!(_result.is_err(), "expected Err, got {_result:?}");

    // Validate layers
    let valid_layers = vec!["VK_LAYER_KHRONOS_validation".to_string()];
    let _result = registry.validate_layers(&valid_layers);
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");

    let invalid_layers = vec!["VK_LAYER_NONEXISTENT".to_string()];
    let _result = registry.validate_layers(&invalid_layers);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_09 — MoltenVK search paths
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_09_moltenvk_search_paths() {
    let static_paths = moltenvk_search_paths();
    assert!(!static_paths.is_empty());
    assert!(
        static_paths
            .iter()
            .any(|p| p.to_string_lossy().contains("homebrew"))
    );
    assert!(
        static_paths
            .iter()
            .any(|p| p.to_string_lossy().contains("usr/local"))
    );
    // Phase 2.5: bundled paths
    assert!(
        static_paths
            .iter()
            .any(|p| p.to_string_lossy().contains("MoltenVK"))
    );

    let expanded = moltenvk_expanded_search_paths();
    assert!(expanded.len() > static_paths.len());
    // Should include ~/MoltenVK/ paths
    assert!(
        expanded
            .iter()
            .any(|p| p.to_string_lossy().contains("MoltenVK"))
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_10 — Thread-safe Vulkan state
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_10_thread_safe_vulkan_state() {
    let ts_state = ThreadSafeVulkanState::new();
    assert_eq!(ts_state.instance_count(), 0);

    // Create instance
    let inst = ts_state.create_instance("test", "test", &[], &[]).unwrap();
    assert_ne!(inst, 0);
    assert_eq!(ts_state.instance_count(), 1);

    // Enumerate and create device
    let phys_devs = ts_state.enumerate_physical_devices(inst).unwrap();
    let dev = ts_state
        .create_device(phys_devs[0], &[], &[(0, 1)])
        .unwrap();
    assert_eq!(ts_state.device_count(), 1);

    // Create buffer
    let buf = ts_state.create_buffer(dev, 2048, 0).unwrap();
    assert_ne!(buf, 0);

    // Create image
    let img = ts_state
        .create_image(
            dev,
            VkFormat::B8G8R8A8Unorm,
            (256, 256, 1),
            1,
            1,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
        )
        .unwrap();
    assert_ne!(img, 0);

    // Create pipeline layout and pipeline
    let layout = ts_state
        .create_shader_module(dev, &minimal_spirv())
        .unwrap();
    assert_ne!(layout, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_11 — Queue submit and synchronization
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_11_queue_submit_and_synchronization() {
    let (mut state, _, _, dev) = bootstrap_device();

    // Create synchronization objects
    let fence = state.create_fence(dev, false).unwrap();
    let sem1 = state.create_semaphore(dev).unwrap();
    let sem2 = state.create_semaphore(dev).unwrap();

    // Create command buffer with draw
    let pool = state.create_command_pool(dev, 0).unwrap();
    let cmds = state
        .allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1)
        .unwrap();
    let cmd = cmds[0];
    state.begin_command_buffer(cmd, 0).unwrap();
    state.cmd_draw(cmd, 3, 1, 0, 0).unwrap();
    state.end_command_buffer(cmd).unwrap();

    // Get queue
    let queue = state.get_device_queue(dev, 0, 0).unwrap();

    // Submit with wait/signal semaphores and fence
    let submit = VkSubmitInfo {
        wait_semaphores: vec![sem1],
        command_buffers: vec![cmd],
        signal_semaphores: vec![sem2],
    };
    state.queue_submit(queue, &[submit], Some(fence)).unwrap();

    // Verify command buffer transitioned
    let cmd_info = state.get_command_buffer(cmd).unwrap();
    assert_eq!(cmd_info.state, CommandBufferState::Complete);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_12 — SPIR-V shader module compilation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_12_spirv_shader_module_compilation() {
    let (mut state, _, _, dev) = bootstrap_device();

    let spirv = minimal_spirv();
    let module = state.create_shader_module(dev, &spirv).unwrap();
    let info = state.get_shader_module(module).unwrap();

    // Verify MSL was generated
    assert!(info.msl_source.is_some());
    let msl = info.msl_source.as_ref().unwrap();
    assert!(msl.contains("metal_stdlib"));
    assert!(msl.contains("vertex"));
    assert!(msl.contains("main"));

    // Verify entry points
    assert!(info.entry_points.contains(&"main".to_string()));
    assert_eq!(info.stage, casa1::vkgl::VkShaderStageFlagBits::Vertex);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_13 — Pipeline barrier and image layout transition
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_13_pipeline_barrier_and_layout_transition() {
    let (mut state, _, _, dev) = bootstrap_device();

    let img = state
        .create_image(
            dev,
            VkFormat::B8G8R8A8Unorm,
            (256, 256, 1),
            1,
            1,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
        )
        .unwrap();

    let pool = state.create_command_pool(dev, 0).unwrap();
    let cmds = state
        .allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1)
        .unwrap();
    let cmd = cmds[0];

    state.begin_command_buffer(cmd, 0).unwrap();
    state
        .cmd_pipeline_barrier(
            cmd,
            VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
            VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
            false,
            vec![],
            vec![],
            vec![VkImageMemoryBarrier {
                src_access_mask: 0,
                dst_access_mask: VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
                old_layout: VkImageLayout::Undefined,
                new_layout: VkImageLayout::ColorAttachmentOptimal,
                src_queue_family_index: 0,
                dst_queue_family_index: 0,
                image: img,
                subresource_range: ImageSubresourceRange {
                    aspect_mask: 1,
                    base_mip_level: 0,
                    level_count: 1,
                    base_array_layer: 0,
                    layer_count: 1,
                },
            }],
        )
        .unwrap();
    state.end_command_buffer(cmd).unwrap();

    // Verify image layout was transitioned
    let img_info = state.get_image(img).unwrap();
    assert_eq!(img_info.layout, VkImageLayout::ColorAttachmentOptimal);
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_14 — Vulkan loader info
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_14_vulkan_loader_info() {
    let loader = load_vulkan_loader(true).unwrap();
    assert!(loader.supported);
    assert_eq!(loader.backend, casa1::vkgl::GraphicsBackend::VulkanOnMetal);
    assert!(!loader.api_version.is_empty());
    assert!(!loader.instance_extensions.is_empty());
    assert!(!loader.device_extensions.is_empty());
    assert!(!loader.physical_device_name.is_empty());

    // Unsupported loader
    let err = load_vulkan_loader(false).unwrap_err();
    assert!(err.to_string().contains("vulkan-1.dll"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_15 — Supported KHR extensions and validation layers constants
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_15_khr_extensions_and_validation_layers_constants() {
    // Verify all required extensions are in the supported list
    let required = [
        "VK_KHR_swapchain",
        "VK_KHR_maintenance1",
        "VK_KHR_maintenance2",
        "VK_KHR_maintenance3",
        "VK_KHR_shader_draw_parameters",
    ];
    for ext in &required {
        assert!(
            SUPPORTED_VK_KHR_EXTENSIONS.contains(ext),
            "missing extension: {}",
            ext
        );
    }

    // Verify validation layers
    assert!(KNOWN_VALIDATION_LAYERS.contains(&"VK_LAYER_KHRONOS_validation"));
    assert!(KNOWN_VALIDATION_LAYERS.contains(&"VK_LAYER_LUNARG_standard_validation"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_16 — Stale / unknown handles are not found
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_16_stale_unknown_handle_rejection() {
    let (mut state, _inst, _phys, dev) = bootstrap_device();

    // Create a buffer — handle should be findable
    let buf = state.create_buffer(dev, 64, 0).unwrap();
    assert!(state.get_buffer(buf).is_some());

    // Bogus handles should return None
    assert!(state.get_buffer(99999).is_none());
    assert!(state.get_image(99999).is_none());
    assert!(state.get_pipeline(99999).is_none());

    // Create an image — handle should be findable
    let img = state
        .create_image(dev, VkFormat::R8G8B8A8Unorm, (16, 16, 1), 1, 1, 0)
        .unwrap();
    assert!(state.get_image(img).is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_17 — Wrong-type handle rejection
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_17_wrong_type_handle_rejection() {
    let (mut state, _inst, _phys, dev) = bootstrap_device();

    // Create a buffer
    let buf = state.create_buffer(dev, 128, 0).unwrap();

    // Buffer handle should NOT be found in image / pipeline tables
    assert!(state.get_buffer(buf).is_some());
    assert!(state.get_image(buf).is_none());
    assert!(state.get_pipeline(buf).is_none());

    // Create an image
    let img = state
        .create_image(dev, VkFormat::B8G8R8A8Unorm, (32, 32, 1), 1, 1, 0)
        .unwrap();

    // Image handle should NOT be found in buffer / pipeline tables
    assert!(state.get_image(img).is_some());
    assert!(state.get_buffer(img).is_none());
    assert!(state.get_pipeline(img).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_18 — State updates happen only after validation succeeds
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_18_state_updates_after_validation() {
    let mut state = VulkanState::new();
    assert_eq!(state.device_count(), 0);

    // create_device with a bogus physical device handle should fail
    let result = state.create_device(99999, &[], &[(0, 1)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    // No device should have been added
    assert_eq!(state.device_count(), 0);

    // create_shader_module with a valid device but empty SPIR-V should fail
    let (mut state2, _inst, _phys, dev) = bootstrap_device();
    // Device count should be 1 after bootstrap
    assert_eq!(state2.device_count(), 1);

    // Empty SPIR-V (<5 words) must fail
    let empty: Vec<u32> = vec![];
    let result = state2.create_shader_module(dev, &empty);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // SPIR-V with bad magic must fail
    let bad_magic = vec![0xDEADBEEF, 0x00010000, 0x00000000, 0x00000007, 0x00000000];
    let result = state2.create_shader_module(dev, &bad_magic);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Valid minimal SPIR-V must succeed
    let spirv = minimal_spirv();
    let result = state2.create_shader_module(dev, &spirv);
    assert!(result.is_ok(), "expected Ok, got {result:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_19 — Malformed SPIR-V is rejected
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_19_malformed_spirv_rejected() {
    let (mut state, _inst, _phys, dev) = bootstrap_device();

    // SPIR-V with valid header but zero instructions (header only)
    let header_only = vec![0x07230203, 0x00010000, 0x00000000, 0x00000001, 0x00000000];
    let result = state.create_shader_module(dev, &header_only);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // SPIR-V with truncated instruction (partial word)
    let truncated = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000007, 0x00000000, 0x00020011,
    ];
    let result = state.create_shader_module(dev, &truncated);
    assert!(result.is_err(), "expected Err, got {result:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_20 — SPIR-V zero word count / too-short modules are rejected
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn t31_20_spirv_zero_word_count_rejected() {
    let (mut state, _inst, _phys, dev) = bootstrap_device();

    // Empty slice — less than 5 words
    let result = state.create_shader_module(dev, &[]);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // 4 words — just below threshold
    let four_words = vec![0x07230203, 0x00010000, 0x00000000, 0x00000000];
    let result = state.create_shader_module(dev, &four_words);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // 1 word — clearly invalid
    let one_word = vec![0x07230203];
    let result = state.create_shader_module(dev, &one_word);
    assert!(result.is_err(), "expected Err, got {result:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: minimal SPIR-V vertex shader
// ═══════════════════════════════════════════════════════════════════════════════

fn minimal_spirv() -> Vec<u32> {
    vec![
        0x07230203, // magic
        0x00010000, // version 1.0
        0x00000000, // generator
        0x00000007, // bound
        0x00000000, // schema
        0x00020011, 0x00000001, // OpCapability Shader
        0x0003000E, 0x00000000, 0x00000001, // OpMemoryModel
        0x0005000F, 0x00000000, 0x00000005, 0x6E69616D,
        0x00000000, // OpEntryPoint Vertex %main "main"
        0x00040005, 0x00000005, 0x6E69616D, 0x00000000, // OpName %main "main"
        0x00020013, 0x00000002, // OpTypeVoid %void
        0x00030021, 0x00000003, 0x00000002, // OpTypeFunction %fn %void
        0x00050036, 0x00000002, 0x00000000, 0x00000003, 0x00000005, // %main = OpFunction
        0x000200F8, 0x00000006, // %lbl = OpLabel
        0x000100FD, // OpReturn
        0x00010038, // OpFunctionEnd
    ]
}
