#![allow(dead_code, unused_imports)]
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
    VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT, VkExtensionRegistry, VkFormat, VkImageLayout, VulkanState,
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

// ═══════════════════════════════════════════════════════════════════════════════
// t31_06 — Compute pipeline creation
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t31_07 — Draw command recording
// ═══════════════════════════════════════════════════════════════════════════════

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
    // Documented contract: the expanded list must contain every static search
    // path (it adds HOME- and executable-relative paths on top of them). The
    // exact extra count is intentionally not asserted — it depends on the
    // environment (e.g. whether $HOME is set).
    for static_path in &static_paths {
        assert!(
            expanded.iter().any(|p| p == static_path),
            "expanded search paths must include static path {}",
            static_path.display()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// t31_10 — Thread-safe Vulkan state
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t31_11 — Queue submit and synchronization
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t31_12 — SPIR-V shader module compilation
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// t31_13 — Pipeline barrier and image layout transition
// ═══════════════════════════════════════════════════════════════════════════════

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

// Every create_device validation failure must leave the state untouched:
// (a) unknown physical device, (b) unknown queue family, (c) queue count
// exceeding the family capacity, (d) unsupported extensions, (e) duplicate
// family declarations, (f) zero queue counts.
#[test]
fn t31_18_state_updates_after_validation() {
    let mut state = VulkanState::new();
    assert_eq!(state.device_count(), 0);

    // (a) create_device with a bogus physical device handle should fail
    let result = state.create_device(99999, &[], &[(0, 1)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    // No device should have been added
    assert_eq!(state.device_count(), 0);

    let inst = state.create_instance("test", "test", &[], &[]).unwrap();
    let phys = state.enumerate_physical_devices(inst).unwrap()[0];

    // (b) unknown queue family must fail without mutating state
    let result = state.create_device(phys, &[], &[(99, 1)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    assert_eq!(state.device_count(), 0);

    // (c) queue count beyond the family capacity must fail
    let result = state.create_device(phys, &[], &[(0, 17)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    assert_eq!(state.device_count(), 0);

    // (d) unsupported device extensions must fail; supported ones must pass
    let result = state.create_device(phys, &["VK_KHR_nonexistent_ext".to_string()], &[(0, 1)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    assert_eq!(state.device_count(), 0);
    let _dev = state
        .create_device(phys, &["VK_KHR_swapchain".to_string()], &[(0, 1)])
        .expect("supported extension must be accepted");
    assert_eq!(state.device_count(), 1);

    // (e) duplicate family declarations must fail
    let result = state.create_device(phys, &[], &[(0, 1), (0, 1)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    assert_eq!(state.device_count(), 1);

    // (f) zero queue counts are forbidden by the Vulkan contract
    let result = state.create_device(phys, &[], &[(0, 0)]);
    assert!(result.is_err(), "expected Err, got {result:?}");
    assert_eq!(state.device_count(), 1);

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

// Every malformed SPIR-V module below must be rejected by
// `create_shader_module` (header-only, truncated streams, zero word counts,
// oversized word counts, truncated OpEntryPoint, zero bound, invalid result
// IDs, unterminated functions, invalid decoration targets, invalid storage
// classes, invalid execution models, duplicate result IDs). A rejected module
// must never become a shader module.
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

    // Zero word count
    let zero_wc = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000001, 0x00000000, 0x00000000,
    ];
    let result = state.create_shader_module(dev, &zero_wc);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Oversized word count (claims 65535 words with one word present)
    let oversized = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000001, 0x00000000, 0xFFFF0000,
    ];
    let result = state.create_shader_module(dev, &oversized);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Truncated OpEntryPoint: missing the (>=1 word) name operand
    let truncated_entry = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000006, 0x00000000, 0x00020011, 0x00000001,
        0x0003000F, 0x00000000, 0x00000005,
    ];
    let result = state.create_shader_module(dev, &truncated_entry);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Invalid bound (zero): no result ID may be below it
    let zero_bound = vec![0x07230203, 0x00010000, 0x00000000, 0x00000000, 0x00000000];
    let result = state.create_shader_module(dev, &zero_bound);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Invalid result ID: OpTypeVoid declaring ID 7 with bound 7 (ID >= bound)
    let invalid_result_id = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000007, 0x00000000, 0x00020013, 0x00000007,
    ];
    let result = state.create_shader_module(dev, &invalid_result_id);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Unterminated function: minimal module without OpFunctionEnd
    let mut unterminated = minimal_spirv();
    unterminated.pop();
    let result = state.create_shader_module(dev, &unterminated);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Invalid decoration target: OpDecorate targeting ID 99 with bound 7
    let invalid_decoration = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000007, 0x00000000, 0x00020011, 0x00000001,
        0x0003000E, 0x00000000, 0x00000001, 0x00030047, 0x00000063, 0x00000002,
    ];
    let result = state.create_shader_module(dev, &invalid_decoration);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Invalid storage class: OpVariable with storage class 99
    let invalid_storage = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000008, 0x00000000, 0x00020011, 0x00000001,
        0x0003000E, 0x00000000, 0x00000001, 0x00020013, 0x00000002, 0x0004003B, 0x00000002,
        0x00000003, 0x00000063,
    ];
    let result = state.create_shader_module(dev, &invalid_storage);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Invalid execution model: OpEntryPoint with model 99
    let invalid_model = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000006, 0x00000000, 0x00020011, 0x00000001,
        0x0003000E, 0x00000000, 0x00000001, 0x0004000F, 0x00000063, 0x00000005, 0x6E69616D,
    ];
    let result = state.create_shader_module(dev, &invalid_model);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // Duplicate result IDs: two OpTypeVoid both defining ID 2
    let duplicate_ids = vec![
        0x07230203, 0x00010000, 0x00000000, 0x00000004, 0x00000000, 0x00020013, 0x00000002,
        0x00020013, 0x00000002,
    ];
    let result = state.create_shader_module(dev, &duplicate_ids);
    assert!(result.is_err(), "expected Err, got {result:?}");

    // A rejected module must not have been registered as a shader module
    assert_eq!(state.shader_module_count(), 0);

    // And a valid module still succeeds
    let result = state.create_shader_module(dev, &minimal_spirv());
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert_eq!(state.shader_module_count(), 1);
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
        // %main = OpFunction %void None %fn
        0x00050036, 0x00000002, 0x00000005, 0x00000000, 0x00000003, 0x000200F8,
        0x00000006, // %lbl = OpLabel
        0x000100FD, // OpReturn
        0x00010038, // OpFunctionEnd
    ]
}
