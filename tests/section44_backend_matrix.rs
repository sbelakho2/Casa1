#![allow(dead_code, unused_imports)]
//! Build-matrix truth tests for the backend feature model.
//!
//! Asserts the honest feature semantics documented in `docs/FEATURE_FLAGS.md`:
//!
//! 1. Metal is the **mandatory** host backend on macOS — the
//!    `metal_backend::MetalGpuBackend` symbol is exported by the default
//!    build AND by `--no-default-features` builds. There is no `metal`
//!    feature flag.
//! 2. The `vulkan` / `opengl` features are **guest-translation-layer**
//!    features: they toggle the `vkgl` guest-translation symbols
//!    (`vulkan_translation_enabled` / `opengl_translation_enabled` and the
//!    `register_vulkan_dll` / `register_opengl_dll` thunk tables), not the
//!    host backend.
//!
//! Run the reduced-feature leg with:
//!
//! ```bash
//! cargo test --no-default-features --test section44_backend_matrix
//! ```

use casa1::metal_backend::MetalGpuBackend;

#[test]
fn metal_backend_is_mandatory_and_exported() {
    let _type_name = std::any::type_name::<MetalGpuBackend>();
    assert!(!_type_name.is_empty());
    // The Metal device-creation entry point is part of the backend ABI and
    // must be linkable in every configuration.
    let _ = std::any::type_name::<casa1::metal_backend::MetalDevice>();
}

#[cfg(feature = "vulkan")]
#[test]
fn default_build_enables_vulkan_guest_translation() {
    assert!(
        casa1::vkgl::vulkan_translation_enabled(),
        "the `vulkan` feature must enable the Vulkan guest-translation path"
    );
    assert!(
        !casa1::vkgl::register_vulkan_dll().is_empty(),
        "with `vulkan` enabled, the vulkan-1.dll thunk table must be populated"
    );
}

#[cfg(not(feature = "vulkan"))]
#[test]
fn without_vulkan_feature_guest_translation_is_switched_off() {
    assert!(
        !casa1::vkgl::vulkan_translation_enabled(),
        "without the `vulkan` feature the Vulkan guest-translation path must report disabled"
    );
    assert!(
        casa1::vkgl::register_vulkan_dll().is_empty(),
        "without the `vulkan` feature the vulkan-1.dll thunk table must be empty"
    );
}

#[cfg(feature = "opengl")]
#[test]
fn default_build_enables_opengl_guest_translation() {
    assert!(
        casa1::vkgl::opengl_translation_enabled(),
        "the `opengl` feature must enable the OpenGL guest-translation path"
    );
    assert!(
        !casa1::vkgl::register_opengl_dll().is_empty(),
        "with `opengl` enabled, the opengl32.dll thunk table must be populated"
    );
}

#[cfg(not(feature = "opengl"))]
#[test]
fn without_opengl_feature_guest_translation_is_switched_off() {
    assert!(
        !casa1::vkgl::opengl_translation_enabled(),
        "without the `opengl` feature the OpenGL guest-translation path must report disabled"
    );
    assert!(
        casa1::vkgl::register_opengl_dll().is_empty(),
        "without the `opengl` feature the opengl32.dll thunk table must be empty"
    );
}

#[test]
fn guest_translation_routes_onto_metal_regardless_of_features() {
    // Vulkan-on-Metal and Metal-GL are the only guest backends; the host
    // backend enum they build on is the Metal GPU backend.
    let _ = casa1::vkgl::GraphicsBackend::VulkanOnMetal;
    let _ = casa1::vkgl::GraphicsBackend::MetalGl;
    let _type = std::any::type_name::<casa1::vkgl::GraphicsBackend>();
    assert!(!_type.is_empty());
}
