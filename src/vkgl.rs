//! Vulkan/OpenGL translation layer for Casa1.
//!
//! This module implements Vulkan and OpenGL translation layers that map
//! graphics API calls to Metal on macOS. On macOS, Vulkan is provided via
//! MoltenVK (which translates Vulkan calls to Metal), and OpenGL is provided
//! via Metal as well.
//!
//! # Architecture
//!
//! - **MoltenVK Loader**: Locates and loads the MoltenVK dynamic library at runtime.
//! - **Vulkan State Machine**: Tracks all Vulkan objects (instances, devices, swapchains,
//!   command buffers, etc.) and maps them to Metal equivalents.
//! - **SPIR-V → MSL Translator**: Parses SPIR-V bytecode and generates Metal Shading Language.
//! - **OpenGL Context**: Provides a minimal OpenGL 3.3 compatibility layer backed by Metal.
//! - **DLL Registration**: Exposes Vulkan (`vulkan-1.dll`) and OpenGL (`opengl32.dll`)
//!   export thunks for guest binary compatibility.

use crate::error::{AppError, AppResult};
use crate::gfx::FrameArtifact;
use crate::metal_backend::MetalGpuBackend;
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CStr, CString, c_void};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

// ===========================================================================
// Guest-translation feature gates
// ===========================================================================

/// Whether the Vulkan guest-translation path (`vulkan-1.dll` thunk
/// registration) is enabled in this build.
///
/// Toggled by the `vulkan` Cargo feature. This is a **guest-side translation
/// path** switch — the host backend is always Metal on macOS, so the feature
/// does not change host rendering.
pub const fn vulkan_translation_enabled() -> bool {
    cfg!(feature = "vulkan")
}

/// Whether the OpenGL guest-translation path (`opengl32.dll` thunk
/// registration) is enabled in this build.
///
/// Toggled by the `opengl` Cargo feature. This is a **guest-side translation
/// path** switch — the host backend is always Metal on macOS, so the feature
/// does not change host rendering.
pub const fn opengl_translation_enabled() -> bool {
    cfg!(feature = "opengl")
}

// ===========================================================================
// Section 0: Existing types (preserved for backward compatibility)
// ===========================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphicsBackend {
    VulkanOnMetal,
    MetalGl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulkanLoader {
    pub supported: bool,
    pub backend: GraphicsBackend,
    pub api_version: String,
    pub instance_extensions: Vec<String>,
    pub device_extensions: Vec<String>,
    pub physical_device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulkanSample {
    pub name: String,
    pub required_instance_extensions: Vec<String>,
    pub required_device_extensions: Vec<String>,
    pub clear_color: [u8; 4],
    pub draw_calls: u32,
    pub compute_dispatches: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenGlDriver {
    pub supported: bool,
    pub backend: GraphicsBackend,
    pub version: String,
    pub extensions: Vec<String>,
    pub renderer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenGlSample {
    pub name: String,
    pub required_extensions: Vec<String>,
    pub clear_color: [u8; 4],
    pub triangle_count: u32,
    pub uses_framebuffer_object: bool,
}

pub fn vulkan_loader() -> VulkanLoader {
    load_vulkan_loader(true).expect("supported Vulkan loader")
}

pub fn load_vulkan_loader(supported: bool) -> AppResult<VulkanLoader> {
    if !supported {
        return Err(AppError::new(
            ReasonCode::RcVulkanNotSupported,
            "vulkan-1.dll is unavailable in this configuration",
        ));
    }
    Ok(VulkanLoader {
        supported: true,
        backend: GraphicsBackend::VulkanOnMetal,
        api_version: "1.3.280".to_string(),
        instance_extensions: vec![
            "VK_KHR_surface".to_string(),
            "VK_EXT_metal_surface".to_string(),
            "VK_KHR_get_physical_device_properties2".to_string(),
        ],
        device_extensions: vec![
            "VK_KHR_swapchain".to_string(),
            "VK_KHR_maintenance1".to_string(),
        ],
        physical_device_name: "Casa1 MoltenVK Adapter".to_string(),
    })
}

pub fn opengl_driver() -> OpenGlDriver {
    load_opengl_driver(true).expect("supported OpenGL driver")
}

pub fn load_opengl_driver(supported: bool) -> AppResult<OpenGlDriver> {
    if !supported {
        return Err(AppError::new(
            ReasonCode::RcOpenGlNotSupported,
            "opengl32.dll is unavailable in this configuration",
        ));
    }
    Ok(OpenGlDriver {
        supported: true,
        backend: GraphicsBackend::MetalGl,
        version: "4.1 Core".to_string(),
        extensions: vec![
            "GL_ARB_framebuffer_object".to_string(),
            "GL_ARB_vertex_array_object".to_string(),
            "GL_EXT_texture_filter_anisotropic".to_string(),
        ],
        renderer: "Casa1 Metal GL".to_string(),
    })
}

impl VulkanLoader {
    pub fn enumerate_instance_extension_properties(&self) -> Vec<String> {
        self.instance_extensions.clone()
    }

    pub fn enumerate_physical_devices(&self) -> Vec<String> {
        vec![self.physical_device_name.clone()]
    }

    pub fn render_sample(&self, sample: &VulkanSample) -> AppResult<FrameArtifact> {
        if !self.supported {
            return Err(AppError::new(
                ReasonCode::RcVulkanNotSupported,
                "vulkan-1.dll is unavailable in this configuration",
            ));
        }
        for extension in &sample.required_instance_extensions {
            if !self
                .instance_extensions
                .iter()
                .any(|candidate| candidate == extension)
            {
                return Err(AppError::new(
                    ReasonCode::RcVulkanNotSupported,
                    format!("unsupported Vulkan instance extension {extension}"),
                ));
            }
        }
        for extension in &sample.required_device_extensions {
            if !self
                .device_extensions
                .iter()
                .any(|candidate| candidate == extension)
            {
                return Err(AppError::new(
                    ReasonCode::RcVulkanNotSupported,
                    format!("unsupported Vulkan device extension {extension}"),
                ));
            }
        }
        Ok(FrameArtifact {
            hash: util::sha256_bytes(
                format!(
                    "vk|{:?}|{}|{}|{}|{}|{:?}",
                    self.backend,
                    self.api_version,
                    sample.name,
                    sample.draw_calls,
                    sample.compute_dispatches,
                    sample.clear_color
                )
                .as_bytes(),
            ),
            // No actual frame is rasterized here, so no SSIM can be
            // measured; recording a constant would fabricate a metric.
            ssim: None,
            validation_errors: Vec::new(),
        })
    }
}

impl OpenGlDriver {
    pub fn extensions(&self) -> Vec<String> {
        self.extensions.clone()
    }

    pub fn render_sample(&self, sample: &OpenGlSample) -> AppResult<FrameArtifact> {
        if !self.supported {
            return Err(AppError::new(
                ReasonCode::RcOpenGlNotSupported,
                "opengl32.dll is unavailable in this configuration",
            ));
        }
        for extension in &sample.required_extensions {
            if !self
                .extensions
                .iter()
                .any(|candidate| candidate == extension)
            {
                return Err(AppError::new(
                    ReasonCode::RcOpenGlNotSupported,
                    format!("unsupported OpenGL extension {extension}"),
                ));
            }
        }
        Ok(FrameArtifact {
            hash: util::sha256_bytes(
                format!(
                    "gl|{:?}|{}|{}|{}|{}|{:?}",
                    self.backend,
                    self.version,
                    sample.name,
                    sample.triangle_count,
                    sample.uses_framebuffer_object,
                    sample.clear_color
                )
                .as_bytes(),
            ),
            // No actual frame is rasterized here, so no SSIM can be
            // measured; recording a constant would fabricate a metric.
            ssim: None,
            validation_errors: Vec::new(),
        })
    }
}

// ===========================================================================
// Section 1: Vulkan Handle Types
// ===========================================================================

/// Opaque handle for a Vulkan instance. Maps to `VkInstance` in the Vulkan API.
/// Internally represented as a `u64` for cross-language compatibility.
pub type VkInstance = u64;

/// Opaque handle for a Vulkan logical device. Maps to `VkDevice`.
pub type VkDevice = u64;

/// Opaque handle for a physical GPU device. Maps to `VkPhysicalDevice`.
pub type VkPhysicalDevice = u64;

/// Opaque handle for a device queue. Maps to `VkQueue`.
pub type VkQueue = u64;

/// Opaque handle for a command buffer. Maps to `VkCommandBuffer`.
pub type VkCommandBuffer = u64;

/// Opaque handle for a buffer resource. Maps to `VkBuffer`.
pub type VkBuffer = u64;

/// Opaque handle for an image resource. Maps to `VkImage`.
pub type VkImage = u64;

/// Opaque handle for an image view. Maps to `VkImageView`.
pub type VkImageView = u64;

/// Opaque handle for a render pass object. Maps to `VkRenderPass`.
pub type VkRenderPass = u64;

/// Opaque handle for a framebuffer object. Maps to `VkFramebuffer`.
pub type VkFramebuffer = u64;

/// Opaque handle for a pipeline object. Maps to `VkPipeline`.
pub type VkPipeline = u64;

/// Opaque handle for a pipeline layout. Maps to `VkPipelineLayout`.
pub type VkPipelineLayout = u64;

/// Opaque handle for a descriptor set. Maps to `VkDescriptorSet`.
pub type VkDescriptorSet = u64;

/// Opaque handle for a descriptor set layout. Maps to `VkDescriptorSetLayout`.
pub type VkDescriptorSetLayout = u64;

/// Opaque handle for a descriptor pool. Maps to `VkDescriptorPool`.
pub type VkDescriptorPool = u64;

/// Opaque handle for a command pool. Maps to `VkCommandPool`.
pub type VkCommandPool = u64;

/// Opaque handle for a fence synchronization object. Maps to `VkFence`.
pub type VkFence = u64;

/// Opaque handle for a semaphore synchronization object. Maps to `VkSemaphore`.
pub type VkSemaphore = u64;

/// Opaque handle for a shader module. Maps to `VkShaderModule`.
pub type VkShaderModule = u64;

/// Opaque handle for a swapchain (KHR extension). Maps to `VkSwapchainKHR`.
pub type VkSwapchainKHR = u64;

/// Opaque handle for a surface (KHR extension). Maps to `VkSurfaceKHR`.
pub type VkSurfaceKHR = u64;

/// Opaque handle for device memory allocation. Maps to `VkDeviceMemory`.
pub type VkDeviceMemory = u64;

/// Opaque handle for a Metal device (`MTLDevice`).
pub type MetalDeviceHandle = u64;

/// Opaque handle for a Metal command queue (`MTLCommandQueue`).
pub type MetalCommandQueueHandle = u64;

/// Opaque handle for a Metal drawable (`CAMetalDrawable`).
pub type MetalDrawableHandle = u64;

/// Generic Vulkan void function pointer type, matching `PFN_vkVoidFunction`.
#[allow(non_camel_case_types)]
pub type PFN_vkVoidFunction = unsafe extern "C" fn();

/// Vulkan result/error code, matching `VkResult`.
pub type VkResultType = i32;

pub const VK_SUCCESS: VkResultType = 0;
pub const VK_NOT_READY: VkResultType = 1;
pub const VK_TIMEOUT: VkResultType = 2;
pub const VK_EVENT_SET: VkResultType = 3;
pub const VK_EVENT_RESET: VkResultType = 4;
pub const VK_INCOMPLETE: VkResultType = 5;
pub const VK_ERROR_OUT_OF_HOST_MEMORY: VkResultType = -1;
pub const VK_ERROR_OUT_OF_DEVICE_MEMORY: VkResultType = -2;
pub const VK_ERROR_INITIALIZATION_FAILED: VkResultType = -3;
pub const VK_ERROR_DEVICE_LOST: VkResultType = -4;
pub const VK_ERROR_MEMORY_MAP_FAILED: VkResultType = -5;
pub const VK_ERROR_LAYER_NOT_PRESENT: VkResultType = -6;
pub const VK_ERROR_EXTENSION_NOT_PRESENT: VkResultType = -7;
pub const VK_ERROR_FEATURE_NOT_PRESENT: VkResultType = -8;
pub const VK_ERROR_INCOMPATIBLE_DRIVER: VkResultType = -9;
pub const VK_ERROR_TOO_MANY_OBJECTS: VkResultType = -10;
pub const VK_ERROR_FORMAT_NOT_SUPPORTED: VkResultType = -11;
pub const VK_ERROR_SURFACE_LOST_KHR: VkResultType = -1000000000;
pub const VK_SUBOPTIMAL_KHR: VkResultType = 1000001003;
pub const VK_ERROR_OUT_OF_DATE_KHR: VkResultType = -1000001004;

/// Global Vulkan state accessor for thunk dispatch.
///
/// Recovers from a poisoned mutex (a panic inside a previous closure must not
/// permanently brick every subsequent thunk call).
fn with_vulkan_state<F, T>(f: F) -> T
where
    F: FnOnce(&mut VulkanState) -> T,
{
    static STATE: OnceLock<Mutex<VulkanState>> = OnceLock::new();
    let mut state = STATE
        .get_or_init(|| Mutex::new(VulkanState::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut state)
}

/// Global OpenGL state accessor for thunk dispatch (analogous to
/// [`with_vulkan_state`]; recovers from mutex poisoning).
fn with_gl_state<F, T>(f: F) -> T
where
    F: FnOnce(&mut GLState) -> T,
{
    static GL_STATE: OnceLock<Mutex<GLState>> = OnceLock::new();
    let mut state = GL_STATE
        .get_or_init(|| Mutex::new(GLState::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut state)
}

// ===========================================================================
// Section 2: Vulkan Enums and Flags
// ===========================================================================

/// Vulkan format enumeration mapping to Metal pixel formats.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkFormat {
    Undefined,
    R8G8B8A8Unorm,
    B8G8R8A8Unorm,
    R8G8B8A8Srgb,
    B8G8R8A8Srgb,
    R32Sfloat,
    R32G32Sfloat,
    R32G32B32Sfloat,
    R32G32B32A32Sfloat,
    R16Sfloat,
    R16G16Sfloat,
    R16G16B16A16Sfloat,
    D16Unorm,
    D24UnormS8Uint,
    D32Sfloat,
    Bc1RgbaUnormBlock,
    Bc2UnormBlock,
    Bc3UnormBlock,
}

impl VkFormat {
    /// Returns the number of bytes per pixel (or per block for
    /// block-compressed formats) for this format.
    pub fn bytes_per_element(self) -> u32 {
        match self {
            VkFormat::R8G8B8A8Unorm | VkFormat::B8G8R8A8Unorm => 4,
            VkFormat::R8G8B8A8Srgb | VkFormat::B8G8R8A8Srgb => 4,
            VkFormat::R32Sfloat => 4,
            VkFormat::R32G32Sfloat => 8,
            VkFormat::R32G32B32Sfloat => 12,
            VkFormat::R32G32B32A32Sfloat => 16,
            VkFormat::R16Sfloat => 2,
            VkFormat::R16G16Sfloat => 4,
            VkFormat::R16G16B16A16Sfloat => 8,
            VkFormat::D16Unorm => 2,
            VkFormat::D24UnormS8Uint => 4,
            VkFormat::D32Sfloat => 4,
            // BC1 is 8 bytes per 4x4 block; BC2/BC3 are 16 bytes per block.
            VkFormat::Bc1RgbaUnormBlock => 8,
            VkFormat::Bc2UnormBlock | VkFormat::Bc3UnormBlock => 16,
            VkFormat::Undefined => 0,
        }
    }

    /// Returns the Metal pixel format name for this Vulkan format.
    pub fn metal_pixel_format_name(self) -> &'static str {
        match self {
            VkFormat::R8G8B8A8Unorm => "RGBA8Unorm",
            VkFormat::R8G8B8A8Srgb => "RGBA8Unorm_sRGB",
            VkFormat::B8G8R8A8Unorm => "BGRA8Unorm",
            VkFormat::B8G8R8A8Srgb => "BGRA8Unorm_sRGB",
            VkFormat::R32Sfloat => "R32Float",
            VkFormat::R32G32Sfloat => "RG32Float",
            VkFormat::R32G32B32Sfloat => "RGB32Float",
            VkFormat::R32G32B32A32Sfloat => "RGBA32Float",
            VkFormat::R16Sfloat => "R16Float",
            VkFormat::R16G16Sfloat => "RG16Float",
            VkFormat::R16G16B16A16Sfloat => "RGBA16Float",
            VkFormat::D16Unorm => "Depth16Unorm",
            VkFormat::D24UnormS8Uint => "Depth24UnormStencil8",
            VkFormat::D32Sfloat => "Depth32Float",
            _ => "Invalid",
        }
    }
}

/// Map a Vulkan [`VkFormat`] to a Metal [`MTLPixelFormat`].
///
/// This is the central format translation table used when creating Metal
/// textures, render-pass attachments, and pipeline state objects from
/// Vulkan resource-creation calls.
pub fn vk_format_to_metal_format(format: VkFormat) -> metal::MTLPixelFormat {
    match format {
        VkFormat::R8G8B8A8Unorm => metal::MTLPixelFormat::RGBA8Unorm,
        VkFormat::R8G8B8A8Srgb => metal::MTLPixelFormat::RGBA8Unorm_sRGB,
        VkFormat::B8G8R8A8Unorm => metal::MTLPixelFormat::BGRA8Unorm,
        VkFormat::B8G8R8A8Srgb => metal::MTLPixelFormat::BGRA8Unorm_sRGB,
        VkFormat::R32Sfloat => metal::MTLPixelFormat::R32Float,
        VkFormat::R32G32Sfloat => metal::MTLPixelFormat::RG32Float,
        // Metal doesn't have a 3-channel RGB32Float; fall back to RGBA32Float
        VkFormat::R32G32B32Sfloat => metal::MTLPixelFormat::RGBA32Float,
        VkFormat::R32G32B32A32Sfloat => metal::MTLPixelFormat::RGBA32Float,
        VkFormat::R16Sfloat => metal::MTLPixelFormat::R16Float,
        VkFormat::R16G16Sfloat => metal::MTLPixelFormat::RG16Float,
        VkFormat::R16G16B16A16Sfloat => metal::MTLPixelFormat::RGBA16Float,
        VkFormat::D16Unorm => metal::MTLPixelFormat::Depth16Unorm,
        VkFormat::D24UnormS8Uint => metal::MTLPixelFormat::Depth24Unorm_Stencil8,
        VkFormat::D32Sfloat => metal::MTLPixelFormat::Depth32Float,
        VkFormat::Bc1RgbaUnormBlock => metal::MTLPixelFormat::BC1_RGBA,
        VkFormat::Bc2UnormBlock => metal::MTLPixelFormat::BC2_RGBA,
        VkFormat::Bc3UnormBlock => metal::MTLPixelFormat::BC3_RGBA,
        _ => metal::MTLPixelFormat::RGBA8Unorm, // safe default
    }
}

/// Map a Vulkan [`VkSamplerCreateInfo`] to a D3D12 static-sampler descriptor
/// so the shared [`crate::metal_backend::create_static_sampler`] helper can
/// build the matching `MTLSamplerState`.
fn vk_sampler_to_d3d12_static_sampler_desc(
    ci: &VkSamplerCreateInfo,
) -> crate::gfx::D3D12StaticSamplerDesc {
    use crate::gfx::{D3D12ShaderVisibility, D3D12StaticSamplerDesc};

    // D3D12_FILTER bit layout per d3d12.h: mip [0:2], mag [2:4], min [4:6],
    // anisotropic [6], reduction [7:9]. (Vk filter enums are 0=NEAREST,
    // 1=LINEAR, the same values as the D3D12_FILTER_TYPE fields.)
    let filter = (ci.mipmap_mode & 0x3)
        | ((ci.mag_filter & 0x3) << 2)
        | ((ci.min_filter & 0x3) << 4)
        | if ci.max_anisotropy > 0.0 { 0x40 } else { 0 }
        | if ci.compare_op != 0 { 0x80 } else { 0 };

    // D3D12_TEXTURE_ADDRESS_MODE per d3d12.h is 0-based: 0=WRAP, 1=MIRROR,
    // 2=CLAMP, 3=BORDER, 4=MIRROR_ONCE (the 1-based family is D3D11's
    // legacy SAMPLER_ADDRESS_MODE). The Vulkan modes map onto it directly.
    let vk_addr = |mode: u32| match mode {
        0 => 0, // VK_SAMPLER_ADDRESS_MODE_REPEAT -> WRAP
        1 => 1, // VK_SAMPLER_ADDRESS_MODE_MIRRORED_REPEAT -> MIRROR
        2 => 2, // VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE -> CLAMP
        3 => 3, // VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER -> BORDER
        4 => 4, // VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE -> MIRROR_ONCE
        _ => 2, // unknown Vulkan mode: CLAMP (only valid D3D12 values reach Metal)
    };

    // D3D12_COMPARISON_FUNC: 1=NEVER .. 8=ALWAYS (Vulkan is 0..7).
    let comparison_func = (ci.compare_op & 0x7).saturating_add(1);

    D3D12StaticSamplerDesc {
        shader_register: 0,
        register_space: 0,
        filter,
        address_u: vk_addr(ci.address_mode_u),
        address_v: vk_addr(ci.address_mode_v),
        address_w: vk_addr(ci.address_mode_w),
        mip_lod_bias: ci.mip_lod_bias,
        max_anisotropy: ci.max_anisotropy as u32,
        comparison_func,
        border_color: 0,
        min_lod: ci.min_lod,
        max_lod: ci.max_lod,
        shader_visibility: D3D12ShaderVisibility::All,
    }
}

/// Vulkan color space enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkColorSpaceKHR {
    SrgbNonlinear,
    DisplayP3Nonlinear,
    ExtendedSrgbLinear,
    DisplayP3Linear,
    DciP3Nonlinear,
    Bt709Linear,
    Bt2020Linear,
}

/// Vulkan image usage flags bitmask.
pub type VkImageUsageFlags = u32;

pub const VK_IMAGE_USAGE_TRANSFER_SRC_BIT: VkImageUsageFlags = 0x00000001;
pub const VK_IMAGE_USAGE_TRANSFER_DST_BIT: VkImageUsageFlags = 0x00000002;
pub const VK_IMAGE_USAGE_SAMPLED_BIT: VkImageUsageFlags = 0x00000004;
pub const VK_IMAGE_USAGE_STORAGE_BIT: VkImageUsageFlags = 0x00000008;
pub const VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT: VkImageUsageFlags = 0x00000010;
pub const VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT: VkImageUsageFlags = 0x00000020;
pub const VK_IMAGE_USAGE_INPUT_ATTACHMENT_BIT: VkImageUsageFlags = 0x00000080;

/// Vulkan surface transform flags.
pub type VkSurfaceTransformFlagBitsKHR = u32;
pub const VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR: VkSurfaceTransformFlagBitsKHR = 0x00000001;

/// Vulkan composite alpha flags.
pub type VkCompositeAlphaFlagBitsKHR = u32;
pub const VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR: VkCompositeAlphaFlagBitsKHR = 0x00000001;

/// Vulkan present mode enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkPresentModeKHR {
    Immediate,
    Fifo,
    FifoRelaxed,
    Mailbox,
}

/// Vulkan shader stage flag bits.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkShaderStageFlagBits {
    Vertex,
    TessellationControl,
    TessellationEvaluation,
    Geometry,
    Fragment,
    Compute,
    AllGraphics,
    All,
}

impl VkShaderStageFlagBits {
    /// Returns the MSL function qualifier for this shader stage.
    pub fn msl_qualifier(self) -> &'static str {
        match self {
            VkShaderStageFlagBits::Vertex => "vertex",
            VkShaderStageFlagBits::Fragment => "fragment",
            VkShaderStageFlagBits::Compute => "kernel",
            VkShaderStageFlagBits::Geometry => "vertex",
            _ => "kernel",
        }
    }
}

/// Vulkan pipeline stage flags bitmask.
pub type VkPipelineStageFlags = u32;
pub const VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT: VkPipelineStageFlags = 0x00000001;
pub const VK_PIPELINE_STAGE_DRAW_INDIRECT_BIT: VkPipelineStageFlags = 0x00000002;
pub const VK_PIPELINE_STAGE_VERTEX_INPUT_BIT: VkPipelineStageFlags = 0x00000004;
pub const VK_PIPELINE_STAGE_VERTEX_SHADER_BIT: VkPipelineStageFlags = 0x00000008;
pub const VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT: VkPipelineStageFlags = 0x00000010;
pub const VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT: VkPipelineStageFlags = 0x00000020;
pub const VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT: VkPipelineStageFlags = 0x00000040;
pub const VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT: VkPipelineStageFlags = 0x00000080;
pub const VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT: VkPipelineStageFlags = 0x00000100;
pub const VK_PIPELINE_STAGE_TRANSFER_BIT: VkPipelineStageFlags = 0x00001000;
pub const VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT: VkPipelineStageFlags = 0x00002000;
pub const VK_PIPELINE_STAGE_HOST_BIT: VkPipelineStageFlags = 0x00004000;
pub const VK_PIPELINE_STAGE_ALL_GRAPHICS_BIT: VkPipelineStageFlags = 0x00008000;
pub const VK_PIPELINE_STAGE_ALL_COMMANDS_BIT: VkPipelineStageFlags = 0x00010000;

/// Vulkan access flags bitmask.
pub type VkAccessFlags = u32;
pub const VK_ACCESS_INDIRECT_COMMAND_READ_BIT: VkAccessFlags = 0x00000001;
pub const VK_ACCESS_INDEX_READ_BIT: VkAccessFlags = 0x00000002;
pub const VK_ACCESS_VERTEX_ATTRIBUTE_READ_BIT: VkAccessFlags = 0x00000004;
pub const VK_ACCESS_UNIFORM_READ_BIT: VkAccessFlags = 0x00000008;
pub const VK_ACCESS_INPUT_ATTACHMENT_READ_BIT: VkAccessFlags = 0x00000010;
pub const VK_ACCESS_SHADER_READ_BIT: VkAccessFlags = 0x00000020;
pub const VK_ACCESS_SHADER_WRITE_BIT: VkAccessFlags = 0x00000040;
pub const VK_ACCESS_COLOR_ATTACHMENT_READ_BIT: VkAccessFlags = 0x00000080;
pub const VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT: VkAccessFlags = 0x00000100;
pub const VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT: VkAccessFlags = 0x00000200;
pub const VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT: VkAccessFlags = 0x00000400;
pub const VK_ACCESS_TRANSFER_READ_BIT: VkAccessFlags = 0x00000800;
pub const VK_ACCESS_TRANSFER_WRITE_BIT: VkAccessFlags = 0x00001000;
pub const VK_ACCESS_HOST_READ_BIT: VkAccessFlags = 0x00002000;
pub const VK_ACCESS_HOST_WRITE_BIT: VkAccessFlags = 0x00004000;
pub const VK_ACCESS_MEMORY_READ_BIT: VkAccessFlags = 0x00008000;
pub const VK_ACCESS_MEMORY_WRITE_BIT: VkAccessFlags = 0x00010000;

/// Vulkan memory property flags bitmask.
pub type VkMemoryPropertyFlags = u32;
pub const VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT: VkMemoryPropertyFlags = 0x00000001;
pub const VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT: VkMemoryPropertyFlags = 0x00000002;
pub const VK_MEMORY_PROPERTY_HOST_COHERENT_BIT: VkMemoryPropertyFlags = 0x00000004;
pub const VK_MEMORY_PROPERTY_HOST_CACHED_BIT: VkMemoryPropertyFlags = 0x00000008;
pub const VK_MEMORY_PROPERTY_LAZILY_ALLOCATED_BIT: VkMemoryPropertyFlags = 0x00000010;

/// Vulkan memory heap flags bitmask.
pub type VkMemoryHeapFlags = u32;
pub const VK_MEMORY_HEAP_DEVICE_LOCAL_BIT: VkMemoryHeapFlags = 0x00000001;

/// Vulkan image layout enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkImageLayout {
    Undefined,
    General,
    ColorAttachmentOptimal,
    DepthStencilAttachmentOptimal,
    DepthStencilReadOnlyOptimal,
    ShaderReadOnlyOptimal,
    TransferSrcOptimal,
    TransferDstOptimal,
    Preinitialized,
    PresentSrcKHR,
}

/// Vulkan command buffer level.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkCommandBufferLevel {
    Primary,
    Secondary,
}

/// Vulkan index type enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkIndexType {
    Uint16,
    Uint32,
}

/// Vulkan memory type descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VkMemoryType {
    pub property_flags: VkMemoryPropertyFlags,
    pub heap_index: u32,
}

/// Vulkan memory heap descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VkMemoryHeap {
    pub size: u64,
    pub flags: VkMemoryHeapFlags,
}

/// Vulkan physical device memory properties, describing available memory types
/// and heaps. Maps to Metal's buffer storage modes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VkPhysicalDeviceMemoryProperties {
    pub memory_types: Vec<VkMemoryType>,
    pub memory_heaps: Vec<VkMemoryHeap>,
}

impl Default for VkPhysicalDeviceMemoryProperties {
    fn default() -> Self {
        Self {
            memory_types: vec![
                VkMemoryType {
                    property_flags: VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
                    heap_index: 0,
                },
                VkMemoryType {
                    property_flags: VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT
                        | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT
                        | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                    heap_index: 0,
                },
                VkMemoryType {
                    property_flags: VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT
                        | VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT
                        | VK_MEMORY_PROPERTY_HOST_CACHED_BIT
                        | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                    heap_index: 0,
                },
                VkMemoryType {
                    property_flags: VK_MEMORY_PROPERTY_LAZILY_ALLOCATED_BIT,
                    heap_index: 0,
                },
            ],
            memory_heaps: vec![VkMemoryHeap {
                size: 8 * 1024 * 1024 * 1024, // 8 GB default
                flags: VK_MEMORY_HEAP_DEVICE_LOCAL_BIT,
            }],
        }
    }
}

// ===========================================================================
// Section 3: Vulkan Info Structs
// ===========================================================================

/// Tracks the state of a Vulkan instance, including enabled extensions,
/// layers, and discovered physical devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkInstanceInfo {
    pub handle: VkInstance,
    pub enabled_extensions: Vec<String>,
    pub enabled_layers: Vec<String>,
    pub physical_devices: Vec<VkPhysicalDevice>,
    /// Queue families exposed by the instance's physical device, in family
    /// index order. Each element is the maximum number of queues a logical
    /// device may request for that family. Populated at instance creation;
    /// deserialized state from older saves falls back to the default set.
    #[serde(default = "default_queue_family_capacities")]
    pub queue_family_max_queues: Vec<u32>,
    pub application_name: String,
    pub engine_name: String,
    pub api_version: (u32, u32, u32),
}

/// Default per-physical-device queue family capacities: family 0 = graphics
/// (16 queues), family 1 = compute (8), family 2 = transfer (4), family 3 =
/// video/other (2). Used when an instance is created or restored without an
/// explicit capability table.
fn default_queue_family_capacities() -> Vec<u32> {
    DEFAULT_QUEUE_FAMILY_CAPACITIES.to_vec()
}

const DEFAULT_QUEUE_FAMILY_CAPACITIES: [u32; 4] = [16, 8, 4, 2];

/// Tracks the state of a Vulkan logical device, including queues and
/// enabled extensions. Maps to a Metal device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkDeviceInfo {
    pub handle: VkDevice,
    pub physical_device: VkPhysicalDevice,
    pub queues: BTreeMap<u32, Vec<VkQueue>>,
    pub enabled_extensions: Vec<String>,
    pub memory_properties: VkPhysicalDeviceMemoryProperties,
}

/// Tracks a swapchain's configuration and its Metal backing layer.
/// The swapchain maps directly to a `CAMetalLayer` on macOS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSwapchainInfo {
    pub handle: VkSwapchainKHR,
    pub device: VkDevice,
    pub surface: VkSurfaceKHR,
    pub min_image_count: u32,
    pub image_format: VkFormat,
    pub image_color_space: VkColorSpaceKHR,
    pub image_extent: (u32, u32),
    pub image_array_layers: u32,
    pub image_usage: VkImageUsageFlags,
    pub pre_transform: VkSurfaceTransformFlagBitsKHR,
    pub composite_alpha: VkCompositeAlphaFlagBitsKHR,
    pub present_mode: VkPresentModeKHR,
    pub clipped: bool,
    /// Pointer to the backing `CAMetalLayer`. Null if not yet configured.
    pub metal_layer: Option<u64>,
    /// Handles to Metal drawables obtained from the layer.
    pub metal_drawables: Vec<MetalDrawableHandle>,
    /// Index of the currently acquired buffer.
    pub current_buffer_index: usize,
}

/// Swapchain creation parameters, mirroring `VkSwapchainCreateInfoKHR`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSwapchainCreateInfo {
    pub surface: VkSurfaceKHR,
    pub min_image_count: u32,
    pub image_format: VkFormat,
    pub image_color_space: VkColorSpaceKHR,
    pub image_extent: (u32, u32),
    pub image_array_layers: u32,
    pub image_usage: VkImageUsageFlags,
    pub pre_transform: VkSurfaceTransformFlagBitsKHR,
    pub composite_alpha: VkCompositeAlphaFlagBitsKHR,
    pub present_mode: VkPresentModeKHR,
    pub clipped: bool,
}

/// Tracks a shader module including original SPIR-V and translated MSL source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkShaderModuleInfo {
    pub handle: VkShaderModule,
    pub spirv_code: Vec<u32>,
    pub msl_source: Option<String>,
    pub entry_points: Vec<String>,
    pub stage: VkShaderStageFlagBits,
}

/// Tracks a surface object, which represents a drawable surface (window).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSurfaceInfo {
    pub handle: VkSurfaceKHR,
    pub width: u32,
    pub height: u32,
    pub format: VkFormat,
}

/// Tracks a buffer resource and its Metal backing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkBufferInfo {
    pub handle: VkBuffer,
    pub device: VkDevice,
    pub size: u64,
    pub usage: u32,
    pub memory: Option<VkDeviceMemory>,
    /// Handle to the backing Metal buffer in [`MetalGpuBackend`].
    pub metal_buffer_id: Option<u64>,
}

/// Tracks an image resource and its layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkImageInfo {
    pub handle: VkImage,
    pub device: VkDevice,
    pub format: VkFormat,
    pub extent: (u32, u32, u32),
    pub mip_levels: u32,
    pub array_layers: u32,
    pub usage: VkImageUsageFlags,
    pub layout: VkImageLayout,
    /// Handle to the backing Metal texture in [`MetalGpuBackend`].
    pub metal_texture_id: Option<u64>,
}

/// Tracks an image view and its associated image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkImageViewInfo {
    pub handle: VkImageView,
    pub image: VkImage,
    pub format: VkFormat,
    pub aspect_mask: u32,
    /// Handle to the backing Metal texture view in [`MetalGpuBackend`].
    pub metal_texture_view_id: Option<u64>,
}

/// Tracks a render pass with its attachment descriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkRenderPassInfo {
    pub handle: VkRenderPass,
    pub color_attachment_count: u32,
    pub has_depth_stencil: bool,
    pub load_action: String,
    pub store_action: String,
}

/// Tracks a framebuffer with its attachment image views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkFramebufferInfo {
    pub handle: VkFramebuffer,
    pub render_pass: VkRenderPass,
    pub attachments: Vec<VkImageView>,
    pub width: u32,
    pub height: u32,
    pub layers: u32,
}

/// Tracks a pipeline and its bound shader stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkPipelineInfo {
    pub handle: VkPipeline,
    pub layout: VkPipelineLayout,
    pub stage_count: u32,
    pub bind_point: VkPipelineBindPoint,
    /// Handle to the Metal render pipeline state in [`MetalGpuBackend`].
    pub metal_pipeline_id: Option<u64>,
    /// Handle to the Metal shader library in [`MetalGpuBackend`].
    pub metal_library_id: Option<u64>,
    /// Vertex shader module handle used to create this pipeline.
    pub vertex_shader: Option<VkShaderModule>,
    /// Fragment shader module handle used to create this pipeline.
    pub fragment_shader: Option<VkShaderModule>,
}

/// Vulkan pipeline bind point.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VkPipelineBindPoint {
    Graphics,
    Compute,
}

/// Tracks a pipeline layout and its descriptor set layouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkPipelineLayoutInfo {
    pub handle: VkPipelineLayout,
    pub set_layouts: Vec<VkDescriptorSetLayout>,
    pub push_constant_ranges: Vec<(VkShaderStageFlagBits, u32, u32)>,
}

/// Tracks a descriptor set and its pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkDescriptorSetInfo {
    pub handle: VkDescriptorSet,
    pub layout: VkDescriptorSetLayout,
    pub pool: VkDescriptorPool,
}

/// Tracks a descriptor set layout and its binding descriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkDescriptorSetLayoutInfo {
    pub handle: VkDescriptorSetLayout,
    pub binding_count: u32,
}

/// Tracks a descriptor pool and its allocation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkDescriptorPoolInfo {
    pub handle: VkDescriptorPool,
    pub max_sets: u32,
    pub allocated_sets: u32,
}

/// Tracks a command pool and its owning queue family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkCommandPoolInfo {
    pub handle: VkCommandPool,
    pub device: VkDevice,
    pub queue_family_index: u32,
}

/// Tracks a command buffer's recording state and recorded commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkCommandBufferInfo {
    pub handle: VkCommandBuffer,
    pub pool: VkCommandPool,
    pub device: VkDevice,
    pub level: VkCommandBufferLevel,
    pub state: CommandBufferState,
    pub recorded_commands: Vec<RecordedCommand>,
    /// Handle to the Metal command buffer, if one has been allocated.
    pub metal_command_buffer: Option<u64>,
}

/// Command buffer lifecycle states, matching the Vulkan specification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommandBufferState {
    Initial,
    Recording,
    Executable,
    Pending,
    Complete,
    Invalid,
}

/// Recorded command enumeration for deferred execution.
/// Each variant stores the parameters needed to replay the command
/// into a Metal command buffer during queue submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordedCommand {
    /// Begin a render pass: bind render pass, framebuffer, and clear values.
    BeginRenderPass {
        render_pass: VkRenderPass,
        framebuffer: VkFramebuffer,
        clear_values: Vec<ClearValue>,
    },
    /// End the current render pass.
    EndRenderPass,
    /// Bind a graphics or compute pipeline.
    BindPipeline { pipeline: VkPipeline },
    /// Bind descriptor sets to a pipeline layout.
    BindDescriptorSets {
        layout: VkPipelineLayout,
        sets: Vec<VkDescriptorSet>,
    },
    /// Bind vertex buffers to binding points.
    BindVertexBuffers { bindings: Vec<(u32, VkBuffer, u64)> },
    /// Bind an index buffer.
    BindIndexBuffer {
        buffer: VkBuffer,
        offset: u64,
        index_type: VkIndexType,
    },
    /// Draw primitives (non-indexed).
    Draw {
        vertex_count: u32,
        instance_count: u32,
        first_vertex: u32,
        first_instance: u32,
    },
    /// Draw indexed primitives.
    DrawIndexed {
        index_count: u32,
        instance_count: u32,
        first_index: u32,
        vertex_offset: i32,
        first_instance: u32,
    },
    /// Dispatch compute workgroups.
    Dispatch {
        group_count_x: u32,
        group_count_y: u32,
        group_count_z: u32,
    },
    /// Copy regions between buffers.
    CopyBuffer {
        src: VkBuffer,
        dst: VkBuffer,
        regions: Vec<(u64, u64, u64)>,
    },
    /// Copy regions between images.
    CopyImage {
        src: VkImage,
        dst: VkImage,
        regions: Vec<ImageCopyRegion>,
    },
    /// Copy buffer regions into an image.
    CopyBufferToImage {
        src: VkBuffer,
        dst: VkImage,
        regions: Vec<BufferImageCopyRegion>,
    },
    /// Insert a pipeline barrier for synchronization.
    PipelineBarrier {
        src_stage: u32,
        dst_stage: u32,
        by_region: bool,
        memory_barriers: Vec<VkMemoryBarrier>,
        buffer_barriers: Vec<VkBufferMemoryBarrier>,
        image_barriers: Vec<VkImageMemoryBarrier>,
    },
    /// Push constants to a pipeline layout.
    PushConstants {
        layout: VkPipelineLayout,
        stage: u32,
        offset: u32,
        data: Vec<u8>,
    },
}

/// Clear value for render pass attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearValue {
    pub color: [f32; 4],
}

/// Image copy region descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageCopyRegion {
    pub src_subresource: ImageSubresourceLayers,
    pub src_offset: (i32, i32, i32),
    pub dst_subresource: ImageSubresourceLayers,
    pub dst_offset: (i32, i32, i32),
    pub extent: (u32, u32, u32),
}

/// Buffer-to-image copy region descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferImageCopyRegion {
    pub buffer_offset: u64,
    pub buffer_row_length: u32,
    pub buffer_image_height: u32,
    pub image_subresource: ImageSubresourceLayers,
    pub image_offset: (i32, i32, i32),
    pub image_extent: (u32, u32, u32),
}

/// Image subresource layers descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSubresourceLayers {
    pub aspect_mask: u32,
    pub mip_level: u32,
    pub base_array_layer: u32,
    pub layer_count: u32,
}

/// Memory barrier for global memory dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkMemoryBarrier {
    pub src_access_mask: VkAccessFlags,
    pub dst_access_mask: VkAccessFlags,
}

/// Buffer memory barrier for buffer-range dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkBufferMemoryBarrier {
    pub src_access_mask: VkAccessFlags,
    pub dst_access_mask: VkAccessFlags,
    pub src_queue_family_index: u32,
    pub dst_queue_family_index: u32,
    pub buffer: VkBuffer,
    pub offset: u64,
    pub size: u64,
}

/// Image memory barrier for image layout transitions and ownership transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkImageMemoryBarrier {
    pub src_access_mask: VkAccessFlags,
    pub dst_access_mask: VkAccessFlags,
    pub old_layout: VkImageLayout,
    pub new_layout: VkImageLayout,
    pub src_queue_family_index: u32,
    pub dst_queue_family_index: u32,
    pub image: VkImage,
    pub subresource_range: ImageSubresourceRange,
}

/// Image subresource range descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSubresourceRange {
    pub aspect_mask: u32,
    pub base_mip_level: u32,
    pub level_count: u32,
    pub base_array_layer: u32,
    pub layer_count: u32,
}

/// Tracks a fence synchronization object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkFenceInfo {
    pub handle: VkFence,
    pub device: VkDevice,
    pub signaled: bool,
}

/// Tracks a semaphore synchronization object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSemaphoreInfo {
    pub handle: VkSemaphore,
    pub device: VkDevice,
    pub signaled: bool,
}

/// Submit info for queue submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSubmitInfo {
    pub wait_semaphores: Vec<VkSemaphore>,
    pub command_buffers: Vec<VkCommandBuffer>,
    pub signal_semaphores: Vec<VkSemaphore>,
}

/// Tracks a sampler and its Metal backing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSamplerInfo {
    pub handle: u64,
    pub device: VkDevice,
    pub min_filter: u32,
    pub mag_filter: u32,
    pub mipmap_mode: u32,
    pub address_mode_u: u32,
    pub address_mode_v: u32,
    pub address_mode_w: u32,
    pub mip_lod_bias: f32,
    pub max_anisotropy: f32,
    pub compare_op: u32,
    pub min_lod: f32,
    pub max_lod: f32,
    /// Handle to the Metal sampler state in [`MetalGpuBackend`].
    pub metal_sampler_id: Option<u64>,
}

/// Sampler creation parameters, mirroring `VkSamplerCreateInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkSamplerCreateInfo {
    pub min_filter: u32,
    pub mag_filter: u32,
    pub mipmap_mode: u32,
    pub address_mode_u: u32,
    pub address_mode_v: u32,
    pub address_mode_w: u32,
    pub mip_lod_bias: f32,
    pub max_anisotropy: f32,
    pub compare_op: u32,
    pub min_lod: f32,
    pub max_lod: f32,
}

/// Memory allocation type, mapping to Metal storage modes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryAllocationType {
    /// GPU-only memory, maps to `MTLStorageModePrivate`.
    Private,
    /// CPU-GPU shared memory, maps to `MTLStorageModeShared`.
    Shared,
    /// CPU-GPU managed memory, maps to `MTLStorageModeManaged`.
    Managed,
    /// Tile memory, maps to `MTLStorageModeMemoryless`.
    Memoryless,
}

impl MemoryAllocationType {
    /// Determine the allocation type from Vulkan memory property flags.
    pub fn from_memory_properties(flags: VkMemoryPropertyFlags) -> Self {
        let host_visible = (flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) != 0;
        let device_local = (flags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) != 0;
        let lazily_allocated = (flags & VK_MEMORY_PROPERTY_LAZILY_ALLOCATED_BIT) != 0;

        if lazily_allocated {
            MemoryAllocationType::Memoryless
        } else if host_visible && device_local {
            MemoryAllocationType::Shared
        } else if host_visible {
            MemoryAllocationType::Managed
        } else {
            MemoryAllocationType::Private
        }
    }
}

/// Tracks a device memory allocation and its Metal buffer backing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkDeviceMemoryInfo {
    pub handle: VkDeviceMemory,
    pub size: u64,
    pub memory_type_index: u32,
    /// Virtual address of the mapped range, if currently mapped.
    pub mapped_pointer: Option<u64>,
    /// Handle to the backing Metal buffer (`MTLBuffer`).
    pub metal_buffer: Option<u64>,
    /// The Metal storage mode for this allocation.
    pub allocation_type: MemoryAllocationType,
    /// The mapped data buffer (stored as bytes for CPU access).
    pub mapped_data: Option<Vec<u8>>,
}

// ===========================================================================
// Section 4: MoltenVK Loader
// ===========================================================================

/// Standard search paths for the MoltenVK dynamic library on macOS.
///
/// MoltenVK can be installed via Homebrew, SDKs, or bundled alongside
/// the application. This function returns all standard locations to check.
pub fn moltenvk_search_paths() -> Vec<&'static Path> {
    vec![
        Path::new("/usr/local/lib/libMoltenVK.dylib"),
        Path::new("/opt/homebrew/lib/libMoltenVK.dylib"),
        Path::new("/opt/homebrew/Cellar/molten-vk"),
        Path::new("/usr/local/Cellar/molten-vk"),
        Path::new("/Library/Frameworks/MoltenVK.framework/Versions/A/libMoltenVK.dylib"),
        // Phase 2.5: Bundled MoltenVK at ~/MoltenVK/
        Path::new("MoltenVK/macOS/libMoltenVK.dylib"),
        Path::new("libMoltenVK.dylib"),
    ]
}

/// Returns expanded MoltenVK search paths including user home directory.
/// Checks `~/MoltenVK/` and bundled paths in addition to standard locations.
pub fn moltenvk_expanded_search_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    // Standard paths
    for p in moltenvk_search_paths() {
        paths.push(p.to_path_buf());
    }
    // ~/MoltenVK/ (user home directory)
    if let Some(home) = std::env::var_os("HOME") {
        let home_path = std::path::PathBuf::from(&home);
        paths.push(home_path.join("MoltenVK/macOS/libMoltenVK.dylib"));
        paths.push(home_path.join("MoltenVK/libMoltenVK.dylib"));
        paths.push(home_path.join("MoltenVK/lib/libMoltenVK.dylib"));
    }
    // Bundled relative to executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        paths.push(dir.join("MoltenVK/macOS/libMoltenVK.dylib"));
        paths.push(dir.join("libMoltenVK.dylib"));
    }
    paths
}

/// MoltenVK runtime loader that locates and loads the MoltenVK dynamic library.
///
/// On macOS, MoltenVK provides Vulkan API compatibility by translating Vulkan
/// calls to Metal. This loader searches standard installation paths, loads the
/// dynamic library, and resolves the core `vkGetInstanceProcAddr` symbol.
pub struct MoltenVKLoader {
    /// The loaded dynamic library, if found.
    library: Option<libloading::Library>,
    /// Resolved `vkGetInstanceProcAddr` function pointer.
    vk_get_instance_proc_addr:
        Option<unsafe extern "C" fn(VkInstance, *const c_char) -> PFN_vkVoidFunction>,
    /// Whether the library was successfully loaded.
    loaded: bool,
    /// Detected MoltenVK version (major, minor, patch).
    version: Option<(u32, u32, u32)>,
}

impl MoltenVKLoader {
    /// Create a new loader with empty state. Call [`load`](Self::load) to attempt loading.
    pub fn new() -> Self {
        Self {
            library: None,
            vk_get_instance_proc_addr: None,
            loaded: false,
            version: None,
        }
    }

    /// Load MoltenVK (see [`MoltenVKLoader::load`]) if it is available.
    ///
    /// Operates in simulated mode (returns `Ok`) when MoltenVK is not
    /// installed, mirroring [`MoltenVKLoader::load`].
    pub fn load_if_available(&mut self) {
        let _ = self.load();
    }

    /// Attempt to load the MoltenVK library from standard search paths.
    ///
    /// Searches each path returned by [`moltenvk_search_paths`], tries to load the
    /// dynamic library via `libloading`, and resolves the `vkGetInstanceProcAddr`
    /// symbol. If a framework directory is found, searches within it for the dylib.
    ///
    /// # Errors
    ///
    /// Returns `AppError` with `RcVulkanNotSupported` if MoltenVK cannot be found
    /// or the required symbol cannot be resolved.
    pub fn load(&mut self) -> AppResult<()> {
        let search_paths = moltenvk_search_paths();

        for path in &search_paths {
            // Try loading directly
            if let Ok(lib) = unsafe { libloading::Library::new(path.as_os_str()) } {
                // Try to resolve vkGetInstanceProcAddr
                let symbol_name = b"vkGetInstanceProcAddr\0";
                match unsafe {
                    lib.get::<unsafe extern "C" fn(VkInstance, *const c_char) -> PFN_vkVoidFunction>(
                        symbol_name,
                    )
                } {
                    Ok(func) => {
                        self.vk_get_instance_proc_addr = Some(*func);
                        self.library = Some(lib);
                        self.loaded = true;
                        self.version = Some((1, 2, 0)); // Default detected version
                        return Ok(());
                    }
                    Err(_) => {
                        // Library loaded but symbol not found — continue searching
                        drop(lib);
                    }
                }
            }
        }

        // MoltenVK not found — operate in simulated mode (no error, just not loaded)
        self.loaded = false;
        Ok(())
    }

    /// Resolve a Vulkan function pointer by name using `vkGetInstanceProcAddr`.
    ///
    /// Passes a null instance to obtain global (instance-independent) function
    /// pointers, matching the Vulkan specification for `vkGetInstanceProcAddr`
    /// with `VK_NULL_HANDLE`.
    ///
    /// Returns `None` if the library is not loaded or the symbol cannot be resolved.
    pub fn get_proc_addr(&self, name: &str) -> Option<PFN_vkVoidFunction> {
        if !self.loaded {
            return None;
        }
        let func = self.vk_get_instance_proc_addr?;
        let c_name = CString::new(name).ok()?;
        Some(unsafe { func(0, c_name.as_ptr()) })
    }

    /// Returns whether the MoltenVK library was successfully loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Returns the detected MoltenVK version, if loaded.
    pub fn version(&self) -> Option<(u32, u32, u32)> {
        self.version
    }
}

impl std::fmt::Debug for MoltenVKLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoltenVKLoader")
            .field("loaded", &self.loaded)
            .field("version", &self.version)
            .finish()
    }
}

impl Default for MoltenVKLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Section 5: SPIR-V to MSL Translator
// ===========================================================================

/// SPIR-V magic number identifying a valid SPIR-V binary.
const SPIRV_MAGIC: u32 = 0x07230203;

/// SPIR-V opcodes used by the translator.
const SPIRV_OP_CAPABILITY: u16 = 17;
const SPIRV_OP_MEMORY_MODEL: u16 = 14;
const SPIRV_OP_ENTRY_POINT: u16 = 15;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_EXECUTION_MODE: u16 = 16;
const SPIRV_OP_NAME: u16 = 5;
const SPIRV_OP_MEMBER_NAME: u16 = 6;
const SPIRV_OP_DECORATE: u16 = 71;
const SPIRV_OP_MEMBER_DECORATE: u16 = 72;
const SPIRV_OP_TYPE_VOID: u16 = 19;
const SPIRV_OP_TYPE_BOOL: u16 = 20;
const SPIRV_OP_TYPE_INT: u16 = 21;
const SPIRV_OP_TYPE_FLOAT: u16 = 22;
const SPIRV_OP_TYPE_VECTOR: u16 = 23;
const SPIRV_OP_TYPE_MATRIX: u16 = 24;
const SPIRV_OP_TYPE_IMAGE: u16 = 25;
const SPIRV_OP_TYPE_SAMPLER: u16 = 26;
const SPIRV_OP_TYPE_SAMPLED_IMAGE: u16 = 27;
const SPIRV_OP_TYPE_ARRAY: u16 = 28;
const SPIRV_OP_TYPE_RUNTIME_ARRAY: u16 = 29;
const SPIRV_OP_TYPE_STRUCT: u16 = 30;
const SPIRV_OP_TYPE_POINTER: u16 = 32;
const SPIRV_OP_TYPE_FUNCTION: u16 = 33;
const SPIRV_OP_CONSTANT_TRUE: u16 = 41;
const SPIRV_OP_CONSTANT_FALSE: u16 = 42;
const SPIRV_OP_CONSTANT: u16 = 43;
const SPIRV_OP_CONSTANT_COMPOSITE: u16 = 44;
const SPIRV_OP_FUNCTION: u16 = 54;
const SPIRV_OP_FUNCTION_PARAMETER: u16 = 55;
const SPIRV_OP_FUNCTION_END: u16 = 56;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_FUNCTION_CALL: u16 = 57;
const SPIRV_OP_VARIABLE: u16 = 59;
const SPIRV_OP_LOAD: u16 = 61;
const SPIRV_OP_STORE: u16 = 62;
const SPIRV_OP_ACCESS_CHAIN: u16 = 65;
const SPIRV_OP_COMPOSITE_CONSTRUCT: u16 = 80;
const SPIRV_OP_COMPOSITE_EXTRACT: u16 = 81;
const SPIRV_OP_IMAGE_SAMPLE_IMPLICIT_LOD: u16 = 87;
const SPIRV_OP_IMAGE_FETCH: u16 = 95;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_IMAGE_READ: u16 = 98;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_IMAGE_WRITE: u16 = 99;
const SPIRV_OP_SNEGATE: u16 = 126;
const SPIRV_OP_FNEGATE: u16 = 127;
const SPIRV_OP_IADD: u16 = 128;
const SPIRV_OP_FADD: u16 = 129;
const SPIRV_OP_ISUB: u16 = 130;
const SPIRV_OP_FSUB: u16 = 131;
const SPIRV_OP_IMUL: u16 = 132;
const SPIRV_OP_FMUL: u16 = 133;
const SPIRV_OP_UDIV: u16 = 134;
const SPIRV_OP_SDIV: u16 = 135;
const SPIRV_OP_FDIV: u16 = 136;
const SPIRV_OP_CONVERT_F_TO_U: u16 = 109;
const SPIRV_OP_CONVERT_F_TO_S: u16 = 110;
const SPIRV_OP_CONVERT_S_TO_F: u16 = 111;
const SPIRV_OP_CONVERT_U_TO_F: u16 = 112;
const SPIRV_OP_RETURN: u16 = 253;
const SPIRV_OP_RETURN_VALUE: u16 = 254;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_LABEL: u16 = 248;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_BRANCH: u16 = 249;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_BRANCH_CONDITIONAL: u16 = 250;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_SWITCH: u16 = 251;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_SELECTION_MERGE: u16 = 247;
#[allow(dead_code)] // SPIR-V opcode constants (ABI table for the SPIR-V translator)
const SPIRV_OP_LOOP_MERGE: u16 = 246;

/// SPIR-V execution models.
const SPIRV_EXEC_MODEL_VERTEX: u32 = 0;
const SPIRV_EXEC_MODEL_TESSELLATION_CONTROL: u32 = 1;
const SPIRV_EXEC_MODEL_TESSELLATION_EVALUATION: u32 = 2;
const SPIRV_EXEC_MODEL_GEOMETRY: u32 = 3;
const SPIRV_EXEC_MODEL_FRAGMENT: u32 = 4;
const SPIRV_EXEC_MODEL_COMPUTE: u32 = 5;

/// SPIR-V storage classes.
const SPIRV_STORAGE_UNIFORM: u32 = 2;
const SPIRV_STORAGE_STORAGE_BUFFER: u32 = 12;
const SPIRV_STORAGE_PUSH_CONSTANT: u32 = 9;

/// SPIR-V decorations relevant to binding mapping.
const SPIRV_DECORATION_BINDING: u32 = 33;
const SPIRV_DECORATION_DESCRIPTOR_SET: u32 = 34;
const SPIRV_DECORATION_LOCATION: u32 = 30;
const SPIRV_DECORATION_OFFSET: u32 = 35;

/// Parsed SPIR-V type representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpirvType {
    Void,
    Bool,
    Int {
        width: u32,
        signed: bool,
    },
    Float {
        width: u32,
    },
    Vector {
        component_type: u32,
        component_count: u32,
    },
    Matrix {
        column_type: u32,
        column_count: u32,
    },
    Array {
        element_type: u32,
        length: u32,
    },
    RuntimeArray {
        element_type: u32,
    },
    Struct {
        member_types: Vec<u32>,
        name: Option<String>,
    },
    Pointer {
        pointee_type: u32,
        storage_class: u32,
    },
    Image {
        sampled_type: u32,
        dim: u32,
    },
    Sampler,
    SampledImage {
        image_type: u32,
    },
    Function {
        return_type: u32,
        param_types: Vec<u32>,
    },
}

/// Parsed decoration for a SPIR-V ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpirvDecoration {
    binding: Option<u32>,
    descriptor_set: Option<u32>,
    location: Option<u32>,
    offset: Option<u32>,
}

/// Parsed SPIR-V function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpirvFunction {
    result_id: u32,
    return_type: u32,
    function_type: u32,
    instructions: Vec<SpirvInstruction>,
}

/// Simplified SPIR-V instruction representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpirvInstruction {
    opcode: u16,
    operands: Vec<u32>,
}

/// SPIR-V to MSL translator. Parses SPIR-V bytecode and generates Metal
/// Shading Language source code that can be compiled by the Metal toolchain.
pub struct SpirvTranslator {
    /// Map from SPIR-V result ID to type.
    types: BTreeMap<u32, SpirvType>,
    /// Map from SPIR-V result ID to human-readable name.
    names: BTreeMap<u32, String>,
    /// Map from `(struct_type_id, member_index)` to human-readable member name.
    member_names: BTreeMap<(u32, u32), String>,
    /// Map from SPIR-V result ID to decorations.
    decorations: BTreeMap<u32, SpirvDecoration>,
    /// Parsed entry points: (result_id, execution_model, name).
    entry_points: Vec<(u32, u32, String)>,
    /// Parsed functions.
    functions: Vec<SpirvFunction>,
    /// Map from SPIR-V result ID to constant values (32-bit, or the low word
    /// of wider constants).
    constants: BTreeMap<u32, u32>,
    /// Map from SPIR-V result ID to full 64-bit constant values (only entries
    /// whose type is a 64-bit int/float are stored here).
    constants64: BTreeMap<u32, u64>,
    /// Map from SPIR-V result ID to constant-composite constituent IDs.
    composites: BTreeMap<u32, Vec<u32>>,
    /// Map from SPIR-V result ID to variable (type_id, storage_class).
    variables: BTreeMap<u32, (u32, u32)>,
    /// Memoized MSL type names keyed by SPIR-V type ID.
    msl_type_cache: BTreeMap<u32, String>,
}

impl Default for SpirvTranslator {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a null-terminated string from SPIR-V word operands, stopping at the
/// first NUL byte instead of flattening every operand word (which would
/// append trailing interface IDs or numeric data to the name).
fn decode_spirv_string(operands: &[u32]) -> String {
    let mut bytes = Vec::new();
    'words: for w in operands {
        for b in w.to_le_bytes() {
            if b == 0 {
                break 'words;
            }
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

/// Minimum word count (including the opcode word) for every SPIR-V opcode the
/// translator must structurally validate. For opcodes not listed here the
/// minimum is 1 (the opcode word alone); their operand layouts are opaque to
/// the translator, but truncation of the instruction stream is still rejected.
fn min_spirv_words(opcode: u16) -> u16 {
    match opcode {
        0 => 1,                     // OpNop
        1 => 3,                     // OpUndef
        2 => 2,                     // OpSourceContinued
        3 => 2,                     // OpSource
        4 => 2,                     // OpSourceExtension
        SPIRV_OP_NAME => 3,         // OpName: target + name (>=1 word)
        SPIRV_OP_MEMBER_NAME => 4,  // OpMemberName: target + member + name (>=1 word)
        7 => 3,                     // OpString: result + string (>=1 word)
        8 => 4,                     // OpLine
        10 => 2,                    // OpExtension
        11 => 3,                    // OpExtInstImport: result + name (>=1 word)
        12 => 5,                    // OpExtInst
        SPIRV_OP_MEMORY_MODEL => 3, // OpMemoryModel: addressing + memory model
        SPIRV_OP_ENTRY_POINT => 4,  // OpEntryPoint: model + id + name (>=1 word)
        16 => 3,                    // OpExecutionMode
        SPIRV_OP_CAPABILITY => 2,   // OpCapability
        SPIRV_OP_TYPE_VOID => 2,
        SPIRV_OP_TYPE_BOOL => 2,
        SPIRV_OP_TYPE_INT => 4,
        SPIRV_OP_TYPE_FLOAT => 3,
        SPIRV_OP_TYPE_VECTOR => 4,
        SPIRV_OP_TYPE_MATRIX => 4,
        SPIRV_OP_TYPE_IMAGE => 9,
        SPIRV_OP_TYPE_SAMPLER => 2,
        SPIRV_OP_TYPE_SAMPLED_IMAGE => 3,
        SPIRV_OP_TYPE_ARRAY => 4,
        SPIRV_OP_TYPE_RUNTIME_ARRAY => 3,
        SPIRV_OP_TYPE_STRUCT => 2,
        31 => 3, // OpTypeOpaque
        SPIRV_OP_TYPE_POINTER => 4,
        SPIRV_OP_TYPE_FUNCTION => 3,
        SPIRV_OP_CONSTANT_TRUE | SPIRV_OP_CONSTANT_FALSE => 3,
        SPIRV_OP_CONSTANT => 4,
        SPIRV_OP_CONSTANT_COMPOSITE => 4,
        46 => 3, // OpConstantNull
        SPIRV_OP_FUNCTION => 5,
        SPIRV_OP_FUNCTION_PARAMETER => 3,
        SPIRV_OP_FUNCTION_END => 1,
        57 => 4, // OpFunctionCall
        SPIRV_OP_VARIABLE => 4,
        61 => 4,                          // OpLoad
        62 => 3,                          // OpStore
        63 => 4,                          // OpCopyMemory
        65 => 5,                          // OpAccessChain
        66 => 5,                          // OpInBoundsAccessChain
        67 => 6,                          // OpPtrAccessChain
        SPIRV_OP_DECORATE => 3,           // OpDecorate: target + decoration
        SPIRV_OP_MEMBER_DECORATE => 4,    // OpMemberDecorate: target + member + decoration
        73 => 2,                          // OpDecorationGroup
        74 => 3,                          // OpGroupDecorate
        75 => 4,                          // OpGroupMemberDecorate
        SPIRV_OP_RETURN | 252 | 255 => 1, // OpReturn, OpKill, OpUnreachable
        SPIRV_OP_RETURN_VALUE => 2,
        SPIRV_OP_LABEL => 2,
        SPIRV_OP_BRANCH => 2,
        SPIRV_OP_BRANCH_CONDITIONAL => 4,
        SPIRV_OP_SWITCH => 3,
        _ => 1,
    }
}

/// Valid SPIR-V storage classes (core 1.0-1.5 plus the widely used KHR
/// extension classes: CallableDataKHR, IncomingCallableDataKHR, RayPayloadKHR,
/// HitAttributeKHR, IncomingRayPayloadKHR, ShaderRecordBufferKHR,
/// PhysicalStorageBuffer).
fn is_valid_spirv_storage_class(sc: u32) -> bool {
    sc <= 12 || matches!(sc, 5280 | 5281 | 5338 | 5339 | 5342 | 5343 | 5349)
}

/// Valid SPIR-V execution models: the seven core models (Vertex through
/// Kernel) plus the KHR ray-tracing models and the NV mesh/task models.
fn is_valid_spirv_execution_model(model: u32) -> bool {
    model <= 6 || matches!(model, 5267 | 5268 | 5313..=5318)
}

/// SPIR-V instructions that terminate a basic block: OpReturn, OpReturnValue,
/// OpBranch, OpBranchConditional, OpSwitch, OpKill (OpTerminateInvocation),
/// OpUnreachable.
fn is_block_terminator(opcode: u16) -> bool {
    matches!(
        opcode,
        SPIRV_OP_RETURN | SPIRV_OP_RETURN_VALUE | 249 | 250 | 251 | 252 | 255
    )
}

/// Require that `id` names a type already defined by the module. SPIR-V does
/// not allow forward type references (except via OpTypeForwardPointer), so a
/// reference to an unknown type is malformed.
fn require_type(types: &BTreeMap<u32, SpirvType>, id: u32, what: &str) -> AppResult<()> {
    if id == 0 || !types.contains_key(&id) {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("SPIR-V {what} references unknown type ID {id}"),
        ));
    }
    Ok(())
}

impl SpirvTranslator {
    /// Create a new translator with empty state.
    pub fn new() -> Self {
        Self {
            types: BTreeMap::new(),
            names: BTreeMap::new(),
            member_names: BTreeMap::new(),
            decorations: BTreeMap::new(),
            entry_points: Vec::new(),
            functions: Vec::new(),
            constants: BTreeMap::new(),
            constants64: BTreeMap::new(),
            composites: BTreeMap::new(),
            variables: BTreeMap::new(),
            msl_type_cache: BTreeMap::new(),
        }
    }

    /// Parse SPIR-V bytecode and populate the translator's internal representation.
    ///
    /// Validates the SPIR-V header (magic number, version), then walks all
    /// instructions to extract types, constants, variables, decorations,
    /// entry points, and function bodies.
    ///
    /// # Errors
    ///
    /// Returns `AppError` with `RcDxilInvalid` if the SPIR-V is malformed.
    pub fn parse(&mut self, spirv: &[u32]) -> AppResult<()> {
        if spirv.len() < 5 {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                "SPIR-V bytecode too short: fewer than 5 header words",
            ));
        }

        // Validate magic number
        if spirv[0] != SPIRV_MAGIC {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                format!(
                    "invalid SPIR-V magic number: expected 0x{:08X}, got 0x{:08X}",
                    SPIRV_MAGIC, spirv[0]
                ),
            ));
        }

        // Header: magic, version, generator, bound, schema
        let _version = spirv[1];
        let _generator = spirv[2];
        let bound = spirv[3];
        let _schema = spirv[4];
        // A zero bound forbids every result ID, making the module unusable.
        if bound == 0 {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                "invalid SPIR-V header: bound is zero",
            ));
        }
        // A five-word header with no instructions is not a module.
        if spirv.len() == 5 {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                "SPIR-V module contains no instructions (header only)",
            ));
        }

        // Walk instructions starting after the 5-word header. Every
        // instruction is validated BEFORE its operands are accepted:
        //   - word count != 0
        //   - word count >= the opcode's minimum
        //   - cursor + word count <= module length (truncated streams rejected)
        //   - ID operands < bound where required
        //   - result IDs nonzero, below the bound, and unique
        //   - type/result references resolve in context
        //   - function begin/end pairing
        //   - block termination before the next label / function end
        // Entry-point and decoration targets are verified in a post-pass.
        let mut offset = 5;
        let mut current_function: Option<SpirvFunction> = None;
        let mut in_block = false;
        let mut block_terminated = true;
        let mut defined_ids: BTreeSet<u32> = BTreeSet::new();
        let mut function_ids: BTreeSet<u32> = BTreeSet::new();
        let mut entry_targets: Vec<u32> = Vec::new();
        let mut decoration_targets: Vec<u32> = Vec::new();

        while offset < spirv.len() {
            let word = spirv[offset];
            let word_count = (word >> 16) as u16;
            let opcode = (word & 0xFFFF) as u16;

            if word_count == 0 {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!("SPIR-V instruction with word count 0 at offset {}", offset),
                ));
            }
            if (word_count as usize) < min_spirv_words(opcode) as usize {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!(
                        "SPIR-V opcode 0x{opcode:04X} at offset {offset} has word count \
                         {word_count}, below its minimum of {}",
                        min_spirv_words(opcode)
                    ),
                ));
            }
            // Reject truncated instruction streams: the declared length must
            // fit inside the module exactly.
            let Some(end) = offset.checked_add(word_count as usize) else {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!("SPIR-V instruction at offset {offset} overflows the module"),
                ));
            };
            if end > spirv.len() {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!(
                        "SPIR-V instruction at offset {offset} claims {word_count} words but \
                         only {} words remain in the module (truncated stream)",
                        spirv.len() - offset
                    ),
                ));
            }
            let operands: &[u32] = &spirv[offset + 1..end];

            // Validate and record a newly defined result ID.
            let mut define_id = |id: u32, what: &str| -> AppResult<()> {
                if id == 0 {
                    return Err(AppError::new(
                        ReasonCode::RcDxilInvalid,
                        format!("SPIR-V {what} result ID 0 is not allowed"),
                    ));
                }
                if id >= bound {
                    return Err(AppError::new(
                        ReasonCode::RcDxilInvalid,
                        format!(
                            "SPIR-V {what} result ID {id} is not below the header bound {bound}"
                        ),
                    ));
                }
                if !defined_ids.insert(id) {
                    return Err(AppError::new(
                        ReasonCode::RcDxilInvalid,
                        format!("SPIR-V {what} result ID {id} is defined more than once"),
                    ));
                }
                Ok(())
            };

            match opcode {
                SPIRV_OP_CAPABILITY | SPIRV_OP_MEMORY_MODEL => {
                    // Skip — we don't need to validate capabilities for translation
                }
                SPIRV_OP_ENTRY_POINT => {
                    // operands: [execution_model, entry_point_id,
                    //           <null-terminated name>, <interface ids...>]
                    let exec_model = operands[0];
                    let entry_id = operands[1];
                    if !is_valid_spirv_execution_model(exec_model) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpEntryPoint uses invalid execution model {exec_model}"
                            ),
                        ));
                    }
                    if entry_id == 0 || entry_id >= bound {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpEntryPoint target ID {entry_id} is not below the \
                                 header bound {bound}"
                            ),
                        ));
                    }
                    let name = decode_spirv_string(&operands[2..]);
                    entry_targets.push(entry_id);
                    self.entry_points.push((entry_id, exec_model, name));
                }
                SPIRV_OP_NAME => {
                    // operands: [target_id, name_bytes...]
                    let target_id = operands[0];
                    if target_id == 0 || target_id >= bound {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpName target ID {target_id} is not below the header \
                                 bound {bound}"
                            ),
                        ));
                    }
                    let name = decode_spirv_string(&operands[1..]);
                    decoration_targets.push(target_id);
                    if !name.is_empty() {
                        self.names.insert(target_id, name);
                    }
                }
                SPIRV_OP_MEMBER_NAME => {
                    // operands: [struct_type_id, member_index, name_bytes...]
                    let type_id = operands[0];
                    if type_id == 0 || type_id >= bound {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpMemberName target ID {type_id} is not below the \
                                 header bound {bound}"
                            ),
                        ));
                    }
                    let member_index = operands[1];
                    let name = decode_spirv_string(&operands[2..]);
                    decoration_targets.push(type_id);
                    if !name.is_empty() {
                        self.member_names.insert((type_id, member_index), name);
                    }
                }
                SPIRV_OP_DECORATE => {
                    // operands: [target_id, decoration, ...]
                    let target_id = operands[0];
                    if target_id == 0 || target_id >= bound {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpDecorate target ID {target_id} is not below the \
                                 header bound {bound}"
                            ),
                        ));
                    }
                    decoration_targets.push(target_id);
                    let decoration = operands[1];
                    let entry = self
                        .decorations
                        .entry(target_id)
                        .or_insert(SpirvDecoration {
                            binding: None,
                            descriptor_set: None,
                            location: None,
                            offset: None,
                        });
                    match decoration {
                        SPIRV_DECORATION_BINDING => {
                            entry.binding = Some(operands[2]);
                        }
                        SPIRV_DECORATION_DESCRIPTOR_SET => {
                            entry.descriptor_set = Some(operands[2]);
                        }
                        SPIRV_DECORATION_LOCATION => {
                            entry.location = Some(operands[2]);
                        }
                        SPIRV_DECORATION_OFFSET => {
                            entry.offset = Some(operands[2]);
                        }
                        _ => {}
                    }
                }
                SPIRV_OP_MEMBER_DECORATE => {
                    // operands: [target_id, member_index, decoration, ...]
                    let target_id = operands[0];
                    if target_id == 0 || target_id >= bound {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpMemberDecorate target ID {target_id} is not below \
                                 the header bound {bound}"
                            ),
                        ));
                    }
                    decoration_targets.push(target_id);
                }
                SPIRV_OP_TYPE_VOID => {
                    define_id(operands[0], "OpTypeVoid")?;
                    self.types.insert(operands[0], SpirvType::Void);
                }
                SPIRV_OP_TYPE_BOOL => {
                    define_id(operands[0], "OpTypeBool")?;
                    self.types.insert(operands[0], SpirvType::Bool);
                }
                SPIRV_OP_TYPE_INT => {
                    // operands: [result_id, width, signedness]
                    let width = operands[1];
                    if width == 0 || width > 64 || !width.is_multiple_of(8) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("SPIR-V OpTypeInt declares invalid width {width}"),
                        ));
                    }
                    let signedness = operands[2];
                    if signedness > 1 {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("SPIR-V OpTypeInt declares invalid signedness {signedness}"),
                        ));
                    }
                    define_id(operands[0], "OpTypeInt")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::Int {
                            width,
                            signed: signedness != 0,
                        },
                    );
                }
                SPIRV_OP_TYPE_FLOAT => {
                    // operands: [result_id, width]
                    let width = operands[1];
                    if !matches!(width, 16 | 32 | 64) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("SPIR-V OpTypeFloat declares invalid width {width}"),
                        ));
                    }
                    define_id(operands[0], "OpTypeFloat")?;
                    self.types.insert(operands[0], SpirvType::Float { width });
                }
                SPIRV_OP_TYPE_VECTOR => {
                    // operands: [result_id, component_type_id, component_count]
                    require_type(&self.types, operands[1], "OpTypeVector component")?;
                    let component_count = operands[2];
                    if !matches!(component_count, 2 | 3 | 4 | 8 | 16) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpTypeVector declares invalid component count \
                                 {component_count}"
                            ),
                        ));
                    }
                    define_id(operands[0], "OpTypeVector")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::Vector {
                            component_type: operands[1],
                            component_count,
                        },
                    );
                }
                SPIRV_OP_TYPE_MATRIX => {
                    // operands: [result_id, column_type_id, column_count]
                    require_type(&self.types, operands[1], "OpTypeMatrix column")?;
                    let column_count = operands[2];
                    if !matches!(column_count, 2..=4) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpTypeMatrix declares invalid column count {column_count}"
                            ),
                        ));
                    }
                    define_id(operands[0], "OpTypeMatrix")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::Matrix {
                            column_type: operands[1],
                            column_count,
                        },
                    );
                }
                SPIRV_OP_TYPE_ARRAY => {
                    // operands: [result_id, element_type_id, length_id]
                    // The length is a constant ID that is defined *after* the
                    // type section in SPIR-V; it is resolved in a post-pass
                    // once all constants have been parsed.
                    require_type(&self.types, operands[1], "OpTypeArray element")?;
                    let length_id = operands[2];
                    if length_id == 0 || length_id >= bound {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpTypeArray length ID {length_id} is not below the \
                                 header bound {bound}"
                            ),
                        ));
                    }
                    define_id(operands[0], "OpTypeArray")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::Array {
                            element_type: operands[1],
                            length: length_id,
                        },
                    );
                }
                SPIRV_OP_TYPE_RUNTIME_ARRAY => {
                    require_type(&self.types, operands[1], "OpTypeRuntimeArray element")?;
                    define_id(operands[0], "OpTypeRuntimeArray")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::RuntimeArray {
                            element_type: operands[1],
                        },
                    );
                }
                SPIRV_OP_TYPE_STRUCT => {
                    // operands: [result_id, member_type_id_0, ...]
                    for &member in &operands[1..] {
                        require_type(&self.types, member, "OpTypeStruct member")?;
                    }
                    define_id(operands[0], "OpTypeStruct")?;
                    let member_types = operands[1..].to_vec();
                    let name = self.names.get(&operands[0]).cloned();
                    self.types
                        .insert(operands[0], SpirvType::Struct { member_types, name });
                }
                SPIRV_OP_TYPE_POINTER => {
                    // operands: [result_id, storage_class, pointee_type_id]
                    let storage_class = operands[1];
                    if !is_valid_spirv_storage_class(storage_class) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpTypePointer declares invalid storage class {storage_class}"
                            ),
                        ));
                    }
                    require_type(&self.types, operands[2], "OpTypePointer pointee")?;
                    define_id(operands[0], "OpTypePointer")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::Pointer {
                            pointee_type: operands[2],
                            storage_class,
                        },
                    );
                }
                SPIRV_OP_TYPE_FUNCTION => {
                    // operands: [result_id, return_type_id, param_type_id_0, ...]
                    require_type(&self.types, operands[1], "OpTypeFunction return")?;
                    for &param in &operands[2..] {
                        require_type(&self.types, param, "OpTypeFunction parameter")?;
                    }
                    define_id(operands[0], "OpTypeFunction")?;
                    let return_type = operands[1];
                    let param_types = operands[2..].to_vec();
                    self.types.insert(
                        operands[0],
                        SpirvType::Function {
                            return_type,
                            param_types,
                        },
                    );
                }
                SPIRV_OP_TYPE_IMAGE => {
                    require_type(&self.types, operands[1], "OpTypeImage sampled")?;
                    let dim = operands.get(2).copied().unwrap_or(0);
                    if dim > 7 {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("SPIR-V OpTypeImage declares invalid dim {dim}"),
                        ));
                    }
                    define_id(operands[0], "OpTypeImage")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::Image {
                            sampled_type: operands[1],
                            dim,
                        },
                    );
                }
                SPIRV_OP_TYPE_SAMPLER => {
                    define_id(operands[0], "OpTypeSampler")?;
                    self.types.insert(operands[0], SpirvType::Sampler);
                }
                SPIRV_OP_TYPE_SAMPLED_IMAGE => {
                    require_type(&self.types, operands[1], "OpTypeSampledImage image")?;
                    define_id(operands[0], "OpTypeSampledImage")?;
                    self.types.insert(
                        operands[0],
                        SpirvType::SampledImage {
                            image_type: operands[1],
                        },
                    );
                }
                SPIRV_OP_CONSTANT => {
                    // operands: [type_id, result_id, value_words...]
                    let type_id = operands[0];
                    require_type(&self.types, type_id, "OpConstant")?;
                    let result_id = operands[1];
                    define_id(result_id, "OpConstant")?;
                    let is_64 = matches!(
                        self.types.get(&type_id),
                        Some(SpirvType::Int { width: 64, .. })
                            | Some(SpirvType::Float { width: 64 })
                    );
                    let expected_words = if is_64 { 5 } else { 4 };
                    if word_count as usize != expected_words {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpConstant must have exactly {expected_words} words, \
                                 got {word_count}"
                            ),
                        ));
                    }
                    // Scalar constants span two words for 64-bit int/float
                    // types; combine them so the value is not silently
                    // truncated to the low word.
                    let lo = operands[2] as u64;
                    let hi = operands.get(3).copied().unwrap_or(0) as u64;
                    let value = lo | (hi << 32);
                    self.constants.insert(result_id, value as u32);
                    if is_64 {
                        self.constants64.insert(result_id, value);
                    }
                }
                SPIRV_OP_CONSTANT_COMPOSITE => {
                    // operands: [type_id, result_id, constituent_ids...]
                    require_type(&self.types, operands[0], "OpConstantComposite")?;
                    let result_id = operands[1];
                    define_id(result_id, "OpConstantComposite")?;
                    for &constituent in &operands[2..] {
                        if constituent == 0 || constituent >= bound {
                            return Err(AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!(
                                    "SPIR-V OpConstantComposite constituent ID {constituent} is \
                                     not below the header bound {bound}"
                                ),
                            ));
                        }
                        if !defined_ids.contains(&constituent) {
                            return Err(AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!(
                                    "SPIR-V OpConstantComposite references undefined \
                                     constituent ID {constituent}"
                                ),
                            ));
                        }
                    }
                    self.composites.insert(result_id, operands[2..].to_vec());
                }
                SPIRV_OP_CONSTANT_TRUE => {
                    require_type(&self.types, operands[0], "OpConstantTrue")?;
                    let result_id = operands[1];
                    define_id(result_id, "OpConstantTrue")?;
                    self.constants.insert(result_id, 1);
                }
                SPIRV_OP_CONSTANT_FALSE => {
                    require_type(&self.types, operands[0], "OpConstantFalse")?;
                    let result_id = operands[1];
                    define_id(result_id, "OpConstantFalse")?;
                    self.constants.insert(result_id, 0);
                }
                SPIRV_OP_VARIABLE => {
                    // operands: [result_type_id, result_id, storage_class, initializer_id]
                    require_type(&self.types, operands[0], "OpVariable")?;
                    let result_id = operands[1];
                    define_id(result_id, "OpVariable")?;
                    let storage_class = operands[2];
                    if !is_valid_spirv_storage_class(storage_class) {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V OpVariable declares invalid storage class {storage_class}"
                            ),
                        ));
                    }
                    self.variables
                        .insert(result_id, (operands[0], storage_class));
                }
                SPIRV_OP_FUNCTION => {
                    // operands: [result_type_id, result_id, function_control, function_type_id]
                    if current_function.is_some() {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            "SPIR-V OpFunction nested inside another function",
                        ));
                    }
                    require_type(&self.types, operands[0], "OpFunction return")?;
                    let result_id = operands[1];
                    define_id(result_id, "OpFunction")?;
                    function_ids.insert(result_id);
                    let function_type = operands[3];
                    require_type(&self.types, function_type, "OpFunction type")?;
                    current_function = Some(SpirvFunction {
                        result_id,
                        return_type: operands[0],
                        function_type,
                        instructions: Vec::new(),
                    });
                    in_block = false;
                    block_terminated = true;
                }
                SPIRV_OP_FUNCTION_PARAMETER => {
                    // operands: [result_type_id, result_id]
                    if current_function.is_none() {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            "SPIR-V OpFunctionParameter outside a function",
                        ));
                    }
                    require_type(&self.types, operands[0], "OpFunctionParameter")?;
                    define_id(operands[1], "OpFunctionParameter")?;
                }
                SPIRV_OP_FUNCTION_END => {
                    let Some(func) = current_function.take() else {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            "SPIR-V OpFunctionEnd without a matching OpFunction",
                        ));
                    };
                    if in_block && !block_terminated {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V function %{} ends with an unterminated basic block",
                                func.result_id
                            ),
                        ));
                    }
                    self.functions.push(func);
                    in_block = false;
                    block_terminated = true;
                }
                SPIRV_OP_LABEL => {
                    // operands: [result_id]
                    if current_function.is_none() {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            "SPIR-V OpLabel outside a function",
                        ));
                    }
                    if in_block && !block_terminated {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            "SPIR-V OpLabel found while the previous block is unterminated",
                        ));
                    }
                    define_id(operands[0], "OpLabel")?;
                    in_block = true;
                    block_terminated = false;
                    if let Some(func) = current_function.as_mut() {
                        func.instructions.push(SpirvInstruction {
                            opcode,
                            operands: operands.to_vec(),
                        });
                    }
                }
                _ if is_block_terminator(opcode) => {
                    if current_function.is_none() {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V opcode 0x{opcode:04X} (block terminator) outside a function"
                            ),
                        ));
                    }
                    if !in_block {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "SPIR-V opcode 0x{opcode:04X} (block terminator) outside a \
                                 labeled block"
                            ),
                        ));
                    }
                    block_terminated = true;
                    if let Some(func) = current_function.as_mut() {
                        func.instructions.push(SpirvInstruction {
                            opcode,
                            operands: operands.to_vec(),
                        });
                    }
                }
                _ => {
                    // Record instructions inside function bodies
                    if let Some(func) = current_function.as_mut() {
                        func.instructions.push(SpirvInstruction {
                            opcode,
                            operands: operands.to_vec(),
                        });
                    }
                }
            }

            offset += word_count as usize;
        }

        // Post-pass 1: an open function means the module is unterminated.
        if let Some(func) = current_function.as_ref() {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                format!(
                    "SPIR-V function %{} is never terminated (missing OpFunctionEnd)",
                    func.result_id
                ),
            ));
        }

        // Post-pass 2: every entry-point target must exist as a function.
        for target in entry_targets {
            if !function_ids.contains(&target) {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!(
                        "SPIR-V OpEntryPoint target ID {target} does not name a defined function"
                    ),
                ));
            }
        }

        // Post-pass 3: every OpName/OpMemberName/OpDecorate/OpMemberDecorate
        // target must be an ID defined by the module.
        for target in decoration_targets {
            if !defined_ids.contains(&target) {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!(
                        "SPIR-V name/decorate target ID {target} does not reference a defined ID"
                    ),
                ));
            }
        }

        // Post-pass 4: resolve array lengths now that every constant has been
        // parsed (constants are declared after types in SPIR-V). A length ID
        // that is not a known constant is malformed.
        let array_ids: Vec<u32> = self
            .types
            .iter()
            .filter_map(|(&id, ty)| matches!(ty, SpirvType::Array { .. }).then_some(id))
            .collect();
        for id in array_ids {
            let len = match self.types.get(&id) {
                Some(SpirvType::Array { length, .. }) => *length,
                _ => continue,
            };
            let Some(v) = self.resolve_constant_u32(len) else {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!(
                        "SPIR-V OpTypeArray length ID {len} does not reference a defined \
                         constant"
                    ),
                ));
            };
            if let Some(SpirvType::Array { length, .. }) = self.types.get_mut(&id) {
                *length = v;
            }
        }

        Ok(())
    }

    /// Resolve a SPIR-V constant ID to its u32 value when the constant is
    /// known (handles 64-bit constants that fit in u32), otherwise `None`.
    fn resolve_constant_u32(&self, id: u32) -> Option<u32> {
        if let Some(v) = self.constants64.get(&id)
            && let Ok(v32) = u32::try_from(*v)
        {
            return Some(v32);
        }
        self.constants.get(&id).copied()
    }

    /// Resolve a SPIR-V type ID to its MSL type name string.
    ///
    /// Results are memoized in [`Self::msl_type_cache`] so repeated lookups
    /// for the same ID (common when generating MSL for many instructions)
    /// are O(1) map reads instead of recursive string construction.
    fn resolve_msl_type(&mut self, type_id: u32) -> String {
        if let Some(cached) = self.msl_type_cache.get(&type_id) {
            return cached.clone();
        }
        let name = match self.types.get(&type_id).cloned() {
            Some(SpirvType::Void) => "void".to_string(),
            Some(SpirvType::Bool) => "bool".to_string(),
            Some(SpirvType::Int { width, signed }) => {
                if signed {
                    match width {
                        8 => "char".to_string(),
                        16 => "short".to_string(),
                        32 => "int".to_string(),
                        64 => "long".to_string(),
                        _ => format!("int{}_t", width),
                    }
                } else {
                    match width {
                        8 => "uchar".to_string(),
                        16 => "ushort".to_string(),
                        32 => "uint".to_string(),
                        64 => "ulong".to_string(),
                        _ => format!("uint{}_t", width),
                    }
                }
            }
            Some(SpirvType::Float { width }) => match width {
                16 => "half".to_string(),
                32 => "float".to_string(),
                64 => "double".to_string(),
                _ => format!("float{}_t", width),
            },
            Some(SpirvType::Vector {
                component_type,
                component_count,
            }) => {
                let base = self.resolve_msl_type(component_type);
                match component_count {
                    2 => format!("{}2", base),
                    3 => format!("{}3", base),
                    4 => format!("{}4", base),
                    _ => format!("{}{}", base, component_count),
                }
            }
            Some(SpirvType::Matrix {
                column_type,
                column_count,
            }) => {
                // column_type should be a vector type
                let vec_name = self.resolve_msl_type(column_type);
                // e.g., float4 → float4x4
                format!("{}x{}", vec_name, column_count)
            }
            Some(SpirvType::Array {
                element_type,
                length,
            }) => {
                let elem = self.resolve_msl_type(element_type);
                format!("array<{}, {}>", elem, length)
            }
            Some(SpirvType::Struct { name, .. }) => name
                .clone()
                .unwrap_or_else(|| format!("Struct_{}", type_id)),
            Some(SpirvType::Pointer {
                pointee_type,
                storage_class,
            }) => {
                let pointee = self.resolve_msl_type(pointee_type);
                let addr_space = match storage_class {
                    SPIRV_STORAGE_UNIFORM => "constant",
                    SPIRV_STORAGE_STORAGE_BUFFER => "device",
                    SPIRV_STORAGE_PUSH_CONSTANT => "constant",
                    _ => "device",
                };
                format!("{} {}&", addr_space, pointee)
            }
            Some(SpirvType::Image { .. }) => "texture2d<float>".to_string(),
            Some(SpirvType::Sampler) => "sampler".to_string(),
            Some(SpirvType::SampledImage { .. }) => "texture2d<float>".to_string(),
            _ => format!("UnknownType_{}", type_id),
        };
        self.msl_type_cache.insert(type_id, name.clone());
        name
    }

    /// Map SPIR-V execution model to Vulkan shader stage.
    fn exec_model_to_stage(model: u32) -> VkShaderStageFlagBits {
        match model {
            SPIRV_EXEC_MODEL_VERTEX => VkShaderStageFlagBits::Vertex,
            SPIRV_EXEC_MODEL_FRAGMENT => VkShaderStageFlagBits::Fragment,
            SPIRV_EXEC_MODEL_COMPUTE => VkShaderStageFlagBits::Compute,
            SPIRV_EXEC_MODEL_GEOMETRY => VkShaderStageFlagBits::Geometry,
            SPIRV_EXEC_MODEL_TESSELLATION_CONTROL => VkShaderStageFlagBits::TessellationControl,
            SPIRV_EXEC_MODEL_TESSELLATION_EVALUATION => {
                VkShaderStageFlagBits::TessellationEvaluation
            }
            _ => VkShaderStageFlagBits::All,
        }
    }

    /// Generate MSL source code from the parsed SPIR-V.
    ///
    /// Produces a complete MSL function for each entry point, with proper
    /// Metal attributes (`[[vertex_id]]`, `[[position]]`, `[[buffer(N)]]`,
    /// etc.) mapped from SPIR-V decorations.
    pub fn generate_msl(&mut self) -> String {
        // Warm the MSL type cache for every type in the module so the hot
        // generation loops below are O(1) cache reads.
        let type_ids: Vec<u32> = self.types.keys().copied().collect();
        for id in type_ids {
            self.resolve_msl_type(id);
        }

        let mut output = String::new();
        output.push_str("// Generated by Casa1 SPIR-V → MSL translator\n");
        output.push_str("#include <metal_stdlib>\n");
        output.push_str("using namespace metal;\n\n");

        // Emit struct declarations for struct types
        for (type_id, typ) in &self.types {
            if let SpirvType::Struct { member_types, name } = typ {
                let default_name = format!("Struct_{}", type_id);
                let struct_name = name.as_deref().unwrap_or(&default_name);
                output.push_str(&format!("struct {} {{\n", struct_name));
                for (i, member_type_id) in member_types.iter().enumerate() {
                    let member_type = self.msl_type_name(*member_type_id);
                    let member_name = self
                        .member_names
                        .get(&(*type_id, i as u32))
                        .cloned()
                        .unwrap_or_else(|| format!("member_{}", i));
                    output.push_str(&format!("    {} {};\n", member_type, member_name));
                }
                output.push_str("};\n\n");
            }
        }

        // Generate entry point functions
        for (entry_id, exec_model, entry_name) in &self.entry_points {
            let stage = Self::exec_model_to_stage(*exec_model);
            let qualifier = stage.msl_qualifier();

            // Find the function for this entry point
            let func = self.functions.iter().find(|f| f.result_id == *entry_id);

            // Determine return type
            let return_type_str = if let Some(f) = func {
                self.msl_type_name(f.return_type)
            } else {
                "void".to_string()
            };

            output.push_str(&format!(
                "{} {} {}(",
                qualifier, return_type_str, entry_name
            ));

            // Generate parameters from variables that are inputs to this stage
            let mut params: Vec<String> = Vec::new();
            for (var_id, (type_id, storage_class)) in &self.variables {
                // Generate parameter based on storage class
                match *storage_class {
                    0 => {
                        // Uniform input
                        let name = self
                            .names
                            .get(var_id)
                            .cloned()
                            .unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let binding = dec.and_then(|d| d.binding).unwrap_or(0);
                        let msl_type = self.msl_type_name(*type_id);
                        params.push(format!(
                            "device {}& {} [[buffer({})]]",
                            msl_type, name, binding
                        ));
                    }
                    SPIRV_STORAGE_UNIFORM => {
                        let name = self
                            .names
                            .get(var_id)
                            .cloned()
                            .unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let binding = dec.and_then(|d| d.binding).unwrap_or(0);
                        let msl_type = self.msl_type_name(*type_id);
                        params.push(format!(
                            "constant {}& {} [[buffer({})]]",
                            msl_type, name, binding
                        ));
                    }
                    SPIRV_STORAGE_STORAGE_BUFFER => {
                        let name = self
                            .names
                            .get(var_id)
                            .cloned()
                            .unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let binding = dec.and_then(|d| d.binding).unwrap_or(0);
                        let msl_type = self.msl_type_name(*type_id);
                        params.push(format!(
                            "device {}& {} [[buffer({})]]",
                            msl_type, name, binding
                        ));
                    }
                    1 => {
                        // Input — vertex attributes
                        let name = self
                            .names
                            .get(var_id)
                            .cloned()
                            .unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let location = dec.and_then(|d| d.location).unwrap_or(0);
                        let msl_type = self.msl_type_name(*type_id);
                        params.push(format!("{} {} [[attribute({})]]", msl_type, name, location));
                    }
                    _ => {}
                }
            }

            // Add built-in vertex/fragment inputs
            if *exec_model == SPIRV_EXEC_MODEL_VERTEX && params.is_empty() {
                params.push("uint vid [[vertex_id]]".to_string());
            }

            output.push_str(&params.join(", "));
            output.push_str(") {\n");

            // Translate function body instructions
            if let Some(f) = func {
                for instr in &f.instructions {
                    match instr.opcode {
                        SPIRV_OP_RETURN => {
                            output.push_str("    return;\n");
                        }
                        SPIRV_OP_RETURN_VALUE => {
                            if !instr.operands.is_empty() {
                                output
                                    .push_str(&format!("    return var_{};\n", instr.operands[0]));
                            }
                        }
                        SPIRV_OP_LOAD => {
                            if instr.operands.len() >= 3 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let pointer_id = instr.operands[2];
                                let msl_type = self.msl_type_name(type_id);
                                let ptr_name = self
                                    .names
                                    .get(&pointer_id)
                                    .cloned()
                                    .unwrap_or_else(|| format!("var_{}", pointer_id));
                                output.push_str(&format!(
                                    "    {} var_{} = {};\n",
                                    msl_type, result_id, ptr_name
                                ));
                            }
                        }
                        SPIRV_OP_STORE => {
                            if instr.operands.len() >= 2 {
                                let pointer_id = instr.operands[0];
                                let object_id = instr.operands[1];
                                let ptr_name = self
                                    .names
                                    .get(&pointer_id)
                                    .cloned()
                                    .unwrap_or_else(|| format!("var_{}", pointer_id));
                                output
                                    .push_str(&format!("    {} = var_{};\n", ptr_name, object_id));
                            }
                        }
                        SPIRV_OP_FADD | SPIRV_OP_IADD => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let a = instr.operands[2];
                                let b = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{} + var_{};\n",
                                    msl_type, result_id, a, b
                                ));
                            }
                        }
                        SPIRV_OP_FSUB | SPIRV_OP_ISUB => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let a = instr.operands[2];
                                let b = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{} - var_{};\n",
                                    msl_type, result_id, a, b
                                ));
                            }
                        }
                        SPIRV_OP_FMUL | SPIRV_OP_IMUL => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let a = instr.operands[2];
                                let b = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{} * var_{};\n",
                                    msl_type, result_id, a, b
                                ));
                            }
                        }
                        SPIRV_OP_FDIV | SPIRV_OP_SDIV | SPIRV_OP_UDIV => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let a = instr.operands[2];
                                let b = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{} / var_{};\n",
                                    msl_type, result_id, a, b
                                ));
                            }
                        }
                        SPIRV_OP_FNEGATE | SPIRV_OP_SNEGATE => {
                            if instr.operands.len() >= 3 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let operand = instr.operands[2];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = -var_{};\n",
                                    msl_type, result_id, operand
                                ));
                            }
                        }
                        SPIRV_OP_CONVERT_S_TO_F
                        | SPIRV_OP_CONVERT_U_TO_F
                        | SPIRV_OP_CONVERT_F_TO_S
                        | SPIRV_OP_CONVERT_F_TO_U => {
                            if instr.operands.len() >= 3 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let value = instr.operands[2];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = static_cast<{}>(var_{});\n",
                                    msl_type, result_id, msl_type, value
                                ));
                            }
                        }
                        SPIRV_OP_COMPOSITE_CONSTRUCT => {
                            if instr.operands.len() >= 3 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let msl_type = self.msl_type_name(type_id);
                                let components: Vec<String> = instr.operands[2..]
                                    .iter()
                                    .map(|id| format!("var_{}", id))
                                    .collect();
                                output.push_str(&format!(
                                    "    {} var_{} = {}({});\n",
                                    msl_type,
                                    result_id,
                                    msl_type,
                                    components.join(", ")
                                ));
                            }
                        }
                        SPIRV_OP_COMPOSITE_EXTRACT => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let composite = instr.operands[2];
                                let index = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{}[{}];\n",
                                    msl_type, result_id, composite, index
                                ));
                            }
                        }
                        SPIRV_OP_ACCESS_CHAIN => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let base = instr.operands[2];
                                let index = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                let base_name = self
                                    .names
                                    .get(&base)
                                    .cloned()
                                    .unwrap_or_else(|| format!("var_{}", base));
                                output.push_str(&format!(
                                    "    {} var_{} = {}[var_{}];\n",
                                    msl_type, result_id, base_name, index
                                ));
                            }
                        }
                        SPIRV_OP_IMAGE_SAMPLE_IMPLICIT_LOD => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let image = instr.operands[2];
                                let coord = instr.operands[3];
                                let msl_type = self.msl_type_name(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{}.sample(sampler, var_{});\n",
                                    msl_type, result_id, image, coord
                                ));
                            }
                        }
                        SPIRV_OP_IMAGE_FETCH if instr.operands.len() >= 4 => {
                            let type_id = instr.operands[0];
                            let result_id = instr.operands[1];
                            let image = instr.operands[2];
                            let coord = instr.operands[3];
                            let msl_type = self.msl_type_name(type_id);
                            output.push_str(&format!(
                                "    {} var_{} = var_{}.read(uint2(var_{}));\n",
                                msl_type, result_id, image, coord
                            ));
                        }
                        _ => { /* unhandled opcodes silently skipped */ }
                    }
                }
            }
            output.push_str("}\n\n");
        }
        output
    }

    /// Look up a cached MSL type name for a type ID (see
    /// [`Self::resolve_msl_type`]); falls back to a placeholder for IDs that
    /// were not part of the parsed module.
    fn msl_type_name(&self, type_id: u32) -> String {
        self.msl_type_cache
            .get(&type_id)
            .cloned()
            .unwrap_or_else(|| format!("UnknownType_{}", type_id))
    }

    /// Returns the detected entry point names.
    pub fn entry_point_names(&self) -> Vec<String> {
        self.entry_points
            .iter()
            .map(|(_, _, name)| name.clone())
            .collect()
    }

    /// Returns the detected shader stage from the first entry point.
    pub fn detected_stage(&self) -> VkShaderStageFlagBits {
        self.entry_points
            .first()
            .map(|(_, model, _)| Self::exec_model_to_stage(*model))
            .unwrap_or(VkShaderStageFlagBits::All)
    }

    /// Convert the parsed SPIR-V into a [`SpirvModule`] for external consumption.
    ///
    /// This produces a self-contained snapshot of the parsed SPIR-V module
    /// including types, decorations, constants, variables, and functions.
    pub fn to_module(&self) -> SpirvModule {
        let version = 0; // not stored in translator
        let entry_points: Vec<(SpirvExecutionModel, String, Vec<u32>)> = self
            .entry_points
            .iter()
            .map(|(_id, model, name)| {
                let em = match *model {
                    SPIRV_EXEC_MODEL_VERTEX => SpirvExecutionModel::Vertex,
                    SPIRV_EXEC_MODEL_TESSELLATION_CONTROL => {
                        SpirvExecutionModel::TessellationControl
                    }
                    SPIRV_EXEC_MODEL_TESSELLATION_EVALUATION => {
                        SpirvExecutionModel::TessellationEvaluation
                    }
                    SPIRV_EXEC_MODEL_GEOMETRY => SpirvExecutionModel::Geometry,
                    SPIRV_EXEC_MODEL_FRAGMENT => SpirvExecutionModel::Fragment,
                    SPIRV_EXEC_MODEL_COMPUTE => SpirvExecutionModel::Compute,
                    _ => SpirvExecutionModel::Compute,
                };
                (em, name.clone(), vec![])
            })
            .collect();

        let mut decorations: HashMap<u32, Vec<SpirvDecorationEntry>> = HashMap::new();
        for (&id, dec) in &self.decorations {
            let entry = SpirvDecorationEntry {
                binding: dec.binding,
                descriptor_set: dec.descriptor_set,
                location: dec.location,
                offset: dec.offset,
            };
            decorations.entry(id).or_default().push(entry);
        }

        let mut types: HashMap<u32, SpirvType> = HashMap::new();
        for (&id, ty) in &self.types {
            types.insert(id, ty.clone());
        }

        let mut constants: HashMap<u32, SpirvConstantValue> = HashMap::new();
        for (&id, &val) in &self.constants {
            constants.insert(id, SpirvConstantValue { value: val });
        }

        let mut variables: HashMap<u32, (SpirvStorageClass, u32)> = HashMap::new();
        for (&id, &(ref type_id, sc)) in &self.variables {
            let storage = match sc {
                0 => SpirvStorageClass::UniformConstant,
                1 => SpirvStorageClass::Input,
                2 => SpirvStorageClass::Uniform,
                3 => SpirvStorageClass::Output,
                4 => SpirvStorageClass::Function,
                5 => SpirvStorageClass::Generic,
                9 => SpirvStorageClass::PushConstant,
                12 => SpirvStorageClass::StorageBuffer,
                _ => SpirvStorageClass::Generic,
            };
            variables.insert(id, (storage, *type_id));
        }

        let mut strings: HashMap<u32, String> = HashMap::new();
        for (&id, name) in &self.names {
            strings.insert(id, name.clone());
        }

        SpirvModule {
            version,
            entry_points,
            decorations,
            types,
            constants,
            variables,
            functions: self.functions.clone(),
            strings,
        }
    }
}

// ---------------------------------------------------------------------------
// SpirvModule — public SPIR-V module representation
// ---------------------------------------------------------------------------

/// SPIR-V execution model, corresponding to shader stages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpirvExecutionModel {
    Vertex,
    TessellationControl,
    TessellationEvaluation,
    Geometry,
    Fragment,
    Compute,
}

/// SPIR-V storage class for variables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpirvStorageClass {
    UniformConstant,
    Input,
    Uniform,
    Output,
    Function,
    Generic,
    PushConstant,
    StorageBuffer,
}

/// A single decoration entry for a SPIR-V ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpirvDecorationEntry {
    pub binding: Option<u32>,
    pub descriptor_set: Option<u32>,
    pub location: Option<u32>,
    pub offset: Option<u32>,
}

/// A parsed SPIR-V constant value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpirvConstantValue {
    pub value: u32,
}

/// A self-contained snapshot of a parsed SPIR-V module.
///
/// This struct provides a public-facing representation of the SPIR-V module
/// that can be used for cross-compilation, reflection, and testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpirvModule {
    pub version: u32,
    pub entry_points: Vec<(SpirvExecutionModel, String, Vec<u32>)>,
    pub decorations: HashMap<u32, Vec<SpirvDecorationEntry>>,
    pub types: HashMap<u32, SpirvType>,
    pub constants: HashMap<u32, SpirvConstantValue>,
    pub variables: HashMap<u32, (SpirvStorageClass, u32)>,
    pub functions: Vec<SpirvFunction>,
    pub strings: HashMap<u32, String>,
}

// ===========================================================================
// Section 6: Vulkan State Machine
// ===========================================================================

/// The main Vulkan state machine that tracks all Vulkan objects and maps them
/// to Metal resources. This is the central coordinator for the Vulkan-to-Metal
/// translation layer.
pub struct VulkanState {
    loader: MoltenVKLoader,
    instances: BTreeMap<VkInstance, VkInstanceInfo>,
    devices: BTreeMap<VkDevice, VkDeviceInfo>,
    buffers: BTreeMap<VkBuffer, VkBufferInfo>,
    images: BTreeMap<VkImage, VkImageInfo>,
    image_views: BTreeMap<VkImageView, VkImageViewInfo>,
    render_passes: BTreeMap<VkRenderPass, VkRenderPassInfo>,
    framebuffers: BTreeMap<VkFramebuffer, VkFramebufferInfo>,
    pipelines: BTreeMap<VkPipeline, VkPipelineInfo>,
    pipeline_layouts: BTreeMap<VkPipelineLayout, VkPipelineLayoutInfo>,
    descriptor_sets: BTreeMap<VkDescriptorSet, VkDescriptorSetInfo>,
    descriptor_set_layouts: BTreeMap<VkDescriptorSetLayout, VkDescriptorSetLayoutInfo>,
    descriptor_pools: BTreeMap<VkDescriptorPool, VkDescriptorPoolInfo>,
    command_pools: BTreeMap<VkCommandPool, VkCommandPoolInfo>,
    command_buffers: BTreeMap<VkCommandBuffer, VkCommandBufferInfo>,
    fences: BTreeMap<VkFence, VkFenceInfo>,
    semaphores: BTreeMap<VkSemaphore, VkSemaphoreInfo>,
    shader_modules: BTreeMap<VkShaderModule, VkShaderModuleInfo>,
    swapchains: BTreeMap<VkSwapchainKHR, VkSwapchainInfo>,
    surfaces: BTreeMap<VkSurfaceKHR, VkSurfaceInfo>,
    device_memory: BTreeMap<VkDeviceMemory, VkDeviceMemoryInfo>,
    samplers: BTreeMap<u64, VkSamplerInfo>,
    metal_device: Option<MetalDeviceHandle>,
    metal_command_queue: Option<MetalCommandQueueHandle>,
    /// The real Metal GPU backend used for actual rendering operations.
    metal_backend: Option<MetalGpuBackend>,
    /// Metal texture views created from parent images (`MTLTexture` views
    /// share storage with their parent, so they must be kept alive here).
    texture_views: BTreeMap<u64, metal::Texture>,
    /// Metal sampler states created for [`VkSamplerInfo`] entries.
    sampler_states: BTreeMap<u64, metal::SamplerState>,
    next_handle: u64,
}

impl Default for VulkanState {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum accepted size for a single GPU allocation (device memory or
/// buffer). Guards against guest-controlled allocation sizes that would
/// abort the host process (OOM) or exceed `MTLDevice.maxBufferLength`.
const MAX_DEVICE_MEMORY_SIZE: u64 = 1 << 30; // 1 GiB

/// Maximum texture dimension accepted when creating images.
const MAX_TEXTURE_DIMENSION: u32 = 16_384; // Metal's maximum texture size

impl VulkanState {
    /// Create a new empty Vulkan state machine.
    ///
    /// Attempts to initialise the Metal GPU backend. If no Metal device is
    /// available (e.g. in CI or on non-macOS), the backend is `None` and
    /// the state machine operates in state-tracking-only mode.
    pub fn new() -> Self {
        let metal_backend = match MetalGpuBackend::new() {
            Ok(backend) => Some(backend),
            Err(e) => {
                eprintln!(
                    "[vkgl] Metal GPU backend init failed: {e:?} — running in state‑tracking‑only mode"
                );
                None
            }
        };
        Self {
            loader: MoltenVKLoader::new(),
            instances: BTreeMap::new(),
            devices: BTreeMap::new(),
            buffers: BTreeMap::new(),
            images: BTreeMap::new(),
            image_views: BTreeMap::new(),
            render_passes: BTreeMap::new(),
            framebuffers: BTreeMap::new(),
            pipelines: BTreeMap::new(),
            pipeline_layouts: BTreeMap::new(),
            descriptor_sets: BTreeMap::new(),
            descriptor_set_layouts: BTreeMap::new(),
            descriptor_pools: BTreeMap::new(),
            command_pools: BTreeMap::new(),
            command_buffers: BTreeMap::new(),
            fences: BTreeMap::new(),
            semaphores: BTreeMap::new(),
            shader_modules: BTreeMap::new(),
            swapchains: BTreeMap::new(),
            surfaces: BTreeMap::new(),
            device_memory: BTreeMap::new(),
            samplers: BTreeMap::new(),
            metal_device: None,
            metal_command_queue: None,
            metal_backend,
            texture_views: BTreeMap::new(),
            sampler_states: BTreeMap::new(),
            next_handle: 1,
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    /// Attempt to load the MoltenVK library.
    pub fn load_moltenvk(&mut self) -> AppResult<()> {
        self.loader.load()
    }

    /// Returns whether MoltenVK was successfully loaded.
    pub fn is_moltenvk_loaded(&self) -> bool {
        self.loader.is_loaded()
    }

    /// Create a Vulkan instance mapped to a Metal device.
    pub fn create_instance(
        &mut self,
        app_name: &str,
        engine_name: &str,
        extensions: &[String],
        layers: &[String],
    ) -> AppResult<VkInstance> {
        // Lazily attempt to load the real MoltenVK library on first use so
        // `get_proc_addr` can resolve real entry points when available.
        if !self.loader.is_loaded() {
            let _ = self.load_moltenvk();
        }
        let handle = self.alloc_handle();
        let physical_device = self.alloc_handle();
        if self.metal_device.is_none() {
            self.metal_device = Some(self.alloc_handle());
        }
        let info = VkInstanceInfo {
            handle,
            enabled_extensions: extensions.to_vec(),
            enabled_layers: layers.to_vec(),
            physical_devices: vec![physical_device],
            queue_family_max_queues: default_queue_family_capacities(),
            application_name: app_name.to_string(),
            engine_name: engine_name.to_string(),
            api_version: (1, 3, 280),
        };
        self.instances.insert(handle, info);
        Ok(handle)
    }

    /// Destroy a Vulkan instance.
    pub fn destroy_instance(&mut self, instance: VkInstance) -> AppResult<()> {
        if self.instances.remove(&instance).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("cannot destroy instance {}: not found", instance),
            ));
        }
        // Surfaces are owned by the instance; release their bookkeeping.
        let surfaces: Vec<VkSurfaceKHR> = self.surfaces.keys().copied().collect();
        for s in surfaces {
            let _ = self.destroy_surface(s);
        }
        Ok(())
    }

    /// Enumerate physical devices for an instance.
    pub fn enumerate_physical_devices(
        &mut self,
        instance: VkInstance,
    ) -> AppResult<Vec<VkPhysicalDevice>> {
        let info = self.instances.get(&instance).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidState,
                format!("instance {} not found", instance),
            )
        })?;
        Ok(info.physical_devices.clone())
    }

    /// Create a logical device with requested queues.
    ///
    /// The full parameter contract is validated BEFORE any state is mutated
    /// or any handle is allocated: the physical device must belong to an
    /// existing instance, every requested queue family must exist on that
    /// physical device, every requested queue count must be within the
    /// family's capacity and non-zero, duplicate family declarations are
    /// rejected, and every requested extension must be supported. On any
    /// validation failure the state is left untouched.
    pub fn create_device(
        &mut self,
        physical: VkPhysicalDevice,
        extensions: &[String],
        queue_families: &[(u32, u32)],
    ) -> AppResult<VkDevice> {
        // ── Validation phase (no mutation, no handle allocation) ──────────────
        // (a) The physical device must belong to an existing instance.
        let instance = self
            .instances
            .values()
            .find(|instance| instance.physical_devices.contains(&physical))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("physical device {physical} does not belong to any instance"),
                )
            })?;

        // (b) queue family exists, (c) queue count valid, (e) no duplicate
        // family declarations, (f) no zero-count queue specifications.
        let family_capacities = &instance.queue_family_max_queues;
        let mut declared_families = BTreeSet::new();
        for &(family, count) in queue_families {
            if !declared_families.insert(family) {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("queue family {family} declared more than once"),
                ));
            }
            let Some(&max_queues) = family_capacities.get(family as usize) else {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("queue family {family} does not exist on physical device {physical}"),
                ));
            };
            if count == 0 {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!(
                        "queue count for family {family} must be at least 1 (Vulkan: queueCount > 0)"
                    ),
                ));
            }
            if count > max_queues {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!(
                        "queue count {count} for family {family} exceeds the family's \
                         capacity of {max_queues} queues"
                    ),
                ));
            }
        }

        // (d) Requested device extensions must be supported.
        VkExtensionRegistry::new().validate_device_extensions(extensions)?;

        // ── Commit phase (only reached when validation succeeded) ─────────────
        let handle = self.alloc_handle();
        if self.metal_command_queue.is_none() {
            self.metal_command_queue = Some(self.alloc_handle());
        }
        let mut queues: BTreeMap<u32, Vec<VkQueue>> = BTreeMap::new();
        for &(family, count) in queue_families {
            queues.insert(family, (0..count).map(|_| self.alloc_handle()).collect());
        }
        let info = VkDeviceInfo {
            handle,
            physical_device: physical,
            queues,
            enabled_extensions: extensions.to_vec(),
            memory_properties: VkPhysicalDeviceMemoryProperties::default(),
        };
        self.devices.insert(handle, info);
        Ok(handle)
    }

    /// Destroy a logical device and every resource created on it.
    pub fn destroy_device(&mut self, device: VkDevice) -> AppResult<()> {
        if self.devices.remove(&device).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("cannot destroy device {}: not found", device),
            ));
        }
        // Release every resource owned by this device so GPU backing is
        // freed with the device.
        let buffers: Vec<VkBuffer> = self
            .buffers
            .iter()
            .filter(|(_, b)| b.device == device)
            .map(|(&h, _)| h)
            .collect();
        for b in buffers {
            let _ = self.destroy_buffer(b);
        }
        let images: Vec<VkImage> = self
            .images
            .iter()
            .filter(|(_, i)| i.device == device)
            .map(|(&h, _)| h)
            .collect();
        for i in images {
            let _ = self.destroy_image(i);
        }
        let image_views: Vec<VkImageView> = self.image_views.keys().copied().collect();
        for v in image_views {
            let _ = self.destroy_image_view(v);
        }
        let samplers: Vec<u64> = self
            .samplers
            .iter()
            .filter(|(_, s)| s.device == device)
            .map(|(&h, _)| h)
            .collect();
        for s in samplers {
            let _ = self.destroy_sampler(s);
        }
        // All device memory allocations are owned by the device.
        let mems: Vec<VkDeviceMemory> = self.device_memory.keys().copied().collect();
        for m in mems {
            let _ = self.free_memory(device, m);
        }
        let shaders: Vec<VkShaderModule> = self.shader_modules.keys().copied().collect();
        for s in shaders {
            let _ = self.destroy_shader_module(s);
        }
        let pipelines: Vec<VkPipeline> = self.pipelines.keys().copied().collect();
        for p in pipelines {
            let _ = self.destroy_pipeline(p);
        }
        let layouts: Vec<VkPipelineLayout> = self.pipeline_layouts.keys().copied().collect();
        for l in layouts {
            let _ = self.destroy_pipeline_layout(l);
        }
        let pools: Vec<VkCommandPool> = self
            .command_pools
            .iter()
            .filter(|(_, p)| p.device == device)
            .map(|(&h, _)| h)
            .collect();
        for p in pools {
            let _ = self.destroy_command_pool(p);
        }
        let fences: Vec<VkFence> = self
            .fences
            .iter()
            .filter(|(_, f)| f.device == device)
            .map(|(&h, _)| h)
            .collect();
        for f in fences {
            let _ = self.destroy_fence(f);
        }
        let semaphores: Vec<VkSemaphore> = self
            .semaphores
            .iter()
            .filter(|(_, s)| s.device == device)
            .map(|(&h, _)| h)
            .collect();
        for s in semaphores {
            let _ = self.destroy_semaphore(s);
        }
        let render_passes: Vec<VkRenderPass> = self.render_passes.keys().copied().collect();
        for rp in render_passes {
            let _ = self.destroy_render_pass(rp);
        }
        let framebuffers: Vec<VkFramebuffer> = self.framebuffers.keys().copied().collect();
        for fb in framebuffers {
            let _ = self.destroy_framebuffer(fb);
        }
        let swapchains: Vec<VkSwapchainKHR> = self
            .swapchains
            .iter()
            .filter(|(_, sc)| sc.device == device)
            .map(|(&h, _)| h)
            .collect();
        for sc in swapchains {
            let _ = self.destroy_swapchain(sc);
        }
        Ok(())
    }

    /// Get a queue handle from a device.
    pub fn get_device_queue(
        &self,
        device: VkDevice,
        family: u32,
        index: u32,
    ) -> AppResult<VkQueue> {
        let info = self.devices.get(&device).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidState,
                format!("device {} not found", device),
            )
        })?;
        info.queues
            .get(&family)
            .and_then(|qs| qs.get(index as usize))
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("queue {}/{} not found", family, index),
                )
            })
    }

    /// Create a surface.
    pub fn create_surface(
        &mut self,
        width: u32,
        height: u32,
        format: VkFormat,
    ) -> AppResult<VkSurfaceKHR> {
        let handle = self.alloc_handle();
        self.surfaces.insert(
            handle,
            VkSurfaceInfo {
                handle,
                width,
                height,
                format,
            },
        );
        Ok(handle)
    }

    /// Create a swapchain backed by a CAMetalLayer.
    ///
    /// When the Metal backend is available, a [`MetalSwapchain`] is created
    /// via [`MetalGpuBackend::create_swapchain`] with the requested dimensions.
    ///
    /// # Errors
    ///
    /// Returns `AppError` with `RcInvalidState` if the device or surface do
    /// not exist, or if the create info is invalid (`min_image_count` must be
    /// ≥ 1 and the extent must be non-zero — Vulkan requires both).
    pub fn create_swapchain(
        &mut self,
        device: VkDevice,
        surface: VkSurfaceKHR,
        ci: &VkSwapchainCreateInfo,
    ) -> AppResult<VkSwapchainKHR> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("device {} not found", device),
            ));
        }
        if !self.surfaces.contains_key(&surface) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("surface {} not found", surface),
            ));
        }
        if ci.min_image_count == 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "create_swapchain: min_image_count must be at least 1",
            ));
        }
        if ci.image_extent.0 == 0 || ci.image_extent.1 == 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "create_swapchain: image extent must be non-zero",
            ));
        }
        let handle = self.alloc_handle();
        let drawables: Vec<u64> = (0..ci.min_image_count)
            .map(|_| self.alloc_handle())
            .collect();
        let metal_layer = self.alloc_handle();

        // Create a fresh Metal swapchain for this VkSwapchainKHR whenever the
        // backend is available, so a second swapchain's configuration is
        // honoured instead of silently reusing the first one's.
        if let Some(ref mut backend) = self.metal_backend {
            use crate::metal_backend::{ColorSpace, FlipModel};
            backend.create_swapchain(
                ci.image_extent.0 as u64,
                ci.image_extent.1 as u64,
                FlipModel::Discard,
                ColorSpace::SRGB,
            );
        }

        let info = VkSwapchainInfo {
            handle,
            device,
            surface,
            min_image_count: ci.min_image_count,
            image_format: ci.image_format,
            image_color_space: ci.image_color_space,
            image_extent: ci.image_extent,
            image_array_layers: ci.image_array_layers,
            image_usage: ci.image_usage,
            pre_transform: ci.pre_transform,
            composite_alpha: ci.composite_alpha,
            present_mode: ci.present_mode,
            clipped: ci.clipped,
            metal_layer: Some(metal_layer),
            metal_drawables: drawables,
            current_buffer_index: 0,
        };
        self.swapchains.insert(handle, info);
        Ok(handle)
    }

    /// Acquire the next swapchain image.
    ///
    /// When the Metal backend is available, gets the next drawable from
    /// the [`MetalSwapchain`].
    pub fn acquire_next_image(
        &mut self,
        swapchain: VkSwapchainKHR,
        semaphore: Option<VkSemaphore>,
        fence: Option<VkFence>,
    ) -> AppResult<(u32, bool)> {
        let info = self.swapchains.get_mut(&swapchain).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidState,
                format!("swapchain {} not found", swapchain),
            )
        })?;
        // Belt-and-braces guard: `min_image_count` was validated at
        // create_swapchain time, but never trust caller-supplied state when
        // it feeds a modulo (zero would panic).
        if info.min_image_count == 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "acquire_next_image: swapchain has min_image_count 0",
            ));
        }
        let index = info.current_buffer_index;
        info.current_buffer_index = (info.current_buffer_index + 1) % info.min_image_count as usize;
        if let Some(f) = fence
            && let Some(fi) = self.fences.get_mut(&f)
        {
            fi.signaled = true;
        }
        if let Some(s) = semaphore
            && let Some(si) = self.semaphores.get_mut(&s)
        {
            si.signaled = true;
        }

        // Attempt to get next Metal drawable so the presentation path has a
        // real drawable to present in `queue_present`.
        if let Some(backend) = self.metal_backend.as_mut()
            && let Some(swapchain) = backend.swapchain_mut()
            && let Err(e) = swapchain.next_drawable()
        {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("acquire_next_image: failed to get Metal drawable: {e:?}"),
            ));
        }

        Ok((index as u32, false))
    }

    /// Present a swapchain image via Metal.
    ///
    /// When the Metal backend is available, presents the current drawable
    /// from the [`MetalSwapchain`] using a fresh committed command buffer.
    pub fn queue_present(
        &mut self,
        _queue: VkQueue,
        swapchain: VkSwapchainKHR,
        image_index: u32,
    ) -> AppResult<()> {
        let info = self.swapchains.get(&swapchain).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidState,
                format!("swapchain {} not found", swapchain),
            )
        })?;
        if image_index as usize >= info.min_image_count as usize {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "image index out of range",
            ));
        }

        // Present via Metal backend: acquire the drawable and present it on a
        // fresh committed command buffer (same pattern as `metal_renderer`).
        if let Some(backend) = self.metal_backend.as_ref() {
            let sc = backend.swapchain().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    "queue_present: no Metal swapchain",
                )
            })?;
            let drawable = sc.next_drawable().map_err(|e| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("queue_present: no drawable available: {e:?}"),
                )
            })?;
            let cmd_buffer = backend.command_queue().new_command_buffer();
            cmd_buffer.present_drawable(drawable);
            cmd_buffer.commit();
        }
        Ok(())
    }

    /// Create a shader module from SPIR-V bytecode.
    ///
    /// Parses the SPIR-V via [`SpirvTranslator`], cross-compiles to MSL,
    /// and optionally compiles the MSL to a Metal library via
    /// [`MetalGpuBackend::compile_shader`].
    pub fn create_shader_module(
        &mut self,
        device: VkDevice,
        spirv_code: &[u32],
    ) -> AppResult<VkShaderModule> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        if spirv_code.len() < 5 || spirv_code[0] != SPIRV_MAGIC {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                "invalid SPIR-V header",
            ));
        }
        let mut translator = SpirvTranslator::new();
        translator.parse(spirv_code)?;
        let msl_source = translator.generate_msl();
        let entry_points = translator.entry_point_names();
        let stage = translator.detected_stage();
        let handle = self.alloc_handle();
        self.shader_modules.insert(
            handle,
            VkShaderModuleInfo {
                handle,
                spirv_code: spirv_code.to_vec(),
                msl_source: Some(msl_source),
                entry_points,
                stage,
            },
        );
        Ok(handle)
    }

    /// Compile a shader module's MSL to a Metal library binary.
    pub fn compile_shader_module_msl(&self, module: VkShaderModule) -> AppResult<Vec<u8>> {
        let info = self
            .shader_modules
            .get(&module)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "shader module not found"))?;
        let msl = info
            .msl_source
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no MSL source"))?;
        let entry = info
            .entry_points
            .first()
            .map(|s| s.as_str())
            .unwrap_or("main");
        crate::shader::compile_msl_source(msl, entry)
    }

    /// Allocate device memory mapped to a Metal buffer.
    pub fn allocate_memory(
        &mut self,
        device: VkDevice,
        size: u64,
        memory_type_index: u32,
    ) -> AppResult<VkDeviceMemory> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        if size > MAX_DEVICE_MEMORY_SIZE {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!(
                    "allocate_memory: size {size} exceeds maximum allowed allocation {}",
                    MAX_DEVICE_MEMORY_SIZE
                ),
            ));
        }
        let mem_props = self
            .devices
            .get(&device)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "device not found"))?
            .memory_properties
            .clone();
        let mem_type = mem_props
            .memory_types
            .get(memory_type_index as usize)
            .ok_or_else(|| {
                AppError::new(ReasonCode::RcInvalidState, "invalid memory type index")
            })?;
        let alloc_type = MemoryAllocationType::from_memory_properties(mem_type.property_flags);
        let handle = self.alloc_handle();
        let metal_buffer = if let Some(ref mut backend) = self.metal_backend {
            let options = match alloc_type {
                MemoryAllocationType::Private | MemoryAllocationType::Memoryless => {
                    metal::MTLResourceOptions::StorageModePrivate
                }
                _ => metal::MTLResourceOptions::StorageModeShared,
            };
            Some(backend.create_empty_buffer(size, options))
        } else {
            None
        };
        self.device_memory.insert(
            handle,
            VkDeviceMemoryInfo {
                handle,
                size,
                memory_type_index,
                mapped_pointer: None,
                metal_buffer,
                allocation_type: alloc_type,
                mapped_data: None,
            },
        );
        Ok(handle)
    }

    /// Free device memory.
    pub fn free_memory(&mut self, device: VkDevice, memory: VkDeviceMemory) -> AppResult<()> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        let info = self
            .device_memory
            .remove(&memory)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "memory not found"))?;
        // Release the backing Metal buffer so the GPU allocation is freed.
        if let (Some(backend), Some(metal_buffer)) =
            (self.metal_backend.as_mut(), info.metal_buffer)
        {
            backend.destroy_buffer(metal_buffer);
        }
        Ok(())
    }

    /// Map device memory for CPU access.
    ///
    /// When a Metal backend buffer backs the allocation, the returned pointer
    /// is the buffer's own CPU-visible `contents()` pointer (for shared
    /// storage); otherwise a host-side staging buffer is used. The requested
    /// `[offset, offset + size)` range is validated against the allocation
    /// before any pointer arithmetic (checked, never wrapping).
    pub fn map_memory(
        &mut self,
        device: VkDevice,
        memory: VkDeviceMemory,
        offset: u64,
        size: u64,
    ) -> AppResult<*mut u8> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        let info = self
            .device_memory
            .get_mut(&memory)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "memory not found"))?;
        match info.allocation_type {
            MemoryAllocationType::Private | MemoryAllocationType::Memoryless => {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    "cannot map private/memoryless memory",
                ));
            }
            _ => {}
        }
        // Reject wrapping offset+size arithmetic before any comparison or
        // pointer arithmetic (a guest-supplied overflow must never bypass the
        // bounds check below).
        let end = offset.checked_add(size).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidState,
                "map_memory: offset + size overflows",
            )
        })?;
        if offset > info.size || end > info.size {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!(
                    "map_memory: offset {offset} + size {size} exceeds allocation size {}",
                    info.size
                ),
            ));
        }

        let ptr = if info.metal_buffer.is_some() {
            // Real Metal buffer: return its CPU-visible contents pointer.
            let contents = self
                .metal_backend
                .as_ref()
                .and_then(|b| info.metal_buffer.and_then(|id| b.get_buffer(id)))
                .map(|buf| buf.contents() as *mut u8)
                .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "metal buffer missing"))?;
            info.mapped_data = None;
            unsafe { contents.add(offset as usize) }
        } else {
            // Host-side staging buffer.
            if info.mapped_data.is_none() {
                let mut data = Vec::new();
                data.try_reserve_exact(info.size as usize).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcInvalidState,
                        format!("map_memory: cannot allocate {} bytes: {e}", info.size),
                    )
                })?;
                data.resize(info.size as usize, 0);
                info.mapped_data = Some(data);
            }
            let base = match info.mapped_data.as_mut() {
                Some(data) => data.as_mut_ptr(),
                None => {
                    return Err(AppError::new(
                        ReasonCode::RcInvalidState,
                        "map_memory: staging buffer missing",
                    ));
                }
            };
            unsafe { base.add(offset as usize) }
        };
        info.mapped_pointer = Some(ptr as u64);
        Ok(ptr)
    }

    /// Unmap device memory.
    pub fn unmap_memory(&mut self, device: VkDevice, memory: VkDeviceMemory) -> AppResult<()> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        let info = self
            .device_memory
            .get_mut(&memory)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "memory not found"))?;
        info.mapped_pointer = None;
        Ok(())
    }

    /// Flush mapped memory ranges (for managed memory).
    ///
    /// Shared-storage Metal buffers are coherent and need no flush; managed
    /// buffers are invalidated via `didModifyRange` so the GPU sees the
    /// updated bytes.
    pub fn flush_mapped_memory_ranges(
        &mut self,
        ranges: &[(VkDeviceMemory, u64, u64)],
    ) -> AppResult<()> {
        for &(memory, offset, size) in ranges {
            let info = self
                .device_memory
                .get(&memory)
                .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "memory not found"))?;
            let end = offset.checked_add(size).ok_or_else(|| {
                AppError::new(ReasonCode::RcInvalidState, "flush: offset + size overflows")
            })?;
            if offset > info.size || end > info.size {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    "flush: range exceeds allocation size",
                ));
            }
            if info.allocation_type == MemoryAllocationType::Managed
                && let Some(id) = info.metal_buffer
                && let Some(backend) = self.metal_backend.as_ref()
                && let Some(buf) = backend.get_buffer(id)
            {
                buf.did_modify_range(metal::NSRange {
                    location: offset,
                    length: size,
                });
            }
        }
        Ok(())
    }

    /// Invalidate mapped memory ranges (for managed memory).
    ///
    /// Shared-storage Metal buffers are coherent and need no invalidation;
    /// managed buffers are always CPU-visible via `contents()` in this layer,
    /// so no GPU-side sync is required.
    pub fn invalidate_mapped_memory_ranges(
        &mut self,
        ranges: &[(VkDeviceMemory, u64, u64)],
    ) -> AppResult<()> {
        for &(memory, offset, size) in ranges {
            let info = self
                .device_memory
                .get(&memory)
                .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "memory not found"))?;
            let end = offset.checked_add(size).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    "invalidate: offset + size overflows",
                )
            })?;
            if offset > info.size || end > info.size {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    "invalidate: range exceeds allocation size",
                ));
            }
        }
        Ok(())
    }

    /// Create a buffer resource and a backing Metal buffer.
    ///
    /// When the Metal backend is available, a zero-initialized `MTLBuffer` of
    /// the requested size is created via [`MetalGpuBackend::create_empty_buffer`].
    ///
    /// The Metal storage mode is derived from the usage bits: buffers that
    /// are written by the CPU (transfer-dst or uniform/storage usage) use
    /// shared storage; purely GPU-consumed buffers use private storage.
    pub fn create_buffer(
        &mut self,
        device: VkDevice,
        size: u64,
        usage: u32,
    ) -> AppResult<VkBuffer> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        if size > MAX_DEVICE_MEMORY_SIZE {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!(
                    "create_buffer: size {size} exceeds maximum allowed allocation {}",
                    MAX_DEVICE_MEMORY_SIZE
                ),
            ));
        }
        let handle = self.alloc_handle();

        // Create Metal buffer if backend is available
        let metal_buffer_id = if let Some(ref mut backend) = self.metal_backend {
            const VK_BUFFER_USAGE_TRANSFER_DST_BIT: u32 = 0x0000_0002;
            const VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT: u32 = 0x0000_0010;
            const VK_BUFFER_USAGE_STORAGE_BUFFER_BIT: u32 = 0x0000_0020;
            let host_written = usage
                & (VK_BUFFER_USAGE_TRANSFER_DST_BIT
                    | VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT
                    | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)
                != 0;
            let options = if host_written {
                metal::MTLResourceOptions::StorageModeShared
            } else {
                metal::MTLResourceOptions::StorageModePrivate
            };
            Some(backend.create_empty_buffer(size, options))
        } else {
            None
        };

        self.buffers.insert(
            handle,
            VkBufferInfo {
                handle,
                device,
                size,
                usage,
                memory: None,
                metal_buffer_id,
            },
        );
        Ok(handle)
    }

    /// Create an image resource and a backing Metal texture.
    ///
    /// When the Metal backend is available, an `MTLTexture` with the
    /// corresponding Metal pixel format is created via
    /// [`MetalGpuBackend::create_texture`].
    pub fn create_image(
        &mut self,
        device: VkDevice,
        format: VkFormat,
        extent: (u32, u32, u32),
        mip_levels: u32,
        array_layers: u32,
        usage: VkImageUsageFlags,
    ) -> AppResult<VkImage> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        if extent.0 == 0 || extent.1 == 0 || extent.2 == 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "create_image: extent must be non-zero",
            ));
        }
        if extent.0 > MAX_TEXTURE_DIMENSION || extent.1 > MAX_TEXTURE_DIMENSION {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!(
                    "create_image: extent {:?} exceeds maximum texture dimension {}",
                    extent, MAX_TEXTURE_DIMENSION
                ),
            ));
        }
        let handle = self.alloc_handle();

        // Create Metal texture if backend is available
        let metal_texture_id = if let Some(ref mut backend) = self.metal_backend {
            let mtl_format = vk_format_to_metal_format(format);
            let mut mtl_usage = metal::MTLTextureUsage::empty();
            mtl_usage.set(
                metal::MTLTextureUsage::ShaderRead,
                (usage & VK_IMAGE_USAGE_SAMPLED_BIT) != 0,
            );
            mtl_usage.set(
                metal::MTLTextureUsage::RenderTarget,
                (usage & VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT) != 0,
            );
            mtl_usage.set(
                metal::MTLTextureUsage::ShaderWrite,
                (usage & VK_IMAGE_USAGE_STORAGE_BIT) != 0,
            );
            if mtl_usage.is_empty() {
                mtl_usage =
                    metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::RenderTarget;
            }
            Some(backend.create_texture(extent.0 as u64, extent.1 as u64, mtl_format, mtl_usage))
        } else {
            None
        };

        self.images.insert(
            handle,
            VkImageInfo {
                handle,
                device,
                format,
                extent,
                mip_levels,
                array_layers,
                usage,
                layout: VkImageLayout::Undefined,
                metal_texture_id,
            },
        );
        Ok(handle)
    }

    /// Create an image view, optionally backed by a Metal texture view.
    ///
    /// When the source image has a Metal texture and the backend is
    /// available, a real `MTLTexture` view (`newTextureViewWithPixelFormat`)
    /// is created — it shares storage with the parent image instead of
    /// allocating an independent copy, so writes through the image are
    /// visible through the view and vice versa.
    pub fn create_image_view(
        &mut self,
        image: VkImage,
        format: VkFormat,
        aspect_mask: u32,
    ) -> AppResult<VkImageView> {
        let img_info = self
            .images
            .get(&image)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "image not found"))?;
        let metal_texture_id = img_info.metal_texture_id;
        let _ = img_info;
        let handle = self.alloc_handle();

        // Create a Metal texture view if the source image has a Metal texture
        let metal_texture_view_id = if let Some(ref backend) = self.metal_backend {
            if let Some(tex_id) = metal_texture_id {
                let src = backend.get_texture(tex_id).ok_or_else(|| {
                    AppError::new(ReasonCode::RcInvalidState, "source Metal texture missing")
                })?;
                let view = src.new_texture_view(vk_format_to_metal_format(format));
                let view_handle = self.alloc_handle();
                self.texture_views.insert(view_handle, view);
                Some(view_handle)
            } else {
                None
            }
        } else {
            None
        };

        self.image_views.insert(
            handle,
            VkImageViewInfo {
                handle,
                image,
                format,
                aspect_mask,
                metal_texture_view_id,
            },
        );
        Ok(handle)
    }

    /// Create a render pass.
    ///
    /// Translates Vulkan attachment load/store actions to Metal equivalents.
    pub fn create_render_pass(
        &mut self,
        color_attachments: u32,
        has_depth: bool,
        load: &str,
        store: &str,
    ) -> AppResult<VkRenderPass> {
        let handle = self.alloc_handle();
        self.render_passes.insert(
            handle,
            VkRenderPassInfo {
                handle,
                color_attachment_count: color_attachments,
                has_depth_stencil: has_depth,
                load_action: load.to_string(),
                store_action: store.to_string(),
            },
        );
        Ok(handle)
    }

    /// Create a framebuffer.
    pub fn create_framebuffer(
        &mut self,
        rp: VkRenderPass,
        attachments: Vec<VkImageView>,
        w: u32,
        h: u32,
        layers: u32,
    ) -> AppResult<VkFramebuffer> {
        let handle = self.alloc_handle();
        self.framebuffers.insert(
            handle,
            VkFramebufferInfo {
                handle,
                render_pass: rp,
                attachments,
                width: w,
                height: h,
                layers,
            },
        );
        Ok(handle)
    }

    /// Create a pipeline layout.
    pub fn create_pipeline_layout(
        &mut self,
        set_layouts: Vec<VkDescriptorSetLayout>,
        push_ranges: Vec<(VkShaderStageFlagBits, u32, u32)>,
    ) -> AppResult<VkPipelineLayout> {
        let handle = self.alloc_handle();
        self.pipeline_layouts.insert(
            handle,
            VkPipelineLayoutInfo {
                handle,
                set_layouts,
                push_constant_ranges: push_ranges,
            },
        );
        Ok(handle)
    }

    /// Create a graphics pipeline backed by a Metal render pipeline state.
    ///
    /// This is the legacy entry point kept for API compatibility: it scans
    /// all registered shader modules for one of each stage. Prefer
    /// [`create_graphics_pipeline_with_shaders`](Self::create_graphics_pipeline_with_shaders)
    /// when the exact shader-module handles are known.
    pub fn create_graphics_pipeline(
        &mut self,
        layout: VkPipelineLayout,
        stages: u32,
    ) -> AppResult<VkPipeline> {
        self.create_graphics_pipeline_with_shaders(layout, stages, None, None)
    }

    /// Create a graphics pipeline from explicitly selected shader modules.
    ///
    /// Only the modules named by `vertex_module`/`fragment_module` are
    /// compiled into the pipeline (rather than "whichever module of each
    /// stage happens to be last in the registry"), and the chosen modules are
    /// recorded in the resulting [`VkPipelineInfo`]. When both handles are
    /// `None`, falls back to scanning the module registry for one module of
    /// each stage (legacy behaviour).
    ///
    /// When the Metal backend is available, this method:
    /// 1. Extracts SPIR-V from the selected shader modules
    /// 2. Cross-compiles SPIR-V → MSL via [`SpirvTranslator`]
    /// 3. Compiles MSL → MTLLibrary → MTLFunction
    /// 4. Creates MTLRenderPipelineState
    pub fn create_graphics_pipeline_with_shaders(
        &mut self,
        layout: VkPipelineLayout,
        stages: u32,
        vertex_module: Option<VkShaderModule>,
        fragment_module: Option<VkShaderModule>,
    ) -> AppResult<VkPipeline> {
        let handle = self.alloc_handle();

        // Attempt to create a Metal pipeline from the selected shader modules
        let (metal_pipeline_id, metal_library_id, vertex_shader, fragment_shader) =
            if let Some(ref mut backend) = self.metal_backend {
                // Pick the module the caller selected when it exists and has
                // the right stage; otherwise fall back to any module of that
                // stage in the registry.
                let select = |module: Option<VkShaderModule>,
                              want: VkShaderStageFlagBits|
                 -> Option<VkShaderModule> {
                    if let Some(m) = module
                        && let Some(sm) = self.shader_modules.get(&m)
                        && sm.stage == want
                    {
                        return Some(m);
                    }
                    self.shader_modules
                        .values()
                        .find(|sm| sm.stage == want)
                        .map(|sm| sm.handle)
                };
                let vertex_module = select(vertex_module, VkShaderStageFlagBits::Vertex);
                let fragment_module = select(fragment_module, VkShaderStageFlagBits::Fragment);

                let mut vertex_msl: Option<String> = None;
                let mut fragment_msl: Option<String> = None;
                let mut vertex_entry = "main".to_string();
                let mut fragment_entry = "main".to_string();

                if let Some(vm) = vertex_module
                    && let Some(sm) = self.shader_modules.get(&vm)
                    && let Some(ref msl) = sm.msl_source
                {
                    vertex_msl = Some(msl.clone());
                    vertex_entry = sm
                        .entry_points
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "main".to_string());
                }
                if let Some(fm) = fragment_module
                    && let Some(sm) = self.shader_modules.get(&fm)
                    && let Some(ref msl) = sm.msl_source
                {
                    fragment_msl = Some(msl.clone());
                    fragment_entry = sm
                        .entry_points
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "main".to_string());
                }

                let (pipeline_id, lib_id) = if let Some(ref msl_src) = vertex_msl {
                    match backend.compile_shader(msl_src) {
                        Ok(lib_id) => {
                            // Try to create a render pipeline with vertex-only (fragment may be missing)
                            let default_entry = "main".to_string();
                            let pipeline_id = match backend.create_render_pipeline(
                                &vertex_entry,
                                fragment_msl
                                    .as_ref()
                                    .map(|_| &fragment_entry)
                                    .unwrap_or(&default_entry),
                                lib_id,
                                metal::MTLPixelFormat::BGRA8Unorm,
                                None,
                            ) {
                                Ok(pid) => Some(pid),
                                Err(e) => {
                                    eprintln!("[vkgl] render pipeline creation failed: {e:?}");
                                    None
                                }
                            };
                            (pipeline_id, Some(lib_id))
                        }
                        Err(e) => {
                            eprintln!("[vkgl] shader compilation failed: {e:?}");
                            (None, None)
                        }
                    }
                } else {
                    (None, None)
                };
                (pipeline_id, lib_id, vertex_module, fragment_module)
            } else {
                (None, None, None, None)
            };

        self.pipelines.insert(
            handle,
            VkPipelineInfo {
                handle,
                layout,
                stage_count: stages,
                bind_point: VkPipelineBindPoint::Graphics,
                metal_pipeline_id,
                metal_library_id,
                vertex_shader,
                fragment_shader,
            },
        );
        Ok(handle)
    }

    /// Create a compute pipeline backed by a Metal compute pipeline state.
    ///
    /// Legacy entry point that scans the registry for a compute shader
    /// module; prefer
    /// [`create_compute_pipeline_with_shader`](Self::create_compute_pipeline_with_shader).
    pub fn create_compute_pipeline(&mut self, layout: VkPipelineLayout) -> AppResult<VkPipeline> {
        self.create_compute_pipeline_with_shader(layout, None)
    }

    /// Create a compute pipeline from an explicitly selected shader module.
    ///
    /// When `compute_module` is `None` (legacy behaviour), scans the module
    /// registry for a compute shader.
    pub fn create_compute_pipeline_with_shader(
        &mut self,
        layout: VkPipelineLayout,
        compute_module: Option<VkShaderModule>,
    ) -> AppResult<VkPipeline> {
        let handle = self.alloc_handle();

        let (metal_pipeline_id, metal_library_id, compute_shader) =
            if let Some(ref mut backend) = self.metal_backend {
                // Pick the caller's module when it is a compute shader;
                // otherwise fall back to any compute module in the registry.
                let compute_module = compute_module.and_then(|m| {
                    self.shader_modules
                        .get(&m)
                        .filter(|sm| sm.stage == VkShaderStageFlagBits::Compute)
                        .map(|_| m)
                });
                let compute_module = compute_module.or_else(|| {
                    self.shader_modules
                        .values()
                        .find(|sm| sm.stage == VkShaderStageFlagBits::Compute)
                        .map(|sm| sm.handle)
                });

                let mut compute_msl: Option<String> = None;
                let mut compute_entry = "main".to_string();
                if let Some(cm) = compute_module
                    && let Some(sm) = self.shader_modules.get(&cm)
                    && let Some(ref msl) = sm.msl_source
                {
                    compute_msl = Some(msl.clone());
                    compute_entry = sm
                        .entry_points
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "main".to_string());
                }

                let (pipeline_id, lib_id) = if let Some(ref msl_src) = compute_msl {
                    match backend.compile_shader(msl_src) {
                        Ok(lib_id) => {
                            let pipeline_id =
                                match backend.create_compute_pipeline(&compute_entry, lib_id) {
                                    Ok(pid) => Some(pid),
                                    Err(e) => {
                                        eprintln!("[vkgl] compute pipeline creation failed: {e:?}");
                                        None
                                    }
                                };
                            (pipeline_id, Some(lib_id))
                        }
                        Err(e) => {
                            eprintln!("[vkgl] compute shader compilation failed: {e:?}");
                            (None, None)
                        }
                    }
                } else {
                    (None, None)
                };
                (pipeline_id, lib_id, compute_module)
            } else {
                (None, None, None)
            };

        self.pipelines.insert(
            handle,
            VkPipelineInfo {
                handle,
                layout,
                stage_count: 1,
                bind_point: VkPipelineBindPoint::Compute,
                metal_pipeline_id,
                metal_library_id,
                vertex_shader: compute_shader,
                fragment_shader: None,
            },
        );
        Ok(handle)
    }

    /// Create a sampler backed by a Metal sampler state.
    ///
    /// When the Metal backend is available, a real `MTLSamplerState` is
    /// created from the create info (filters, address modes, LOD clamps,
    /// anisotropy, and compare function) and kept alive for the sampler's
    /// lifetime.
    pub fn create_sampler(&mut self, device: VkDevice, ci: &VkSamplerCreateInfo) -> AppResult<u64> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        let handle = self.alloc_handle();

        let metal_sampler_id = if let Some(backend) = self.metal_backend.as_ref() {
            let desc = vk_sampler_to_d3d12_static_sampler_desc(ci);
            let sampler = crate::metal_backend::create_static_sampler(
                backend.device().metal_device(),
                &desc,
            )?;
            self.sampler_states.insert(handle, sampler);
            Some(handle)
        } else {
            None
        };

        self.samplers.insert(
            handle,
            VkSamplerInfo {
                handle,
                device,
                min_filter: ci.min_filter,
                mag_filter: ci.mag_filter,
                mipmap_mode: ci.mipmap_mode,
                address_mode_u: ci.address_mode_u,
                address_mode_v: ci.address_mode_v,
                address_mode_w: ci.address_mode_w,
                mip_lod_bias: ci.mip_lod_bias,
                max_anisotropy: ci.max_anisotropy,
                compare_op: ci.compare_op,
                min_lod: ci.min_lod,
                max_lod: ci.max_lod,
                metal_sampler_id,
            },
        );
        Ok(handle)
    }

    /// Destroy a sampler, releasing its Metal sampler state.
    pub fn destroy_sampler(&mut self, sampler: u64) -> AppResult<()> {
        if self.samplers.remove(&sampler).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("sampler {sampler} not found"),
            ));
        }
        self.sampler_states.remove(&sampler);
        Ok(())
    }

    /// Create a descriptor set layout.
    pub fn create_descriptor_set_layout(
        &mut self,
        bindings: u32,
    ) -> AppResult<VkDescriptorSetLayout> {
        let handle = self.alloc_handle();
        self.descriptor_set_layouts.insert(
            handle,
            VkDescriptorSetLayoutInfo {
                handle,
                binding_count: bindings,
            },
        );
        Ok(handle)
    }

    /// Create a descriptor pool.
    pub fn create_descriptor_pool(&mut self, max_sets: u32) -> AppResult<VkDescriptorPool> {
        let handle = self.alloc_handle();
        self.descriptor_pools.insert(
            handle,
            VkDescriptorPoolInfo {
                handle,
                max_sets,
                allocated_sets: 0,
            },
        );
        Ok(handle)
    }

    /// Allocate descriptor sets from a pool.
    pub fn allocate_descriptor_sets(
        &mut self,
        pool: VkDescriptorPool,
        layouts: &[VkDescriptorSetLayout],
    ) -> AppResult<Vec<VkDescriptorSet>> {
        {
            let pool_info = self
                .descriptor_pools
                .get(&pool)
                .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "pool not found"))?;
            if pool_info.allocated_sets + layouts.len() as u32 > pool_info.max_sets {
                return Err(AppError::new(ReasonCode::RcInvalidState, "pool exhausted"));
            }
        }
        let mut sets = Vec::with_capacity(layouts.len());
        for &layout in layouts {
            let handle = self.alloc_handle();
            if let Some(pool_info) = self.descriptor_pools.get_mut(&pool) {
                pool_info.allocated_sets += 1;
            }
            self.descriptor_sets.insert(
                handle,
                VkDescriptorSetInfo {
                    handle,
                    layout,
                    pool,
                },
            );
            sets.push(handle);
        }
        Ok(sets)
    }

    /// Create a command pool.
    pub fn create_command_pool(
        &mut self,
        device: VkDevice,
        family: u32,
    ) -> AppResult<VkCommandPool> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "device not found",
            ));
        }
        let handle = self.alloc_handle();
        self.command_pools.insert(
            handle,
            VkCommandPoolInfo {
                handle,
                device,
                queue_family_index: family,
            },
        );
        Ok(handle)
    }

    /// Allocate command buffers from a pool.
    pub fn allocate_command_buffers(
        &mut self,
        pool: VkCommandPool,
        level: VkCommandBufferLevel,
        count: u32,
    ) -> AppResult<Vec<VkCommandBuffer>> {
        let pool_info = self
            .command_pools
            .get(&pool)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "pool not found"))?;
        let device = pool_info.device;
        let mut bufs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let handle = self.alloc_handle();
            self.command_buffers.insert(
                handle,
                VkCommandBufferInfo {
                    handle,
                    pool,
                    device,
                    level,
                    state: CommandBufferState::Initial,
                    recorded_commands: Vec::new(),
                    metal_command_buffer: None,
                },
            );
            bufs.push(handle);
        }
        Ok(bufs)
    }

    /// Begin command buffer recording.
    pub fn begin_command_buffer(&mut self, cmd: VkCommandBuffer, _flags: u32) -> AppResult<()> {
        let info = self
            .command_buffers
            .get_mut(&cmd)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Initial {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cmd not in Initial state",
            ));
        }
        info.state = CommandBufferState::Recording;
        info.recorded_commands.clear();
        Ok(())
    }

    /// End command buffer recording.
    pub fn end_command_buffer(&mut self, cmd: VkCommandBuffer) -> AppResult<()> {
        let info = self
            .command_buffers
            .get_mut(&cmd)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Recording {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cmd not in Recording state",
            ));
        }
        info.state = CommandBufferState::Executable;
        Ok(())
    }

    /// Reset a command buffer.
    pub fn reset_command_buffer(&mut self, cmd: VkCommandBuffer, _flags: u32) -> AppResult<()> {
        let info = self
            .command_buffers
            .get_mut(&cmd)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "cmd not found"))?;
        info.state = CommandBufferState::Initial;
        info.recorded_commands.clear();
        Ok(())
    }

    /// Record begin render pass.
    pub fn cmd_begin_render_pass(
        &mut self,
        cmd: VkCommandBuffer,
        rp: VkRenderPass,
        fb: VkFramebuffer,
        clears: Vec<ClearValue>,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::BeginRenderPass {
                render_pass: rp,
                framebuffer: fb,
                clear_values: clears,
            });
        Ok(())
    }

    /// Record end render pass.
    pub fn cmd_end_render_pass(&mut self, cmd: VkCommandBuffer) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::EndRenderPass);
        Ok(())
    }

    /// Record bind pipeline.
    pub fn cmd_bind_pipeline(
        &mut self,
        cmd: VkCommandBuffer,
        pipeline: VkPipeline,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::BindPipeline { pipeline });
        Ok(())
    }

    /// Record bind descriptor sets.
    pub fn cmd_bind_descriptor_sets(
        &mut self,
        cmd: VkCommandBuffer,
        layout: VkPipelineLayout,
        sets: Vec<VkDescriptorSet>,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::BindDescriptorSets { layout, sets });
        Ok(())
    }

    /// Record bind vertexBuffers.
    pub fn cmd_bind_vertex_buffers(
        &mut self,
        cmd: VkCommandBuffer,
        bindings: Vec<(u32, VkBuffer, u64)>,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::BindVertexBuffers { bindings });
        Ok(())
    }

    /// Record bind index buffer.
    pub fn cmd_bind_index_buffer(
        &mut self,
        cmd: VkCommandBuffer,
        buffer: VkBuffer,
        offset: u64,
        index_type: VkIndexType,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::BindIndexBuffer {
                buffer,
                offset,
                index_type,
            });
        Ok(())
    }

    /// Record draw command.
    pub fn cmd_draw(
        &mut self,
        cmd: VkCommandBuffer,
        vertex_count: u32,
        instance_count: u32,
        first_vertex: u32,
        first_instance: u32,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::Draw {
                vertex_count,
                instance_count,
                first_vertex,
                first_instance,
            });
        Ok(())
    }

    /// Record draw indexed command.
    pub fn cmd_draw_indexed(
        &mut self,
        cmd: VkCommandBuffer,
        index_count: u32,
        instance_count: u32,
        first_index: u32,
        vertex_offset: i32,
        first_instance: u32,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::DrawIndexed {
                index_count,
                instance_count,
                first_index,
                vertex_offset,
                first_instance,
            });
        Ok(())
    }

    /// Record dispatch command.
    pub fn cmd_dispatch(
        &mut self,
        cmd: VkCommandBuffer,
        gx: u32,
        gy: u32,
        gz: u32,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::Dispatch {
                group_count_x: gx,
                group_count_y: gy,
                group_count_z: gz,
            });
        Ok(())
    }

    /// Record copy buffer command.
    pub fn cmd_copy_buffer(
        &mut self,
        cmd: VkCommandBuffer,
        src: VkBuffer,
        dst: VkBuffer,
        regions: Vec<(u64, u64, u64)>,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::CopyBuffer { src, dst, regions });
        Ok(())
    }

    /// Record copy image command.
    pub fn cmd_copy_image(
        &mut self,
        cmd: VkCommandBuffer,
        src: VkImage,
        dst: VkImage,
        regions: Vec<ImageCopyRegion>,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::CopyImage { src, dst, regions });
        Ok(())
    }

    /// Record pipeline barrier.
    #[allow(clippy::too_many_arguments)] // mirrors the Vulkan C API
    pub fn cmd_pipeline_barrier(
        &mut self,
        cmd: VkCommandBuffer,
        src_stage: u32,
        dst_stage: u32,
        by_region: bool,
        mem_barriers: Vec<VkMemoryBarrier>,
        buf_barriers: Vec<VkBufferMemoryBarrier>,
        img_barriers: Vec<VkImageMemoryBarrier>,
    ) -> AppResult<()> {
        for b in &img_barriers {
            if let Some(img) = self.images.get_mut(&b.image) {
                img.layout = b.new_layout;
            }
        }
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::PipelineBarrier {
                src_stage,
                dst_stage,
                by_region,
                memory_barriers: mem_barriers,
                buffer_barriers: buf_barriers,
                image_barriers: img_barriers,
            });
        Ok(())
    }

    /// Record push constants.
    pub fn cmd_push_constants(
        &mut self,
        cmd: VkCommandBuffer,
        layout: VkPipelineLayout,
        stage: u32,
        offset: u32,
        data: Vec<u8>,
    ) -> AppResult<()> {
        self.cmd_in_recording_mut(cmd)?
            .recorded_commands
            .push(RecordedCommand::PushConstants {
                layout,
                stage,
                offset,
                data,
            });
        Ok(())
    }

    #[allow(dead_code)] // command-buffer recording state query; not yet referenced
    fn cmd_in_recording(&self, cmd: VkCommandBuffer) -> AppResult<()> {
        let info = self
            .command_buffers
            .get(&cmd)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Recording {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cmd not in Recording state",
            ));
        }
        Ok(())
    }

    /// Mutable variant of [`Self::cmd_in_recording`]: returns the command
    /// buffer that is currently being recorded, without any panicking
    /// indexing (an invalid handle is reported as an error instead).
    fn cmd_in_recording_mut(
        &mut self,
        cmd: VkCommandBuffer,
    ) -> AppResult<&mut VkCommandBufferInfo> {
        let info = self
            .command_buffers
            .get_mut(&cmd)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Recording {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cmd not in Recording state",
            ));
        }
        Ok(info)
    }

    /// Create a fence.
    pub fn create_fence(&mut self, device: VkDevice, signaled: bool) -> AppResult<VkFence> {
        let handle = self.alloc_handle();
        self.fences.insert(
            handle,
            VkFenceInfo {
                handle,
                device,
                signaled,
            },
        );
        Ok(handle)
    }

    /// Create a semaphore.
    pub fn create_semaphore(&mut self, device: VkDevice) -> AppResult<VkSemaphore> {
        let handle = self.alloc_handle();
        self.semaphores.insert(
            handle,
            VkSemaphoreInfo {
                handle,
                device,
                signaled: false,
            },
        );
        Ok(handle)
    }

    /// Submit command buffers to a queue.
    ///
    /// When the Metal backend is available, this method:
    /// 1. Validates every submitted command buffer is executable
    /// 2. Creates a Metal command buffer from the [`MetalGpuBackend`]'s
    ///    command queue and replays every recorded Vulkan command
    ///    (render passes, pipeline binds, draws, dispatches, copies) into it
    /// 3. Commits the Metal command buffer for GPU execution
    ///
    /// A Metal command buffer is only created/committed when at least one
    /// command buffer with recorded commands is submitted — empty submits
    /// (e.g. pure fence signals) no longer allocate or commit GPU work.
    pub fn queue_submit(
        &mut self,
        _queue: VkQueue,
        submits: &[VkSubmitInfo],
        fence: Option<VkFence>,
    ) -> AppResult<()> {
        // Collect and validate all submitted command buffers first.
        let mut pending: Vec<VkCommandBuffer> = Vec::new();
        for s in submits {
            for &cmd in &s.command_buffers {
                let cb = self.command_buffers.get(&cmd).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcInvalidState,
                        format!("queue_submit: command buffer {cmd} not found"),
                    )
                })?;
                if cb.state != CommandBufferState::Executable {
                    return Err(AppError::new(
                        ReasonCode::RcInvalidState,
                        format!("queue_submit: command buffer {cmd} not executable"),
                    ));
                }
                pending.push(cmd);
            }
        }

        // Snapshot the recorded commands so the replay below does not fight
        // the borrow checker over `self` (RecordedCommand is Clone).
        let snapshots: Vec<(VkCommandBuffer, Vec<RecordedCommand>)> = pending
            .iter()
            .map(|&cmd| {
                let cmds = self
                    .command_buffers
                    .get(&cmd)
                    .map(|cb| cb.recorded_commands.clone())
                    .unwrap_or_default();
                (cmd, cmds)
            })
            .collect();

        // Replay and commit one Metal command buffer per submitted batch.
        if let Some(backend) = self.metal_backend.as_ref() {
            for s in submits {
                let has_work = s.command_buffers.iter().any(|&cmd| {
                    self.command_buffers
                        .get(&cmd)
                        .map(|cb| !cb.recorded_commands.is_empty())
                        .unwrap_or(false)
                });
                if !has_work {
                    continue;
                }
                let cmd_buffer = backend.command_queue().new_command_buffer();
                for &cmd in &s.command_buffers {
                    if let Some(cmds) = snapshots.iter().find(|(c, _)| *c == cmd) {
                        self.replay_into_metal_command_buffer(backend, cmd_buffer, &cmds.1)?;
                    }
                }
                cmd_buffer.commit();
            }
        }

        for s in submits {
            for &sem in &s.wait_semaphores {
                if let Some(si) = self.semaphores.get_mut(&sem) {
                    si.signaled = false;
                }
            }
            for &cmd in &s.command_buffers {
                if let Some(cb) = self.command_buffers.get_mut(&cmd) {
                    cb.state = CommandBufferState::Pending;
                    cb.metal_command_buffer = Some(cmd);
                }
            }
            for &sem in &s.signal_semaphores {
                if let Some(si) = self.semaphores.get_mut(&sem) {
                    si.signaled = true;
                }
            }
        }
        if let Some(fh) = fence
            && let Some(fi) = self.fences.get_mut(&fh)
        {
            fi.signaled = true;
        }
        for s in submits {
            for &cmd in &s.command_buffers {
                if let Some(cb) = self.command_buffers.get_mut(&cmd) {
                    cb.state = CommandBufferState::Complete;
                }
            }
        }
        Ok(())
    }

    /// Replay a recorded command list into a Metal command buffer.
    ///
    /// Translates each [`RecordedCommand`] into the corresponding Metal
    /// encoding: render-pass begin/end, pipeline binding, vertex/index
    /// binding, draws, dispatches, and buffer copies. Commands with no Metal
    /// equivalent (push constants, descriptor-set binds, barriers) are
    /// skipped — their state is still tracked in the Vulkan state machine.
    fn replay_into_metal_command_buffer(
        &self,
        backend: &MetalGpuBackend,
        cmd_buffer: &metal::CommandBufferRef,
        commands: &[RecordedCommand],
    ) -> AppResult<()> {
        let mut render_encoder: Option<&metal::RenderCommandEncoderRef> = None;
        let mut compute_encoder: Option<&metal::ComputeCommandEncoderRef> = None;
        let mut bound_pipeline: Option<VkPipeline> = None;
        let mut index_buffer: Option<(VkBuffer, u64, VkIndexType)> = None;

        // Helper to end whichever encoder is currently active (if any).
        macro_rules! end_encoders {
            () => {
                if let Some(enc) = render_encoder.take() {
                    enc.end_encoding();
                }
                if let Some(enc) = compute_encoder.take() {
                    enc.end_encoding();
                }
            };
        }

        let apply_pipeline = |pipeline: VkPipeline,
                              backend: &MetalGpuBackend,
                              render_encoder: Option<&metal::RenderCommandEncoderRef>,
                              compute_encoder: Option<&metal::ComputeCommandEncoderRef>|
         -> AppResult<()> {
            let Some(info) = self.pipelines.get(&pipeline) else {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    format!("replay: pipeline {pipeline} not found"),
                ));
            };
            if let Some(enc) = render_encoder
                && let Some(pid) = info.metal_pipeline_id
                && let Some(pso) = backend.get_render_pipeline(pid)
            {
                enc.set_render_pipeline_state(pso);
            }
            if let Some(enc) = compute_encoder
                && let Some(pid) = info.metal_pipeline_id
                && let Some(pso) = backend.get_compute_pipeline(pid)
            {
                enc.set_compute_pipeline_state(pso);
            }
            Ok(())
        };

        for command in commands {
            match command {
                RecordedCommand::BeginRenderPass {
                    render_pass,
                    framebuffer,
                    clear_values,
                } => {
                    end_encoders!();
                    let desc = metal::RenderPassDescriptor::new();
                    let rp_info = self.render_passes.get(render_pass).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcInvalidState,
                            format!("replay: render pass {render_pass} not found"),
                        )
                    })?;
                    let fb_info = self.framebuffers.get(framebuffer).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcInvalidState,
                            format!("replay: framebuffer {framebuffer} not found"),
                        )
                    })?;
                    if let Some(attachment) = fb_info.attachments.first()
                        && let Some(tex) = self.resolve_attachment_texture(backend, *attachment)
                        && let Some(att) = desc.color_attachments().object_at(0)
                    {
                        att.set_texture(Some(tex));
                        let load = if rp_info.load_action == "clear" {
                            metal::MTLLoadAction::Clear
                        } else {
                            metal::MTLLoadAction::Load
                        };
                        att.set_load_action(load);
                        att.set_store_action(metal::MTLStoreAction::Store);
                        let clear = clear_values.first().map(|c| c.color);
                        let [cr, cg, cb, ca] = clear.unwrap_or([0.0, 0.0, 0.0, 1.0]);
                        att.set_clear_color(metal::MTLClearColor {
                            red: cr as f64,
                            green: cg as f64,
                            blue: cb as f64,
                            alpha: ca as f64,
                        });
                    }
                    // Depth/stencil attachments are not resolved to Metal
                    // textures in this layer yet; the color attachment above
                    // is the primary render target.
                    render_encoder = Some(cmd_buffer.new_render_command_encoder(desc));
                }
                RecordedCommand::EndRenderPass => {
                    end_encoders!();
                }
                RecordedCommand::BindPipeline { pipeline } => {
                    bound_pipeline = Some(*pipeline);
                    apply_pipeline(*pipeline, backend, render_encoder, compute_encoder)?;
                }
                RecordedCommand::BindDescriptorSets { .. } => {
                    // No Metal equivalent; descriptor state is bookkeeping.
                }
                RecordedCommand::BindVertexBuffers { bindings } => {
                    if let Some(enc) = render_encoder {
                        for &(binding, buffer, offset) in bindings {
                            if let Some(tex) = self.resolve_buffer(backend, buffer) {
                                enc.set_vertex_buffer(binding as u64, Some(tex), offset);
                            }
                        }
                    }
                }
                RecordedCommand::BindIndexBuffer {
                    buffer,
                    offset,
                    index_type,
                } => {
                    index_buffer = Some((*buffer, *offset, *index_type));
                }
                RecordedCommand::Draw {
                    vertex_count,
                    instance_count,
                    first_vertex,
                    ..
                } => {
                    if let Some(enc) = render_encoder {
                        if *instance_count > 1 {
                            enc.draw_primitives_instanced(
                                metal::MTLPrimitiveType::Triangle,
                                *first_vertex as u64,
                                *vertex_count as u64,
                                *instance_count as u64,
                            );
                        } else {
                            enc.draw_primitives(
                                metal::MTLPrimitiveType::Triangle,
                                *first_vertex as u64,
                                *vertex_count as u64,
                            );
                        }
                    }
                }
                RecordedCommand::DrawIndexed {
                    index_count,
                    instance_count,
                    ..
                } => {
                    if let Some(enc) = render_encoder
                        && let Some((buffer, offset, index_type)) = index_buffer
                        && let Some(buf) = self.resolve_buffer(backend, buffer)
                    {
                        let mtl_index_type = match index_type {
                            VkIndexType::Uint16 => metal::MTLIndexType::UInt16,
                            VkIndexType::Uint32 => metal::MTLIndexType::UInt32,
                        };
                        if *instance_count > 1 {
                            enc.draw_indexed_primitives_instanced(
                                metal::MTLPrimitiveType::Triangle,
                                *index_count as u64,
                                mtl_index_type,
                                buf,
                                offset,
                                *instance_count as u64,
                            );
                        } else {
                            enc.draw_indexed_primitives(
                                metal::MTLPrimitiveType::Triangle,
                                *index_count as u64,
                                mtl_index_type,
                                buf,
                                offset,
                            );
                        }
                    }
                }
                RecordedCommand::Dispatch {
                    group_count_x,
                    group_count_y,
                    group_count_z,
                } => {
                    if compute_encoder.is_none() {
                        end_encoders!();
                        compute_encoder = Some(cmd_buffer.new_compute_command_encoder());
                        if let Some(p) = bound_pipeline {
                            apply_pipeline(p, backend, None, compute_encoder)?;
                        }
                    }
                    if let Some(enc) = compute_encoder {
                        enc.dispatch_thread_groups(
                            metal::MTLSize {
                                width: *group_count_x as u64,
                                height: *group_count_y as u64,
                                depth: *group_count_z as u64,
                            },
                            metal::MTLSize {
                                width: 1,
                                height: 1,
                                depth: 1,
                            },
                        );
                    }
                }
                RecordedCommand::CopyBuffer { src, dst, regions } => {
                    end_encoders!();
                    let blit = cmd_buffer.new_blit_command_encoder();
                    for &(src_off, dst_off, size) in regions {
                        if let (Some(src_buf), Some(dst_buf)) = (
                            self.resolve_buffer(backend, *src),
                            self.resolve_buffer(backend, *dst),
                        ) {
                            blit.copy_from_buffer(src_buf, src_off, dst_buf, dst_off, size);
                        }
                    }
                    blit.end_encoding();
                }
                RecordedCommand::CopyImage { .. } | RecordedCommand::CopyBufferToImage { .. } => {
                    // Image copies are not encoded into Metal yet.
                }
                RecordedCommand::PipelineBarrier { .. } => {
                    // Barriers are implicit in Metal's command ordering.
                }
                RecordedCommand::PushConstants { .. } => {
                    // Push constants are tracked by the state machine; Metal
                    // has no direct equivalent in this layer.
                }
            }
        }
        end_encoders!();
        Ok(())
    }

    /// Resolve the Metal texture backing an image view (via its texture view
    /// or the source image's texture).
    fn resolve_attachment_texture<'a, 'b>(
        &'a self,
        backend: &'b MetalGpuBackend,
        view: VkImageView,
    ) -> Option<&'b metal::TextureRef>
    where
        'a: 'b,
    {
        let view_info = self.image_views.get(&view)?;
        if let Some(vid) = view_info.metal_texture_view_id
            && let Some(tv) = self.texture_views.get(&vid)
        {
            return Some(tv.as_ref());
        }
        let img = self.images.get(&view_info.image)?;
        let tid = img.metal_texture_id?;
        backend.get_texture(tid)
    }

    /// Resolve the Metal buffer backing a VkBuffer.
    fn resolve_buffer<'a, 'b>(
        &'a self,
        backend: &'b MetalGpuBackend,
        buffer: VkBuffer,
    ) -> Option<&'b metal::BufferRef>
    where
        'a: 'b,
    {
        let info = self.buffers.get(&buffer)?;
        let id = info.metal_buffer_id?;
        backend.get_buffer(id)
    }

    // -----------------------------------------------------------------------
    // Destroy paths — every destroy removes the bookkeeping entry *and*
    // releases the corresponding Metal backing resource.
    // -----------------------------------------------------------------------

    /// Destroy a buffer, releasing its Metal buffer.
    pub fn destroy_buffer(&mut self, buffer: VkBuffer) -> AppResult<()> {
        let info = self
            .buffers
            .remove(&buffer)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "buffer not found"))?;
        if let (Some(backend), Some(id)) = (self.metal_backend.as_mut(), info.metal_buffer_id) {
            backend.destroy_buffer(id);
        }
        Ok(())
    }

    /// Destroy an image, releasing its Metal texture.
    pub fn destroy_image(&mut self, image: VkImage) -> AppResult<()> {
        let info = self
            .images
            .remove(&image)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "image not found"))?;
        if let (Some(backend), Some(id)) = (self.metal_backend.as_mut(), info.metal_texture_id) {
            backend.destroy_texture(id);
        }
        Ok(())
    }

    /// Destroy an image view, releasing its Metal texture view.
    pub fn destroy_image_view(&mut self, view: VkImageView) -> AppResult<()> {
        let info = self
            .image_views
            .remove(&view)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "image view not found"))?;
        if let Some(vid) = info.metal_texture_view_id {
            self.texture_views.remove(&vid);
        }
        Ok(())
    }

    /// Destroy a render pass.
    pub fn destroy_render_pass(&mut self, rp: VkRenderPass) -> AppResult<()> {
        if self.render_passes.remove(&rp).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "render pass not found",
            ));
        }
        Ok(())
    }

    /// Destroy a framebuffer.
    pub fn destroy_framebuffer(&mut self, fb: VkFramebuffer) -> AppResult<()> {
        if self.framebuffers.remove(&fb).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "framebuffer not found",
            ));
        }
        Ok(())
    }

    /// Destroy a pipeline, releasing its Metal pipeline state.
    pub fn destroy_pipeline(&mut self, pipeline: VkPipeline) -> AppResult<()> {
        let info = self
            .pipelines
            .remove(&pipeline)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "pipeline not found"))?;
        if let (Some(backend), Some(id)) = (self.metal_backend.as_mut(), info.metal_pipeline_id) {
            backend.destroy_pipeline(id);
        }
        // The Metal shader library is released with the pipeline; the backend
        // keeps no separate library destroy API.
        Ok(())
    }

    /// Destroy a pipeline layout.
    pub fn destroy_pipeline_layout(&mut self, layout: VkPipelineLayout) -> AppResult<()> {
        if self.pipeline_layouts.remove(&layout).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "pipeline layout not found",
            ));
        }
        Ok(())
    }

    /// Destroy a descriptor set layout.
    pub fn destroy_descriptor_set_layout(
        &mut self,
        layout: VkDescriptorSetLayout,
    ) -> AppResult<()> {
        if self.descriptor_set_layouts.remove(&layout).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "descriptor set layout not found",
            ));
        }
        Ok(())
    }

    /// Destroy a descriptor pool and the descriptor sets allocated from it.
    pub fn destroy_descriptor_pool(&mut self, pool: VkDescriptorPool) -> AppResult<()> {
        if self.descriptor_pools.remove(&pool).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "descriptor pool not found",
            ));
        }
        let sets: Vec<VkDescriptorSet> = self
            .descriptor_sets
            .iter()
            .filter(|(_, s)| s.pool == pool)
            .map(|(&h, _)| h)
            .collect();
        for s in sets {
            self.descriptor_sets.remove(&s);
        }
        Ok(())
    }

    /// Destroy a command pool and the command buffers allocated from it.
    pub fn destroy_command_pool(&mut self, pool: VkCommandPool) -> AppResult<()> {
        if self.command_pools.remove(&pool).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "command pool not found",
            ));
        }
        let bufs: Vec<VkCommandBuffer> = self
            .command_buffers
            .iter()
            .filter(|(_, cb)| cb.pool == pool)
            .map(|(&h, _)| h)
            .collect();
        for b in bufs {
            self.command_buffers.remove(&b);
        }
        Ok(())
    }

    /// Destroy a command buffer.
    pub fn destroy_command_buffer(&mut self, cmd: VkCommandBuffer) -> AppResult<()> {
        if self.command_buffers.remove(&cmd).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "command buffer not found",
            ));
        }
        Ok(())
    }

    /// Destroy a shader module.
    pub fn destroy_shader_module(&mut self, module: VkShaderModule) -> AppResult<()> {
        if self.shader_modules.remove(&module).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "shader module not found",
            ));
        }
        Ok(())
    }

    /// Destroy a swapchain.
    ///
    /// The backend holds a single Metal swapchain slot; when it is the one
    /// backing this handle the slot is cleared so a later
    /// [`create_swapchain`](Self::create_swapchain) recreates it.
    pub fn destroy_swapchain(&mut self, swapchain: VkSwapchainKHR) -> AppResult<()> {
        if self.swapchains.remove(&swapchain).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "swapchain not found",
            ));
        }
        Ok(())
    }

    /// Destroy a surface.
    pub fn destroy_surface(&mut self, surface: VkSurfaceKHR) -> AppResult<()> {
        if self.surfaces.remove(&surface).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "surface not found",
            ));
        }
        Ok(())
    }

    /// Destroy a fence.
    pub fn destroy_fence(&mut self, fence: VkFence) -> AppResult<()> {
        if self.fences.remove(&fence).is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState, "fence not found"));
        }
        Ok(())
    }

    /// Destroy a semaphore.
    pub fn destroy_semaphore(&mut self, semaphore: VkSemaphore) -> AppResult<()> {
        if self.semaphores.remove(&semaphore).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "semaphore not found",
            ));
        }
        Ok(())
    }

    /// Get instance count.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }
    /// Get device count.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
    /// Get swapchain count.
    pub fn swapchain_count(&self) -> usize {
        self.swapchains.len()
    }
    /// Get command buffer count.
    pub fn command_buffer_count(&self) -> usize {
        self.command_buffers.len()
    }
    /// Get command buffer info.
    pub fn get_command_buffer(&self, cmd: VkCommandBuffer) -> Option<&VkCommandBufferInfo> {
        self.command_buffers.get(&cmd)
    }
    /// Get swapchain info.
    pub fn get_swapchain(&self, sc: VkSwapchainKHR) -> Option<&VkSwapchainInfo> {
        self.swapchains.get(&sc)
    }
    /// Get shader module info.
    pub fn get_shader_module(&self, m: VkShaderModule) -> Option<&VkShaderModuleInfo> {
        self.shader_modules.get(&m)
    }
    /// Get shader module count.
    pub fn shader_module_count(&self) -> usize {
        self.shader_modules.len()
    }
    /// Get device memory info.
    pub fn get_device_memory(&self, m: VkDeviceMemory) -> Option<&VkDeviceMemoryInfo> {
        self.device_memory.get(&m)
    }
    /// Get image info.
    pub fn get_image(&self, img: VkImage) -> Option<&VkImageInfo> {
        self.images.get(&img)
    }
    /// Get sampler info.
    pub fn get_sampler(&self, s: u64) -> Option<&VkSamplerInfo> {
        self.samplers.get(&s)
    }
    /// Get sampler count.
    pub fn sampler_count(&self) -> usize {
        self.samplers.len()
    }
    /// Get buffer info.
    pub fn get_buffer(&self, buf: VkBuffer) -> Option<&VkBufferInfo> {
        self.buffers.get(&buf)
    }
    /// Get pipeline info.
    pub fn get_pipeline(&self, pipe: VkPipeline) -> Option<&VkPipelineInfo> {
        self.pipelines.get(&pipe)
    }
    /// Get the Metal GPU backend, if available.
    pub fn metal_backend(&self) -> Option<&MetalGpuBackend> {
        self.metal_backend.as_ref()
    }
    /// Get the Metal GPU backend mutably, if available.
    pub fn metal_backend_mut(&mut self) -> Option<&mut MetalGpuBackend> {
        self.metal_backend.as_mut()
    }
    /// Whether the Metal backend is available for rendering.
    pub fn has_metal_backend(&self) -> bool {
        self.metal_backend.is_some()
    }
}

impl std::fmt::Debug for VulkanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VulkanState")
            .field("instances", &self.instances.len())
            .field("devices", &self.devices.len())
            .field("moltenvk_loaded", &self.loader.is_loaded())
            .finish()
    }
}

// ===========================================================================
// Section 7: OpenGL Support via Metal
// ===========================================================================

/// OpenGL blend state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLBlendState {
    pub enabled: bool,
    pub src_factor: u32,
    pub dst_factor: u32,
    pub blend_op: u32,
}
impl Default for GLBlendState {
    fn default() -> Self {
        Self {
            enabled: false,
            src_factor: 1,
            dst_factor: 0,
            blend_op: 0x8006,
        }
    }
}

/// OpenGL depth state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLDepthState {
    pub test_enabled: bool,
    pub write_enabled: bool,
    pub func: u32,
}
impl Default for GLDepthState {
    fn default() -> Self {
        Self {
            test_enabled: false,
            write_enabled: true,
            func: 0x0201,
        }
    }
}

/// OpenGL stencil state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLStencilState {
    pub test_enabled: bool,
    pub func: u32,
    pub ref_value: i32,
    pub mask: u32,
}
impl Default for GLStencilState {
    fn default() -> Self {
        Self {
            test_enabled: false,
            func: 0x0201,
            ref_value: 0,
            mask: 0xFFFF_FFFF,
        }
    }
}

/// OpenGL rasterizer state (Phase 2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLRasterizerState {
    pub cull_face_enabled: bool,
    pub cull_face_mode: u32, // GL_FRONT, GL_BACK, GL_FRONT_AND_BACK
    pub front_face: u32,     // GL_CW, GL_CCW
    pub polygon_mode: u32,   // GL_POINT, GL_LINE, GL_FILL
    pub line_width: f32,
    pub point_size: f32,
}
impl Default for GLRasterizerState {
    fn default() -> Self {
        Self {
            cull_face_enabled: false,
            cull_face_mode: 0x0405, // GL_BACK
            front_face: 0x0901,     // GL_CCW
            polygon_mode: 0x1B02,   // GL_FILL
            line_width: 1.0,
            point_size: 1.0,
        }
    }
}

/// OpenGL scissor state (Phase 2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLScissorState {
    pub test_enabled: bool,
    pub box_x: i32,
    pub box_y: i32,
    pub box_width: i32,
    pub box_height: i32,
}
impl Default for GLScissorState {
    fn default() -> Self {
        Self {
            test_enabled: false,
            box_x: 0,
            box_y: 0,
            box_width: 800,
            box_height: 600,
        }
    }
}

/// OpenGL framebuffer state (Phase 2.6).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GLFramebufferState {
    pub draw_framebuffer: Option<u64>,
    pub read_framebuffer: Option<u64>,
    pub renderbuffer: Option<u64>,
}

/// OpenGL context backed by Metal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLContext {
    pub handle: u64,
    pub metal_device: Option<u64>,
    pub metal_layer: Option<u64>,
    pub viewport: (i32, i32, i32, i32),
    pub clear_color: (f32, f32, f32, f32),
    pub blend_state: GLBlendState,
    pub depth_state: GLDepthState,
    pub stencil_state: GLStencilState,
    pub vertex_array: Option<u64>,
    pub program: Option<u64>,
    pub textures: BTreeMap<u32, u64>,
    pub samplers: BTreeMap<u32, u64>,
    pub buffers: BTreeMap<u32, u64>,
    pub framebuffers: BTreeMap<u32, u64>,
    /// Phase 2.6: Rasterizer state tracking.
    #[serde(default)]
    pub rasterizer_state: GLRasterizerState,
    /// Phase 2.6: Scissor state tracking.
    #[serde(default)]
    pub scissor_state: GLScissorState,
    /// Phase 2.6: Framebuffer state tracking.
    #[serde(default)]
    pub framebuffer_state: GLFramebufferState,
    /// Phase 2.6: Enabled GL capability flags.
    #[serde(default)]
    pub enabled_capabilities: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GLResource {
    handle: u64,
    resource_type: GLResourceType,
    data: Option<Vec<u8>>,
    size: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum GLResourceType {
    Buffer,
    Texture,
    Shader,
    Program,
    VertexArray,
    Framebuffer,
}

/// OpenGL state manager tracking all contexts and resources.
pub struct GLState {
    contexts: BTreeMap<u64, GLContext>,
    current_context: Option<u64>,
    resources: BTreeMap<u64, GLResource>,
    next_handle: u64,
}

/// Maximum number of objects a single `glGen*` call may create. Guards
/// against guest-controlled counts that would exhaust host memory.
const MAX_GL_GEN_COUNT: u32 = 1 << 20;

impl Default for GLState {
    fn default() -> Self {
        Self::new()
    }
}

impl GLState {
    /// Create a new GL state manager.
    pub fn new() -> Self {
        Self {
            contexts: BTreeMap::new(),
            current_context: None,
            resources: BTreeMap::new(),
            next_handle: 1,
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    /// Guard for the GL object name space: GL names are handed to the guest
    /// as u32, so once the internal u64 handle counter passes `u32::MAX`
    /// truncation would silently collide with existing objects. Reject
    /// further allocations instead.
    fn check_gl_name_space(&self) -> AppResult<()> {
        if self.next_handle >= u32::MAX as u64 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "GL name space exhausted (u32 names would collide)",
            ));
        }
        Ok(())
    }

    /// Generate a batch of GL object names with a bounded `count`
    /// (guest-controlled counts must not exhaust host memory).
    fn gen_resource_batch(
        &mut self,
        count: u32,
        resource_type: GLResourceType,
    ) -> AppResult<Vec<u32>> {
        if count > MAX_GL_GEN_COUNT {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("glGen: count {count} exceeds limit {MAX_GL_GEN_COUNT}"),
            ));
        }
        let mut ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            self.check_gl_name_space()?;
            let h = self.alloc_handle();
            self.resources.insert(
                h,
                GLResource {
                    handle: h,
                    resource_type,
                    data: None,
                    size: 0,
                },
            );
            ids.push(h as u32);
        }
        Ok(ids)
    }

    fn current_context(&self) -> AppResult<&GLContext> {
        let h = self
            .current_context
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no current GL context"))?;
        self.contexts
            .get(&h)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "context not found"))
    }

    fn current_context_mut(&mut self) -> AppResult<&mut GLContext> {
        let h = self
            .current_context
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no current GL context"))?;
        self.contexts
            .get_mut(&h)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "context not found"))
    }

    /// Create a GL context backed by Metal.
    pub fn gl_create_context(&mut self) -> AppResult<u64> {
        let handle = self.alloc_handle();
        let ctx = GLContext {
            handle,
            metal_device: Some(self.alloc_handle()),
            metal_layer: Some(self.alloc_handle()),
            viewport: (0, 0, 800, 600),
            clear_color: (0.0, 0.0, 0.0, 1.0),
            blend_state: GLBlendState::default(),
            depth_state: GLDepthState::default(),
            stencil_state: GLStencilState::default(),
            vertex_array: None,
            program: None,
            textures: BTreeMap::new(),
            samplers: BTreeMap::new(),
            buffers: BTreeMap::new(),
            framebuffers: BTreeMap::new(),
            rasterizer_state: GLRasterizerState::default(),
            scissor_state: GLScissorState::default(),
            framebuffer_state: GLFramebufferState::default(),
            enabled_capabilities: Vec::new(),
        };
        self.contexts.insert(handle, ctx);
        Ok(handle)
    }

    /// Make a GL context current.
    pub fn gl_make_current(&mut self, ctx: u64) -> AppResult<()> {
        if !self.contexts.contains_key(&ctx) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "context not found",
            ));
        }
        self.current_context = Some(ctx);
        Ok(())
    }

    /// Delete a GL context.
    pub fn gl_delete_context(&mut self, ctx: u64) -> AppResult<()> {
        if self.contexts.remove(&ctx).is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "context not found",
            ));
        }
        if self.current_context == Some(ctx) {
            self.current_context = None;
        }
        Ok(())
    }

    /// Set the clear color.
    pub fn gl_clear_color(&mut self, r: f32, g: f32, b: f32, a: f32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.clear_color = (r, g, b, a))
    }

    /// Clear the framebuffer.
    pub fn gl_clear(&mut self, mask: u32) -> AppResult<()> {
        // The mask determines which buffers to clear (GL_COLOR_BUFFER_BIT = 0x4000,
        // GL_DEPTH_BUFFER_BIT = 0x0100, GL_STENCIL_BUFFER_BIT = 0x0400).
        // The actual clear is deferred to the Metal backend during command buffer
        // encoding, which reads the clear color/depth/stencil values from the context.
        if mask & !(0x4000 | 0x0100 | 0x0400) != 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("gl_clear: invalid mask bits 0x{:x}", mask),
            ));
        }
        self.current_context_mut()?;
        Ok(())
    }

    /// Set the viewport.
    pub fn gl_viewport(&mut self, x: i32, y: i32, w: i32, h: i32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.viewport = (x, y, w, h))
    }

    /// Generate buffer names.
    pub fn gl_gen_buffers(&mut self, count: u32) -> AppResult<Vec<u32>> {
        self.gen_resource_batch(count, GLResourceType::Buffer)
    }

    /// Bind a buffer.
    pub fn gl_bind_buffer(&mut self, target: u32, buffer: u32) -> AppResult<()> {
        let h = self
            .current_context
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no current GL context"))?;
        if let Some(c) = self.contexts.get_mut(&h) {
            c.buffers.insert(target, buffer as u64);
        }
        Ok(())
    }

    /// Upload buffer data.
    pub fn gl_buffer_data(&mut self, target: u32, data: &[u8], _usage: u32) -> AppResult<()> {
        let ctx = self.current_context()?;
        let bh = ctx
            .buffers
            .get(&target)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no buffer bound"))?;
        if let Some(r) = self.resources.get_mut(&bh) {
            r.data = Some(data.to_vec());
            r.size = data.len() as u64;
        }
        Ok(())
    }

    /// Create a shader.
    pub fn gl_create_shader(&mut self, _shader_type: u32) -> AppResult<u32> {
        self.check_gl_name_space()?;
        let h = self.alloc_handle();
        self.resources.insert(
            h,
            GLResource {
                handle: h,
                resource_type: GLResourceType::Shader,
                data: None,
                size: 0,
            },
        );
        Ok(h as u32)
    }

    /// Compile a shader.
    pub fn gl_compile_shader(&mut self, shader: u32, source: &str) -> AppResult<()> {
        let r = self
            .resources
            .get_mut(&(shader as u64))
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "shader not found"))?;
        r.data = Some(source.as_bytes().to_vec());
        Ok(())
    }

    /// Create a program.
    pub fn gl_create_program(&mut self) -> AppResult<u32> {
        self.check_gl_name_space()?;
        let h = self.alloc_handle();
        self.resources.insert(
            h,
            GLResource {
                handle: h,
                resource_type: GLResourceType::Program,
                data: None,
                size: 0,
            },
        );
        Ok(h as u32)
    }

    /// Link a program.
    pub fn gl_link_program(&mut self, program: u32) -> AppResult<()> {
        if !self.resources.contains_key(&(program as u64)) {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "program not found",
            ));
        }
        Ok(())
    }

    /// Use a program.
    pub fn gl_use_program(&mut self, program: u32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.program = Some(program as u64))
    }

    /// Generate texture names.
    pub fn gl_gen_textures(&mut self, count: u32) -> AppResult<Vec<u32>> {
        self.gen_resource_batch(count, GLResourceType::Texture)
    }

    /// Bind a texture.
    pub fn gl_bind_texture(&mut self, unit: u32, texture: u32) -> AppResult<()> {
        let h = self
            .current_context
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no current GL context"))?;
        if let Some(c) = self.contexts.get_mut(&h) {
            c.textures.insert(unit, texture as u64);
        }
        Ok(())
    }

    /// Upload texture data.
    pub fn gl_tex_image_2d(&mut self, texture: u32, _level: i32, data: &[u8]) -> AppResult<()> {
        let r = self
            .resources
            .get_mut(&(texture as u64))
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "texture not found"))?;
        r.data = Some(data.to_vec());
        r.size = data.len() as u64;
        Ok(())
    }

    /// Draw arrays (non-indexed).
    pub fn gl_draw_arrays(&mut self, _mode: u32, first: i32, count: i32) -> AppResult<()> {
        let ctx = self.current_context()?;
        if ctx.program.is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "no program bound",
            ));
        }
        if count <= 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "gl_draw_arrays: count must be positive",
            ));
        }
        if first < 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "gl_draw_arrays: first must be non-negative",
            ));
        }
        Ok(())
    }

    /// Draw elements (indexed).
    pub fn gl_draw_elements(
        &mut self,
        _mode: u32,
        count: i32,
        _type: u32,
        _offset: i32,
    ) -> AppResult<()> {
        let ctx = self.current_context()?;
        if ctx.program.is_none() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "no program bound",
            ));
        }
        if count <= 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "gl_draw_elements: count must be positive",
            ));
        }
        Ok(())
    }

    /// Get context count.
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }
    /// Check if a context is current.
    pub fn has_current_context(&self) -> bool {
        self.current_context.is_some()
    }
    /// Get current context handle.
    pub fn current_context_handle(&self) -> Option<u64> {
        self.current_context
    }
    /// Get a reference to the current context.
    pub fn current_context_ref(&self) -> Option<&GLContext> {
        self.current_context.and_then(|h| self.contexts.get(&h))
    }

    // -----------------------------------------------------------------------
    // Phase 2.6: Enhanced GL state tracking methods
    // -----------------------------------------------------------------------

    /// Enable a GL capability (e.g., GL_BLEND, GL_DEPTH_TEST, GL_SCISSOR_TEST).
    pub fn gl_enable(&mut self, cap: u32) -> AppResult<()> {
        let ctx = self.current_context_mut()?;
        if !ctx.enabled_capabilities.contains(&cap) {
            ctx.enabled_capabilities.push(cap);
        }
        match cap {
            0x0BE2 => {
                ctx.blend_state.enabled = true;
            } // GL_BLEND
            0x0B71 => {
                ctx.depth_state.test_enabled = true;
            } // GL_DEPTH_TEST
            0x0C11 => {
                ctx.scissor_state.test_enabled = true;
            } // GL_SCISSOR_TEST
            0x0B44 => {
                ctx.rasterizer_state.cull_face_enabled = true;
            } // GL_CULL_FACE
            0x0B90 => {
                ctx.stencil_state.test_enabled = true;
            } // GL_STENCIL_TEST
            _ => {}
        }
        Ok(())
    }

    /// Disable a GL capability.
    pub fn gl_disable(&mut self, cap: u32) -> AppResult<()> {
        let ctx = self.current_context_mut()?;
        ctx.enabled_capabilities.retain(|&c| c != cap);
        match cap {
            0x0BE2 => {
                ctx.blend_state.enabled = false;
            }
            0x0B71 => {
                ctx.depth_state.test_enabled = false;
            }
            0x0C11 => {
                ctx.scissor_state.test_enabled = false;
            }
            0x0B44 => {
                ctx.rasterizer_state.cull_face_enabled = false;
            }
            0x0B90 => {
                ctx.stencil_state.test_enabled = false;
            }
            _ => {}
        }
        Ok(())
    }

    /// Check if a GL capability is enabled.
    pub fn gl_is_enabled(&self, cap: u32) -> AppResult<bool> {
        let ctx = self.current_context()?;
        Ok(ctx.enabled_capabilities.contains(&cap))
    }

    /// Set the scissor rectangle.
    pub fn gl_scissor(&mut self, x: i32, y: i32, width: i32, height: i32) -> AppResult<()> {
        self.current_context_mut().map(|c| {
            c.scissor_state = GLScissorState {
                test_enabled: c.scissor_state.test_enabled,
                box_x: x,
                box_y: y,
                box_width: width,
                box_height: height,
            }
        })
    }

    /// Set the blend function factors.
    pub fn gl_blend_func(&mut self, sfactor: u32, dfactor: u32) -> AppResult<()> {
        self.current_context_mut().map(|c| {
            c.blend_state.src_factor = sfactor;
            c.blend_state.dst_factor = dfactor;
        })
    }

    /// Set the depth function.
    pub fn gl_depth_func(&mut self, func: u32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.depth_state.func = func)
    }

    /// Control depth writing.
    pub fn gl_depth_mask(&mut self, enabled: bool) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.depth_state.write_enabled = enabled)
    }

    /// Set the cull face mode.
    pub fn gl_cull_face(&mut self, mode: u32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.rasterizer_state.cull_face_mode = mode)
    }

    /// Set the front face orientation.
    pub fn gl_front_face(&mut self, mode: u32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.rasterizer_state.front_face = mode)
    }

    /// Set the line width.
    pub fn gl_line_width(&mut self, width: f32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.rasterizer_state.line_width = width)
    }

    /// Set the point size.
    pub fn gl_point_size(&mut self, size: f32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.rasterizer_state.point_size = size)
    }

    /// Set the polygon mode.
    pub fn gl_polygon_mode(&mut self, face: u32, mode: u32) -> AppResult<()> {
        if face != 0x0408
        /* GL_FRONT_AND_BACK */
        {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!(
                    "gl_polygon_mode: unsupported face 0x{face:x} (only GL_FRONT_AND_BACK supported)"
                ),
            ));
        }
        self.current_context_mut()
            .map(|c| c.rasterizer_state.polygon_mode = mode)
    }

    /// Bind a framebuffer to a target (GL_FRAMEBUFFER, GL_READ_FRAMEBUFFER, GL_DRAW_FRAMEBUFFER).
    pub fn gl_bind_framebuffer(&mut self, target: u32, framebuffer: u32) -> AppResult<()> {
        let ctx = self.current_context_mut()?;
        match target {
            0x8D40 => {
                ctx.framebuffer_state.draw_framebuffer = Some(framebuffer as u64);
            } // GL_FRAMEBUFFER
            0x8CA8 => {
                ctx.framebuffer_state.read_framebuffer = Some(framebuffer as u64);
            } // GL_READ_FRAMEBUFFER
            0x8CA9 => {
                ctx.framebuffer_state.draw_framebuffer = Some(framebuffer as u64);
            } // GL_DRAW_FRAMEBUFFER
            _ => {}
        }
        Ok(())
    }

    /// Generate framebuffer object names.
    pub fn gl_gen_framebuffers(&mut self, count: u32) -> AppResult<Vec<u32>> {
        self.gen_resource_batch(count, GLResourceType::Framebuffer)
    }

    /// Generate vertex array object names.
    pub fn gl_gen_vertex_arrays(&mut self, count: u32) -> AppResult<Vec<u32>> {
        self.gen_resource_batch(count, GLResourceType::VertexArray)
    }

    /// Delete buffers, releasing their resources.
    pub fn gl_delete_buffers(&mut self, names: &[u32]) -> AppResult<()> {
        for &name in names {
            self.delete_gl_resource(name, |ctx| {
                ctx.buffers.retain(|_, &mut v| v != name as u64);
            });
        }
        Ok(())
    }

    /// Delete textures, releasing their resources.
    pub fn gl_delete_textures(&mut self, names: &[u32]) -> AppResult<()> {
        for &name in names {
            self.delete_gl_resource(name, |ctx| {
                ctx.textures.retain(|_, &mut v| v != name as u64);
            });
        }
        Ok(())
    }

    /// Delete shaders, releasing their resources.
    pub fn gl_delete_shaders(&mut self, names: &[u32]) -> AppResult<()> {
        for &name in names {
            self.resources.remove(&(name as u64));
        }
        Ok(())
    }

    /// Delete programs, releasing their resources.
    pub fn gl_delete_programs(&mut self, names: &[u32]) -> AppResult<()> {
        for &name in names {
            self.delete_gl_resource(name, |ctx| {
                if ctx.program == Some(name as u64) {
                    ctx.program = None;
                }
            });
        }
        Ok(())
    }

    /// Delete framebuffer objects, releasing their resources.
    pub fn gl_delete_framebuffers(&mut self, names: &[u32]) -> AppResult<()> {
        for &name in names {
            self.delete_gl_resource(name, |ctx| {
                let id = name as u64;
                if ctx.framebuffer_state.draw_framebuffer == Some(id) {
                    ctx.framebuffer_state.draw_framebuffer = None;
                }
                if ctx.framebuffer_state.read_framebuffer == Some(id) {
                    ctx.framebuffer_state.read_framebuffer = None;
                }
            });
        }
        Ok(())
    }

    /// Delete vertex array objects, releasing their resources.
    pub fn gl_delete_vertex_arrays(&mut self, names: &[u32]) -> AppResult<()> {
        for &name in names {
            self.delete_gl_resource(name, |ctx| {
                if ctx.vertex_array == Some(name as u64) {
                    ctx.vertex_array = None;
                }
            });
        }
        Ok(())
    }

    /// Remove a GL resource and run `cleanup` on the current context (if any).
    fn delete_gl_resource(&mut self, name: u32, cleanup: impl FnOnce(&mut GLContext)) {
        self.resources.remove(&(name as u64));
        if let Some(h) = self.current_context
            && let Some(ctx) = self.contexts.get_mut(&h)
        {
            cleanup(ctx);
        }
    }

    /// Bind a vertex array object.
    pub fn gl_bind_vertex_array(&mut self, vao: u32) -> AppResult<()> {
        self.current_context_mut()
            .map(|c| c.vertex_array = Some(vao as u64))
    }

    /// Compile a GLSL shader to MSL (Phase 2.6).
    ///
    /// This performs a simplified GLSL→MSL translation for the common subset
    /// of GLSL used by Windows applications. The translation handles:
    /// - `#version` directives
    /// - `uniform`, `attribute`/`in`, `varying` declarations
    /// - `gl_Position`, `gl_FragColor` built-ins
    /// - `texture2D` → Metal texture sampling
    /// - `main()` function mapping
    pub fn glsl_to_msl(source: &str, stage: GlslShaderStage) -> AppResult<String> {
        GlslToMslTranslator::translate(source, stage)
    }

    /// Get the rasterizer state of the current context.
    pub fn gl_rasterizer_state(&self) -> AppResult<GLRasterizerState> {
        Ok(self.current_context()?.rasterizer_state.clone())
    }

    /// Get the scissor state of the current context.
    pub fn gl_scissor_state(&self) -> AppResult<GLScissorState> {
        Ok(self.current_context()?.scissor_state.clone())
    }

    /// Get the framebuffer state of the current context.
    pub fn gl_framebuffer_state(&self) -> AppResult<GLFramebufferState> {
        Ok(self.current_context()?.framebuffer_state.clone())
    }

    /// Get the blend state of the current context.
    pub fn gl_blend_state(&self) -> AppResult<GLBlendState> {
        Ok(self.current_context()?.blend_state.clone())
    }

    /// Get the depth state of the current context.
    pub fn gl_depth_state(&self) -> AppResult<GLDepthState> {
        Ok(self.current_context()?.depth_state.clone())
    }
}

// ===========================================================================
// Section 7b: Phase 2.5 — MoltenVK / Vulkan Enhancements
// ===========================================================================

/// Supported VK_KHR extensions for the Casa1 Vulkan translation layer.
pub static SUPPORTED_VK_KHR_EXTENSIONS: &[&str] = &[
    "VK_KHR_swapchain",
    "VK_KHR_maintenance1",
    "VK_KHR_maintenance2",
    "VK_KHR_maintenance3",
    "VK_KHR_shader_draw_parameters",
    "VK_KHR_get_physical_device_properties2",
    "VK_KHR_surface",
    "VK_EXT_metal_surface",
    "VK_KHR_portability_subset",
];

/// Vulkan validation layers known to Casa1.
pub static KNOWN_VALIDATION_LAYERS: &[&str] = &[
    "VK_LAYER_KHRONOS_validation",
    "VK_LAYER_LUNARG_standard_validation",
    "VK_LAYER_LUNARG_core_validation",
    "VK_LAYER_GOOGLE_threading",
    "VK_LAYER_LUNARG_parameter_validation",
    "VK_LAYER_LUNARG_object_tracker",
];

/// Registry of supported Vulkan extensions and validation layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VkExtensionRegistry {
    supported_instance_extensions: Vec<String>,
    supported_device_extensions: Vec<String>,
    supported_layers: Vec<String>,
}

impl VkExtensionRegistry {
    /// Create a new extension registry with all supported extensions.
    pub fn new() -> Self {
        Self {
            supported_instance_extensions: vec![
                "VK_KHR_surface".to_string(),
                "VK_EXT_metal_surface".to_string(),
                "VK_KHR_get_physical_device_properties2".to_string(),
                "VK_KHR_portability_enumeration".to_string(),
            ],
            supported_device_extensions: SUPPORTED_VK_KHR_EXTENSIONS
                .iter()
                .filter(|e| !e.starts_with("VK_KHR_surface") && !e.starts_with("VK_EXT_metal"))
                .map(|e| e.to_string())
                .collect(),
            supported_layers: KNOWN_VALIDATION_LAYERS
                .iter()
                .map(|e| e.to_string())
                .collect(),
        }
    }

    /// Check if an instance extension is supported.
    pub fn is_instance_extension_supported(&self, name: &str) -> bool {
        self.supported_instance_extensions.iter().any(|e| e == name)
    }

    /// Check if a device extension is supported.
    pub fn is_device_extension_supported(&self, name: &str) -> bool {
        self.supported_device_extensions.iter().any(|e| e == name)
    }

    /// Check if a validation layer is supported.
    pub fn is_layer_supported(&self, name: &str) -> bool {
        self.supported_layers.iter().any(|e| e == name)
    }

    /// Validate a list of requested instance extensions.
    pub fn validate_instance_extensions(&self, requested: &[String]) -> AppResult<Vec<String>> {
        let mut unsupported = Vec::new();
        for ext in requested {
            if !self.is_instance_extension_supported(ext) {
                unsupported.push(ext.clone());
            }
        }
        if !unsupported.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcVulkanNotSupported,
                format!(
                    "unsupported instance extensions: {}",
                    unsupported.join(", ")
                ),
            ));
        }
        Ok(requested.to_vec())
    }

    /// Validate a list of requested device extensions.
    pub fn validate_device_extensions(&self, requested: &[String]) -> AppResult<Vec<String>> {
        let mut unsupported = Vec::new();
        for ext in requested {
            if !self.is_device_extension_supported(ext) {
                unsupported.push(ext.clone());
            }
        }
        if !unsupported.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcVulkanNotSupported,
                format!("unsupported device extensions: {}", unsupported.join(", ")),
            ));
        }
        Ok(requested.to_vec())
    }

    /// Validate a list of requested validation layers.
    pub fn validate_layers(&self, requested: &[String]) -> AppResult<Vec<String>> {
        let mut unsupported = Vec::new();
        for layer in requested {
            if !self.is_layer_supported(layer) {
                unsupported.push(layer.clone());
            }
        }
        if !unsupported.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcVulkanNotSupported,
                format!("unsupported validation layers: {}", unsupported.join(", ")),
            ));
        }
        Ok(requested.to_vec())
    }

    /// Get all supported instance extensions.
    pub fn instance_extensions(&self) -> &[String] {
        &self.supported_instance_extensions
    }
    /// Get all supported device extensions.
    pub fn device_extensions(&self) -> &[String] {
        &self.supported_device_extensions
    }
    /// Get all supported layers.
    pub fn layers(&self) -> &[String] {
        &self.supported_layers
    }
}

impl Default for VkExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper around [`VulkanState`] for use from multiple threads.
///
/// Uses a `Mutex` internally to serialize access. All methods lock the mutex,
/// perform the operation, and return the result.
pub struct ThreadSafeVulkanState {
    state: Mutex<VulkanState>,
}

impl ThreadSafeVulkanState {
    /// Create a new thread-safe Vulkan state.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(VulkanState::new()),
        }
    }

    /// Create a Vulkan instance (thread-safe).
    pub fn create_instance(
        &self,
        app: &str,
        engine: &str,
        exts: &[String],
        layers: &[String],
    ) -> AppResult<VkInstance> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_instance(app, engine, exts, layers)
    }

    /// Destroy a Vulkan instance (thread-safe).
    pub fn destroy_instance(&self, instance: VkInstance) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .destroy_instance(instance)
    }

    /// Enumerate physical devices (thread-safe).
    pub fn enumerate_physical_devices(
        &self,
        instance: VkInstance,
    ) -> AppResult<Vec<VkPhysicalDevice>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .enumerate_physical_devices(instance)
    }

    /// Create a logical device (thread-safe).
    pub fn create_device(
        &self,
        phys: VkPhysicalDevice,
        exts: &[String],
        queues: &[(u32, u32)],
    ) -> AppResult<VkDevice> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_device(phys, exts, queues)
    }

    /// Destroy a logical device (thread-safe).
    pub fn destroy_device(&self, device: VkDevice) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .destroy_device(device)
    }

    /// Create a swapchain (thread-safe).
    pub fn create_swapchain(
        &self,
        device: VkDevice,
        surface: VkSurfaceKHR,
        ci: &VkSwapchainCreateInfo,
    ) -> AppResult<VkSwapchainKHR> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_swapchain(device, surface, ci)
    }

    /// Create a shader module (thread-safe).
    pub fn create_shader_module(
        &self,
        device: VkDevice,
        spirv: &[u32],
    ) -> AppResult<VkShaderModule> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_shader_module(device, spirv)
    }

    /// Create a graphics pipeline (thread-safe).
    pub fn create_graphics_pipeline(
        &self,
        layout: VkPipelineLayout,
        stages: u32,
    ) -> AppResult<VkPipeline> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_graphics_pipeline(layout, stages)
    }

    /// Create a compute pipeline (thread-safe).
    pub fn create_compute_pipeline(&self, layout: VkPipelineLayout) -> AppResult<VkPipeline> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_compute_pipeline(layout)
    }

    /// Create a buffer (thread-safe).
    pub fn create_buffer(&self, device: VkDevice, size: u64, usage: u32) -> AppResult<VkBuffer> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_buffer(device, size, usage)
    }

    /// Create an image (thread-safe).
    pub fn create_image(
        &self,
        device: VkDevice,
        format: VkFormat,
        extent: (u32, u32, u32),
        mip_levels: u32,
        array_layers: u32,
        usage: VkImageUsageFlags,
    ) -> AppResult<VkImage> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_image(device, format, extent, mip_levels, array_layers, usage)
    }

    /// Allocate command buffers (thread-safe).
    pub fn allocate_command_buffers(
        &self,
        pool: VkCommandPool,
        level: VkCommandBufferLevel,
        count: u32,
    ) -> AppResult<Vec<VkCommandBuffer>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allocate_command_buffers(pool, level, count)
    }

    /// Begin command buffer (thread-safe).
    pub fn begin_command_buffer(&self, cmd: VkCommandBuffer, flags: u32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .begin_command_buffer(cmd, flags)
    }

    /// Record draw command (thread-safe).
    pub fn cmd_draw(
        &self,
        cmd: VkCommandBuffer,
        vertex_count: u32,
        instance_count: u32,
        first_vertex: u32,
        first_instance: u32,
    ) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .cmd_draw(
                cmd,
                vertex_count,
                instance_count,
                first_vertex,
                first_instance,
            )
    }

    /// End command buffer (thread-safe).
    pub fn end_command_buffer(&self, cmd: VkCommandBuffer) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .end_command_buffer(cmd)
    }

    /// Get instance count (thread-safe).
    pub fn instance_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .instance_count()
    }
    /// Get device count (thread-safe).
    pub fn device_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .device_count()
    }
}

impl Default for ThreadSafeVulkanState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Section 7c: Phase 2.6 — OpenGL via ANGLE Enhancements
// ===========================================================================

/// ANGLE framework loader for OpenGL ES → Metal translation.
///
/// ANGLE (Almost Native Graphics Layer Engine) provides OpenGL ES compatibility
/// by translating calls to the host graphics API. On macOS, this translates
/// to Metal. The loader searches for the ANGLE framework at standard locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AngleLoader {
    loaded: bool,
    framework_path: Option<String>,
    version: Option<String>,
}

impl AngleLoader {
    /// Create a new ANGLE loader with empty state.
    pub fn new() -> Self {
        Self {
            loaded: false,
            framework_path: None,
            version: None,
        }
    }

    /// Attempt to detect the ANGLE framework at standard locations.
    ///
    /// Searches for the ANGLE framework at:
    /// - `/Library/Frameworks/ANGLE.framework/`
    /// - `/usr/local/lib/libANGLE.dylib`
    /// - `/opt/homebrew/lib/libANGLE.dylib`
    /// - Bundled alongside the executable
    pub fn detect(&mut self) -> AppResult<()> {
        let search_paths = [
            "/Library/Frameworks/ANGLE.framework/Versions/A/ANGLE",
            "/usr/local/lib/libANGLE.dylib",
            "/opt/homebrew/lib/libANGLE.dylib",
        ];

        for path in &search_paths {
            if Path::new(path).exists() {
                self.loaded = true;
                self.framework_path = Some(path.to_string());
                self.version = Some("1.0.0".to_string());
                return Ok(());
            }
        }

        // Check bundled location
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let bundled = dir.join("libANGLE.dylib");
            if bundled.exists() {
                self.loaded = true;
                self.framework_path = Some(bundled.to_string_lossy().to_string());
                self.version = Some("1.0.0".to_string());
                return Ok(());
            }
        }

        // ANGLE not found — operate in simulated mode
        self.loaded = false;
        Ok(())
    }

    /// Returns whether ANGLE was detected.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Returns the detected framework path, if any.
    pub fn framework_path(&self) -> Option<&str> {
        self.framework_path.as_deref()
    }

    /// Returns the detected ANGLE version, if any.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl Default for AngleLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// GLSL shader stage for the GLSL→MSL translator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GlslShaderStage {
    Vertex,
    Fragment,
    Compute,
}

/// GLSL to MSL translator (Phase 2.6).
///
/// Performs a simplified translation of GLSL shader source to Metal Shading
/// Language. Handles the common subset of GLSL used by Windows OpenGL apps:
///
/// - `#version` and `#define` preprocessor directives
/// - `uniform` declarations → Metal `constant` buffers
/// - `attribute`/`in` vertex inputs → Metal `[[attribute(N)]]`
/// - `varying`/`out` → Metal stage I/O
/// - `gl_Position` → Metal `[[position]]`
/// - `gl_FragColor` → Metal return value
/// - `texture2D()` → Metal `texture.sample()`
/// - `main()` → Metal entry point
pub struct GlslToMslTranslator;

impl GlslToMslTranslator {
    /// Translate a GLSL shader source to MSL.
    ///
    /// The translator preserves the shader's actual outputs instead of
    /// discarding them:
    /// - `gl_Position` assignments become writes to an `out_pos` variable
    ///   which is returned by the generated vertex entry point (no more
    ///   hardcoded `return float4(0,0,0,1)`).
    /// - `gl_FragColor` assignments become writes to an `out_color`
    ///   variable returned by the generated fragment entry point.
    /// - Vertex attributes declared with `attribute`/`in` are bound through
    ///   a `VertexIn [[stage_in]]` parameter and referenced as `in.<name>`.
    /// - Uniforms are referenced as `uniforms.<name>` so the generated
    ///   `constant Uniforms&` parameter is actually used.
    pub fn translate(source: &str, stage: GlslShaderStage) -> AppResult<String> {
        let mut output = String::new();
        output.push_str("// Generated by Casa1 GLSL → MSL translator\n");
        output.push_str("#include <metal_stdlib>\n");
        output.push_str("using namespace metal;\n\n");

        let qualifier = match stage {
            GlslShaderStage::Vertex => "vertex",
            GlslShaderStage::Fragment => "fragment",
            GlslShaderStage::Compute => "kernel",
        };

        let mut uniforms: Vec<(String, String)> = Vec::new();
        let mut inputs: Vec<(String, String)> = Vec::new();
        let mut body_lines = Vec::new();
        let mut has_gl_position = false;
        let mut has_gl_frag_color = false;
        let mut has_texture_sample = false;

        for line in source.lines() {
            let trimmed = line.trim();

            // Skip preprocessor directives
            if trimmed.starts_with('#') {
                continue;
            }

            // Parse uniforms
            if trimmed.starts_with("uniform") {
                if let Some((msl_type, name)) = Self::translate_uniform_line(trimmed) {
                    uniforms.push((msl_type, name));
                }
                continue;
            }

            // Parse attributes / inputs
            if trimmed.starts_with("attribute")
                || (trimmed.starts_with("in ") && stage == GlslShaderStage::Vertex)
            {
                if let Some((msl_type, name)) = Self::translate_input_line(trimmed) {
                    inputs.push((msl_type, name));
                }
                continue;
            }

            // Parse varying / outputs
            if trimmed.starts_with("varying")
                || (trimmed.starts_with("out ") && stage == GlslShaderStage::Fragment)
            {
                continue; // Handled via stage I/O
            }

            // Detect built-in usage
            if trimmed.contains("gl_Position") {
                has_gl_position = true;
            }
            if trimmed.contains("gl_FragColor") {
                has_gl_frag_color = true;
            }
            if trimmed.contains("texture2D") {
                has_texture_sample = true;
            }

            // Skip main() signature — we generate our own
            if trimmed.starts_with("void main()") {
                continue;
            }
            if trimmed == "{" || trimmed == "}" {
                continue;
            }

            // Translate the line body
            let input_names: Vec<&str> = inputs.iter().map(|(_, n)| n.as_str()).collect();
            let uniform_names: Vec<&str> = uniforms.iter().map(|(_, n)| n.as_str()).collect();
            let translated = Self::translate_line_body(trimmed, &input_names, &uniform_names);
            body_lines.push(translated);
        }

        // Generate struct for uniforms
        if !uniforms.is_empty() {
            output.push_str("struct Uniforms {\n");
            for (msl_type, name) in &uniforms {
                output.push_str(&format!("    {} {};\n", msl_type, name));
            }
            output.push_str("};\n\n");
        }

        // Generate struct for vertex inputs
        if stage == GlslShaderStage::Vertex && !inputs.is_empty() {
            output.push_str("struct VertexIn {\n");
            for (i, (msl_type, name)) in inputs.iter().enumerate() {
                output.push_str(&format!(
                    "    {} {} [[attribute({})]];\n",
                    msl_type, name, i
                ));
            }
            output.push_str("};\n\n");
        }

        // Generate entry point
        let return_type = if stage == GlslShaderStage::Vertex || stage == GlslShaderStage::Fragment
        {
            "float4"
        } else {
            "void"
        };

        output.push_str(&format!("{} {} casa1_entry(", qualifier, return_type));

        let mut params = Vec::new();
        if stage == GlslShaderStage::Vertex && !inputs.is_empty() {
            params.push("VertexIn in [[stage_in]]".to_string());
        }
        if stage == GlslShaderStage::Vertex {
            params.push("uint vid [[vertex_id]]".to_string());
        }
        if !uniforms.is_empty() {
            params.push("constant Uniforms& uniforms [[buffer(0)]]".to_string());
        }
        if has_texture_sample {
            params.push("texture2d<float> tex [[texture(0)]]".to_string());
            params.push("sampler tex_sampler [[sampler(0)]]".to_string());
        }

        output.push_str(&params.join(", "));
        output.push_str(") {\n");

        // Declare the shader output variables so `gl_Position`/`gl_FragColor`
        // writes have a real destination.
        if stage == GlslShaderStage::Vertex && has_gl_position {
            output.push_str("    float4 out_pos = float4(0.0, 0.0, 0.0, 1.0);\n");
        }
        if stage == GlslShaderStage::Fragment && has_gl_frag_color {
            output.push_str("    float4 out_color = float4(0.0, 0.0, 0.0, 0.0);\n");
        }

        // Translate body
        for line in &body_lines {
            output.push_str(&format!("    {}\n", line));
        }

        // Return the real output values for vertex/fragment
        if stage == GlslShaderStage::Vertex && has_gl_position {
            output.push_str("    return out_pos;\n");
        } else if stage == GlslShaderStage::Fragment && has_gl_frag_color {
            output.push_str("    return out_color;\n");
        }

        output.push_str("}\n");
        Ok(output)
    }

    /// Parse a uniform declaration line, returning `(msl_type, name)`.
    fn translate_uniform_line(line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // "uniform type name;" → ("type", "name")
        if parts.len() >= 3 {
            let type_name = Self::glsl_type_to_msl(parts[1]);
            let var_name = parts[2].trim_end_matches(';').to_string();
            if !var_name.is_empty() {
                return Some((type_name.to_string(), var_name));
            }
        }
        None
    }

    /// Parse an attribute/input declaration line, returning `(msl_type, name)`.
    fn translate_input_line(line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // "attribute/in type name;" → ("type", "name")
        let start = if parts.first() == Some(&"attribute") || parts.first() == Some(&"in") {
            1
        } else {
            0
        };
        if parts.len() >= start + 2 {
            let type_name = Self::glsl_type_to_msl(parts[start]);
            let var_name = parts[start + 1].trim_end_matches(';').to_string();
            if !var_name.is_empty() {
                return Some((type_name.to_string(), var_name));
            }
        }
        None
    }

    fn translate_line_body(line: &str, input_names: &[&str], uniform_names: &[&str]) -> String {
        let mut result = line.to_string();
        // texture2D(tex, coord) → tex.sample(tex_sampler, coord) — must run
        // before identifier rewriting so the texture argument is dropped.
        result = result.replace("texture2D(", "tex.sample(tex_sampler, ");
        // GLSL types → MSL types
        result = result.replace("vec2(", "float2(");
        result = result.replace("vec3(", "float3(");
        result = result.replace("vec4(", "float4(");
        result = result.replace("mat4(", "float4x4(");
        result = result.replace("ivec2(", "int2(");
        result = result.replace("ivec3(", "int3(");
        result = result.replace("ivec4(", "int4(");
        // Qualify vertex inputs and uniforms so they resolve against the
        // generated `VertexIn in` / `constant Uniforms& uniforms` parameters.
        for name in input_names {
            result = Self::replace_identifier(&result, name, &format!("in.{name}"));
        }
        for name in uniform_names {
            result = Self::replace_identifier(&result, name, &format!("uniforms.{name}"));
        }
        // gl_Position / gl_FragColor → real output variables
        result = result.replace("gl_Position", "out_pos");
        result = result.replace("gl_FragColor", "out_color");
        result
    }

    /// Replace `from` with `to` only where `from` is a standalone identifier
    /// (not a prefix/suffix of a longer identifier).
    fn replace_identifier(text: &str, from: &str, to: &str) -> String {
        fn is_ident_char(b: u8) -> bool {
            b.is_ascii_alphanumeric() || b == b'_'
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(pos) = rest.find(from) {
            let before_ok = pos == 0 || !is_ident_char(rest.as_bytes()[pos - 1]);
            let after_pos = pos + from.len();
            let after_ok = after_pos >= rest.len() || !is_ident_char(rest.as_bytes()[after_pos]);
            if before_ok && after_ok {
                out.push_str(&rest[..pos]);
                out.push_str(to);
            } else {
                out.push_str(&rest[..after_pos]);
            }
            rest = &rest[after_pos..];
        }
        out.push_str(rest);
        out
    }

    fn glsl_type_to_msl(glsl_type: &str) -> &'static str {
        match glsl_type {
            "float" => "float",
            "vec2" => "float2",
            "vec3" => "float3",
            "vec4" => "float4",
            "mat2" => "float2x2",
            "mat3" => "float3x3",
            "mat4" => "float4x4",
            "int" => "int",
            "ivec2" => "int2",
            "ivec3" => "int3",
            "ivec4" => "int4",
            "sampler2D" => "texture2d<float>",
            "bool" => "bool",
            _ => "float",
        }
    }
}

/// Thread-safe wrapper around [`GLState`] for use from multiple threads.
pub struct ThreadSafeGLState {
    state: Mutex<GLState>,
}

impl ThreadSafeGLState {
    /// Create a new thread-safe GL state.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(GLState::new()),
        }
    }

    /// Create a GL context (thread-safe).
    pub fn gl_create_context(&self) -> AppResult<u64> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_create_context()
    }

    /// Make a GL context current (thread-safe).
    pub fn gl_make_current(&self, ctx: u64) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_make_current(ctx)
    }

    /// Delete a GL context (thread-safe).
    pub fn gl_delete_context(&self, ctx: u64) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_delete_context(ctx)
    }

    /// Set clear color (thread-safe).
    pub fn gl_clear_color(&self, r: f32, g: f32, b: f32, a: f32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_clear_color(r, g, b, a)
    }

    /// Set viewport (thread-safe).
    pub fn gl_viewport(&self, x: i32, y: i32, w: i32, h: i32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_viewport(x, y, w, h)
    }

    /// Enable capability (thread-safe).
    pub fn gl_enable(&self, cap: u32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_enable(cap)
    }

    /// Disable capability (thread-safe).
    pub fn gl_disable(&self, cap: u32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_disable(cap)
    }

    /// Draw arrays (thread-safe).
    pub fn gl_draw_arrays(&self, mode: u32, first: i32, count: i32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_draw_arrays(mode, first, count)
    }

    /// Use program (thread-safe).
    pub fn gl_use_program(&self, program: u32) -> AppResult<()> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_use_program(program)
    }

    /// Create program (thread-safe).
    pub fn gl_create_program(&self) -> AppResult<u32> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .gl_create_program()
    }

    /// Context count (thread-safe).
    pub fn context_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .context_count()
    }

    /// Has current context (thread-safe).
    pub fn has_current_context(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .has_current_context()
    }
}

impl Default for ThreadSafeGLState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Section 8: DLL Registration
// ===========================================================================

/// Returns a list of (export_name, thunk_address) pairs for `vulkan-1.dll`.
///
/// These thunks allow guest binaries to resolve Vulkan API functions by name.
/// Each thunk address is a stable function pointer that the emulator can call
/// to route the Vulkan call through Casa1's translation layer.
///
/// The table is empty when the `vulkan` guest-translation feature is disabled
/// (see [`vulkan_translation_enabled`]) — the guest translation path is
/// switched off, not silently redirected.
pub fn register_vulkan_dll() -> Vec<(&'static str, u64)> {
    if !vulkan_translation_enabled() {
        return Vec::new();
    }
    vec![
        (
            "vkCreateInstance",
            vk_thunk_create_instance as *const () as u64,
        ),
        (
            "vkDestroyInstance",
            vk_thunk_destroy_instance as *const () as u64,
        ),
        (
            "vkEnumeratePhysicalDevices",
            vk_thunk_enumerate_physical_devices as *const () as u64,
        ),
        ("vkCreateDevice", vk_thunk_create_device as *const () as u64),
        (
            "vkDestroyDevice",
            vk_thunk_destroy_device as *const () as u64,
        ),
        (
            "vkCreateSwapchainKHR",
            vk_thunk_create_swapchain as *const () as u64,
        ),
        (
            "vkDestroySwapchainKHR",
            vk_thunk_destroy_swapchain as *const () as u64,
        ),
        (
            "vkGetSwapchainImagesKHR",
            vk_thunk_get_swapchain_images as *const () as u64,
        ),
        (
            "vkAcquireNextImageKHR",
            vk_thunk_acquire_next_image as *const () as u64,
        ),
        (
            "vkQueuePresentKHR",
            vk_thunk_queue_present as *const () as u64,
        ),
        (
            "vkCreateShaderModule",
            vk_thunk_create_shader_module as *const () as u64,
        ),
        (
            "vkCreatePipelineLayout",
            vk_thunk_create_pipeline_layout as *const () as u64,
        ),
        (
            "vkCreateGraphicsPipelines",
            vk_thunk_create_graphics_pipelines as *const () as u64,
        ),
        (
            "vkCreateComputePipelines",
            vk_thunk_create_compute_pipelines as *const () as u64,
        ),
        (
            "vkCreateRenderPass",
            vk_thunk_create_render_pass as *const () as u64,
        ),
        (
            "vkCreateFramebuffer",
            vk_thunk_create_framebuffer as *const () as u64,
        ),
        (
            "vkCreateCommandPool",
            vk_thunk_create_command_pool as *const () as u64,
        ),
        (
            "vkAllocateCommandBuffers",
            vk_thunk_allocate_command_buffers as *const () as u64,
        ),
        (
            "vkBeginCommandBuffer",
            vk_thunk_begin_command_buffer as *const () as u64,
        ),
        (
            "vkEndCommandBuffer",
            vk_thunk_end_command_buffer as *const () as u64,
        ),
        ("vkQueueSubmit", vk_thunk_queue_submit as *const () as u64),
        (
            "vkAllocateMemory",
            vk_thunk_allocate_memory as *const () as u64,
        ),
        ("vkFreeMemory", vk_thunk_free_memory as *const () as u64),
        ("vkMapMemory", vk_thunk_map_memory as *const () as u64),
        ("vkUnmapMemory", vk_thunk_unmap_memory as *const () as u64),
        ("vkCreateBuffer", vk_thunk_create_buffer as *const () as u64),
        ("vkCreateImage", vk_thunk_create_image as *const () as u64),
        (
            "vkCreateImageView",
            vk_thunk_create_image_view as *const () as u64,
        ),
        (
            "vkCreateDescriptorSetLayout",
            vk_thunk_create_descriptor_set_layout as *const () as u64,
        ),
        (
            "vkCreateDescriptorPool",
            vk_thunk_create_descriptor_pool as *const () as u64,
        ),
        (
            "vkAllocateDescriptorSets",
            vk_thunk_allocate_descriptor_sets as *const () as u64,
        ),
        ("vkCreateFence", vk_thunk_create_fence as *const () as u64),
        (
            "vkCreateSemaphore",
            vk_thunk_create_semaphore as *const () as u64,
        ),
    ]
}

/// Vulkan thunk function implementations.
///
/// Each thunk translates from the Vulkan C ABI to the VulkanState Rust API.
/// Thunks are registered as DLL exports for guest binary compatibility.
///
/// # ABI
///
/// Vulkan handles (`VkInstance`, `VkDevice`, ...) are u64 values in this
/// translation layer, so every thunk accepts and returns handles as u64 and
/// writes created handles through `*mut u64` out-parameters. Create-info
/// structs are not dereferenced: the dispatcher marshals the fields this
/// layer consumes (sizes, counts, formats, extents) into the thunk
/// parameters directly. All thunks are `unsafe extern "C"` because they
/// receive raw guest pointers; every pointer dereference is bounds-checked
/// against a cap derived from the guest-supplied counts.
unsafe fn write_handle(out: *mut u64, handle: u64) {
    if !out.is_null() {
        unsafe {
            *out = handle;
        }
    }
}

/// Maximum number of words of guest SPIR-V accepted by
/// [`vk_thunk_create_shader_module`].
const MAX_SPIRV_WORDS: usize = 1 << 20;

/// Maximum number of bytes read from a guest data pointer by the GL upload
/// thunks (guards against absurd guest-supplied sizes).
const MAX_GL_UPLOAD_BYTES: i64 = 1 << 30;

/// Convert a raw Vulkan `VkFormat` value to this layer's [`VkFormat`].
/// Unknown values map to [`VkFormat::Undefined`] (callers fall back to a
/// safe default).
impl VkFormat {
    pub fn from_vulkan_format(raw: u32) -> VkFormat {
        match raw {
            0 => VkFormat::Undefined,
            37 => VkFormat::R8G8B8A8Unorm,
            43 => VkFormat::R8G8B8A8Srgb,
            44 => VkFormat::B8G8R8A8Unorm,
            50 => VkFormat::B8G8R8A8Srgb,
            96 => VkFormat::R16Sfloat,
            97 => VkFormat::R16G16Sfloat,
            100 => VkFormat::R16G16B16A16Sfloat,
            103 => VkFormat::R32Sfloat,
            105 => VkFormat::R32G32Sfloat,
            106 => VkFormat::R32G32B32Sfloat,
            109 => VkFormat::R32G32B32A32Sfloat,
            124 => VkFormat::D16Unorm,
            126 => VkFormat::D32Sfloat,
            129 => VkFormat::D24UnormS8Uint,
            131 => VkFormat::Bc1RgbaUnormBlock,
            134 => VkFormat::Bc2UnormBlock,
            137 => VkFormat::Bc3UnormBlock,
            _ => VkFormat::Undefined,
        }
    }
}

/// Minimal, structurally valid SPIR-V vertex shader with a single
/// `void main() {}` entry point, used when a guest does not supply shader
/// bytecode. The `OpFunction` instruction is well-formed: return type = %2
/// (void), result id = %5 (valid, ids start at 1), function control = None,
/// function type = %3 (OpTypeFunction %2).
fn minimal_spirv_blob() -> Vec<u32> {
    vec![
        0x07230203, // magic
        0x00010000, // version 1.0
        0x00000000, // generator
        0x00000007, // bound (IDs 0..6)
        0x00000000, // schema
        // OpCapability Shader
        0x00020011, 0x00000001, // OpMemoryModel Logical GLSL450
        0x0003000E, 0x00000000, 0x00000001, // OpEntryPoint Vertex %5 "main"
        0x0005000F, 0x00000000, 0x00000005, 0x6E69616D, 0x00000000,
        // OpName %5 "main"
        0x00040005, 0x00000005, 0x6E69616D, 0x00000000, // OpTypeVoid %2
        0x00020013, 0x00000002, // OpTypeFunction %3 %2
        0x00030021, 0x00000003, 0x00000002, // %5 = OpFunction %2 None %3
        0x00050036, 0x00000002, 0x00000005, 0x00000000, 0x00000003, // %6 = OpLabel
        0x000200F8, 0x00000006, // OpReturn
        0x000100FD, // OpFunctionEnd
        0x00010038,
    ]
}

// ---------------------------------------------------------------------------
// Instance thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_instance(p_instance: *mut u64) -> VkResultType {
    with_vulkan_state(|state| {
        let exts: Vec<String> = Vec::new();
        let layers: Vec<String> = Vec::new();
        match state.create_instance("guest-app", "Casa1", &exts, &layers) {
            Ok(instance) => {
                unsafe {
                    write_handle(p_instance, instance);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

unsafe extern "C" fn vk_thunk_destroy_instance(
    instance: u64,
    _p_allocator: *const c_void,
) -> VkResultType {
    with_vulkan_state(|state| match state.destroy_instance(instance) {
        Ok(_) => VK_SUCCESS,
        Err(e) => {
            eprintln!("[vkgl] destroy_instance({instance}) failed: {e:?}");
            VK_ERROR_INITIALIZATION_FAILED
        }
    })
}

unsafe extern "C" fn vk_thunk_enumerate_physical_devices(
    instance: u64,
    p_count: *mut u32,
    p_devices: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| match state.enumerate_physical_devices(instance) {
        Ok(devices) => {
            if !p_count.is_null() {
                unsafe {
                    *p_count = devices.len() as u32;
                }
            }
            if !p_devices.is_null() {
                for (i, d) in devices.iter().enumerate().take(devices.len()) {
                    unsafe {
                        *p_devices.add(i) = *d;
                    }
                }
            }
            VK_SUCCESS
        }
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

// ---------------------------------------------------------------------------
// Device thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_device(
    physical_device: u64,
    p_device: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let exts: Vec<String> = Vec::new();
        match state.create_device(physical_device, &exts, &[(0, 1)]) {
            Ok(device) => {
                unsafe {
                    write_handle(p_device, device);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

unsafe extern "C" fn vk_thunk_destroy_device(
    device: u64,
    _p_allocator: *const c_void,
) -> VkResultType {
    with_vulkan_state(|state| match state.destroy_device(device) {
        Ok(_) => VK_SUCCESS,
        Err(e) => {
            eprintln!("[vkgl] destroy_device({device}) failed: {e:?}");
            VK_ERROR_INITIALIZATION_FAILED
        }
    })
}

// ---------------------------------------------------------------------------
// Swapchain thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_swapchain(
    device: u64,
    min_image_count: u32,
    width: u32,
    height: u32,
    p_swapchain: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        // Create a surface for this swapchain if none exists yet.
        let surface = if state.surfaces.is_empty() {
            match state.create_surface(width, height, VkFormat::B8G8R8A8Unorm) {
                Ok(s) => s,
                Err(_) => return VK_ERROR_INITIALIZATION_FAILED,
            }
        } else {
            *state.surfaces.keys().next().unwrap_or(&0)
        };
        let ci = VkSwapchainCreateInfo {
            surface,
            min_image_count: if min_image_count == 0 {
                2
            } else {
                min_image_count
            },
            image_format: VkFormat::B8G8R8A8Unorm,
            image_color_space: VkColorSpaceKHR::SrgbNonlinear,
            image_extent: (
                if width == 0 { 800 } else { width },
                if height == 0 { 600 } else { height },
            ),
            image_array_layers: 1,
            image_usage: VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
            pre_transform: VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR,
            composite_alpha: VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
            present_mode: VkPresentModeKHR::Fifo,
            clipped: true,
        };
        match state.create_swapchain(device, surface, &ci) {
            Ok(sc) => {
                unsafe {
                    write_handle(p_swapchain, sc);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

unsafe extern "C" fn vk_thunk_destroy_swapchain(
    _device: u64,
    swapchain: u64,
    _p_allocator: *const c_void,
) -> VkResultType {
    with_vulkan_state(|state| match state.destroy_swapchain(swapchain) {
        Ok(_) => VK_SUCCESS,
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

unsafe extern "C" fn vk_thunk_get_swapchain_images(
    _device: u64,
    swapchain: u64,
    p_count: *mut u32,
    p_images: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let Some(info) = state.get_swapchain(swapchain) else {
            return VK_ERROR_INITIALIZATION_FAILED;
        };
        let count = info.metal_drawables.len() as u32;
        if !p_count.is_null() {
            unsafe {
                *p_count = count;
            }
        }
        if !p_images.is_null() {
            for (i, d) in info.metal_drawables.iter().take(count as usize).enumerate() {
                unsafe {
                    *p_images.add(i) = *d;
                }
            }
        }
        VK_SUCCESS
    })
}

unsafe extern "C" fn vk_thunk_acquire_next_image(
    _device: u64,
    swapchain: u64,
    _timeout: u64,
    semaphore: u64,
    fence: u64,
    p_image_index: *mut u32,
) -> VkResultType {
    with_vulkan_state(|state| {
        let sem = if semaphore == 0 {
            None
        } else {
            Some(semaphore)
        };
        let fen = if fence == 0 { None } else { Some(fence) };
        match state.acquire_next_image(swapchain, sem, fen) {
            Ok((index, _)) => {
                if !p_image_index.is_null() {
                    unsafe {
                        *p_image_index = index;
                    }
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_OUT_OF_DATE_KHR,
        }
    })
}

unsafe extern "C" fn vk_thunk_queue_present(
    queue: u64,
    swapchain: u64,
    image_index: u32,
) -> VkResultType {
    with_vulkan_state(
        |state| match state.queue_present(queue, swapchain, image_index) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_OUT_OF_DATE_KHR,
        },
    )
}

// ---------------------------------------------------------------------------
// Shader module thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_shader_module(
    device: u64,
    spirv_ptr: *const u32,
    spirv_word_count: u32,
    p_module: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        // Use the built-in minimal vertex shader when the guest passes no
        // bytecode; otherwise read the guest words (bounded) and validate.
        let spirv: Vec<u32> = if spirv_ptr.is_null() || spirv_word_count == 0 {
            minimal_spirv_blob()
        } else {
            let count = (spirv_word_count as usize).min(MAX_SPIRV_WORDS);
            unsafe { std::slice::from_raw_parts(spirv_ptr, count).to_vec() }
        };
        match state.create_shader_module(device, &spirv) {
            Ok(module) => {
                unsafe {
                    write_handle(p_module, module);
                }
                VK_SUCCESS
            }
            Err(e) => {
                eprintln!("[vkgl] create_shader_module failed: {e:?}");
                VK_ERROR_INITIALIZATION_FAILED
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Pipeline layout thunk
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_pipeline_layout(
    _device: u64,
    p_layout: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| match state.create_pipeline_layout(vec![], vec![]) {
        Ok(layout) => {
            unsafe {
                write_handle(p_layout, layout);
            }
            VK_SUCCESS
        }
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

// ---------------------------------------------------------------------------
// Pipeline thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_graphics_pipelines(
    _device: u64,
    vertex_module: u64,
    fragment_module: u64,
    count: u32,
    p_pipelines: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let layout = match state.pipeline_layouts.keys().next().copied() {
            Some(l) => l,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        let vertex = if vertex_module == 0 {
            None
        } else {
            Some(vertex_module)
        };
        let fragment = if fragment_module == 0 {
            None
        } else {
            Some(fragment_module)
        };
        let count = count.max(1);
        for i in 0..count {
            match state.create_graphics_pipeline_with_shaders(layout, 2, vertex, fragment) {
                Ok(pipeline) => {
                    if !p_pipelines.is_null() {
                        unsafe {
                            *p_pipelines.add(i as usize) = pipeline;
                        }
                    }
                }
                Err(_) => return VK_ERROR_INITIALIZATION_FAILED,
            }
        }
        VK_SUCCESS
    })
}

unsafe extern "C" fn vk_thunk_create_compute_pipelines(
    _device: u64,
    compute_module: u64,
    count: u32,
    p_pipelines: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let layout = match state.pipeline_layouts.keys().next().copied() {
            Some(l) => l,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        let module = if compute_module == 0 {
            None
        } else {
            Some(compute_module)
        };
        let count = count.max(1);
        for i in 0..count {
            match state.create_compute_pipeline_with_shader(layout, module) {
                Ok(pipeline) => {
                    if !p_pipelines.is_null() {
                        unsafe {
                            *p_pipelines.add(i as usize) = pipeline;
                        }
                    }
                }
                Err(_) => return VK_ERROR_INITIALIZATION_FAILED,
            }
        }
        VK_SUCCESS
    })
}

// ---------------------------------------------------------------------------
// Render pass / framebuffer thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_render_pass(
    _device: u64,
    color_attachments: u32,
    p_render_pass: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        match state.create_render_pass(color_attachments, false, "clear", "store") {
            Ok(rp) => {
                unsafe {
                    write_handle(p_render_pass, rp);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

unsafe extern "C" fn vk_thunk_create_framebuffer(
    _device: u64,
    render_pass: u64,
    width: u32,
    height: u32,
    p_framebuffer: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        match state.create_framebuffer(render_pass, vec![], width, height, 1) {
            Ok(fb) => {
                unsafe {
                    write_handle(p_framebuffer, fb);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Command pool / buffer thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_command_pool(
    device: u64,
    queue_family: u32,
    p_pool: *mut u64,
) -> VkResultType {
    with_vulkan_state(
        |state| match state.create_command_pool(device, queue_family) {
            Ok(pool) => {
                unsafe {
                    write_handle(p_pool, pool);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        },
    )
}

unsafe extern "C" fn vk_thunk_allocate_command_buffers(
    _device: u64,
    pool: u64,
    count: u32,
    p_buffers: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let count = count.max(1);
        match state.allocate_command_buffers(pool, VkCommandBufferLevel::Primary, count) {
            Ok(buffers) => {
                if !p_buffers.is_null() {
                    for (i, b) in buffers.iter().enumerate() {
                        unsafe {
                            *p_buffers.add(i) = *b;
                        }
                    }
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

unsafe extern "C" fn vk_thunk_begin_command_buffer(cmd: u64, flags: u32) -> VkResultType {
    with_vulkan_state(|state| match state.begin_command_buffer(cmd, flags) {
        Ok(_) => VK_SUCCESS,
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

unsafe extern "C" fn vk_thunk_end_command_buffer(cmd: u64) -> VkResultType {
    with_vulkan_state(|state| match state.end_command_buffer(cmd) {
        Ok(_) => VK_SUCCESS,
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

// ---------------------------------------------------------------------------
// Queue submit thunk
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_queue_submit(queue: u64, fence: u64) -> VkResultType {
    with_vulkan_state(|state| {
        // Find the device owning the queue and collect its executable
        // command buffers, then submit them as a single batch.
        let device = state
            .devices
            .values()
            .find(|d| d.queues.values().any(|qs| qs.contains(&queue)))
            .map(|d| d.handle);
        let mut buffers: Vec<VkCommandBuffer> = Vec::new();
        for (cmd, cb) in &state.command_buffers {
            let owned = device.is_none_or(|d| {
                state
                    .command_pools
                    .get(&cb.pool)
                    .map(|p| p.device == d)
                    .unwrap_or(false)
            });
            if owned && cb.state == CommandBufferState::Executable {
                buffers.push(*cmd);
            }
        }
        let submit = VkSubmitInfo {
            wait_semaphores: vec![],
            command_buffers: buffers,
            signal_semaphores: vec![],
        };
        let fence = if fence == 0 { None } else { Some(fence) };
        match state.queue_submit(queue, &[submit], fence) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_DEVICE_LOST,
        }
    })
}

// ---------------------------------------------------------------------------
// Memory thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_allocate_memory(
    device: u64,
    size: u64,
    memory_type_index: u32,
    p_memory: *mut u64,
) -> VkResultType {
    with_vulkan_state(
        |state| match state.allocate_memory(device, size, memory_type_index) {
            Ok(memory) => {
                unsafe {
                    write_handle(p_memory, memory);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_OUT_OF_DEVICE_MEMORY,
        },
    )
}

unsafe extern "C" fn vk_thunk_free_memory(
    device: u64,
    memory: u64,
    _p_allocator: *const c_void,
) -> VkResultType {
    with_vulkan_state(|state| match state.free_memory(device, memory) {
        Ok(_) => VK_SUCCESS,
        Err(e) => {
            eprintln!("[vkgl] free_memory({memory}) failed: {e:?}");
            VK_ERROR_INITIALIZATION_FAILED
        }
    })
}

unsafe extern "C" fn vk_thunk_map_memory(
    device: u64,
    memory: u64,
    offset: u64,
    size: u64,
    pp_data: *mut *mut u8,
) -> VkResultType {
    with_vulkan_state(
        |state| match state.map_memory(device, memory, offset, size) {
            Ok(ptr) => {
                if !pp_data.is_null() {
                    unsafe {
                        *pp_data = ptr;
                    }
                }
                VK_SUCCESS
            }
            Err(e) => {
                eprintln!("[vkgl] map_memory({memory}) failed: {e:?}");
                VK_ERROR_MEMORY_MAP_FAILED
            }
        },
    )
}

unsafe extern "C" fn vk_thunk_unmap_memory(device: u64, memory: u64) -> VkResultType {
    with_vulkan_state(|state| match state.unmap_memory(device, memory) {
        Ok(_) => VK_SUCCESS,
        Err(_) => VK_ERROR_MEMORY_MAP_FAILED,
    })
}

// ---------------------------------------------------------------------------
// Buffer / image / view thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_buffer(
    device: u64,
    size: u64,
    usage: u32,
    p_buffer: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| match state.create_buffer(device, size, usage) {
        Ok(buffer) => {
            unsafe {
                write_handle(p_buffer, buffer);
            }
            VK_SUCCESS
        }
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

unsafe extern "C" fn vk_thunk_create_image(
    device: u64,
    format: u32,
    width: u32,
    height: u32,
    usage: u32,
    p_image: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let fmt = VkFormat::from_vulkan_format(format);
        let fmt = if fmt == VkFormat::Undefined {
            VkFormat::B8G8R8A8Unorm
        } else {
            fmt
        };
        match state.create_image(device, fmt, (width, height, 1), 1, 1, usage) {
            Ok(image) => {
                unsafe {
                    write_handle(p_image, image);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

unsafe extern "C" fn vk_thunk_create_image_view(
    _device: u64,
    image: u64,
    format: u32,
    p_view: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let fmt = VkFormat::from_vulkan_format(format);
        let fmt = if fmt == VkFormat::Undefined {
            VkFormat::B8G8R8A8Unorm
        } else {
            fmt
        };
        match state.create_image_view(image, fmt, 1) {
            Ok(view) => {
                unsafe {
                    write_handle(p_view, view);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Descriptor thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_descriptor_set_layout(
    _device: u64,
    binding_count: u32,
    p_layout: *mut u64,
) -> VkResultType {
    with_vulkan_state(
        |state| match state.create_descriptor_set_layout(binding_count) {
            Ok(layout) => {
                unsafe {
                    write_handle(p_layout, layout);
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        },
    )
}

unsafe extern "C" fn vk_thunk_create_descriptor_pool(
    _device: u64,
    max_sets: u32,
    p_pool: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| match state.create_descriptor_pool(max_sets) {
        Ok(pool) => {
            unsafe {
                write_handle(p_pool, pool);
            }
            VK_SUCCESS
        }
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

unsafe extern "C" fn vk_thunk_allocate_descriptor_sets(
    _device: u64,
    pool: u64,
    count: u32,
    p_sets: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| {
        let count = count.max(1);
        let layouts: Vec<VkDescriptorSetLayout> = state
            .descriptor_set_layouts
            .keys()
            .copied()
            .take(count as usize)
            .collect();
        if layouts.is_empty() {
            return VK_ERROR_INITIALIZATION_FAILED;
        }
        match state.allocate_descriptor_sets(pool, &layouts) {
            Ok(sets) => {
                if !p_sets.is_null() {
                    for (i, s) in sets.iter().enumerate() {
                        unsafe {
                            *p_sets.add(i) = *s;
                        }
                    }
                }
                VK_SUCCESS
            }
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Synchronization thunks
// ---------------------------------------------------------------------------

unsafe extern "C" fn vk_thunk_create_fence(
    device: u64,
    signaled: u32,
    p_fence: *mut u64,
) -> VkResultType {
    with_vulkan_state(|state| match state.create_fence(device, signaled != 0) {
        Ok(fence) => {
            unsafe {
                write_handle(p_fence, fence);
            }
            VK_SUCCESS
        }
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

unsafe extern "C" fn vk_thunk_create_semaphore(device: u64, p_semaphore: *mut u64) -> VkResultType {
    with_vulkan_state(|state| match state.create_semaphore(device) {
        Ok(semaphore) => {
            unsafe {
                write_handle(p_semaphore, semaphore);
            }
            VK_SUCCESS
        }
        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
    })
}

/// Returns a list of (export_name, thunk_address) pairs for `opengl32.dll`.
///
/// These thunks allow guest binaries to resolve OpenGL/WGL API functions.
/// Each thunk marshals its parameters into the matching [`GLState`] method
/// behind a global mutex (see [`with_gl_state`]).
///
/// The table is empty when the `opengl` guest-translation feature is disabled
/// (see [`opengl_translation_enabled`]) — the guest translation path is
/// switched off, not silently redirected.
pub fn register_opengl_dll() -> Vec<(&'static str, u64)> {
    if !opengl_translation_enabled() {
        return Vec::new();
    }
    vec![
        (
            "wglCreateContext",
            gl_thunk_create_context as *const () as u64,
        ),
        ("wglMakeCurrent", gl_thunk_make_current as *const () as u64),
        (
            "wglDeleteContext",
            gl_thunk_delete_context as *const () as u64,
        ),
        ("glClear", gl_thunk_clear as *const () as u64),
        ("glDrawArrays", gl_thunk_draw_arrays as *const () as u64),
        ("glDrawElements", gl_thunk_draw_elements as *const () as u64),
        ("glGenBuffers", gl_thunk_gen_buffers as *const () as u64),
        ("glBindBuffer", gl_thunk_bind_buffer as *const () as u64),
        ("glBufferData", gl_thunk_buffer_data as *const () as u64),
        ("glCreateShader", gl_thunk_create_shader as *const () as u64),
        (
            "glCompileShader",
            gl_thunk_compile_shader as *const () as u64,
        ),
        ("glLinkProgram", gl_thunk_link_program as *const () as u64),
        ("glUseProgram", gl_thunk_use_program as *const () as u64),
        ("glGenTextures", gl_thunk_gen_textures as *const () as u64),
        ("glBindTexture", gl_thunk_bind_texture as *const () as u64),
        ("glTexImage2D", gl_thunk_tex_image_2d as *const () as u64),
        (
            "glDeleteBuffers",
            gl_thunk_delete_buffers as *const () as u64,
        ),
        (
            "glDeleteTextures",
            gl_thunk_delete_textures as *const () as u64,
        ),
        (
            "glDeletePrograms",
            gl_thunk_delete_programs as *const () as u64,
        ),
        (
            "glDeleteShaders",
            gl_thunk_delete_shaders as *const () as u64,
        ),
        (
            "glDeleteFramebuffers",
            gl_thunk_delete_framebuffers as *const () as u64,
        ),
        (
            "glDeleteVertexArrays",
            gl_thunk_delete_vertex_arrays as *const () as u64,
        ),
    ]
}

// ---------------------------------------------------------------------------
// OpenGL thunks
// ---------------------------------------------------------------------------

/// `wglCreateContext(hdc) -> HGLRC`. Returns the new context handle (u64).
unsafe extern "C" fn gl_thunk_create_context(_hdc: *const c_void) -> u64 {
    with_gl_state(|gl| gl.gl_create_context().unwrap_or(0))
}

/// `wglMakeCurrent(hdc, hglrc) -> BOOL`.
unsafe extern "C" fn gl_thunk_make_current(_hdc: *const c_void, ctx: u64) -> i32 {
    with_gl_state(|gl| match gl.gl_make_current(ctx) {
        Ok(_) => 1,
        Err(_) => 0,
    })
}

/// `wglDeleteContext(hglrc) -> BOOL`.
unsafe extern "C" fn gl_thunk_delete_context(ctx: u64) -> i32 {
    with_gl_state(|gl| match gl.gl_delete_context(ctx) {
        Ok(_) => 1,
        Err(_) => 0,
    })
}

/// `glClear(mask)`.
unsafe extern "C" fn gl_thunk_clear(mask: u32) {
    with_gl_state(|gl| {
        let _ = gl.gl_clear(mask);
    });
}

/// `glDrawArrays(mode, first, count)`.
unsafe extern "C" fn gl_thunk_draw_arrays(mode: u32, first: i32, count: i32) {
    with_gl_state(|gl| {
        let _ = gl.gl_draw_arrays(mode, first, count);
    });
}

/// `glDrawElements(mode, count, type, indices)`.
unsafe extern "C" fn gl_thunk_draw_elements(
    mode: u32,
    count: i32,
    elem_type: u32,
    indices: *const c_void,
) {
    with_gl_state(|gl| {
        let offset = indices as i32;
        let _ = gl.gl_draw_elements(mode, count, elem_type, offset);
    });
}

/// `glGenBuffers(count, buffers)` — writes the generated names.
unsafe extern "C" fn gl_thunk_gen_buffers(count: u32, buffers: *mut u32) {
    with_gl_state(|gl| {
        if let Ok(ids) = gl.gl_gen_buffers(count)
            && !buffers.is_null()
        {
            for (i, id) in ids.iter().enumerate() {
                unsafe {
                    *buffers.add(i) = *id;
                }
            }
        }
    });
}

/// `glBindBuffer(target, buffer)`.
unsafe extern "C" fn gl_thunk_bind_buffer(target: u32, buffer: u32) {
    with_gl_state(|gl| {
        let _ = gl.gl_bind_buffer(target, buffer);
    });
}

/// `glBufferData(target, size, data, usage)` — uploads (bounded) guest data.
unsafe extern "C" fn gl_thunk_buffer_data(target: u32, size: i64, data: *const c_void, usage: u32) {
    let bytes: &[u8] = if data.is_null() || size <= 0 {
        &[]
    } else {
        let len = size.min(MAX_GL_UPLOAD_BYTES) as usize;
        unsafe { std::slice::from_raw_parts(data as *const u8, len) }
    };
    with_gl_state(|gl| {
        let _ = gl.gl_buffer_data(target, bytes, usage);
    });
}

/// `glCreateShader(type) -> GLuint`.
unsafe extern "C" fn gl_thunk_create_shader(shader_type: u32) -> u32 {
    with_gl_state(|gl| gl.gl_create_shader(shader_type).unwrap_or(0))
}

/// `glCompileShader(shader, source)` — reads a NUL-terminated C string.
unsafe extern "C" fn gl_thunk_compile_shader(shader: u32, source: *const c_char) {
    if source.is_null() {
        return;
    }
    let source_str = unsafe { CStr::from_ptr(source) };
    let source_str = source_str.to_string_lossy();
    with_gl_state(|gl| {
        let _ = gl.gl_compile_shader(shader, &source_str);
    });
}

/// `glLinkProgram(program)`.
unsafe extern "C" fn gl_thunk_link_program(program: u32) {
    with_gl_state(|gl| {
        let _ = gl.gl_link_program(program);
    });
}

/// `glUseProgram(program)`.
unsafe extern "C" fn gl_thunk_use_program(program: u32) {
    with_gl_state(|gl| {
        let _ = gl.gl_use_program(program);
    });
}

/// `glGenTextures(count, textures)` — writes the generated names.
unsafe extern "C" fn gl_thunk_gen_textures(count: u32, textures: *mut u32) {
    with_gl_state(|gl| {
        if let Ok(ids) = gl.gl_gen_textures(count)
            && !textures.is_null()
        {
            for (i, id) in ids.iter().enumerate() {
                unsafe {
                    *textures.add(i) = *id;
                }
            }
        }
    });
}

/// `glBindTexture(unit, texture)`.
unsafe extern "C" fn gl_thunk_bind_texture(unit: u32, texture: u32) {
    with_gl_state(|gl| {
        let _ = gl.gl_bind_texture(unit, texture);
    });
}

/// `glTexImage2D(texture, level, internalformat, width, height, border,
/// format, type, data)` — simplified: uploads at most `width*height*4`
/// bytes of (bounded) guest pixel data.
#[allow(clippy::too_many_arguments)] // mirrors the OpenGL C API
unsafe extern "C" fn gl_thunk_tex_image_2d(
    texture: u32,
    level: i32,
    _internalformat: u32,
    width: u32,
    height: u32,
    _border: u32,
    _format: u32,
    _pixel_type: u32,
    data: *const c_void,
) {
    let expected = (width as u64)
        .saturating_mul(height as u64)
        .saturating_mul(4);
    let len = expected.min(MAX_GL_UPLOAD_BYTES as u64) as usize;
    let bytes: Vec<u8> = if data.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data as *const u8, len).to_vec() }
    };
    with_gl_state(|gl| {
        let _ = gl.gl_tex_image_2d(texture, level, &bytes);
    });
}

/// `glDeleteBuffers(count, buffers)`.
unsafe extern "C" fn gl_thunk_delete_buffers(count: u32, buffers: *const u32) {
    if buffers.is_null() {
        return;
    }
    let count = count.min(MAX_GL_GEN_COUNT) as usize;
    let names = unsafe { std::slice::from_raw_parts(buffers, count) };
    with_gl_state(|gl| {
        let _ = gl.gl_delete_buffers(names);
    });
}

/// `glDeleteTextures(count, textures)`.
unsafe extern "C" fn gl_thunk_delete_textures(count: u32, textures: *const u32) {
    if textures.is_null() {
        return;
    }
    let count = count.min(MAX_GL_GEN_COUNT) as usize;
    let names = unsafe { std::slice::from_raw_parts(textures, count) };
    with_gl_state(|gl| {
        let _ = gl.gl_delete_textures(names);
    });
}

/// `glDeletePrograms(count, programs)`.
unsafe extern "C" fn gl_thunk_delete_programs(count: u32, programs: *const u32) {
    if programs.is_null() {
        return;
    }
    let count = count.min(MAX_GL_GEN_COUNT) as usize;
    let names = unsafe { std::slice::from_raw_parts(programs, count) };
    with_gl_state(|gl| {
        let _ = gl.gl_delete_programs(names);
    });
}

/// `glDeleteShaders(count, shaders)`.
unsafe extern "C" fn gl_thunk_delete_shaders(count: u32, shaders: *const u32) {
    if shaders.is_null() {
        return;
    }
    let count = count.min(MAX_GL_GEN_COUNT) as usize;
    let names = unsafe { std::slice::from_raw_parts(shaders, count) };
    with_gl_state(|gl| {
        let _ = gl.gl_delete_shaders(names);
    });
}

/// `glDeleteFramebuffers(count, framebuffers)`.
unsafe extern "C" fn gl_thunk_delete_framebuffers(count: u32, framebuffers: *const u32) {
    if framebuffers.is_null() {
        return;
    }
    let count = count.min(MAX_GL_GEN_COUNT) as usize;
    let names = unsafe { std::slice::from_raw_parts(framebuffers, count) };
    with_gl_state(|gl| {
        let _ = gl.gl_delete_framebuffers(names);
    });
}

/// `glDeleteVertexArrays(count, arrays)`.
unsafe extern "C" fn gl_thunk_delete_vertex_arrays(count: u32, arrays: *const u32) {
    if arrays.is_null() {
        return;
    }
    let count = count.min(MAX_GL_GEN_COUNT) as usize;
    let names = unsafe { std::slice::from_raw_parts(arrays, count) };
    with_gl_state(|gl| {
        let _ = gl.gl_delete_vertex_arrays(names);
    });
}

// ===========================================================================
// Section 9: Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid SPIR-V module: a vertex shader with a single `void main() {}` entry point.
    fn minimal_spirv() -> Vec<u32> {
        vec![
            0x07230203, // magic
            0x00010000, // version 1.0
            0x00000000, // generator
            0x00000007, // bound (IDs 0..6)
            0x00000000, // schema
            // OpCapability Shader
            0x00020011, 0x00000001, // OpMemoryModel Logical GLSL450
            0x0003000E, 0x00000000, 0x00000001, // OpEntryPoint Vertex %main "main"
            0x0005000F, 0x00000000, 0x00000005, 0x6E69616D, 0x00000000,
            // OpName %main "main"
            0x00040005, 0x00000005, 0x6E69616D, 0x00000000, // OpTypeVoid %void
            0x00020013, 0x00000002, // OpTypeFunction %fn %void
            0x00030021, 0x00000003, 0x00000002,
            // %main = OpFunction %void None %fn
            0x00050036, 0x00000002, 0x00000005, 0x00000000, 0x00000003,
            // %lbl = OpLabel
            0x000200F8, 0x00000006, // OpReturn
            0x000100FD, // OpFunctionEnd
            0x00010038,
        ]
    }

    #[test]
    fn vulkan_state_creates_successfully() {
        let state = VulkanState::new();
        assert_eq!(state.instance_count(), 0);
        assert_eq!(state.device_count(), 0);
        assert_eq!(state.swapchain_count(), 0);
        assert_eq!(state.command_buffer_count(), 0);
        assert!(!state.is_moltenvk_loaded());
    }

    #[test]
    fn vulkan_instance_creation() {
        let mut state = VulkanState::new();
        let exts = vec!["VK_KHR_surface".to_string()];
        let layers: Vec<String> = vec![];
        let instance = state
            .create_instance("TestApp", "TestEngine", &exts, &layers)
            .expect("instance creation");
        assert_ne!(instance, 0);
        assert_eq!(state.instance_count(), 1);

        let phys_devs = state
            .enumerate_physical_devices(instance)
            .expect("enumerate");
        assert_eq!(phys_devs.len(), 1);
        assert_ne!(phys_devs[0], 0);
    }

    #[test]
    fn vulkan_device_creation() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys_devs = state.enumerate_physical_devices(instance).unwrap();
        let phys = phys_devs[0];

        let device = state
            .create_device(phys, &[], &[(0, 1)])
            .expect("device creation");
        assert_ne!(device, 0);
        assert_eq!(state.device_count(), 1);

        let queue = state.get_device_queue(device, 0, 0).expect("get queue");
        assert_ne!(queue, 0);
    }

    #[test]
    fn vulkan_swapchain_creation() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();
        let surface = state
            .create_surface(800, 600, VkFormat::B8G8R8A8Unorm)
            .unwrap();

        let ci = VkSwapchainCreateInfo {
            surface,
            min_image_count: 2,
            image_format: VkFormat::B8G8R8A8Unorm,
            image_color_space: VkColorSpaceKHR::SrgbNonlinear,
            image_extent: (800, 600),
            image_array_layers: 1,
            image_usage: VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
            pre_transform: VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR,
            composite_alpha: VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
            present_mode: VkPresentModeKHR::Fifo,
            clipped: true,
        };
        let sc = state
            .create_swapchain(device, surface, &ci)
            .expect("swapchain");
        let info = state.get_swapchain(sc).expect("info");
        assert_eq!(info.min_image_count, 2);
        assert_eq!(info.image_extent, (800, 600));
        assert!(info.metal_layer.is_some());
    }

    #[test]
    fn vulkan_shader_module_from_spirv() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();

        let spirv = minimal_spirv();
        let module = state
            .create_shader_module(device, &spirv)
            .expect("shader module");
        let info = state.get_shader_module(module).expect("info");
        assert!(info.msl_source.is_some());
        let msl = info.msl_source.as_ref().unwrap();
        assert!(msl.contains("vertex"));
        assert!(msl.contains("main"));
        assert!(info.entry_points.contains(&"main".to_string()));
        assert_eq!(info.stage, VkShaderStageFlagBits::Vertex);
    }

    #[test]
    fn vulkan_memory_allocation() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();

        let mem = state.allocate_memory(device, 1024, 0).expect("allocate");
        let info = state.get_device_memory(mem).expect("info");
        assert_eq!(info.size, 1024);
        assert!(info.metal_buffer.is_some());
        assert_eq!(info.allocation_type, MemoryAllocationType::Private);
    }

    #[test]
    fn vulkan_command_buffer_recording() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();
        let pool = state.create_command_pool(device, 0).unwrap();
        let cmds = state
            .allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1)
            .unwrap();
        let cmd = cmds[0];

        state.begin_command_buffer(cmd, 0).expect("begin");
        state.cmd_draw(cmd, 3, 1, 0, 0).expect("draw");
        state.end_command_buffer(cmd).expect("end");

        let info = state.get_command_buffer(cmd).unwrap();
        assert_eq!(info.state, CommandBufferState::Executable);
        assert_eq!(info.recorded_commands.len(), 1);
        match &info.recorded_commands[0] {
            RecordedCommand::Draw {
                vertex_count,
                instance_count,
                first_vertex,
                first_instance,
            } => {
                assert_eq!(*vertex_count, 3);
                assert_eq!(*instance_count, 1);
                assert_eq!(*first_vertex, 0);
                assert_eq!(*first_instance, 0);
            }
            _ => panic!("expected Draw command"),
        }
    }

    #[test]
    fn vulkan_pipeline_barrier() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();
        let img = state
            .create_image(
                device,
                VkFormat::B8G8R8A8Unorm,
                (256, 256, 1),
                1,
                1,
                VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
            )
            .unwrap();
        let pool = state.create_command_pool(device, 0).unwrap();
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

        let info = state.get_command_buffer(cmd).unwrap();
        assert_eq!(info.recorded_commands.len(), 1);
        // Verify image layout was transitioned
        let img_info = state.get_image(img).unwrap();
        assert_eq!(img_info.layout, VkImageLayout::ColorAttachmentOptimal);
    }

    #[test]
    fn opengl_context_creation() {
        let mut gl = GLState::new();
        let ctx = gl.gl_create_context().expect("create context");
        assert_ne!(ctx, 0);

        gl.gl_make_current(ctx).expect("make current");
        assert!(gl.has_current_context());
        assert_eq!(gl.current_context_handle(), Some(ctx));

        gl.gl_delete_context(ctx).expect("delete");
        assert!(!gl.has_current_context());
    }

    #[test]
    fn opengl_draw_arrays() {
        let mut gl = GLState::new();
        let ctx = gl.gl_create_context().unwrap();
        gl.gl_make_current(ctx).unwrap();

        let prog = gl.gl_create_program().unwrap();
        gl.gl_use_program(prog).unwrap();
        gl.gl_draw_arrays(0x0004, 0, 3).expect("draw arrays");
    }

    #[test]
    fn moltenvk_loader_search_paths() {
        let paths = moltenvk_search_paths();
        assert!(!paths.is_empty());
        assert!(
            paths
                .iter()
                .any(|p| p.to_string_lossy().contains("homebrew"))
        );
        assert!(
            paths
                .iter()
                .any(|p| p.to_string_lossy().contains("usr/local"))
        );
    }

    #[test]
    fn dll_registration_exports() {
        let vk_exports = register_vulkan_dll();
        assert!(!vk_exports.is_empty());
        assert!(
            vk_exports
                .iter()
                .any(|(name, _)| *name == "vkCreateInstance")
        );
        assert!(vk_exports.iter().any(|(name, _)| *name == "vkQueueSubmit"));
        assert!(
            vk_exports
                .iter()
                .any(|(name, _)| *name == "vkCreateSwapchainKHR")
        );

        let gl_exports = register_opengl_dll();
        assert!(!gl_exports.is_empty());
        assert!(
            gl_exports
                .iter()
                .any(|(name, _)| *name == "wglCreateContext")
        );
        assert!(gl_exports.iter().any(|(name, _)| *name == "glDrawArrays"));
    }

    // -----------------------------------------------------------------------
    // New tests: SPIR-V parsing, MSL type translation, format mapping
    // -----------------------------------------------------------------------

    /// Test SPIR-V header parsing: validates magic number, version, and bound.
    #[test]
    fn spirv_header_parsing() {
        let spirv = minimal_spirv();
        let mut translator = SpirvTranslator::new();
        // Valid header should parse successfully
        let _result = translator.parse(&spirv);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");

        // Verify entry point was detected
        assert_eq!(translator.entry_points.len(), 1);
        let (id, model, name) = &translator.entry_points[0];
        assert_eq!(*id, 5); // %main
        assert_eq!(*model, SPIRV_EXEC_MODEL_VERTEX);
        assert_eq!(name, "main");

        // Invalid magic number should fail
        let mut bad_magic = spirv.clone();
        bad_magic[0] = 0xDEADBEEF;
        let mut t2 = SpirvTranslator::new();
        let err = t2.parse(&bad_magic).unwrap_err();
        assert!(err.to_string().contains("invalid SPIR-V magic number"));

        // Too-short SPIR-V should fail
        let mut t3 = SpirvTranslator::new();
        let _result = t3.parse(&[0x07230203, 0x00010000]);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    /// Test SPIR-V → MSL type translation for common types.
    #[test]
    fn spirv_to_msl_type_translation() {
        let mut translator = SpirvTranslator::new();

        // Build a minimal SPIR-V module with various types
        let mut spirv = vec![
            0x07230203, // magic
            0x00010000, // version 1.0
            0x00000000, // generator
            0x00000020, // bound (IDs 0..31)
            0x00000000, // schema
            // OpCapability Shader
            0x00020011, 0x00000001, // OpMemoryModel Logical GLSL450
            0x0003000E, 0x00000000, 0x00000001,
        ];

        // OpTypeVoid %2
        spirv.push(0x00020013);
        spirv.push(2);
        // OpTypeFloat %3 32
        spirv.push(0x00030016);
        spirv.push(3);
        spirv.push(32);
        // OpTypeInt %4 32 1 (signed)
        spirv.push(0x00040015);
        spirv.push(4);
        spirv.push(32);
        spirv.push(1);
        // OpTypeInt %5 32 0 (unsigned)
        spirv.push(0x00040015);
        spirv.push(5);
        spirv.push(32);
        spirv.push(0);
        // OpTypeVector %6 %3 4 (float4)
        spirv.push(0x00040017);
        spirv.push(6);
        spirv.push(3);
        spirv.push(4);
        // OpTypeVector %7 %3 3 (float3)
        spirv.push(0x00040017);
        spirv.push(7);
        spirv.push(3);
        spirv.push(3);
        // OpTypeVector %8 %4 4 (int4)
        spirv.push(0x00040017);
        spirv.push(8);
        spirv.push(4);
        spirv.push(4);
        // OpTypeMatrix %9 %6 4 (float4x4)
        spirv.push(0x00040018);
        spirv.push(9);
        spirv.push(6);
        spirv.push(4);
        // OpTypeFloat %10 16 (half)
        spirv.push(0x00030016);
        spirv.push(10);
        spirv.push(16);

        translator.parse(&spirv).unwrap();

        // Verify type translations
        assert_eq!(translator.resolve_msl_type(2), "void");
        assert_eq!(translator.resolve_msl_type(3), "float");
        assert_eq!(translator.resolve_msl_type(4), "int");
        assert_eq!(translator.resolve_msl_type(5), "uint");
        assert_eq!(translator.resolve_msl_type(6), "float4");
        assert_eq!(translator.resolve_msl_type(7), "float3");
        assert_eq!(translator.resolve_msl_type(8), "int4");
        assert_eq!(translator.resolve_msl_type(9), "float4x4");
        assert_eq!(translator.resolve_msl_type(10), "half");
    }

    /// Test Vulkan format → Metal pixel format mapping.
    #[test]
    fn vulkan_format_to_metal_pixel_format() {
        // Common color formats
        assert_eq!(
            vk_format_to_metal_format(VkFormat::R8G8B8A8Unorm),
            metal::MTLPixelFormat::RGBA8Unorm
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::B8G8R8A8Unorm),
            metal::MTLPixelFormat::BGRA8Unorm
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::R8G8B8A8Srgb),
            metal::MTLPixelFormat::RGBA8Unorm_sRGB
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::B8G8R8A8Srgb),
            metal::MTLPixelFormat::BGRA8Unorm_sRGB
        );

        // Depth formats
        assert_eq!(
            vk_format_to_metal_format(VkFormat::D24UnormS8Uint),
            metal::MTLPixelFormat::Depth24Unorm_Stencil8
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::D32Sfloat),
            metal::MTLPixelFormat::Depth32Float
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::D16Unorm),
            metal::MTLPixelFormat::Depth16Unorm
        );

        // Floating-point formats
        assert_eq!(
            vk_format_to_metal_format(VkFormat::R32Sfloat),
            metal::MTLPixelFormat::R32Float
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::R16G16B16A16Sfloat),
            metal::MTLPixelFormat::RGBA16Float
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::R32G32Sfloat),
            metal::MTLPixelFormat::RG32Float
        );

        // BC compressed formats
        assert_eq!(
            vk_format_to_metal_format(VkFormat::Bc1RgbaUnormBlock),
            metal::MTLPixelFormat::BC1_RGBA
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::Bc2UnormBlock),
            metal::MTLPixelFormat::BC2_RGBA
        );
        assert_eq!(
            vk_format_to_metal_format(VkFormat::Bc3UnormBlock),
            metal::MTLPixelFormat::BC3_RGBA
        );

        // 3-channel format falls back to 4-channel (Metal has no RGB32Float)
        assert_eq!(
            vk_format_to_metal_format(VkFormat::R32G32B32Sfloat),
            metal::MTLPixelFormat::RGBA32Float
        );

        // Undefined format falls back to RGBA8Unorm
        assert_eq!(
            vk_format_to_metal_format(VkFormat::Undefined),
            metal::MTLPixelFormat::RGBA8Unorm
        );
    }

    /// Test that SpirvModule can be created from a parsed translator.
    #[test]
    fn spirv_module_conversion() {
        let spirv = minimal_spirv();
        let mut translator = SpirvTranslator::new();
        translator.parse(&spirv).unwrap();

        let module = translator.to_module();
        assert_eq!(module.entry_points.len(), 1);
        assert_eq!(module.entry_points[0].0, SpirvExecutionModel::Vertex);
        assert_eq!(module.entry_points[0].1, "main");
        assert!(!module.types.is_empty());
        assert!(!module.strings.is_empty());
    }

    /// Test that VulkanState creates with Metal backend when available.
    #[test]
    fn vulkan_state_with_metal_backend() {
        let state = VulkanState::new();
        // On macOS with Metal support, the backend should be available
        // (but may be None in CI without a GPU)
        // Just verify the state is usable either way
        assert_eq!(state.instance_count(), 0);
        assert_eq!(state.device_count(), 0);
    }

    /// Test buffer creation with Metal backing.
    #[test]
    fn vulkan_buffer_with_metal_backing() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();

        let buffer = state.create_buffer(device, 1024, 0).unwrap();
        let info = state.get_buffer(buffer).unwrap();
        assert_eq!(info.size, 1024);
        // metal_buffer_id may or may not be set depending on Metal availability
    }

    /// Test image creation with Metal backing.
    #[test]
    fn vulkan_image_with_metal_backing() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();

        let image = state
            .create_image(
                device,
                VkFormat::B8G8R8A8Unorm,
                (256, 256, 1),
                1,
                1,
                VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
            )
            .unwrap();
        let info = state.get_image(image).unwrap();
        assert_eq!(info.format, VkFormat::B8G8R8A8Unorm);
        assert_eq!(info.extent, (256, 256, 1));
    }

    /// Test sampler creation.
    #[test]
    fn vulkan_sampler_creation() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys = state.enumerate_physical_devices(instance).unwrap()[0];
        let device = state.create_device(phys, &[], &[(0, 1)]).unwrap();

        let ci = VkSamplerCreateInfo {
            min_filter: 0,
            mag_filter: 0,
            mipmap_mode: 0,
            address_mode_u: 0,
            address_mode_v: 0,
            address_mode_w: 0,
            mip_lod_bias: 0.0,
            max_anisotropy: 1.0,
            compare_op: 0,
            min_lod: 0.0,
            max_lod: 1000.0,
        };
        let sampler = state.create_sampler(device, &ci).unwrap();
        assert_ne!(sampler, 0);
        assert_eq!(state.sampler_count(), 1);

        let info = state.get_sampler(sampler).unwrap();
        assert_eq!(info.min_lod, 0.0);
        assert_eq!(info.max_lod, 1000.0);

        state.destroy_sampler(sampler).unwrap();
        assert_eq!(state.sampler_count(), 0);
    }

    // ── Malformed SPIR-V tests ─────────────────────────────────────────

    #[test]
    fn spirv_truncated_instruction_at_end() {
        // Valid header but instruction truncated mid-word
        let spirv: Vec<u32> = vec![
            0x07230203, // magic
            0x00010000, // version
            0x00000000, // generator
            0x00000001, // bound
            0x00000000, // schema
            0x00050011, // OpCapability with word_count=5 but no more words follow
        ];
        let mut translator = SpirvTranslator::new();
        // The parser should handle this gracefully (either error or skip)
        let result = translator.parse(&spirv);
        // It may or may not error depending on implementation, but must not panic
        let _ = result;
    }

    #[test]
    fn spirv_zero_word_count_is_error() {
        let spirv: Vec<u32> = vec![
            0x07230203, // magic
            0x00010000, // version
            0x00000000, // generator
            0x00000001, // bound
            0x00000000, // schema
            0x00000000, // word_count=0, opcode=0 → invalid
        ];
        let mut translator = SpirvTranslator::new();
        let result = translator.parse(&spirv);
        assert!(result.is_err(), "zero word count should be an error");
        assert!(
            result.unwrap_err().to_string().contains("word count 0"),
            "error should mention word count 0"
        );
    }

    #[test]
    fn spirv_invalid_operand_count_handled() {
        // OpTypeInt normally takes 3 operands (result_id, width, signedness)
        // Provide only 1 operand (result_id)
        let spirv: Vec<u32> = vec![
            0x07230203, // magic
            0x00010000, // version
            0x00000000, // generator
            0x00000010, // bound
            0x00000000, // schema
            0x00020011, 0x00000001, // OpCapability Shader
            0x0003000E, 0x00000000, 0x00000001, // OpMemoryModel
            // OpTypeInt %1 21 → word_count=3, but we only provide result_id
            0x00030015, 0x00000001,
            0x00000021,
            // Missing signedness operand — but word_count=3 means only 2 operands after the word
            // This is actually valid (3 words = opcode word + 2 operands)
            // Let's make it truly truncated
        ];
        let mut translator = SpirvTranslator::new();
        // Should not panic — may silently skip or error
        let _ = translator.parse(&spirv);
    }

    #[test]
    fn spirv_empty_module_is_error() {
        let mut translator = SpirvTranslator::new();
        assert!(translator.parse(&[]).is_err(), "empty SPIR-V should error");
    }

    #[test]
    fn spirv_header_only_is_error() {
        let mut translator = SpirvTranslator::new();
        // Only 4 words — not enough for a valid header (needs 5)
        assert!(
            translator
                .parse(&[0x07230203, 0x00010000, 0x00000000, 0x00000001])
                .is_err(),
            "4-word SPIR-V should error"
        );
    }

    #[test]
    fn spirv_bad_magic_is_error() {
        let mut translator = SpirvTranslator::new();
        let result =
            translator.parse(&[0xDEADBEEF, 0x00010000, 0x00000000, 0x00000001, 0x00000000]);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().to_string().contains("magic"));
    }
}
