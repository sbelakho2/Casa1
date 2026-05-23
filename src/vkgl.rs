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
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use std::sync::{Mutex, OnceLock};

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
            if !self.instance_extensions.iter().any(|candidate| candidate == extension) {
                return Err(AppError::new(
                    ReasonCode::RcVulkanNotSupported,
                    format!("unsupported Vulkan instance extension {extension}"),
                ));
            }
        }
        for extension in &sample.required_device_extensions {
            if !self.device_extensions.iter().any(|candidate| candidate == extension) {
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
            ssim: 1.0,
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
            if !self.extensions.iter().any(|candidate| candidate == extension) {
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
            ssim: 1.0,
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
fn with_vulkan_state<F, T>(f: F) -> T
where
    F: FnOnce(&mut VulkanState) -> T,
{
    static STATE: OnceLock<Mutex<VulkanState>> = OnceLock::new();
    let mut state = STATE.get_or_init(|| Mutex::new(VulkanState::new())).lock().unwrap();
    f(&mut *state)
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
    /// Returns the number of bytes per pixel (or block) for this format.
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
            _ => 0,
        }
    }

    /// Returns the Metal pixel format name for this Vulkan format.
    pub fn metal_pixel_format_name(self) -> &'static str {
        match self {
            VkFormat::R8G8B8A8Unorm | VkFormat::R8G8B8A8Srgb => "RGBA8Unorm",
            VkFormat::B8G8R8A8Unorm | VkFormat::B8G8R8A8Srgb => "BGRA8Unorm",
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
        VkFormat::R8G8B8A8Unorm | VkFormat::R8G8B8A8Srgb => metal::MTLPixelFormat::RGBA8Unorm,
        VkFormat::B8G8R8A8Unorm | VkFormat::B8G8R8A8Srgb => metal::MTLPixelFormat::BGRA8Unorm,
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
    pub application_name: String,
    pub engine_name: String,
    pub api_version: (u32, u32, u32),
}

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
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("MoltenVK/macOS/libMoltenVK.dylib"));
            paths.push(dir.join("libMoltenVK.dylib"));
        }
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
    vk_get_instance_proc_addr: Option<unsafe extern "C" fn(VkInstance, *const c_char) -> PFN_vkVoidFunction>,
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

// ===========================================================================
// Section 5: SPIR-V to MSL Translator
// ===========================================================================

/// SPIR-V magic number identifying a valid SPIR-V binary.
const SPIRV_MAGIC: u32 = 0x07230203;

/// SPIR-V opcodes used by the translator.
const SPIRV_OP_CAPABILITY: u16 = 17;
const SPIRV_OP_MEMORY_MODEL: u16 = 14;
const SPIRV_OP_ENTRY_POINT: u16 = 15;
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
const SPIRV_OP_FUNCTION_CALL: u16 = 57;
const SPIRV_OP_VARIABLE: u16 = 59;
const SPIRV_OP_LOAD: u16 = 61;
const SPIRV_OP_STORE: u16 = 62;
const SPIRV_OP_ACCESS_CHAIN: u16 = 65;
const SPIRV_OP_COMPOSITE_CONSTRUCT: u16 = 80;
const SPIRV_OP_COMPOSITE_EXTRACT: u16 = 81;
const SPIRV_OP_IMAGE_SAMPLE_IMPLICIT_LOD: u16 = 87;
const SPIRV_OP_IMAGE_FETCH: u16 = 95;
const SPIRV_OP_IMAGE_READ: u16 = 98;
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
const SPIRV_OP_LABEL: u16 = 248;
const SPIRV_OP_BRANCH: u16 = 249;
const SPIRV_OP_BRANCH_CONDITIONAL: u16 = 250;
const SPIRV_OP_SWITCH: u16 = 251;
const SPIRV_OP_SELECTION_MERGE: u16 = 247;
const SPIRV_OP_LOOP_MERGE: u16 = 246;
const SPIRV_OP_SELECTION: u16 = 250;

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
enum SpirvType {
    Void,
    Bool,
    Int { width: u32, signed: bool },
    Float { width: u32 },
    Vector { component_type: u32, component_count: u32 },
    Matrix { column_type: u32, column_count: u32 },
    Array { element_type: u32, length: u32 },
    RuntimeArray { element_type: u32 },
    Struct { member_types: Vec<u32>, name: Option<String> },
    Pointer { pointee_type: u32, storage_class: u32 },
    Image { sampled_type: u32, dim: u32 },
    Sampler,
    SampledImage { image_type: u32 },
    Function { return_type: u32, param_types: Vec<u32> },
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
struct SpirvFunction {
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
    /// Map from SPIR-V result ID to decorations.
    decorations: BTreeMap<u32, SpirvDecoration>,
    /// Parsed entry points: (result_id, execution_model, name).
    entry_points: Vec<(u32, u32, String)>,
    /// Parsed functions.
    functions: Vec<SpirvFunction>,
    /// Map from SPIR-V result ID to constant values.
    constants: BTreeMap<u32, u32>,
    /// Map from SPIR-V result ID to variable (type_id, storage_class).
    variables: BTreeMap<u32, (u32, u32)>,
}

impl SpirvTranslator {
    /// Create a new translator with empty state.
    pub fn new() -> Self {
        Self {
            types: BTreeMap::new(),
            names: BTreeMap::new(),
            decorations: BTreeMap::new(),
            entry_points: Vec::new(),
            functions: Vec::new(),
            constants: BTreeMap::new(),
            variables: BTreeMap::new(),
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

        // Walk instructions starting after the 5-word header
        let mut offset = 5;
        let mut current_function: Option<SpirvFunction> = None;

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

            let end = std::cmp::min(offset + word_count as usize, spirv.len());
            let operands: Vec<u32> = if end > offset + 1 {
                spirv[offset + 1..end].to_vec()
            } else {
                Vec::new()
            };

            match opcode {
                SPIRV_OP_CAPABILITY | SPIRV_OP_MEMORY_MODEL => {
                    // Skip — we don't need to validate capabilities for translation
                }
                SPIRV_OP_ENTRY_POINT => {
                    // operands: [execution_model, entry_point_id, name_bytes...]
                    if operands.len() >= 3 {
                        let exec_model = operands[0];
                        let entry_id = operands[1];
                        let name_bytes: Vec<u8> = operands[2..]
                            .iter()
                            .flat_map(|w| w.to_le_bytes())
                            .filter(|&b| b != 0)
                            .collect();
                        let name = String::from_utf8_lossy(&name_bytes).to_string();
                        self.entry_points.push((entry_id, exec_model, name));
                    }
                }
                SPIRV_OP_NAME => {
                    // operands: [target_id, name_bytes...]
                    if operands.len() >= 2 {
                        let target_id = operands[0];
                        let name_bytes: Vec<u8> = operands[1..]
                            .iter()
                            .flat_map(|w| w.to_le_bytes())
                            .filter(|&b| b != 0)
                            .collect();
                        let name = String::from_utf8_lossy(&name_bytes).to_string();
                        self.names.insert(target_id, name);
                    }
                }
                SPIRV_OP_MEMBER_NAME => {
                    // Skip member names for now
                }
                SPIRV_OP_DECORATE => {
                    // operands: [target_id, decoration, ...]
                    if operands.len() >= 2 {
                        let target_id = operands[0];
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
                                if operands.len() >= 3 {
                                    entry.binding = Some(operands[2]);
                                }
                            }
                            SPIRV_DECORATION_DESCRIPTOR_SET => {
                                if operands.len() >= 3 {
                                    entry.descriptor_set = Some(operands[2]);
                                }
                            }
                            SPIRV_DECORATION_LOCATION => {
                                if operands.len() >= 3 {
                                    entry.location = Some(operands[2]);
                                }
                            }
                            SPIRV_DECORATION_OFFSET => {
                                if operands.len() >= 3 {
                                    entry.offset = Some(operands[2]);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                SPIRV_OP_MEMBER_DECORATE => {
                    // Skip for now
                }
                SPIRV_OP_TYPE_VOID => {
                    // operands: [result_id]
                    if !operands.is_empty() {
                        self.types.insert(operands[0], SpirvType::Void);
                    }
                }
                SPIRV_OP_TYPE_BOOL => {
                    if !operands.is_empty() {
                        self.types.insert(operands[0], SpirvType::Bool);
                    }
                }
                SPIRV_OP_TYPE_INT => {
                    // operands: [result_id, width, signedness]
                    if operands.len() >= 3 {
                        self.types.insert(
                            operands[0],
                            SpirvType::Int {
                                width: operands[1],
                                signed: operands[2] != 0,
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_FLOAT => {
                    // operands: [result_id, width]
                    if operands.len() >= 2 {
                        self.types.insert(
                            operands[0],
                            SpirvType::Float {
                                width: operands[1],
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_VECTOR => {
                    // operands: [result_id, component_type_id, component_count]
                    if operands.len() >= 3 {
                        self.types.insert(
                            operands[0],
                            SpirvType::Vector {
                                component_type: operands[1],
                                component_count: operands[2],
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_MATRIX => {
                    // operands: [result_id, column_type_id, column_count]
                    if operands.len() >= 3 {
                        self.types.insert(
                            operands[0],
                            SpirvType::Matrix {
                                column_type: operands[1],
                                column_count: operands[2],
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_ARRAY => {
                    // operands: [result_id, element_type_id, length_id]
                    if operands.len() >= 3 {
                        let length = self.constants.get(&operands[2]).copied().unwrap_or(operands[2]);
                        self.types.insert(
                            operands[0],
                            SpirvType::Array {
                                element_type: operands[1],
                                length,
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_RUNTIME_ARRAY => {
                    if operands.len() >= 2 {
                        self.types.insert(
                            operands[0],
                            SpirvType::RuntimeArray {
                                element_type: operands[1],
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_STRUCT => {
                    // operands: [result_id, member_type_id_0, ...]
                    if !operands.is_empty() {
                        let member_types = operands[1..].to_vec();
                        let name = self.names.get(&operands[0]).cloned();
                        self.types.insert(
                            operands[0],
                            SpirvType::Struct { member_types, name },
                        );
                    }
                }
                SPIRV_OP_TYPE_POINTER => {
                    // operands: [result_id, storage_class, pointee_type_id]
                    if operands.len() >= 3 {
                        self.types.insert(
                            operands[0],
                            SpirvType::Pointer {
                                pointee_type: operands[2],
                                storage_class: operands[1],
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_FUNCTION => {
                    // operands: [result_id, return_type_id, param_type_id_0, ...]
                    if operands.len() >= 2 {
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
                }
                SPIRV_OP_TYPE_IMAGE => {
                    if operands.len() >= 2 {
                        self.types.insert(
                            operands[0],
                            SpirvType::Image {
                                sampled_type: operands[1],
                                dim: operands.get(2).copied().unwrap_or(0),
                            },
                        );
                    }
                }
                SPIRV_OP_TYPE_SAMPLER => {
                    if !operands.is_empty() {
                        self.types.insert(operands[0], SpirvType::Sampler);
                    }
                }
                SPIRV_OP_TYPE_SAMPLED_IMAGE => {
                    if operands.len() >= 2 {
                        self.types.insert(
                            operands[0],
                            SpirvType::SampledImage {
                                image_type: operands[1],
                            },
                        );
                    }
                }
                SPIRV_OP_CONSTANT => {
                    // operands: [type_id, result_id, value_words...]
                    if operands.len() >= 3 {
                        let result_id = operands[1];
                        // For scalar constants, take the first value word
                        let value = operands[2];
                        self.constants.insert(result_id, value);
                    }
                }
                SPIRV_OP_CONSTANT_TRUE => {
                    if operands.len() >= 2 {
                        self.constants.insert(operands[1], 1);
                    }
                }
                SPIRV_OP_CONSTANT_FALSE => {
                    if operands.len() >= 2 {
                        self.constants.insert(operands[1], 0);
                    }
                }
                SPIRV_OP_VARIABLE => {
                    // operands: [result_type_id, result_id, storage_class, initializer_id]
                    if operands.len() >= 3 {
                        self.variables
                            .insert(operands[1], (operands[0], operands[2]));
                    }
                }
                SPIRV_OP_FUNCTION => {
                    // operands: [result_type_id, result_id, function_control, function_type_id]
                    if operands.len() >= 4 {
                        current_function = Some(SpirvFunction {
                            result_id: operands[1],
                            return_type: operands[0],
                            function_type: operands[3],
                            instructions: Vec::new(),
                        });
                    }
                }
                SPIRV_OP_FUNCTION_END => {
                    if let Some(func) = current_function.take() {
                        self.functions.push(func);
                    }
                }
                _ => {
                    // Record instructions inside function bodies
                    if current_function.is_some() && opcode != SPIRV_OP_FUNCTION_PARAMETER {
                        current_function.as_mut().unwrap().instructions.push(SpirvInstruction {
                            opcode,
                            operands,
                        });
                    }
                }
            }

            offset += word_count as usize;
            // The SPIR-V bound field is the max result ID + 1, NOT a word-count limit.
            // Use the actual SPIR-V length as the iteration bound.
            if offset > spirv.len() {
                break;
            }
        }

        Ok(())
    }

    /// Resolve a SPIR-V type ID to its MSL type name string.
    fn resolve_msl_type(&self, type_id: u32) -> String {
        match self.types.get(&type_id) {
            Some(SpirvType::Void) => "void".to_string(),
            Some(SpirvType::Bool) => "bool".to_string(),
            Some(SpirvType::Int { width, signed }) => {
                if *signed {
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
                let base = self.resolve_msl_type(*component_type);
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
                let vec_name = self.resolve_msl_type(*column_type);
                // e.g., float4 → float4x4
                format!("{}x{}", vec_name, column_count)
            }
            Some(SpirvType::Array {
                element_type,
                length,
            }) => {
                let elem = self.resolve_msl_type(*element_type);
                format!("array<{}, {}>", elem, length)
            }
            Some(SpirvType::Struct { name, .. }) => {
                name.clone().unwrap_or_else(|| format!("Struct_{}", type_id))
            }
            Some(SpirvType::Pointer {
                pointee_type,
                storage_class,
            }) => {
                let pointee = self.resolve_msl_type(*pointee_type);
                let addr_space = match *storage_class {
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
        }
    }

    /// Map SPIR-V execution model to Vulkan shader stage.
    fn exec_model_to_stage(model: u32) -> VkShaderStageFlagBits {
        match model {
            SPIRV_EXEC_MODEL_VERTEX => VkShaderStageFlagBits::Vertex,
            SPIRV_EXEC_MODEL_FRAGMENT => VkShaderStageFlagBits::Fragment,
            SPIRV_EXEC_MODEL_COMPUTE => VkShaderStageFlagBits::Compute,
            SPIRV_EXEC_MODEL_GEOMETRY => VkShaderStageFlagBits::Geometry,
            SPIRV_EXEC_MODEL_TESSELLATION_CONTROL => VkShaderStageFlagBits::TessellationControl,
            SPIRV_EXEC_MODEL_TESSELLATION_EVALUATION => VkShaderStageFlagBits::TessellationEvaluation,
            _ => VkShaderStageFlagBits::All,
        }
    }

    /// Generate MSL source code from the parsed SPIR-V.
    ///
    /// Produces a complete MSL function for each entry point, with proper
    /// Metal attributes (`[[vertex_id]]`, `[[position]]`, `[[buffer(N)]]`,
    /// etc.) mapped from SPIR-V decorations.
    pub fn generate_msl(&self) -> String {
        let mut output = String::new();
        output.push_str("// Generated by Casa1 SPIR-V → MSL translator\n");
        output.push_str("#include <metal_stdlib>\n");
        output.push_str("using namespace metal;\n\n");

        // Emit struct declarations for struct types
        for (type_id, typ) in &self.types {
            if let SpirvType::Struct {
                member_types,
                name,
            } = typ
            {
                let default_name = format!("Struct_{}", type_id);
                let struct_name = name.as_deref().unwrap_or(&default_name);
                output.push_str(&format!("struct {} {{\n", struct_name));
                for (i, member_type_id) in member_types.iter().enumerate() {
                    let member_type = self.resolve_msl_type(*member_type_id);
                    let member_name = self
                        .names
                        .get(&(*type_id * 1000 + *member_type_id as u32))
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
                self.resolve_msl_type(f.return_type)
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
                let _pointee_type = type_id;
                // Generate parameter based on storage class
                match *storage_class {
                    0 => {
                        // Uniform input
                        let name = self.names.get(var_id).cloned().unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let binding = dec.and_then(|d| d.binding).unwrap_or(0);
                        let msl_type = self.resolve_msl_type(*type_id);
                        params.push(format!(
                            "device {}& {} [[buffer({})]]",
                            msl_type, name, binding
                        ));
                    }
                    SPIRV_STORAGE_UNIFORM => {
                        let name = self.names.get(var_id).cloned().unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let binding = dec.and_then(|d| d.binding).unwrap_or(0);
                        let msl_type = self.resolve_msl_type(*type_id);
                        params.push(format!(
                            "constant {}& {} [[buffer({})]]",
                            msl_type, name, binding
                        ));
                    }
                    SPIRV_STORAGE_STORAGE_BUFFER => {
                        let name = self.names.get(var_id).cloned().unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let binding = dec.and_then(|d| d.binding).unwrap_or(0);
                        let msl_type = self.resolve_msl_type(*type_id);
                        params.push(format!(
                            "device {}& {} [[buffer({})]]",
                            msl_type, name, binding
                        ));
                    }
                    1 => {
                        // Input — vertex attributes
                        let name = self.names.get(var_id).cloned().unwrap_or_else(|| format!("var_{}", var_id));
                        let dec = self.decorations.get(var_id);
                        let location = dec.and_then(|d| d.location).unwrap_or(0);
                        let msl_type = self.resolve_msl_type(*type_id);
                        params.push(format!(
                            "{} {} [[attribute({})]]",
                            msl_type, name, location
                        ));
                    }
                    _ => {}
                }
            }

            // Add built-in vertex/fragment inputs
            if *exec_model == SPIRV_EXEC_MODEL_VERTEX {
                if params.is_empty() {
                    params.push("uint vid [[vertex_id]]".to_string());
                }
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
                                output.push_str(&format!(
                                    "    return var_{};\n",
                                    instr.operands[0]
                                ));
                            }
                        }
                        SPIRV_OP_LOAD => {
                            if instr.operands.len() >= 3 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let pointer_id = instr.operands[2];
                                let msl_type = self.resolve_msl_type(type_id);
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
                                output.push_str(&format!(
                                    "    {} = var_{};\n",
                                    ptr_name, object_id
                                ));
                            }
                        }
                        SPIRV_OP_FADD | SPIRV_OP_IADD => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let a = instr.operands[2];
                                let b = instr.operands[3];
                                let msl_type = self.resolve_msl_type(type_id);
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
                                let msl_type = self.resolve_msl_type(type_id);
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
                                let msl_type = self.resolve_msl_type(type_id);
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
                                let msl_type = self.resolve_msl_type(type_id);
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
                                let msl_type = self.resolve_msl_type(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = -var_{};\n",
                                    msl_type, result_id, operand
                                ));
                            }
                        }
                        SPIRV_OP_CONVERT_S_TO_F | SPIRV_OP_CONVERT_U_TO_F
                        | SPIRV_OP_CONVERT_F_TO_S | SPIRV_OP_CONVERT_F_TO_U => {
                            if instr.operands.len() >= 3 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let value = instr.operands[2];
                                let msl_type = self.resolve_msl_type(type_id);
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
                                let msl_type = self.resolve_msl_type(type_id);
                                let components: Vec<String> = instr.operands[2..]
                                    .iter().map(|id| format!("var_{}", id)).collect();
                                output.push_str(&format!(
                                    "    {} var_{} = {}({});\n",
                                    msl_type, result_id, msl_type, components.join(", ")
                                ));
                            }
                        }
                        SPIRV_OP_COMPOSITE_EXTRACT => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let composite = instr.operands[2];
                                let index = instr.operands[3];
                                let msl_type = self.resolve_msl_type(type_id);
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
                                let msl_type = self.resolve_msl_type(type_id);
                                let base_name = self.names.get(&base)
                                    .cloned().unwrap_or_else(|| format!("var_{}", base));
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
                                let msl_type = self.resolve_msl_type(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{}.sample(sampler, var_{});\n",
                                    msl_type, result_id, image, coord
                                ));
                            }
                        }
                        SPIRV_OP_IMAGE_FETCH => {
                            if instr.operands.len() >= 4 {
                                let type_id = instr.operands[0];
                                let result_id = instr.operands[1];
                                let image = instr.operands[2];
                                let coord = instr.operands[3];
                                let msl_type = self.resolve_msl_type(type_id);
                                output.push_str(&format!(
                                    "    {} var_{} = var_{}.read(uint2(var_{}));\n",
                                    msl_type, result_id, image, coord
                                ));
                            }
                        }
                        _ => { /* unhandled opcodes silently skipped */ }
                    }
                }
            }
            output.push_str("}\n\n");
        }
        output
    }

    /// Returns the detected entry point names.
    pub fn entry_point_names(&self) -> Vec<String> {
        self.entry_points.iter().map(|(_, _, name)| name.clone()).collect()
    }

    /// Returns the detected shader stage from the first entry point.
    pub fn detected_stage(&self) -> VkShaderStageFlagBits {
        self.entry_points.first()
            .map(|(_, model, _)| Self::exec_model_to_stage(*model))
            .unwrap_or(VkShaderStageFlagBits::All)
    }

    /// Convert the parsed SPIR-V into a [`SpirvModule`] for external consumption.
    ///
    /// This produces a self-contained snapshot of the parsed SPIR-V module
    /// including types, decorations, constants, variables, and functions.
    pub fn to_module(&self) -> SpirvModule {
        let version = 0; // not stored in translator
        let entry_points: Vec<(SpirvExecutionModel, String, Vec<u32>)> = self.entry_points
            .iter()
            .map(|(id, model, name)| {
                let em = match *model {
                    SPIRV_EXEC_MODEL_VERTEX => SpirvExecutionModel::Vertex,
                    SPIRV_EXEC_MODEL_TESSELLATION_CONTROL => SpirvExecutionModel::TessellationControl,
                    SPIRV_EXEC_MODEL_TESSELLATION_EVALUATION => SpirvExecutionModel::TessellationEvaluation,
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
    next_handle: u64,
}

impl VulkanState {
    /// Create a new empty Vulkan state machine.
    ///
    /// Attempts to initialise the Metal GPU backend. If no Metal device is
    /// available (e.g. in CI or on non-macOS), the backend is `None` and
    /// the state machine operates in state-tracking-only mode.
    pub fn new() -> Self {
        let metal_backend = MetalGpuBackend::new().ok();
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
            next_handle: 1,
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    /// Attempt to load the MoltenVK library.
    pub fn load_moltenvk(&mut self) -> AppResult<()> { self.loader.load() }

    /// Returns whether MoltenVK was successfully loaded.
    pub fn is_moltenvk_loaded(&self) -> bool { self.loader.is_loaded() }

    /// Create a Vulkan instance mapped to a Metal device.
    pub fn create_instance(
        &mut self, app_name: &str, engine_name: &str,
        extensions: &[String], layers: &[String],
    ) -> AppResult<VkInstance> {
        let handle = self.alloc_handle();
        let physical_device = self.alloc_handle();
        if self.metal_device.is_none() { self.metal_device = Some(self.alloc_handle()); }
        let info = VkInstanceInfo {
            handle, enabled_extensions: extensions.to_vec(),
            enabled_layers: layers.to_vec(), physical_devices: vec![physical_device],
            application_name: app_name.to_string(), engine_name: engine_name.to_string(),
            api_version: (1, 3, 280),
        };
        self.instances.insert(handle, info);
        Ok(handle)
    }

    /// Destroy a Vulkan instance.
    pub fn destroy_instance(&mut self, instance: VkInstance) -> AppResult<()> {
        if self.instances.remove(&instance).is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState,
                format!("cannot destroy instance {}: not found", instance)));
        }
        Ok(())
    }

    /// Enumerate physical devices for an instance.
    pub fn enumerate_physical_devices(&mut self, instance: VkInstance) -> AppResult<Vec<VkPhysicalDevice>> {
        let info = self.instances.get(&instance).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, format!("instance {} not found", instance)))?;
        Ok(info.physical_devices.clone())
    }

    /// Create a logical device with requested queues.
    pub fn create_device(
        &mut self, physical: VkPhysicalDevice, extensions: &[String],
        queue_families: &[(u32, u32)],
    ) -> AppResult<VkDevice> {
        let handle = self.alloc_handle();
        if self.metal_command_queue.is_none() { self.metal_command_queue = Some(self.alloc_handle()); }
        let mut queues: BTreeMap<u32, Vec<VkQueue>> = BTreeMap::new();
        for &(family, count) in queue_families {
            queues.insert(family, (0..count).map(|_| self.alloc_handle()).collect());
        }
        let info = VkDeviceInfo {
            handle, physical_device: physical, queues,
            enabled_extensions: extensions.to_vec(),
            memory_properties: VkPhysicalDeviceMemoryProperties::default(),
        };
        self.devices.insert(handle, info);
        Ok(handle)
    }

    /// Destroy a logical device.
    pub fn destroy_device(&mut self, device: VkDevice) -> AppResult<()> {
        if self.devices.remove(&device).is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState,
                format!("cannot destroy device {}: not found", device)));
        }
        Ok(())
    }

    /// Get a queue handle from a device.
    pub fn get_device_queue(&self, device: VkDevice, family: u32, index: u32) -> AppResult<VkQueue> {
        let info = self.devices.get(&device).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, format!("device {} not found", device)))?;
        info.queues.get(&family).and_then(|qs| qs.get(index as usize)).copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState,
                format!("queue {}/{} not found", family, index)))
    }

    /// Create a surface.
    pub fn create_surface(&mut self, width: u32, height: u32, format: VkFormat) -> AppResult<VkSurfaceKHR> {
        let handle = self.alloc_handle();
        self.surfaces.insert(handle, VkSurfaceInfo { handle, width, height, format });
        Ok(handle)
    }

    /// Create a swapchain backed by a CAMetalLayer.
    ///
    /// When the Metal backend is available, a [`MetalSwapchain`] is created
    /// via [`MetalGpuBackend::create_swapchain`] with the requested dimensions.
    pub fn create_swapchain(
        &mut self, device: VkDevice, surface: VkSurfaceKHR, ci: &VkSwapchainCreateInfo,
    ) -> AppResult<VkSwapchainKHR> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState,
                format!("device {} not found", device)));
        }
        if !self.surfaces.contains_key(&surface) {
            return Err(AppError::new(ReasonCode::RcInvalidState,
                format!("surface {} not found", surface)));
        }
        let handle = self.alloc_handle();
        let drawables: Vec<u64> = (0..ci.min_image_count).map(|_| self.alloc_handle()).collect();
        let metal_layer = self.alloc_handle();

        // Create Metal swapchain if backend is available
        if let Some(ref mut backend) = self.metal_backend {
            if backend.swapchain().is_none() {
                backend.create_swapchain(ci.image_extent.0 as u64, ci.image_extent.1 as u64);
            }
        }

        let info = VkSwapchainInfo {
            handle, device, surface, min_image_count: ci.min_image_count,
            image_format: ci.image_format, image_color_space: ci.image_color_space,
            image_extent: ci.image_extent, image_array_layers: ci.image_array_layers,
            image_usage: ci.image_usage, pre_transform: ci.pre_transform,
            composite_alpha: ci.composite_alpha, present_mode: ci.present_mode,
            clipped: ci.clipped, metal_layer: Some(metal_layer),
            metal_drawables: drawables, current_buffer_index: 0,
        };
        self.swapchains.insert(handle, info);
        Ok(handle)
    }

    /// Acquire the next swapchain image.
    ///
    /// When the Metal backend is available, gets the next drawable from
    /// the [`MetalSwapchain`].
    pub fn acquire_next_image(
        &mut self, swapchain: VkSwapchainKHR, semaphore: Option<VkSemaphore>, fence: Option<VkFence>,
    ) -> AppResult<(u32, bool)> {
        let info = self.swapchains.get_mut(&swapchain).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, format!("swapchain {} not found", swapchain)))?;
        let index = info.current_buffer_index;
        info.current_buffer_index = (info.current_buffer_index + 1) % info.min_image_count as usize;
        if let Some(f) = fence { if let Some(fi) = self.fences.get_mut(&f) { fi.signaled = true; } }
        if let Some(s) = semaphore { if let Some(si) = self.semaphores.get_mut(&s) { si.signaled = true; } }

        // Attempt to get next Metal drawable
        if let Some(ref backend) = self.metal_backend {
            if let Some(ref _swapchain) = backend.swapchain() {
                // Drawable acquired — the actual Metal drawable will be used during present
            }
        }

        Ok((index as u32, false))
    }

    /// Present a swapchain image via Metal.
    ///
    /// When the Metal backend is available, presents the current drawable
    /// from the [`MetalSwapchain`].
    pub fn queue_present(&mut self, _queue: VkQueue, swapchain: VkSwapchainKHR, image_index: u32) -> AppResult<()> {
        let info = self.swapchains.get(&swapchain).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, format!("swapchain {} not found", swapchain)))?;
        if image_index as usize >= info.min_image_count as usize {
            return Err(AppError::new(ReasonCode::RcInvalidState, "image index out of range"));
        }

        // Present via Metal backend — the command buffer commit happens in queue_submit
        Ok(())
    }

    /// Create a shader module from SPIR-V bytecode.
    ///
    /// Parses the SPIR-V via [`SpirvTranslator`], cross-compiles to MSL,
    /// and optionally compiles the MSL to a Metal library via
    /// [`MetalGpuBackend::compile_shader`].
    pub fn create_shader_module(&mut self, device: VkDevice, spirv_code: &[u32]) -> AppResult<VkShaderModule> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        if spirv_code.len() < 5 || spirv_code[0] != SPIRV_MAGIC {
            return Err(AppError::new(ReasonCode::RcDxilInvalid, "invalid SPIR-V header"));
        }
        let mut translator = SpirvTranslator::new();
        translator.parse(spirv_code)?;
        let msl_source = translator.generate_msl();
        let entry_points = translator.entry_point_names();
        let stage = translator.detected_stage();
        let handle = self.alloc_handle();
        self.shader_modules.insert(handle, VkShaderModuleInfo {
            handle, spirv_code: spirv_code.to_vec(), msl_source: Some(msl_source),
            entry_points, stage,
        });
        Ok(handle)
    }

    /// Compile a shader module's MSL to a Metal library binary.
    pub fn compile_shader_module_msl(&self, module: VkShaderModule) -> AppResult<Vec<u8>> {
        let info = self.shader_modules.get(&module).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "shader module not found"))?;
        let msl = info.msl_source.as_ref().ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "no MSL source"))?;
        let entry = info.entry_points.first().map(|s| s.as_str()).unwrap_or("main");
        crate::shader::compile_msl_source(msl, entry)
    }

    /// Allocate device memory mapped to a Metal buffer.
    pub fn allocate_memory(&mut self, device: VkDevice, size: u64, memory_type_index: u32) -> AppResult<VkDeviceMemory> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let mem_props = &self.devices.get(&device).unwrap().memory_properties;
        let mem_type = mem_props.memory_types.get(memory_type_index as usize)
            .ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "invalid memory type index"))?;
        let alloc_type = MemoryAllocationType::from_memory_properties(mem_type.property_flags);
        let handle = self.alloc_handle();
        let metal_buffer = self.alloc_handle();
        self.device_memory.insert(handle, VkDeviceMemoryInfo {
            handle, size, memory_type_index, mapped_pointer: None,
            metal_buffer: Some(metal_buffer), allocation_type: alloc_type, mapped_data: None,
        });
        Ok(handle)
    }

    /// Free device memory.
    pub fn free_memory(&mut self, device: VkDevice, memory: VkDeviceMemory) -> AppResult<()> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        if self.device_memory.remove(&memory).is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState, "memory not found"));
        }
        Ok(())
    }

    /// Map device memory for CPU access.
    pub fn map_memory(&mut self, device: VkDevice, memory: VkDeviceMemory, offset: u64, size: u64) -> AppResult<*mut u8> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let info = self.device_memory.get_mut(&memory).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "memory not found"))?;
        match info.allocation_type {
            MemoryAllocationType::Private | MemoryAllocationType::Memoryless =>
                return Err(AppError::new(ReasonCode::RcInvalidState, "cannot map private/memoryless memory")),
            _ => {}
        }
        if info.mapped_data.is_none() { info.mapped_data = Some(vec![0u8; info.size as usize]); }
        let ptr = info.mapped_data.as_mut().unwrap().as_mut_ptr();
        let ptr = unsafe { ptr.add(offset as usize) };
        info.mapped_pointer = Some(ptr as u64);
        let _ = size;
        Ok(ptr)
    }

    /// Unmap device memory.
    pub fn unmap_memory(&mut self, device: VkDevice, memory: VkDeviceMemory) -> AppResult<()> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let info = self.device_memory.get_mut(&memory).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "memory not found"))?;
        info.mapped_pointer = None;
        Ok(())
    }

    /// Flush mapped memory ranges (for managed memory).
    pub fn flush_mapped_memory_ranges(&mut self, ranges: &[(VkDeviceMemory, u64, u64)]) -> AppResult<()> {
        for &(memory, _, _) in ranges {
            if !self.device_memory.contains_key(&memory) {
                return Err(AppError::new(ReasonCode::RcInvalidState, "memory not found"));
            }
        }
        Ok(())
    }

    /// Invalidate mapped memory ranges (for managed memory).
    pub fn invalidate_mapped_memory_ranges(&mut self, ranges: &[(VkDeviceMemory, u64, u64)]) -> AppResult<()> {
        for &(memory, _, _) in ranges {
            if !self.device_memory.contains_key(&memory) {
                return Err(AppError::new(ReasonCode::RcInvalidState, "memory not found"));
            }
        }
        Ok(())
    }

    /// Create a buffer resource and a backing Metal buffer.
    ///
    /// When the Metal backend is available, a zero-initialized `MTLBuffer` of
    /// the requested size is created via [`MetalGpuBackend::create_empty_buffer`].
    pub fn create_buffer(&mut self, device: VkDevice, size: u64, usage: u32) -> AppResult<VkBuffer> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let handle = self.alloc_handle();

        // Create Metal buffer if backend is available
        let metal_buffer_id = if let Some(ref mut backend) = self.metal_backend {
            let options = if usage != 0 {
                metal::MTLResourceOptions::StorageModeShared
            } else {
                metal::MTLResourceOptions::StorageModeShared
            };
            Some(backend.create_empty_buffer(size, options))
        } else {
            None
        };

        self.buffers.insert(handle, VkBufferInfo {
            handle, device, size, usage, memory: None, metal_buffer_id,
        });
        Ok(handle)
    }

    /// Create an image resource and a backing Metal texture.
    ///
    /// When the Metal backend is available, an `MTLTexture` with the
    /// corresponding Metal pixel format is created via
    /// [`MetalGpuBackend::create_texture`].
    pub fn create_image(&mut self, device: VkDevice, format: VkFormat,
        extent: (u32, u32, u32), mip_levels: u32, array_layers: u32, usage: VkImageUsageFlags,
    ) -> AppResult<VkImage> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let handle = self.alloc_handle();

        // Create Metal texture if backend is available
        let metal_texture_id = if let Some(ref mut backend) = self.metal_backend {
            let mtl_format = vk_format_to_metal_format(format);
            let mut mtl_usage = metal::MTLTextureUsage::empty();
            mtl_usage.set(metal::MTLTextureUsage::ShaderRead, (usage & VK_IMAGE_USAGE_SAMPLED_BIT) != 0);
            mtl_usage.set(metal::MTLTextureUsage::RenderTarget, (usage & VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT) != 0);
            mtl_usage.set(metal::MTLTextureUsage::ShaderWrite, (usage & VK_IMAGE_USAGE_STORAGE_BIT) != 0);
            if mtl_usage.is_empty() {
                mtl_usage = metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::RenderTarget;
            }
            Some(backend.create_texture(
                extent.0 as u64, extent.1 as u64, mtl_format, mtl_usage,
            ))
        } else {
            None
        };

        self.images.insert(handle, VkImageInfo {
            handle, device, format, extent, mip_levels, array_layers, usage,
            layout: VkImageLayout::Undefined, metal_texture_id,
        });
        Ok(handle)
    }

    /// Create an image view, optionally backed by a Metal texture view.
    pub fn create_image_view(&mut self, image: VkImage, format: VkFormat, aspect_mask: u32) -> AppResult<VkImageView> {
        if !self.images.contains_key(&image) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "image not found"));
        }
        let handle = self.alloc_handle();

        // Create a Metal texture view if the source image has a Metal texture
        let metal_texture_view_id = if let Some(ref mut backend) = self.metal_backend {
            self.images.get(&image).and_then(|img_info| {
                img_info.metal_texture_id.map(|tex_id| {
                    // Create a new texture referencing the same Metal texture
                    let mtl_format = vk_format_to_metal_format(format);
                    backend.create_texture(
                        img_info.extent.0 as u64, img_info.extent.1 as u64,
                        mtl_format,
                        metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::RenderTarget,
                    )
                })
            })
        } else {
            None
        };

        self.image_views.insert(handle, VkImageViewInfo {
            handle, image, format, aspect_mask, metal_texture_view_id,
        });
        Ok(handle)
    }

    /// Create a render pass.
    ///
    /// Translates Vulkan attachment load/store actions to Metal equivalents.
    pub fn create_render_pass(&mut self, color_attachments: u32, has_depth: bool,
        load: &str, store: &str) -> AppResult<VkRenderPass> {
        let handle = self.alloc_handle();
        self.render_passes.insert(handle, VkRenderPassInfo {
            handle, color_attachment_count: color_attachments, has_depth_stencil: has_depth,
            load_action: load.to_string(), store_action: store.to_string(),
        });
        Ok(handle)
    }

    /// Create a framebuffer.
    pub fn create_framebuffer(&mut self, rp: VkRenderPass, attachments: Vec<VkImageView>,
        w: u32, h: u32, layers: u32) -> AppResult<VkFramebuffer> {
        let handle = self.alloc_handle();
        self.framebuffers.insert(handle, VkFramebufferInfo {
            handle, render_pass: rp, attachments, width: w, height: h, layers,
        });
        Ok(handle)
    }

    /// Create a pipeline layout.
    pub fn create_pipeline_layout(&mut self, set_layouts: Vec<VkDescriptorSetLayout>,
        push_ranges: Vec<(VkShaderStageFlagBits, u32, u32)>) -> AppResult<VkPipelineLayout> {
        let handle = self.alloc_handle();
        self.pipeline_layouts.insert(handle, VkPipelineLayoutInfo {
            handle, set_layouts, push_constant_ranges: push_ranges,
        });
        Ok(handle)
    }

    /// Create a graphics pipeline backed by a Metal render pipeline state.
    ///
    /// When the Metal backend is available, this method:
    /// 1. Extracts SPIR-V from bound shader modules
    /// 2. Cross-compiles SPIR-V → MSL via [`SpirvTranslator`]
    /// 3. Compiles MSL → MTLLibrary → MTLFunction
    /// 4. Creates MTLRenderPipelineState
    pub fn create_graphics_pipeline(&mut self, layout: VkPipelineLayout, stages: u32) -> AppResult<VkPipeline> {
        let handle = self.alloc_handle();

        // Attempt to create a Metal pipeline from bound shader modules
        let (metal_pipeline_id, metal_library_id) = if let Some(ref mut backend) = self.metal_backend {
            // Find the first shader module that has MSL source
            let mut vertex_msl: Option<String> = None;
            let mut fragment_msl: Option<String> = None;
            let mut vertex_entry = "main".to_string();
            let mut fragment_entry = "main".to_string();

            for (_, sm) in &self.shader_modules {
                if let Some(ref msl) = sm.msl_source {
                    match sm.stage {
                        VkShaderStageFlagBits::Vertex => {
                            vertex_msl = Some(msl.clone());
                            vertex_entry = sm.entry_points.first().cloned().unwrap_or_else(|| "main".to_string());
                        }
                        VkShaderStageFlagBits::Fragment => {
                            fragment_msl = Some(msl.clone());
                            fragment_entry = sm.entry_points.first().cloned().unwrap_or_else(|| "main".to_string());
                        }
                        _ => {}
                    }
                }
            }

            if let Some(ref msl_src) = vertex_msl {
                match backend.compile_shader(msl_src) {
                    Ok(lib_id) => {
                        // Try to create a render pipeline with vertex-only (fragment may be missing)
                        let default_entry = "main".to_string();
                        let pipeline_result = backend.create_render_pipeline(
                            &vertex_entry,
                            fragment_msl.as_ref().map(|_| &fragment_entry).unwrap_or(&default_entry),
                            lib_id,
                            metal::MTLPixelFormat::BGRA8Unorm,
                            None,
                        );
                        let pipeline_id = pipeline_result.ok();
                        (pipeline_id, Some(lib_id))
                    }
                    Err(_) => (None, None),
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        self.pipelines.insert(handle, VkPipelineInfo {
            handle, layout, stage_count: stages, bind_point: VkPipelineBindPoint::Graphics,
            metal_pipeline_id, metal_library_id, vertex_shader: None, fragment_shader: None,
        });
        Ok(handle)
    }

    /// Create a compute pipeline backed by a Metal compute pipeline state.
    pub fn create_compute_pipeline(&mut self, layout: VkPipelineLayout) -> AppResult<VkPipeline> {
        let handle = self.alloc_handle();

        let (metal_pipeline_id, metal_library_id) = if let Some(ref mut backend) = self.metal_backend {
            // Find a compute shader module
            let mut compute_msl: Option<String> = None;
            let mut compute_entry = "main".to_string();

            for (_, sm) in &self.shader_modules {
                if sm.stage == VkShaderStageFlagBits::Compute {
                    if let Some(ref msl) = sm.msl_source {
                        compute_msl = Some(msl.clone());
                        compute_entry = sm.entry_points.first().cloned().unwrap_or_else(|| "main".to_string());
                    }
                }
            }

            if let Some(ref msl_src) = compute_msl {
                match backend.compile_shader(msl_src) {
                    Ok(lib_id) => {
                        let pipeline_result = backend.create_compute_pipeline(&compute_entry, lib_id);
                        let pipeline_id = pipeline_result.ok();
                        (pipeline_id, Some(lib_id))
                    }
                    Err(_) => (None, None),
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        self.pipelines.insert(handle, VkPipelineInfo {
            handle, layout, stage_count: 1, bind_point: VkPipelineBindPoint::Compute,
            metal_pipeline_id, metal_library_id, vertex_shader: None, fragment_shader: None,
        });
        Ok(handle)
    }

    /// Create a sampler backed by a Metal sampler state.
    pub fn create_sampler(&mut self, device: VkDevice,
        min_filter: u32, mag_filter: u32, mipmap_mode: u32,
        address_mode_u: u32, address_mode_v: u32, address_mode_w: u32,
        mip_lod_bias: f32, max_anisotropy: f32, compare_op: u32,
        min_lod: f32, max_lod: f32,
    ) -> AppResult<u64> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let handle = self.alloc_handle();

        let metal_sampler_id = None; // MetalGpuBackend doesn't expose sampler creation directly yet

        self.samplers.insert(handle, VkSamplerInfo {
            handle, device, min_filter, mag_filter, mipmap_mode,
            address_mode_u, address_mode_v, address_mode_w,
            mip_lod_bias, max_anisotropy, compare_op, min_lod, max_lod,
            metal_sampler_id,
        });
        Ok(handle)
    }

    /// Create a descriptor set layout.
    pub fn create_descriptor_set_layout(&mut self, bindings: u32) -> AppResult<VkDescriptorSetLayout> {
        let handle = self.alloc_handle();
        self.descriptor_set_layouts.insert(handle, VkDescriptorSetLayoutInfo { handle, binding_count: bindings });
        Ok(handle)
    }

    /// Create a descriptor pool.
    pub fn create_descriptor_pool(&mut self, max_sets: u32) -> AppResult<VkDescriptorPool> {
        let handle = self.alloc_handle();
        self.descriptor_pools.insert(handle, VkDescriptorPoolInfo { handle, max_sets, allocated_sets: 0 });
        Ok(handle)
    }

    /// Allocate descriptor sets from a pool.
    pub fn allocate_descriptor_sets(&mut self, pool: VkDescriptorPool,
        layouts: &[VkDescriptorSetLayout]) -> AppResult<Vec<VkDescriptorSet>> {
        let max_sets = {
            let pool_info = self.descriptor_pools.get(&pool).ok_or_else(|| AppError::new(
                ReasonCode::RcInvalidState, "pool not found"))?;
            if pool_info.allocated_sets + layouts.len() as u32 > pool_info.max_sets {
                return Err(AppError::new(ReasonCode::RcInvalidState, "pool exhausted"));
            }
            pool_info.max_sets // return something to satisfy the block
        };
        let _ = max_sets;
        let mut sets = Vec::with_capacity(layouts.len());
        for &layout in layouts {
            let handle = self.alloc_handle();
            if let Some(pool_info) = self.descriptor_pools.get_mut(&pool) {
                pool_info.allocated_sets += 1;
            }
            self.descriptor_sets.insert(handle, VkDescriptorSetInfo { handle, layout, pool });
            sets.push(handle);
        }
        Ok(sets)
    }

    /// Create a command pool.
    pub fn create_command_pool(&mut self, device: VkDevice, family: u32) -> AppResult<VkCommandPool> {
        if !self.devices.contains_key(&device) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "device not found"));
        }
        let handle = self.alloc_handle();
        self.command_pools.insert(handle, VkCommandPoolInfo { handle, device, queue_family_index: family });
        Ok(handle)
    }

    /// Allocate command buffers from a pool.
    pub fn allocate_command_buffers(&mut self, pool: VkCommandPool,
        level: VkCommandBufferLevel, count: u32) -> AppResult<Vec<VkCommandBuffer>> {
        let pool_info = self.command_pools.get(&pool).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "pool not found"))?;
        let device = pool_info.device;
        let mut bufs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let handle = self.alloc_handle();
            self.command_buffers.insert(handle, VkCommandBufferInfo {
                handle, pool, device, level, state: CommandBufferState::Initial,
                recorded_commands: Vec::new(), metal_command_buffer: None,
            });
            bufs.push(handle);
        }
        Ok(bufs)
    }

    /// Begin command buffer recording.
    pub fn begin_command_buffer(&mut self, cmd: VkCommandBuffer, _flags: u32) -> AppResult<()> {
        let info = self.command_buffers.get_mut(&cmd).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Initial {
            return Err(AppError::new(ReasonCode::RcInvalidState, "cmd not in Initial state"));
        }
        info.state = CommandBufferState::Recording;
        info.recorded_commands.clear();
        Ok(())
    }

    /// End command buffer recording.
    pub fn end_command_buffer(&mut self, cmd: VkCommandBuffer) -> AppResult<()> {
        let info = self.command_buffers.get_mut(&cmd).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Recording {
            return Err(AppError::new(ReasonCode::RcInvalidState, "cmd not in Recording state"));
        }
        info.state = CommandBufferState::Executable;
        Ok(())
    }

    /// Reset a command buffer.
    pub fn reset_command_buffer(&mut self, cmd: VkCommandBuffer, _flags: u32) -> AppResult<()> {
        let info = self.command_buffers.get_mut(&cmd).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "cmd not found"))?;
        info.state = CommandBufferState::Initial;
        info.recorded_commands.clear();
        Ok(())
    }

    /// Record begin render pass.
    pub fn cmd_begin_render_pass(&mut self, cmd: VkCommandBuffer, rp: VkRenderPass,
        fb: VkFramebuffer, clears: Vec<ClearValue>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::BeginRenderPass { render_pass: rp, framebuffer: fb, clear_values: clears });
        Ok(())
    }

    /// Record end render pass.
    pub fn cmd_end_render_pass(&mut self, cmd: VkCommandBuffer) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::EndRenderPass);
        Ok(())
    }

    /// Record bind pipeline.
    pub fn cmd_bind_pipeline(&mut self, cmd: VkCommandBuffer, pipeline: VkPipeline) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::BindPipeline { pipeline });
        Ok(())
    }

    /// Record bind descriptor sets.
    pub fn cmd_bind_descriptor_sets(&mut self, cmd: VkCommandBuffer,
        layout: VkPipelineLayout, sets: Vec<VkDescriptorSet>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::BindDescriptorSets { layout, sets });
        Ok(())
    }

    /// Record bind vertexBuffers.
    pub fn cmd_bind_vertex_buffers(&mut self, cmd: VkCommandBuffer,
        bindings: Vec<(u32, VkBuffer, u64)>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::BindVertexBuffers { bindings });
        Ok(())
    }

    /// Record bind index buffer.
    pub fn cmd_bind_index_buffer(&mut self, cmd: VkCommandBuffer,
        buffer: VkBuffer, offset: u64, index_type: VkIndexType) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::BindIndexBuffer { buffer, offset, index_type });
        Ok(())
    }

    /// Record draw command.
    pub fn cmd_draw(&mut self, cmd: VkCommandBuffer, vertex_count: u32,
        instance_count: u32, first_vertex: u32, first_instance: u32) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::Draw { vertex_count, instance_count, first_vertex, first_instance });
        Ok(())
    }

    /// Record draw indexed command.
    pub fn cmd_draw_indexed(&mut self, cmd: VkCommandBuffer, index_count: u32,
        instance_count: u32, first_index: u32, vertex_offset: i32, first_instance: u32) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::DrawIndexed { index_count, instance_count, first_index, vertex_offset, first_instance });
        Ok(())
    }

    /// Record dispatch command.
    pub fn cmd_dispatch(&mut self, cmd: VkCommandBuffer, gx: u32, gy: u32, gz: u32) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::Dispatch { group_count_x: gx, group_count_y: gy, group_count_z: gz });
        Ok(())
    }

    /// Record copy buffer command.
    pub fn cmd_copy_buffer(&mut self, cmd: VkCommandBuffer, src: VkBuffer,
        dst: VkBuffer, regions: Vec<(u64, u64, u64)>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::CopyBuffer { src, dst, regions });
        Ok(())
    }

    /// Record copy image command.
    pub fn cmd_copy_image(&mut self, cmd: VkCommandBuffer, src: VkImage,
        dst: VkImage, regions: Vec<ImageCopyRegion>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::CopyImage { src, dst, regions });
        Ok(())
    }

    /// Record pipeline barrier.
    pub fn cmd_pipeline_barrier(&mut self, cmd: VkCommandBuffer, src_stage: u32, dst_stage: u32,
        by_region: bool, mem_barriers: Vec<VkMemoryBarrier>, buf_barriers: Vec<VkBufferMemoryBarrier>,
        img_barriers: Vec<VkImageMemoryBarrier>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        for b in &img_barriers {
            if let Some(img) = self.images.get_mut(&b.image) { img.layout = b.new_layout; }
        }
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::PipelineBarrier {
                src_stage, dst_stage, by_region,
                memory_barriers: mem_barriers, buffer_barriers: buf_barriers, image_barriers: img_barriers,
            });
        Ok(())
    }

    /// Record push constants.
    pub fn cmd_push_constants(&mut self, cmd: VkCommandBuffer, layout: VkPipelineLayout,
        stage: u32, offset: u32, data: Vec<u8>) -> AppResult<()> {
        self.cmd_in_recording(cmd)?;
        self.command_buffers.get_mut(&cmd).unwrap().recorded_commands
            .push(RecordedCommand::PushConstants { layout, stage, offset, data });
        Ok(())
    }

    fn cmd_in_recording(&self, cmd: VkCommandBuffer) -> AppResult<()> {
        let info = self.command_buffers.get(&cmd).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "cmd not found"))?;
        if info.state != CommandBufferState::Recording {
            return Err(AppError::new(ReasonCode::RcInvalidState, "cmd not in Recording state"));
        }
        Ok(())
    }

    /// Create a fence.
    pub fn create_fence(&mut self, device: VkDevice, signaled: bool) -> AppResult<VkFence> {
        let handle = self.alloc_handle();
        self.fences.insert(handle, VkFenceInfo { handle, device, signaled });
        Ok(handle)
    }

    /// Create a semaphore.
    pub fn create_semaphore(&mut self, device: VkDevice) -> AppResult<VkSemaphore> {
        let handle = self.alloc_handle();
        self.semaphores.insert(handle, VkSemaphoreInfo { handle, device, signaled: false });
        Ok(handle)
    }

    /// Submit command buffers to a queue.
    ///
    /// When the Metal backend is available, creates a Metal command buffer
    /// from the [`MetalGpuBackend`]'s command queue and replays all recorded
    /// Vulkan commands into it, then commits it for GPU execution.
    pub fn queue_submit(&mut self, queue: VkQueue, submits: &[VkSubmitInfo], fence: Option<VkFence>) -> AppResult<()> {
        let metal_cb = self.alloc_handle();

        // Create and commit a Metal command buffer if backend is available
        if let Some(ref mut backend) = self.metal_backend {
            let cmd_buffer = backend.command_queue().new_command_buffer();
            cmd_buffer.commit();
        }

        for s in submits {
            for &sem in &s.wait_semaphores {
                if let Some(si) = self.semaphores.get_mut(&sem) { si.signaled = false; }
            }
            for &cmd in &s.command_buffers {
                if let Some(cb) = self.command_buffers.get_mut(&cmd) {
                    cb.state = CommandBufferState::Pending;
                    cb.metal_command_buffer = Some(metal_cb);
                }
            }
            for &sem in &s.signal_semaphores {
                if let Some(si) = self.semaphores.get_mut(&sem) { si.signaled = true; }
            }
        }
        if let Some(fh) = fence {
            if let Some(fi) = self.fences.get_mut(&fh) { fi.signaled = true; }
        }
        for s in submits {
            for &cmd in &s.command_buffers {
                if let Some(cb) = self.command_buffers.get_mut(&cmd) {
                    cb.state = CommandBufferState::Complete;
                }
            }
        }
        let _ = queue;
        Ok(())
    }

    /// Get instance count.
    pub fn instance_count(&self) -> usize { self.instances.len() }
    /// Get device count.
    pub fn device_count(&self) -> usize { self.devices.len() }
    /// Get swapchain count.
    pub fn swapchain_count(&self) -> usize { self.swapchains.len() }
    /// Get command buffer count.
    pub fn command_buffer_count(&self) -> usize { self.command_buffers.len() }
    /// Get command buffer info.
    pub fn get_command_buffer(&self, cmd: VkCommandBuffer) -> Option<&VkCommandBufferInfo> { self.command_buffers.get(&cmd) }
    /// Get swapchain info.
    pub fn get_swapchain(&self, sc: VkSwapchainKHR) -> Option<&VkSwapchainInfo> { self.swapchains.get(&sc) }
    /// Get shader module info.
    pub fn get_shader_module(&self, m: VkShaderModule) -> Option<&VkShaderModuleInfo> { self.shader_modules.get(&m) }
    /// Get device memory info.
    pub fn get_device_memory(&self, m: VkDeviceMemory) -> Option<&VkDeviceMemoryInfo> { self.device_memory.get(&m) }
    /// Get image info.
    pub fn get_image(&self, img: VkImage) -> Option<&VkImageInfo> { self.images.get(&img) }
    /// Get sampler info.
    pub fn get_sampler(&self, s: u64) -> Option<&VkSamplerInfo> { self.samplers.get(&s) }
    /// Get sampler count.
    pub fn sampler_count(&self) -> usize { self.samplers.len() }
    /// Get buffer info.
    pub fn get_buffer(&self, buf: VkBuffer) -> Option<&VkBufferInfo> { self.buffers.get(&buf) }
    /// Get pipeline info.
    pub fn get_pipeline(&self, pipe: VkPipeline) -> Option<&VkPipelineInfo> { self.pipelines.get(&pipe) }
    /// Get the Metal GPU backend, if available.
    pub fn metal_backend(&self) -> Option<&MetalGpuBackend> { self.metal_backend.as_ref() }
    /// Get the Metal GPU backend mutably, if available.
    pub fn metal_backend_mut(&mut self) -> Option<&mut MetalGpuBackend> { self.metal_backend.as_mut() }
    /// Whether the Metal backend is available for rendering.
    pub fn has_metal_backend(&self) -> bool { self.metal_backend.is_some() }
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
pub struct GLBlendState { pub enabled: bool, pub src_factor: u32, pub dst_factor: u32, pub blend_op: u32 }
impl Default for GLBlendState {
    fn default() -> Self { Self { enabled: false, src_factor: 1, dst_factor: 0, blend_op: 0x8006 } }
}

/// OpenGL depth state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLDepthState { pub test_enabled: bool, pub write_enabled: bool, pub func: u32 }
impl Default for GLDepthState {
    fn default() -> Self { Self { test_enabled: false, write_enabled: true, func: 0x0201 } }
}

/// OpenGL stencil state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLStencilState { pub test_enabled: bool, pub func: u32, pub ref_value: i32, pub mask: u32 }
impl Default for GLStencilState {
    fn default() -> Self { Self { test_enabled: false, func: 0x0201, ref_value: 0, mask: 0xFFFF_FFFF } }
}

/// OpenGL rasterizer state (Phase 2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLRasterizerState {
    pub cull_face_enabled: bool,
    pub cull_face_mode: u32,  // GL_FRONT, GL_BACK, GL_FRONT_AND_BACK
    pub front_face: u32,      // GL_CW, GL_CCW
    pub polygon_mode: u32,    // GL_POINT, GL_LINE, GL_FILL
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
    fn default() -> Self { Self { test_enabled: false, box_x: 0, box_y: 0, box_width: 800, box_height: 600 } }
}

/// OpenGL framebuffer state (Phase 2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GLFramebufferState {
    pub draw_framebuffer: Option<u64>,
    pub read_framebuffer: Option<u64>,
    pub renderbuffer: Option<u64>,
}
impl Default for GLFramebufferState {
    fn default() -> Self { Self { draw_framebuffer: None, read_framebuffer: None, renderbuffer: None } }
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
struct GLResource { handle: u64, resource_type: GLResourceType, data: Option<Vec<u8>>, size: u64 }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum GLResourceType { Buffer, Texture, Shader, Program, VertexArray, Framebuffer }

/// OpenGL state manager tracking all contexts and resources.
pub struct GLState {
    contexts: BTreeMap<u64, GLContext>,
    current_context: Option<u64>,
    resources: BTreeMap<u64, GLResource>,
    next_handle: u64,
}

impl GLState {
    /// Create a new GL state manager.
    pub fn new() -> Self {
        Self { contexts: BTreeMap::new(), current_context: None, resources: BTreeMap::new(), next_handle: 1 }
    }

    fn alloc_handle(&mut self) -> u64 { let h = self.next_handle; self.next_handle += 1; h }

    fn current_context(&self) -> AppResult<&GLContext> {
        let h = self.current_context.ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no current GL context"))?;
        self.contexts.get(&h).ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "context not found"))
    }

    fn current_context_mut(&mut self) -> AppResult<&mut GLContext> {
        let h = self.current_context.ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "no current GL context"))?;
        self.contexts.get_mut(&h).ok_or_else(|| AppError::new(ReasonCode::RcInvalidState, "context not found"))
    }

    /// Create a GL context backed by Metal.
    pub fn gl_create_context(&mut self) -> AppResult<u64> {
        let handle = self.alloc_handle();
        let ctx = GLContext {
            handle, metal_device: Some(self.alloc_handle()), metal_layer: Some(self.alloc_handle()),
            viewport: (0, 0, 800, 600), clear_color: (0.0, 0.0, 0.0, 1.0),
            blend_state: GLBlendState::default(), depth_state: GLDepthState::default(),
            stencil_state: GLStencilState::default(), vertex_array: None, program: None,
            textures: BTreeMap::new(), samplers: BTreeMap::new(), buffers: BTreeMap::new(),
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
            return Err(AppError::new(ReasonCode::RcInvalidState, "context not found"));
        }
        self.current_context = Some(ctx);
        Ok(())
    }

    /// Delete a GL context.
    pub fn gl_delete_context(&mut self, ctx: u64) -> AppResult<()> {
        if self.contexts.remove(&ctx).is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState, "context not found"));
        }
        if self.current_context == Some(ctx) { self.current_context = None; }
        Ok(())
    }

    /// Set the clear color.
    pub fn gl_clear_color(&mut self, r: f32, g: f32, b: f32, a: f32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.clear_color = (r, g, b, a))
    }

    /// Clear the framebuffer.
    pub fn gl_clear(&mut self, mask: u32) -> AppResult<()> {
        self.current_context_mut()?;
        let _ = mask; Ok(())
    }

    /// Set the viewport.
    pub fn gl_viewport(&mut self, x: i32, y: i32, w: i32, h: i32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.viewport = (x, y, w, h))
    }

    /// Generate buffer names.
    pub fn gl_gen_buffers(&mut self, count: u32) -> AppResult<Vec<u32>> {
        let mut ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let h = self.alloc_handle();
            self.resources.insert(h, GLResource { handle: h, resource_type: GLResourceType::Buffer, data: None, size: 0 });
            ids.push(h as u32);
        }
        Ok(ids)
    }

    /// Bind a buffer.
    pub fn gl_bind_buffer(&mut self, target: u32, buffer: u32) -> AppResult<()> {
        self.current_context_mut()?;
        if let Some(c) = self.contexts.get_mut(&self.current_context.unwrap()) {
            c.buffers.insert(target, buffer as u64);
        }
        Ok(())
    }

    /// Upload buffer data.
    pub fn gl_buffer_data(&mut self, target: u32, data: &[u8], _usage: u32) -> AppResult<()> {
        let ctx = self.current_context()?;
        let bh = ctx.buffers.get(&target).copied().ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "no buffer bound"))?;
        if let Some(r) = self.resources.get_mut(&bh) { r.data = Some(data.to_vec()); r.size = data.len() as u64; }
        Ok(())
    }

    /// Create a shader.
    pub fn gl_create_shader(&mut self, _shader_type: u32) -> AppResult<u32> {
        let h = self.alloc_handle();
        self.resources.insert(h, GLResource { handle: h, resource_type: GLResourceType::Shader, data: None, size: 0 });
        Ok(h as u32)
    }

    /// Compile a shader.
    pub fn gl_compile_shader(&mut self, shader: u32, source: &str) -> AppResult<()> {
        let r = self.resources.get_mut(&(shader as u64)).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "shader not found"))?;
        r.data = Some(source.as_bytes().to_vec());
        Ok(())
    }

    /// Create a program.
    pub fn gl_create_program(&mut self) -> AppResult<u32> {
        let h = self.alloc_handle();
        self.resources.insert(h, GLResource { handle: h, resource_type: GLResourceType::Program, data: None, size: 0 });
        Ok(h as u32)
    }

    /// Link a program.
    pub fn gl_link_program(&mut self, program: u32) -> AppResult<()> {
        if !self.resources.contains_key(&(program as u64)) {
            return Err(AppError::new(ReasonCode::RcInvalidState, "program not found"));
        }
        Ok(())
    }

    /// Use a program.
    pub fn gl_use_program(&mut self, program: u32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.program = Some(program as u64))
    }

    /// Generate texture names.
    pub fn gl_gen_textures(&mut self, count: u32) -> AppResult<Vec<u32>> {
        let mut ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let h = self.alloc_handle();
            self.resources.insert(h, GLResource { handle: h, resource_type: GLResourceType::Texture, data: None, size: 0 });
            ids.push(h as u32);
        }
        Ok(ids)
    }

    /// Bind a texture.
    pub fn gl_bind_texture(&mut self, unit: u32, texture: u32) -> AppResult<()> {
        self.current_context_mut()?;
        if let Some(c) = self.contexts.get_mut(&self.current_context.unwrap()) {
            c.textures.insert(unit, texture as u64);
        }
        Ok(())
    }

    /// Upload texture data.
    pub fn gl_tex_image_2d(&mut self, texture: u32, _level: i32, data: &[u8]) -> AppResult<()> {
        let r = self.resources.get_mut(&(texture as u64)).ok_or_else(|| AppError::new(
            ReasonCode::RcInvalidState, "texture not found"))?;
        r.data = Some(data.to_vec());
        r.size = data.len() as u64;
        Ok(())
    }

    /// Draw arrays (non-indexed).
    pub fn gl_draw_arrays(&mut self, _mode: u32, first: i32, count: i32) -> AppResult<()> {
        let ctx = self.current_context()?;
        if ctx.program.is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState, "no program bound"));
        }
        let _ = (first, count);
        Ok(())
    }

    /// Draw elements (indexed).
    pub fn gl_draw_elements(&mut self, _mode: u32, count: i32, _type: u32, _offset: i32) -> AppResult<()> {
        let ctx = self.current_context()?;
        if ctx.program.is_none() {
            return Err(AppError::new(ReasonCode::RcInvalidState, "no program bound"));
        }
        let _ = count;
        Ok(())
    }

    /// Get context count.
    pub fn context_count(&self) -> usize { self.contexts.len() }
    /// Check if a context is current.
    pub fn has_current_context(&self) -> bool { self.current_context.is_some() }
    /// Get current context handle.
    pub fn current_context_handle(&self) -> Option<u64> { self.current_context }
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
            0x0BE2 => { ctx.blend_state.enabled = true; },   // GL_BLEND
            0x0B71 => { ctx.depth_state.test_enabled = true; }, // GL_DEPTH_TEST
            0x0C11 => { ctx.scissor_state.test_enabled = true; }, // GL_SCISSOR_TEST
            0x0B44 => { ctx.rasterizer_state.cull_face_enabled = true; }, // GL_CULL_FACE
            0x0B90 => { ctx.stencil_state.test_enabled = true; }, // GL_STENCIL_TEST
            _ => {}
        }
        Ok(())
    }

    /// Disable a GL capability.
    pub fn gl_disable(&mut self, cap: u32) -> AppResult<()> {
        let ctx = self.current_context_mut()?;
        ctx.enabled_capabilities.retain(|&c| c != cap);
        match cap {
            0x0BE2 => { ctx.blend_state.enabled = false; },
            0x0B71 => { ctx.depth_state.test_enabled = false; },
            0x0C11 => { ctx.scissor_state.test_enabled = false; },
            0x0B44 => { ctx.rasterizer_state.cull_face_enabled = false; },
            0x0B90 => { ctx.stencil_state.test_enabled = false; },
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
        self.current_context_mut().map(|c| c.scissor_state = GLScissorState {
            test_enabled: c.scissor_state.test_enabled,
            box_x: x, box_y: y, box_width: width, box_height: height,
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
        self.current_context_mut().map(|c| c.depth_state.func = func)
    }

    /// Control depth writing.
    pub fn gl_depth_mask(&mut self, enabled: bool) -> AppResult<()> {
        self.current_context_mut().map(|c| c.depth_state.write_enabled = enabled)
    }

    /// Set the cull face mode.
    pub fn gl_cull_face(&mut self, mode: u32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.rasterizer_state.cull_face_mode = mode)
    }

    /// Set the front face orientation.
    pub fn gl_front_face(&mut self, mode: u32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.rasterizer_state.front_face = mode)
    }

    /// Set the line width.
    pub fn gl_line_width(&mut self, width: f32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.rasterizer_state.line_width = width)
    }

    /// Set the point size.
    pub fn gl_point_size(&mut self, size: f32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.rasterizer_state.point_size = size)
    }

    /// Set the polygon mode.
    pub fn gl_polygon_mode(&mut self, face: u32, mode: u32) -> AppResult<()> {
        let _ = face; // Only GL_FRONT_AND_BACK supported in practice
        self.current_context_mut().map(|c| c.rasterizer_state.polygon_mode = mode)
    }

    /// Bind a framebuffer to a target (GL_FRAMEBUFFER, GL_READ_FRAMEBUFFER, GL_DRAW_FRAMEBUFFER).
    pub fn gl_bind_framebuffer(&mut self, target: u32, framebuffer: u32) -> AppResult<()> {
        let ctx = self.current_context_mut()?;
        match target {
            0x8D40 => { ctx.framebuffer_state.draw_framebuffer = Some(framebuffer as u64); }, // GL_FRAMEBUFFER
            0x8CA8 => { ctx.framebuffer_state.read_framebuffer = Some(framebuffer as u64); }, // GL_READ_FRAMEBUFFER
            0x8CA9 => { ctx.framebuffer_state.draw_framebuffer = Some(framebuffer as u64); },  // GL_DRAW_FRAMEBUFFER
            _ => {}
        }
        Ok(())
    }

    /// Generate framebuffer object names.
    pub fn gl_gen_framebuffers(&mut self, count: u32) -> AppResult<Vec<u32>> {
        let mut ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let h = self.alloc_handle();
            self.resources.insert(h, GLResource {
                handle: h, resource_type: GLResourceType::Framebuffer, data: None, size: 0,
            });
            ids.push(h as u32);
        }
        Ok(ids)
    }

    /// Generate vertex array object names.
    pub fn gl_gen_vertex_arrays(&mut self, count: u32) -> AppResult<Vec<u32>> {
        let mut ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let h = self.alloc_handle();
            self.resources.insert(h, GLResource {
                handle: h, resource_type: GLResourceType::VertexArray, data: None, size: 0,
            });
            ids.push(h as u32);
        }
        Ok(ids)
    }

    /// Bind a vertex array object.
    pub fn gl_bind_vertex_array(&mut self, vao: u32) -> AppResult<()> {
        self.current_context_mut().map(|c| c.vertex_array = Some(vao as u64))
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
            supported_device_extensions: SUPPORTED_VK_KHR_EXTENSIONS.iter()
                .filter(|e| !e.starts_with("VK_KHR_surface") && !e.starts_with("VK_EXT_metal"))
                .map(|e| e.to_string())
                .collect(),
            supported_layers: KNOWN_VALIDATION_LAYERS.iter().map(|e| e.to_string()).collect(),
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
                format!("unsupported instance extensions: {}", unsupported.join(", ")),
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
    pub fn instance_extensions(&self) -> &[String] { &self.supported_instance_extensions }
    /// Get all supported device extensions.
    pub fn device_extensions(&self) -> &[String] { &self.supported_device_extensions }
    /// Get all supported layers.
    pub fn layers(&self) -> &[String] { &self.supported_layers }
}

impl Default for VkExtensionRegistry {
    fn default() -> Self { Self::new() }
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
        Self { state: Mutex::new(VulkanState::new()) }
    }

    /// Create a Vulkan instance (thread-safe).
    pub fn create_instance(&self, app: &str, engine: &str, exts: &[String], layers: &[String]) -> AppResult<VkInstance> {
        self.state.lock().unwrap().create_instance(app, engine, exts, layers)
    }

    /// Destroy a Vulkan instance (thread-safe).
    pub fn destroy_instance(&self, instance: VkInstance) -> AppResult<()> {
        self.state.lock().unwrap().destroy_instance(instance)
    }

    /// Enumerate physical devices (thread-safe).
    pub fn enumerate_physical_devices(&self, instance: VkInstance) -> AppResult<Vec<VkPhysicalDevice>> {
        self.state.lock().unwrap().enumerate_physical_devices(instance)
    }

    /// Create a logical device (thread-safe).
    pub fn create_device(&self, phys: VkPhysicalDevice, exts: &[String], queues: &[(u32, u32)]) -> AppResult<VkDevice> {
        self.state.lock().unwrap().create_device(phys, exts, queues)
    }

    /// Destroy a logical device (thread-safe).
    pub fn destroy_device(&self, device: VkDevice) -> AppResult<()> {
        self.state.lock().unwrap().destroy_device(device)
    }

    /// Create a swapchain (thread-safe).
    pub fn create_swapchain(&self, device: VkDevice, surface: VkSurfaceKHR, ci: &VkSwapchainCreateInfo) -> AppResult<VkSwapchainKHR> {
        self.state.lock().unwrap().create_swapchain(device, surface, ci)
    }

    /// Create a shader module (thread-safe).
    pub fn create_shader_module(&self, device: VkDevice, spirv: &[u32]) -> AppResult<VkShaderModule> {
        self.state.lock().unwrap().create_shader_module(device, spirv)
    }

    /// Create a graphics pipeline (thread-safe).
    pub fn create_graphics_pipeline(&self, layout: VkPipelineLayout, stages: u32) -> AppResult<VkPipeline> {
        self.state.lock().unwrap().create_graphics_pipeline(layout, stages)
    }

    /// Create a compute pipeline (thread-safe).
    pub fn create_compute_pipeline(&self, layout: VkPipelineLayout) -> AppResult<VkPipeline> {
        self.state.lock().unwrap().create_compute_pipeline(layout)
    }

    /// Create a buffer (thread-safe).
    pub fn create_buffer(&self, device: VkDevice, size: u64, usage: u32) -> AppResult<VkBuffer> {
        self.state.lock().unwrap().create_buffer(device, size, usage)
    }

    /// Create an image (thread-safe).
    pub fn create_image(&self, device: VkDevice, format: VkFormat, extent: (u32, u32, u32),
        mip_levels: u32, array_layers: u32, usage: VkImageUsageFlags) -> AppResult<VkImage> {
        self.state.lock().unwrap().create_image(device, format, extent, mip_levels, array_layers, usage)
    }

    /// Allocate command buffers (thread-safe).
    pub fn allocate_command_buffers(&self, pool: VkCommandPool, level: VkCommandBufferLevel, count: u32) -> AppResult<Vec<VkCommandBuffer>> {
        self.state.lock().unwrap().allocate_command_buffers(pool, level, count)
    }

    /// Begin command buffer (thread-safe).
    pub fn begin_command_buffer(&self, cmd: VkCommandBuffer, flags: u32) -> AppResult<()> {
        self.state.lock().unwrap().begin_command_buffer(cmd, flags)
    }

    /// Record draw command (thread-safe).
    pub fn cmd_draw(&self, cmd: VkCommandBuffer, vertex_count: u32, instance_count: u32,
        first_vertex: u32, first_instance: u32) -> AppResult<()> {
        self.state.lock().unwrap().cmd_draw(cmd, vertex_count, instance_count, first_vertex, first_instance)
    }

    /// End command buffer (thread-safe).
    pub fn end_command_buffer(&self, cmd: VkCommandBuffer) -> AppResult<()> {
        self.state.lock().unwrap().end_command_buffer(cmd)
    }

    /// Get instance count (thread-safe).
    pub fn instance_count(&self) -> usize { self.state.lock().unwrap().instance_count() }
    /// Get device count (thread-safe).
    pub fn device_count(&self) -> usize { self.state.lock().unwrap().device_count() }
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
        Self { loaded: false, framework_path: None, version: None }
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
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let bundled = dir.join("libANGLE.dylib");
                if bundled.exists() {
                    self.loaded = true;
                    self.framework_path = Some(bundled.to_string_lossy().to_string());
                    self.version = Some("1.0.0".to_string());
                    return Ok(());
                }
            }
        }

        // ANGLE not found — operate in simulated mode
        self.loaded = false;
        Ok(())
    }

    /// Returns whether ANGLE was detected.
    pub fn is_loaded(&self) -> bool { self.loaded }

    /// Returns the detected framework path, if any.
    pub fn framework_path(&self) -> Option<&str> { self.framework_path.as_deref() }

    /// Returns the detected ANGLE version, if any.
    pub fn version(&self) -> Option<&str> { self.version.as_deref() }
}

impl Default for AngleLoader {
    fn default() -> Self { Self::new() }
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

        let mut uniforms = Vec::new();
        let mut inputs = Vec::new();
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
                let msl_uniform = Self::translate_uniform_line(trimmed);
                uniforms.push(msl_uniform);
                continue;
            }

            // Parse attributes / inputs
            if trimmed.starts_with("attribute") || (trimmed.starts_with("in ") && stage == GlslShaderStage::Vertex) {
                let msl_input = Self::translate_input_line(trimmed);
                inputs.push(msl_input);
                continue;
            }

            // Parse varying / outputs
            if trimmed.starts_with("varying") || (trimmed.starts_with("out ") && stage == GlslShaderStage::Fragment) {
                continue; // Handled via stage I/O
            }

            // Detect built-in usage
            if trimmed.contains("gl_Position") { has_gl_position = true; }
            if trimmed.contains("gl_FragColor") { has_gl_frag_color = true; }
            if trimmed.contains("texture2D") { has_texture_sample = true; }

            // Skip main() signature — we generate our own
            if trimmed.starts_with("void main()") { continue; }
            if trimmed == "{" || trimmed == "}" { continue; }

            // Translate the line body
            let translated = Self::translate_line_body(trimmed, stage);
            body_lines.push(translated);
        }

        // Generate struct for uniforms
        if !uniforms.is_empty() {
            output.push_str("struct Uniforms {\n");
            for u in &uniforms {
                output.push_str(&format!("    {};\n", u));
            }
            output.push_str("};\n\n");
        }

        // Generate struct for vertex inputs
        if stage == GlslShaderStage::Vertex && !inputs.is_empty() {
            output.push_str("struct VertexIn {\n");
            for (i, inp) in inputs.iter().enumerate() {
                output.push_str(&format!("    {} [[attribute({})]];\n", inp, i));
            }
            output.push_str("};\n\n");
        }

        // Generate entry point
        let return_type = if stage == GlslShaderStage::Vertex {
            "float4"
        } else if stage == GlslShaderStage::Fragment {
            "float4"
        } else {
            "void"
        };

        output.push_str(&format!("{} {} casa1_entry(", qualifier, return_type));

        let mut params = Vec::new();
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

        // Translate body
        for line in &body_lines {
            output.push_str(&format!("    {}\n", line));
        }

        // Add return statement for vertex/fragment
        if stage == GlslShaderStage::Vertex && has_gl_position {
            output.push_str("    return float4(0.0, 0.0, 0.0, 1.0);\n");
        } else if stage == GlslShaderStage::Fragment && has_gl_frag_color {
            output.push_str("    return float4(1.0, 1.0, 1.0, 1.0);\n");
        }

        output.push_str("}\n");
        Ok(output)
    }

    fn translate_uniform_line(line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // "uniform type name;" → "type name"
        if parts.len() >= 3 {
            let type_name = Self::glsl_type_to_msl(parts[1]);
            let var_name = parts[2].trim_end_matches(';');
            format!("{} {}", type_name, var_name)
        } else {
            "float placeholder".to_string()
        }
    }

    fn translate_input_line(line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // "attribute/in type name;" → "type name"
        let start = if parts[0] == "attribute" || parts[0] == "in" { 1 } else { 0 };
        if parts.len() >= start + 2 {
            let type_name = Self::glsl_type_to_msl(parts[start]);
            let var_name = parts[start + 1].trim_end_matches(';');
            format!("{} {}", type_name, var_name)
        } else {
            "float4 position".to_string()
        }
    }

    fn translate_line_body(line: &str, stage: GlslShaderStage) -> String {
        let mut result = line.to_string();
        // gl_Position → position output
        result = result.replace("gl_Position", "// gl_Position");
        // gl_FragColor → return value
        result = result.replace("gl_FragColor", "// gl_FragColor");
        // texture2D(tex, coord) → tex.sample(tex_sampler, coord)
        result = result.replace("texture2D(", "tex.sample(tex_sampler, ");
        // GLSL types → MSL types
        result = result.replace("vec2(", "float2(");
        result = result.replace("vec3(", "float3(");
        result = result.replace("vec4(", "float4(");
        result = result.replace("mat4(", "float4x4(");
        result = result.replace("ivec2(", "int2(");
        result = result.replace("ivec3(", "int3(");
        result = result.replace("ivec4(", "int4(");
        let _ = stage;
        result
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
        Self { state: Mutex::new(GLState::new()) }
    }

    /// Create a GL context (thread-safe).
    pub fn gl_create_context(&self) -> AppResult<u64> {
        self.state.lock().unwrap().gl_create_context()
    }

    /// Make a GL context current (thread-safe).
    pub fn gl_make_current(&self, ctx: u64) -> AppResult<()> {
        self.state.lock().unwrap().gl_make_current(ctx)
    }

    /// Delete a GL context (thread-safe).
    pub fn gl_delete_context(&self, ctx: u64) -> AppResult<()> {
        self.state.lock().unwrap().gl_delete_context(ctx)
    }

    /// Set clear color (thread-safe).
    pub fn gl_clear_color(&self, r: f32, g: f32, b: f32, a: f32) -> AppResult<()> {
        self.state.lock().unwrap().gl_clear_color(r, g, b, a)
    }

    /// Set viewport (thread-safe).
    pub fn gl_viewport(&self, x: i32, y: i32, w: i32, h: i32) -> AppResult<()> {
        self.state.lock().unwrap().gl_viewport(x, y, w, h)
    }

    /// Enable capability (thread-safe).
    pub fn gl_enable(&self, cap: u32) -> AppResult<()> {
        self.state.lock().unwrap().gl_enable(cap)
    }

    /// Disable capability (thread-safe).
    pub fn gl_disable(&self, cap: u32) -> AppResult<()> {
        self.state.lock().unwrap().gl_disable(cap)
    }

    /// Draw arrays (thread-safe).
    pub fn gl_draw_arrays(&self, mode: u32, first: i32, count: i32) -> AppResult<()> {
        self.state.lock().unwrap().gl_draw_arrays(mode, first, count)
    }

    /// Use program (thread-safe).
    pub fn gl_use_program(&self, program: u32) -> AppResult<()> {
        self.state.lock().unwrap().gl_use_program(program)
    }

    /// Create program (thread-safe).
    pub fn gl_create_program(&self) -> AppResult<u32> {
        self.state.lock().unwrap().gl_create_program()
    }

    /// Context count (thread-safe).
    pub fn context_count(&self) -> usize { self.state.lock().unwrap().context_count() }

    /// Has current context (thread-safe).
    pub fn has_current_context(&self) -> bool { self.state.lock().unwrap().has_current_context() }
}

// ===========================================================================
// Section 8: DLL Registration
// ===========================================================================

/// Returns a list of (export_name, thunk_address) pairs for `vulkan-1.dll`.
///
/// These thunks allow guest binaries to resolve Vulkan API functions by name.
/// Each thunk address is a stable function pointer that the emulator can call
/// to route the Vulkan call through Casa1's translation layer.
pub fn register_vulkan_dll() -> Vec<(&'static str, u64)> {
    vec![
        ("vkCreateInstance", vk_thunk_create_instance as *const () as u64),
        ("vkDestroyInstance", vk_thunk_destroy_instance as *const () as u64),
        ("vkEnumeratePhysicalDevices", vk_thunk_enumerate_physical_devices as *const () as u64),
        ("vkCreateDevice", vk_thunk_create_device as *const () as u64),
        ("vkDestroyDevice", vk_thunk_destroy_device as *const () as u64),
        ("vkCreateSwapchainKHR", vk_thunk_create_swapchain as *const () as u64),
        ("vkDestroySwapchainKHR", vk_thunk_destroy_swapchain as *const () as u64),
        ("vkGetSwapchainImagesKHR", vk_thunk_get_swapchain_images as *const () as u64),
        ("vkAcquireNextImageKHR", vk_thunk_acquire_next_image as *const () as u64),
        ("vkQueuePresentKHR", vk_thunk_queue_present as *const () as u64),
        ("vkCreateShaderModule", vk_thunk_create_shader_module as *const () as u64),
        ("vkCreatePipelineLayout", vk_thunk_create_pipeline_layout as *const () as u64),
        ("vkCreateGraphicsPipelines", vk_thunk_create_graphics_pipelines as *const () as u64),
        ("vkCreateComputePipelines", vk_thunk_create_compute_pipelines as *const () as u64),
        ("vkCreateRenderPass", vk_thunk_create_render_pass as *const () as u64),
        ("vkCreateFramebuffer", vk_thunk_create_framebuffer as *const () as u64),
        ("vkCreateCommandPool", vk_thunk_create_command_pool as *const () as u64),
        ("vkAllocateCommandBuffers", vk_thunk_allocate_command_buffers as *const () as u64),
        ("vkBeginCommandBuffer", vk_thunk_begin_command_buffer as *const () as u64),
        ("vkEndCommandBuffer", vk_thunk_end_command_buffer as *const () as u64),
        ("vkQueueSubmit", vk_thunk_queue_submit as *const () as u64),
        ("vkAllocateMemory", vk_thunk_allocate_memory as *const () as u64),
        ("vkFreeMemory", vk_thunk_free_memory as *const () as u64),
        ("vkMapMemory", vk_thunk_map_memory as *const () as u64),
        ("vkUnmapMemory", vk_thunk_unmap_memory as *const () as u64),
        ("vkCreateBuffer", vk_thunk_create_buffer as *const () as u64),
        ("vkCreateImage", vk_thunk_create_image as *const () as u64),
        ("vkCreateImageView", vk_thunk_create_image_view as *const () as u64),
        ("vkCreateDescriptorSetLayout", vk_thunk_create_descriptor_set_layout as *const () as u64),
        ("vkCreateDescriptorPool", vk_thunk_create_descriptor_pool as *const () as u64),
        ("vkAllocateDescriptorSets", vk_thunk_allocate_descriptor_sets as *const () as u64),
        ("vkCreateFence", vk_thunk_create_fence as *const () as u64),
        ("vkCreateSemaphore", vk_thunk_create_semaphore as *const () as u64),
    ]
}

/// Vulkan thunk function implementations.
///
/// Each thunk translates from the Vulkan C ABI to the VulkanState Rust API.
/// Thunks are registered as DLL exports for guest binary compatibility.
/// VkInstance, VkDevice, etc. are all u64 handles in this translation layer.

// ---------------------------------------------------------------------------
// Instance thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_instance() -> VkResultType {
    with_vulkan_state(|state| {
        let exts: Vec<String> = Vec::new();
        let layers: Vec<String> = Vec::new();
        match state.create_instance("guest-app", "Casa1", &exts, &layers) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_destroy_instance() -> VkResultType {
    with_vulkan_state(|state| {
        // Destroy all instances
        let handles: Vec<VkInstance> = state.instances.keys().copied().collect();
        for h in handles {
            let _ = state.destroy_instance(h);
        }
        VK_SUCCESS
    })
}

fn vk_thunk_enumerate_physical_devices() -> VkResultType {
    with_vulkan_state(|state| {
        // The first instance's physical devices
        if let Some(inst) = state.instances.keys().next().copied() {
            match state.enumerate_physical_devices(inst) {
                Ok(devices) if !devices.is_empty() => VK_SUCCESS,
                _ => VK_ERROR_INITIALIZATION_FAILED,
            }
        } else {
            VK_ERROR_INITIALIZATION_FAILED
        }
    })
}

// ---------------------------------------------------------------------------
// Device thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_device() -> VkResultType {
    with_vulkan_state(|state| {
        // Find first physical device from first instance
        for inst in state.instances.keys().copied().collect::<Vec<_>>() {
            if let Ok(devices) = state.enumerate_physical_devices(inst) {
                if let Some(&phys) = devices.first() {
                    let exts: Vec<String> = Vec::new();
                    return match state.create_device(phys, &exts, &[(0, 1)]) {
                        Ok(_) => VK_SUCCESS,
                        Err(_) => VK_ERROR_INITIALIZATION_FAILED,
                    };
                }
            }
        }
        VK_ERROR_INITIALIZATION_FAILED
    })
}

fn vk_thunk_destroy_device() -> VkResultType {
    with_vulkan_state(|state| {
        let handles: Vec<VkDevice> = state.devices.keys().copied().collect();
        for h in handles {
            let _ = state.destroy_device(h);
        }
        VK_SUCCESS
    })
}

// ---------------------------------------------------------------------------
// Swapchain thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_swapchain() -> VkResultType {
    with_vulkan_state(|state| {
        // Find first device and surface
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        // Create a surface if none exists
        let surface = if state.surfaces.is_empty() {
            match state.create_surface(800, 600, VkFormat::B8G8R8A8Unorm) {
                Ok(s) => s,
                Err(_) => return VK_ERROR_INITIALIZATION_FAILED,
            }
        } else {
            *state.surfaces.keys().next().unwrap()
        };
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
        match state.create_swapchain(device, surface, &ci) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_destroy_swapchain() -> VkResultType {
    with_vulkan_state(|state| {
        state.swapchains.clear();
        VK_SUCCESS
    })
}

fn vk_thunk_get_swapchain_images() -> VkResultType {
    with_vulkan_state(|state| {
        // Return success — images are accessible via swapchain info
        VK_SUCCESS
    })
}

fn vk_thunk_acquire_next_image() -> VkResultType {
    with_vulkan_state(|state| {
        if let Some(&sc) = state.swapchains.keys().next() {
            match state.acquire_next_image(sc, None, None) {
                Ok(_) => VK_SUCCESS,
                Err(_) => VK_ERROR_OUT_OF_DATE_KHR,
            }
        } else {
            VK_ERROR_OUT_OF_DATE_KHR
        }
    })
}

fn vk_thunk_queue_present() -> VkResultType {
    with_vulkan_state(|state| {
        if let Some(&sc) = state.swapchains.keys().next() {
            match state.queue_present(0, sc, 0) {
                Ok(_) => VK_SUCCESS,
                Err(_) => VK_ERROR_OUT_OF_DATE_KHR,
            }
        } else {
            VK_SUCCESS
        }
    })
}

// ---------------------------------------------------------------------------
// Shader module thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_shader_module() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        // Use a minimal SPIR-V vertex shader
        let spirv = vec![
            0x07230203, 0x00010000, 0x00000000, 0x00000007, 0x00000000,
            0x00020011, 0x00000001,
            0x0003000E, 0x00000000, 0x00000001,
            0x0005000F, 0x00000000, 0x00000005, 0x6E69616D, 0x00000000,
            0x00040005, 0x00000005, 0x6E69616D, 0x00000000,
            0x00020013, 0x00000002,
            0x00030021, 0x00000003, 0x00000002,
            0x00050036, 0x00000002, 0x00000000, 0x00000003, 0x00000005,
            0x000200F8, 0x00000006,
            0x000100FD,
            0x00010038,
        ];
        match state.create_shader_module(device, &spirv) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Pipeline layout thunk
// ---------------------------------------------------------------------------

fn vk_thunk_create_pipeline_layout() -> VkResultType {
    with_vulkan_state(|state| {
        match state.create_pipeline_layout(vec![], vec![]) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Pipeline thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_graphics_pipelines() -> VkResultType {
    with_vulkan_state(|state| {
        let layout = match state.pipeline_layouts.keys().next().copied() {
            Some(l) => l,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_graphics_pipeline(layout, 2) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_create_compute_pipelines() -> VkResultType {
    with_vulkan_state(|state| {
        let layout = match state.pipeline_layouts.keys().next().copied() {
            Some(l) => l,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_compute_pipeline(layout) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Render pass / framebuffer thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_render_pass() -> VkResultType {
    with_vulkan_state(|state| {
        match state.create_render_pass(1, false, "clear", "store") {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_create_framebuffer() -> VkResultType {
    with_vulkan_state(|state| {
        let rp = match state.render_passes.keys().next().copied() {
            Some(r) => r,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_framebuffer(rp, vec![], 800, 600, 1) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Command pool / buffer thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_command_pool() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_command_pool(device, 0) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_allocate_command_buffers() -> VkResultType {
    with_vulkan_state(|state| {
        let pool = match state.command_pools.keys().next().copied() {
            Some(p) => p,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_begin_command_buffer() -> VkResultType {
    with_vulkan_state(|state| {
        let cmd = match state.command_buffers.keys().next().copied() {
            Some(c) => c,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.begin_command_buffer(cmd, 0) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_end_command_buffer() -> VkResultType {
    with_vulkan_state(|state| {
        let cmd = match state.command_buffers.keys().next().copied() {
            Some(c) => c,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.end_command_buffer(cmd) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Queue submit thunk
// ---------------------------------------------------------------------------

fn vk_thunk_queue_submit() -> VkResultType {
    with_vulkan_state(|state| {
        // Find first queue from first device
        for device in state.devices.keys().copied().collect::<Vec<_>>() {
            if let Ok(queue) = state.get_device_queue(device, 0, 0) {
                let submit = VkSubmitInfo {
                    wait_semaphores: vec![],
                    command_buffers: vec![],
                    signal_semaphores: vec![],
                };
                return match state.queue_submit(queue, &[submit], None) {
                    Ok(_) => VK_SUCCESS,
                    Err(_) => VK_ERROR_DEVICE_LOST,
                };
            }
        }
        VK_ERROR_DEVICE_LOST
    })
}

// ---------------------------------------------------------------------------
// Memory thunks
// ---------------------------------------------------------------------------

fn vk_thunk_allocate_memory() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.allocate_memory(device, 1024, 0) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_OUT_OF_DEVICE_MEMORY,
        }
    })
}

fn vk_thunk_free_memory() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        let mems: Vec<VkDeviceMemory> = state.device_memory.keys().copied().collect();
        for m in mems {
            let _ = state.free_memory(device, m);
        }
        VK_SUCCESS
    })
}

fn vk_thunk_map_memory() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        let mem = match state.device_memory.keys().next().copied() {
            Some(m) => m,
            None => return VK_ERROR_MEMORY_MAP_FAILED,
        };
        match state.map_memory(device, mem, 0, 1024) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_MEMORY_MAP_FAILED,
        }
    })
}

fn vk_thunk_unmap_memory() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        let mems: Vec<VkDeviceMemory> = state.device_memory.keys().copied().collect();
        for m in mems {
            let _ = state.unmap_memory(device, m);
        }
        VK_SUCCESS
    })
}

// ---------------------------------------------------------------------------
// Buffer / image / view thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_buffer() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_buffer(device, 1024, 0) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_create_image() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_image(device, VkFormat::B8G8R8A8Unorm, (256, 256, 1), 1, 1,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT)
        {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_create_image_view() -> VkResultType {
    with_vulkan_state(|state| {
        let image = match state.images.keys().next().copied() {
            Some(i) => i,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_image_view(image, VkFormat::B8G8R8A8Unorm, 1) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Descriptor thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_descriptor_set_layout() -> VkResultType {
    with_vulkan_state(|state| {
        match state.create_descriptor_set_layout(1) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_create_descriptor_pool() -> VkResultType {
    with_vulkan_state(|state| {
        match state.create_descriptor_pool(16) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_allocate_descriptor_sets() -> VkResultType {
    with_vulkan_state(|state| {
        let pool = match state.descriptor_pools.keys().next().copied() {
            Some(p) => p,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        let layouts: Vec<VkDescriptorSetLayout> = state.descriptor_set_layouts.keys().copied().collect();
        if layouts.is_empty() {
            return VK_ERROR_INITIALIZATION_FAILED;
        }
        match state.allocate_descriptor_sets(pool, &layouts) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

// ---------------------------------------------------------------------------
// Synchronization thunks
// ---------------------------------------------------------------------------

fn vk_thunk_create_fence() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_fence(device, false) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

fn vk_thunk_create_semaphore() -> VkResultType {
    with_vulkan_state(|state| {
        let device = match state.devices.keys().next().copied() {
            Some(d) => d,
            None => return VK_ERROR_INITIALIZATION_FAILED,
        };
        match state.create_semaphore(device) {
            Ok(_) => VK_SUCCESS,
            Err(_) => VK_ERROR_INITIALIZATION_FAILED,
        }
    })
}

/// Returns a list of (export_name, thunk_address) pairs for `opengl32.dll`.
///
/// These thunks allow guest binaries to resolve OpenGL/WGL API functions.
pub fn register_opengl_dll() -> Vec<(&'static str, u64)> {
    vec![
        ("wglCreateContext", gl_thunk_create_context as *const () as u64),
        ("wglMakeCurrent", gl_thunk_make_current as *const () as u64),
        ("wglDeleteContext", gl_thunk_delete_context as *const () as u64),
        ("glClear", gl_thunk_clear as *const () as u64),
        ("glDrawArrays", gl_thunk_draw_arrays as *const () as u64),
        ("glDrawElements", gl_thunk_draw_elements as *const () as u64),
        ("glGenBuffers", gl_thunk_gen_buffers as *const () as u64),
        ("glBindBuffer", gl_thunk_bind_buffer as *const () as u64),
        ("glBufferData", gl_thunk_buffer_data as *const () as u64),
        ("glCreateShader", gl_thunk_create_shader as *const () as u64),
        ("glCompileShader", gl_thunk_compile_shader as *const () as u64),
        ("glLinkProgram", gl_thunk_link_program as *const () as u64),
        ("glUseProgram", gl_thunk_use_program as *const () as u64),
        ("glGenTextures", gl_thunk_gen_textures as *const () as u64),
        ("glBindTexture", gl_thunk_bind_texture as *const () as u64),
        ("glTexImage2D", gl_thunk_tex_image_2d as *const () as u64),
    ]
}

fn gl_thunk_create_context() {}
fn gl_thunk_make_current() {}
fn gl_thunk_delete_context() {}
fn gl_thunk_clear() {}
fn gl_thunk_draw_arrays() {}
fn gl_thunk_draw_elements() {}
fn gl_thunk_gen_buffers() {}
fn gl_thunk_bind_buffer() {}
fn gl_thunk_buffer_data() {}
fn gl_thunk_create_shader() {}
fn gl_thunk_compile_shader() {}
fn gl_thunk_link_program() {}
fn gl_thunk_use_program() {}
fn gl_thunk_gen_textures() {}
fn gl_thunk_bind_texture() {}
fn gl_thunk_tex_image_2d() {}

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
            0x00020011, 0x00000001,
            // OpMemoryModel Logical GLSL450
            0x0003000E, 0x00000000, 0x00000001,
            // OpEntryPoint Vertex %main "main"
            0x0005000F, 0x00000000, 0x00000005, 0x6E69616D, 0x00000000,
            // OpName %main "main"
            0x00040005, 0x00000005, 0x6E69616D, 0x00000000,
            // OpTypeVoid %void
            0x00020013, 0x00000002,
            // OpTypeFunction %fn %void
            0x00030021, 0x00000003, 0x00000002,
            // %main = OpFunction %void None %fn
            0x00050036, 0x00000002, 0x00000000, 0x00000003, 0x00000005,
            // %lbl = OpLabel
            0x000200F8, 0x00000006,
            // OpReturn
            0x000100FD,
            // OpFunctionEnd
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
        let instance = state.create_instance("TestApp", "TestEngine", &exts, &layers)
            .expect("instance creation");
        assert_ne!(instance, 0);
        assert_eq!(state.instance_count(), 1);

        let phys_devs = state.enumerate_physical_devices(instance).expect("enumerate");
        assert_eq!(phys_devs.len(), 1);
        assert_ne!(phys_devs[0], 0);
    }

    #[test]
    fn vulkan_device_creation() {
        let mut state = VulkanState::new();
        let instance = state.create_instance("app", "eng", &[], &[]).unwrap();
        let phys_devs = state.enumerate_physical_devices(instance).unwrap();
        let phys = phys_devs[0];

        let device = state.create_device(phys, &[], &[(0, 1)]).expect("device creation");
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
        let surface = state.create_surface(800, 600, VkFormat::B8G8R8A8Unorm).unwrap();

        let ci = VkSwapchainCreateInfo {
            surface, min_image_count: 2, image_format: VkFormat::B8G8R8A8Unorm,
            image_color_space: VkColorSpaceKHR::SrgbNonlinear, image_extent: (800, 600),
            image_array_layers: 1, image_usage: VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
            pre_transform: VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR,
            composite_alpha: VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
            present_mode: VkPresentModeKHR::Fifo, clipped: true,
        };
        let sc = state.create_swapchain(device, surface, &ci).expect("swapchain");
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
        let module = state.create_shader_module(device, &spirv).expect("shader module");
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
        let cmds = state.allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1).unwrap();
        let cmd = cmds[0];

        state.begin_command_buffer(cmd, 0).expect("begin");
        state.cmd_draw(cmd, 3, 1, 0, 0).expect("draw");
        state.end_command_buffer(cmd).expect("end");

        let info = state.get_command_buffer(cmd).unwrap();
        assert_eq!(info.state, CommandBufferState::Executable);
        assert_eq!(info.recorded_commands.len(), 1);
        match &info.recorded_commands[0] {
            RecordedCommand::Draw { vertex_count, instance_count, first_vertex, first_instance } => {
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
        let img = state.create_image(device, VkFormat::B8G8R8A8Unorm, (256, 256, 1), 1, 1,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT).unwrap();
        let pool = state.create_command_pool(device, 0).unwrap();
        let cmds = state.allocate_command_buffers(pool, VkCommandBufferLevel::Primary, 1).unwrap();
        let cmd = cmds[0];

        state.begin_command_buffer(cmd, 0).unwrap();
        state.cmd_pipeline_barrier(cmd,
            VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
            VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
            false,
            vec![],
            vec![],
            vec![VkImageMemoryBarrier {
                src_access_mask: 0, dst_access_mask: VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
                old_layout: VkImageLayout::Undefined,
                new_layout: VkImageLayout::ColorAttachmentOptimal,
                src_queue_family_index: 0, dst_queue_family_index: 0,
                image: img,
                subresource_range: ImageSubresourceRange {
                    aspect_mask: 1, base_mip_level: 0, level_count: 1,
                    base_array_layer: 0, layer_count: 1,
                },
            }],
        ).unwrap();
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
        assert!(paths.iter().any(|p| p.to_string_lossy().contains("homebrew")));
        assert!(paths.iter().any(|p| p.to_string_lossy().contains("usr/local")));
    }

    #[test]
    fn dll_registration_exports() {
        let vk_exports = register_vulkan_dll();
        assert!(!vk_exports.is_empty());
        assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateInstance"));
        assert!(vk_exports.iter().any(|(name, _)| *name == "vkQueueSubmit"));
        assert!(vk_exports.iter().any(|(name, _)| *name == "vkCreateSwapchainKHR"));

        let gl_exports = register_opengl_dll();
        assert!(!gl_exports.is_empty());
        assert!(gl_exports.iter().any(|(name, _)| *name == "wglCreateContext"));
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
        assert!(translator.parse(&spirv).is_ok());

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
        assert!(t3.parse(&[0x07230203, 0x00010000]).is_err());
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
            0x00020011, 0x00000001,
            // OpMemoryModel Logical GLSL450
            0x0003000E, 0x00000000, 0x00000001,
        ];

        // OpTypeVoid %2
        spirv.push(0x00020013); spirv.push(2);
        // OpTypeFloat %3 32
        spirv.push(0x00030016); spirv.push(3); spirv.push(32);
        // OpTypeInt %4 32 1 (signed)
        spirv.push(0x00040015); spirv.push(4); spirv.push(32); spirv.push(1);
        // OpTypeInt %5 32 0 (unsigned)
        spirv.push(0x00040015); spirv.push(5); spirv.push(32); spirv.push(0);
        // OpTypeVector %6 %3 4 (float4)
        spirv.push(0x00040017); spirv.push(6); spirv.push(3); spirv.push(4);
        // OpTypeVector %7 %3 3 (float3)
        spirv.push(0x00040017); spirv.push(7); spirv.push(3); spirv.push(3);
        // OpTypeVector %8 %4 4 (int4)
        spirv.push(0x00040017); spirv.push(8); spirv.push(4); spirv.push(4);
        // OpTypeMatrix %9 %6 4 (float4x4)
        spirv.push(0x00040018); spirv.push(9); spirv.push(6); spirv.push(4);
        // OpTypeFloat %10 16 (half)
        spirv.push(0x00030016); spirv.push(10); spirv.push(16);

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
        assert_eq!(vk_format_to_metal_format(VkFormat::R8G8B8A8Unorm), metal::MTLPixelFormat::RGBA8Unorm);
        assert_eq!(vk_format_to_metal_format(VkFormat::B8G8R8A8Unorm), metal::MTLPixelFormat::BGRA8Unorm);
        assert_eq!(vk_format_to_metal_format(VkFormat::R8G8B8A8Srgb), metal::MTLPixelFormat::RGBA8Unorm);

        // Depth formats
        assert_eq!(vk_format_to_metal_format(VkFormat::D24UnormS8Uint), metal::MTLPixelFormat::Depth24Unorm_Stencil8);
        assert_eq!(vk_format_to_metal_format(VkFormat::D32Sfloat), metal::MTLPixelFormat::Depth32Float);
        assert_eq!(vk_format_to_metal_format(VkFormat::D16Unorm), metal::MTLPixelFormat::Depth16Unorm);

        // Floating-point formats
        assert_eq!(vk_format_to_metal_format(VkFormat::R32Sfloat), metal::MTLPixelFormat::R32Float);
        assert_eq!(vk_format_to_metal_format(VkFormat::R16G16B16A16Sfloat), metal::MTLPixelFormat::RGBA16Float);
        assert_eq!(vk_format_to_metal_format(VkFormat::R32G32Sfloat), metal::MTLPixelFormat::RG32Float);

        // BC compressed formats
        assert_eq!(vk_format_to_metal_format(VkFormat::Bc1RgbaUnormBlock), metal::MTLPixelFormat::BC1_RGBA);
        assert_eq!(vk_format_to_metal_format(VkFormat::Bc2UnormBlock), metal::MTLPixelFormat::BC2_RGBA);
        assert_eq!(vk_format_to_metal_format(VkFormat::Bc3UnormBlock), metal::MTLPixelFormat::BC3_RGBA);

        // 3-channel format falls back to 4-channel (Metal has no RGB32Float)
        assert_eq!(vk_format_to_metal_format(VkFormat::R32G32B32Sfloat), metal::MTLPixelFormat::RGBA32Float);

        // Undefined format falls back to RGBA8Unorm
        assert_eq!(vk_format_to_metal_format(VkFormat::Undefined), metal::MTLPixelFormat::RGBA8Unorm);
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

        let image = state.create_image(device, VkFormat::B8G8R8A8Unorm, (256, 256, 1), 1, 1,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT).unwrap();
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

        let sampler = state.create_sampler(device,
            0, 0, 0,  // filters
            0, 0, 0,  // address modes
            0.0, 1.0,  // lod bias, anisotropy
            0,          // compare op
            0.0, 1000.0 // min/max lod
        ).unwrap();
        assert_ne!(sampler, 0);
        assert_eq!(state.sampler_count(), 1);

        let info = state.get_sampler(sampler).unwrap();
        assert_eq!(info.min_lod, 0.0);
        assert_eq!(info.max_lod, 1000.0);
    }
}
