use crate::error::{AppError, AppResult};
use crate::gfx::FrameArtifact;
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};

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