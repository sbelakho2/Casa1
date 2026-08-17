//! D3D10 API support via D3D11 translation layer.
//!
//! D3D10 and D3D11 share the same hardware feature level and driver model.
//! Rather than implementing D3D10 from scratch, this module translates D3D10
//! API calls into their D3D11 equivalents. The D3D11 implementation in
//! [`crate::d3d11`] handles the actual Metal translation.
//!
//! Key mapping:
//! - ID3D10Device  → ID3D11Device  (D3D10 device wraps D3D11 device)
//! - ID3D10DeviceContext (immediate) → ID3D11DeviceContext
//! - ID3D10Texture2D / ID3D10Buffer → D3D11 equivalents
//! - ID3D10RenderTargetView / ID3D10DepthStencilView → D3D11 equivalents
//! - ID3D10*Shader → ID3D11*Shader (same shader bytecode format)
//! - State objects (blend, rasterizer, DS, sampler) → same descs as D3D11
//! - Input layout → same desc as D3D11

use crate::d3d11::{
    self, BlendStateDesc, BlendStateId, D3d11Device, D3d11ResourceId, D3d11ViewId,
    DepthStencilStateDesc, DepthStencilStateId, DeviceCreationRequest, FeatureLevel,
    InputLayoutDesc, InputLayoutId, RasterizerStateDesc, RasterizerStateId, SamplerStateDesc,
    SamplerStateId, ScissorRect, ShaderId, ShaderModuleDesc, ShaderStage, Viewport,
};
use crate::error::{AppError, AppResult};
use crate::gfx::{DxgiFormat, ResourceUsageHint, SwapchainDesc};
use crate::reason::ReasonCode;

// ---------------------------------------------------------------------------
// D3D10 DXBC shader bytecode parsing
// ---------------------------------------------------------------------------

/// Magic bytes for DXBC containers.
const DXBC_MAGIC: &[u8; 4] = b"DXBC";
/// Magic bytes for DXIL containers (D3D11 shader model 5.0+).
const DXIL_MAGIC: &[u8; 4] = b"DXIL";

/// Shader program type values from the version token in SHDR/SHEX chunks.
const D3D10_PROGRAM_TYPE_VS: u32 = 0; // Vertex shader
const D3D10_PROGRAM_TYPE_PS: u32 = 1; // Pixel shader
const D3D10_PROGRAM_TYPE_GS: u32 = 2; // Geometry shader

/// Parse a D3D10/D3D11 DXBC container to extract the shader stage and entry
/// point name. Returns `(ShaderStage, entry_point_name)`.
///
/// The DXBC container format is:
///   [0..4)  magic         "DXBC"
///   [4..8)  version       u32 (typically 1)
///   [8..12) total_size    u32
///   [12..16) chunk_count  u32
///   [16..)  chunk descriptors (12 bytes each: 4 byte fourCC, 4 byte offset, 4 byte size)
///
/// DXIL containers (D3D11 shader model 5.0+) are rejected: they have no
/// DXBC chunk descriptor table, and D3D10 only supports DXBC shader model
/// 4.x bytecode.
fn parse_dxbc_bytecode(bytecode: &[u8]) -> AppResult<(ShaderStage, String)> {
    if bytecode.len() < 16 {
        return Err(AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            "D3D10: shader bytecode too small for DXBC header",
        ));
    }
    let magic = &bytecode[..4];
    if magic == DXIL_MAGIC {
        return Err(AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            "D3D10: DXIL (shader model 5.0+) bytecode is not supported; D3D10 requires DXBC shader model 4.x",
        ));
    }
    if magic != DXBC_MAGIC {
        return Err(AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            format!(
                "D3D10: invalid shader bytecode magic (expected DXBC, got {:02x?})",
                magic
            ),
        ));
    }
    let chunk_count = u32::from_le_bytes(bytecode[12..16].try_into().unwrap()) as usize;
    if chunk_count == 0 || chunk_count > 32 {
        return Err(AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            "D3D10: invalid chunk count in shader bytecode",
        ));
    }
    // Scan chunk descriptors for SHDR or SHEX
    let mut stage: Option<ShaderStage> = None;
    for i in 0..chunk_count {
        let desc_offset = 16 + i * 12;
        if desc_offset + 12 > bytecode.len() {
            break;
        }
        let four_cc = &bytecode[desc_offset..desc_offset + 4];
        // SHDR = shader model 4.0, SHEX = shader model 4.1+
        if four_cc == b"SHDR" || four_cc == b"SHEX" {
            let chunk_off = u32::from_le_bytes(
                bytecode[desc_offset + 4..desc_offset + 8]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let chunk_sz = u32::from_le_bytes(
                bytecode[desc_offset + 8..desc_offset + 12]
                    .try_into()
                    .unwrap(),
            ) as usize;
            if chunk_off + 4 > bytecode.len() || chunk_sz < 4 {
                continue;
            }
            // First DWORD of the chunk is the version token:
            //   bits 0-7:   minor version
            //   bits 8-15:  major version
            //   bits 16-23: program type (0=VS, 1=PS, 2=GS, ...)
            //   bits 24-31: 0xFF
            let version_token =
                u32::from_le_bytes(bytecode[chunk_off..chunk_off + 4].try_into().unwrap());
            let program_type = (version_token >> 16) & 0xFF;
            stage = Some(match program_type {
                D3D10_PROGRAM_TYPE_VS => ShaderStage::Vs,
                D3D10_PROGRAM_TYPE_PS => ShaderStage::Ps,
                D3D10_PROGRAM_TYPE_GS => ShaderStage::Gs,
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcD3dFeatureUnsupported,
                        format!("D3D10: unsupported shader program type {}", program_type),
                    ));
                }
            });
            break;
        }
    }
    let stage = stage.ok_or_else(|| {
        AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            "D3D10: no SHDR/SHEX chunk found in shader bytecode",
        )
    })?;
    // Default entry point is "main" for HLSL-compiled shaders.
    // Advanced parsing could extract the real entry name from metadata chunks.
    Ok((stage, "main".to_string()))
}
// ── D3D10 Constants ─────────────────────────────────────────────────────────

/// D3D10_SDK_VERSION
pub const D3D10_SDK_VERSION: u32 = 7;

/// D3D10_CREATE_DEVICE_FLAGS
pub const D3D10_CREATE_DEVICE_SINGLETHREADED: u32 = 0x00000001;
pub const D3D10_CREATE_DEVICE_DEBUG: u32 = 0x00000002;
pub const D3D10_CREATE_DEVICE_SWITCH_TO_REF: u32 = 0x00000004;
pub const D3D10_CREATE_DEVICE_PREVENT_INTERNAL_THREADING_OPTIMIZATIONS: u32 = 0x00000008;
pub const D3D10_CREATE_DEVICE_ALLOW_NULL_FROM_MAP: u32 = 0x00000010;
pub const D3D10_CREATE_DEVICE_BGRA_SUPPORT: u32 = 0x00000020;
pub const D3D10_CREATE_DEVICE_PREVENT_ALTERING_LAYER_SETTINGS_FROM_REGISTRY: u32 = 0x00000080;
pub const D3D10_CREATE_DEVICE_STRICT_VALIDATION: u32 = 0x00000200;
pub const D3D10_CREATE_DEVICE_DEBUGGABLE: u32 = 0x00000400;

/// D3D10_RESOURCE_MISC_FLAG
pub const D3D10_RESOURCE_MISC_GENERATE_MIPS: u32 = 0x00000001;
pub const D3D10_RESOURCE_MISC_SHARED: u32 = 0x00000002;
pub const D3D10_RESOURCE_MISC_TEXTURECUBE: u32 = 0x00000004;
pub const D3D10_RESOURCE_MISC_SHARED_KEYEDMUTEX: u32 = 0x00000010;
pub const D3D10_RESOURCE_MISC_GDI_COMPATIBLE: u32 = 0x00000020;

/// D3D10_BIND_FLAG
pub const D3D10_BIND_VERTEX_BUFFER: u32 = 0x00000001;
pub const D3D10_BIND_INDEX_BUFFER: u32 = 0x00000002;
pub const D3D10_BIND_CONSTANT_BUFFER: u32 = 0x00000004;
pub const D3D10_BIND_SHADER_RESOURCE: u32 = 0x00000008;
pub const D3D10_BIND_STREAM_OUTPUT: u32 = 0x00000010;
pub const D3D10_BIND_RENDER_TARGET: u32 = 0x00000020;
pub const D3D10_BIND_DEPTH_STENCIL: u32 = 0x00000040;

/// D3D10_USAGE
pub const D3D10_USAGE_DEFAULT: u32 = 0;
pub const D3D10_USAGE_IMMUTABLE: u32 = 1;
pub const D3D10_USAGE_DYNAMIC: u32 = 2;
pub const D3D10_USAGE_STAGING: u32 = 3;

/// D3D10_CPU_ACCESS_FLAG
pub const D3D10_CPU_ACCESS_WRITE: u32 = 0x00010000;
pub const D3D10_CPU_ACCESS_READ: u32 = 0x00020000;

/// D3D10_MAP
pub const D3D10_MAP_READ: u32 = 1;
pub const D3D10_MAP_WRITE: u32 = 2;
pub const D3D10_MAP_READ_WRITE: u32 = 3;
pub const D3D10_MAP_WRITE_DISCARD: u32 = 4;
pub const D3D10_MAP_WRITE_NO_OVERWRITE: u32 = 5;

/// D3D10_PRIMITIVE_TOPOLOGY (matching D3D11 values)
pub const D3D10_PRIMITIVE_TOPOLOGY_UNDEFINED: u32 = 0;
pub const D3D10_PRIMITIVE_TOPOLOGY_POINTLIST: u32 = 1;
pub const D3D10_PRIMITIVE_TOPOLOGY_LINELIST: u32 = 2;
pub const D3D10_PRIMITIVE_TOPOLOGY_LINESTRIP: u32 = 3;
pub const D3D10_PRIMITIVE_TOPOLOGY_TRIANGLELIST: u32 = 4;
pub const D3D10_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP: u32 = 5;

/// D3D10_CLEAR_FLAG
pub const D3D10_CLEAR_DEPTH: u32 = 0x00000001;
pub const D3D10_CLEAR_STENCIL: u32 = 0x00000002;

/// D3D10_FILTER (matching D3D11 defines)
pub const D3D10_FILTER_MIN_MAG_MIP_POINT: u32 = 0;
pub const D3D10_FILTER_MIN_MAG_POINT_MIP_LINEAR: u32 = 0x01;
pub const D3D10_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT: u32 = 0x04;
pub const D3D10_FILTER_MIN_POINT_MAG_MIP_LINEAR: u32 = 0x05;
pub const D3D10_FILTER_MIN_LINEAR_MAG_MIP_POINT: u32 = 0x10;
pub const D3D10_FILTER_MIN_LINEAR_MAG_POINT_MIP_LINEAR: u32 = 0x11;
pub const D3D10_FILTER_MIN_MAG_LINEAR_MIP_POINT: u32 = 0x14;
pub const D3D10_FILTER_MIN_MAG_MIP_LINEAR: u32 = 0x15;
pub const D3D10_FILTER_ANISOTROPIC: u32 = 0x55;

/// D3D10_TEXTURE_ADDRESS_MODE
pub const D3D10_TEXTURE_ADDRESS_WRAP: u32 = 1;
pub const D3D10_TEXTURE_ADDRESS_MIRROR: u32 = 2;
pub const D3D10_TEXTURE_ADDRESS_CLAMP: u32 = 3;
pub const D3D10_TEXTURE_ADDRESS_BORDER: u32 = 4;
pub const D3D10_TEXTURE_ADDRESS_MIRROR_ONCE: u32 = 5;

/// D3D10_COMPARISON_FUNC
pub const D3D10_COMPARISON_NEVER: u32 = 1;
pub const D3D10_COMPARISON_LESS: u32 = 2;
pub const D3D10_COMPARISON_EQUAL: u32 = 3;
pub const D3D10_COMPARISON_LESS_EQUAL: u32 = 4;
pub const D3D10_COMPARISON_GREATER: u32 = 5;
pub const D3D10_COMPARISON_NOT_EQUAL: u32 = 6;
pub const D3D10_COMPARISON_GREATER_EQUAL: u32 = 7;
pub const D3D10_COMPARISON_ALWAYS: u32 = 8;

/// D3D10_STENCIL_OP
pub const D3D10_STENCIL_OP_KEEP: u32 = 1;
pub const D3D10_STENCIL_OP_ZERO: u32 = 2;
pub const D3D10_STENCIL_OP_REPLACE: u32 = 3;
pub const D3D10_STENCIL_OP_INCR_SAT: u32 = 4;
pub const D3D10_STENCIL_OP_DECR_SAT: u32 = 5;
pub const D3D10_STENCIL_OP_INVERT: u32 = 6;
pub const D3D10_STENCIL_OP_INCR: u32 = 7;
pub const D3D10_STENCIL_OP_DECR: u32 = 8;

/// D3D10_BLEND
pub const D3D10_BLEND_ZERO: u32 = 1;
pub const D3D10_BLEND_ONE: u32 = 2;
pub const D3D10_BLEND_SRC_COLOR: u32 = 3;
pub const D3D10_BLEND_INV_SRC_COLOR: u32 = 4;
pub const D3D10_BLEND_SRC_ALPHA: u32 = 5;
pub const D3D10_BLEND_INV_SRC_ALPHA: u32 = 6;
pub const D3D10_BLEND_DEST_ALPHA: u32 = 7;
pub const D3D10_BLEND_INV_DEST_ALPHA: u32 = 8;
pub const D3D10_BLEND_DEST_COLOR: u32 = 9;
pub const D3D10_BLEND_INV_DEST_COLOR: u32 = 10;
pub const D3D10_BLEND_SRC_ALPHA_SAT: u32 = 11;
pub const D3D10_BLEND_BLEND_FACTOR: u32 = 14;

/// D3D10_BLEND_OP
pub const D3D10_BLEND_OP_ADD: u32 = 1;
pub const D3D10_BLEND_OP_SUBTRACT: u32 = 2;
pub const D3D10_BLEND_OP_REV_SUBTRACT: u32 = 3;
pub const D3D10_BLEND_OP_MIN: u32 = 4;
pub const D3D10_BLEND_OP_MAX: u32 = 5;

/// D3D10_FILL_MODE
pub const D3D10_FILL_WIREFRAME: u32 = 2;
pub const D3D10_FILL_SOLID: u32 = 3;

/// D3D10_CULL_MODE
pub const D3D10_CULL_NONE: u32 = 1;
pub const D3D10_CULL_FRONT: u32 = 2;
pub const D3D10_CULL_BACK: u32 = 3;

/// D3D10_FORMAT_SUPPORT
pub const D3D10_FORMAT_SUPPORT_BUFFER: u32 = 0x00000001;
pub const D3D10_FORMAT_SUPPORT_IA_VERTEX_BUFFER: u32 = 0x00000002;
pub const D3D10_FORMAT_SUPPORT_IA_INDEX_BUFFER: u32 = 0x00000004;
pub const D3D10_FORMAT_SUPPORT_SO_BUFFER: u32 = 0x00000008;
pub const D3D10_FORMAT_SUPPORT_TEXTURE1D: u32 = 0x00000010;
pub const D3D10_FORMAT_SUPPORT_TEXTURE2D: u32 = 0x00000020;
pub const D3D10_FORMAT_SUPPORT_TEXTURE3D: u32 = 0x00000040;
pub const D3D10_FORMAT_SUPPORT_TEXTURECUBE: u32 = 0x00000080;
pub const D3D10_FORMAT_SUPPORT_SHADER_LOAD: u32 = 0x00000100;
pub const D3D10_FORMAT_SUPPORT_SHADER_SAMPLE: u32 = 0x00000200;
pub const D3D10_FORMAT_SUPPORT_SHADER_SAMPLE_COMPARISON: u32 = 0x00000400;
pub const D3D10_FORMAT_SUPPORT_SHADER_SAMPLE_MONO_TEXT: u32 = 0x00000800;
pub const D3D10_FORMAT_SUPPORT_MIP: u32 = 0x00001000;
pub const D3D10_FORMAT_SUPPORT_RENDER_TARGET: u32 = 0x00004000;
pub const D3D10_FORMAT_SUPPORT_BLENDABLE: u32 = 0x00008000;
pub const D3D10_FORMAT_SUPPORT_DEPTH_STENCIL: u32 = 0x00010000;
pub const D3D10_FORMAT_SUPPORT_CPU_LOCKABLE: u32 = 0x00020000;
pub const D3D10_FORMAT_SUPPORT_MULTISAMPLE_RESOLVE: u32 = 0x00040000;
pub const D3D10_FORMAT_SUPPORT_DISPLAY: u32 = 0x00080000;
pub const D3D10_FORMAT_SUPPORT_CAST_WITHIN_BIT_LAYOUT: u32 = 0x00100000;
pub const D3D10_FORMAT_SUPPORT_MULTISAMPLE_RENDERTARGET: u32 = 0x00200000;
pub const D3D10_FORMAT_SUPPORT_MULTISAMPLE_LOAD: u32 = 0x00400000;
pub const D3D10_FORMAT_SUPPORT_SHADER_GATHER: u32 = 0x00800000;

/// D3D10_QUERY types
pub const D3D10_QUERY_EVENT: u32 = 0;
pub const D3D10_QUERY_OCCLUSION: u32 = 1;
pub const D3D10_QUERY_TIMESTAMP: u32 = 2;
pub const D3D10_QUERY_TIMESTAMP_DISJOINT: u32 = 3;
pub const D3D10_QUERY_PIPELINE_STATISTICS: u32 = 4;
pub const D3D10_QUERY_OCCLUSION_PREDICATE: u32 = 5;
pub const D3D10_QUERY_SO_STATISTICS: u32 = 6;
pub const D3D10_QUERY_SO_OVERFLOW_PREDICATE: u32 = 7;

/// D3D10_SO_BUFFER (slot max for stream output)
pub const D3D10_SO_BUFFER_MAX_SLOTS: u32 = 4;

/// D3D10_MAX constant limits
pub const D3D10_MAX_MULTISAMPLE_SAMPLE_COUNT: u32 = 32;
pub const D3D10_MAX_TEXTURE_DIMENSION: u32 = 8192;
pub const D3D10_MAX_VERTEX_SHADER_INSTRUCTIONS: u32 = 2048;
pub const D3D10_MAX_PIXEL_SHADER_INSTRUCTIONS: u32 = 2048;
pub const D3D10_SIMULTANEOUS_RENDER_TARGET_COUNT: u32 = 8;
pub const D3D10_IA_PRIMITIVE_TOPOLOGY_MAX: u32 = 6;

/// D3D10 feature level support - D3D10 only supports 10_0 and 10_1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D3d10FeatureLevel {
    Level10_0,
    Level10_1,
}

impl D3d10FeatureLevel {
    /// Convert to the equivalent D3D11 feature level
    pub fn to_d3d11(&self) -> FeatureLevel {
        match self {
            D3d10FeatureLevel::Level10_0 | D3d10FeatureLevel::Level10_1 => FeatureLevel::Level10_1,
        }
    }
}

// ── D3D10 Structure Definitions ─────────────────────────────────────────────

/// D3D10_TEXTURE2D_DESC
#[derive(Debug, Clone)]
pub struct D3d10Texture2dDesc {
    pub width: u32,
    pub height: u32,
    pub mip_levels: u32,
    pub array_size: u32,
    pub format: DxgiFormat,
    pub sample_desc: D3d10SampleDesc,
    pub usage: u32,
    pub bind_flags: u32,
    pub cpu_access_flags: u32,
    pub misc_flags: u32,
}

/// D3D10_SAMPLE_DESC
#[derive(Debug, Clone, Copy)]
pub struct D3d10SampleDesc {
    pub count: u32,
    pub quality: u32,
}

/// D3D10_BUFFER_DESC
#[derive(Debug, Clone)]
pub struct D3d10BufferDesc {
    pub byte_width: u32,
    pub usage: u32,
    pub bind_flags: u32,
    pub cpu_access_flags: u32,
    pub misc_flags: u32,
}

/// D3D10_TEXTURE1D_DESC
#[derive(Debug, Clone)]
pub struct D3d10Texture1dDesc {
    pub width: u32,
    pub mip_levels: u32,
    pub array_size: u32,
    pub format: DxgiFormat,
    pub usage: u32,
    pub bind_flags: u32,
    pub cpu_access_flags: u32,
    pub misc_flags: u32,
}

/// D3D10_TEXTURE3D_DESC
#[derive(Debug, Clone)]
pub struct D3d10Texture3dDesc {
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub mip_levels: u32,
    pub format: DxgiFormat,
    pub usage: u32,
    pub bind_flags: u32,
    pub cpu_access_flags: u32,
    pub misc_flags: u32,
}

/// D3D10_VIEWPORT
#[derive(Debug, Clone, Copy)]
pub struct D3d10Viewport {
    pub top_left_x: i32,
    pub top_left_y: i32,
    pub width: i32,
    pub height: i32,
    pub min_depth: f32,
    pub max_depth: f32,
}

impl From<D3d10Viewport> for Viewport {
    fn from(v: D3d10Viewport) -> Self {
        Viewport {
            x: v.top_left_x as f32,
            y: v.top_left_y as f32,
            width: v.width as f32,
            height: v.height as f32,
        }
    }
}

/// D3D10_RECT (scissor rect)
#[derive(Debug, Clone, Copy)]
pub struct D3d10Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl From<D3d10Rect> for ScissorRect {
    fn from(r: D3d10Rect) -> Self {
        ScissorRect {
            left: r.left,
            top: r.top,
            right: r.right,
            bottom: r.bottom,
        }
    }
}

/// D3D10_SHADER_RESOURCE_VIEW_DESC
#[derive(Debug, Clone)]
pub struct D3d10ShaderResourceViewDesc {
    pub format: DxgiFormat,
    pub view_dimension: u32, // D3D10_SRV_DIMENSION
    pub most_detailed_mip: u32,
    pub mip_levels: u32,
}

/// D3D10_RENDER_TARGET_VIEW_DESC
#[derive(Debug, Clone)]
pub struct D3d10RenderTargetViewDesc {
    pub format: DxgiFormat,
    pub view_dimension: u32, // D3D10_RTV_DIMENSION
    pub mip_slice: u32,
}

/// D3D10_DEPTH_STENCIL_VIEW_DESC
#[derive(Debug, Clone)]
pub struct D3d10DepthStencilViewDesc {
    pub format: DxgiFormat,
    pub view_dimension: u32, // D3D10_DSV_DIMENSION
    pub mip_slice: u32,
}

/// D3D10_SAMPLER_DESC (same as D3D11_SAMPLER_DESC)
#[derive(Debug, Clone)]
pub struct D3d10SamplerDesc {
    pub filter: u32,
    pub address_u: u32,
    pub address_v: u32,
    pub address_w: u32,
    pub mip_lod_bias: f32,
    pub max_anisotropy: u32,
    pub comparison_func: u32,
    pub border_color: [f32; 4],
    pub min_lod: f32,
    pub max_lod: f32,
}

impl Default for D3d10SamplerDesc {
    fn default() -> Self {
        Self {
            filter: D3D10_FILTER_MIN_MAG_MIP_POINT,
            address_u: D3D10_TEXTURE_ADDRESS_CLAMP,
            address_v: D3D10_TEXTURE_ADDRESS_CLAMP,
            address_w: D3D10_TEXTURE_ADDRESS_CLAMP,
            mip_lod_bias: 0.0,
            max_anisotropy: 1,
            comparison_func: D3D10_COMPARISON_NEVER,
            border_color: [1.0, 1.0, 1.0, 1.0],
            min_lod: -f32::MAX,
            max_lod: f32::MAX,
        }
    }
}

impl D3d10SamplerDesc {
    /// Convert to D3D11 SamplerStateDesc with full field mapping.
    pub fn to_d3d11(&self) -> SamplerStateDesc {
        SamplerStateDesc {
            filter: self.d3d10_filter_to_d3d11(),
            address_u: self.map_address_mode(self.address_u),
            address_v: self.map_address_mode(self.address_v),
            address_w: self.map_address_mode(self.address_w),
            mip_lod_bias: self.mip_lod_bias,
            max_anisotropy: self.max_anisotropy,
            comparison_func: self.comparison_func,
            border_color: self.border_color,
            min_lod: self.min_lod,
            max_lod: self.max_lod,
        }
    }

    fn d3d10_filter_to_d3d11(&self) -> crate::gfx::FilterMode {
        // Map D3D10 filter to the closest FilterMode.
        // Comparison filters map to the corresponding non-comparison filter mode
        // since FilterMode doesn't have comparison variants. The comparison_func
        // field captures the comparison semantics separately.
        let raw = self.filter & 0x7F; // Mask off comparison bit (0x80)
        match raw {
            D3D10_FILTER_MIN_MAG_MIP_POINT
            | D3D10_FILTER_MIN_MAG_POINT_MIP_LINEAR
            | D3D10_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT
            | D3D10_FILTER_MIN_POINT_MAG_MIP_LINEAR => crate::gfx::FilterMode::Point,
            D3D10_FILTER_MIN_LINEAR_MAG_MIP_POINT
            | D3D10_FILTER_MIN_LINEAR_MAG_POINT_MIP_LINEAR
            | D3D10_FILTER_MIN_MAG_LINEAR_MIP_POINT
            | D3D10_FILTER_MIN_MAG_MIP_LINEAR => crate::gfx::FilterMode::Linear,
            D3D10_FILTER_ANISOTROPIC => crate::gfx::FilterMode::Linear,
            _ => crate::gfx::FilterMode::Point,
        }
    }

    fn map_address_mode(&self, mode: u32) -> String {
        match mode {
            D3D10_TEXTURE_ADDRESS_WRAP => "wrap".to_string(),
            D3D10_TEXTURE_ADDRESS_MIRROR => "mirror".to_string(),
            D3D10_TEXTURE_ADDRESS_CLAMP => "clamp".to_string(),
            D3D10_TEXTURE_ADDRESS_BORDER => "border".to_string(),
            D3D10_TEXTURE_ADDRESS_MIRROR_ONCE => "mirror_once".to_string(),
            _ => "wrap".to_string(),
        }
    }
}

/// D3D10_BLEND_DESC (simplified for D3D10 – single render target)
#[derive(Debug, Clone)]
pub struct D3d10BlendDesc {
    pub alpha_to_coverage_enable: bool,
    pub blend_enable: [bool; 8],
    pub src_blend: [u32; 8],
    pub dest_blend: [u32; 8],
    pub blend_op: [u32; 8],
    pub src_blend_alpha: [u32; 8],
    pub dest_blend_alpha: [u32; 8],
    pub blend_op_alpha: [u32; 8],
    pub render_target_write_mask: [u8; 8],
}

impl D3d10BlendDesc {
    pub fn to_d3d11(&self) -> BlendStateDesc {
        // Map D3D10 blend/op constants to the u32 values used by D3D11
        // (they are the same numeric values for the standard blend factors)
        let map_rt = |i: usize| crate::d3d11::RenderTargetBlendDesc {
            blend_enable: self.blend_enable[i],
            src_blend: self.src_blend[i],
            dest_blend: self.dest_blend[i],
            blend_op: self.blend_op[i],
            src_blend_alpha: self.src_blend_alpha[i],
            dest_blend_alpha: self.dest_blend_alpha[i],
            blend_op_alpha: self.blend_op_alpha[i],
            render_target_write_mask: self.render_target_write_mask[i],
        };
        BlendStateDesc {
            alpha_to_coverage_enable: self.alpha_to_coverage_enable,
            independent_blend_enable: false, // D3D10 does not support independent blend
            render_target: [
                map_rt(0),
                map_rt(1),
                map_rt(2),
                map_rt(3),
                map_rt(4),
                map_rt(5),
                map_rt(6),
                map_rt(7),
            ],
        }
    }
}

impl Default for D3d10BlendDesc {
    fn default() -> Self {
        D3d10BlendDesc {
            alpha_to_coverage_enable: false,
            blend_enable: [false; 8],
            src_blend: [D3D10_BLEND_ONE; 8],
            dest_blend: [D3D10_BLEND_ZERO; 8],
            blend_op: [D3D10_BLEND_OP_ADD; 8],
            src_blend_alpha: [D3D10_BLEND_ONE; 8],
            dest_blend_alpha: [D3D10_BLEND_ZERO; 8],
            blend_op_alpha: [D3D10_BLEND_OP_ADD; 8],
            render_target_write_mask: [0x0F; 8],
        }
    }
}

/// D3D10_RASTERIZER_DESC
#[derive(Debug, Clone)]
pub struct D3d10RasterizerDesc {
    pub fill_mode: u32,
    pub cull_mode: u32,
    pub front_counter_clockwise: bool,
    pub depth_bias: i32,
    pub depth_bias_clamp: f32,
    pub slope_scaled_depth_bias: f32,
    pub depth_clip_enable: bool,
    pub scissor_enable: bool,
    pub multisample_enable: bool,
    pub antialiased_line_enable: bool,
}

impl D3d10RasterizerDesc {
    pub fn to_d3d11(&self) -> RasterizerStateDesc {
        RasterizerStateDesc {
            fill_mode: match self.fill_mode {
                D3D10_FILL_WIREFRAME => "wireframe".to_string(),
                _ => "solid".to_string(),
            },
            cull_mode: match self.cull_mode {
                D3D10_CULL_NONE => "none".to_string(),
                D3D10_CULL_FRONT => "front".to_string(),
                _ => "back".to_string(),
            },
            front_counter_clockwise: self.front_counter_clockwise,
            depth_bias: self.depth_bias,
            depth_bias_clamp: self.depth_bias_clamp,
            slope_scaled_depth_bias: self.slope_scaled_depth_bias,
            depth_clip_enable: self.depth_clip_enable,
            scissor_enable: self.scissor_enable,
            multisample_enable: self.multisample_enable,
            antialiased_line_enable: self.antialiased_line_enable,
        }
    }
}

impl Default for D3d10RasterizerDesc {
    fn default() -> Self {
        D3d10RasterizerDesc {
            fill_mode: D3D10_FILL_SOLID,
            cull_mode: D3D10_CULL_BACK,
            front_counter_clockwise: false,
            depth_bias: 0,
            depth_bias_clamp: 0.0,
            slope_scaled_depth_bias: 0.0,
            depth_clip_enable: true,
            scissor_enable: false,
            multisample_enable: false,
            antialiased_line_enable: false,
        }
    }
}

/// D3D10_DEPTH_STENCIL_DESC
#[derive(Debug, Clone)]
pub struct D3d10DepthStencilDesc {
    pub depth_enable: bool,
    pub depth_write_mask: u8, // D3D10_DEPTH_WRITE_MASK_ALL=1, ZERO=0
    pub depth_func: u32,
    pub stencil_enable: bool,
    pub stencil_read_mask: u8,
    pub stencil_write_mask: u8,
    pub front_stencil_fail_op: u32,
    pub front_stencil_depth_fail_op: u32,
    pub front_stencil_pass_op: u32,
    pub front_stencil_func: u32,
    pub back_stencil_fail_op: u32,
    pub back_stencil_depth_fail_op: u32,
    pub back_stencil_pass_op: u32,
    pub back_stencil_func: u32,
}

impl D3d10DepthStencilDesc {
    pub fn to_d3d11(&self) -> DepthStencilStateDesc {
        DepthStencilStateDesc {
            depth_enable: self.depth_enable,
            depth_write_mask: self.depth_write_mask,
            depth_func: self.depth_func,
            stencil_enable: self.stencil_enable,
            stencil_read_mask: self.stencil_read_mask,
            stencil_write_mask: self.stencil_write_mask,
            front_stencil_fail_op: self.front_stencil_fail_op,
            front_stencil_depth_fail_op: self.front_stencil_depth_fail_op,
            front_stencil_pass_op: self.front_stencil_pass_op,
            front_stencil_func: self.front_stencil_func,
            back_stencil_fail_op: self.back_stencil_fail_op,
            back_stencil_depth_fail_op: self.back_stencil_depth_fail_op,
            back_stencil_pass_op: self.back_stencil_pass_op,
            back_stencil_func: self.back_stencil_func,
        }
    }
}

impl Default for D3d10DepthStencilDesc {
    fn default() -> Self {
        D3d10DepthStencilDesc {
            depth_enable: true,
            depth_write_mask: 1, // D3D10_DEPTH_WRITE_MASK_ALL
            depth_func: D3D10_COMPARISON_LESS,
            stencil_enable: false,
            stencil_read_mask: 0xFF,
            stencil_write_mask: 0xFF,
            front_stencil_fail_op: D3D10_STENCIL_OP_KEEP,
            front_stencil_depth_fail_op: D3D10_STENCIL_OP_KEEP,
            front_stencil_pass_op: D3D10_STENCIL_OP_KEEP,
            front_stencil_func: D3D10_COMPARISON_ALWAYS,
            back_stencil_fail_op: D3D10_STENCIL_OP_KEEP,
            back_stencil_depth_fail_op: D3D10_STENCIL_OP_KEEP,
            back_stencil_pass_op: D3D10_STENCIL_OP_KEEP,
            back_stencil_func: D3D10_COMPARISON_ALWAYS,
        }
    }
}

/// D3D10_INPUT_ELEMENT_DESC
#[derive(Debug, Clone)]
pub struct D3d10InputElementDesc {
    pub semantic_name: String,
    pub semantic_index: u32,
    pub format: DxgiFormat,
    pub input_slot: u32,
    pub aligned_byte_offset: u32,
    pub input_slot_class: u32, // D3D10_INPUT_PER_VERTEX_DATA=0, D3D10_INPUT_PER_INSTANCE_DATA=1
    pub instance_data_step_rate: u32,
}

impl D3d10InputElementDesc {
    /// Convert to the D3D11 input element representation.
    ///
    /// Note: `crate::d3d11::InputElementDesc` only carries the semantic,
    /// format and input slot — `aligned_byte_offset`, `input_slot_class`
    /// (per-instance data) and `instance_data_step_rate` have no D3D11
    /// counterpart yet. The D3D10 layer therefore keeps the full element
    /// list in [`D3d10Device::input_layouts`] so the information is not
    /// lost, and instanced draws must be fed through a future extension of
    /// the D3D11 input layout description.
    pub fn to_d3d11(&self) -> crate::d3d11::InputElementDesc {
        crate::d3d11::InputElementDesc {
            semantic: format!("{}{}", self.semantic_name, self.semantic_index),
            format: self.format,
            slot: self.input_slot,
        }
    }
}

// ── D3D10 Device ──────────────────────────────────────────────────────────

/// D3D10 device wrapper that delegates to an internal D3D11 device.
///
/// This is the primary type representing an ID3D10Device. All D3D10 API calls
/// on the device are forwarded to the equivalent D3D11 methods.
pub struct D3d10Device {
    /// The underlying D3D11 device that does all the real work.
    pub(crate) d3d11_device: D3d11Device,
    /// Creation flags passed to D3D10CreateDevice
    pub(crate) creation_flags: u32,
    /// Resource tracking for D3D10→D3D11 resource ID mapping
    next_resource_id: u64,
    resources: std::collections::BTreeMap<u64, D3d10Resource>,
    /// Full D3D10 input layouts preserved by id (the D3D11 input element
    /// representation cannot carry offset/slot-class/step-rate yet).
    input_layouts: std::collections::BTreeMap<InputLayoutId, Vec<D3d10InputElementDesc>>,
    /// The swapchain created by `d3d10_create_device_and_swapchain`, used by
    /// `present`.
    swapchain_id: Option<crate::gfx::SwapchainId>,
}

/// Resource tracked in the D3D10 layer.
#[derive(Debug, Clone)]
struct D3d10Resource {
    d3d11_id: D3d11ResourceId,
    kind: D3d10ResourceKind,
}

#[derive(Debug, Clone)]
enum D3d10ResourceKind {
    Buffer(D3d10BufferDesc),
    Texture2D(D3d10Texture2dDesc),
    Texture1D,
    Texture3D,
}

impl D3d10Device {
    /// Access the underlying D3D11 device.
    pub fn d3d11_device(&self) -> &D3d11Device {
        &self.d3d11_device
    }

    /// Access the underlying D3D11 device mutably.
    pub fn d3d11_device_mut(&mut self) -> &mut D3d11Device {
        &mut self.d3d11_device
    }

    /// Get the D3D10 feature level.
    pub fn feature_level(&self) -> D3d10FeatureLevel {
        // Map D3D11 feature level back to D3D10
        match self.d3d11_device.feature_level() {
            FeatureLevel::Level10_1 => D3d10FeatureLevel::Level10_1,
            FeatureLevel::Level11_0 => D3d10FeatureLevel::Level10_1,
        }
    }

    // ── Resource Creation ──────────────────────────────────────────────────

    /// ID3D10Device::CreateTexture2D
    pub fn create_texture_2d(
        &mut self,
        desc: &D3d10Texture2dDesc,
        initial_data: Option<&[u8]>,
    ) -> AppResult<u64> {
        if desc.sample_desc.count > 1 {
            return Err(AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                format!(
                    "D3D10: multisampled textures (sample count {}) are not supported",
                    desc.sample_desc.count
                ),
            ));
        }
        let resource_id = self.d3d11_device.create_texture_2d_with_usage(
            &format!("d3d10-texture2d-{}", self.next_resource_id),
            desc.width,
            desc.height,
            desc.format,
            self.map_d3d10_usage_to_hint(desc.usage, desc.bind_flags, desc.cpu_access_flags),
        )?;

        if let Some(data) = initial_data {
            self.d3d11_device.update_subresource(resource_id, data)?;
        }

        let d3d10_id = self.next_resource_id;
        self.next_resource_id += 1;
        self.resources.insert(
            d3d10_id,
            D3d10Resource {
                d3d11_id: resource_id,
                kind: D3d10ResourceKind::Texture2D(desc.clone()),
            },
        );
        Ok(d3d10_id)
    }

    /// ID3D10Device::CreateBuffer
    pub fn create_buffer(
        &mut self,
        desc: &D3d10BufferDesc,
        initial_data: Option<&[u8]>,
    ) -> AppResult<u64> {
        let size = desc.byte_width as usize;
        let hint = self.map_d3d10_usage_to_hint(desc.usage, desc.bind_flags, desc.cpu_access_flags);
        let resource_id = self.d3d11_device.create_buffer(
            &format!("d3d10-buffer-{}", self.next_resource_id),
            size,
            hint,
        )?;

        if let Some(data) = initial_data {
            self.d3d11_device.update_subresource(resource_id, data)?;
        }

        let d3d10_id = self.next_resource_id;
        self.next_resource_id += 1;
        self.resources.insert(
            d3d10_id,
            D3d10Resource {
                d3d11_id: resource_id,
                kind: D3d10ResourceKind::Buffer(desc.clone()),
            },
        );
        Ok(d3d10_id)
    }

    /// Get the D3D11 resource ID for a D3D10 resource
    pub fn get_d3d11_resource_id(&self, d3d10_resource_id: u64) -> AppResult<D3d11ResourceId> {
        self.resources
            .get(&d3d10_resource_id)
            .map(|r| r.d3d11_id)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    format!("D3D10 resource {} not found", d3d10_resource_id),
                )
            })
    }

    // ── View Creation ──────────────────────────────────────────────────────

    /// ID3D10Device::CreateRenderTargetView
    pub fn create_render_target_view(
        &mut self,
        resource_id: u64,
        desc: Option<&D3d10RenderTargetViewDesc>,
    ) -> AppResult<D3d11ViewId> {
        let d3d11_id = self.get_d3d11_resource_id(resource_id)?;
        let format = self.resolve_view_format(d3d11_id, desc.map(|d| d.format))?;
        self.d3d11_device
            .create_render_target_view(d3d11_id, format)
    }

    /// ID3D10Device::CreateDepthStencilView
    pub fn create_depth_stencil_view(
        &mut self,
        resource_id: u64,
        desc: Option<&D3d10DepthStencilViewDesc>,
    ) -> AppResult<D3d11ViewId> {
        let d3d11_id = self.get_d3d11_resource_id(resource_id)?;
        let format = self.resolve_view_format(d3d11_id, desc.map(|d| d.format))?;
        self.d3d11_device
            .create_depth_stencil_view(d3d11_id, format)
    }

    /// ID3D10Device::CreateShaderResourceView
    pub fn create_shader_resource_view(
        &mut self,
        resource_id: u64,
        desc: Option<&D3d10ShaderResourceViewDesc>,
    ) -> AppResult<D3d11ViewId> {
        let d3d11_id = self.get_d3d11_resource_id(resource_id)?;
        let format = self.resolve_view_format(d3d11_id, desc.map(|d| d.format))?;
        self.d3d11_device
            .create_shader_resource_view(d3d11_id, format)
    }

    /// Resolve the view format: the caller's view-desc format when provided,
    /// otherwise the resource's own format.
    fn resolve_view_format(
        &self,
        d3d11_resource_id: D3d11ResourceId,
        requested: Option<DxgiFormat>,
    ) -> AppResult<DxgiFormat> {
        match requested {
            Some(format) => Ok(format),
            None => Ok(self.d3d11_device.resource_desc(d3d11_resource_id)?.format),
        }
    }

    // ── Shader Creation ────────────────────────────────────────────────────

    /// Parse D3D10 DXBC shader bytecode and create a Metal function via the
    /// D3D11 translation pipeline.
    ///
    /// Returns the entry point name extracted from the bytecode (defaults to
    /// "main" for standard HLSL-compiled shaders).
    fn create_shader_from_bytecode(
        &mut self,
        bytecode: &[u8],
        expected_stage: ShaderStage,
    ) -> AppResult<ShaderId> {
        let (detected_stage, entry) = parse_dxbc_bytecode(bytecode)?;
        // Verify the bytecode shader type matches the expected D3D10 API call
        if detected_stage != expected_stage {
            return Err(AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                format!(
                    "D3D10: shader bytecode stage {:?} does not match expected {:?}",
                    detected_stage, expected_stage
                ),
            ));
        }
        let desc = ShaderModuleDesc {
            stage: detected_stage,
            entry,
        };
        // Route through the D3D11 DXIL translation pipeline. For native D3D10
        // bytecode (shader model 4.0/4.1 tokens wrapped in DXBC) the
        // translate_shader pipeline will attempt DXIL parsing; if the bytecode
        // is actually DXIL (D3D11 shader model 5.0+), full Metal translation
        // will occur. For D3D10 token bytecode, translation will fall through
        // and the shader is stored without a Metal artifact (deferred).
        self.d3d11_device
            .create_shader_from_dxil(desc, bytecode.to_vec(), Vec::new())
    }

    /// ID3D10Device::CreateVertexShader
    pub fn create_vertex_shader(&mut self, bytecode: &[u8]) -> AppResult<ShaderId> {
        self.create_shader_from_bytecode(bytecode, ShaderStage::Vs)
    }

    /// ID3D10Device::CreatePixelShader
    pub fn create_pixel_shader(&mut self, bytecode: &[u8]) -> AppResult<ShaderId> {
        self.create_shader_from_bytecode(bytecode, ShaderStage::Ps)
    }

    /// ID3D10Device::CreateGeometryShader
    pub fn create_geometry_shader(&mut self, bytecode: &[u8]) -> AppResult<ShaderId> {
        self.create_shader_from_bytecode(bytecode, ShaderStage::Gs)
    }

    // ── State Object Creation ──────────────────────────────────────────────

    /// ID3D10Device::CreateBlendState
    pub fn create_blend_state(&mut self, desc: &D3d10BlendDesc) -> BlendStateId {
        self.d3d11_device.create_blend_state(desc.to_d3d11())
    }

    /// ID3D10Device::CreateRasterizerState
    pub fn create_rasterizer_state(&mut self, desc: &D3d10RasterizerDesc) -> RasterizerStateId {
        self.d3d11_device.create_rasterizer_state(desc.to_d3d11())
    }

    /// ID3D10Device::CreateDepthStencilState
    pub fn create_depth_stencil_state(
        &mut self,
        desc: &D3d10DepthStencilDesc,
    ) -> DepthStencilStateId {
        self.d3d11_device
            .create_depth_stencil_state(desc.to_d3d11())
    }

    /// ID3D10Device::CreateSamplerState
    pub fn create_sampler_state(&mut self, desc: &D3d10SamplerDesc) -> SamplerStateId {
        self.d3d11_device.create_sampler_state(desc.to_d3d11())
    }

    /// ID3D10Device::CreateInputLayout
    pub fn create_input_layout(&mut self, elements: &[D3d10InputElementDesc]) -> InputLayoutId {
        let d3d11_elements: Vec<crate::d3d11::InputElementDesc> =
            elements.iter().map(|e| e.to_d3d11()).collect();
        let id = self.d3d11_device.create_input_layout(InputLayoutDesc {
            elements: d3d11_elements,
        });
        self.input_layouts.insert(id, elements.to_vec());
        id
    }

    // ── Device Context Methods (D3D10 merges device + context) ─────────────

    /// ID3D10Device::OMSetRenderTargets
    pub fn om_set_render_targets(
        &mut self,
        render_targets: Vec<D3d11ViewId>,
        depth_target: Option<D3d11ViewId>,
    ) {
        self.d3d11_device
            .om_set_render_targets(render_targets, depth_target);
    }

    /// ID3D10Device::OMSetBlendState
    pub fn om_set_blend_state(&mut self, state: BlendStateId) {
        self.d3d11_device.om_set_blend_state(state);
    }

    /// ID3D10Device::OMSetDepthStencilState
    pub fn om_set_depth_stencil_state(&mut self, state: DepthStencilStateId) {
        self.d3d11_device.om_set_depth_stencil_state(state);
    }

    /// ID3D10Device::RSSetState
    pub fn rs_set_state(&mut self, state: RasterizerStateId) {
        self.d3d11_device.rs_set_state(state);
    }

    /// ID3D10Device::RSSetViewports
    pub fn rs_set_viewports(&mut self, viewport: D3d10Viewport) {
        self.d3d11_device.rs_set_viewports(viewport.into());
    }

    /// ID3D10Device::RSSetScissorRects
    pub fn rs_set_scissor_rects(&mut self, rect: D3d10Rect) {
        self.d3d11_device.rs_set_scissor_rects(rect.into());
    }

    /// ID3D10Device::IASetInputLayout
    pub fn ia_set_input_layout(&mut self, layout: InputLayoutId) {
        self.d3d11_device.ia_set_input_layout(layout);
    }

    /// ID3D10Device::IASetVertexBuffers
    pub fn ia_set_vertex_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.d3d11_device.ia_set_vertex_buffers(buffers);
    }

    /// ID3D10Device::IASetIndexBuffer
    pub fn ia_set_index_buffer(&mut self, buffer: D3d11ResourceId) {
        self.d3d11_device.ia_set_index_buffer(buffer);
    }

    /// ID3D10Device::IASetPrimitiveTopology
    pub fn ia_set_primitive_topology(&mut self, topology: u32) {
        self.d3d11_device.ia_set_primitive_topology(topology);
    }

    /// ID3D10Device::VSSetShader
    pub fn vs_set_shader(&mut self, shader: ShaderId) {
        self.d3d11_device.vs_set_shader(shader);
    }

    /// ID3D10Device::VSSetConstantBuffers
    pub fn vs_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.d3d11_device.vs_set_constant_buffers(buffers);
    }

    /// ID3D10Device::PSSetShader
    pub fn ps_set_shader(&mut self, shader: ShaderId) {
        self.d3d11_device.ps_set_shader(shader);
    }

    /// ID3D10Device::PSSetConstantBuffers
    pub fn ps_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.d3d11_device.ps_set_constant_buffers(buffers);
    }

    /// ID3D10Device::PSSetShaderResources
    pub fn ps_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.d3d11_device.ps_set_shader_resources(resources);
    }

    /// ID3D10Device::PSSetSamplers
    pub fn ps_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.d3d11_device.ps_set_samplers(samplers);
    }

    /// ID3D10Device::GSSetShader
    pub fn gs_set_shader(&mut self, shader: ShaderId) {
        self.d3d11_device.gs_set_shader(shader);
    }

    // ── Draw / Dispatch ────────────────────────────────────────────────────

    /// ID3D10Device::Draw
    pub fn draw(&mut self, vertices: u32) {
        self.d3d11_device.draw(vertices);
    }

    /// ID3D10Device::DrawIndexed
    pub fn draw_indexed(&mut self, indices: u32) {
        self.d3d11_device.draw_indexed(indices);
    }

    /// ID3D10Device::DrawInstanced
    pub fn draw_instanced(&mut self, vertex_count_per_instance: u32, instance_count: u32) {
        self.d3d11_device
            .draw_instanced(vertex_count_per_instance, instance_count);
    }

    /// ID3D10Device::DrawIndexedInstanced
    pub fn draw_indexed_instanced(&mut self, index_count_per_instance: u32, instance_count: u32) {
        self.d3d11_device
            .draw_indexed_instanced(index_count_per_instance, instance_count);
    }

    /// ID3D10Device::ClearRenderTargetView
    pub fn clear_render_target_view(&mut self, view: D3d11ViewId, color: [u8; 4]) -> AppResult<()> {
        self.d3d11_device.clear_render_target_view(view, color)
    }

    /// ID3D10Device::ClearDepthStencilView
    pub fn clear_depth_stencil_view(
        &mut self,
        view: D3d11ViewId,
        clear_flags: u32,
        depth: f32,
        stencil: u8,
    ) -> AppResult<()> {
        // The D3D11 layer stores the depth as the raw 4 bytes written into
        // the depth resource, which is the IEEE-754 bit pattern of the f32
        // clear value (e.g. 0.5 -> 0x3F000000). A plain `as u32` cast would
        // truncate fractional depths to their integer part.
        let depth_val = if clear_flags & D3D10_CLEAR_DEPTH != 0 {
            depth.to_bits()
        } else {
            0
        };
        let stencil_val = if clear_flags & D3D10_CLEAR_STENCIL != 0 {
            stencil
        } else {
            0
        };
        self.d3d11_device
            .clear_depth_stencil_view(view, depth_val, stencil_val)
    }

    /// ID3D10Device::UpdateSubresource
    pub fn update_subresource(&mut self, resource_id: u64, data: &[u8]) -> AppResult<()> {
        let d3d11_id = self.get_d3d11_resource_id(resource_id)?;
        self.d3d11_device.update_subresource(d3d11_id, data)
    }

    /// ID3D10Device::CopyResource
    pub fn copy_resource(&mut self, src: u64, dst: u64) -> AppResult<()> {
        let src_id = self.get_d3d11_resource_id(src)?;
        let dst_id = self.get_d3d11_resource_id(dst)?;
        self.d3d11_device.copy_resource(src_id, dst_id)
    }

    /// ID3D10Device::CopySubresourceRegion
    #[allow(clippy::too_many_arguments)]
    pub fn copy_subresource_region(
        &mut self,
        dst: u64,
        dst_subresource: u32,
        dst_x: u32,
        dst_y: u32,
        dst_z: u32,
        src: u64,
        src_subresource: u32,
        src_box: Option<[u32; 6]>,
    ) -> AppResult<()> {
        let src_id = self.get_d3d11_resource_id(src)?;
        let dst_id = self.get_d3d11_resource_id(dst)?;
        let src_desc = self.d3d11_device.resource_desc(src_id)?;
        // A NULL source box means the entire source subresource is copied.
        // A box spanning the whole source, with zero destination offsets and
        // matching subresources, is equivalent to CopyResource and is the
        // only case this translation layer can represent exactly.
        let copies_whole = match src_box {
            None => true,
            Some(box_) => {
                let (left, top, front, right, bottom, back) =
                    (box_[0], box_[1], box_[2], box_[3], box_[4], box_[5]);
                left == 0
                    && top == 0
                    && front == 0
                    && right >= src_desc.width
                    && bottom >= src_desc.height
                    && back >= src_desc.depth
            }
        };
        if copies_whole
            && dst_x == 0
            && dst_y == 0
            && dst_z == 0
            && dst_subresource == src_subresource
        {
            self.d3d11_device.copy_resource(src_id, dst_id)
        } else {
            Err(AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                "D3D10 CopySubresourceRegion with a partial source box, nonzero \
                 destination offset, or differing subresources is not supported",
            ))
        }
    }

    /// ID3D10Device::ResolveSubresource
    pub fn resolve_subresource(
        &mut self,
        dst: u64,
        _dst_subresource: u32,
        src: u64,
        _src_subresource: u32,
        _format: DxgiFormat,
    ) -> AppResult<()> {
        let src_id = self.get_d3d11_resource_id(src)?;
        let dst_id = self.get_d3d11_resource_id(dst)?;
        self.d3d11_device.copy_resource(src_id, dst_id)
    }

    /// ID3D10Device::Map
    pub fn map(&mut self, resource_id: u64) -> AppResult<Vec<u8>> {
        let d3d11_id = self.get_d3d11_resource_id(resource_id)?;
        self.d3d11_device.map(d3d11_id)
    }

    /// ID3D10Device::Unmap
    pub fn unmap(&mut self, resource_id: u64, data: &[u8]) -> AppResult<()> {
        let d3d11_id = self.get_d3d11_resource_id(resource_id)?;
        self.d3d11_device.unmap(d3d11_id, data)
    }

    /// ID3D10Device::GenerateMips
    pub fn generate_mips(&mut self, view_srv: D3d11ViewId) {
        self.d3d11_device.generate_mips(view_srv);
    }

    /// ID3D10Device::Submit (execute immediate commands)
    pub fn submit(&mut self) -> AppResult<crate::d3d11::SubmissionResult> {
        self.d3d11_device.submit_immediate()
    }

    /// ID3D10Device::Present (via swapchain)
    pub fn present(&mut self) -> AppResult<()> {
        // Present the swapchain this device was created with (if any).
        // The D3D11 layer presents the device's own swapchain; this check
        // keeps the D3D10 contract honest instead of silently presenting
        // a nonexistent swapchain.
        if self.swapchain_id.is_none() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "D3D10 device has no swapchain to present",
            ));
        }
        self.d3d11_device.present_swapchain(0, false, true)?;
        Ok(())
    }

    // ── Helper: map D3D10 usage/bind/cpu flags to D3D11 ResourceUsageHint ──

    fn map_d3d10_usage_to_hint(
        &self,
        usage: u32,
        bind_flags: u32,
        cpu_access_flags: u32,
    ) -> ResourceUsageHint {
        let is_depth_stencil = (bind_flags & D3D10_BIND_DEPTH_STENCIL) != 0;
        let is_render_target = (bind_flags & D3D10_BIND_RENDER_TARGET) != 0;
        let is_constant = (bind_flags & D3D10_BIND_CONSTANT_BUFFER) != 0;
        let is_shader_resource = (bind_flags & D3D10_BIND_SHADER_RESOURCE) != 0;

        // STAGING resources are CPU-accessible copies used for both upload
        // and readback; honor the CPU access flags so a read-oriented
        // staging buffer is not given a write-oriented placement.
        let cpu_write_frequent = matches!(usage, D3D10_USAGE_DYNAMIC)
            || (usage == D3D10_USAGE_STAGING && cpu_access_flags & D3D10_CPU_ACCESS_READ == 0);

        if is_depth_stencil {
            ResourceUsageHint::DepthStencil
        } else if is_render_target {
            ResourceUsageHint::Texture {
                sampled: false,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent,
            }
        } else if is_constant {
            ResourceUsageHint::Buffer {
                role: crate::gfx::BufferRole::Constant,
                cpu_write_frequent: false,
            }
        } else if is_shader_resource && cpu_write_frequent {
            ResourceUsageHint::Buffer {
                role: crate::gfx::BufferRole::Generic,
                cpu_write_frequent: true,
            }
        } else if is_shader_resource {
            ResourceUsageHint::Texture {
                sampled: true,
                render_target: false,
                depth_stencil: false,
                cpu_write_frequent,
            }
        } else if cpu_write_frequent {
            ResourceUsageHint::Buffer {
                role: crate::gfx::BufferRole::Generic,
                cpu_write_frequent: true,
            }
        } else {
            ResourceUsageHint::Generic
        }
    }
}

// ── Entry Points ─────────────────────────────────────────────────────────

/// Maps D3D10 driver type to a feature level request.
/// D3D10 only supports hardware (D3D10_DRIVER_TYPE_HARDWARE) and WARP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D3d10DriverType {
    Hardware,
    Reference,
    Null,
    Software,
    Warp,
}

/// D3D10CreateDevice entry point.
///
/// Creates a D3D10 device that wraps a D3D11 device internally.
/// This is the primary entry point for D3D10 applications.
///
/// Returns a [`D3d10Device`] that delegates all operations to the D3D11
/// implementation, which in turn translates to Metal via the graphics backend.
pub fn d3d10_create_device(
    _adapter: u64,
    driver_type: D3d10DriverType,
    _software_rasterizer: u64,
    flags: u32,
    feature_levels: &[D3d10FeatureLevel],
    _sdk_version: u32,
) -> AppResult<D3d10Device> {
    validate_driver_type(driver_type)?;
    validate_creation_flags(flags)?;

    let request = DeviceCreationRequest {
        requested_feature_levels: vec![requested_d3d10_feature_level(feature_levels)],
    };

    let d3d11_device = d3d11::d3d11_create_device(request)?;

    Ok(D3d10Device {
        d3d11_device,
        creation_flags: flags,
        next_resource_id: 1,
        resources: std::collections::BTreeMap::new(),
        input_layouts: std::collections::BTreeMap::new(),
        swapchain_id: None,
    })
}

/// D3D10CreateDeviceAndSwapChain entry point.
///
/// Creates a D3D10 device with an associated swapchain, wrapping D3D11 internally.
pub fn d3d10_create_device_and_swapchain(
    _adapter: u64,
    driver_type: D3d10DriverType,
    _software_rasterizer: u64,
    flags: u32,
    feature_levels: &[D3d10FeatureLevel],
    _sdk_version: u32,
    swapchain_desc: &SwapchainDesc,
) -> AppResult<D3d10Device> {
    validate_driver_type(driver_type)?;
    validate_creation_flags(flags)?;

    let request = DeviceCreationRequest {
        requested_feature_levels: vec![requested_d3d10_feature_level(feature_levels)],
    };

    let d3d11_device = d3d11::d3d11_create_device_and_swapchain(request, swapchain_desc.clone())?;
    let swapchain_id = d3d11_device.swapchain_state().map(|state| state.id);

    Ok(D3d10Device {
        d3d11_device,
        creation_flags: flags,
        next_resource_id: 1,
        resources: std::collections::BTreeMap::new(),
        input_layouts: std::collections::BTreeMap::new(),
        swapchain_id,
    })
}

/// Validate the D3D10 driver type: only hardware, reference and WARP are
/// realizable on top of the D3D11/Metal translation layer.
fn validate_driver_type(driver_type: D3d10DriverType) -> AppResult<()> {
    match driver_type {
        D3d10DriverType::Hardware | D3d10DriverType::Reference | D3d10DriverType::Warp => Ok(()),
        D3d10DriverType::Null | D3d10DriverType::Software => Err(AppError::new(
            ReasonCode::RcD3dFeatureUnsupported,
            format!("D3D10 driver type {driver_type:?} is not supported"),
        )),
    }
}

/// Validate D3D10 creation flags against the defined D3D10_CREATE_DEVICE_FLAG
/// values; unknown bits are rejected instead of silently ignored.
fn validate_creation_flags(flags: u32) -> AppResult<()> {
    const KNOWN_FLAGS: u32 = D3D10_CREATE_DEVICE_SINGLETHREADED
        | D3D10_CREATE_DEVICE_DEBUG
        | D3D10_CREATE_DEVICE_SWITCH_TO_REF
        | D3D10_CREATE_DEVICE_PREVENT_INTERNAL_THREADING_OPTIMIZATIONS
        | D3D10_CREATE_DEVICE_ALLOW_NULL_FROM_MAP
        | D3D10_CREATE_DEVICE_BGRA_SUPPORT
        | D3D10_CREATE_DEVICE_PREVENT_ALTERING_LAYER_SETTINGS_FROM_REGISTRY
        | D3D10_CREATE_DEVICE_STRICT_VALIDATION
        | D3D10_CREATE_DEVICE_DEBUGGABLE;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "unknown D3D10 creation flag bits 0x{:x}",
                flags & !KNOWN_FLAGS
            ),
        ));
    }
    Ok(())
}

/// Resolve the requested feature level: the most preferred level from the
/// caller's array (the first entry), falling back to 10_1. D3D10 only
/// supports 10_0 and 10_1, which both translate to the D3D11 10_1 level.
fn requested_d3d10_feature_level(feature_levels: &[D3d10FeatureLevel]) -> FeatureLevel {
    feature_levels
        .first()
        .copied()
        .unwrap_or(D3d10FeatureLevel::Level10_1)
        .to_d3d11()
}

// ── D3D10 Interface IIDs (for COM QueryInterface) ────────────────────────

/// D3D10 interface GUIDs as byte arrays.
pub struct D3d10Iid;

impl D3d10Iid {
    /// IID_ID3D10DeviceChild: {9B7E4C00-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10DEVICECHILD: [u8; 16] = [
        0x00, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Resource: {9B7E4C01-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10RESOURCE: [u8; 16] = [
        0x01, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Buffer: {9B7E4C02-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10BUFFER: [u8; 16] = [
        0x02, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Texture1D: {9B7E4C03-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10TEXTURE1D: [u8; 16] = [
        0x03, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Texture2D: {9B7E4C04-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10TEXTURE2D: [u8; 16] = [
        0x04, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Texture3D: {9B7E4C05-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10TEXTURE3D: [u8; 16] = [
        0x05, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10View: {C902B03F-60A7-49BA-9936-2A3AB37A7E33}
    pub const ID3D10VIEW: [u8; 16] = [
        0x3F, 0xB0, 0x02, 0xC9, 0xA7, 0x60, 0xBA, 0x49, 0x99, 0x36, 0x2A, 0x3A, 0xB3, 0x7A, 0x7E,
        0x33,
    ];
    /// IID_ID3D10ShaderResourceView: {9B7E4C07-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10SHADERRESOURCEVIEW: [u8; 16] = [
        0x07, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10RenderTargetView: {9B7E4C08-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10RENDERTARGETVIEW: [u8; 16] = [
        0x08, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10DepthStencilView: {9B7E4C09-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10DEPTHSTENCILVIEW: [u8; 16] = [
        0x09, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10VertexShader: {9B7E4C0A-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10VERTEXSHADER: [u8; 16] = [
        0x0A, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10InputLayout: {9B7E4C0B-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10INPUTLAYOUT: [u8; 16] = [
        0x0B, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10SamplerState: {9B7E4C0C-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10SAMPLERSTATE: [u8; 16] = [
        0x0C, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Asynchronous: {9B7E4C0D-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10ASYNCHRONOUS: [u8; 16] = [
        0x0D, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Query: {9B7E4C0E-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10QUERY: [u8; 16] = [
        0x0E, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Device: {9B7E4C0F-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10DEVICE: [u8; 16] = [
        0x0F, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Predicate: {9B7E4C10-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10PREDICATE: [u8; 16] = [
        0x10, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Counter: {9B7E4C11-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10COUNTER: [u8; 16] = [
        0x11, 0x4C, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10Multithread: {9B7E4E00-342C-4106-A19F-4F2704F689F0}
    pub const ID3D10MULTITHREAD: [u8; 16] = [
        0x00, 0x4E, 0x7E, 0x9B, 0x2C, 0x34, 0x06, 0x41, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89,
        0xF0,
    ];
    /// IID_ID3D10BlendState: {EDAD8D19-8A35-4D6D-8566-2EA276CDE161}
    pub const ID3D10BLENDSTATE: [u8; 16] = [
        0x19, 0x8D, 0xAD, 0xED, 0x35, 0x8A, 0x6D, 0x4D, 0x85, 0x66, 0x2E, 0xA2, 0x76, 0xCD, 0xE1,
        0x61,
    ];
    /// IID_ID3D10DepthStencilState: {2B4B1CC8-A4AD-41F8-8322-CA86FC3EC675}
    pub const ID3D10DEPTHSTENCILSTATE: [u8; 16] = [
        0xC8, 0x1C, 0x4B, 0x2B, 0xAD, 0xA4, 0xF8, 0x41, 0x83, 0x22, 0xCA, 0x86, 0xFC, 0x3E, 0xC6,
        0x75,
    ];
    /// IID_ID3D10GeometryShader: {6316BE88-54CD-4040-AB44-20461BC81F68}
    pub const ID3D10GEOMETRYSHADER: [u8; 16] = [
        0x88, 0xBE, 0x16, 0x63, 0xCD, 0x54, 0x40, 0x40, 0xAB, 0x44, 0x20, 0x46, 0x1B, 0xC8, 0x1F,
        0x68,
    ];
    /// IID_ID3D10PixelShader: {4968B601-9D00-4CDE-8346-8E7F675819B6}
    pub const ID3D10PIXELSHADER: [u8; 16] = [
        0x01, 0xB6, 0x68, 0x49, 0x00, 0x9D, 0xDE, 0x4C, 0x83, 0x46, 0x8E, 0x7F, 0x67, 0x58, 0x19,
        0xB6,
    ];
    /// IID_ID3D10RasterizerState: {A2A07292-89AF-4345-BE2E-C53D9FBB6E9F}
    pub const ID3D10RASTERIZERSTATE: [u8; 16] = [
        0x92, 0x72, 0xA0, 0xA2, 0xAF, 0x89, 0x45, 0x43, 0xBE, 0x2E, 0xC5, 0x3D, 0x9F, 0xBB, 0x6E,
        0x9F,
    ];
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that D3D10CreateDevice produces a usable device.
    #[test]
    fn test_d3d10_create_device() {
        let device =
            d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
                .expect("D3D10CreateDevice should succeed");
        assert_eq!(device.feature_level(), D3d10FeatureLevel::Level10_1);
    }

    /// Test that D3D10CreateDeviceAndSwapChain produces a device with swapchain.
    #[test]
    fn test_d3d10_create_device_and_swapchain() {
        let swapchain_desc = SwapchainDesc {
            width: 800,
            height: 600,
            buffer_count: 2,
            format: DxgiFormat::B8G8R8A8Unorm,
        };
        let device = d3d10_create_device_and_swapchain(
            0,
            D3d10DriverType::Hardware,
            0,
            0,
            &[],
            D3D10_SDK_VERSION,
            &swapchain_desc,
        )
        .expect("D3D10CreateDeviceAndSwapChain should succeed");
        assert_eq!(device.feature_level(), D3d10FeatureLevel::Level10_1);
    }

    /// Test creating a D3D10 texture and verifying it maps to D3D11.
    #[test]
    fn test_d3d10_create_texture2d() {
        let mut device =
            d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
                .expect("create device");

        let desc = D3d10Texture2dDesc {
            width: 64,
            height: 64,
            mip_levels: 1,
            array_size: 1,
            format: DxgiFormat::R8G8B8A8Unorm,
            sample_desc: D3d10SampleDesc {
                count: 1,
                quality: 0,
            },
            usage: D3D10_USAGE_DEFAULT,
            bind_flags: D3D10_BIND_RENDER_TARGET,
            cpu_access_flags: 0,
            misc_flags: 0,
        };

        let resource_id = device
            .create_texture_2d(&desc, None)
            .expect("create texture 2d");
        assert!(resource_id > 0);

        let d3d11_id = device
            .get_d3d11_resource_id(resource_id)
            .expect("get d3d11 id");
        let desc_info = device
            .d3d11_device()
            .resource_desc(d3d11_id)
            .expect("resource desc");
        assert_eq!(desc_info.width, 64);
        assert_eq!(desc_info.height, 64);
    }

    /// Test creating a D3D10 buffer.
    #[test]
    fn test_d3d10_create_buffer() {
        let mut device =
            d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
                .expect("create device");

        let desc = D3d10BufferDesc {
            byte_width: 1024,
            usage: D3D10_USAGE_DEFAULT,
            bind_flags: D3D10_BIND_VERTEX_BUFFER,
            cpu_access_flags: 0,
            misc_flags: 0,
        };

        let resource_id = device.create_buffer(&desc, None).expect("create buffer");
        assert!(resource_id > 0);
    }

    /// Test basic state creation and setting.
    #[test]
    fn test_d3d10_render_state_setup() {
        let mut device =
            d3d10_create_device(0, D3d10DriverType::Hardware, 0, 0, &[], D3D10_SDK_VERSION)
                .expect("create device");

        // Create rasterizer state
        let rs_desc = D3d10RasterizerDesc {
            fill_mode: D3D10_FILL_SOLID,
            cull_mode: D3D10_CULL_BACK,
            ..Default::default()
        };
        let rs_id = device.create_rasterizer_state(&rs_desc);
        device.rs_set_state(rs_id);

        // Create blend state
        let blend_desc = D3d10BlendDesc {
            blend_enable: [true, false, false, false, false, false, false, false],
            ..Default::default()
        };
        let blend_id = device.create_blend_state(&blend_desc);
        device.om_set_blend_state(blend_id);

        // Create depth-stencil state
        let ds_desc = D3d10DepthStencilDesc {
            depth_enable: true,
            depth_write_mask: 1,
            ..Default::default()
        };
        let ds_id = device.create_depth_stencil_state(&ds_desc);
        device.om_set_depth_stencil_state(ds_id);

        // Create sampler state
        let sampler_desc = D3d10SamplerDesc {
            filter: D3D10_FILTER_MIN_MAG_MIP_LINEAR,
            address_u: D3D10_TEXTURE_ADDRESS_WRAP,
            address_v: D3D10_TEXTURE_ADDRESS_WRAP,
            address_w: D3D10_TEXTURE_ADDRESS_WRAP,
            ..Default::default()
        };
        let sampler_id = device.create_sampler_state(&sampler_desc);
        device.ps_set_samplers(vec![sampler_id]);

        // Create input layout
        let input_elements = vec![
            D3d10InputElementDesc {
                semantic_name: "POSITION".to_string(),
                semantic_index: 0,
                format: DxgiFormat::R32G32B32A32Float,
                input_slot: 0,
                aligned_byte_offset: 0,
                input_slot_class: 0,
                instance_data_step_rate: 0,
            },
            D3d10InputElementDesc {
                semantic_name: "COLOR".to_string(),
                semantic_index: 0,
                format: DxgiFormat::R32G32B32A32Float,
                input_slot: 0,
                aligned_byte_offset: 16,
                input_slot_class: 0,
                instance_data_step_rate: 0,
            },
        ];
        let layout_id = device.create_input_layout(&input_elements);
        device.ia_set_input_layout(layout_id);
        device.ia_set_primitive_topology(D3D10_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

        // Create a render target and depth-stencil view
        let tex_desc = D3d10Texture2dDesc {
            width: 256,
            height: 256,
            mip_levels: 1,
            array_size: 1,
            format: DxgiFormat::R8G8B8A8Unorm,
            sample_desc: D3d10SampleDesc {
                count: 1,
                quality: 0,
            },
            usage: D3D10_USAGE_DEFAULT,
            bind_flags: D3D10_BIND_RENDER_TARGET,
            cpu_access_flags: 0,
            misc_flags: 0,
        };
        let rt_id = device
            .create_texture_2d(&tex_desc, None)
            .expect("create RT texture");
        let rtv = device
            .create_render_target_view(rt_id, None)
            .expect("create RTV");

        let ds_tex_desc = D3d10Texture2dDesc {
            width: 256,
            height: 256,
            mip_levels: 1,
            array_size: 1,
            format: DxgiFormat::D24UnormS8Uint,
            sample_desc: D3d10SampleDesc {
                count: 1,
                quality: 0,
            },
            usage: D3D10_USAGE_DEFAULT,
            bind_flags: D3D10_BIND_DEPTH_STENCIL,
            cpu_access_flags: 0,
            misc_flags: 0,
        };
        let ds_id = device
            .create_texture_2d(&ds_tex_desc, None)
            .expect("create DS texture");
        let dsv = device
            .create_depth_stencil_view(ds_id, None)
            .expect("create DSV");

        // Set render targets
        device.om_set_render_targets(vec![rtv], Some(dsv));

        // Should not crash
        device.draw(3);
    }

    /// Test D3D10CreateDevice with BGRA support flag.
    #[test]
    fn test_d3d10_create_device_with_flags() {
        let device = d3d10_create_device(
            0,
            D3d10DriverType::Hardware,
            0,
            D3D10_CREATE_DEVICE_BGRA_SUPPORT,
            &[],
            D3D10_SDK_VERSION,
        )
        .expect("create device with BGRA support");
        assert_eq!(
            device.creation_flags & D3D10_CREATE_DEVICE_BGRA_SUPPORT,
            D3D10_CREATE_DEVICE_BGRA_SUPPORT
        );
    }

    /// Test D3D10CreateDevice with WARP driver type.
    #[test]
    fn test_d3d10_create_device_warp() {
        let device = d3d10_create_device(0, D3d10DriverType::Warp, 0, 0, &[], D3D10_SDK_VERSION)
            .expect("create device with WARP driver");
        assert_eq!(device.feature_level(), D3d10FeatureLevel::Level10_1);
    }
}
